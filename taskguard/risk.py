"""Strict task capsules and tamper-evident, monotonic SSS risk routing."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping


class CapsuleError(ValueError):
    """Raised when a task capsule or risk chain cannot be routed safely."""


_CAPSULE_FIELDS = {
    "version",
    "task_id",
    "outcome",
    "scope",
    "invariants",
    "evidence",
    "risk",
    "signals",
    "external_actions",
    "authority",
}
_RESULT_FIELDS = {
    "version",
    "task_id",
    "stage",
    "declared_risk",
    "effective_risk",
    "hard_triggers",
    "soft_signals",
    "blockers",
    "guards",
    "independent_review",
    "admitted",
    "previous",
    "result_digest",
}
_ACTION_FIELDS = {"action", "target", "environment", "scope"}
_AUTHORITY_FIELDS = _ACTION_FIELDS | {"task_id", "user_evidence"}
_TASK_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RISKS = ("L0", "L1", "L2", "L3")
_STAGE_PREVIOUS = {"initial": None, "diff": "initial", "final": "diff"}
_HARD_L2 = {
    "public_api", "persistence", "migration", "identity", "authorization",
    "tenant", "privacy", "security", "data_loss", "false_supported", "ai_output",
}
_HARD_L3 = {
    "deploy", "delete", "production_write", "third_party_write",
    "external_irreversible",
}
_SOFT = {
    "material_ambiguity", "multiple_owners", "dirty_overlap",
    "no_trusted_verification", "repeated_hypothesis_failure", "diff_expansion",
    "evidence_conflict", "evidence_staleness",
}
_CONTROL = {"scope_expansion"}
_KNOWN_SIGNALS = _HARD_L2 | _HARD_L3 | _SOFT | _CONTROL
_BASE_GUARDS = {
    "L0": ["precise_check"],
    "L1": ["change_contract", "focused_red_green", "final_verification"],
    "L2": ["preflight", "taskguard", "boundary_matrix", "failure_paths", "ownership_check"],
    "L3": [
        "preflight", "taskguard", "boundary_matrix", "failure_paths",
        "ownership_check", "explicit_authority", "dry_run", "rollback", "health_check",
    ],
}


def _canonical_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise CapsuleError(f"value is not canonical JSON: {exc}") from exc


def _text(value: Any, field: str) -> str:
    if type(value) is not str or not value.strip() or "\x00" in value:
        raise CapsuleError(f"{field} must be a non-empty string without NUL")
    return value


def _text_array(value: Any, field: str, *, nonempty: bool) -> list[str]:
    if type(value) is not list or (nonempty and not value):
        raise CapsuleError(f"{field} must be {'a non-empty ' if nonempty else 'an '}array")
    parsed = [_text(item, f"{field} item") for item in value]
    if len(set(parsed)) != len(parsed):
        raise CapsuleError(f"{field} contains duplicate entries")
    return parsed


def _scope_path(value: str) -> str:
    path = PurePosixPath(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise CapsuleError("scope entries must remain repository-relative")
    if any(part.casefold() == ".git" for part in path.parts):
        raise CapsuleError("scope entries must not select Git administrative data")
    return path.as_posix()


def _action(value: object, field: str, *, authority: bool) -> dict[str, str]:
    expected = _AUTHORITY_FIELDS if authority else _ACTION_FIELDS
    if type(value) is not dict or set(value) != expected:
        raise CapsuleError(f"{field} has an inexact schema")
    parsed = {key: _text(value[key], f"{field}.{key}") for key in expected}
    if parsed["action"] not in _HARD_L3:
        raise CapsuleError(f"{field}.action must name an L3 action")
    return parsed


def _action_key(value: Mapping[str, str]) -> tuple[str, str, str, str]:
    return (value["action"], value["target"], value["environment"], value["scope"])


def validate_capsule(value: object) -> dict[str, object]:
    """Return a strict, target-bound task capsule or fail closed."""

    if type(value) is not dict or set(value) != _CAPSULE_FIELDS:
        raise CapsuleError("capsule fields do not match task-capsule-v1")
    if type(value["version"]) is not int or value["version"] != 1:
        raise CapsuleError("version must be integer 1")
    task_id = _text(value["task_id"], "task_id")
    if _TASK_ID.fullmatch(task_id) is None:
        raise CapsuleError("task_id has an invalid format")
    outcome = _text(value["outcome"], "outcome")
    scope = [_scope_path(item) for item in _text_array(value["scope"], "scope", nonempty=True)]
    invariants = _text_array(value["invariants"], "invariants", nonempty=False)
    evidence = _text_array(value["evidence"], "evidence", nonempty=True)
    risk = value["risk"]
    if type(risk) is not str or risk not in _RISKS:
        raise CapsuleError("risk must be one of L0, L1, L2, L3")
    signals = _text_array(value["signals"], "signals", nonempty=False)
    unknown = [signal for signal in signals if signal not in _KNOWN_SIGNALS]
    if unknown:
        raise CapsuleError("unknown risk signals: " + ", ".join(unknown))
    if type(value["external_actions"]) is not list or type(value["authority"]) is not list:
        raise CapsuleError("external_actions and authority must be arrays")
    actions = [
        _action(item, f"external_actions[{index}]", authority=False)
        for index, item in enumerate(value["external_actions"])
    ]
    authorities = [
        _action(item, f"authority[{index}]", authority=True)
        for index, item in enumerate(value["authority"])
    ]
    if len({_action_key(item) for item in actions}) != len(actions):
        raise CapsuleError("external_actions contains duplicate entries")
    if len({_action_key(item) for item in authorities}) != len(authorities):
        raise CapsuleError("authority contains duplicate entries")
    signal_actions = {signal for signal in signals if signal in _HARD_L3}
    bound_actions = {item["action"] for item in actions}
    if signal_actions != bound_actions:
        raise CapsuleError("L3 signals and external_actions must name the same actions")
    for item in authorities:
        if item["task_id"] != task_id or item["action"] not in signal_actions:
            raise CapsuleError("authority must bind this task_id and a requested L3 action")
    return {
        "version": 1, "task_id": task_id, "outcome": outcome, "scope": scope,
        "invariants": invariants, "evidence": evidence, "risk": risk,
        "signals": signals, "external_actions": actions, "authority": authorities,
    }


def _validate_previous(value: object, *, task_id: str, stage: str) -> dict[str, object]:
    if type(value) is not dict or set(value) != _RESULT_FIELDS:
        raise CapsuleError("previous risk result has an inexact schema")
    digest = value.get("result_digest")
    unsigned = dict(value)
    unsigned.pop("result_digest", None)
    expected = hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
    if type(digest) is not str or _SHA256.fullmatch(digest) is None or digest != expected:
        raise CapsuleError("previous risk result digest is invalid")
    expected_stage = _STAGE_PREVIOUS[stage]
    if value.get("stage") != expected_stage or value.get("task_id") != task_id:
        raise CapsuleError("previous risk result does not bind the required task and stage")
    nested = value.get("previous")
    if expected_stage == "initial" and nested is not None:
        raise CapsuleError("initial risk result must start the chain")
    if expected_stage in {"diff", "final"}:
        _validate_previous(nested, task_id=task_id, stage=str(expected_stage))
    if value.get("effective_risk") not in _RISKS or type(value.get("admitted")) is not bool:
        raise CapsuleError("previous risk result has invalid verdict fields")
    return copy.deepcopy(value)


def _ordered_union(first: list[str], second: list[str]) -> list[str]:
    return list(dict.fromkeys([*first, *second]))


def evaluate_risk(
    capsule: Mapping[str, object] | object,
    stage: str,
    *,
    previous_result: object | None = None,
) -> dict[str, object]:
    """Evaluate one tamper-evident stage of the one-way SSS risk fuse."""

    if type(stage) is not str or stage not in _STAGE_PREVIOUS:
        raise CapsuleError("stage must be initial, diff, or final")
    parsed = validate_capsule(capsule)
    if stage == "initial" and previous_result is not None:
        raise CapsuleError("initial stage must not have a previous risk result")
    previous: dict[str, object] | None = None
    blockers: list[str] = []
    if stage != "initial":
        if previous_result is None:
            blockers.append("previous_stage_result_required")
        else:
            previous = _validate_previous(
                previous_result, task_id=str(parsed["task_id"]), stage=stage
            )
            if not bool(previous["admitted"]):
                blockers.append("previous_stage_not_admitted")

    declared = str(parsed["risk"])
    signals = list(parsed["signals"])
    current_hard = [signal for signal in signals if signal in _HARD_L2 | _HARD_L3]
    current_soft = [signal for signal in signals if signal in _SOFT]
    hard_triggers = _ordered_union(
        [] if previous is None else list(previous["hard_triggers"]), current_hard
    )
    soft_signals = _ordered_union(
        [] if previous is None else list(previous["soft_signals"]), current_soft
    )
    hard_l2 = [signal for signal in hard_triggers if signal in _HARD_L2]
    hard_l3 = [signal for signal in hard_triggers if signal in _HARD_L3]
    effective_index = _RISKS.index(declared)
    if previous is not None:
        effective_index = max(effective_index, _RISKS.index(str(previous["effective_risk"])))
    if hard_l3:
        effective_index = max(effective_index, 3)
    elif hard_l2:
        effective_index = max(effective_index, 2)
    elif len(soft_signals) >= 2:
        effective_index = max(effective_index, 1 if declared == "L0" else 2)
    effective = _RISKS[effective_index]
    independent_review = declared in {"L2", "L3"} and len(soft_signals) >= 2
    if "scope_expansion" in signals:
        blockers.append("scope_reconfirmation_required")
    if stage == "final" and "evidence_conflict" in soft_signals:
        blockers.append("contradictory_evidence")
    actions = {_action_key(item): item for item in parsed["external_actions"]}
    authority = {_action_key(item): item for item in parsed["authority"]}
    for signal in hard_l3:
        matching = [item for item in actions.values() if item["action"] == signal]
        if not matching:
            blockers.append(f"missing_action_binding:{signal}")
        for item in matching:
            if _action_key(item) not in authority:
                blockers.append(f"missing_authority:{signal}:{item['target']}")
    guards = list(_BASE_GUARDS[effective])
    if independent_review:
        guards.append("independent_review")
    admitted = _RISKS.index(declared) >= effective_index and not blockers
    result: dict[str, object] = {
        "version": "ligong-risk-result-v2",
        "task_id": parsed["task_id"],
        "stage": stage,
        "declared_risk": declared,
        "effective_risk": effective,
        "hard_triggers": hard_triggers,
        "soft_signals": soft_signals,
        "blockers": blockers,
        "guards": guards,
        "independent_review": independent_review,
        "admitted": admitted,
        "previous": previous,
    }
    result["result_digest"] = hashlib.sha256(_canonical_bytes(result)).hexdigest()
    return result


__all__ = ["CapsuleError", "evaluate_risk", "validate_capsule"]
