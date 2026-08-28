"""Deterministic ForgeLoop development-capsule evaluation."""

from __future__ import annotations

import json
import re
from typing import Any

from .validation import loads_strict_json as _shared_loads_strict_json


RESULT_VERSION = "ligong-development-result-v1"

_CAPSULE_FIELDS = {
    "version",
    "task_id",
    "creativity",
    "outcome",
    "constraints",
    "non_goals",
    "signals",
    "candidates",
    "chosen_candidate",
    "decision_evidence",
    "requirements",
    "validation",
}
_CANDIDATE_FIELDS = {
    "id",
    "mechanism",
    "summary",
    "tradeoffs",
    "status",
    "evidence",
    "wildcard",
}
_REQUIREMENT_FIELDS = {"id", "outcome", "owner", "invariant", "evidence"}
_VALIDATION_FIELDS = {"lane", "evidence"}
_CREATIVITY = {"C0": 1, "C1": 2, "C2": 3, "C3": 4}
_BASE_LANES = {
    "C0": {"behavior"},
    "C1": {"behavior", "regression"},
    "C2": {"behavior", "failure", "regression"},
    "C3": {"adversarial", "behavior", "failure", "regression", "simplification"},
}
_SIGNAL_LANES = {
    "compatibility": "compatibility",
    "concurrency": "concurrency",
    "migration": "migration",
    "performance": "performance",
    "recovery": "recovery",
    "security": "security",
}
_LANES = set(_SIGNAL_LANES.values()) | set().union(*_BASE_LANES.values())
_MECHANISM_VARIANTS = {
    "enhanced", "fast", "faster", "improved", "new", "optimized",
    "plus", "v", "version",
}


def _nonempty_string(value: Any) -> bool:
    return type(value) is str and bool(value.strip())


def loads_strict_json(text: str) -> object:
    """Parse strict JSON through the shared TaskGuard boundary."""

    return _shared_loads_strict_json(text)


def _mechanism_signature(value: str) -> str:
    tokens = [
        token.strip("_")
        for token in re.split(r"[^\w]+", value.casefold())
        if token.strip("_")
    ]
    semantic = [
        token
        for token in tokens
        if token not in _MECHANISM_VARIANTS
        and not token.isdigit()
        and not re.fullmatch(r"v\d+", token)
    ]
    return " ".join(semantic)


def _string_list(value: Any, field: str, findings: list[str]) -> list[str]:
    if type(value) is not list:
        findings.append(f"{field} must be an array")
        return []
    result: list[str] = []
    for index, item in enumerate(value):
        if not _nonempty_string(item):
            findings.append(f"{field}[{index}] must be a non-empty string")
        else:
            result.append(item)
    return result


def _object_fields(
    value: Any,
    *,
    field: str,
    expected: set[str],
    findings: list[str],
) -> dict[str, Any] | None:
    if type(value) is not dict:
        findings.append(f"{field} must be an object")
        return None
    missing = sorted(expected.difference(value))
    unknown = sorted(set(value).difference(expected))
    if missing:
        findings.append(f"{field} missing fields: {', '.join(missing)}")
    if unknown:
        findings.append(f"{field} has unknown fields: {', '.join(unknown)}")
    return value


def _invalid_result(findings: list[str], creativity: Any = None) -> dict[str, object]:
    known_creativity = type(creativity) is str and creativity in _CREATIVITY
    return {
        "version": RESULT_VERSION,
        "status": "INVALID",
        "creativity": creativity if known_creativity else None,
        "required_candidate_count": _CREATIVITY[creativity] if known_creativity else None,
        "required_validation": sorted(_BASE_LANES[creativity]) if known_creativity else [],
        "missing": [],
        "findings": sorted(set(findings)),
    }


def evaluate_development_capsule(value: object) -> dict[str, object]:
    """Evaluate ForgeLoop planning evidence without claiming implementation success."""

    findings: list[str] = []
    if type(value) is not dict:
        return _invalid_result(["capsule must be an object"])
    capsule: dict[str, Any] = value
    unknown = sorted(set(capsule).difference(_CAPSULE_FIELDS))
    absent = sorted(_CAPSULE_FIELDS.difference(capsule))
    if unknown:
        findings.append(f"unknown capsule fields: {', '.join(unknown)}")
    if absent:
        findings.append(f"missing capsule fields: {', '.join(absent)}")

    version = capsule.get("version")
    if type(version) is not int or version != 1:
        findings.append("version must be integer 1")
    for field in ("task_id", "outcome", "chosen_candidate"):
        if not _nonempty_string(capsule.get(field)):
            findings.append(f"{field} must be a non-empty string")

    creativity = capsule.get("creativity")
    if type(creativity) is not str or creativity not in _CREATIVITY:
        findings.append("creativity must be one of C0, C1, C2, C3")

    _string_list(capsule.get("constraints"), "constraints", findings)
    _string_list(capsule.get("non_goals"), "non_goals", findings)
    decision_evidence = _string_list(
        capsule.get("decision_evidence"), "decision_evidence", findings
    )
    signals = _string_list(capsule.get("signals"), "signals", findings)
    if len(signals) != len(set(signals)):
        findings.append("signals must be unique")
    unknown_signals = sorted(set(signals).difference(_SIGNAL_LANES))
    if unknown_signals:
        findings.append(f"unknown signals: {', '.join(unknown_signals)}")

    candidates_value = capsule.get("candidates")
    if type(candidates_value) is not list:
        findings.append("candidates must be an array")
        candidates: list[Any] = []
    else:
        candidates = candidates_value
    candidate_ids: list[str] = []
    mechanisms: list[str] = []
    chosen_ids: list[str] = []
    wildcard_count = 0
    candidate_evidence: dict[str, list[str]] = {}
    candidate_tradeoffs: dict[str, list[str]] = {}
    candidate_status: dict[str, str] = {}
    for index, item in enumerate(candidates):
        parsed = _object_fields(
            item,
            field=f"candidates[{index}]",
            expected=_CANDIDATE_FIELDS,
            findings=findings,
        )
        if parsed is None:
            continue
        for field in ("id", "mechanism", "summary"):
            if not _nonempty_string(parsed.get(field)):
                findings.append(f"candidates[{index}].{field} must be a non-empty string")
        candidate_id = parsed.get("id")
        mechanism = parsed.get("mechanism")
        if _nonempty_string(candidate_id):
            candidate_ids.append(candidate_id)
        if _nonempty_string(mechanism):
            mechanisms.append(_mechanism_signature(mechanism))
        status = parsed.get("status")
        if type(status) is not str or status not in {"chosen", "rejected"}:
            findings.append(f"candidates[{index}].status must be chosen or rejected")
        elif status == "chosen" and _nonempty_string(candidate_id):
            chosen_ids.append(candidate_id)
        if _nonempty_string(candidate_id) and type(status) is str:
            candidate_status[candidate_id] = status
        if type(parsed.get("wildcard")) is not bool:
            findings.append(f"candidates[{index}].wildcard must be a boolean")
        elif parsed["wildcard"]:
            wildcard_count += 1
        tradeoffs = _string_list(
            parsed.get("tradeoffs"), f"candidates[{index}].tradeoffs", findings
        )
        evidence = _string_list(
            parsed.get("evidence"), f"candidates[{index}].evidence", findings
        )
        if _nonempty_string(candidate_id):
            candidate_evidence[candidate_id] = evidence
            candidate_tradeoffs[candidate_id] = tradeoffs
    if len(candidate_ids) != len(set(candidate_ids)):
        findings.append("candidate ids must be unique")
    if len(chosen_ids) != 1 or capsule.get("chosen_candidate") != (
        chosen_ids[0] if len(chosen_ids) == 1 else None
    ):
        findings.append("chosen_candidate must reference the candidate with status chosen")

    requirements_value = capsule.get("requirements")
    if type(requirements_value) is not list:
        findings.append("requirements must be an array")
        requirements: list[Any] = []
    else:
        requirements = requirements_value
    requirement_ids: list[str] = []
    requirement_evidence: dict[str, list[str]] = {}
    for index, item in enumerate(requirements):
        parsed = _object_fields(
            item,
            field=f"requirements[{index}]",
            expected=_REQUIREMENT_FIELDS,
            findings=findings,
        )
        if parsed is None:
            continue
        for field in ("id", "outcome", "owner", "invariant"):
            if not _nonempty_string(parsed.get(field)):
                findings.append(f"requirements[{index}].{field} must be a non-empty string")
        requirement_id = parsed.get("id")
        if _nonempty_string(requirement_id):
            requirement_ids.append(requirement_id)
            requirement_evidence[requirement_id] = _string_list(
                parsed.get("evidence"), f"requirements[{index}].evidence", findings
            )
        else:
            _string_list(parsed.get("evidence"), f"requirements[{index}].evidence", findings)
    if len(requirement_ids) != len(set(requirement_ids)):
        findings.append("requirement ids must be unique")

    validation_value = capsule.get("validation")
    if type(validation_value) is not list:
        findings.append("validation must be an array")
        validation: list[Any] = []
    else:
        validation = validation_value
    lanes: list[str] = []
    for index, item in enumerate(validation):
        parsed = _object_fields(
            item,
            field=f"validation[{index}]",
            expected=_VALIDATION_FIELDS,
            findings=findings,
        )
        if parsed is None:
            continue
        lane = parsed.get("lane")
        if type(lane) is not str or lane not in _LANES:
            findings.append(f"validation[{index}].lane is unknown")
        else:
            lanes.append(lane)
        if not _nonempty_string(parsed.get("evidence")):
            findings.append(f"validation[{index}].evidence must be a non-empty string")
    if len(lanes) != len(set(lanes)):
        findings.append("validation lanes must be unique")

    if findings:
        return _invalid_result(findings, creativity)

    required_count = _CREATIVITY[creativity]
    required_lanes = set(_BASE_LANES[creativity])
    required_lanes.update(_SIGNAL_LANES[signal] for signal in signals)
    missing: list[str] = []
    if len(candidates) < required_count:
        missing.append(f"candidate_count:{required_count}")
    if len(set(mechanisms)) < required_count:
        missing.append(f"distinct_candidate_mechanisms:{required_count}")
    if creativity == "C3" and wildcard_count == 0:
        missing.append("wildcard_candidate")
    if not decision_evidence:
        missing.append("decision_evidence")
    if not requirements:
        missing.append("requirement_traceability")
    for requirement_id, evidence in requirement_evidence.items():
        if not evidence:
            missing.append(f"requirement_evidence:{requirement_id}")
    for candidate_id, evidence in candidate_evidence.items():
        if candidate_status.get(candidate_id) == "chosen" and not evidence:
            missing.append(f"selection_evidence:{candidate_id}")
        elif candidate_status.get(candidate_id) == "rejected" and not evidence:
            missing.append(f"rejection_evidence:{candidate_id}")
    for candidate_id, tradeoffs in candidate_tradeoffs.items():
        if not tradeoffs:
            missing.append(f"candidate_tradeoffs:{candidate_id}")
    for lane in sorted(required_lanes.difference(lanes)):
        missing.append(f"validation:{lane}")

    return {
        "version": RESULT_VERSION,
        "status": "READY" if not missing else "REVISE",
        "creativity": creativity,
        "required_candidate_count": required_count,
        "required_validation": sorted(required_lanes),
        "missing": sorted(missing),
        "findings": [],
    }
