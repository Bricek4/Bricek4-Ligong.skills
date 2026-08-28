"""Canonical JSON command-line interface for TaskGuard v2."""

from __future__ import annotations

import argparse
import copy
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import sys
from typing import Any, Callable, Iterable, Mapping, Sequence

from .contract import Acceptance, Contract, ContractError, load_contract
from .runner import (
    Operation,
    RetryBudget,
    RunResult,
    TaskRunner,
    _bounded_process,
    _exact_command_freshness,
    _nofollow_runtime_cwd,
    _redact_and_bound,
    _workspace_ownership_proof,
    classify_failure,
    valid_expected_red,
)
from .state import ConcurrentUpdateError, ExecutionLease, StateError, StateStore
from .workspace import ScopeViolation, WorkspaceSnapshot


_TASK_STATE_ID = "task"
_CHECKPOINT_STATE_ID = "checkpoint"
_VERIFICATION_RECEIPT_VERSION = "taskguard-verification-receipt-v1"
_CONTRACT_BINDING_VERSION = "taskguard-contract-binding-v2"
_ACCEPTANCE_BINDING_VERSION = "taskguard-acceptance-binding-v2"
_OUTPUT_LIMIT = 16 * 1024
_SURFACE_TIMEOUT_SECONDS = 120
_MAX_SCAN_FILE_BYTES = 4 * 1024 * 1024
_PRECEDENCE = {"SUPPORTED": 0, "UNKNOWN": 1, "STALE": 2, "FAILED": 3}
_CREDENTIAL_OPTION = re.compile(
    r"(?i)--(?:api[-_]?key|access[-_]?token|token|password|passwd|secret)\Z"
)
_INLINE_CREDENTIAL_OPTION = re.compile(
    r"(?i)--(?:api[-_]?key|access[-_]?token|token|password|passwd|secret)="
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_RESULT_VERDICTS = {"SUPPORTED", "FAILED", "STALE", "UNKNOWN"}
_SURFACE_CLASSIFICATIONS = {
    "SUCCESS",
    "AUTH",
    "PERMISSION",
    "ASSERTION",
    "BUILD",
    "INPUT",
    "TRANSPORT",
    "TIMEOUT",
    "UNKNOWN",
}


class CliInputError(ValueError):
    """Stable exit-2 command or contract usage failure."""


class AdmissionFailure(RuntimeError):
    """Stable exit-1 policy rejection before task state is created."""


def _json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _digest(value: Any) -> str:
    return hashlib.sha256(_json_bytes(value)).hexdigest()


def _exact_json_equal(left: Any, right: Any) -> bool:
    """Compare canonical JSON bytes so booleans never equal integer fields."""

    try:
        return _json_bytes(left) == _json_bytes(right)
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return False


def _emit(payload: Mapping[str, Any]) -> None:
    sys.stdout.write(_json_bytes(payload).decode("ascii") + "\n")


def _forward_output(result: RunResult) -> None:
    for value in (result.stdout, result.stderr):
        if value:
            sys.stderr.write(value)
            if not value.endswith("\n"):
                sys.stderr.write("\n")


def _persistable_argv(argv: Sequence[str], *, label: str) -> list[str]:
    canonical = list(argv)
    for index, argument in enumerate(canonical):
        if _INLINE_CREDENTIAL_OPTION.match(argument) or (
            _CREDENTIAL_OPTION.fullmatch(argument) and index + 1 < len(canonical)
        ):
            raise CliInputError(
                f"{label} argv must not contain literal credentials; inject them through "
                "a non-persisted environment or credential provider"
            )
    return canonical


def _acceptance_manifest(acceptance: Acceptance) -> dict[str, Any]:
    argv = _persistable_argv(acceptance.argv, label="acceptance")
    return {
        "id": acceptance.id,
        "argv": argv,
        "cwd": acceptance.cwd,
        "selector": acceptance.selector,
        "idempotent": acceptance.idempotent,
        "requires_red": acceptance.requires_red,
        "expected_red_pattern": acceptance.expected_red_pattern,
    }


def _surface_manifest(surface: Mapping[str, Any]) -> dict[str, Any]:
    manifest = copy.deepcopy(dict(surface))
    argv = manifest.get("argv")
    if not isinstance(argv, Sequence) or isinstance(argv, (str, bytes)):
        raise CliInputError("surface argv must be a string array")
    manifest["argv"] = _persistable_argv(argv, label="surface")
    return manifest


def _contract_manifest(contract: Contract) -> dict[str, Any]:
    return {
        "binding_version": _CONTRACT_BINDING_VERSION,
        "version": contract.version,
        "task_id": contract.task_id,
        "goal": contract.goal,
        "risk": contract.risk,
        "repo": str(contract.repo),
        "scope": list(contract.scope),
        "acknowledge_dirty": list(contract.acknowledge_dirty),
        "acceptance": [_acceptance_manifest(item) for item in contract.acceptance],
        "forbidden": copy.deepcopy(contract.forbidden),
        "surfaces": [_surface_manifest(surface) for surface in contract.surfaces],
    }


def _admission_manifest(
    contract: Mapping[str, Any],
    baseline_snapshot: Any,
    obligations: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the create-only portion of task state that cannot be replayed."""

    return {
        "version": "taskguard-admission-anchor-v1",
        "contract": contract,
        "baseline_snapshot": baseline_snapshot,
        "forbidden": obligations.get("forbidden"),
        "surfaces": obligations.get("surfaces"),
    }


def _validate_task_contract(value: Any) -> dict[str, Any]:
    required_fields = {
        "binding_version",
        "version",
        "task_id",
        "goal",
        "risk",
        "repo",
        "scope",
        "acknowledge_dirty",
        "acceptance",
        "forbidden",
        "surfaces",
    }
    if type(value) is not dict or set(value) != required_fields:
        raise StateError("task state has no valid canonical contract binding")

    def text(value_to_check: Any, label: str) -> str:
        if (
            type(value_to_check) is not str
            or not value_to_check.strip()
            or "\x00" in value_to_check
        ):
            raise StateError(f"task contract {label} must be a non-empty string")
        return value_to_check

    def text_array(value_to_check: Any, label: str, *, nonempty: bool) -> list[str]:
        if type(value_to_check) is not list or (nonempty and not value_to_check):
            raise StateError(f"task contract {label} must be an array")
        parsed = [text(item, f"{label} item") for item in value_to_check]
        if len(set(parsed)) != len(parsed):
            raise StateError(f"task contract {label} contains duplicate entries")
        return parsed

    if value["binding_version"] != _CONTRACT_BINDING_VERSION:
        raise StateError("task contract binding version is invalid")
    if type(value["version"]) is not int or value["version"] != 2:
        raise StateError("task contract version must be integer 2")
    text(value["task_id"], "task_id")
    text(value["goal"], "goal")
    if type(value["risk"]) is not str or value["risk"] not in {"L0", "L1", "L2", "L3"}:
        raise StateError("task contract risk is invalid")
    repo = text(value["repo"], "repo")
    if not Path(repo).is_absolute():
        raise StateError("task contract repo must be an absolute canonical path")
    text_array(value["scope"], "scope", nonempty=True)
    text_array(value["acknowledge_dirty"], "acknowledge_dirty", nonempty=False)

    acceptance = value["acceptance"]
    if type(acceptance) is not list or not acceptance:
        raise StateError("task contract acceptance must be a non-empty array")
    acceptance_ids: list[str] = []
    for item in acceptance:
        if type(item) is not dict or set(item) != {
            "id",
            "argv",
            "cwd",
            "selector",
            "idempotent",
            "requires_red",
            "expected_red_pattern",
        }:
            raise StateError("task contract acceptance item has an inexact schema")
        acceptance_ids.append(text(item["id"], "acceptance id"))
        text_array(item["argv"], "acceptance argv", nonempty=True)
        text(item["cwd"], "acceptance cwd")
        if item["selector"] is not None:
            text(item["selector"], "acceptance selector")
        if type(item["idempotent"]) is not bool or type(item["requires_red"]) is not bool:
            raise StateError("task contract acceptance booleans are invalid")
        expected_red = item["expected_red_pattern"]
        if item["requires_red"] is True:
            text(expected_red, "acceptance expected_red_pattern")
        elif expected_red is not None:
            text(expected_red, "acceptance expected_red_pattern")
    if len(set(acceptance_ids)) != len(acceptance_ids):
        raise StateError("task contract acceptance ids must be unique")

    forbidden = value["forbidden"]
    if type(forbidden) is not list:
        raise StateError("task contract forbidden must be an array")
    forbidden_ids: list[str] = []
    for item in forbidden:
        if type(item) is not dict or set(item) != {"id", "glob", "regex", "mode"}:
            raise StateError("task contract forbidden item has an inexact schema")
        forbidden_ids.append(text(item["id"], "forbidden id"))
        text(item["glob"], "forbidden glob")
        pattern = text(item["regex"], "forbidden regex")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise StateError(f"task contract forbidden regex is invalid: {exc}") from exc
        if type(item["mode"]) is not str or item["mode"] not in {"eliminate", "no_new"}:
            raise StateError("task contract forbidden mode is invalid")
    if len(set(forbidden_ids)) != len(forbidden_ids):
        raise StateError("task contract forbidden ids must be unique")

    surfaces = value["surfaces"]
    if type(surfaces) is not list:
        raise StateError("task contract surfaces must be an array")
    surface_ids: list[str] = []
    for item in surfaces:
        if type(item) is not dict or set(item) != {
            "id",
            "argv",
            "cwd",
            "read_only",
            "normalizer_version",
            "allowed_writes",
        }:
            raise StateError("task contract surface item has an inexact schema")
        surface_ids.append(text(item["id"], "surface id"))
        text_array(item["argv"], "surface argv", nonempty=True)
        text(item["cwd"], "surface cwd")
        if item["read_only"] is not True:
            raise StateError("task contract surface must be read-only")
        text(item["normalizer_version"], "surface normalizer_version")
        text_array(item["allowed_writes"], "surface allowed_writes", nonempty=False)
    if len(set(surface_ids)) != len(surface_ids):
        raise StateError("task contract surface ids must be unique")
    return value


def _validate_phase_receipt(
    value: Any,
    *,
    phase: str,
    binding_digest: str,
) -> None:
    if value is None:
        return
    if type(value) is not dict:
        raise StateError(f"task {phase} receipt must be an object or null")
    regular_fields = {
        "phase",
        "binding_digest",
        "verdict",
        "process",
        "workspace_success",
        "workspace_ownership",
    }
    disposition_fields = regular_fields | {"disposition"}
    fields = frozenset(value)
    if fields not in {frozenset(regular_fields), frozenset(disposition_fields)}:
        raise StateError(f"task {phase} receipt has an inexact schema")
    if value["phase"] != phase or value["binding_digest"] != binding_digest:
        raise StateError(f"task {phase} receipt contradicts its acceptance binding")
    if type(value["verdict"]) is not str or value["verdict"] not in {
        "SUPPORTED",
        "FAILED",
        "STALE",
        "UNKNOWN",
    }:
        raise StateError(f"task {phase} receipt has an invalid verdict")
    if type(value["process"]) is not dict and not (
        "disposition" in value and value["process"] is None
    ):
        raise StateError(f"task {phase} receipt has no process evidence")
    for key in ("workspace_success", "workspace_ownership"):
        if value[key] is not None and type(value[key]) is not dict:
            raise StateError(f"task {phase} receipt {key} must be an object or null")
    if "disposition" in value:
        disposition = value["disposition"]
        if type(disposition) is not dict or set(disposition) != {
            "verdict",
            "operation_revision",
            "rerun",
        }:
            raise StateError(f"task {phase} disposition has an inexact schema")
        if type(disposition["verdict"]) is not str or disposition["verdict"] not in {
            "FAILED",
            "UNKNOWN",
        }:
            raise StateError(f"task {phase} disposition has an invalid verdict")
        revision = disposition["operation_revision"]
        if revision is not None and (type(revision) is not int or revision < 1):
            raise StateError(f"task {phase} disposition revision is invalid")
        if disposition["rerun"] is not False:
            raise StateError(f"task {phase} disposition must prove no rerun")


def _validate_task_obligations(
    contract: Mapping[str, Any],
    value: Any,
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != {
        "acceptance",
        "forbidden",
        "surfaces",
    }:
        raise StateError("task obligation ledger has an inexact schema")
    acceptance_items = contract["acceptance"]
    acceptance = value["acceptance"]
    expected_acceptance_ids = {item["id"] for item in acceptance_items}
    if type(acceptance) is not dict or set(acceptance) != expected_acceptance_ids:
        raise StateError("task acceptance obligation set is incomplete or inexact")
    for item in acceptance_items:
        acceptance_id = item["id"]
        record = acceptance[acceptance_id]
        if type(record) is not dict or set(record) != {
            "binding_digest",
            "baseline",
            "candidate",
        }:
            raise StateError("task acceptance obligation record has an inexact schema")
        binding_digest = _digest(_acceptance_binding(item))
        if record["binding_digest"] != binding_digest:
            raise StateError("task acceptance obligation binding digest is inconsistent")
        if item["requires_red"] is True:
            _validate_phase_receipt(
                record["baseline"],
                phase="baseline",
                binding_digest=binding_digest,
            )
        elif not _exact_json_equal(record["baseline"], {"verdict": "NOT_REQUIRED"}):
            raise StateError("task acceptance baseline obligation is inconsistent")
        _validate_phase_receipt(
            record["candidate"],
            phase="candidate",
            binding_digest=binding_digest,
        )

    for ledger_name, contract_name in (
        ("forbidden", "forbidden"),
        ("surfaces", "surfaces"),
    ):
        ledger = value[ledger_name]
        expected_ids = {item["id"] for item in contract[contract_name]}
        if type(ledger) is not dict or set(ledger) != expected_ids:
            raise StateError(f"task {ledger_name} obligation set is incomplete or inexact")
        for item_id, receipt in ledger.items():
            if type(receipt) is not dict or receipt.get("id") != item_id:
                raise StateError(f"task {ledger_name} baseline receipt is invalid")
    return value


def _validate_disposition_process(
    value: Any,
    *,
    operation_id: str,
    operation_revision: int,
) -> None:
    if type(value) is not dict:
        raise StateError("task disposition process evidence must be an object")
    summary_fields = {
        "operation_id",
        "lifecycle",
        "verdict",
        "attempts",
        "state_revision",
    }
    full_fields = summary_fields | {
        "reuse_status",
        "classification",
        "exit_code",
        "timed_out",
        "stdout",
        "stderr",
        "failure_markers",
        "stdout_truncated",
        "stderr_truncated",
        "retry_eligible",
        "workspace_snapshot",
        "workspace_ownership",
    }
    if frozenset(value) not in {frozenset(summary_fields), frozenset(full_fields)}:
        raise StateError("task disposition process evidence has an inexact schema")
    if (
        value["operation_id"] != operation_id
        or value["state_revision"] != operation_revision
        or value["lifecycle"] not in {"TERMINAL", "TERMINAL_ERROR"}
        or value["verdict"] not in _RESULT_VERDICTS
        or type(value["attempts"]) is not int
        or value["attempts"] < 0
    ):
        raise StateError("task disposition process evidence is inconsistent")
    if set(value) == summary_fields:
        return
    if (
        type(value["reuse_status"]) is not str
        or value["classification"] not in _SURFACE_CLASSIFICATIONS
        or (value["exit_code"] is not None and type(value["exit_code"]) is not int)
        or type(value["timed_out"]) is not bool
        or type(value["stdout"]) is not str
        or type(value["stderr"]) is not str
        or type(value["failure_markers"]) is not list
        or any(type(marker) is not str for marker in value["failure_markers"])
        or type(value["stdout_truncated"]) is not bool
        or type(value["stderr_truncated"]) is not bool
        or type(value["retry_eligible"]) is not bool
        or (
            value["workspace_snapshot"] is not None
            and type(value["workspace_snapshot"]) is not dict
        )
        or (
            value["workspace_ownership"] is not None
            and type(value["workspace_ownership"]) is not dict
        )
    ):
        raise StateError("task disposition process evidence is invalid")


def _validate_disposition_consistency(
    state: Mapping[str, Any],
    contract: Mapping[str, Any],
    obligations: Mapping[str, Any],
) -> None:
    """Bind every no-rerun disposition to its exact acceptance phase receipt."""

    receipt_dispositions: dict[tuple[str, str], dict[str, Any]] = {}
    acceptance_records = obligations["acceptance"]
    for acceptance in contract["acceptance"]:
        acceptance_id = str(acceptance["id"])
        record = acceptance_records[acceptance_id]
        for phase in ("baseline", "candidate"):
            receipt = record[phase]
            if type(receipt) is not dict or "disposition" not in receipt:
                continue
            disposition = receipt["disposition"]
            if (
                receipt["verdict"] != disposition["verdict"]
                or receipt["workspace_success"] is not None
                or receipt["workspace_ownership"] is not None
            ):
                raise StateError(
                    "task disposition phase receipt contradicts its fail-closed verdict"
                )
            operation_id = _operation_id(
                str(contract["task_id"]), acceptance_id, phase
            )
            operation_revision = disposition["operation_revision"]
            process = receipt["process"]
            if process is None:
                if operation_revision is not None:
                    raise StateError(
                        "task disposition phase receipt has a revision without process evidence"
                    )
            else:
                if type(operation_revision) is not int:
                    raise StateError(
                        "task disposition process evidence has no operation revision"
                    )
                _validate_disposition_process(
                    process,
                    operation_id=operation_id,
                    operation_revision=operation_revision,
                )
            receipt_dispositions[(acceptance_id, phase)] = {
                "acceptance": acceptance_id,
                "phase": phase,
                "operation_id": operation_id,
                "operation_revision": operation_revision,
                "verdict": disposition["verdict"],
                "rerun": False,
            }

    persisted = state.get("dispositions", [])
    persisted_by_phase = {
        (str(item["acceptance"]), str(item["phase"])): item for item in persisted
    }
    if set(persisted_by_phase) != set(receipt_dispositions):
        raise StateError(
            "task dispositions do not match the persisted phase receipts exactly"
        )
    for key, expected in receipt_dispositions.items():
        if not _exact_json_equal(persisted_by_phase[key], expected):
            raise StateError(
                "task disposition contradicts its persisted phase receipt"
            )
    if receipt_dispositions and (
        state["lifecycle"] == "TERMINAL"
        or state["verdict"] == "SUPPORTED"
        or state["aggregate"] == "SUPPORTED"
    ):
        raise StateError(
            "task dispositions cannot coexist with TERMINAL/SUPPORTED state"
        )
    if state["next_action"] == "VERIFY_OR_INSPECT":
        if not receipt_dispositions:
            raise StateError("task direct disposition state has no phase receipts")
        disposition_aggregate = _aggregate(
            item["verdict"] for item in receipt_dispositions.values()
        )
        if (
            state["lifecycle"] != "TERMINAL_ERROR"
            or state["verdict"] != disposition_aggregate
            or state["aggregate"] != disposition_aggregate
        ):
            raise StateError(
                "task disposition aggregate contradicts its terminal verdict"
            )


def _validate_text_list(value: Any, *, label: str) -> None:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise StateError(f"task obligation results {label} must be a string array")


def _validate_ownership_result(value: Any, *, label: str) -> None:
    if type(value) is not dict:
        raise StateError(f"task obligation results {label} must be an object")
    fields = set(value)
    if fields == {"verdict", "reason"}:
        if value["verdict"] not in {"FAILED", "UNKNOWN"} or type(value["reason"]) is not str:
            raise StateError(f"task obligation results {label} is invalid")
        return
    if fields != {
        "version",
        "baseline_digest",
        "snapshot_digest",
        "verdict",
        "owned_paths",
        "reason",
    }:
        raise StateError(f"task obligation results {label} has an inexact schema")
    if (
        value["version"] != "taskguard-workspace-ownership-v1"
        or type(value["baseline_digest"]) is not str
        or _SHA256.fullmatch(value["baseline_digest"]) is None
        or type(value["snapshot_digest"]) is not str
        or _SHA256.fullmatch(value["snapshot_digest"]) is None
        or value["verdict"] not in {"SUPPORTED", "FAILED", "UNKNOWN"}
        or type(value["reason"]) is not str
    ):
        raise StateError(f"task obligation results {label} is invalid")
    _validate_text_list(value["owned_paths"], label=f"{label} owned_paths")


def _validate_freshness_result(value: Any, *, label: str) -> str:
    if type(value) is not dict:
        raise StateError(f"task obligation results {label} must be an object")
    fields = set(value)
    if fields == {"verdict", "reason"}:
        if value["verdict"] not in _RESULT_VERDICTS or type(value["reason"]) is not str:
            raise StateError(f"task obligation results {label} is invalid")
    elif fields == {"verdict", "reason", "ownership"}:
        if value["verdict"] not in _RESULT_VERDICTS or type(value["reason"]) is not str:
            raise StateError(f"task obligation results {label} is invalid")
        _validate_ownership_result(value["ownership"], label=f"{label} ownership")
    elif fields == {"verdict", "status", "changed_paths", "warnings", "ownership"}:
        if value["verdict"] not in _RESULT_VERDICTS or value["status"] not in {
            "FRESH",
            "STALE",
            "UNKNOWN",
        }:
            raise StateError(f"task obligation results {label} is invalid")
        _validate_text_list(value["changed_paths"], label=f"{label} changed_paths")
        _validate_text_list(value["warnings"], label=f"{label} warnings")
        _validate_ownership_result(value["ownership"], label=f"{label} ownership")
    else:
        raise StateError(f"task obligation results {label} has an inexact schema")
    return str(value["verdict"])


def _validate_phase_audit(
    value: Any,
    *,
    label: str,
    expected_operation_id: str,
) -> bool:
    if type(value) is not dict:
        raise StateError(f"task obligation results {label} must be an object")
    if set(value) == {"reason"}:
        if type(value["reason"]) is not str:
            raise StateError(f"task obligation results {label} reason is invalid")
        return False
    if set(value) != {"operation_id", "state_revision", "attempts"}:
        raise StateError(f"task obligation results {label} has an inexact schema")
    if (
        value["operation_id"] != expected_operation_id
        or type(value["state_revision"]) is not int
        or value["state_revision"] < 1
        or type(value["attempts"]) is not int
        or value["attempts"] < 0
    ):
        raise StateError(f"task obligation results {label} is invalid")
    return True


def _validate_acceptance_result(
    contract: Mapping[str, Any],
    acceptance: Mapping[str, Any],
    record: Mapping[str, Any],
    value: Any,
) -> str:
    acceptance_id = str(acceptance["id"])
    required = {"id", "candidate", "freshness", "verdict"}
    optional = {"candidate_audit"}
    phases = ["candidate"]
    if acceptance["requires_red"] is True:
        required.add("baseline")
        optional.add("baseline_audit")
        phases.insert(0, "baseline")
    if type(value) is not dict or not required.issubset(value) or not set(value).issubset(
        required | optional
    ):
        raise StateError("task obligation results acceptance has an inexact schema")
    if value["id"] != acceptance_id:
        raise StateError("task obligation results acceptance id is inconsistent")

    verdicts: list[str] = []
    for phase in phases:
        phase_verdict = value[phase]
        if type(phase_verdict) is not str or phase_verdict not in _RESULT_VERDICTS:
            raise StateError("task obligation results acceptance phase verdict is invalid")
        verdicts.append(phase_verdict)
        audit_key = f"{phase}_audit"
        audit_is_proof = False
        if audit_key in value:
            audit_is_proof = _validate_phase_audit(
                value[audit_key],
                label=f"acceptance {acceptance_id} {audit_key}",
                expected_operation_id=_operation_id(
                    str(contract["task_id"]), acceptance_id, phase
                ),
            )
        receipt = record[phase]
        if phase_verdict == "SUPPORTED" and (
            type(receipt) is not dict
            or receipt.get("verdict") != "SUPPORTED"
            or not audit_is_proof
        ):
            raise StateError(
                "task obligation results acceptance verdict is not ledger-backed"
            )

    verdicts.append(
        _validate_freshness_result(
            value["freshness"], label=f"acceptance {acceptance_id} freshness"
        )
    )
    expected = _aggregate(verdicts)
    if type(value["verdict"]) is not str or value["verdict"] != expected:
        raise StateError("task obligation results acceptance aggregate is inconsistent")
    return expected


def _validate_forbidden_match(value: Any, *, label: str) -> None:
    if type(value) is not dict or set(value) != {"path", "line", "digest"}:
        raise StateError(f"task obligation results {label} has an inexact schema")
    if (
        type(value["path"]) is not str
        or type(value["line"]) is not int
        or value["line"] < 1
        or type(value["digest"]) is not str
        or _SHA256.fullmatch(value["digest"]) is None
    ):
        raise StateError(f"task obligation results {label} is invalid")


def _validate_forbidden_current(
    value: Any,
    *,
    rule: Mapping[str, Any],
) -> None:
    if type(value) is not dict:
        raise StateError("task obligation results forbidden current must be an object")
    fields = set(value)
    success_fields = {"id", "mode", "matcher_version", "verdict", "matches"}
    error_fields = {"id", "mode", "verdict", "error", "matches"}
    if frozenset(fields) not in {frozenset(success_fields), frozenset(error_fields)}:
        raise StateError("task obligation results forbidden current has an inexact schema")
    if (
        value["id"] != rule["id"]
        or value["mode"] != rule["mode"]
        or type(value["matches"]) is not list
    ):
        raise StateError("task obligation results forbidden current is inconsistent")
    for match in value["matches"]:
        _validate_forbidden_match(match, label="forbidden match")
    if fields == success_fields:
        if value["matcher_version"] != "python-re-v1" or value["verdict"] != "SUPPORTED":
            raise StateError("task obligation results forbidden current is invalid")
    elif value["verdict"] != "UNKNOWN" or type(value["error"]) is not str:
        raise StateError("task obligation results forbidden current is invalid")


def _validate_forbidden_result(
    rule: Mapping[str, Any],
    baseline: Mapping[str, Any],
    value: Any,
) -> str:
    if type(value) is not dict or "current" not in value:
        raise StateError("task obligation results forbidden has an inexact schema")
    _validate_forbidden_current(value["current"], rule=rule)
    expected = _forbidden_verdict(rule, baseline, value["current"])
    if not _exact_json_equal(value, expected):
        raise StateError("task obligation results forbidden verdict is inconsistent")
    return str(expected["verdict"])


def _surface_result(
    surface_id: str,
    baseline: Mapping[str, Any] | None,
    current: Mapping[str, Any],
) -> dict[str, Any]:
    if current.get("verdict") != "SUPPORTED" or not isinstance(baseline, Mapping):
        return {
            "id": surface_id,
            "verdict": str(current.get("verdict", "UNKNOWN")),
            "current": current,
        }
    if baseline.get("verdict") != "SUPPORTED":
        return {"id": surface_id, "verdict": "UNKNOWN", "current": current}
    return {
        "id": surface_id,
        "verdict": "SUPPORTED"
        if current.get("normalized_digest") == baseline.get("normalized_digest")
        else "FAILED",
        "current": current,
    }


def _validate_surface_current(value: Any, *, surface_id: str) -> None:
    if type(value) is not dict:
        raise StateError("task obligation results surface current must be an object")
    fields = set(value)
    minimal = {"id", "verdict", "error"}
    minimal_timed = minimal | {"timed_out"}
    base = {
        "id",
        "verdict",
        "exit_code",
        "timed_out",
        "classification",
        "stderr",
        "stdout_truncated",
        "stderr_truncated",
        "process_group",
    }
    exact_shapes = {
        frozenset(minimal),
        frozenset(minimal_timed),
        frozenset(base | {"error"}),
        frozenset(base | {"error", "external_side_effects"}),
        frozenset(base | {"error", "changed_paths"}),
        frozenset(base | {"error", "changed_paths", "external_side_effects"}),
        frozenset(
            base
            | {
                "error",
                "changed_paths",
                "unsafe_symlink_paths",
                "external_side_effects",
            }
        ),
        frozenset(base | {"normalized_digest", "changed_paths", "external_side_effects"}),
    }
    if frozenset(fields) not in exact_shapes:
        raise StateError("task obligation results surface current has an inexact schema")
    if value["id"] != surface_id or value["verdict"] not in {
        "SUPPORTED",
        "FAILED",
        "UNKNOWN",
    }:
        raise StateError("task obligation results surface current is inconsistent")
    if "error" in value and type(value["error"]) is not str:
        raise StateError("task obligation results surface current error is invalid")
    if frozenset(fields) in {frozenset(minimal), frozenset(minimal_timed)}:
        if value["verdict"] != "UNKNOWN" or (
            "timed_out" in value and value["timed_out"] is not False
        ):
            raise StateError("task obligation results surface current is invalid")
        return
    if (
        (value["exit_code"] is not None and type(value["exit_code"]) is not int)
        or type(value["timed_out"]) is not bool
        or value["classification"] not in _SURFACE_CLASSIFICATIONS
        or type(value["stderr"]) is not str
        or type(value["stdout_truncated"]) is not bool
        or type(value["stderr_truncated"]) is not bool
    ):
        raise StateError("task obligation results surface process evidence is invalid")
    process_group = value["process_group"]
    if (
        type(process_group) is not dict
        or set(process_group)
        != {"isolated", "containment", "termination", "detached_sessions"}
        or type(process_group["isolated"]) is not bool
        or process_group["containment"]
        not in {"GROUP_EXIT_CONFIRMED", "UNPROVEN", "NOT_STARTED"}
        or process_group["termination"]
        not in {
            "NOT_REQUIRED",
            "NOT_STARTED",
            "TERM",
            "TERM_THEN_KILL",
            "POST_EXIT_TERM",
            "POST_EXIT_TERM_THEN_KILL",
        }
        or process_group["detached_sessions"] != "NOT_PORTABLY_OBSERVABLE"
    ):
        raise StateError("task obligation results surface process group is invalid")
    for key in ("changed_paths", "unsafe_symlink_paths"):
        if key in value:
            _validate_text_list(value[key], label=f"surface {key}")
    if "normalized_digest" in value and (
        type(value["normalized_digest"]) is not str
        or _SHA256.fullmatch(value["normalized_digest"]) is None
    ):
        raise StateError("task obligation results surface digest is invalid")
    if "external_side_effects" in value and value["external_side_effects"] not in {
        "UNPROVEN_NOT_REVERTED",
        "NOT_OBSERVED_WITHIN_REPOSITORY_BOUNDARY",
    }:
        raise StateError("task obligation results surface side-effect evidence is invalid")


def _validate_surface_result(
    surface_id: str,
    baseline: Mapping[str, Any] | None,
    value: Any,
) -> str:
    if type(value) is not dict or set(value) != {"id", "verdict", "current"}:
        raise StateError("task obligation results surface has an inexact schema")
    _validate_surface_current(value["current"], surface_id=surface_id)
    expected = _surface_result(surface_id, baseline, value["current"])
    if not _exact_json_equal(value, expected):
        raise StateError("task obligation results surface verdict is inconsistent")
    return str(expected["verdict"])


def _validate_obligation_results(
    state: Mapping[str, Any],
    contract: Mapping[str, Any],
    obligations: Mapping[str, Any],
) -> None:
    results = state["obligation_results"]
    if not results:
        if state["lifecycle"] == "TERMINAL":
            raise StateError("task TERMINAL state has no obligation results")
        return
    if set(results) != {"acceptance", "forbidden", "surfaces", "workspace_ownership"}:
        raise StateError("task obligation results have an inexact top-level schema")
    expected_sets = {
        "acceptance": {str(item["id"]) for item in contract["acceptance"]},
        "forbidden": {str(item["id"]) for item in contract["forbidden"]},
        "surfaces": {str(item["id"]) for item in contract["surfaces"]},
    }
    for section, expected in expected_sets.items():
        if type(results[section]) is not dict or set(results[section]) != expected:
            raise StateError(
                f"task obligation results {section} set is incomplete or inexact"
            )

    verdicts: list[str] = []
    for acceptance in contract["acceptance"]:
        acceptance_id = str(acceptance["id"])
        verdicts.append(
            _validate_acceptance_result(
                contract,
                acceptance,
                obligations["acceptance"][acceptance_id],
                results["acceptance"][acceptance_id],
            )
        )
    _validate_ownership_result(
        results["workspace_ownership"], label="workspace ownership"
    )
    verdicts.append(str(results["workspace_ownership"]["verdict"]))
    for rule in contract["forbidden"]:
        rule_id = str(rule["id"])
        verdicts.append(
            _validate_forbidden_result(
                rule,
                obligations["forbidden"][rule_id],
                results["forbidden"][rule_id],
            )
        )
    for surface in contract["surfaces"]:
        surface_id = str(surface["id"])
        verdicts.append(
            _validate_surface_result(
                surface_id,
                obligations["surfaces"].get(surface_id),
                results["surfaces"][surface_id],
            )
        )
    results_aggregate = _aggregate(verdicts)
    lifecycle = state["lifecycle"]
    if lifecycle == "TERMINAL" and results_aggregate != "SUPPORTED":
        raise StateError("task TERMINAL obligation results aggregate is not SUPPORTED")
    if lifecycle == "TERMINAL_ERROR":
        if state["next_action"] != "INSPECT_OR_REFRESH":
            raise StateError(
                "task terminal disposition or execution failure retains stale obligation results"
            )
        if state["aggregate"] != results_aggregate or state["verdict"] != results_aggregate:
            raise StateError("task obligation results aggregate contradicts terminal state")
    elif lifecycle not in {"TERMINAL", "VERIFYING"}:
        raise StateError("task inactive verification results contradict its lifecycle")


def _verification_receipt_id(task_revision: int) -> str:
    if type(task_revision) is not int or task_revision < 1:
        raise StateError("task verification receipt revision is invalid")
    return f"verification-{task_revision}"


def _verification_receipt_payload(
    state: Mapping[str, Any],
    *,
    task_revision: int,
    aggregate: str,
    results: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "version": _VERIFICATION_RECEIPT_VERSION,
        "task_operation_id": _TASK_STATE_ID,
        "task_owner": state["owner"],
        "task_revision": task_revision,
        "contract_digest": state["contract_digest"],
        "task_admission_anchor": state["admission_anchor"],
        "aggregate": aggregate,
        "obligation_results": copy.deepcopy(dict(results)),
    }


def _persist_verification_receipt(
    store: StateStore,
    state: Mapping[str, Any],
    *,
    aggregate: str,
    results: Mapping[str, Any],
) -> dict[str, str]:
    """Create an immutable cooperative anchor for one final task revision."""

    task_revision = int(state["revision"]) + 1
    operation_id = _verification_receipt_id(task_revision)
    payload = _verification_receipt_payload(
        state,
        task_revision=task_revision,
        aggregate=aggregate,
        results=results,
    )
    anchor = _digest(payload)
    store.create(
        operation_id,
        owner=str(state["owner"]),
        receipt=payload,
        admission_anchor=anchor,
    )
    return {"operation_id": operation_id, "anchor": anchor}


def _validate_verification_receipt(
    store: StateStore,
    state: Mapping[str, Any],
) -> None:
    results = state["obligation_results"]
    reference = state["verification_receipt"]
    if not results:
        if reference is not None:
            raise StateError("task without results retains a verification receipt")
        return
    if type(reference) is not dict or set(reference) != {"operation_id", "anchor"}:
        raise StateError("task verification receipt reference has an inexact schema")
    expected_operation_id = _verification_receipt_id(int(state["revision"]))
    if (
        reference["operation_id"] != expected_operation_id
        or type(reference["anchor"]) is not str
        or _SHA256.fullmatch(reference["anchor"]) is None
    ):
        raise StateError("task verification receipt reference is not revision-bound")
    receipt_state = store.load(expected_operation_id)
    if set(receipt_state) != {
        "schema_version",
        "operation_id",
        "owner",
        "lifecycle",
        "verdict",
        "revision",
        "checksum",
        "receipt",
        "admission_anchor",
    }:
        raise StateError("task verification receipt state has an inexact schema")
    if (
        receipt_state["schema_version"] != 2
        or receipt_state["operation_id"] != expected_operation_id
        or receipt_state["owner"] != state["owner"]
        or receipt_state["lifecycle"] != "INITIALIZED"
        or receipt_state["verdict"] != "UNKNOWN"
        or receipt_state["revision"] != 1
    ):
        raise StateError("task verification receipt state is not create-only")
    payload = receipt_state["receipt"]
    if type(payload) is not dict or set(payload) != {
        "version",
        "task_operation_id",
        "task_owner",
        "task_revision",
        "contract_digest",
        "task_admission_anchor",
        "aggregate",
        "obligation_results",
    }:
        raise StateError("task verification receipt payload has an inexact schema")
    expected_anchor = _digest(payload)
    if (
        receipt_state["admission_anchor"] != expected_anchor
        or reference["anchor"] != expected_anchor
    ):
        raise StateError("task verification receipt create-only anchor is invalid")
    if (
        payload["version"] != _VERIFICATION_RECEIPT_VERSION
        or payload["task_operation_id"] != _TASK_STATE_ID
        or payload["task_owner"] != state["owner"]
        or payload["task_revision"] != state["revision"]
        or payload["contract_digest"] != state["contract_digest"]
        or payload["task_admission_anchor"] != state["admission_anchor"]
        or payload["aggregate"] != state["aggregate"]
        or not _exact_json_equal(payload["obligation_results"], results)
    ):
        raise StateError("task verification receipt contradicts the task state")


def _validate_task_envelope(
    state: Mapping[str, Any],
    contract: Mapping[str, Any],
) -> None:
    required_fields = {
        "schema_version",
        "operation_id",
        "owner",
        "lifecycle",
        "verdict",
        "revision",
        "checksum",
        "contract",
        "contract_digest",
        "baseline_snapshot",
        "obligations",
        "admission_anchor",
        "aggregate",
        "obligation_results",
        "verification_receipt",
        "execution_lease",
        "current_operation",
        "next_action",
    }
    optional_fields = {"dispositions"}
    if not required_fields.issubset(state) or not set(state).issubset(
        required_fields | optional_fields
    ):
        raise StateError("task state has an inexact top-level schema")
    aggregate = state["aggregate"]
    if type(aggregate) is not str or aggregate not in {
        "SUPPORTED",
        "FAILED",
        "STALE",
        "UNKNOWN",
    }:
        raise StateError("task aggregate is invalid")
    if type(state["obligation_results"]) is not dict:
        raise StateError("task obligation results must be an object")
    if state["verification_receipt"] is not None and type(
        state["verification_receipt"]
    ) is not dict:
        raise StateError("task verification receipt must be an object or null")
    next_action = state["next_action"]
    if type(next_action) is not str or next_action not in {
        "RUN_BASELINE_OR_CANDIDATE",
        "RUN_CANDIDATE",
        "VERIFY",
        "RECOVER_OR_RECORD_OPERATION",
        "INSPECT_OR_DISPOSE",
        "INSPECT_OR_REFRESH",
        "VERIFY_OR_INSPECT",
        "REUSE_OR_CHECKPOINT",
    }:
        raise StateError("task next action is invalid")

    lifecycle = state["lifecycle"]
    verdict = state["verdict"]
    running = lifecycle in {"RUNNING", "RETRY_WAIT"}
    current = state["current_operation"]
    lease = state["execution_lease"]
    if running:
        if type(current) is not dict or set(current) != {"acceptance", "phase"}:
            raise StateError("running task has an invalid current operation")
        acceptance_ids = {item["id"] for item in contract["acceptance"]}
        if (
            type(current["acceptance"]) is not str
            or current["acceptance"] not in acceptance_ids
            or type(current["phase"]) is not str
            or current["phase"] not in {"baseline", "candidate"}
        ):
            raise StateError("running task current operation is not contract-bound")
        if (
            type(lease) is not dict
            or set(lease)
            != {"version", "device", "inode", "root_device", "root_inode"}
            or lease["version"] != "taskguard-execution-lease-v1"
            or any(
                type(lease[key]) is not int or lease[key] < 0
                for key in ("device", "inode", "root_device", "root_inode")
            )
        ):
            raise StateError("running task execution lease is invalid")
        if verdict != "UNKNOWN" or aggregate != "UNKNOWN":
            raise StateError("running task must remain fail-closed UNKNOWN")
    elif current is not None or lease is not None:
        raise StateError("inactive task retains impossible execution evidence")

    if lifecycle == "INITIALIZED":
        if verdict != "UNKNOWN" or aggregate != "UNKNOWN":
            raise StateError("initialized task must remain UNKNOWN")
    elif lifecycle == "VERIFYING":
        if verdict != "UNKNOWN" or aggregate != "UNKNOWN":
            raise StateError("verifying task must remain UNKNOWN")
    elif lifecycle == "TERMINAL":
        if verdict != "SUPPORTED" or aggregate != "SUPPORTED":
            raise StateError("terminal task lacks supported aggregate evidence")
    elif lifecycle == "TERMINAL_ERROR":
        if verdict not in {"FAILED", "STALE", "UNKNOWN"} or aggregate != verdict:
            raise StateError("terminal-error task verdict and aggregate are inconsistent")
    elif not running:
        raise StateError("task lifecycle is not produced by the controller")

    allowed_next_actions = {
        "INITIALIZED": {"RUN_BASELINE_OR_CANDIDATE", "RUN_CANDIDATE", "VERIFY"},
        "RUNNING": {"RECOVER_OR_RECORD_OPERATION"},
        "RETRY_WAIT": {"RECOVER_OR_RECORD_OPERATION"},
        "VERIFYING": {"VERIFY"},
        "TERMINAL": {"REUSE_OR_CHECKPOINT"},
        "TERMINAL_ERROR": {
            "INSPECT_OR_DISPOSE",
            "INSPECT_OR_REFRESH",
            "VERIFY_OR_INSPECT",
        },
    }
    if next_action not in allowed_next_actions[lifecycle]:
        raise StateError("task next action contradicts its lifecycle")

    if "dispositions" in state:
        dispositions = state["dispositions"]
        if type(dispositions) is not list or not dispositions:
            raise StateError("task dispositions must be a non-empty array")
        seen: set[tuple[str, str]] = set()
        for disposition in dispositions:
            if type(disposition) is not dict or set(disposition) != {
                "acceptance",
                "phase",
                "operation_id",
                "operation_revision",
                "verdict",
                "rerun",
            }:
                raise StateError("task disposition has an inexact schema")
            acceptance_id = disposition["acceptance"]
            phase = disposition["phase"]
            if (
                type(acceptance_id) is not str
                or acceptance_id not in {item["id"] for item in contract["acceptance"]}
                or type(phase) is not str
                or phase not in {"baseline", "candidate"}
                or disposition["operation_id"]
                != _operation_id(str(contract["task_id"]), acceptance_id, str(phase))
                or type(disposition["verdict"]) is not str
                or disposition["verdict"] not in {"FAILED", "UNKNOWN"}
                or disposition["rerun"] is not False
            ):
                raise StateError("task disposition contradicts its contract binding")
            operation_revision = disposition["operation_revision"]
            if operation_revision is not None and (
                type(operation_revision) is not int or operation_revision < 1
            ):
                raise StateError("task disposition operation revision is invalid")
            key = (acceptance_id, str(phase))
            if key in seen:
                raise StateError("task disposition is duplicated")
            seen.add(key)


def _acceptance_binding(acceptance: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "version": _ACCEPTANCE_BINDING_VERSION,
        "id": acceptance.get("id"),
        "argv": list(acceptance.get("argv", [])),
        "cwd": acceptance.get("cwd"),
        "selector": acceptance.get("selector"),
        "idempotent": acceptance.get("idempotent"),
        "requires_red": acceptance.get("requires_red"),
        "expected_red_pattern": acceptance.get("expected_red_pattern"),
    }


def _state_path(state_dir: Path, operation_id: str) -> Path:
    return state_dir / f"{operation_id}.json"


def _load_task(
    state_dir: Path,
    *,
    store: StateStore | None = None,
) -> tuple[StateStore, dict[str, Any]]:
    store = StateStore(state_dir) if store is None else store
    state = store.load(_TASK_STATE_ID)
    contract = _validate_task_contract(state.get("contract"))
    _validate_task_envelope(state, contract)
    if contract.get("binding_version") != _CONTRACT_BINDING_VERSION:
        raise StateError("task state has no valid canonical contract binding")
    if state.get("contract_digest") != _digest(contract):
        raise StateError("task contract binding digest does not match canonical state")
    obligations = _validate_task_obligations(contract, state.get("obligations"))
    baseline_manifest = state.get("baseline_snapshot")
    try:
        baseline = WorkspaceSnapshot.from_manifest(baseline_manifest)
    except ScopeViolation as exc:
        raise StateError(f"task admission baseline is invalid: {exc}") from exc
    if (
        not _exact_json_equal(baseline_manifest, baseline.to_manifest())
        or str(baseline.repo) != contract["repo"]
        or list(baseline.scope) != contract["scope"]
        or list(baseline.acknowledged_dirty) != contract["acknowledge_dirty"]
    ):
        raise StateError("task admission baseline contradicts the canonical contract")
    expected_anchor = _digest(
        _admission_manifest(contract, baseline_manifest, obligations)
    )
    if state.get("admission_anchor") != expected_anchor:
        raise StateError("task admission anchor does not match immutable baseline evidence")
    _validate_disposition_consistency(state, contract, obligations)
    _validate_obligation_results(state, contract, obligations)
    _validate_verification_receipt(store, state)
    return store, state


def _owner_for_operations(task_owner: str) -> str:
    return "task-operations-" + hashlib.sha256(task_owner.encode("utf-8")).hexdigest()[:24]


def _selected(path: str, selectors: Iterable[str]) -> bool:
    candidate = path.rstrip("/")
    for selector in selectors:
        normalized = selector.rstrip("/")
        if normalized == ".":
            return True
        if not any(character in selector for character in "*?["):
            if candidate == normalized or candidate.startswith(normalized + "/"):
                return True
        elif fnmatch.fnmatchcase(candidate, selector) or PurePosixPath(candidate).match(selector):
            return True
    return False


def _expand_scan_files(repo: Path, glob: str) -> list[Path]:
    try:
        raw_matches = list(repo.glob(glob))
    except (OSError, RuntimeError, ValueError) as exc:
        raise ScopeViolation(f"cannot expand forbidden glob {glob!r}: {exc}") from exc
    candidates: list[Path] = []
    for match in raw_matches:
        if match.is_dir() and not match.is_symlink():
            try:
                candidates.extend(path for path in match.rglob("*") if path.is_file() or path.is_symlink())
            except OSError as exc:
                raise ScopeViolation(f"cannot enumerate forbidden directory {match}: {exc}") from exc
        else:
            candidates.append(match)
    return sorted(set(candidates), key=lambda path: path.as_posix())


def _scan_forbidden_rule(repo: Path, rule: Mapping[str, Any]) -> dict[str, Any]:
    rule_id = rule.get("id")
    glob = rule.get("glob")
    pattern = rule.get("regex")
    mode = rule.get("mode")
    if not all(isinstance(value, str) for value in (rule_id, glob, pattern, mode)):
        return {"id": rule_id, "verdict": "UNKNOWN", "error": "invalid persisted forbidden rule"}
    try:
        matcher = re.compile(pattern)
    except re.error as exc:
        return {"id": rule_id, "verdict": "UNKNOWN", "error": f"invalid persisted regex: {exc}"}
    matches: list[dict[str, Any]] = []
    try:
        for path in _expand_scan_files(repo, glob):
            try:
                resolved = path.resolve(strict=True)
                relative = resolved.relative_to(repo).as_posix()
            except (OSError, RuntimeError, ValueError) as exc:
                raise ScopeViolation(f"forbidden scan path escaped the repository: {path}: {exc}") from exc
            if path.is_symlink():
                raise ScopeViolation(f"forbidden scan refuses symlink input: {path.relative_to(repo)}")
            try:
                size = path.stat().st_size
            except OSError as exc:
                raise ScopeViolation(f"cannot inspect forbidden scan file {relative}: {exc}") from exc
            if size > _MAX_SCAN_FILE_BYTES:
                raise ScopeViolation(f"forbidden scan file exceeds {_MAX_SCAN_FILE_BYTES} bytes: {relative}")
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                raise ScopeViolation(f"cannot read forbidden scan file {relative}: {exc}") from exc
            for found in matcher.finditer(text):
                line = text.count("\n", 0, found.start()) + 1
                token = found.group(0)
                matches.append(
                    {
                        "path": relative,
                        "line": line,
                        "digest": hashlib.sha256(token.encode("utf-8", "replace")).hexdigest(),
                    }
                )
    except ScopeViolation as exc:
        return {"id": rule_id, "mode": mode, "verdict": "UNKNOWN", "error": str(exc), "matches": []}
    return {
        "id": rule_id,
        "mode": mode,
        "matcher_version": "python-re-v1",
        "verdict": "SUPPORTED",
        "matches": matches,
    }


def _scan_forbidden(repo: Path, rules: Sequence[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    return {str(rule.get("id")): _scan_forbidden_rule(repo, rule) for rule in rules}


def _forbidden_verdict(
    rule: Mapping[str, Any],
    baseline: Mapping[str, Any] | None,
    current: Mapping[str, Any],
) -> dict[str, Any]:
    if current.get("verdict") != "SUPPORTED" or not isinstance(baseline, Mapping):
        return {"id": rule.get("id"), "verdict": "UNKNOWN", "current": current}
    mode = rule.get("mode")
    current_matches = current.get("matches") if isinstance(current.get("matches"), list) else []
    if mode == "eliminate":
        verdict = "SUPPORTED" if not current_matches else "FAILED"
        return {"id": rule.get("id"), "verdict": verdict, "current": current}
    if baseline.get("verdict") != "SUPPORTED" or mode != "no_new":
        return {"id": rule.get("id"), "verdict": "UNKNOWN", "current": current}
    baseline_keys = {
        (item.get("path"), item.get("line"), item.get("digest"))
        for item in baseline.get("matches", [])
        if isinstance(item, Mapping)
    }
    new_matches = [
        item
        for item in current_matches
        if isinstance(item, Mapping)
        and (item.get("path"), item.get("line"), item.get("digest")) not in baseline_keys
    ]
    return {
        "id": rule.get("id"),
        "verdict": "SUPPORTED" if not new_matches else "FAILED",
        "current": current,
        "new_matches": new_matches,
    }


def _normalize_surface(stdout: str, version: str) -> bytes:
    if version == "json-v1":
        try:
            return _json_bytes(json.loads(stdout))
        except json.JSONDecodeError as exc:
            raise ScopeViolation(f"surface output is not valid JSON: {exc}") from exc
    if version == "text-v1":
        normalized = "\n".join(line.rstrip() for line in stdout.replace("\r\n", "\n").split("\n")).strip()
        return normalized.encode("utf-8")
    raise ScopeViolation(f"unsupported surface normalizer: {version!r}")


def _validate_allowed_write_literal(repo: Path, relative: str) -> None:
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ScopeViolation(f"surface allowed write escapes repository: {relative!r}")
    parent = path.parent.as_posix()
    parent = "." if parent == "." else parent
    metadata = repo.lstat()
    with _nofollow_runtime_cwd(
        repo,
        parent,
        expected_repo_identity=(metadata.st_dev, metadata.st_ino),
    ):
        candidate = repo / path
        try:
            target_metadata = candidate.lstat()
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ScopeViolation(f"cannot inspect surface allowed write {relative!r}: {exc}") from exc
        if stat.S_ISLNK(target_metadata.st_mode):
            raise ScopeViolation(f"surface allowed write is a symlink escape: {relative!r}")


def _validate_surface_allowed_writes(repo: Path, selectors: Sequence[str]) -> None:
    for selector in selectors:
        if not isinstance(selector, str):
            raise ScopeViolation("surface allowed_writes contains a non-string selector")
        if any(character in selector for character in "*?["):
            literal_parts: list[str] = []
            for part in PurePosixPath(selector).parts:
                if any(character in part for character in "*?["):
                    break
                literal_parts.append(part)
            if literal_parts:
                _validate_allowed_write_literal(repo, PurePosixPath(*literal_parts).as_posix())
            try:
                matches = list(repo.glob(selector))
            except (OSError, RuntimeError, ValueError) as exc:
                raise ScopeViolation(f"cannot expand surface allowed write {selector!r}: {exc}") from exc
            for match in matches:
                try:
                    relative = match.relative_to(repo).as_posix()
                except ValueError as exc:
                    raise ScopeViolation(f"surface allowed write escaped repository: {match}") from exc
                _validate_allowed_write_literal(repo, relative)
        else:
            _validate_allowed_write_literal(repo, selector)


def _run_surface(
    repo: Path,
    surface: Mapping[str, Any],
    *,
    normalized_observer: Callable[[bytes], None] | None = None,
) -> dict[str, Any]:
    surface_id = surface.get("id")
    try:
        repo = repo.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        return {"id": surface_id, "verdict": "UNKNOWN", "error": f"cannot resolve surface repo: {exc}"}
    argv = surface.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(item, str) for item in argv):
        return {"id": surface_id, "verdict": "UNKNOWN", "error": "invalid persisted surface argv"}
    if surface.get("read_only") is not True:
        return {"id": surface_id, "verdict": "UNKNOWN", "error": "surface is not declared read-only"}
    before: WorkspaceSnapshot | None = None
    try:
        before = WorkspaceSnapshot.capture(repo, scope=["."])
        allowed = surface.get("allowed_writes")
        if not isinstance(allowed, list):
            raise ScopeViolation("surface allowed_writes must be an array")
        _validate_surface_allowed_writes(repo, allowed)
        metadata = repo.lstat()
        expected_identity = (metadata.st_dev, metadata.st_ino)
        with _nofollow_runtime_cwd(
            repo,
            surface.get("cwd"),
            expected_repo_identity=expected_identity,
        ) as cwd:
            completed = _bounded_process(
                list(argv),
                cwd=cwd,
                timeout=_SURFACE_TIMEOUT_SECONDS,
            )
        raw_stdout, raw_stderr = completed.stdout, completed.stderr
        timed_out = completed.timed_out
        exit_code: int | None = completed.exit_code
        process_group = completed.process_group
    except (OSError, ScopeViolation, CliInputError, ValueError) as exc:
        return {
            "id": surface_id,
            "verdict": "UNKNOWN",
            "timed_out": False,
            "error": str(exc),
        }
    classification = classify_failure(
        exit_code=exit_code,
        timed_out=timed_out,
        stdout=raw_stdout.decode("utf-8", "replace") if isinstance(raw_stdout, bytes) else (raw_stdout or ""),
        stderr=raw_stderr.decode("utf-8", "replace") if isinstance(raw_stderr, bytes) else (raw_stderr or ""),
    )
    if process_group.get("containment") == "UNPROVEN":
        classification = "TIMEOUT"
    stdout, stdout_truncated = _redact_and_bound(raw_stdout, _OUTPUT_LIMIT)
    stderr, stderr_truncated = _redact_and_bound(raw_stderr, _OUTPUT_LIMIT)
    truncated = stdout_truncated or stderr_truncated
    if truncated:
        classification = "UNKNOWN"
    record: dict[str, Any] = {
        "id": surface_id,
        "verdict": "UNKNOWN",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "classification": classification,
        "stderr": stderr,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "process_group": process_group,
    }
    if process_group.get("containment") == "UNPROVEN":
        record["error"] = (
            "surface process containment is unproven; detached-session side effects "
            "cannot be proven absent or reverted"
        )
        record["external_side_effects"] = "UNPROVEN_NOT_REVERTED"
    elif classification != "SUCCESS" or truncated:
        record["error"] = "surface command failed or normalized output was truncated"
    try:
        after = WorkspaceSnapshot.capture(repo, scope=["."])
        comparison = after.compare_to(before) if before is not None else None
    except ScopeViolation as exc:
        record["error"] = f"surface workspace comparison unavailable: {exc}"
        record["external_side_effects"] = "UNPROVEN_NOT_REVERTED"
        return record
    changed = tuple(comparison.changed_paths) if comparison is not None else ()
    allowed = surface.get("allowed_writes") if isinstance(surface.get("allowed_writes"), list) else []
    disallowed = [path for path in changed if path != "<git-head>" and not _selected(path, allowed)]
    if comparison is None or not before.stable or not after.stable:
        record["error"] = "surface workspace comparison is unstable or unavailable"
        record["changed_paths"] = list(changed)
        record["external_side_effects"] = "UNPROVEN_NOT_REVERTED"
        return record
    if "<git-head>" in changed or disallowed:
        record["verdict"] = "FAILED"
        record["error"] = "read-only surface command changed disallowed workspace paths"
        record["changed_paths"] = list(changed)
        record["external_side_effects"] = "UNPROVEN_NOT_REVERTED"
        return record
    if comparison.status == "UNKNOWN" and changed:
        record["error"] = "surface workspace delta is not exact"
        record["changed_paths"] = list(changed)
        return record
    unsafe_links = [
        path
        for path in changed
        if path != "<git-head>"
        and after.files.get(path) is not None
        and after.files[path].kind in {"symlink", "ancestor-symlink"}
    ]
    if unsafe_links:
        record["verdict"] = "FAILED"
        record["error"] = (
            "surface command created or modified a symlink boundary; repository-external "
            "side effects cannot be proven absent or reverted"
        )
        record["changed_paths"] = list(changed)
        record["unsafe_symlink_paths"] = unsafe_links
        record["external_side_effects"] = "UNPROVEN_NOT_REVERTED"
        return record
    if process_group.get("containment") == "UNPROVEN":
        record["changed_paths"] = list(changed)
        return record
    if classification != "SUCCESS" or truncated:
        record["changed_paths"] = list(changed)
        record["external_side_effects"] = "UNPROVEN_NOT_REVERTED"
        return record
    try:
        _validate_surface_allowed_writes(repo, allowed)
    except ScopeViolation as exc:
        record["verdict"] = "FAILED"
        record["error"] = (
            f"post-run surface write boundary is unsafe: {exc}; external side effects "
            "cannot be proven absent or reverted"
        )
        record["changed_paths"] = list(changed)
        record["external_side_effects"] = "UNPROVEN_NOT_REVERTED"
        return record
    try:
        normalized = _normalize_surface(stdout, str(surface.get("normalizer_version")))
    except ScopeViolation as exc:
        record["error"] = str(exc)
        return record
    if normalized_observer is not None:
        normalized_observer(normalized)
    record["verdict"] = "SUPPORTED"
    record["normalized_digest"] = hashlib.sha256(normalized).hexdigest()
    record["changed_paths"] = list(changed)
    record["external_side_effects"] = "NOT_OBSERVED_WITHIN_REPOSITORY_BOUNDARY"
    return record


def _aggregate(verdicts: Iterable[str]) -> str:
    values = list(verdicts)
    if not values:
        return "SUPPORTED"
    return max(values, key=lambda value: _PRECEDENCE.get(value, _PRECEDENCE["UNKNOWN"]))


def _deterministic_scope_failure(exc: ScopeViolation) -> bool:
    return str(exc).startswith("new out-of-scope workspace change:")


def _workspace_freshness(
    contract: Mapping[str, Any],
    success_manifest: Any,
    task_baseline_manifest: Any,
    persisted_ownership: Any,
) -> dict[str, Any]:
    if not isinstance(success_manifest, Mapping) or not isinstance(task_baseline_manifest, Mapping):
        return {"verdict": "UNKNOWN", "reason": "missing task or successful workspace snapshot"}
    try:
        task_baseline = WorkspaceSnapshot.from_manifest(task_baseline_manifest)
        success = WorkspaceSnapshot.from_manifest(success_manifest)
        ownership = _workspace_ownership_proof(task_baseline, success)
        if not isinstance(persisted_ownership, Mapping) or dict(persisted_ownership) != ownership:
            return {
                "verdict": "UNKNOWN",
                "reason": "persisted task-owned workspace proof does not revalidate",
                "ownership": ownership,
            }
        if ownership["verdict"] != "SUPPORTED":
            return {
                "verdict": ownership["verdict"],
                "reason": ownership["reason"],
                "ownership": ownership,
            }
        current = WorkspaceSnapshot.capture(
            Path(str(contract["repo"])),
            scope=list(contract["scope"]),
            acknowledged_dirty=list(contract.get("acknowledge_dirty", [])),
        )
        freshness = _exact_command_freshness(current, success, ownership)
    except ScopeViolation as exc:
        verdict = "FAILED" if _deterministic_scope_failure(exc) else "UNKNOWN"
        return {"verdict": verdict, "reason": str(exc)}
    return {
        "verdict": freshness["verdict"],
        "status": freshness["status"],
        "changed_paths": list(freshness["changed_paths"]),
        "warnings": list(current.warnings),
        "ownership": ownership,
    }


def _current_workspace_ownership(
    contract: Mapping[str, Any],
    task_baseline_manifest: Any,
) -> dict[str, Any]:
    if not isinstance(task_baseline_manifest, Mapping):
        return {"verdict": "UNKNOWN", "reason": "missing task workspace baseline"}
    try:
        baseline = WorkspaceSnapshot.from_manifest(task_baseline_manifest)
        current = WorkspaceSnapshot.capture(
            Path(str(contract["repo"])),
            scope=list(contract["scope"]),
            acknowledged_dirty=list(contract.get("acknowledge_dirty", [])),
        )
        return _workspace_ownership_proof(baseline, current)
    except ScopeViolation as exc:
        return {
            "verdict": "FAILED" if _deterministic_scope_failure(exc) else "UNKNOWN",
            "reason": str(exc),
        }


def _acceptance_verdict(
    acceptance: Mapping[str, Any],
    evidence: Mapping[str, Any],
    contract: Mapping[str, Any],
    task_baseline_manifest: Any,
    *,
    state_dir: Path,
    task_owner: str,
) -> dict[str, Any]:
    expected_binding = _digest(_acceptance_binding(acceptance))
    verdicts: list[str] = []
    detail: dict[str, Any] = {"id": acceptance.get("id")}
    try:
        task_baseline = WorkspaceSnapshot.from_manifest(task_baseline_manifest)
    except ScopeViolation as exc:
        detail["ledger_error"] = f"task baseline cannot be reconstructed: {exc}"
        task_baseline = None

    def audited_phase(phase: str) -> tuple[str, dict[str, Any] | None]:
        persisted = evidence.get(phase)
        if type(persisted) is not dict:
            return "UNKNOWN", None
        if persisted.get("binding_digest") != expected_binding:
            return "FAILED", None
        if task_baseline is None:
            return "UNKNOWN", None
        operation = Operation(
            id=_operation_id(str(contract["task_id"]), str(acceptance["id"]), phase),
            argv=list(acceptance["argv"]),
            cwd=str(acceptance["cwd"]),
            scope=list(contract["scope"]),
            selector=acceptance.get("selector"),
            idempotent=acceptance.get("idempotent"),
        )
        operation_path = state_dir / "operations" / f"{operation.id}.json"
        if not os.path.lexists(operation_path):
            return "UNKNOWN", {"reason": "checksummed operation ledger is absent"}
        runner = TaskRunner(
            state_root=state_dir / "operations",
            workspace_root=Path(str(contract["repo"])),
            owner=_owner_for_operations(task_owner),
        )
        try:
            audited = runner.audit(operation, ownership_baseline=task_baseline)
            reconstructed = _phase_evidence(phase, acceptance, audited)
        except (ConcurrentUpdateError, StateError, ScopeViolation, TypeError, ValueError) as exc:
            return "UNKNOWN", {"reason": f"operation ledger did not revalidate: {exc}"}
        if not _exact_json_equal(persisted, reconstructed):
            return "UNKNOWN", {
                "reason": "task phase receipt does not match the audited operation ledger"
            }
        return str(reconstructed["verdict"]), {
            "operation_id": audited.operation_id,
            "state_revision": audited.state_revision,
            "attempts": audited.attempts,
        }

    if acceptance.get("requires_red") is True:
        baseline_verdict, baseline_audit = audited_phase("baseline")
        detail["baseline"] = baseline_verdict
        if baseline_audit is not None:
            detail["baseline_audit"] = baseline_audit
        verdicts.append(baseline_verdict)
    candidate = evidence.get("candidate")
    candidate_verdict, candidate_audit = audited_phase("candidate")
    detail["candidate"] = candidate_verdict
    if candidate_audit is not None:
        detail["candidate_audit"] = candidate_audit
    verdicts.append(candidate_verdict)
    if isinstance(candidate, Mapping):
        freshness = _workspace_freshness(
            contract,
            candidate.get("workspace_success"),
            task_baseline_manifest,
            candidate.get("workspace_ownership"),
        )
    else:
        freshness = {"verdict": "UNKNOWN", "reason": "candidate evidence is absent"}
    detail["freshness"] = freshness
    verdicts.append(str(freshness["verdict"]))
    detail["verdict"] = _aggregate(verdicts)
    return detail


def _evaluate(
    state: Mapping[str, Any],
    *,
    execute_surfaces: bool,
    state_dir: Path,
) -> tuple[str, dict[str, Any]]:
    contract = state["contract"]
    repo = Path(str(contract["repo"]))
    obligations = state["obligations"]
    acceptance_evidence = obligations.get("acceptance", {})
    results: dict[str, Any] = {"acceptance": {}, "forbidden": {}, "surfaces": {}}
    verdicts: list[str] = []
    for acceptance in contract.get("acceptance", []):
        acceptance_id = str(acceptance.get("id"))
        evidence = acceptance_evidence.get(acceptance_id, {}) if isinstance(acceptance_evidence, Mapping) else {}
        detail = _acceptance_verdict(
            acceptance,
            evidence,
            contract,
            state.get("baseline_snapshot"),
            state_dir=state_dir,
            task_owner=str(state.get("owner")),
        )
        results["acceptance"][acceptance_id] = detail
        verdicts.append(detail["verdict"])

    ownership = _current_workspace_ownership(contract, state.get("baseline_snapshot"))
    results["workspace_ownership"] = ownership
    verdicts.append(str(ownership.get("verdict", "UNKNOWN")))

    forbidden_rules = contract.get("forbidden", [])
    current_forbidden = _scan_forbidden(repo, forbidden_rules)
    baseline_forbidden = obligations.get("forbidden", {})
    for rule in forbidden_rules:
        rule_id = str(rule.get("id"))
        baseline = baseline_forbidden.get(rule_id) if isinstance(baseline_forbidden, Mapping) else None
        detail = _forbidden_verdict(rule, baseline, current_forbidden[rule_id])
        results["forbidden"][rule_id] = detail
        verdicts.append(detail["verdict"])

    previous_results = state.get("obligation_results", {})
    previous_surfaces = previous_results.get("surfaces", {}) if isinstance(previous_results, Mapping) else {}
    baseline_surfaces = obligations.get("surfaces", {})
    for surface in contract.get("surfaces", []):
        surface_id = str(surface.get("id"))
        if execute_surfaces:
            current = _run_surface(repo, surface)
            baseline = baseline_surfaces.get(surface_id) if isinstance(baseline_surfaces, Mapping) else None
            detail = _surface_result(surface_id, baseline, current)
        else:
            prior = previous_surfaces.get(surface_id) if isinstance(previous_surfaces, Mapping) else None
            detail = copy.deepcopy(prior) if isinstance(prior, Mapping) else {"id": surface_id, "verdict": "UNKNOWN"}
        results["surfaces"][surface_id] = detail
        verdicts.append(str(detail.get("verdict", "UNKNOWN")))

    if state.get("lifecycle") in {"RUNNING", "RETRY_WAIT"} or state.get("current_operation") is not None:
        verdicts.append("UNKNOWN")
        results["recovery"] = {"verdict": "UNKNOWN", "reason": "interrupted operation"}
    return _aggregate(verdicts), results


def _operation_id(task_id: str, acceptance_id: str, phase: str) -> str:
    encoded = f"{task_id}\0{acceptance_id}\0{phase}".encode("utf-8")
    return "phase-" + hashlib.sha256(encoded).hexdigest()[:32]


def _find_acceptance(contract: Mapping[str, Any], acceptance_id: str) -> Mapping[str, Any]:
    for acceptance in contract.get("acceptance", []):
        if isinstance(acceptance, Mapping) and acceptance.get("id") == acceptance_id:
            return acceptance
    raise CliInputError(f"unknown acceptance id: {acceptance_id}")


def _command_init(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    state_dir = Path(arguments.state_dir)
    store = StateStore(state_dir)
    if os.path.lexists(_state_path(state_dir, _TASK_STATE_ID)):
        # Loading first distinguishes a valid prior task from corrupt state; neither is reset.
        store.load(_TASK_STATE_ID)
        raise CliInputError("task state already exists; init refuses to replace it")
    contract = load_contract(arguments.contract, workspace_root=Path.cwd())
    if contract.risk == "L3":
        raise AdmissionFailure(
            "L3 is unsupported by TaskGuard v2 until authority, dry-run, rollback, "
            "and health obligations are structurally bound"
        )
    if contract.risk == "L2":
        from .chain import require_stage

        require_stage(
            state_dir,
            task_id=contract.task_id,
            goal=contract.goal,
            scope=list(contract.scope),
            stage="initial",
            risk="L2",
        )
    manifest = _contract_manifest(contract)
    baseline = WorkspaceSnapshot.capture(
        contract.repo,
        scope=list(contract.scope),
        acknowledged_dirty=list(contract.acknowledge_dirty),
    )
    if not baseline.stable:
        raise AdmissionFailure("workspace admission evidence is unstable")
    if baseline.unacknowledged_dirty:
        raise AdmissionFailure(
            "unacknowledged in-scope dirty paths: " + ", ".join(baseline.unacknowledged_dirty)
        )
    forbidden = _scan_forbidden(contract.repo, manifest["forbidden"])
    normalized_surfaces: dict[str, bytes] = {}
    surfaces: dict[str, dict[str, Any]] = {}
    for surface in manifest["surfaces"]:
        surface_id = str(surface.get("id"))
        surfaces[surface_id] = _run_surface(
            contract.repo,
            surface,
            normalized_observer=lambda output, key=surface_id: normalized_surfaces.__setitem__(
                key, output
            ),
        )
    conflicts: list[str] = []
    for rule in manifest["forbidden"]:
        if rule.get("mode") != "eliminate":
            continue
        matcher = re.compile(str(rule["regex"]))
        for surface_id, normalized in normalized_surfaces.items():
            if matcher.search(normalized.decode("utf-8", errors="replace")) is not None:
                conflicts.append(
                    f"eliminate rule {rule['id']!r} matches frozen surface {surface_id!r}"
                )
    if conflicts:
        raise AdmissionFailure(
            "contract conflict: "
            + "; ".join(conflicts)
            + "; freeze only stable interface fields and exclude semantics declared for elimination"
        )
    # Read-only surface adapters must not silently change the admitted baseline.
    baseline = WorkspaceSnapshot.capture(
        contract.repo,
        scope=list(contract.scope),
        acknowledged_dirty=list(contract.acknowledge_dirty),
    )
    owner = "task-" + secrets.token_hex(12)
    acceptance_records = {
        str(item["id"]): {
            "binding_digest": _digest(_acceptance_binding(item)),
            "baseline": None if item["requires_red"] else {"verdict": "NOT_REQUIRED"},
            "candidate": None,
        }
        for item in manifest["acceptance"]
    }
    baseline_manifest = baseline.to_manifest()
    obligations = {
        "acceptance": acceptance_records,
        "forbidden": forbidden,
        "surfaces": surfaces,
    }
    state = store.create(
        _TASK_STATE_ID,
        owner=owner,
        contract=manifest,
        contract_digest=_digest(manifest),
        baseline_snapshot=baseline_manifest,
        obligations=obligations,
        admission_anchor=_digest(
            _admission_manifest(manifest, baseline_manifest, obligations)
        ),
        aggregate="UNKNOWN",
        obligation_results={},
        verification_receipt=None,
        execution_lease=None,
        current_operation=None,
        next_action="RUN_BASELINE_OR_CANDIDATE",
    )
    return {
        "aggregate": "UNKNOWN",
        "lifecycle": state["lifecycle"],
        "revision": state["revision"],
        "task_id": manifest["task_id"],
    }, 0


def _validate_optional_contract(path: str, expected_state: Mapping[str, Any]) -> None:
    candidate = _contract_manifest(load_contract(path, workspace_root=Path.cwd()))
    if _digest(candidate) != expected_state.get("contract_digest") or candidate != expected_state.get("contract"):
        raise CliInputError("contract binding drift: supplied contract does not match initialized task")


def _phase_evidence(
    phase: str,
    acceptance: Mapping[str, Any],
    result: RunResult,
) -> dict[str, Any]:
    binding_digest = _digest(_acceptance_binding(acceptance))
    if phase == "baseline":
        valid = valid_expected_red(
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stdout=result.stdout,
            stderr=result.stderr,
            expected_literal=acceptance.get("expected_red_pattern"),
            failure_markers=result.failure_markers,
        )
        verdict = "SUPPORTED" if valid else ("UNKNOWN" if result.verdict == "UNKNOWN" else "FAILED")
    else:
        valid = (
            result.exit_code == 0
            and not result.timed_out
            and result.classification == "SUCCESS"
            and result.verdict == "SUPPORTED"
        )
        if valid:
            verdict = "SUPPORTED"
        elif result.verdict in {"UNKNOWN", "STALE"}:
            verdict = result.verdict
        else:
            verdict = "FAILED"
    return {
        "phase": phase,
        "binding_digest": binding_digest,
        "verdict": verdict,
        "process": result.to_manifest(),
        "workspace_success": result.workspace_snapshot,
        "workspace_ownership": result.workspace_ownership,
    }


def _command_run(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    state_dir = Path(arguments.state_dir)
    store = StateStore(state_dir)
    snapshot = store.load_snapshot(_TASK_STATE_ID)
    if snapshot.get("contract", {}).get("risk") == "L3":
        raise AdmissionFailure("existing L3 task state is unsupported by TaskGuard v2")
    with store.execution_lease(_TASK_STATE_ID, blocking=True) as task_lease:
        return _command_run_with_lease(
            arguments,
            store=store,
            task_lease=task_lease,
        )


def _command_run_with_lease(
    arguments: argparse.Namespace,
    *,
    store: StateStore,
    task_lease: ExecutionLease,
) -> tuple[dict[str, Any], int]:
    state_dir = Path(arguments.state_dir)
    store, state = _load_task(state_dir, store=store)
    if arguments.contract:
        _validate_optional_contract(arguments.contract, state)
    contract = state["contract"]
    acceptance = _find_acceptance(contract, arguments.acceptance)
    acceptance_id = str(acceptance["id"])
    obligations = copy.deepcopy(state["obligations"])
    acceptance_records = obligations.get("acceptance")
    if not isinstance(acceptance_records, dict) or not isinstance(acceptance_records.get(acceptance_id), dict):
        raise StateError(f"missing acceptance obligation record: {acceptance_id}")
    record = acceptance_records[acceptance_id]
    if arguments.phase == "candidate" and acceptance.get("requires_red") is True:
        baseline = record.get("baseline")
        if not isinstance(baseline, Mapping):
            raise CliInputError("candidate cannot run before the required baseline phase")
    existing = record.get(arguments.phase)
    if isinstance(existing, Mapping) and existing.get("verdict") != "NOT_REQUIRED":
        raise CliInputError(f"duplicate phase evidence is not allowed: {acceptance_id}/{arguments.phase}")
    if arguments.phase == "baseline" and acceptance.get("requires_red") is not True:
        raise CliInputError("baseline is not required for this acceptance")
    operation = Operation(
        id=_operation_id(str(contract["task_id"]), acceptance_id, arguments.phase),
        argv=list(acceptance["argv"]),
        cwd=str(acceptance["cwd"]),
        scope=list(contract["scope"]),
        selector=acceptance.get("selector"),
        idempotent=acceptance.get("idempotent"),
    )
    try:
        task_baseline = WorkspaceSnapshot.from_manifest(state.get("baseline_snapshot"))
    except ScopeViolation as exc:
        raise StateError(f"task workspace baseline cannot be reconstructed: {exc}") from exc
    runner = TaskRunner(
        state_root=state_dir / "operations",
        workspace_root=Path(str(contract["repo"])),
        owner=_owner_for_operations(str(state["owner"])),
    )

    # Validate the live cwd before changing task lifecycle; TaskRunner repeats
    # the same no-follow validation immediately before every subprocess.
    repo = Path(str(contract["repo"]))
    metadata = repo.lstat()
    with _nofollow_runtime_cwd(
        repo,
        str(acceptance["cwd"]),
        expected_repo_identity=(metadata.st_dev, metadata.st_ino),
    ):
        pass

    current_ownership = _current_workspace_ownership(contract, state.get("baseline_snapshot"))
    if current_ownership.get("verdict") == "FAILED":
        blocked = RunResult(
            operation_id=operation.id,
            lifecycle="TERMINAL_ERROR",
            verdict="FAILED",
            attempts=0,
            reuse_status="EXECUTION_BLOCKED",
            classification="SCOPE",
            exit_code=None,
            timed_out=False,
            stdout="",
            stderr=str(current_ownership.get("reason", "workspace ownership policy failed")),
            state_revision=state["revision"],
            failure_markers=("SCOPE",),
            workspace_snapshot=None,
            workspace_ownership=current_ownership,
        )
        evidence = _phase_evidence(arguments.phase, acceptance, blocked)
        obligations["acceptance"][acceptance_id][arguments.phase] = evidence
        state = store.update(
            _TASK_STATE_ID,
            expected_revision=state["revision"],
            expected_owner=state["owner"],
            lifecycle="INITIALIZED",
            verdict="UNKNOWN",
            obligations=obligations,
            current_operation=None,
            aggregate="UNKNOWN",
            obligation_results={},
            verification_receipt=None,
            next_action="VERIFY",
        )
        payload = {
            "acceptance": acceptance_id,
            "aggregate": "UNKNOWN",
            "attempts": 0,
            "classification": "SCOPE",
            "evidence_verdict": evidence["verdict"],
            "lifecycle": state["lifecycle"],
            "phase": arguments.phase,
            "revision": state["revision"],
        }
        return payload, 1

    current_operation = {"acceptance": acceptance_id, "phase": arguments.phase}
    state = store.update(
        _TASK_STATE_ID,
        expected_revision=state["revision"],
        expected_owner=state["owner"],
        lifecycle="RUNNING",
        verdict="UNKNOWN",
        aggregate="UNKNOWN",
        obligation_results={},
        verification_receipt=None,
        execution_lease=task_lease.to_manifest(),
        current_operation=current_operation,
        next_action="RECOVER_OR_RECORD_OPERATION",
    )
    try:
        result = runner.run(
            operation,
            # The public skill CLI never treats a transport-looking string as
            # permission to replay a task command.  Network/session recovery
            # belongs to the outer Codex controller, not to Ligong.
            budget=RetryBudget(attempts=1),
            ownership_baseline=task_baseline,
        )
    except (StateError, ScopeViolation, ValueError):
        latest = store.load(_TASK_STATE_ID)
        if latest.get("current_operation") == current_operation:
            store.update(
                _TASK_STATE_ID,
                expected_revision=latest["revision"],
                expected_owner=latest["owner"],
                lifecycle="TERMINAL_ERROR",
                verdict="UNKNOWN",
                aggregate="UNKNOWN",
                execution_lease=None,
                current_operation=None,
                next_action="INSPECT_OR_DISPOSE",
            )
        raise
    evidence = _phase_evidence(arguments.phase, acceptance, result)
    obligations["acceptance"][acceptance_id][arguments.phase] = evidence
    state = store.update(
        _TASK_STATE_ID,
        expected_revision=state["revision"],
        expected_owner=state["owner"],
        lifecycle="INITIALIZED",
        verdict="UNKNOWN",
        execution_lease=None,
        obligations=obligations,
        current_operation=None,
        aggregate="UNKNOWN",
        next_action="RUN_CANDIDATE" if arguments.phase == "baseline" else "VERIFY",
    )
    _forward_output(result)
    payload = {
        "acceptance": acceptance_id,
        "aggregate": "UNKNOWN",
        "attempts": result.attempts,
        "classification": result.classification,
        "evidence_verdict": evidence["verdict"],
        "lifecycle": state["lifecycle"],
        "phase": arguments.phase,
        "revision": state["revision"],
    }
    if arguments.phase == "baseline":
        return payload, 1
    return payload, 0 if evidence["verdict"] == "SUPPORTED" else 1


def _strict_write_supported(
    store: StateStore,
    state: dict[str, Any],
    results: Mapping[str, Any],
    verification_receipt: Mapping[str, str],
) -> dict[str, Any]:
    """The sole CLI transition that can create TERMINAL/SUPPORTED."""

    contract = state["contract"]
    for acceptance in contract.get("acceptance", []):
        detail = results.get("acceptance", {}).get(str(acceptance.get("id")))
        if not isinstance(detail, Mapping) or detail.get("verdict") != "SUPPORTED":
            raise StateError("strict verifier rejected incomplete acceptance evidence")
        evidence = state["obligations"]["acceptance"][str(acceptance["id"])]["candidate"]
        freshness = _workspace_freshness(
            contract,
            evidence.get("workspace_success"),
            state.get("baseline_snapshot"),
            evidence.get("workspace_ownership"),
        )
        if freshness.get("verdict") != "SUPPORTED":
            raise StateError("strict verifier rejected stale candidate evidence")
    if results.get("workspace_ownership", {}).get("verdict") != "SUPPORTED":
        raise StateError("strict verifier rejected unknown workspace ownership")
    current_forbidden = _scan_forbidden(Path(str(contract["repo"])), contract.get("forbidden", []))
    for rule in contract.get("forbidden", []):
        rule_id = str(rule.get("id"))
        detail = _forbidden_verdict(rule, state["obligations"]["forbidden"].get(rule_id), current_forbidden[rule_id])
        if detail.get("verdict") != "SUPPORTED":
            raise StateError("strict verifier rejected forbidden-rule evidence")
    for detail in results.get("surfaces", {}).values():
        if not isinstance(detail, Mapping) or detail.get("verdict") != "SUPPORTED":
            raise StateError("strict verifier rejected surface evidence")
    return store.update(
        _TASK_STATE_ID,
        expected_revision=state["revision"],
        expected_owner=state["owner"],
        lifecycle="TERMINAL",
        verdict="SUPPORTED",
        aggregate="SUPPORTED",
        obligation_results=copy.deepcopy(results),
        verification_receipt=copy.deepcopy(dict(verification_receipt)),
        current_operation=None,
        next_action="REUSE_OR_CHECKPOINT",
    )


def _command_verify(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    state_dir = Path(arguments.state_dir)
    store, state = _load_task(state_dir)
    contract = state.get("contract", {})
    if contract.get("risk") == "L3":
        raise AdmissionFailure("existing L3 task state is unsupported by TaskGuard v2")
    if contract.get("risk") == "L2":
        from .chain import require_stage

        require_stage(
            state_dir,
            task_id=str(contract.get("task_id")),
            goal=str(contract.get("goal")),
            scope=list(contract.get("scope", [])),
            stage="final",
            risk="L2",
        )
    if state.get("lifecycle") in {"RUNNING", "RETRY_WAIT"} or state.get("current_operation") is not None:
        raise CliInputError("interrupted operation requires explicit dispose before verify")
    state = store.update(
        _TASK_STATE_ID,
        expected_revision=state["revision"],
        expected_owner=state["owner"],
        lifecycle="VERIFYING",
        verdict="UNKNOWN",
        aggregate="UNKNOWN",
        obligation_results={},
        verification_receipt=None,
        next_action="VERIFY",
    )
    aggregate, results = _evaluate(state, execute_surfaces=True, state_dir=state_dir)
    verification_receipt = _persist_verification_receipt(
        store,
        state,
        aggregate=aggregate,
        results=results,
    )
    if aggregate == "SUPPORTED":
        state = _strict_write_supported(
            store,
            state,
            results,
            verification_receipt,
        )
    else:
        state = store.update(
            _TASK_STATE_ID,
            expected_revision=state["revision"],
            expected_owner=state["owner"],
            lifecycle="TERMINAL_ERROR",
            verdict=aggregate,
            aggregate=aggregate,
            obligation_results=results,
            verification_receipt=verification_receipt,
            current_operation=None,
            next_action="INSPECT_OR_REFRESH",
        )
    payload = {
        "aggregate": aggregate,
        "lifecycle": state["lifecycle"],
        "obligations": results,
        "revision": state["revision"],
        "verdict": state["verdict"],
    }
    return payload, 0 if aggregate == "SUPPORTED" else 1


def _load_checkpoint(store: StateStore, state_dir: Path) -> dict[str, Any] | None:
    if not os.path.lexists(_state_path(state_dir, _CHECKPOINT_STATE_ID)):
        return None
    checkpoint = store.load(_CHECKPOINT_STATE_ID)
    return {
        "label": checkpoint.get("label"),
        "next_action": checkpoint.get("next_action"),
        "revision": checkpoint.get("revision"),
        "task_revision": checkpoint.get("task_revision"),
    }


def _command_status(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    state_dir = Path(arguments.state_dir)
    store, state = _load_task(state_dir)
    if state.get("contract", {}).get("risk") == "L3":
        return {
            "aggregate": "UNKNOWN",
            "checkpoint": _load_checkpoint(store, state_dir),
            "lifecycle": state["lifecycle"],
            "next_action": "L3_UNSUPPORTED",
            "obligations": {},
            "revision": state["revision"],
            "verdict": "UNKNOWN",
        }, 1
    aggregate, results = _evaluate(state, execute_surfaces=False, state_dir=state_dir)
    if state["lifecycle"] in {"TERMINAL", "TERMINAL_ERROR"}:
        aggregate = _aggregate(
            (aggregate, str(state["aggregate"]), str(state["verdict"]))
        )
    elif state["lifecycle"] in {"RUNNING", "RETRY_WAIT", "VERIFYING"}:
        aggregate = _aggregate((aggregate, "UNKNOWN"))
    checkpoint = _load_checkpoint(store, state_dir)
    if aggregate == "SUPPORTED":
        next_action = "REUSE_OR_CHECKPOINT"
    elif state.get("lifecycle") in {"RUNNING", "RETRY_WAIT"}:
        next_action = "EXPLICIT_DISPOSITION_REQUIRED"
    else:
        next_action = "VERIFY_OR_INSPECT"
    payload = {
        "aggregate": aggregate,
        "checkpoint": checkpoint,
        "lifecycle": state["lifecycle"],
        "next_action": next_action,
        "obligations": results,
        "revision": state["revision"],
        "verdict": state["verdict"],
    }
    return payload, 0 if aggregate == "SUPPORTED" else 1


def _command_checkpoint(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    label = arguments.label
    if not isinstance(label, str) or not label.strip() or "\x00" in label:
        raise CliInputError("checkpoint label must be non-empty and contain no NUL")
    if len(label.encode("utf-8")) > 128:
        raise CliInputError("checkpoint label must be at most 128 UTF-8 bytes")
    state_dir = Path(arguments.state_dir)
    store, task_state = _load_task(state_dir)
    if os.path.lexists(_state_path(state_dir, _CHECKPOINT_STATE_ID)):
        checkpoint = store.load(_CHECKPOINT_STATE_ID)
        if checkpoint["owner"] != task_state["owner"]:
            raise ConcurrentUpdateError("checkpoint owner conflicts with task owner")
        next_revision = checkpoint["revision"] + 1
        checkpoint = store.update(
            _CHECKPOINT_STATE_ID,
            expected_revision=checkpoint["revision"],
            expected_owner=task_state["owner"],
            label=label,
            task_revision=task_state["revision"],
            checkpoint_revision=next_revision,
            next_action="VERIFY",
        )
    else:
        checkpoint = store.create(
            _CHECKPOINT_STATE_ID,
            owner=task_state["owner"],
            label=label,
            task_revision=task_state["revision"],
            checkpoint_revision=1,
            next_action="VERIFY",
        )
    return {
        "label": checkpoint["label"],
        "next_action": checkpoint["next_action"],
        "revision": checkpoint["revision"],
        "task_revision": checkpoint["task_revision"],
    }, 0


def _command_dispose(arguments: argparse.Namespace) -> tuple[dict[str, Any], int]:
    state_dir = Path(arguments.state_dir)
    store = StateStore(state_dir)
    with store.execution_lease(_TASK_STATE_ID, blocking=False) as task_lease:
        return _command_dispose_with_lease(
            arguments,
            store=store,
            task_lease=task_lease,
        )


def _command_dispose_with_lease(
    arguments: argparse.Namespace,
    *,
    store: StateStore,
    task_lease: ExecutionLease,
) -> tuple[dict[str, Any], int]:
    """Disposition an interrupted public CLI phase without rerunning its command."""

    state_dir = Path(arguments.state_dir)
    store, state = _load_task(state_dir, store=store)
    current = state.get("current_operation")
    if state.get("lifecycle") not in {"RUNNING", "RETRY_WAIT"} or not isinstance(current, Mapping):
        raise CliInputError("dispose requires an interrupted RUNNING or RETRY_WAIT task")
    task_lease.require_manifest(state.get("execution_lease"))
    acceptance_id = current.get("acceptance")
    phase = current.get("phase")
    if not isinstance(acceptance_id, str) or phase not in {"baseline", "candidate"}:
        raise StateError("interrupted task has an invalid current operation binding")
    acceptance = _find_acceptance(state["contract"], acceptance_id)
    operation = Operation(
        id=_operation_id(str(state["contract"]["task_id"]), acceptance_id, str(phase)),
        argv=list(acceptance["argv"]),
        cwd=str(acceptance["cwd"]),
        scope=list(state["contract"]["scope"]),
        selector=acceptance.get("selector"),
        idempotent=acceptance.get("idempotent"),
    )
    runner = TaskRunner(
        state_root=state_dir / "operations",
        workspace_root=Path(str(state["contract"]["repo"])),
        owner=_owner_for_operations(str(state["owner"])),
    )
    operation_state_path = state_dir / "operations" / f"{operation.id}.json"
    process_manifest: dict[str, Any] | None = None
    operation_revision: int | None = None
    if os.path.lexists(operation_state_path):
        operation_state = runner.store.load(operation.id)
        if operation_state.get("lifecycle") in {"RUNNING", "RETRY_WAIT"}:
            disposed = runner.dispose(operation, verdict=arguments.verdict)
            process_manifest = disposed.to_manifest()
            operation_revision = disposed.state_revision
        else:
            # A command may have finished immediately before the CLI was killed.
            # Preserve that ledger but never promote it during explicit disposition.
            operation_revision = int(operation_state["revision"])
            process_manifest = {
                "operation_id": operation.id,
                "lifecycle": operation_state.get("lifecycle"),
                "verdict": operation_state.get("verdict"),
                "attempts": len(operation_state.get("attempt_records", [])),
                "state_revision": operation_revision,
            }

    obligations = copy.deepcopy(state["obligations"])
    acceptance_records = obligations.get("acceptance")
    if not isinstance(acceptance_records, dict) or not isinstance(
        acceptance_records.get(acceptance_id), dict
    ):
        raise StateError(f"missing acceptance obligation record: {acceptance_id}")
    existing = acceptance_records[acceptance_id].get(str(phase))
    if isinstance(existing, Mapping) and existing.get("verdict") != "NOT_REQUIRED":
        raise StateError("interrupted phase already has durable evidence; dispose refuses to overwrite it")
    acceptance_records[acceptance_id][str(phase)] = {
        "phase": phase,
        "binding_digest": _digest(_acceptance_binding(acceptance)),
        "verdict": arguments.verdict,
        "process": process_manifest,
        "workspace_success": None,
        "workspace_ownership": None,
        "disposition": {
            "verdict": arguments.verdict,
            "operation_revision": operation_revision,
            "rerun": False,
        },
    }
    dispositions = list(state.get("dispositions", []))
    dispositions.append(
        {
            "acceptance": acceptance_id,
            "phase": phase,
            "operation_id": operation.id,
            "operation_revision": operation_revision,
            "verdict": arguments.verdict,
            "rerun": False,
        }
    )
    disposition_aggregate = _aggregate(
        item["verdict"] for item in dispositions
    )
    state = store.update(
        _TASK_STATE_ID,
        expected_revision=state["revision"],
        expected_owner=state["owner"],
        lifecycle="TERMINAL_ERROR",
        verdict=disposition_aggregate,
        aggregate=disposition_aggregate,
        obligation_results={},
        verification_receipt=None,
        execution_lease=None,
        obligations=obligations,
        current_operation=None,
        dispositions=dispositions,
        next_action="VERIFY_OR_INSPECT",
    )
    return {
        "acceptance": acceptance_id,
        "lifecycle": state["lifecycle"],
        "operation_revision": operation_revision,
        "phase": phase,
        "revision": state["revision"],
        "rerun": False,
        "verdict": state["verdict"],
    }, 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="task_guard.py")
    commands = parser.add_subparsers(dest="command", required=True)

    initialize = commands.add_parser("init")
    initialize.add_argument("--state-dir", required=True)
    initialize.add_argument("--contract", required=True)

    run = commands.add_parser("run")
    run.add_argument("--state-dir", required=True)
    run.add_argument("--acceptance", required=True)
    run.add_argument("--phase", required=True, choices=("baseline", "candidate"))
    run.add_argument("--contract")

    verify = commands.add_parser("verify")
    verify.add_argument("--state-dir", required=True)

    status = commands.add_parser("status")
    status.add_argument("--state-dir", required=True)

    checkpoint = commands.add_parser("checkpoint")
    checkpoint.add_argument("--state-dir", required=True)
    checkpoint.add_argument("--label", required=True)

    dispose = commands.add_parser("dispose")
    dispose.add_argument("--state-dir", required=True)
    dispose.add_argument("--verdict", choices=("FAILED", "UNKNOWN"), default="UNKNOWN")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    commands = {
        "init": _command_init,
        "run": _command_run,
        "verify": _command_verify,
        "status": _command_status,
        "checkpoint": _command_checkpoint,
        "dispose": _command_dispose,
    }
    try:
        payload, exit_code = commands[arguments.command](arguments)
    except (CliInputError, ContractError, ValueError) as exc:
        print(f"input error: {exc}", file=sys.stderr)
        return 2
    except AdmissionFailure as exc:
        print(f"admission failed: {exc}", file=sys.stderr)
        return 1
    except (StateError, ScopeViolation) as exc:
        print(f"state/evidence error: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4
    _emit(payload)
    return exit_code


__all__ = ["main"]
