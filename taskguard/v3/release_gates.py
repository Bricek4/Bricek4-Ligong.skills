"""Ordered SHADOW → SANDBOX → CANARY → PRODUCTION evidence gates."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


MODE_REQUIREMENTS = {
    "SHADOW": ("trusted_evidence_root", "receipt_graph", "core", "shadow"),
    "SANDBOX": ("trusted_evidence_root", "receipt_graph", "core", "shadow", "sandbox_conformance", "sandbox_target"),
    "CANARY": ("trusted_evidence_root", "receipt_graph", "core", "shadow", "sandbox_conformance", "sandbox_target", "allowlist", "kill_switch"),
    "PRODUCTION": (
        "trusted_evidence_root", "receipt_graph", "core", "shadow", "sandbox_conformance", "sandbox_target", "allowlist",
        "kill_switch", "trusted_authority", "receipt_readers", "rollback",
    ),
}


@dataclass(frozen=True, slots=True)
class ReleaseGateReport:
    mode: str
    status: str
    ready_for_production: bool
    requested_action_count: int
    action_kind: str
    rollback_required: bool
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReleaseEvidence:
    values: Mapping[str, Any]
    trusted_root_digest: str
    receipt_graph_verified: bool
    trusted_source: bool


def evaluate_release_gates(evidence: ReleaseEvidence | Mapping[str, Any], mode: str) -> ReleaseGateReport:
    if mode not in MODE_REQUIREMENTS:
        raise ValueError("unknown release mode")
    trusted = isinstance(evidence, ReleaseEvidence)
    values = evidence.values if trusted else evidence
    action_count = values.get("requested_action_count")
    action_kind = values.get("action_kind", "")
    rollback_required = values.get("rollback_required") is True
    reasons = [f"MISSING_OR_FAILED/{name}" for name in MODE_REQUIREMENTS[mode] if values.get(name) != "SUPPORTED"]
    if (
        not trusted
        or not evidence.trusted_source
        or not evidence.receipt_graph_verified
        or not evidence.trusted_root_digest
    ):
        reasons.append("UNTRUSTED_RELEASE_EVIDENCE")
    if action_count != 1:
        reasons.append("FIRST_SUBSET_REQUIRES_ONE_ACTION")
    if action_kind not in {"deploy", "write", "update", "publish"}:
        reasons.append("IRREVERSIBLE_OR_UNSUPPORTED_ACTION")
    if not rollback_required:
        reasons.append("ROLLBACK_REQUIRED")
    status = "SUPPORTED" if not reasons else "UNSUPPORTED"
    return ReleaseGateReport(
        mode, status, mode == "PRODUCTION" and status == "SUPPORTED",
        action_count if type(action_count) is int else 0,
        action_kind if type(action_kind) is str else "",
        rollback_required,
        tuple(reasons),
    )
