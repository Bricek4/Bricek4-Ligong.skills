"""Provider-neutral, fixed-case adapter conformance reporting."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..validation import sha256_digest
from .capabilities import REQUIRED_MUTATION_CAPABILITIES


REQUIRED_REVERSIBLE_ACTION_CASES = (
    "identity", "canonical-target", "principal", "plan-purity-binding", "idempotency",
    "commit-before-disconnect-reconcile", "rollback-readiness", "rollback-execution",
    "revision-bound-health", "crash-recovery", "concurrency", "secret-canary",
    "receipt-audit-consistency", "irreversible-refusal",
)


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    status: str
    adapter_id: str
    adapter_version: str
    action_kind: str
    environment: str
    passed: tuple[str, ...]
    failed: tuple[str, ...]
    evidence_digest: str


@dataclass(frozen=True, slots=True)
class ConformanceEvidence:
    case_results: Mapping[str, bool]
    trusted_harness: bool


def run_conformance(
    adapter: Any,
    action: Any,
    evidence: ConformanceEvidence | None = None,
    *,
    environment: str = "sandbox",
) -> ConformanceReport:
    failed: list[str] = []
    try:
        identity = adapter.identity()
        if identity.adapter_id != adapter.adapter_id or identity.adapter_version != adapter.adapter_version:
            failed.append("identity")
        capabilities = adapter.capabilities(action).to_manifest()
    except Exception:
        identity = type("Identity", (), {"adapter_id": getattr(adapter, "adapter_id", "invalid"), "adapter_version": getattr(adapter, "adapter_version", "invalid")})()
        capabilities = {}
        failed.append("identity")
    for capability in sorted(REQUIRED_MUTATION_CAPABILITIES):
        if capabilities.get(capability) is not True:
            failed.append(f"capability/{capability}")
    for case in REQUIRED_REVERSIBLE_ACTION_CASES:
        if case == "identity":
            continue
        supported = (
            evidence is not None
            and evidence.trusted_harness
            and set(evidence.case_results) == set(REQUIRED_REVERSIBLE_ACTION_CASES)
            and evidence.case_results.get(case) is True
        )
        if not supported:
            failed.append(case)
    failed_set = tuple(sorted(set(failed)))
    passed = tuple(case for case in REQUIRED_REVERSIBLE_ACTION_CASES if case not in failed_set)
    payload = {
        "adapter_id": identity.adapter_id,
        "adapter_version": identity.adapter_version,
        "action_kind": action.kind,
        "environment": environment,
        "passed": list(passed),
        "failed": list(failed_set),
    }
    return ConformanceReport(
        "SUPPORTED" if not failed_set else "UNSUPPORTED",
        identity.adapter_id,
        identity.adapter_version,
        action.kind,
        environment,
        passed,
        failed_set,
        sha256_digest(payload),
    )
