"""Canonical fail-closed provider and release readiness reports."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


READINESS_REQUIREMENTS = {
    "trusted_evidence_root": "NO_TRUSTED_RELEASE_EVIDENCE_ROOT",
    "receipt_graph": "RELEASE_RECEIPT_GRAPH_UNVERIFIED",
    "production_adapter": "NO_REGISTERED_PRODUCTION_ADAPTER",
    "provider_conformance": "NO_PROVIDER_SANDBOX_CONFORMANCE",
    "trusted_authority": "NO_TRUSTED_AUTHORITY_PROVIDER",
    "exact_allowlist": "NO_EXACT_RELEASE_ALLOWLIST",
    "kill_switch": "NO_MANAGED_KILL_SWITCH",
    "receipt_readers": "RECEIPT_READER_COMPATIBILITY_UNPROVEN",
    "shadow": "NO_SHADOW_EVIDENCE",
}


@dataclass(frozen=True, slots=True)
class ProviderReadinessReport:
    status: str
    reason_codes: tuple[str, ...]
    production_ready: bool


@dataclass(frozen=True, slots=True)
class ProviderReadinessEvidence:
    values: Mapping[str, str]
    trusted_source: bool
    receipt_graph_verified: bool


def build_provider_readiness_report(
    evidence: ProviderReadinessEvidence | Mapping[str, str] | None = None,
) -> ProviderReadinessReport:
    if evidence is None:
        values: Mapping[str, str] = {}
    elif not isinstance(evidence, ProviderReadinessEvidence):
        return ProviderReadinessReport("UNSUPPORTED", ("UNTRUSTED_PROVIDER_READINESS_EVIDENCE",), False)
    elif not evidence.trusted_source or not evidence.receipt_graph_verified:
        return ProviderReadinessReport("UNSUPPORTED", ("UNTRUSTED_PROVIDER_READINESS_EVIDENCE",), False)
    else:
        values = evidence.values
    reasons = tuple(code for name, code in READINESS_REQUIREMENTS.items() if values.get(name) != "SUPPORTED")
    return ProviderReadinessReport("SUPPORTED" if not reasons else "UNSUPPORTED", reasons, not reasons)
