"""Pure intersection gate for production apply."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


PRODUCTION_GUARDS = (
    "local_platform", "adapter_registered", "exact_allowlist", "adapter_conformance",
    "trusted_authority_provider", "authority_receipt", "plan", "target", "principal",
    "rollback_readiness", "rollback_authority", "kill_switch",
)


@dataclass(frozen=True, slots=True)
class ProductionDecision:
    status: str
    reason_code: str
    failed_guards: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProductionGateContext:
    guards: Mapping[str, str]
    binding_digest: str
    guard_bindings: Mapping[str, str]
    receipt_graph_verified: bool
    trusted_policy_source: bool


def evaluate_production_gate(context: ProductionGateContext | Mapping[str, str]) -> ProductionDecision:
    if not isinstance(context, ProductionGateContext):
        return ProductionDecision("UNSUPPORTED", "UNTRUSTED_PRODUCTION_GATE_CONTEXT", PRODUCTION_GUARDS)
    failed_values = [name for name in PRODUCTION_GUARDS if context.guards.get(name) != "SUPPORTED"]
    if not context.receipt_graph_verified:
        failed_values.append("receipt_graph")
    if not context.trusted_policy_source:
        failed_values.append("trusted_policy_source")
    if not context.binding_digest or any(
        context.guard_bindings.get(name) != context.binding_digest
        for name in PRODUCTION_GUARDS
        if name not in {"local_platform", "kill_switch"}
    ):
        failed_values.append("common_binding")
    failed = tuple(failed_values)
    if not failed:
        return ProductionDecision("SUPPORTED", "ALL_PRODUCTION_GUARDS_SUPPORTED", ())
    if "trusted_authority_provider" in failed:
        reason = "NO_TRUSTED_AUTHORITY_PROVIDER"
    elif "adapter_registered" in failed:
        reason = "NO_REGISTERED_PRODUCTION_ADAPTER"
    else:
        reason = f"PRODUCTION_GUARD_BLOCKED/{failed[0]}"
    return ProductionDecision("UNSUPPORTED", reason, failed)
