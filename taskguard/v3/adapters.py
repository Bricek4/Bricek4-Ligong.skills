"""Typed provider adapter contracts; intentionally no generic command escape hatch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Protocol, runtime_checkable

from ..contracts.v3 import ActionSpec
from .types import AdapterIdentity, CanonicalTarget, PlanReceipt, PrincipalReceipt


@dataclass(frozen=True, slots=True)
class AdapterCapabilities:
    canonical_target: bool
    principal_identity: bool
    side_effect_free_plan: bool
    idempotency_key: bool
    effect_observation: bool
    effect_reconciliation: bool
    rollback_preparation: bool
    rollback_execution: bool
    revision_bound_health: bool

    def to_manifest(self) -> dict[str, bool]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}


@runtime_checkable
class ReadOnlyActionAdapter(Protocol):
    adapter_id: str
    adapter_version: str

    def identity(self) -> AdapterIdentity: ...
    def capabilities(self, action: ActionSpec) -> AdapterCapabilities: ...
    def canonicalize_target(self, action: ActionSpec) -> CanonicalTarget: ...
    def identify_principal(self, request: Mapping[str, Any]) -> PrincipalReceipt: ...
    def plan(self, request: Mapping[str, Any]) -> PlanReceipt: ...


@runtime_checkable
class ProviderAdapter(ReadOnlyActionAdapter, Protocol):
    def prepare_rollback(self, request: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def apply(self, intent: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def observe(self, query: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def reconcile(self, query: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def rollback(self, intent: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def health(self, query: Mapping[str, Any]) -> Mapping[str, Any]: ...
