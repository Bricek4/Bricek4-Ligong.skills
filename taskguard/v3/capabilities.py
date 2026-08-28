"""Pure capability admission and a closed exact adapter registry."""

from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import Iterable, Mapping

from ..contracts.v3 import ActionSpec
from ..validation import sha256_digest
from .adapters import AdapterCapabilities, ReadOnlyActionAdapter


REQUIRED_MUTATION_CAPABILITIES = frozenset({
    "canonical_target", "principal_identity", "side_effect_free_plan", "idempotency_key",
    "effect_observation", "effect_reconciliation", "rollback_preparation",
    "rollback_execution", "revision_bound_health",
})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{2,127}\Z")


class DuplicateAdapter(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class CapabilityReport:
    verdict: str
    reasons: tuple[str, ...]
    adapter_id: str
    adapter_version: str | None
    capabilities: Mapping[str, bool]

    @property
    def digest(self) -> str:
        return sha256_digest(self.to_manifest())

    def to_manifest(self) -> dict[str, object]:
        return {
            "verdict": self.verdict,
            "reasons": list(self.reasons),
            "adapter_id": self.adapter_id,
            "adapter_version": self.adapter_version,
            "capabilities": dict(self.capabilities),
        }


class AdapterRegistry:
    """Exact registration only: no aliases, discovery, wildcard, or fallback."""

    def __init__(self, adapters: Iterable[ReadOnlyActionAdapter] = ()) -> None:
        values: dict[str, ReadOnlyActionAdapter] = {}
        for adapter in adapters:
            adapter_id = getattr(adapter, "adapter_id", None)
            version = getattr(adapter, "adapter_version", None)
            if type(adapter_id) is not str or not _IDENTIFIER.fullmatch(adapter_id):
                raise ValueError("adapter_id is not a stable exact identifier")
            if type(version) is not str or not _IDENTIFIER.fullmatch(version):
                raise ValueError("adapter_version is not a stable exact identifier")
            if adapter_id in values:
                raise DuplicateAdapter(adapter_id)
            values[adapter_id] = adapter
        self._adapters = MappingProxyType(values)

    def get(self, adapter_id: str) -> ReadOnlyActionAdapter | None:
        return self._adapters.get(adapter_id)

    def require(self, adapter_id: str) -> ReadOnlyActionAdapter:
        adapter = self.get(adapter_id)
        if adapter is None:
            raise KeyError(adapter_id)
        return adapter

    def evaluate(self, action: ActionSpec) -> CapabilityReport:
        return evaluate_action_capabilities(action, self)

    @property
    def adapter_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))


def evaluate_action_capabilities(action: ActionSpec, registry: AdapterRegistry) -> CapabilityReport:
    adapter = registry.get(action.adapter)
    if adapter is None:
        return CapabilityReport(
            "UNSUPPORTED",
            ("ADAPTER_NOT_REGISTERED",),
            action.adapter,
            None,
            MappingProxyType({}),
        )
    try:
        capabilities = adapter.capabilities(action)
        manifest = capabilities.to_manifest()
    except Exception:
        return CapabilityReport(
            "UNSUPPORTED", ("CAPABILITY_REPORT_INVALID",), action.adapter,
            getattr(adapter, "adapter_version", None), MappingProxyType({}),
        )
    missing = tuple(
        f"MISSING_CAPABILITY/{name}"
        for name in sorted(REQUIRED_MUTATION_CAPABILITIES)
        if manifest.get(name) is not True
    )
    return CapabilityReport(
        "SUPPORTED" if not missing else "UNSUPPORTED",
        missing,
        action.adapter,
        adapter.adapter_version,
        MappingProxyType(dict(manifest)),
    )


PRODUCTION_ADAPTER_REGISTRY = AdapterRegistry()
