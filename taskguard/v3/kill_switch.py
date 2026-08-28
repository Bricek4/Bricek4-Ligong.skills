"""Recovery-aware managed kill-switch decisions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


RECOVERY_OPERATIONS = frozenset({"reconcile", "rollback", "status", "export"})


@dataclass(frozen=True, slots=True)
class KillSwitchDecision:
    status: str
    reason: str


@dataclass(frozen=True, slots=True)
class KillSwitchPolicy:
    revision: int
    managed_owner: str
    closed: bool
    adapter_id: str | None = None
    action_kind: str | None = None
    environment: str | None = None
    target_digest: str | None = None

    def __post_init__(self) -> None:
        if type(self.revision) is not int or self.revision < 1 or not self.managed_owner or type(self.closed) is not bool:
            raise ValueError("kill switch requires managed owner, positive revision, and boolean state")

    def decide(self, binding: Mapping[str, str], lifecycle: str, operation: str) -> KillSwitchDecision:
        del lifecycle
        scoped = all(
            expected is None or binding.get(name) == expected
            for name, expected in (
                ("adapter_id", self.adapter_id), ("action_kind", self.action_kind),
                ("environment", self.environment), ("canonical_target_digest", self.target_digest),
            )
        )
        if not self.closed or not scoped:
            return KillSwitchDecision("SUPPORTED", "SWITCH_OPEN_OR_OUT_OF_SCOPE")
        if operation in RECOVERY_OPERATIONS:
            return KillSwitchDecision("SUPPORTED", "RECOVERY_PRESERVED")
        return KillSwitchDecision("BLOCKED", "KILL_SWITCH_CLOSED")
