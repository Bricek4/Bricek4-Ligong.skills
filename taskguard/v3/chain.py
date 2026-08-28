"""Monotonic risk-chain-v3 bindings."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from ..validation import canonical_json_bytes, sha256_digest


STAGES = ("initial", "diff", "final")
IMMUTABLE_BINDINGS = frozenset({
    "task_id", "action_id", "action_digest", "target_digest", "environment",
    "resource_scope_digest", "desired_state_digest", "preconditions_digest",
    "adapter_id", "adapter_version", "capability_digest", "authority_policy_digest",
    "plan_policy_digest", "rollback_policy_digest", "health_policy_digest",
})


class ChainBindingMismatch(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ChainStageV3:
    version: str
    stage: str
    binding: Mapping[str, Any]
    previous_digest: str | None
    digest: str

    def to_manifest(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "stage": self.stage,
            "binding": dict(self.binding),
            "previous_digest": self.previous_digest,
            "digest": self.digest,
        }


def commit_chain_stage(stage: str, binding: Mapping[str, Any], previous: ChainStageV3 | None = None) -> ChainStageV3:
    if stage not in STAGES:
        raise ChainBindingMismatch("unknown risk-chain-v3 stage")
    index = STAGES.index(stage)
    if (index == 0) != (previous is None):
        raise ChainBindingMismatch("risk-chain-v3 stage sequence mismatch")
    if previous is not None:
        if STAGES.index(previous.stage) + 1 != index:
            raise ChainBindingMismatch("risk-chain-v3 stage skipped or replayed")
        for field in IMMUTABLE_BINDINGS:
            if field not in previous.binding or field not in binding or previous.binding[field] != binding[field]:
                raise ChainBindingMismatch(f"risk-chain-v3 immutable binding drift: {field}")
    canonical_json_bytes(dict(binding))
    payload = {
        "version": "risk-chain-v3",
        "stage": stage,
        "binding": dict(binding),
        "previous_digest": previous.digest if previous else None,
    }
    return ChainStageV3("risk-chain-v3", stage, dict(binding), payload["previous_digest"], sha256_digest(payload))


def require_chain_stage(value: ChainStageV3, stage: str) -> None:
    if value.version != "risk-chain-v3" or value.stage != stage:
        raise ChainBindingMismatch(f"required risk-chain-v3 stage {stage}")
    payload = {
        "version": value.version,
        "stage": value.stage,
        "binding": dict(value.binding),
        "previous_digest": value.previous_digest,
    }
    if sha256_digest(payload) != value.digest:
        raise ChainBindingMismatch("risk-chain-v3 digest mismatch")
