"""Read-only external-action shadow evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..contracts.v3 import ContractV3
from ..validation import sha256_digest
from .capabilities import REQUIRED_MUTATION_CAPABILITIES


@dataclass(frozen=True, slots=True)
class ShadowReport:
    status: str
    action_verdict: str
    reasons: tuple[str, ...]
    evidence_digest: str


class ShadowEvaluator:
    def __init__(self, adapter: Any, authority: Any | None = None) -> None:
        self.adapter = adapter
        self.authority = authority

    def evaluate(self, contract: ContractV3, action_id: str, raw_authority: Any | None = None) -> ShadowReport:
        action = next((item for item in contract.actions if item.id == action_id), None)
        if action is None:
            raise ValueError(f"unknown action: {action_id}")
        reasons: list[str] = []
        identity = self.adapter.identity()
        if identity.adapter_id != action.adapter or identity.provider != action.target.provider:
            reasons.append("ADAPTER_IDENTITY_MISMATCH")
        capabilities = self.adapter.capabilities(action).to_manifest()
        for capability in sorted(REQUIRED_MUTATION_CAPABILITIES):
            if capabilities.get(capability) is not True:
                reasons.append(f"MISSING_CAPABILITY/{capability}")
        target = self.adapter.canonicalize_target(action)
        if target.to_manifest() != action.target.to_manifest():
            reasons.append("TARGET_MISMATCH")
        principal = self.adapter.identify_principal({"task_id": contract.task_id, "action_id": action.id, "target": target.to_manifest()})
        plan = self.adapter.plan({
            "task_id": contract.task_id, "action_id": action.id,
            "action": action.to_manifest(), "target": target.to_manifest(),
            "principal": principal.to_manifest(),
        })
        if plan.action_id != action.id or plan.target != target or not plan.remote_version:
            reasons.append("PLAN_BINDING_MISMATCH")
        if raw_authority is not None:
            if self.authority is None:
                reasons.append("NO_TRUSTED_AUTHORITY_PROVIDER")
            elif not hasattr(self.authority, "verify"):
                reasons.append("AUTHORITY_VERIFY_UNAVAILABLE")
            else:
                # Verification-only. Shadow deliberately has no consume call.
                verdict = self.authority.verify(raw_authority, None)
                if getattr(verdict, "verdict", None) != "SUPPORTED":
                    reasons.append("AUTHORITY_VERIFICATION_FAILED")
        payload = {
            "task_id": contract.task_id,
            "action_id": action.id,
            "adapter": identity.to_manifest(),
            "target": target.to_manifest(),
            "principal": principal.to_manifest(),
            "remote_version": plan.remote_version,
            "reasons": sorted(set(reasons)),
        }
        return ShadowReport(
            "READY" if not reasons else "BLOCKED",
            "UNKNOWN",
            tuple(payload["reasons"]),
            sha256_digest(payload),
        )
