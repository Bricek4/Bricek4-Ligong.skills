"""Side-effect-free v3 plan construction and exact binding."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from ..contracts.v3 import ActionSpec
from ..validation import canonical_json_bytes, sha256_digest
from .adapters import ReadOnlyActionAdapter
from .receipt_store import ReceiptStore
from .receipts import RECEIPT_VERSION, Receipt


class PlanBindingError(RuntimeError):
    pass


class Planner:
    def __init__(
        self,
        receipts: ReceiptStore,
        adapter: ReadOnlyActionAdapter,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.receipts = receipts
        self.adapter = adapter
        self.clock = clock or (lambda: datetime.now(timezone.utc))

    def create_plan(self, task_state: Mapping[str, Any], action: ActionSpec):
        identity = self.adapter.identity()
        if identity.adapter_id != action.adapter or identity.provider != action.target.provider:
            raise PlanBindingError("adapter identity does not match declared action")
        capabilities = self.adapter.capabilities(action)
        capability_manifest = capabilities.to_manifest()
        if capability_manifest.get("side_effect_free_plan") is not True:
            raise PlanBindingError("adapter does not prove a side-effect-free plan")
        target = self.adapter.canonicalize_target(action)
        if target.to_manifest() != action.target.to_manifest():
            raise PlanBindingError("adapter canonical target differs from contract target")
        principal = self.adapter.identify_principal({
            "task_id": task_state["task_id"],
            "action_id": action.id,
            "target": target.to_manifest(),
        })
        plan = self.adapter.plan({
            "task_id": task_state["task_id"],
            "action_id": action.id,
            "action": action.to_manifest(),
            "target": target.to_manifest(),
            "principal": principal.to_manifest(),
        })
        if plan.action_id != action.id or plan.target != target or not plan.remote_version:
            raise PlanBindingError("provider plan returned a mismatched binding")
        canonical_json_bytes(dict(plan.provider_plan))
        if len(canonical_json_bytes(dict(plan.provider_plan))) > 256 * 1024:
            raise PlanBindingError("provider plan exceeds maximum size")
        binding = {
            "task_id": task_state["task_id"],
            "action_id": action.id,
            "action_digest": sha256_digest(action.to_manifest()),
            "adapter_digest": sha256_digest(identity.to_manifest()),
            "capability_digest": sha256_digest(capability_manifest),
            "target_digest": sha256_digest(target.to_manifest()),
            "principal_digest": sha256_digest(principal.to_manifest()),
            "preconditions_digest": sha256_digest(dict(action.preconditions)),
            "remote_version": plan.remote_version,
        }
        receipt = Receipt(
            RECEIPT_VERSION,
            "plan-receipt-v1",
            task_state["task_id"],
            action.id,
            binding,
            {
                "adapter": identity.to_manifest(),
                "target": target.to_manifest(),
                "principal": principal.to_manifest(),
                "provider_plan": dict(plan.provider_plan),
            },
            (),
            self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        return self.receipts.put(receipt)
