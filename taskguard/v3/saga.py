"""Durable receipt-driven apply/reconcile/rollback coordination."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from ..receipts.refs import ReceiptRef
from ..validation import sha256_digest
from .receipt_store import ReceiptStore
from .receipts import RECEIPT_VERSION, Receipt


class EffectUnknown(RuntimeError):
    def __init__(self, intent_ref: ReceiptRef, reason: str) -> None:
        super().__init__(reason)
        self.intent_ref = intent_ref
        self.reason = reason


class SagaBindingError(RuntimeError):
    pass


class SagaService:
    """Injected execution engine; the public production registry never constructs it."""

    def __init__(
        self,
        receipts: ReceiptStore,
        adapter: Any,
        *,
        clock: Callable[[], datetime] | None = None,
        authority_consumer: Callable[[ReceiptRef, str, str, str], bool] | None = None,
        kill_switch: Any | None = None,
    ) -> None:
        self.receipts = receipts
        self.adapter = adapter
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.authority_consumer = authority_consumer
        self.kill_switch = kill_switch

    def _release_check(
        self,
        *,
        release_binding: Mapping[str, str] | None,
        lifecycle: str,
        operation: str,
    ) -> None:
        if self.kill_switch is None:
            return
        if release_binding is None:
            raise SagaBindingError("kill-switch scope binding is required")
        decision = self.kill_switch.decide(release_binding, lifecycle, operation)
        if decision.status != "SUPPORTED":
            raise SagaBindingError(decision.reason)

    def _consume_authority(self, ref: ReceiptRef, operation: str, task_id: str, action_id: str) -> None:
        if self.authority_consumer is None:
            raise SagaBindingError("NO_TRUSTED_AUTHORITY_CONSUMER")
        if self.authority_consumer(ref, operation, task_id, action_id) is not True:
            raise SagaBindingError("AUTHORITY_CONSUMPTION_REJECTED")

    def _receipt(
        self,
        kind: str,
        task_id: str,
        action_id: str,
        binding: Mapping[str, Any],
        body: Mapping[str, Any],
        parents: tuple[ReceiptRef, ...],
    ) -> ReceiptRef:
        return self.receipts.put(Receipt(
            RECEIPT_VERSION,
            kind,
            task_id,
            action_id,
            dict(binding),
            dict(body),
            tuple(sorted(parents, key=lambda item: (item.digest, item.kind))),
            self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        ))

    def _require_apply_bindings(
        self,
        plan_ref: ReceiptRef,
        authority_ref: ReceiptRef,
        readiness_ref: ReceiptRef,
        target_digest: str,
        *,
        max_readiness_age_seconds: int,
    ) -> None:
        plan = self.receipts.load(plan_ref)
        authority = self.receipts.load(authority_ref)
        readiness = self.receipts.load(readiness_ref)
        if plan.kind != "plan-receipt-v1" or plan.binding.get("target_digest") != target_digest:
            raise SagaBindingError("plan is not bound to the exact target")
        if (
            authority.kind != "authority-receipt-v1"
            or authority.binding.get("plan_digest") != plan_ref.digest
            or authority.binding.get("target_digest") != target_digest
            or authority.body.get("apply_authorized") is not True
        ):
            raise SagaBindingError("authority does not authorize this exact apply")
        if (
            readiness.kind != "rollback-readiness-receipt-v1"
            or readiness.binding.get("plan_digest") != plan_ref.digest
            or readiness.binding.get("authority_digest") != authority_ref.digest
            or readiness.binding.get("target_digest") != target_digest
        ):
            raise SagaBindingError("rollback readiness is not exactly bound")
        issued = datetime.fromisoformat(readiness.issued_at.replace("Z", "+00:00"))
        age = (self.clock().astimezone(timezone.utc) - issued.astimezone(timezone.utc)).total_seconds()
        if age < 0 or age > max_readiness_age_seconds:
            raise SagaBindingError("rollback readiness is stale")

    def prepare_rollback(
        self,
        *,
        task_id: str,
        action_id: str,
        plan_ref: ReceiptRef,
        authority_ref: ReceiptRef,
        target_digest: str,
        recovery_point: Mapping[str, Any],
    ) -> ReceiptRef:
        response = self.adapter.prepare_rollback({
            "task_id": task_id,
            "action_id": action_id,
            "plan_digest": plan_ref.digest,
            "target_digest": target_digest,
            "recovery_point": dict(recovery_point),
        })
        if response.get("ready") is not True:
            raise SagaBindingError("provider did not prove rollback readiness")
        return self._receipt(
            "rollback-readiness-receipt-v1", task_id, action_id,
            {"plan_digest": plan_ref.digest, "authority_digest": authority_ref.digest, "target_digest": target_digest},
            {"recovery_point": dict(recovery_point), "provider": dict(response)},
            (plan_ref, authority_ref),
        )

    def apply(
        self,
        *,
        task_id: str,
        action_id: str,
        plan_ref: ReceiptRef,
        authority_ref: ReceiptRef,
        readiness_ref: ReceiptRef,
        target_digest: str,
        max_readiness_age_seconds: int = 300,
        release_binding: Mapping[str, str] | None = None,
        lifecycle: str = "ROLLBACK_READY",
    ) -> tuple[ReceiptRef, ReceiptRef]:
        self._release_check(release_binding=release_binding, lifecycle=lifecycle, operation="apply")
        self.receipts.verify_graph([plan_ref, authority_ref, readiness_ref])
        self._require_apply_bindings(
            plan_ref,
            authority_ref,
            readiness_ref,
            target_digest,
            max_readiness_age_seconds=max_readiness_age_seconds,
        )
        intent_binding = {
            "plan_digest": plan_ref.digest,
            "authority_digest": authority_ref.digest,
            "rollback_readiness_digest": readiness_ref.digest,
            "target_digest": target_digest,
        }
        self._consume_authority(authority_ref, "apply", task_id, action_id)
        self._release_check(release_binding=release_binding, lifecycle=lifecycle, operation="apply")
        intent_ref = self._receipt(
            "apply-intent-receipt-v1", task_id, action_id, intent_binding,
            {"idempotency_key": sha256_digest({"task_id": task_id, "action_id": action_id, **intent_binding})},
            (plan_ref, authority_ref, readiness_ref),
        )
        intent = self.receipts.load(intent_ref)
        try:
            response = self.adapter.apply({
                "task_id": task_id,
                "action_id": action_id,
                "idempotency_key": intent.body["idempotency_key"],
                **intent_binding,
            })
        except Exception as exc:
            self._receipt(
                "effect-unknown-receipt-v1", task_id, action_id,
                {"apply_intent_digest": intent_ref.digest},
                {"reason": type(exc).__name__}, (intent_ref,),
            )
            raise EffectUnknown(intent_ref, type(exc).__name__) from exc
        if response.get("effect_state") != "APPLIED" or not response.get("effect_revision"):
            raise EffectUnknown(intent_ref, "MALFORMED_OR_AMBIGUOUS_APPLY_RESPONSE")
        effect_ref = self._receipt(
            "effect-receipt-v1", task_id, action_id,
            {"apply_intent_digest": intent_ref.digest, "target_digest": target_digest},
            dict(response), (intent_ref,),
        )
        return intent_ref, effect_ref

    def reconcile(self, *, task_id: str, action_id: str, intent_ref: ReceiptRef) -> ReceiptRef:
        intent = self.receipts.load(intent_ref)
        if intent.kind != "apply-intent-receipt-v1":
            raise SagaBindingError("reconcile requires an apply-intent receipt")
        response = self.adapter.reconcile({
            "task_id": task_id,
            "action_id": action_id,
            "idempotency_key": intent.body["idempotency_key"],
            "apply_intent_digest": intent_ref.digest,
        })
        state = response.get("effect_state")
        if state not in {"APPLIED", "NOT_APPLIED", "UNKNOWN"}:
            state = "UNKNOWN"
        return self._receipt(
            "reconcile-receipt-v1", task_id, action_id,
            {"apply_intent_digest": intent_ref.digest},
            {**dict(response), "effect_state": state}, (intent_ref,),
        )

    def rollback(
        self,
        *,
        task_id: str,
        action_id: str,
        effect_ref: ReceiptRef,
        readiness_ref: ReceiptRef,
        authority_ref: ReceiptRef,
        release_binding: Mapping[str, str] | None = None,
        lifecycle: str = "ROLLBACK_REQUIRED",
    ) -> tuple[ReceiptRef, ReceiptRef]:
        self._release_check(release_binding=release_binding, lifecycle=lifecycle, operation="rollback")
        self.receipts.verify_graph([effect_ref, readiness_ref, authority_ref])
        authority = self.receipts.load(authority_ref)
        if authority.kind != "authority-receipt-v1" or authority.body.get("rollback_authorized") is not True:
            raise SagaBindingError("authority does not authorize rollback")
        self._consume_authority(authority_ref, "rollback", task_id, action_id)
        binding = {
            "effect_digest": effect_ref.digest,
            "rollback_readiness_digest": readiness_ref.digest,
            "authority_digest": authority_ref.digest,
        }
        intent_ref = self._receipt(
            "rollback-intent-receipt-v1", task_id, action_id, binding,
            {"idempotency_key": sha256_digest({"task_id": task_id, "action_id": action_id, **binding})},
            (effect_ref, readiness_ref, authority_ref),
        )
        response = self.adapter.rollback({
            "task_id": task_id,
            "action_id": action_id,
            "idempotency_key": self.receipts.load(intent_ref).body["idempotency_key"],
            **binding,
        })
        if response.get("rollback_state") != "ROLLED_BACK":
            raise EffectUnknown(intent_ref, "ROLLBACK_EFFECT_UNKNOWN")
        result_ref = self._receipt(
            "rollback-receipt-v1", task_id, action_id,
            {"rollback_intent_digest": intent_ref.digest}, dict(response), (intent_ref,),
        )
        return intent_ref, result_ref
