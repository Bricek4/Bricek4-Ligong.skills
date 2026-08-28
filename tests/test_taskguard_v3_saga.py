from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from taskguard.receipts import ReceiptRef
from taskguard.v3.action_machine import (
    ActionEvent,
    ActionLifecycle,
    ActionState,
    InvalidTransition,
    TRANSITIONS,
    reduce_action,
)
from taskguard.v3.aggregator import REQUIRED_DIMENSIONS, aggregate_terminal
from taskguard.v3.health import HealthSample, evaluate_health_window
from taskguard.v3.receipt_store import ReceiptStore
from taskguard.v3.receipts import RECEIPT_VERSION, Receipt
from taskguard.v3.saga import EffectUnknown, SagaBindingError, SagaService


NOW = datetime(2026, 8, 27, 4, 0, tzinfo=timezone.utc)


class DeterministicAdapter:
    def __init__(self) -> None:
        self.effects: dict[str, dict[str, object]] = {}
        self.rollbacks: dict[str, dict[str, object]] = {}
        self.disconnect_after_commit = False
        self.apply_calls = 0

    def prepare_rollback(self, request):
        return {"ready": True, "recovery_version": "before-1", "request": request["action_id"]}

    def apply(self, intent):
        self.apply_calls += 1
        key = intent["idempotency_key"]
        result = self.effects.setdefault(key, {"effect_state": "APPLIED", "effect_revision": "effect-1"})
        if self.disconnect_after_commit:
            self.disconnect_after_commit = False
            raise ConnectionError("commit before disconnect")
        return result

    def reconcile(self, query):
        return self.effects.get(query["idempotency_key"], {"effect_state": "NOT_APPLIED"})

    def rollback(self, intent):
        key = intent["idempotency_key"]
        return self.rollbacks.setdefault(key, {"rollback_state": "ROLLED_BACK", "effect_revision": "before-1"})


class SagaTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.store = ReceiptStore(Path(self.temporary.name) / "evidence")
        self.adapter = DeterministicAdapter()
        self.consumed: set[tuple[str, str]] = set()

        def consume(ref, operation, task_id, action_id):
            key = (ref.digest, operation)
            if key in self.consumed or task_id != "task" or action_id != "action":
                return False
            self.consumed.add(key)
            return True

        self.saga = SagaService(self.store, self.adapter, clock=lambda: NOW, authority_consumer=consume)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def put(self, kind, binding, body, parents=()):
        return self.store.put(Receipt(
            RECEIPT_VERSION, kind, "task", "action", binding, body,
            tuple(sorted(parents, key=lambda item: (item.digest, item.kind))), NOW.isoformat(),
        ))

    def prerequisites(self):
        plan = self.put("plan-receipt-v1", {"target_digest": "target"}, {"plan": "safe"})
        authority = self.put(
            "authority-receipt-v1",
            {"plan_digest": plan.digest, "target_digest": "target"},
            {"apply_authorized": True, "rollback_authorized": True},
            (plan,),
        )
        readiness = self.saga.prepare_rollback(
            task_id="task", action_id="action", plan_ref=plan, authority_ref=authority,
            target_digest="target", recovery_point={"revision": "before-1"},
        )
        return plan, authority, readiness

    def test_apply_intent_precedes_effect_and_key_is_idempotent(self) -> None:
        plan, authority, readiness = self.prerequisites()
        intent, effect = self.saga.apply(
            task_id="task", action_id="action", plan_ref=plan, authority_ref=authority,
            readiness_ref=readiness, target_digest="target",
        )
        self.assertEqual(self.store.load(effect).parents, (intent,))
        first_key = self.store.load(intent).body["idempotency_key"]
        duplicate = self.adapter.apply({"idempotency_key": first_key})
        self.assertEqual(duplicate["effect_revision"], "effect-1")
        self.assertEqual(len(self.adapter.effects), 1)

    def test_commit_before_disconnect_is_reconciled_without_replay(self) -> None:
        plan, authority, readiness = self.prerequisites()
        self.adapter.disconnect_after_commit = True
        with self.assertRaises(EffectUnknown) as caught:
            self.saga.apply(
                task_id="task", action_id="action", plan_ref=plan, authority_ref=authority,
                readiness_ref=readiness, target_digest="target",
            )
        reconciled = self.saga.reconcile(task_id="task", action_id="action", intent_ref=caught.exception.intent_ref)
        self.assertEqual(self.store.load(reconciled).body["effect_state"], "APPLIED")
        self.assertEqual(len(self.adapter.effects), 1)

    def test_wrong_binding_and_apply_only_rollback_are_rejected(self) -> None:
        plan, authority, readiness = self.prerequisites()
        with self.assertRaises(SagaBindingError):
            self.saga.apply(
                task_id="task", action_id="action", plan_ref=plan, authority_ref=authority,
                readiness_ref=readiness, target_digest="different",
            )
        apply_only = self.put(
            "authority-receipt-v1",
            {"plan_digest": plan.digest, "target_digest": "target"},
            {"apply_authorized": True, "rollback_authorized": False}, (plan,),
        )
        effect = self.put("effect-receipt-v1", {"target_digest": "target"}, {"effect_revision": "effect-1"})
        with self.assertRaises(SagaBindingError):
            self.saga.rollback(
                task_id="task", action_id="action", effect_ref=effect,
                readiness_ref=readiness, authority_ref=apply_only,
            )

    def test_action_machine_rejects_every_undeclared_transition(self) -> None:
        for lifecycle in ActionLifecycle:
            for event in ActionEvent:
                state = ActionState(lifecycle, 1)
                if (lifecycle, event) in TRANSITIONS:
                    payload = {}
                    if event in {ActionEvent.APPLY_UNKNOWN, ActionEvent.HEALTH_FAIL, ActionEvent.ROLLBACK_UNKNOWN, ActionEvent.FINALIZE_ERROR}:
                        payload["failure_reason"] = "test"
                    self.assertEqual(reduce_action(state, event, payload).revision, 2)
                else:
                    with self.assertRaises(InvalidTransition):
                        reduce_action(state, event)

    def test_health_is_revision_and_window_bound(self) -> None:
        healthy = evaluate_health_window(
            [
                HealthSample("effect-1", 0, {"revision": True, "ready": True}),
                HealthSample("effect-1", 300, {"revision": True, "ready": True}),
            ],
            effect_revision="effect-1", required_signals=("revision", "ready"),
            minimum_samples=2, window_seconds=300,
        )
        self.assertEqual(healthy.verdict, "SUPPORTED")
        failed = evaluate_health_window(
            [
                HealthSample("effect-1", 0, {"revision": True, "ready": True}),
                HealthSample("effect-1", 300, {"revision": True, "ready": False}),
            ],
            effect_revision="effect-1", required_signals=("revision", "ready"),
            minimum_samples=2, window_seconds=300,
        )
        self.assertEqual(failed.verdict, "FAILED")

    def test_only_complete_dimensions_can_be_supported(self) -> None:
        dimensions = {name: "SUPPORTED" for name in REQUIRED_DIMENSIONS}
        self.assertEqual(aggregate_terminal(dimensions, "HEALTHY").verdict, "SUPPORTED")
        for name in REQUIRED_DIMENSIONS:
            changed = dict(dimensions)
            changed[name] = "STALE"
            self.assertEqual(aggregate_terminal(changed, "HEALTHY").verdict, "FAILED")
        self.assertEqual(aggregate_terminal(dimensions, "RECOVERED").verdict, "FAILED")


if __name__ == "__main__":
    unittest.main()
