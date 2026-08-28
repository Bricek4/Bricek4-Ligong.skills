from __future__ import annotations

import unittest

from taskguard.risk import CapsuleError, evaluate_risk, validate_capsule


def capsule(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "task_id": "migration-auth",
        "outcome": "deliver the requested repository behavior",
        "scope": ["src/**", "tests/**"],
        "invariants": ["tenant isolation remains enforced"],
        "evidence": ["focused tests"],
        "risk": "L1",
        "signals": [],
        "external_actions": [],
        "authority": [],
    }
    value.update(overrides)
    return value


class RiskFuseTests(unittest.TestCase):
    def staged(self, value: dict[str, object], stage: str) -> dict[str, object]:
        if stage == "initial":
            return evaluate_risk(value, "initial")
        initial = evaluate_risk(value, "initial")
        diff = evaluate_risk(value, "diff", previous_result=initial)
        if stage == "diff":
            return diff
        return evaluate_risk(value, "final", previous_result=diff)

    def test_public_api_hard_trigger_requires_l2(self) -> None:
        result = evaluate_risk(capsule(signals=["public_api"]), "initial")

        self.assertEqual(result["effective_risk"], "L2")
        self.assertEqual(result["hard_triggers"], ["public_api"])
        self.assertFalse(result["admitted"])
        self.assertIn("taskguard", result["guards"])

    def test_production_write_requires_l3_and_matching_authority(self) -> None:
        action = {
            "action": "production_write",
            "target": "orders-db",
            "environment": "production",
            "scope": "orders/*",
        }
        missing = evaluate_risk(
            capsule(signals=["production_write"], external_actions=[action]),
            "initial",
        )
        authorized = self.staged(
            capsule(
                risk="L3",
                signals=["production_write"],
                external_actions=[action],
                authority=[
                    {
                        **action,
                        "task_id": "migration-auth",
                        "user_evidence": "user explicitly approved this target",
                    }
                ],
            ),
            "diff",
        )

        self.assertEqual(missing["effective_risk"], "L3")
        self.assertEqual(
            missing["blockers"],
            ["missing_authority:production_write:orders-db"],
        )
        self.assertFalse(missing["admitted"])
        self.assertTrue(authorized["admitted"])
        self.assertIn("rollback", authorized["guards"])

    def test_two_soft_signals_raise_l1_to_l2(self) -> None:
        result = self.staged(
            capsule(signals=["dirty_overlap", "evidence_conflict"]),
            "diff",
        )

        self.assertEqual(result["effective_risk"], "L2")
        self.assertEqual(
            result["soft_signals"],
            ["dirty_overlap", "evidence_conflict"],
        )
        self.assertFalse(result["independent_review"])

    def test_soft_signals_at_l2_request_review_but_never_create_l3(self) -> None:
        result = self.staged(
            capsule(
                risk="L2",
                signals=["dirty_overlap", "evidence_conflict"],
            ),
            "diff",
        )

        self.assertEqual(result["effective_risk"], "L2")
        self.assertTrue(result["independent_review"])
        self.assertTrue(result["admitted"])
        self.assertIn("independent_review", result["guards"])

    def test_final_contradictory_evidence_blocks_completion(self) -> None:
        result = self.staged(
            capsule(risk="L2", signals=["evidence_conflict"]),
            "final",
        )

        self.assertEqual(result["blockers"], ["contradictory_evidence"])
        self.assertFalse(result["admitted"])

    def test_scope_expansion_blocks_until_scope_is_reconfirmed(self) -> None:
        initial = evaluate_risk(capsule(), "initial")
        result = evaluate_risk(
            capsule(signals=["scope_expansion"]),
            "diff",
            previous_result=initial,
        )

        self.assertEqual(result["blockers"], ["scope_reconfirmation_required"])
        self.assertFalse(result["admitted"])

    def test_capsule_rejects_unknown_duplicate_and_wrong_types(self) -> None:
        invalid_values = [
            capsule(signals=["unknown-signal"]),
            capsule(signals=["dirty_overlap", "dirty_overlap"]),
            capsule(version=True),
            capsule(scope=["../escape"]),
            {**capsule(), "extra": "not allowed"},
        ]

        for value in invalid_values:
            with self.subTest(value=value):
                with self.assertRaises(CapsuleError):
                    validate_capsule(value)

    def test_invalid_stage_is_rejected(self) -> None:
        with self.assertRaises(CapsuleError):
            evaluate_risk(capsule(), "after-lunch")

    def test_later_stages_require_a_valid_monotonic_previous_result(self) -> None:
        initial = evaluate_risk(
            capsule(risk="L2", signals=["public_api"]),
            "initial",
        )
        dropped = capsule(risk="L1", signals=[])

        without_previous = evaluate_risk(dropped, "diff")
        diff = evaluate_risk(dropped, "diff", previous_result=initial)
        tampered = dict(initial)
        tampered["effective_risk"] = "L0"

        self.assertIn("previous_stage_result_required", without_previous["blockers"])
        self.assertEqual(diff["effective_risk"], "L2")
        self.assertIn("public_api", diff["hard_triggers"])
        self.assertFalse(diff["admitted"])
        with self.assertRaises(CapsuleError):
            evaluate_risk(dropped, "diff", previous_result=tampered)

    def test_authority_is_bound_to_exact_target(self) -> None:
        requested = {
            "action": "production_write",
            "target": "service-b",
            "environment": "production",
            "scope": "records/*",
        }
        wrong_target = {
            "action": "production_write",
            "target": "service-a",
            "environment": "production",
            "scope": "records/*",
            "task_id": "migration-auth",
            "user_evidence": "approved service-a only",
        }

        result = evaluate_risk(
            capsule(
                risk="L3",
                signals=["production_write"],
                external_actions=[requested],
                authority=[wrong_target],
            ),
            "initial",
        )

        self.assertIn("missing_authority:production_write:service-b", result["blockers"])
        self.assertFalse(result["admitted"])


if __name__ == "__main__":
    unittest.main()
