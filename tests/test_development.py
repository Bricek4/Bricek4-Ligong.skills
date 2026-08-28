from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from taskguard.development import evaluate_development_capsule


SKILL_ROOT = Path(__file__).resolve().parents[1]
FORGE_CHECK = SKILL_ROOT / "scripts" / "forge_check.py"
RUN_EVALS = SKILL_ROOT / "scripts" / "run_development_evals.py"


def candidate(
    candidate_id: str,
    mechanism: str,
    *,
    status: str = "rejected",
    wildcard: bool = False,
) -> dict[str, object]:
    return {
        "id": candidate_id,
        "mechanism": mechanism,
        "summary": f"implement through {mechanism}",
        "tradeoffs": [f"cost profile for {mechanism}"],
        "status": status,
        "evidence": ["selected by explicit tournament"] if status == "chosen" else ["loses on measured fit"],
        "wildcard": wildcard,
    }


def capsule(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "task_id": "offline-sync",
        "creativity": "C3",
        "outcome": "offline edits synchronize exactly once without silent loss",
        "constraints": ["preserve the public API"],
        "non_goals": ["replace the entire transport stack"],
        "signals": ["compatibility", "concurrency", "recovery"],
        "candidates": [
            candidate("poll", "snapshot-polling"),
            candidate("outbox", "persistent-outbox", status="chosen"),
            candidate("events", "event-sourcing"),
            candidate("crdt", "crdt-replication", wildcard=True),
        ],
        "chosen_candidate": "outbox",
        "decision_evidence": ["best reversible fit to the existing polling boundary"],
        "requirements": [
            {
                "id": "exactly-once",
                "outcome": "a retried operation has one external effect",
                "owner": "sync/outbox.ts",
                "invariant": "operationId is durable and unique",
                "evidence": ["concurrent retry test"],
            }
        ],
        "validation": [
            {"lane": lane, "evidence": f"planned {lane} probe"}
            for lane in (
                "adversarial",
                "behavior",
                "compatibility",
                "concurrency",
                "failure",
                "recovery",
                "regression",
                "simplification",
            )
        ],
    }
    value.update(overrides)
    return value


class DevelopmentCapsuleTests(unittest.TestCase):
    def test_c3_ready_requires_diverse_tournament_traceability_and_signal_lanes(self) -> None:
        result = evaluate_development_capsule(capsule())

        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["creativity"], "C3")
        self.assertEqual(result["required_candidate_count"], 4)
        self.assertEqual(result["missing"], [])

    def test_c3_without_wildcard_is_revise(self) -> None:
        value = capsule()
        value["candidates"] = [
            candidate("poll", "snapshot-polling"),
            candidate("outbox", "persistent-outbox", status="chosen"),
            candidate("events", "event-sourcing"),
            candidate("queue", "durable-queue"),
        ]

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "REVISE")
        self.assertIn("wildcard_candidate", result["missing"])

    def test_superficial_candidate_diversity_is_revise(self) -> None:
        value = capsule(creativity="C2")
        value["candidates"] = [
            candidate("a", "polling", status="chosen"),
            candidate("b", " Polling "),
            candidate("c", "POLLING"),
        ]
        value["chosen_candidate"] = "a"

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "REVISE")
        self.assertIn("distinct_candidate_mechanisms:3", result["missing"])

    def test_signals_add_required_validation_lanes(self) -> None:
        value = capsule(creativity="C1", signals=["performance", "migration", "security"])
        value["candidates"] = [
            candidate("a", "direct-change", status="chosen"),
            candidate("b", "compatibility-adapter"),
        ]
        value["chosen_candidate"] = "a"
        value["validation"] = [
            {"lane": "behavior", "evidence": "focused behavior test"},
            {"lane": "regression", "evidence": "existing suite"},
        ]

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "REVISE")
        self.assertEqual(
            result["missing"],
            ["validation:migration", "validation:performance", "validation:security"],
        )

    def test_requirement_without_owner_is_invalid(self) -> None:
        value = capsule()
        value["requirements"] = [
            {
                "id": "broken",
                "outcome": "something happens",
                "owner": "",
                "invariant": "something remains true",
                "evidence": ["a test"],
            }
        ]

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "INVALID")
        self.assertIn("requirements[0].owner must be a non-empty string", result["findings"])

    def test_chosen_candidate_must_reference_the_single_chosen_entry(self) -> None:
        result = evaluate_development_capsule(capsule(chosen_candidate="events"))

        self.assertEqual(result["status"], "INVALID")
        self.assertIn("chosen_candidate must reference the candidate with status chosen", result["findings"])

    def test_exact_types_and_known_keys_are_enforced(self) -> None:
        value = capsule(version=True, surprise="not allowed")

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "INVALID")
        self.assertIn("unknown capsule fields: surprise", result["findings"])
        self.assertIn("version must be integer 1", result["findings"])

    def test_unhashable_enum_values_return_invalid_instead_of_crashing(self) -> None:
        creativity = evaluate_development_capsule(capsule(creativity=[]))
        value = capsule()
        value["candidates"][0]["status"] = []
        status = evaluate_development_capsule(value)

        self.assertEqual(creativity["status"], "INVALID")
        self.assertEqual(status["status"], "INVALID")

    def test_variant_suffixes_do_not_create_mechanism_diversity(self) -> None:
        value = capsule()
        value["candidates"] = [
            candidate("a", "polling", status="chosen"),
            candidate("b", "polling-v2"),
            candidate("c", "polling-fast"),
            candidate("d", "polling-plus", wildcard=True),
        ]
        value["chosen_candidate"] = "a"

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "REVISE")
        self.assertIn("distinct_candidate_mechanisms:4", result["missing"])

    def test_unicode_mechanism_names_remain_distinct(self) -> None:
        value = capsule()
        value["candidates"] = [
            candidate("a", "直接修改状态机", status="chosen"),
            candidate("b", "兼容适配层"),
            candidate("c", "事件日志"),
            candidate("d", "约束求解器", wildcard=True),
        ]
        value["chosen_candidate"] = "a"

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "READY")

    def test_every_candidate_needs_tradeoffs_and_selection_or_rejection_evidence(self) -> None:
        value = capsule()
        value["candidates"][0]["tradeoffs"] = []
        value["candidates"][1]["evidence"] = []

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "REVISE")
        self.assertIn("candidate_tradeoffs:poll", result["missing"])
        self.assertIn("selection_evidence:outbox", result["missing"])

    def test_non_goals_are_a_required_string_array(self) -> None:
        value = capsule()
        del value["non_goals"]
        missing = evaluate_development_capsule(value)
        malformed = evaluate_development_capsule(capsule(non_goals=[False]))

        self.assertEqual(missing["status"], "INVALID")
        self.assertIn("missing capsule fields: non_goals", missing["findings"])
        self.assertEqual(malformed["status"], "INVALID")
        self.assertIn("non_goals[0] must be a non-empty string", malformed["findings"])

    def test_c0_keeps_the_fast_path(self) -> None:
        value = capsule(creativity="C0", signals=[])
        value["candidates"] = [candidate("only", "mechanical-edit", status="chosen")]
        value["chosen_candidate"] = "only"
        value["validation"] = [{"lane": "behavior", "evidence": "focused check"}]

        result = evaluate_development_capsule(value)

        self.assertEqual(result["status"], "READY")
        self.assertEqual(result["required_candidate_count"], 1)


class DevelopmentCliTests(unittest.TestCase):
    def test_forge_check_is_cwd_independent_and_canonical(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-forge-check-") as directory:
            path = Path(directory) / "capsule.json"
            path.write_text(json.dumps(capsule()), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(FORGE_CHECK), str(path)],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "READY")
        self.assertEqual(result.stdout, json.dumps(parsed, sort_keys=True, separators=(",", ":")) + "\n")

    def test_forge_check_exit_codes_distinguish_revise_and_invalid(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-forge-exits-") as directory:
            root = Path(directory)
            revise_path = root / "revise.json"
            invalid_path = root / "invalid.json"
            revise_value = capsule(creativity="C3", signals=[])
            revise_value["candidates"] = [
                candidate("only", "mechanical-edit", status="chosen")
            ]
            revise_value["chosen_candidate"] = "only"
            revise_value["validation"] = [
                {"lane": lane, "evidence": f"planned {lane} probe"}
                for lane in ("adversarial", "behavior", "failure", "regression", "simplification")
            ]
            revise_path.write_text(json.dumps(revise_value), encoding="utf-8")
            invalid_path.write_text("[]", encoding="utf-8")
            revise = subprocess.run(
                [sys.executable, str(FORGE_CHECK), str(revise_path)],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )
            invalid = subprocess.run(
                [sys.executable, str(FORGE_CHECK), str(invalid_path)],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(revise.returncode, 2, revise.stderr)
        self.assertEqual(invalid.returncode, 3, invalid.stderr)

    def test_forge_check_rejects_duplicate_json_keys_with_canonical_invalid_output(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-forge-duplicate-") as directory:
            path = Path(directory) / "duplicate.json"
            path.write_text('{"version":999,"version":1}', encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(FORGE_CHECK), str(path)],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 3, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["status"], "INVALID")
        self.assertIn("duplicate JSON key: version", parsed["findings"][0])

    def test_development_eval_runner_reports_canonical_summary(self) -> None:
        result = subprocess.run(
            [sys.executable, str(RUN_EVALS)],
            cwd="/private/tmp",
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertGreaterEqual(parsed["total"], 24)
        self.assertEqual(parsed["failed"], 0)
        self.assertEqual(parsed["passed"], parsed["total"])

    def test_development_eval_runner_rejects_empty_expectations(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-development-corpus-") as directory:
            path = Path(directory) / "cases.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "base": capsule(),
                        "cases": [{"id": "vacuous", "patch": {}, "expected": {}}],
                    }
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(RUN_EVALS), "--cases", str(path)],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("expected must include status", result.stderr)

    def test_development_eval_runner_names_the_exact_failed_case(self) -> None:
        value = capsule()
        value["candidates"] = [
            candidate("a", "direct", status="chosen"),
            candidate("b", "adapter"),
            candidate("c", "events"),
            candidate("d", "queue"),
        ]
        value["chosen_candidate"] = "a"
        with tempfile.TemporaryDirectory(prefix="ligong-development-failure-") as directory:
            path = Path(directory) / "cases.json"
            path.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "base": value,
                        "cases": [
                            {"id": "wildcard-required", "patch": {}, "expected": {"status": "READY"}}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(RUN_EVALS), "--cases", str(path)],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["failed"], 1)
        self.assertEqual(parsed["failures"][0]["id"], "wildcard-required")

    def test_development_eval_runner_rejects_boolean_version_and_malformed_contains(self) -> None:
        bad_corpora = [
            {
                "version": True,
                "base": capsule(),
                "cases": [{"id": "bad-version", "patch": {}, "expected": {"status": "READY"}}],
            },
            {
                "version": 1,
                "base": capsule(),
                "cases": [
                    {
                        "id": "bad-contains",
                        "patch": {},
                        "expected": {"status": "READY", "missing_contains": "ignored-before"},
                    }
                ],
            },
            {
                "version": 1,
                "base": capsule(),
                "cases": [{"id": "bad-status", "patch": {}, "expected": {"status": []}}],
            },
        ]
        for index, corpus in enumerate(bad_corpora):
            with self.subTest(index=index), tempfile.TemporaryDirectory(
                prefix="ligong-development-malformed-"
            ) as directory:
                path = Path(directory) / "cases.json"
                path.write_text(json.dumps(corpus), encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(RUN_EVALS), "--cases", str(path)],
                    cwd=directory,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn("development eval corpus error", result.stderr)

    def test_development_eval_runner_rejects_empty_case_corpus(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-development-empty-") as directory:
            path = Path(directory) / "cases.json"
            path.write_text(
                json.dumps({"version": 1, "base": capsule(), "cases": []}),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(RUN_EVALS), "--cases", str(path)],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("cases must be a non-empty array", result.stderr)


if __name__ == "__main__":
    unittest.main()
