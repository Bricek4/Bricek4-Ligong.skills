from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
RUNNER = SKILL_ROOT / "scripts" / "run_evals.py"
CASES = SKILL_ROOT / "evals" / "risk-cases.json"


class EvalRunnerTests(unittest.TestCase):
    def test_eval_corpus_is_large_enough_to_cover_risk_boundaries(self) -> None:
        corpus = json.loads(CASES.read_text(encoding="utf-8"))

        self.assertEqual(corpus["version"], "ligong-risk-evals-v1")
        self.assertGreaterEqual(len(corpus["cases"]), 20)
        self.assertEqual(
            {case["stage"] for case in corpus["cases"]},
            {"initial", "diff", "final"},
        )
        self.assertGreaterEqual(
            sum("expected_error" in case for case in corpus["cases"]),
            3,
        )

    def test_runner_passes_from_arbitrary_cwd_with_canonical_summary(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-evals-") as directory:
            result = subprocess.run(
                [sys.executable, str(RUNNER)],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["failed"], 0)
        self.assertGreaterEqual(payload["passed"], 20)
        self.assertEqual(
            result.stdout.strip(),
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )

    def test_custom_failing_corpus_identifies_the_exact_case(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-evals-fail-") as directory:
            corpus_path = Path(directory) / "wrong.json"
            corpus_path.write_text(
                json.dumps(
                    {
                        "version": "ligong-risk-evals-v1",
                        "cases": [
                            {
                                "id": "deliberately-wrong",
                                "stage": "initial",
                                "capsule": {"risk": "L0"},
                                "expected": {"effective_risk": "L3"},
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, str(RUNNER), "--cases", str(corpus_path)],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["failed"], 1)
        self.assertEqual(payload["failures"][0]["id"], "deliberately-wrong")


if __name__ == "__main__":
    unittest.main()
