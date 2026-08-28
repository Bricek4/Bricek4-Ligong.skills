from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
RUNNER = SKILL_ROOT / "scripts" / "run_tests.py"


class PortableTestEntryTests(unittest.TestCase):
    def test_runner_executes_selected_test_from_arbitrary_cwd(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-test-entry-") as directory:
            result = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--pattern",
                    "test_taskguard_contract_conflicts.py",
                ],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Ran 3 tests", result.stderr)
        self.assertIn("OK", result.stderr)


if __name__ == "__main__":
    unittest.main()
