from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]
GUARD = SKILL_ROOT / "scripts" / "workspace_guard.py"


def git(root: Path, *argv: str) -> None:
    subprocess.run(["git", *argv], cwd=root, check=True, capture_output=True)


class WorkspaceGuardTests(unittest.TestCase):
    def test_rejects_outside_target_and_detects_protected_repo_change(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-workspace-guard-") as directory:
            root = Path(directory)
            active = root / "active"
            protected = root / "source"
            for repo in (active, protected):
                repo.mkdir()
                git(repo, "init", "-q")
                git(repo, "config", "user.email", "ligong@example.invalid")
                git(repo, "config", "user.name", "Ligong Test")
                (repo / "tracked.txt").write_text("baseline\n", encoding="utf-8")
                git(repo, "add", "tracked.txt")
                git(repo, "commit", "-qm", "baseline")
            state = root / "guard.json"

            bound = subprocess.run(
                [sys.executable, str(GUARD), "bind", "--workspace", str(active),
                 "--protect", str(protected), "--state", str(state)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(bound.returncode, 0, bound.stderr)

            outside = subprocess.run(
                [sys.executable, str(GUARD), "assert-path", "--state", str(state),
                 "--path", "inside.txt", "--path", str(protected / "tracked.txt")],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(outside.returncode, 1)
            self.assertEqual(json.loads(outside.stdout)["status"], "VIOLATION")

            (protected / "unexpected.txt").write_text("pollution\n", encoding="utf-8")
            checked = subprocess.run(
                [sys.executable, str(GUARD), "check", "--state", str(state)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(checked.returncode, 1)
            self.assertEqual(json.loads(checked.stdout)["status"], "VIOLATION")


if __name__ == "__main__":
    unittest.main()
