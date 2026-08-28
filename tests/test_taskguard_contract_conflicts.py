from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from taskguard.cli import _normalize_surface


SKILL_ROOT = Path(__file__).resolve().parents[1]
TASK_GUARD = SKILL_ROOT / "scripts" / "task_guard.py"


class TaskGuardContractConflictTests(unittest.TestCase):
    def test_json_v1_preserves_array_order_but_canonicalizes_object_keys(self) -> None:
        first = _normalize_surface(
            b'{"meta":{"b":2,"a":1},"tags":["release","legal-hold"]}',
            "json-v1",
        )
        reordered_keys = _normalize_surface(
            b'{"tags":["release","legal-hold"],"meta":{"a":1,"b":2}}',
            "json-v1",
        )
        reversed_tags = _normalize_surface(
            b'{"meta":{"a":1,"b":2},"tags":["legal-hold","release"]}',
            "json-v1",
        )

        self.assertEqual(first, reordered_keys)
        self.assertNotEqual(first, reversed_tags)

    def make_repo(self, root: Path) -> Path:
        repo = root / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "model.js").write_text(
            "export const artifact = { legacyDeleted: false };\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "config", "user.name", "TaskGuard Test"], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.email", "taskguard@example.invalid"],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "add", "src/model.js"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "baseline"], check=True)
        return repo

    def contract(self, repo: Path, *, include_removed_field: bool) -> dict[str, object]:
        response = {"artifact": {"id": "a", "tags": ["release", "legal-hold"]}}
        if include_removed_field:
            response["artifact"]["legacyDeleted"] = False
        surface_code = "import json; print(json.dumps(" + repr(response) + "))"
        return {
            "version": 2,
            "task_id": "contract-conflict",
            "goal": "remove legacy deletion state while preserving stable v1 fields",
            "risk": "L2",
            "repo": str(repo),
            "scope": ["src/**"],
            "acknowledge_dirty": [],
            "acceptance": [
                {
                    "id": "unit",
                    "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                    "cwd": ".",
                    "requires_red": False,
                    "idempotent": True,
                }
            ],
            "forbidden": [
                {
                    "id": "legacy-field",
                    "glob": "src/**",
                    "regex": "legacyDeleted",
                    "mode": "eliminate",
                }
            ],
            "surfaces": [
                {
                    "id": "v1-read",
                    "argv": [sys.executable, "-c", surface_code],
                    "cwd": ".",
                    "read_only": True,
                    "allowed_writes": [],
                    "normalizer_version": "json-v1",
                }
            ],
        }

    def run_init(self, root: Path, contract: dict[str, object]) -> subprocess.CompletedProcess[str]:
        contract_path = root / "contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        capsule_path = root / "capsule.json"
        capsule_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "task_id": contract["task_id"],
                    "outcome": contract["goal"],
                    "scope": contract["scope"],
                    "invariants": [],
                    "evidence": ["contract conflict tests"],
                    "risk": "L2",
                    "signals": ["public_api"],
                    "external_actions": [],
                    "authority": [],
                }
            ),
            encoding="utf-8",
        )
        state_dir = root / "state"
        preflight = subprocess.run(
            [
                sys.executable,
                str(TASK_GUARD),
                "preflight",
                "--capsule",
                str(capsule_path),
                "--stage",
                "initial",
                "--chain-dir",
                str(state_dir),
            ],
            cwd=contract["repo"],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        return subprocess.run(
            [
                sys.executable,
                str(TASK_GUARD),
                "init",
                "--state-dir",
                str(state_dir),
                "--contract",
                str(contract_path),
            ],
            cwd=contract["repo"],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_init_rejects_eliminated_token_frozen_by_surface(self) -> None:
        with tempfile.TemporaryDirectory(prefix="taskguard-conflict-") as directory:
            root = Path(directory)
            repo = self.make_repo(root)
            result = self.run_init(root, self.contract(repo, include_removed_field=True))

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("contract conflict", result.stderr)
        self.assertIn("legacy-field", result.stderr)
        self.assertIn("v1-read", result.stderr)

    def test_init_accepts_surface_projection_without_eliminated_token(self) -> None:
        with tempfile.TemporaryDirectory(prefix="taskguard-no-conflict-") as directory:
            root = Path(directory)
            repo = self.make_repo(root)
            result = self.run_init(root, self.contract(repo, include_removed_field=False))

        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
