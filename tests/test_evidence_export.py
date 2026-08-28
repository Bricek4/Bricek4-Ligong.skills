from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from taskguard.evidence import export_evidence
from taskguard.state import ChecksumError


SKILL_ROOT = Path(__file__).resolve().parents[1]
TASK_GUARD = SKILL_ROOT / "scripts" / "task_guard.py"


def canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


class EvidenceExportTests(unittest.TestCase):
    def make_initialized_state(self, root: Path) -> Path:
        repo = root / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "value.txt").write_text("baseline\n", encoding="utf-8")
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(
            ["git", "-C", str(repo), "config", "user.name", "TaskGuard Test"],
            check=True,
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "config",
                "user.email",
                "taskguard@example.invalid",
            ],
            check=True,
        )
        subprocess.run(["git", "-C", str(repo), "add", "src/value.txt"], check=True)
        subprocess.run(["git", "-C", str(repo), "commit", "-qm", "baseline"], check=True)
        contract = {
            "version": 2,
            "task_id": "evidence-export",
            "goal": "provide deterministic export evidence",
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
            "forbidden": [],
            "surfaces": [],
        }
        contract_path = root / "contract.json"
        contract_path.write_text(json.dumps(contract), encoding="utf-8")
        state_dir = root / "state"
        capsule_path = root / "capsule.json"
        capsule_path.write_text(
            json.dumps(
                {
                    "version": 1,
                    "task_id": contract["task_id"],
                    "outcome": contract["goal"],
                    "scope": contract["scope"],
                    "invariants": [],
                    "evidence": ["evidence export tests"],
                    "risk": "L2",
                    "signals": ["false_supported"],
                    "external_actions": [],
                    "authority": [],
                }
            ),
            encoding="utf-8",
        )
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
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        result = subprocess.run(
            [
                sys.executable,
                str(TASK_GUARD),
                "init",
                "--state-dir",
                str(state_dir),
                "--contract",
                str(contract_path),
            ],
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return state_dir

    def test_export_is_read_only_checksummed_and_unknown_before_verification(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-export-") as directory:
            state_dir = self.make_initialized_state(Path(directory))
            for lock_path in state_dir.glob("*.lock"):
                lock_path.unlink()
            before = {
                path.name: path.read_bytes()
                for path in state_dir.iterdir()
                if path.is_file()
            }

            bundle = export_evidence(state_dir)

            after = {
                path.name: path.read_bytes()
                for path in state_dir.iterdir()
                if path.is_file()
            }

        unsigned = dict(bundle)
        digest = str(unsigned.pop("bundle_digest"))
        self.assertEqual(before, after)
        self.assertEqual(bundle["version"], "taskguard-evidence-v1")
        self.assertEqual(bundle["status"]["aggregate"], "UNKNOWN")
        self.assertIn("task_digest", bundle)
        self.assertIn("checkpoint", bundle)
        self.assertEqual(digest, hashlib.sha256(canonical_bytes(unsigned)).hexdigest())

    def test_cli_export_emits_canonical_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-export-cli-") as directory:
            state_dir = self.make_initialized_state(Path(directory))
            result = subprocess.run(
                [
                    sys.executable,
                    str(TASK_GUARD),
                    "export",
                    "--state-dir",
                    str(state_dir),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(
            result.stdout.strip(),
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )

    def test_corrupt_state_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-export-corrupt-") as directory:
            state_dir = self.make_initialized_state(Path(directory))
            state_path = state_dir / "task.json"
            raw = state_path.read_bytes()
            state_path.write_bytes(raw.replace(b'"revision":1', b'"revision":2'))

            with self.assertRaises(ChecksumError):
                export_evidence(state_dir)


if __name__ == "__main__":
    unittest.main()
