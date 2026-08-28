from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from taskguard.capabilities import evaluate_capabilities
from taskguard.cli import (
    _acceptance_binding,
    _admission_manifest,
    _contract_manifest,
    _digest,
)
from taskguard.contract import load_contract
from taskguard.control import preflight_capsule
from taskguard.state import StateStore
from taskguard.workspace import WorkspaceSnapshot


SKILL_ROOT = Path(__file__).resolve().parents[1]
TASK_GUARD = SKILL_ROOT / "scripts" / "task_guard.py"


def capsule(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "task_id": "sss-control",
        "outcome": "verify the requested repository behavior",
        "scope": ["src/**"],
        "invariants": [],
        "evidence": ["focused tests"],
        "risk": "L1",
        "signals": [],
        "external_actions": [],
        "authority": [],
    }
    value.update(overrides)
    return value


def capability_facts(**overrides: bool) -> dict[str, bool]:
    facts = {
        "posix_platform": True,
        "fcntl": True,
        "o_nofollow": True,
        "o_directory": True,
        "directory_fsync": True,
        "process_groups": True,
        "required_signals": True,
        "git": True,
    }
    facts.update(overrides)
    return facts


def create_legacy_l3_state(contract_path: Path, state_dir: Path, repo: Path) -> None:
    """Create the canonical state shape emitted before L3 init became fail-closed."""

    contract = load_contract(contract_path, workspace_root=repo)
    manifest = _contract_manifest(contract)
    baseline_manifest = WorkspaceSnapshot.capture(
        contract.repo,
        scope=list(contract.scope),
        acknowledged_dirty=list(contract.acknowledge_dirty),
    ).to_manifest()
    obligations = {
        "acceptance": {
            str(item["id"]): {
                "binding_digest": _digest(_acceptance_binding(item)),
                "baseline": None if item["requires_red"] else {"verdict": "NOT_REQUIRED"},
                "candidate": None,
            }
            for item in manifest["acceptance"]
        },
        "forbidden": {},
        "surfaces": {},
    }
    StateStore(state_dir).create(
        "task",
        owner="legacy-task-owner",
        contract=manifest,
        contract_digest=_digest(manifest),
        baseline_snapshot=baseline_manifest,
        obligations=obligations,
        admission_anchor=_digest(
            _admission_manifest(manifest, baseline_manifest, obligations)
        ),
        aggregate="UNKNOWN",
        obligation_results={},
        verification_receipt=None,
        execution_lease=None,
        current_operation=None,
        next_action="RUN_BASELINE_OR_CANDIDATE",
    )


class CapabilityTests(unittest.TestCase):
    def test_supported_platform_requires_every_safety_capability(self) -> None:
        supported = evaluate_capabilities(
            "darwin",
            capability_facts(),
            python_version="3.12.4",
        )
        unsupported = evaluate_capabilities(
            "win32",
            capability_facts(
                posix_platform=False,
                fcntl=False,
                o_nofollow=False,
                process_groups=False,
            ),
            python_version="3.12.4",
        )

        self.assertTrue(supported["taskguard_supported"])
        self.assertEqual(supported["missing"], [])
        self.assertFalse(unsupported["taskguard_supported"])
        self.assertEqual(
            unsupported["missing"],
            ["posix_platform", "fcntl", "o_nofollow", "process_groups"],
        )
        forged_windows = evaluate_capabilities(
            "win32", capability_facts(), python_version="3.12.4"
        )
        self.assertFalse(forged_windows["taskguard_supported"])
        self.assertIn("posix_platform", forged_windows["missing"])


class PreflightTests(unittest.TestCase):
    def test_contradictory_injected_capability_report_is_rejected(self) -> None:
        contradictory = evaluate_capabilities(
            "darwin",
            capability_facts(),
            python_version="3.12.4",
        )
        contradictory["missing"] = ["fcntl"]

        with self.assertRaises(ValueError):
            preflight_capsule(
                capsule(risk="L2", signals=["public_api"]),
                stage="initial",
                capability_report=contradictory,
            )

    def test_l0_is_not_required_on_unsupported_platform(self) -> None:
        capabilities = evaluate_capabilities(
            "win32",
            capability_facts(posix_platform=False, fcntl=False),
            python_version="3.12.4",
        )

        result = preflight_capsule(
            capsule(risk="L0"),
            stage="initial",
            capability_report=capabilities,
        )

        self.assertEqual(result["status"], "NOT_REQUIRED")
        self.assertNotEqual(result["status"], "SUPPORTED")
        self.assertTrue(result["admitted"])

    def test_l2_fails_closed_on_unsupported_platform(self) -> None:
        capabilities = evaluate_capabilities(
            "win32",
            capability_facts(posix_platform=False, fcntl=False),
            python_version="3.12.4",
        )

        result = preflight_capsule(
            capsule(risk="L2", signals=["public_api"]),
            stage="initial",
            capability_report=capabilities,
        )

        self.assertEqual(result["status"], "UNSUPPORTED")
        self.assertFalse(result["admitted"])
        self.assertIn("fcntl", result["missing_capabilities"])

    def test_risk_upgrade_is_reported_before_taskguard_admission(self) -> None:
        capabilities = evaluate_capabilities(
            "darwin",
            capability_facts(),
            python_version="3.12.4",
        )

        result = preflight_capsule(
            capsule(risk="L1", signals=["migration"]),
            stage="initial",
            capability_report=capabilities,
        )

        self.assertEqual(result["status"], "RECLASSIFY")
        self.assertEqual(result["risk"]["effective_risk"], "L2")
        self.assertFalse(result["admitted"])

    def test_l3_is_explicitly_unsupported_until_extended_evidence_is_bound(self) -> None:
        action = {
            "action": "deploy",
            "target": "api",
            "environment": "production",
            "scope": "release-42",
        }
        result = preflight_capsule(
            capsule(
                risk="L3",
                signals=["deploy"],
                external_actions=[action],
                authority=[
                    {
                        **action,
                        "task_id": "sss-control",
                        "user_evidence": "user approved release-42",
                    }
                ],
            ),
            stage="initial",
            capability_report=evaluate_capabilities(
                "darwin", capability_facts(), python_version="3.12.4"
            ),
        )

        self.assertEqual(result["status"], "UNSUPPORTED")
        self.assertFalse(result["admitted"])
        self.assertIn("l3_evidence_binding", result["missing_guards"])


class PublicControlCliTests(unittest.TestCase):
    def test_doctor_runs_from_arbitrary_cwd_and_emits_canonical_json(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-doctor-") as directory:
            result = subprocess.run(
                [sys.executable, str(TASK_GUARD), "doctor"],
                cwd=directory,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["version"], "taskguard-capabilities-v1")
        self.assertEqual(
            result.stdout.strip(),
            json.dumps(payload, sort_keys=True, separators=(",", ":")),
        )

    def test_fuse_reports_upgrade_without_creating_state(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-fuse-") as directory:
            root = Path(directory)
            capsule_path = root / "capsule.json"
            capsule_path.write_text(
                json.dumps(capsule(signals=["public_api"])),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(TASK_GUARD),
                    "fuse",
                    "--capsule",
                    str(capsule_path),
                    "--stage",
                    "initial",
                ],
                cwd=root,
                text=True,
                capture_output=True,
                check=False,
            )

            remaining = sorted(path.name for path in root.iterdir())

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(json.loads(result.stdout)["effective_risk"], "L2")
        self.assertEqual(remaining, ["capsule.json"])

    def test_preflight_accepts_a_valid_l2_taskguard_contract(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-contract-preflight-") as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src" / "value.txt").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            contract_path = root / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "task_id": "preflight-contract",
                        "goal": "validate contract admission without task state",
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
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(TASK_GUARD),
                    "preflight",
                    "--contract",
                    str(contract_path),
                    "--stage",
                    "initial",
                    "--chain-dir",
                    str(root / "state"),
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "READY")
        self.assertEqual(payload["risk"]["effective_risk"], "L2")

    def test_managed_chain_preserves_hard_risk_when_later_capsule_drops_it(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-managed-chain-") as directory:
            root = Path(directory)
            capsule_path = root / "capsule.json"
            chain_dir = root / "state"
            capsule_path.write_text(
                json.dumps(capsule(risk="L2", signals=["public_api"])),
                encoding="utf-8",
            )
            initial = subprocess.run(
                [
                    sys.executable,
                    str(TASK_GUARD),
                    "preflight",
                    "--capsule",
                    str(capsule_path),
                    "--stage",
                    "initial",
                    "--chain-dir",
                    str(chain_dir),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            capsule_path.write_text(
                json.dumps(capsule(risk="L0", signals=[])),
                encoding="utf-8",
            )
            diff = subprocess.run(
                [
                    sys.executable,
                    str(TASK_GUARD),
                    "preflight",
                    "--capsule",
                    str(capsule_path),
                    "--stage",
                    "diff",
                    "--chain-dir",
                    str(chain_dir),
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(initial.returncode, 0, initial.stderr)
        self.assertEqual(diff.returncode, 1, diff.stderr)
        payload = json.loads(diff.stdout)
        self.assertEqual(payload["status"], "RECLASSIFY")
        self.assertEqual(payload["risk"]["effective_risk"], "L2")
        self.assertIn("public_api", payload["risk"]["hard_triggers"])

    def test_public_l2_preflight_requires_a_managed_chain_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-chain-required-") as directory:
            capsule_path = Path(directory) / "capsule.json"
            capsule_path.write_text(
                json.dumps(capsule(risk="L2", signals=["public_api"])),
                encoding="utf-8",
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(TASK_GUARD),
                    "preflight",
                    "--capsule",
                    str(capsule_path),
                    "--stage",
                    "initial",
                ],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("chain-dir", result.stderr)

    def test_taskguard_init_rejects_l3_until_extended_obligations_exist(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-l3-reject-") as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src" / "value.txt").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            contract_path = root / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "task_id": "l3-must-not-pass",
                        "goal": "never treat incomplete L3 evidence as supported",
                        "risk": "L3",
                        "repo": str(repo),
                        "scope": ["src/**"],
                        "acknowledge_dirty": [],
                        "acceptance": [
                            {
                                "id": "always-green",
                                "argv": [sys.executable, "-c", "raise SystemExit(0)"],
                                "cwd": ".",
                                "requires_red": False,
                                "idempotent": True,
                            }
                        ],
                        "forbidden": [],
                        "surfaces": [],
                    }
                ),
                encoding="utf-8",
            )
            state_dir = root / "state"
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

        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("L3", result.stderr)
        self.assertFalse(state_dir.exists())

    def test_existing_v2_l3_state_cannot_run_verify_or_report_supported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-old-l3-") as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src" / "value.txt").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(["git", "-C", str(repo), "add", "src/value.txt"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "baseline"], check=True)
            contract_path = root / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "task_id": "old-l3-state",
                        "goal": "prove old L3 state cannot retain a success verdict",
                        "risk": "L3",
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
                ),
                encoding="utf-8",
            )
            state_dir = root / "state"
            create_legacy_l3_state(contract_path, state_dir, repo)
            run = subprocess.run(
                [
                    sys.executable,
                    str(TASK_GUARD),
                    "run",
                    "--state-dir",
                    str(state_dir),
                    "--acceptance",
                    "unit",
                    "--phase",
                    "candidate",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            verify = subprocess.run(
                [sys.executable, str(TASK_GUARD), "verify", "--state-dir", str(state_dir)],
                text=True,
                capture_output=True,
                check=False,
            )
            status = subprocess.run(
                [sys.executable, str(TASK_GUARD), "status", "--state-dir", str(state_dir)],
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(run.returncode, 1, run.stderr)
        self.assertEqual(verify.returncode, 1, verify.stderr)
        self.assertEqual(status.returncode, 1, status.stderr)
        self.assertEqual(json.loads(status.stdout)["aggregate"], "UNKNOWN")
        self.assertIn("L3", run.stderr)

    def test_l2_verify_requires_final_managed_chain(self) -> None:
        with tempfile.TemporaryDirectory(prefix="ligong-l2-chain-verify-") as directory:
            root = Path(directory)
            repo = root / "repo"
            (repo / "src").mkdir(parents=True)
            (repo / "src" / "value.txt").write_text("baseline\n", encoding="utf-8")
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            subprocess.run(
                ["git", "-C", str(repo), "config", "user.email", "test@example.invalid"],
                check=True,
            )
            subprocess.run(["git", "-C", str(repo), "add", "src/value.txt"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "baseline"], check=True)
            state_dir = root / "state"
            capsule_path = root / "capsule.json"
            goal = "verify requires the final risk-chain stage"
            capsule_path.write_text(
                json.dumps(
                    capsule(
                        risk="L2",
                        signals=["public_api"],
                        outcome=goal,
                        scope=["src/**"],
                    )
                ),
                encoding="utf-8",
            )
            contract_path = root / "contract.json"
            contract_path.write_text(
                json.dumps(
                    {
                        "version": 2,
                        "task_id": "sss-control",
                        "goal": goal,
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
                ),
                encoding="utf-8",
            )

            def run(*arguments: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [sys.executable, str(TASK_GUARD), *arguments],
                    cwd=repo,
                    text=True,
                    capture_output=True,
                    check=False,
                )

            initial = run(
                "preflight", "--capsule", str(capsule_path), "--stage", "initial",
                "--chain-dir", str(state_dir),
            )
            initialized = run(
                "init", "--state-dir", str(state_dir), "--contract", str(contract_path)
            )
            early_verify = run("verify", "--state-dir", str(state_dir))
            diff = run(
                "preflight", "--capsule", str(capsule_path), "--stage", "diff",
                "--chain-dir", str(state_dir),
            )
            premature_final = run(
                "preflight", "--capsule", str(capsule_path), "--stage", "final",
                "--chain-dir", str(state_dir),
            )
            candidate = run(
                "run", "--state-dir", str(state_dir), "--acceptance", "unit",
                "--phase", "candidate",
            )
            final = run(
                "preflight", "--capsule", str(capsule_path), "--stage", "final",
                "--chain-dir", str(state_dir),
            )
            verified = run("verify", "--state-dir", str(state_dir))

        for result in (initial, initialized, candidate, diff, final, verified):
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(early_verify.returncode, 3, early_verify.stderr)
        self.assertEqual(premature_final.returncode, 3, premature_final.stderr)
        self.assertEqual(json.loads(verified.stdout)["aggregate"], "SUPPORTED")

    def test_global_help_lists_new_and_legacy_commands(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TASK_GUARD), "--help"],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        for command in (
            "doctor",
            "fuse",
            "preflight",
            "export",
            "init",
            "run",
            "verify",
            "status",
            "checkpoint",
            "dispose",
        ):
            self.assertIn(command, result.stdout)

    def test_no_arguments_preserves_legacy_usage_error(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TASK_GUARD)],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)

    def test_legacy_subcommand_help_is_preserved(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TASK_GUARD), "init", "--help"],
            text=True,
            capture_output=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--state-dir", result.stdout)
        self.assertIn("--contract", result.stdout)


if __name__ == "__main__":
    unittest.main()
