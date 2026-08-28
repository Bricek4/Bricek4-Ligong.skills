from __future__ import annotations

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from taskguard.contracts.v3 import ContractV3Error, validate_contract_v3
from taskguard.receipts import ReceiptRef
from taskguard.router import UnsupportedProtocol, protocol_from_contract
from taskguard.validation import StrictJSONError, loads_strict_json
from taskguard.v3.adapters import AdapterCapabilities
from taskguard.v3.authority import UnavailableAuthorityProvider
from taskguard.v3.backend import V3Backend
from taskguard.v3.capabilities import AdapterRegistry, evaluate_action_capabilities
from taskguard.v3.receipt_store import ReceiptIntegrityError, ReceiptStore
from taskguard.v3.receipts import RECEIPT_VERSION, Receipt
from taskguard.v3.types import AdapterIdentity, CanonicalTarget, PlanReceipt, PrincipalReceipt


ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "scripts" / "task_guard.py"


class FakeReadOnlyAdapter:
    adapter_id = "provider.deploy/v1"
    adapter_version = "1.0.0"

    def __init__(self) -> None:
        self.external_write_calls = 0

    def identity(self):
        return AdapterIdentity(self.adapter_id, self.adapter_version, "provider-id")

    def capabilities(self, action):
        del action
        return AdapterCapabilities(True, True, True, True, True, True, True, True, True)

    def canonicalize_target(self, action):
        return CanonicalTarget(**action.target.to_manifest())

    def identify_principal(self, request):
        del request
        return PrincipalReceipt("principal:test", "credential:test")

    def plan(self, request):
        return PlanReceipt(
            request["action_id"],
            CanonicalTarget(**request["target"]),
            "remote-revision-1",
            {"changes": ["deploy revision"]},
        )

    def apply(self, intent):
        del intent
        self.external_write_calls += 1
        raise AssertionError("apply must not be called by the control plane")


class TaskGuardV3Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def contract(self) -> dict[str, object]:
        return {
            "version": 3,
            "task_id": "deploy-api-test",
            "goal": "deploy one exact revision",
            "risk": "L3",
            "repo_contract": {
                "repo": str(self.repo),
                "repo_scope": ["."],
                "acknowledge_dirty": [],
                "acceptance": [],
                "forbidden": [],
                "surfaces": [],
            },
            "actions": [{
                "id": "deploy-api",
                "kind": "deploy",
                "adapter": "provider.deploy/v1",
                "target": {
                    "provider": "provider-id",
                    "account_id": "account-1",
                    "project_id": "project-1",
                    "resource_id": "service-api",
                },
                "environment": "production",
                "resource_scope": {"service": "voice-api"},
                "desired_state": {"revision": "sha256:abc", "nested": {"items": [1, 2]}},
                "preconditions": {"resource_version": "etag-1"},
                "authority_policy": {"provider": "host-platform/v1", "bind_plan": True, "max_uses": 1},
                "plan_policy": {"max_age_seconds": 300},
                "rollback_policy": {"required": True, "preauthorize": True, "automatic_on_health_failure": True},
                "health_policy": {"window_seconds": 300, "minimum_samples": 5, "required_signals": ["revision", "readiness"]},
            }],
        }

    def write_contract(self) -> Path:
        path = self.root / "contract.json"
        path.write_text(json.dumps(self.contract()), encoding="utf-8")
        return path

    def test_strict_json_rejects_duplicate_nonfinite_and_nul(self) -> None:
        for raw in ('{"x":1,"x":2}', '{"x":NaN}', '{"x":1e400}', '{"x":"\\u0000"}'):
            with self.subTest(raw=raw), self.assertRaises(StrictJSONError):
                loads_strict_json(raw)

    def test_contract_is_strict_immutable_and_single_action(self) -> None:
        raw = self.contract()
        parsed = validate_contract_v3(raw)
        raw["actions"][0]["desired_state"]["nested"]["items"].append(3)
        self.assertEqual(parsed.to_manifest()["actions"][0]["desired_state"]["nested"]["items"], [1, 2])
        unknown = self.contract()
        unknown["actions"][0]["unexpected"] = True
        with self.assertRaisesRegex(ContractV3Error, "unknown field"):
            validate_contract_v3(unknown)
        multiple = self.contract()
        multiple["actions"].append(copy.deepcopy(multiple["actions"][0]) | {"id": "second"})
        with self.assertRaisesRegex(ContractV3Error, "MULTI_ACTION_NOT_ENABLED"):
            validate_contract_v3(multiple)

    def test_contract_rejects_bool_as_integer_and_missing_rollback(self) -> None:
        raw = self.contract()
        raw["actions"][0]["plan_policy"]["max_age_seconds"] = True
        with self.assertRaises(ContractV3Error):
            validate_contract_v3(raw)

    def test_repo_contract_rejects_unknown_nested_fields(self) -> None:
        raw = self.contract()
        raw["repo_contract"]["acceptance"] = [{
            "id": "unit", "argv": ["python3", "-c", "pass"], "cwd": ".",
            "requires_red": False, "idempotent": True, "unexpected": True,
        }]
        with self.assertRaisesRegex(ContractV3Error, "unknown field"):
            validate_contract_v3(raw)
        raw = self.contract()
        raw["actions"][0]["rollback_policy"]["required"] = False
        with self.assertRaises(ContractV3Error):
            validate_contract_v3(raw)

    def test_receipts_are_content_addressed_and_tamper_evident(self) -> None:
        store = ReceiptStore(self.root / "evidence")
        body = {"ok": True, "nested": {"items": [1, 2]}}
        receipt = Receipt(
            RECEIPT_VERSION, "test-receipt-v1", "task", None,
            {"x": 1}, body, (), datetime.now(timezone.utc).isoformat(),
        )
        body["nested"]["items"].append(3)
        self.assertEqual(receipt.to_manifest()["body"]["nested"]["items"], [1, 2])
        first = store.put(receipt)
        self.assertEqual(first, store.put(receipt))
        self.assertEqual(store.verify_graph([first]), 1)
        blob = store.receipts / f"{first.digest}.json"
        blob.write_text("{}", encoding="utf-8")
        with self.assertRaises(ReceiptIntegrityError):
            store.load(first)

    def test_receipt_hardlinks_are_rejected(self) -> None:
        store = ReceiptStore(self.root / "hardlink-evidence")
        receipt = Receipt(
            RECEIPT_VERSION, "test-receipt-v1", "task", None,
            {"x": 1}, {"ok": True}, (), datetime.now(timezone.utc).isoformat(),
        )
        ref = store.put(receipt)
        source = store.receipts / f"{ref.digest}.json"
        os.link(source, self.root / "receipt-alias.json")
        with self.assertRaises(ReceiptIntegrityError):
            store.load(ref)

    def test_concurrent_identical_receipt_puts_converge(self) -> None:
        store = ReceiptStore(self.root / "concurrent-evidence")
        receipt = Receipt(
            RECEIPT_VERSION, "test-receipt-v1", "task", None,
            {"x": 1}, {"ok": True}, (), datetime.now(timezone.utc).isoformat(),
        )
        with ThreadPoolExecutor(max_workers=8) as executor:
            refs = tuple(executor.map(lambda _: store.put(receipt), range(64)))
        self.assertEqual(len(set(refs)), 1)
        self.assertEqual(len(tuple(store.receipts.glob("*.json"))), 1)

    def test_capabilities_and_authority_fail_closed(self) -> None:
        action = validate_contract_v3(self.contract()).actions[0]
        empty = evaluate_action_capabilities(action, AdapterRegistry())
        self.assertEqual(empty.verdict, "UNSUPPORTED")
        self.assertIn("ADAPTER_NOT_REGISTERED", empty.reasons)
        authority = UnavailableAuthorityProvider()
        self.assertFalse(authority.capabilities().verifiable_attestation)

    def test_apply_tripwire_is_unreachable_in_control_plane(self) -> None:
        adapter = FakeReadOnlyAdapter()
        payload, code = V3Backend(AdapterRegistry([adapter])).execute("apply", {"state_dir": str(self.root / "state")})
        self.assertEqual(code, 1)
        self.assertEqual(payload["reason"], "PHASE_NOT_ENABLED")
        self.assertEqual(adapter.external_write_calls, 0)

    def test_public_init_status_export_and_plan_are_bound(self) -> None:
        contract_path = self.write_contract()
        state = self.root / "state"
        init = V3Backend().init(str(contract_path), str(state))[0]
        self.assertEqual(init["protocol_version"], 3)
        self.assertEqual(init["actions"][0]["verdict"], "UNSUPPORTED")
        status = V3Backend().status(str(state))[0]
        self.assertEqual(status["receipt_integrity"], "VERIFIED")
        exported = V3Backend().export(str(state))[0]
        self.assertEqual(exported["verdict"], "SNAPSHOT_ONLY")

        planned_state = self.root / "planned-state"
        adapter = FakeReadOnlyAdapter()
        backend = V3Backend(AdapterRegistry([adapter]))
        backend.init(str(contract_path), str(planned_state))
        planned, code = backend.plan(str(planned_state), "deploy-api")
        self.assertEqual(code, 0)
        self.assertEqual(planned["reason"], "NO_TRUSTED_AUTHORITY_PROVIDER")
        self.assertEqual(adapter.external_write_calls, 0)

    def test_public_router_keeps_production_fail_closed(self) -> None:
        contract = self.write_contract()
        state = self.root / "public-state"
        init = subprocess.run(
            [sys.executable, str(ENTRY), "init", "--contract", str(contract), "--state-dir", str(state)],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(init.returncode, 0, init.stderr)
        self.assertEqual(json.loads(init.stdout)["protocol_version"], 3)
        apply = subprocess.run(
            [sys.executable, str(ENTRY), "apply", "--state-dir", str(state), "--action", "deploy-api"],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(apply.returncode, 1, apply.stderr)
        self.assertEqual(json.loads(apply.stdout)["reason"], "PHASE_NOT_ENABLED")

    def test_unknown_protocol_never_falls_back(self) -> None:
        for value in (None, True, 1, 4, "3"):
            raw = {} if value is None else {"version": value}
            with self.subTest(value=value), self.assertRaises(UnsupportedProtocol):
                protocol_from_contract(raw)


if __name__ == "__main__":
    unittest.main()
