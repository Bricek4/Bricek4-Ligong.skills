from __future__ import annotations

from pathlib import Path
import subprocess
import tempfile
import unittest

from taskguard.contracts.v3 import validate_contract_v3
from taskguard.validation import sha256_digest
from taskguard.v3.adapter_registry import (
    AdapterContext,
    AdapterRegistration,
    AdapterRegistrationError,
    AdapterRegistrationRegistry,
    default_adapter_registry,
)
from taskguard.v3.adapters import AdapterCapabilities
from taskguard.v3.conformance import ConformanceEvidence, REQUIRED_REVERSIBLE_ACTION_CASES, run_conformance
from taskguard.v3.endpoint_policy import SandboxPolicy, validate_sandbox_target
from taskguard.v3.kill_switch import KillSwitchPolicy
from taskguard.v3.production_gate import PRODUCTION_GUARDS, ProductionGateContext, evaluate_production_gate
from taskguard.v3.release_gates import MODE_REQUIREMENTS, ReleaseEvidence, evaluate_release_gates
from taskguard.v3.release_policy import ReleasePolicy, ReleasePolicyError, ReleaseRule
from taskguard.v3.release_report import build_provider_readiness_report
from taskguard.v3.shadow import ShadowEvaluator
from taskguard.v3.types import AdapterIdentity, CanonicalTarget, PlanReceipt, PrincipalReceipt


class ConformantAdapter:
    adapter_id = "fake.deploy/v1"
    adapter_version = "1.0.0"

    def __init__(self) -> None:
        self.apply_calls = 0
        self.rollback_calls = 0

    def identity(self):
        return AdapterIdentity(self.adapter_id, self.adapter_version, "fake-provider")

    def capabilities(self, action):
        del action
        return AdapterCapabilities(True, True, True, True, True, True, True, True, True)

    def canonicalize_target(self, action):
        return CanonicalTarget(**action.target.to_manifest())

    def identify_principal(self, request):
        del request
        return PrincipalReceipt("principal:fake", "credential:fake")

    def plan(self, request):
        return PlanReceipt(request["action_id"], CanonicalTarget(**request["target"]), "remote-1", {"read_only": True})

    def conformance_probe(self, case, action):
        del action
        return case in REQUIRED_REVERSIBLE_ACTION_CASES

    def apply(self, request):
        del request
        self.apply_calls += 1

    def rollback(self, request):
        del request
        self.rollback_calls += 1


class V3ReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name) / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def contract(self):
        return validate_contract_v3({
            "version": 3,
            "task_id": "release-test",
            "goal": "prove gates",
            "risk": "L3",
            "repo_contract": {
                "repo": str(self.repo), "repo_scope": ["."], "acknowledge_dirty": [],
                "acceptance": [], "forbidden": [], "surfaces": [],
            },
            "actions": [{
                "id": "deploy", "kind": "deploy", "adapter": "fake.deploy/v1",
                "target": {"provider": "fake-provider", "account_id": "sandbox-account", "project_id": "sandbox-project", "resource_id": "sandbox/service"},
                "environment": "sandbox", "resource_scope": {"service": "api"},
                "desired_state": {"revision": "r1"}, "preconditions": {"version": "v1"},
                "authority_policy": {"provider": "fake-authority/v1", "bind_plan": True, "max_uses": 1},
                "plan_policy": {"max_age_seconds": 60},
                "rollback_policy": {"required": True, "preauthorize": True, "automatic_on_health_failure": True},
                "health_policy": {"window_seconds": 60, "minimum_samples": 2, "required_signals": ["ready"]},
            }],
        })

    def test_closed_registration_is_exact_and_default_empty(self) -> None:
        self.assertEqual(default_adapter_registry().registrations(), ())
        registration = AdapterRegistration(
            "fake.deploy/v1", "1.0.0", ("deploy",), ("sandbox",),
            lambda context: ConformantAdapter(),
        )
        registry = AdapterRegistrationRegistry((registration,))
        self.assertIsNotNone(registry.resolve("fake.deploy/v1", action_kind="deploy", environment="sandbox"))
        self.assertIsNone(registry.resolve("fake.deploy/v1", action_kind="deploy", environment="production"))
        with self.assertRaises(AdapterRegistrationError):
            AdapterRegistration("*", "1", ("deploy",), ("sandbox",), lambda context: None)

    def test_conformance_requires_every_fixed_case_and_capability(self) -> None:
        adapter = ConformantAdapter()
        results = {case: True for case in REQUIRED_REVERSIBLE_ACTION_CASES}
        report = run_conformance(
            adapter,
            self.contract().actions[0],
            ConformanceEvidence(results, trusted_harness=True),
        )
        self.assertEqual(report.status, "SUPPORTED")
        self.assertEqual(set(report.passed), set(REQUIRED_REVERSIBLE_ACTION_CASES))
        results["rollback-execution"] = False
        report = run_conformance(
            adapter,
            self.contract().actions[0],
            ConformanceEvidence(results, trusted_harness=True),
        )
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertIn("rollback-execution", report.failed)
        self.assertEqual(run_conformance(adapter, self.contract().actions[0]).status, "UNSUPPORTED")

    def test_sandbox_target_requires_exact_endpoint_and_ids(self) -> None:
        policy = SandboxPolicy(
            "https://sandbox.example.invalid", "fake-provider", "sandbox-account",
            "sandbox-project", "sandbox-tenant", "test-region", ("sandbox/",),
        )
        target = {
            "environment": "sandbox", "endpoint": policy.endpoint, "provider": policy.provider,
            "account_id": policy.account_id, "project_id": policy.project_id,
            "tenant_id": policy.tenant_id, "region": policy.region, "resource_id": "sandbox/service",
        }
        self.assertEqual(validate_sandbox_target(target, policy).status, "SUPPORTED")
        changed = dict(target)
        changed["endpoint"] = "https://production.example.invalid"
        self.assertEqual(validate_sandbox_target(changed, policy).status, "UNSUPPORTED")

    def test_shadow_is_ready_but_never_supported_or_mutating(self) -> None:
        adapter = ConformantAdapter()
        report = ShadowEvaluator(adapter).evaluate(self.contract(), "deploy")
        self.assertEqual(report.status, "READY")
        self.assertEqual(report.action_verdict, "UNKNOWN")
        self.assertEqual(adapter.apply_calls, 0)
        self.assertEqual(adapter.rollback_calls, 0)

    def release_binding(self):
        return {
            "adapter_id": "fake.deploy/v1", "adapter_version": "1.0.0",
            "action_kind": "deploy", "environment": "sandbox",
            "canonical_target_digest": "a" * 64,
            "authority_provider_id": "fake-authority", "authority_provider_version": "1.0.0",
            "conformance_receipt_digest": "b" * 64,
            "receipt_schema_versions": ("taskguard-receipt-v1",),
        }

    def test_release_allowlist_matches_every_dimension_without_wildcards(self) -> None:
        binding = self.release_binding()
        rule = ReleaseRule(**binding, mode="CANARY", enabled=True)
        policy = ReleasePolicy((rule,), managed_owner="host-policy", trusted_source=True)
        self.assertEqual(policy.authorize_mode(binding, "CANARY").status, "SUPPORTED")
        self.assertEqual(
            ReleasePolicy((rule,), managed_owner="caller-text").authorize_mode(binding, "CANARY").status,
            "UNSUPPORTED",
        )
        for field in binding:
            changed = dict(binding)
            changed[field] = "changed" if field != "receipt_schema_versions" else ("changed",)
            self.assertEqual(policy.authorize_mode(changed, "CANARY").status, "UNSUPPORTED")
        with self.assertRaises(ReleasePolicyError):
            ReleaseRule(**(binding | {"adapter_id": "*"}), mode="CANARY", enabled=True)

    def test_closed_kill_switch_preserves_only_recovery(self) -> None:
        binding = self.release_binding()
        switch = KillSwitchPolicy(1, "host-policy", True)
        self.assertEqual(switch.decide(binding, "ROLLBACK_READY", "apply").status, "BLOCKED")
        for operation in ("reconcile", "rollback", "status", "export"):
            self.assertEqual(switch.decide(binding, "EFFECT_UNKNOWN", operation).status, "SUPPORTED")

    def test_every_production_guard_is_required(self) -> None:
        supported = {name: "SUPPORTED" for name in PRODUCTION_GUARDS}
        binding = "c" * 64

        def context(guards):
            return ProductionGateContext(
                guards,
                binding,
                {name: binding for name in PRODUCTION_GUARDS if name not in {"local_platform", "kill_switch"}},
                True,
                True,
            )

        self.assertEqual(evaluate_production_gate(context(supported)).status, "SUPPORTED")
        self.assertEqual(evaluate_production_gate(supported).status, "UNSUPPORTED")
        for guard in PRODUCTION_GUARDS:
            for verdict in ("FAILED", "STALE", "UNKNOWN", "UNSUPPORTED"):
                changed = dict(supported)
                changed[guard] = verdict
                self.assertEqual(evaluate_production_gate(context(changed)).status, "UNSUPPORTED")

    def test_release_modes_require_ordered_evidence_and_reversible_subset(self) -> None:
        evidence = {name: "SUPPORTED" for names in MODE_REQUIREMENTS.values() for name in names}
        evidence.update({"requested_action_count": 1, "action_kind": "deploy", "rollback_required": True})
        trusted = lambda values: ReleaseEvidence(values, "d" * 64, True, True)
        for mode in MODE_REQUIREMENTS:
            report = evaluate_release_gates(trusted(evidence), mode)
            self.assertEqual(report.status, "SUPPORTED")
            self.assertEqual(report.ready_for_production, mode == "PRODUCTION")
        forbidden = dict(evidence, action_kind="delete")
        self.assertEqual(evaluate_release_gates(trusted(forbidden), "PRODUCTION").status, "UNSUPPORTED")
        self.assertEqual(evaluate_release_gates(evidence, "PRODUCTION").status, "UNSUPPORTED")

    def test_default_readiness_is_explicitly_unsupported(self) -> None:
        report = build_provider_readiness_report()
        self.assertEqual(report.status, "UNSUPPORTED")
        self.assertIn("NO_REGISTERED_PRODUCTION_ADAPTER", report.reason_codes)
        self.assertIn("NO_TRUSTED_AUTHORITY_PROVIDER", report.reason_codes)


if __name__ == "__main__":
    unittest.main()
