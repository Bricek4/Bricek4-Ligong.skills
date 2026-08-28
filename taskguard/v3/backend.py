"""Fail-closed TaskGuard v3 control-plane backend."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..contracts.v3 import ContractV3, load_contract_v3, validate_contract_v3
from ..receipts.refs import ReceiptRef
from ..validation import sha256_digest
from .authority import UnavailableAuthorityProvider
from .capabilities import AdapterRegistry, PRODUCTION_ADAPTER_REGISTRY, evaluate_action_capabilities
from .planner import Planner
from .receipt_store import ReceiptGraphError, ReceiptStore
from .receipts import RECEIPT_VERSION, Receipt
from .release_report import build_provider_readiness_report
from .shadow import ShadowEvaluator
from .state import V3State


MUTATION_COMMANDS = frozenset({"apply", "reconcile", "rollback", "health", "verify"})


class V3Backend:
    protocol_version = 3

    def __init__(self, registry: AdapterRegistry | None = None, authority: Any | None = None) -> None:
        self.registry = registry if registry is not None else PRODUCTION_ADAPTER_REGISTRY
        self.authority = authority if authority is not None else UnavailableAuthorityProvider()

    def main(self, argv: Sequence[str]) -> int:
        from .cli import main

        return main(argv, backend=self)

    @staticmethod
    def _unsupported(reason: str, *, command: str | None = None) -> tuple[dict[str, Any], int]:
        payload: dict[str, Any] = {"protocol_version": 3, "verdict": "UNSUPPORTED", "reason": reason}
        if command is not None:
            payload["command"] = command
        return payload, 1

    def _receipts(self, state_dir: str | Path) -> ReceiptStore:
        canonical_state_root = V3State(state_dir).store.root
        return ReceiptStore(canonical_state_root / "v3-evidence")

    def validate(self, contract_path: str) -> tuple[dict[str, Any], int]:
        contract = load_contract_v3(contract_path)
        reports = [evaluate_action_capabilities(action, self.registry).to_manifest() for action in contract.actions]
        return {
            "protocol_version": 3,
            "task_id": contract.task_id,
            "contract_digest": sha256_digest(contract.to_manifest()),
            "valid": True,
            "actions": reports,
        }, 0

    def init(self, contract_path: str, state_dir: str) -> tuple[dict[str, Any], int]:
        contract = load_contract_v3(contract_path)
        contract_manifest = contract.to_manifest()
        v3_state = V3State(state_dir)
        v3_state.prepare()
        receipts = self._receipts(state_dir)
        declaration = Receipt(
            RECEIPT_VERSION,
            "declaration-receipt-v1",
            contract.task_id,
            None,
            {"contract_digest": sha256_digest(contract_manifest)},
            {"contract": contract_manifest},
            (),
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        )
        declaration_ref = receipts.put(declaration)
        actions = []
        for action in contract.actions:
            report = evaluate_action_capabilities(action, self.registry)
            reasons = list(report.reasons)
            reasons.append("NO_TRUSTED_AUTHORITY_PROVIDER")
            actions.append({
                "id": action.id,
                "revision": 1,
                "lifecycle": "DECLARED",
                "verdict": "UNSUPPORTED",
                "next_action": "REGISTER_CAPABILITIES" if report.verdict == "UNSUPPORTED" else "CONNECT_TRUSTED_AUTHORITY",
                "reasons": sorted(set(reasons)),
                "receipt_refs": [],
            })
        manifest = {
            "protocol_version": 3,
            "task_id": contract.task_id,
            "contract_digest": sha256_digest(contract_manifest),
            "contract": contract_manifest,
            "risk_chain_ref": None,
            "local_evidence_refs": [declaration_ref.to_manifest()],
            "actions": actions,
            "aggregate": "UNSUPPORTED",
        }
        state = v3_state.create(manifest)
        return self._public_state(state), 0

    def _public_state(self, state: Mapping[str, Any]) -> dict[str, Any]:
        return {
            key: state[key]
            for key in (
                "protocol_version", "task_id", "contract_digest", "local_evidence_refs",
                "actions", "aggregate", "revision",
            )
            if key in state
        }

    def _load_checked(self, state_dir: str) -> tuple[V3State, dict[str, Any], ReceiptStore]:
        store = V3State(state_dir)
        state = store.load()
        receipts = self._receipts(state_dir)
        refs = tuple(ReceiptRef.from_manifest(item) for item in state.get("local_evidence_refs", []))
        for action in state.get("actions", []):
            refs += tuple(ReceiptRef.from_manifest(item) for item in action.get("receipt_refs", []))
        receipts.verify_graph(refs)
        return store, state, receipts

    def status(self, state_dir: str) -> tuple[dict[str, Any], int]:
        _, state, _ = self._load_checked(state_dir)
        payload = self._public_state(state)
        payload["receipt_integrity"] = "VERIFIED"
        return payload, 0

    def explain(self, contract_path: str | None, state_dir: str | None) -> tuple[dict[str, Any], int]:
        if contract_path:
            contract = load_contract_v3(contract_path)
        elif state_dir:
            _, state, _ = self._load_checked(state_dir)
            contract = validate_contract_v3(state["contract"])
        else:
            raise ValueError("explain requires --contract or --state-dir")
        actions = []
        for action in contract.actions:
            report = evaluate_action_capabilities(action, self.registry)
            reasons = list(report.reasons)
            if not self.authority.capabilities().verifiable_attestation:
                reasons.append("NO_TRUSTED_AUTHORITY_PROVIDER")
            reasons.extend(build_provider_readiness_report().reason_codes)
            actions.append({"id": action.id, "verdict": "UNSUPPORTED" if reasons else "SUPPORTED", "reasons": sorted(set(reasons))})
        verdict = "SUPPORTED" if all(item["verdict"] == "SUPPORTED" for item in actions) else "UNSUPPORTED"
        return {"protocol_version": 3, "task_id": contract.task_id, "verdict": verdict, "actions": actions}, 0

    def doctor(self) -> tuple[dict[str, Any], int]:
        return {
            "protocol_version": 3,
            "verdict": "UNSUPPORTED",
            "reasons": ["NO_PRODUCTION_ADAPTER_REGISTERED", "NO_TRUSTED_AUTHORITY_PROVIDER"],
            "registered_adapters": list(self.registry.adapter_ids),
            "production_mutation_enabled": False,
        }, 0

    def provider_readiness(self) -> tuple[dict[str, Any], int]:
        report = build_provider_readiness_report()
        return {
            "protocol_version": 3,
            "status": report.status,
            "production_ready": report.production_ready,
            "reason_codes": list(report.reason_codes),
        }, 0

    def shadow(self, contract_path: str, action_id: str) -> tuple[dict[str, Any], int]:
        contract = load_contract_v3(contract_path)
        action = next((item for item in contract.actions if item.id == action_id), None)
        if action is None:
            raise ValueError(f"unknown action: {action_id}")
        adapter = self.registry.get(action.adapter)
        if adapter is None:
            return {
                "protocol_version": 3,
                "task_id": contract.task_id,
                "action_id": action_id,
                "status": "UNSUPPORTED",
                "action_verdict": "UNKNOWN",
                "reasons": ["ADAPTER_NOT_REGISTERED"],
            }, 0
        report = ShadowEvaluator(adapter, self.authority).evaluate(contract, action_id)
        return {
            "protocol_version": 3,
            "task_id": contract.task_id,
            "action_id": action_id,
            "status": report.status,
            "action_verdict": report.action_verdict,
            "reasons": list(report.reasons),
            "evidence_digest": report.evidence_digest,
        }, 0

    def export(self, state_dir: str) -> tuple[dict[str, Any], int]:
        _, state, _ = self._load_checked(state_dir)
        snapshot = self._public_state(state)
        return {
            "protocol_version": 3,
            "verdict": "SNAPSHOT_ONLY",
            "snapshot": snapshot,
            "checksum": sha256_digest(snapshot),
        }, 0

    def plan(self, state_dir: str, action_id: str) -> tuple[dict[str, Any], int]:
        store, state, receipts = self._load_checked(state_dir)
        contract = validate_contract_v3(state["contract"])
        action = next((item for item in contract.actions if item.id == action_id), None)
        if action is None:
            raise ValueError(f"unknown action: {action_id}")
        adapter = self.registry.get(action.adapter)
        if adapter is None:
            return self._unsupported("ADAPTER_NOT_REGISTERED", command="plan")
        report = evaluate_action_capabilities(action, self.registry)
        if report.verdict != "SUPPORTED":
            return self._unsupported(report.reasons[0], command="plan")
        ref = Planner(receipts, adapter).create_plan(state, action)
        actions = [dict(item) for item in state["actions"]]
        selected = next(item for item in actions if item["id"] == action_id)
        selected["lifecycle"] = "PLANNED"
        selected["revision"] += 1
        selected["receipt_refs"] = [*selected["receipt_refs"], ref.to_manifest()]
        selected["next_action"] = "OBTAIN_TRUSTED_AUTHORITY"
        selected["reasons"] = ["NO_TRUSTED_AUTHORITY_PROVIDER"]
        updated = store.update(state, actions=actions)
        return {"protocol_version": 3, "task_id": state["task_id"], "action_id": action_id, "verdict": "UNSUPPORTED", "reason": "NO_TRUSTED_AUTHORITY_PROVIDER", "plan_ref": ref.to_manifest(), "revision": updated["revision"]}, 0

    def execute(self, command: str, arguments: Mapping[str, Any]) -> tuple[dict[str, Any], int]:
        if command in MUTATION_COMMANDS:
            return self._unsupported("PHASE_NOT_ENABLED", command=command)
        if command == "validate":
            return self.validate(arguments["contract"])
        if command == "init":
            return self.init(arguments["contract"], arguments["state_dir"])
        if command == "status":
            return self.status(arguments["state_dir"])
        if command == "explain":
            return self.explain(arguments.get("contract"), arguments.get("state_dir"))
        if command == "doctor-v3":
            return self.doctor()
        if command == "provider-readiness":
            return self.provider_readiness()
        if command == "shadow":
            return self.shadow(arguments["contract"], arguments["action"])
        if command == "export":
            return self.export(arguments["state_dir"])
        if command == "plan":
            return self.plan(arguments["state_dir"], arguments["action"])
        raise ValueError(f"unknown v3 command: {command}")
