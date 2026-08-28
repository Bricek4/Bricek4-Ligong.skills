"""Portable SSS control plane for routing before TaskGuard admission."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Sequence

from taskguard.capabilities import detect_capabilities, validate_capability_report
from taskguard.risk import CapsuleError, evaluate_risk


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _load_json(path: str) -> object:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_previous(path: str | None) -> object | None:
    if path is None:
        return None
    value = _load_json(path)
    if type(value) is dict and value.get("version") == "ligong-preflight-v1":
        return value.get("risk")
    return value


def preflight_capsule(
    capsule: object,
    *,
    stage: str,
    previous_result: object | None = None,
    capability_report: dict[str, object] | None = None,
) -> dict[str, object]:
    """Route a capsule and fail closed before guarded execution."""

    risk = evaluate_risk(capsule, stage, previous_result=previous_result)
    capabilities = validate_capability_report(
        detect_capabilities() if capability_report is None else capability_report
    )
    declared = str(risk["declared_risk"])
    effective = str(risk["effective_risk"])
    blockers = list(risk["blockers"])
    if blockers:
        status = "BLOCKED"
        admitted = False
    elif declared != effective:
        status = "RECLASSIFY"
        admitted = False
    elif effective == "L3":
        status = "UNSUPPORTED"
        admitted = False
    elif effective in {"L0", "L1"}:
        status = "NOT_REQUIRED"
        admitted = True
    elif not bool(capabilities.get("taskguard_supported", False)):
        status = "UNSUPPORTED"
        admitted = False
    else:
        status = "READY"
        admitted = True
    return {
        "version": "ligong-preflight-v1",
        "status": status,
        "admitted": admitted,
        "risk": risk,
        "missing_capabilities": list(capabilities.get("missing", [])),
        "missing_guards": ["l3_evidence_binding"] if effective == "L3" else [],
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="task_guard.py")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="report TaskGuard runtime capabilities")
    fuse = commands.add_parser("fuse", help="evaluate the one-way SSS risk fuse")
    fuse.add_argument("--capsule", required=True)
    fuse.add_argument("--previous")
    fuse.add_argument("--stage", required=True, choices=("initial", "diff", "final"))
    preflight = commands.add_parser(
        "preflight", help="evaluate risk and TaskGuard admission"
    )
    source = preflight.add_mutually_exclusive_group(required=True)
    source.add_argument("--capsule")
    source.add_argument("--contract")
    preflight.add_argument(
        "--stage", required=True, choices=("initial", "diff", "final")
    )
    preflight.add_argument("--chain-dir")
    export = commands.add_parser("export", help="export a read-only evidence bundle")
    export.add_argument("--state-dir", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run one portable SSS control command."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            payload = detect_capabilities()
            exit_code = 0
        elif args.command == "fuse":
            payload = evaluate_risk(
                _load_json(args.capsule),
                args.stage,
                previous_result=_load_previous(args.previous),
            )
            exit_code = 0 if bool(payload["admitted"]) else 1
        elif args.command == "preflight":
            if args.capsule:
                capsule = _load_json(args.capsule)
            else:
                from taskguard.contract import load_contract

                contract = load_contract(args.contract)
                capsule = {
                    "version": 1,
                    "task_id": contract.task_id,
                    "outcome": contract.goal,
                    "scope": list(contract.scope),
                    "invariants": [],
                    "evidence": [
                        f"acceptance:{acceptance.id}"
                        for acceptance in contract.acceptance
                    ],
                    "risk": contract.risk,
                    "signals": [],
                    "external_actions": [],
                    "authority": [],
                }
            previous = None
            if args.stage != "initial" and args.chain_dir:
                from taskguard.chain import load_previous

                previous = load_previous(
                    args.chain_dir,
                    task_id=str(capsule["task_id"]),
                    stage=args.stage,
                )
            payload = preflight_capsule(
                capsule,
                stage=args.stage,
                previous_result=previous,
            )
            if payload["risk"]["effective_risk"] == "L2":
                if not args.chain_dir:
                    raise ValueError("L2 preflight requires --chain-dir")
                if payload["admitted"]:
                    from taskguard.chain import commit_result

                    commit_result(args.chain_dir, payload["risk"], capsule)
            exit_code = 0 if bool(payload["admitted"]) else 1
        else:
            from taskguard.evidence import export_evidence

            payload = export_evidence(args.state_dir)
            exit_code = 0
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except RuntimeError as exc:
        print(f"state/evidence error: {exc}", file=sys.stderr)
        return 3
    print(_canonical_json(payload))
    return exit_code


__all__ = ["main", "preflight_capsule"]
