#!/usr/bin/env python3
"""Curated fail-closed mutations for the installed TaskGuard v3 core."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from taskguard.router import UnsupportedProtocol, protocol_from_contract
from taskguard.validation import StrictJSONError, canonical_json_bytes, loads_strict_json
from taskguard.v3.backend import V3Backend
from taskguard.v3.production_gate import PRODUCTION_GUARDS, ProductionGateContext, evaluate_production_gate
from taskguard.v3.release_report import build_provider_readiness_report


def main() -> int:
    passed: list[str] = []
    failed: list[str] = []

    def check(name: str, condition: bool) -> None:
        (passed if condition else failed).append(name)

    for value in (None, True, 1, 4, "3"):
        try:
            protocol_from_contract({} if value is None else {"version": value})
        except UnsupportedProtocol:
            check(f"unknown-protocol/{value!r}", True)
        else:
            check(f"unknown-protocol/{value!r}", False)
    try:
        loads_strict_json('{"x":1,"x":2}')
    except StrictJSONError:
        check("duplicate-json-key", True)
    else:
        check("duplicate-json-key", False)
    payload, _ = V3Backend().execute("apply", {"state_dir": "/nonexistent"})
    check("default-apply-unreachable", payload.get("reason") == "PHASE_NOT_ENABLED")
    check("default-readiness-unsupported", build_provider_readiness_report().status == "UNSUPPORTED")
    guards = {name: "SUPPORTED" for name in PRODUCTION_GUARDS}
    binding = "c" * 64
    for guard in PRODUCTION_GUARDS:
        changed = dict(guards)
        changed[guard] = "STALE"
        context = ProductionGateContext(
            changed,
            binding,
            {name: binding for name in PRODUCTION_GUARDS if name not in {"local_platform", "kill_switch"}},
            True,
            True,
        )
        check(f"production-guard/{guard}", evaluate_production_gate(context).status == "UNSUPPORTED")
    check("caller-guard-strings-untrusted", evaluate_production_gate(guards).status == "UNSUPPORTED")
    result = {
        "version": "taskguard-v3-safety-mutations-v1",
        "passed": len(passed),
        "failed": len(failed),
        "failures": failed,
    }
    sys.stdout.write(canonical_json_bytes(result).decode("ascii") + "\n")
    return 0 if not failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
