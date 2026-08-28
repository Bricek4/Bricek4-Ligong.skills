#!/usr/bin/env python3
"""Read evidence and emit a release decision; never executes an action."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from taskguard.validation import canonical_json_bytes, load_strict_json
from taskguard.v3.release_gates import evaluate_release_gates


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--mode", required=True, choices=("SHADOW", "SANDBOX", "CANARY", "PRODUCTION"))
    arguments = parser.parse_args()
    report = evaluate_release_gates(load_strict_json(arguments.evidence), arguments.mode)
    payload = {
        "mode": report.mode,
        "status": report.status,
        "ready_for_production": report.ready_for_production,
        "requested_action_count": report.requested_action_count,
        "action_kind": report.action_kind,
        "rollback_required": report.rollback_required,
        "reasons": list(report.reasons),
    }
    sys.stdout.write(canonical_json_bytes(payload).decode("ascii") + "\n")
    return 0 if report.status == "SUPPORTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
