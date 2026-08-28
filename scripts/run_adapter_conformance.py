#!/usr/bin/env python3
"""Describe the fixed conformance contract without loading arbitrary modules."""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from taskguard.validation import canonical_json_bytes
from taskguard.v3.conformance import REQUIRED_REVERSIBLE_ACTION_CASES


def main() -> int:
    payload = {
        "version": "taskguard-v3-conformance-runner-v1",
        "status": "UNSUPPORTED",
        "reason": "NO_EXPLICIT_TEST_ADAPTER_INJECTED",
        "required_cases": list(REQUIRED_REVERSIBLE_ACTION_CASES),
        "arbitrary_imports_enabled": False,
    }
    sys.stdout.write(canonical_json_bytes(payload).decode("ascii") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
