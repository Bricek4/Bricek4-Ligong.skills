#!/usr/bin/env python3
"""Evaluate one ForgeLoop development capsule."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from taskguard.development import evaluate_development_capsule, loads_strict_json  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="forge_check.py")
    parser.add_argument("capsule")
    arguments = parser.parse_args(argv)
    try:
        value = loads_strict_json(Path(arguments.capsule).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        result = evaluate_development_capsule(None)
        result["findings"] = [f"cannot read capsule: {exc}"]
    else:
        result = evaluate_development_capsule(value)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return {"READY": 0, "REVISE": 2, "INVALID": 3}[str(result["status"])]


if __name__ == "__main__":
    raise SystemExit(main())
