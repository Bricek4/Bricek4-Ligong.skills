#!/usr/bin/env python3
"""Run the hand-authored ForgeLoop development-evaluation corpus."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
from typing import Any


SKILL_ROOT = Path(__file__).resolve().parents[1]
if str(SKILL_ROOT) not in sys.path:
    sys.path.insert(0, str(SKILL_ROOT))

from taskguard.development import evaluate_development_capsule, loads_strict_json  # noqa: E402


_EXPECTED_FIELDS = {
    "status",
    "creativity",
    "required_candidate_count",
    "missing_contains",
    "findings_contains",
}


def _merge(base: Any, patch: Any) -> Any:
    if type(base) is dict and type(patch) is dict:
        result = copy.deepcopy(base)
        for key, value in patch.items():
            if value is None:
                result.pop(key, None)
            else:
                result[key] = _merge(result.get(key), value)
        return result
    return copy.deepcopy(patch)


def _matches(result: dict[str, object], expected: dict[str, object]) -> list[str]:
    failures: list[str] = []
    for key, value in expected.items():
        if key == "missing_contains":
            missing = result.get("missing", [])
            for item in value if type(value) is list else []:
                if item not in missing:
                    failures.append(f"missing does not contain {item!r}")
        elif key == "findings_contains":
            findings = result.get("findings", [])
            for item in value if type(value) is list else []:
                if item not in findings:
                    failures.append(f"findings does not contain {item!r}")
        elif result.get(key) != value:
            failures.append(f"{key}: expected {value!r}, got {result.get(key)!r}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="run_development_evals.py")
    parser.add_argument(
        "--cases",
        default=str(SKILL_ROOT / "evals" / "development-cases.json"),
    )
    arguments = parser.parse_args(argv)
    try:
        corpus = loads_strict_json(Path(arguments.cases).read_text(encoding="utf-8"))
        if type(corpus) is not dict or type(corpus.get("version")) is not int or corpus.get("version") != 1:
            raise ValueError("corpus version must be integer 1")
        base = corpus["base"]
        cases = corpus["cases"]
        if type(base) is not dict:
            raise ValueError("base must be an object")
        if type(cases) is not list or not cases:
            raise ValueError("cases must be a non-empty array")
    except (KeyError, OSError, UnicodeError, ValueError) as exc:
        print(f"development eval corpus error: {exc}", file=sys.stderr)
        return 2

    failures: list[dict[str, object]] = []
    seen: set[str] = set()
    for index, case in enumerate(cases):
        if type(case) is not dict or type(case.get("id")) is not str:
            print(f"development eval corpus error: cases[{index}] must have a string id", file=sys.stderr)
            return 2
        if set(case).difference({"id", "patch", "expected"}):
            print(f"development eval corpus error: cases[{index}] has unknown fields", file=sys.stderr)
            return 2
        if type(case.get("patch")) is not dict:
            print(f"development eval corpus error: cases[{index}].patch must be an object", file=sys.stderr)
            return 2
        expected = case.get("expected")
        if (
            type(expected) is not dict
            or type(expected.get("status")) is not str
            or expected.get("status") not in {"READY", "REVISE", "INVALID"}
        ):
            print(
                f"development eval corpus error: cases[{index}].expected must include status",
                file=sys.stderr,
            )
            return 2
        if set(expected).difference(_EXPECTED_FIELDS):
            print(f"development eval corpus error: cases[{index}].expected has unknown fields", file=sys.stderr)
            return 2
        for contains_field in ("missing_contains", "findings_contains"):
            contains = expected.get(contains_field)
            if contains is not None and (
                type(contains) is not list
                or any(type(item) is not str or not item for item in contains)
            ):
                print(
                    f"development eval corpus error: cases[{index}].expected.{contains_field} must be a string array",
                    file=sys.stderr,
                )
                return 2
        if "required_candidate_count" in expected and (
            type(expected["required_candidate_count"]) is not int
            or expected["required_candidate_count"] < 1
        ):
            print(
                f"development eval corpus error: cases[{index}].expected.required_candidate_count must be a positive integer",
                file=sys.stderr,
            )
            return 2
        case_id = case["id"]
        if case_id in seen:
            print(f"development eval corpus error: duplicate case id {case_id!r}", file=sys.stderr)
            return 2
        seen.add(case_id)
        value = _merge(base, case.get("patch", {}))
        result = evaluate_development_capsule(value)
        errors = _matches(result, expected)
        if errors:
            failures.append({"id": case_id, "errors": errors, "result": result})

    summary = {
        "version": "ligong-development-eval-result-v1",
        "total": len(cases),
        "passed": len(cases) - len(failures),
        "failed": len(failures),
        "failures": failures,
    }
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
