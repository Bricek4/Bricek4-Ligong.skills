#!/usr/bin/env python3
"""Run deterministic Ligong SSS risk-routing evaluations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_ROOT))

from taskguard.risk import CapsuleError, evaluate_risk  # noqa: E402


def _capsule(overrides: dict[str, object]) -> dict[str, object]:
    value: dict[str, object] = {
        "version": 1,
        "task_id": "risk-eval",
        "outcome": "classify the evaluation case deterministically",
        "scope": ["src/**"],
        "invariants": [],
        "evidence": ["deterministic evaluator result"],
        "risk": "L1",
        "signals": [],
        "external_actions": [],
        "authority": [],
    }
    value.update(overrides)
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="run_evals.py")
    parser.add_argument("--cases", type=Path, default=SKILL_ROOT / "evals" / "risk-cases.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    corpus_path = arguments.cases
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    failures: list[dict[str, object]] = []
    for case in corpus["cases"]:
        try:
            target = _capsule(case["capsule"])
            if case["stage"] == "initial":
                actual = evaluate_risk(target, "initial")
            else:
                earlier = dict(case["capsule"])
                earlier["signals"] = [
                    signal
                    for signal in earlier.get("signals", [])
                    if signal not in {"scope_expansion", "evidence_conflict"}
                ]
                initial = evaluate_risk(_capsule(earlier), "initial")
                if case["stage"] == "diff":
                    actual = evaluate_risk(target, "diff", previous_result=initial)
                else:
                    diff = evaluate_risk(
                        _capsule(earlier), "diff", previous_result=initial
                    )
                    actual = evaluate_risk(target, "final", previous_result=diff)
        except CapsuleError as exc:
            expected_error = case.get("expected_error")
            mismatches = (
                {}
                if isinstance(expected_error, str) and expected_error in str(exc)
                else {"error": {"expected": expected_error, "actual": str(exc)}}
            )
        else:
            if "expected_error" in case:
                mismatches = {
                    "error": {"expected": case["expected_error"], "actual": None}
                }
            else:
                mismatches = {
                    key: {"expected": expected, "actual": actual.get(key)}
                    for key, expected in case["expected"].items()
                    if actual.get(key) != expected
                }
        if mismatches:
            failures.append({"id": case["id"], "mismatches": mismatches})
    payload = {
        "version": "ligong-risk-eval-result-v1",
        "total": len(corpus["cases"]),
        "passed": len(corpus["cases"]) - len(failures),
        "failed": len(failures),
        "failures": failures,
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
