"""Verdict aggregation with explicit protocol semantics."""

from __future__ import annotations

from collections.abc import Iterable


_V2_PRECEDENCE = {"SUPPORTED": 0, "UNKNOWN": 1, "STALE": 2, "FAILED": 3}
_V3_PRECEDENCE = {
    "READY": 0,
    "SUPPORTED": 0,
    "SNAPSHOT_ONLY": 1,
    "UNKNOWN": 2,
    "STALE": 3,
    "UNSUPPORTED": 4,
    "FAILED": 5,
}


def _aggregate(values: Iterable[str], precedence: dict[str, int], default: str) -> str:
    canonical = list(values)
    if not canonical:
        return default
    if any(value not in precedence for value in canonical):
        return "UNKNOWN"
    return max(canonical, key=precedence.__getitem__)


def aggregate_v2_verdicts(values: Iterable[str]) -> str:
    return _aggregate(values, _V2_PRECEDENCE, "UNKNOWN")


def aggregate_v3_verdicts(values: Iterable[str]) -> str:
    return _aggregate(values, _V3_PRECEDENCE, "UNKNOWN")
