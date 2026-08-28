"""Revision-bound windowed health evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Mapping


@dataclass(frozen=True, slots=True)
class HealthSample:
    effect_revision: str
    tick: int
    signals: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class HealthVerdict:
    verdict: str
    reasons: tuple[str, ...]
    sample_count: int
    window_complete: bool


def evaluate_health_window(
    samples: Iterable[HealthSample],
    *,
    effect_revision: str,
    required_signals: tuple[str, ...],
    minimum_samples: int,
    window_seconds: int,
) -> HealthVerdict:
    values = tuple(samples)
    reasons: list[str] = []
    if any(item.effect_revision != effect_revision for item in values):
        reasons.append("EFFECT_REVISION_MISMATCH")
    if len(values) < minimum_samples:
        reasons.append("INSUFFICIENT_SAMPLES")
    complete = bool(values) and values[-1].tick - values[0].tick >= window_seconds
    if not complete:
        reasons.append("HEALTH_WINDOW_INCOMPLETE")
    for sample in values:
        missing = [signal for signal in required_signals if signal not in sample.signals]
        if missing:
            reasons.append(f"MISSING_SIGNAL/{missing[0]}")
        if any(sample.signals.get(signal) is not True for signal in required_signals):
            reasons.append("HEALTH_SIGNAL_FAILED")
    if "HEALTH_SIGNAL_FAILED" in reasons:
        verdict = "FAILED"
    elif reasons:
        verdict = "STALE"
    else:
        verdict = "SUPPORTED"
    return HealthVerdict(verdict, tuple(sorted(set(reasons))), len(values), complete)
