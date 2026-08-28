"""The sole terminal-success aggregator for TaskGuard v3."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


REQUIRED_DIMENSIONS = (
    "contract", "risk_chain", "adapter", "plan", "authority", "rollback_readiness",
    "effect", "health", "workspace", "receipts", "release_gate",
)


@dataclass(frozen=True, slots=True)
class AggregateResult:
    verdict: str
    reasons: tuple[str, ...]


def aggregate_terminal(dimensions: Mapping[str, str], lifecycle: str) -> AggregateResult:
    reasons: list[str] = []
    for name in REQUIRED_DIMENSIONS:
        verdict = dimensions.get(name)
        if verdict != "SUPPORTED":
            reasons.append(f"{name.upper()}/{verdict or 'MISSING'}")
    if lifecycle != "HEALTHY":
        reasons.append(f"LIFECYCLE/{lifecycle}")
    return AggregateResult("SUPPORTED" if not reasons else "FAILED", tuple(reasons))
