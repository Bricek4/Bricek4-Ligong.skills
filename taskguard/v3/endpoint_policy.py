"""Exact sandbox endpoint and resource separation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    endpoint: str
    provider: str
    account_id: str
    project_id: str
    tenant_id: str
    region: str
    resource_prefixes: tuple[str, ...]

    def __post_init__(self) -> None:
        values = (self.endpoint, self.provider, self.account_id, self.project_id, self.tenant_id, self.region, *self.resource_prefixes)
        if any(not item or any(token in item for token in ("*", "?", "[", "]")) for item in values):
            raise ValueError("sandbox policy requires exact non-wildcard values")
        if not self.endpoint.startswith("https://") or not self.resource_prefixes:
            raise ValueError("sandbox policy requires an HTTPS endpoint and resource prefixes")


@dataclass(frozen=True, slots=True)
class SandboxDecision:
    status: str
    reasons: tuple[str, ...]


def validate_sandbox_target(target: Mapping[str, str], policy: SandboxPolicy) -> SandboxDecision:
    required = {"environment", "endpoint", "provider", "account_id", "project_id", "tenant_id", "region", "resource_id"}
    if set(target) != required:
        return SandboxDecision("UNSUPPORTED", ("SANDBOX_TARGET_SHAPE_MISMATCH",))
    reasons = []
    exact = {
        "environment": "sandbox",
        "endpoint": policy.endpoint,
        "provider": policy.provider,
        "account_id": policy.account_id,
        "project_id": policy.project_id,
        "tenant_id": policy.tenant_id,
        "region": policy.region,
    }
    for field, expected in exact.items():
        if target.get(field) != expected:
            reasons.append(f"SANDBOX_{field.upper()}_MISMATCH")
    resource = target.get("resource_id", "")
    if not any(resource.startswith(prefix) for prefix in policy.resource_prefixes):
        reasons.append("SANDBOX_RESOURCE_MISMATCH")
    if any(any(token in value for token in ("*", "?", "[", "]")) for value in target.values()):
        reasons.append("SANDBOX_WILDCARD_FORBIDDEN")
    return SandboxDecision("SUPPORTED" if not reasons else "UNSUPPORTED", tuple(sorted(set(reasons))))
