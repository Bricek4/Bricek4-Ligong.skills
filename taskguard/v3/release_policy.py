"""Exact immutable release allowlists."""

from __future__ import annotations

from dataclasses import dataclass, fields
import re
from typing import Any, Mapping


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_MODES = {"SHADOW", "SANDBOX", "CANARY", "PRODUCTION"}


class ReleasePolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ReleaseRule:
    adapter_id: str
    adapter_version: str
    action_kind: str
    environment: str
    canonical_target_digest: str
    authority_provider_id: str
    authority_provider_version: str
    conformance_receipt_digest: str
    receipt_schema_versions: tuple[str, ...]
    mode: str
    enabled: bool

    def __post_init__(self) -> None:
        strings = (
            self.adapter_id, self.adapter_version, self.action_kind, self.environment,
            self.authority_provider_id, self.authority_provider_version, *self.receipt_schema_versions,
        )
        if any(not item or any(token in item for token in ("*", "?", "[", "]")) for item in strings):
            raise ReleasePolicyError("release rule requires exact non-wildcard values")
        if not _SHA.fullmatch(self.canonical_target_digest) or not _SHA.fullmatch(self.conformance_receipt_digest):
            raise ReleasePolicyError("release rule digests must be lowercase SHA-256")
        if self.mode not in _MODES or type(self.enabled) is not bool:
            raise ReleasePolicyError("release rule mode/enabled is invalid")


@dataclass(frozen=True, slots=True)
class ReleaseDecision:
    status: str
    reason: str


class ReleasePolicy:
    def __init__(
        self,
        rules: tuple[ReleaseRule, ...] = (),
        *,
        revision: int = 1,
        managed_owner: str = "",
        trusted_source: bool = False,
    ) -> None:
        if type(revision) is not int or revision < 1 or not managed_owner:
            raise ReleasePolicyError("release policy requires a managed owner and positive revision")
        keys = [tuple(getattr(rule, field.name) for field in fields(ReleaseRule) if field.name != "enabled") for rule in rules]
        if len(keys) != len(set(keys)):
            raise ReleasePolicyError("duplicate release rule")
        self.rules = rules
        self.revision = revision
        self.managed_owner = managed_owner
        self.trusted_source = trusted_source

    def authorize_mode(self, binding: Mapping[str, Any], mode: str) -> ReleaseDecision:
        if not self.trusted_source:
            return ReleaseDecision("UNSUPPORTED", "UNTRUSTED_RELEASE_POLICY_SOURCE")
        expected_fields = tuple(field.name for field in fields(ReleaseRule) if field.name not in {"enabled", "mode"})
        for rule in self.rules:
            if not rule.enabled or rule.mode != mode:
                continue
            if all(binding.get(name) == getattr(rule, name) for name in expected_fields):
                return ReleaseDecision("SUPPORTED", "EXACT_RELEASE_RULE")
        return ReleaseDecision("UNSUPPORTED", "NO_EXACT_RELEASE_RULE")
