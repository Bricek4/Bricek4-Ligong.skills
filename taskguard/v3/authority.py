"""Trusted authority interfaces and the built-in fail-closed provider."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping, Protocol

from ..validation import sha256_digest


@dataclass(frozen=True, slots=True)
class AuthorityCapabilities:
    challenge: bool
    verifiable_attestation: bool
    one_time_consumption: bool


@dataclass(frozen=True, slots=True)
class AuthorityRequest:
    task_id: str
    action_id: str
    action_digest: str
    plan_digest: str
    target_digest: str
    environment: str
    principal_digest: str
    apply_requested: bool
    rollback_requested: bool
    user_context: str = ""

    def binding(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "action_id": self.action_id,
            "action_digest": self.action_digest,
            "plan_digest": self.plan_digest,
            "target_digest": self.target_digest,
            "environment": self.environment,
            "principal_digest": self.principal_digest,
            "apply_requested": self.apply_requested,
            "rollback_requested": self.rollback_requested,
        }

    @property
    def digest(self) -> str:
        return sha256_digest(self.binding())


@dataclass(frozen=True, slots=True)
class AuthorityReceipt:
    grant_id: str
    nonce: str
    request_digest: str
    issuer: str
    expires_at: str
    apply_authorized: bool
    rollback_authorized: bool
    attestation: str


@dataclass(frozen=True, slots=True)
class AuthorityVerdict:
    verdict: str
    reason: str
    receipt: AuthorityReceipt | None = None


@dataclass(frozen=True, slots=True)
class ActionLease:
    task_id: str
    action_id: str
    revision: int
    owner: str


@dataclass(frozen=True, slots=True)
class ConsumptionReceipt:
    verdict: str
    reason: str
    nonce: str | None = None


class AuthorityProvider(Protocol):
    provider_id: str
    provider_version: str
    def capabilities(self) -> AuthorityCapabilities: ...
    def request_challenge(self, request: AuthorityRequest) -> AuthorityVerdict: ...
    def verify(self, raw_receipt: Mapping[str, Any], request: AuthorityRequest, now: datetime | None = None) -> AuthorityVerdict: ...
    def consume(self, receipt: AuthorityReceipt, lease: ActionLease, now: datetime | None = None) -> ConsumptionReceipt: ...


class UnavailableAuthorityProvider:
    provider_id = "unavailable"
    provider_version = "0"
    _REASON = "NO_TRUSTED_AUTHORITY_PROVIDER"

    def capabilities(self) -> AuthorityCapabilities:
        return AuthorityCapabilities(False, False, False)

    def request_challenge(self, request: AuthorityRequest) -> AuthorityVerdict:
        del request
        return AuthorityVerdict("UNSUPPORTED", self._REASON)

    def verify(self, raw_receipt: Mapping[str, Any], request: AuthorityRequest, now: datetime | None = None) -> AuthorityVerdict:
        del raw_receipt, request, now
        return AuthorityVerdict("UNSUPPORTED", self._REASON)

    def consume(self, receipt: AuthorityReceipt, lease: ActionLease, now: datetime | None = None) -> ConsumptionReceipt:
        del receipt, lease, now
        return ConsumptionReceipt("UNSUPPORTED", self._REASON)
