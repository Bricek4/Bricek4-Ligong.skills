"""Canonical JSON types and immutable provider result types."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, TypeAlias


JSONScalar: TypeAlias = None | bool | int | float | str
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]


@dataclass(frozen=True, slots=True)
class AdapterIdentity:
    adapter_id: str
    adapter_version: str
    provider: str

    def to_manifest(self) -> dict[str, str]:
        return {"adapter_id": self.adapter_id, "adapter_version": self.adapter_version, "provider": self.provider}


@dataclass(frozen=True, slots=True)
class CanonicalTarget:
    provider: str
    account_id: str
    project_id: str
    resource_id: str

    def to_manifest(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "account_id": self.account_id,
            "project_id": self.project_id,
            "resource_id": self.resource_id,
        }


@dataclass(frozen=True, slots=True)
class PrincipalReceipt:
    principal_ref: str
    credential_ref: str

    def to_manifest(self) -> dict[str, str]:
        return {"principal_ref": self.principal_ref, "credential_ref": self.credential_ref}


@dataclass(frozen=True, slots=True)
class PlanReceipt:
    action_id: str
    target: CanonicalTarget
    remote_version: str
    provider_plan: Mapping[str, Any]
