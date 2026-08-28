"""Typed immutable receipt envelopes."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Any, Mapping

from ..receipts.refs import ReceiptRef
from ..validation import canonical_json_bytes, exact_object, freeze_json, sha256_digest, thaw_json


RECEIPT_VERSION = "taskguard-receipt-v1"


class ReceiptError(ValueError):
    pass


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ReceiptError(f"{label} must be an object")
    canonical_json_bytes(value)
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class Receipt:
    version: str
    kind: str
    task_id: str
    action_id: str | None
    binding: Mapping[str, Any]
    body: Mapping[str, Any]
    parents: tuple[ReceiptRef, ...]
    issued_at: str

    def __post_init__(self) -> None:
        if self.version != RECEIPT_VERSION:
            raise ReceiptError("unsupported receipt version")
        for label, value in (("kind", self.kind), ("task_id", self.task_id), ("issued_at", self.issued_at)):
            if type(value) is not str or not value or "\x00" in value:
                raise ReceiptError(f"receipt {label} must be non-empty")
        if self.action_id is not None and (type(self.action_id) is not str or not self.action_id):
            raise ReceiptError("receipt action_id must be null or non-empty")
        try:
            datetime.fromisoformat(self.issued_at.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ReceiptError("receipt issued_at must be RFC3339-compatible") from exc
        if tuple(sorted(self.parents, key=lambda item: (item.digest, item.kind))) != self.parents:
            raise ReceiptError("receipt parents must be in stable digest/kind order")
        if len({item.digest for item in self.parents}) != len(self.parents):
            raise ReceiptError("receipt parents must be unique")
        object.__setattr__(self, "binding", freeze_json(dict(self.binding)))
        object.__setattr__(self, "body", freeze_json(dict(self.body)))
        canonical_json_bytes(self.to_manifest())

    def to_manifest(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "kind": self.kind,
            "task_id": self.task_id,
            "action_id": self.action_id,
            "binding": thaw_json(self.binding),
            "body": thaw_json(self.body),
            "parents": [item.to_manifest() for item in self.parents],
            "issued_at": self.issued_at,
        }

    def digest(self) -> str:
        return sha256_digest(self.to_manifest())

    @classmethod
    def from_manifest(cls, raw: Any) -> "Receipt":
        try:
            value = exact_object(
                raw,
                label="receipt",
                required={"version", "kind", "task_id", "action_id", "binding", "body", "parents", "issued_at"},
            )
        except ValueError as exc:
            raise ReceiptError(str(exc)) from exc
        parents_raw = value["parents"]
        if not isinstance(parents_raw, list):
            raise ReceiptError("receipt.parents must be an array")
        return cls(
            version=value["version"],
            kind=value["kind"],
            task_id=value["task_id"],
            action_id=value["action_id"],
            binding=_mapping(value["binding"], "receipt.binding"),
            body=_mapping(value["body"], "receipt.body"),
            parents=tuple(ReceiptRef.from_manifest(item) for item in parents_raw),
            issued_at=value["issued_at"],
        )
