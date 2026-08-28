"""Immutable content-addressed receipt reference."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class ReceiptRef:
    digest: str
    kind: str

    def __post_init__(self) -> None:
        if not _SHA256.fullmatch(self.digest):
            raise ValueError("receipt digest must be lowercase SHA-256")
        if not self.kind or "\x00" in self.kind:
            raise ValueError("receipt kind must be non-empty")

    def to_manifest(self) -> dict[str, str]:
        return {"digest": self.digest, "kind": self.kind}

    @classmethod
    def from_manifest(cls, value: Any) -> "ReceiptRef":
        if not isinstance(value, dict) or set(value) != {"digest", "kind"}:
            raise ValueError("receipt reference must have exact digest/kind fields")
        if not isinstance(value["digest"], str) or not isinstance(value["kind"], str):
            raise ValueError("receipt reference fields must be strings")
        return cls(value["digest"], value["kind"])
