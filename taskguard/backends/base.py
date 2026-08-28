"""Backend interface used by the explicit protocol router."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence


@dataclass(frozen=True, slots=True)
class BackendResult:
    exit_code: int


class Backend(Protocol):
    protocol_version: int

    def main(self, argv: Sequence[str]) -> int: ...
