"""Compatibility adapter for the unchanged v2 command surface."""

from __future__ import annotations

from typing import Sequence


class V2Backend:
    protocol_version = 2

    def main(self, argv: Sequence[str]) -> int:
        if argv and argv[0] == "export":
            from ..control import main

            return main(argv)
        from ..cli import main

        return main(argv)
