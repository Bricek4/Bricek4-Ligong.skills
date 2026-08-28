"""Repository selector semantics shared by contracts and evidence scanners."""

from __future__ import annotations

from functools import lru_cache
from pathlib import PurePosixPath


@lru_cache(maxsize=4096)
def selector_matches(path: str, selector: str) -> bool:
    """Match POSIX repository paths, with ``dir/**`` also selecting ``dir``."""

    if not path or path.startswith("/") or "\\" in path:
        return False
    if not selector or selector.startswith("/") or "\\" in selector:
        return False
    canonical = PurePosixPath(path).as_posix()
    pattern = PurePosixPath(selector).as_posix()
    if pattern.endswith("/**") and canonical == pattern[:-3].rstrip("/"):
        return True
    return PurePosixPath(canonical).match(pattern)


def selected(path: str, selectors: tuple[str, ...] | list[str]) -> bool:
    return any(selector_matches(path, selector) for selector in selectors)
