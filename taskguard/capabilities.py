"""Read-only TaskGuard capability detection for SSS preflight."""

from __future__ import annotations

import os
import platform
import shutil
import signal
import sys
from typing import Mapping


_CAPABILITY_ORDER = (
    "posix_platform",
    "fcntl",
    "o_nofollow",
    "o_directory",
    "directory_fsync",
    "process_groups",
    "required_signals",
    "git",
)


def evaluate_capabilities(
    platform_name: str,
    facts: Mapping[str, bool],
    *,
    python_version: str,
) -> dict[str, object]:
    """Normalize injected facts into a deterministic support report."""

    if any(name not in facts or type(facts[name]) is not bool for name in _CAPABILITY_ORDER):
        raise ValueError("capability facts must contain exact boolean values")
    platform_supported = platform_name == "darwin" or platform_name.startswith(
        ("linux", "freebsd", "openbsd", "netbsd")
    )
    capabilities = {name: facts[name] for name in _CAPABILITY_ORDER}
    capabilities["posix_platform"] = capabilities["posix_platform"] and platform_supported
    missing = [name for name in _CAPABILITY_ORDER if not capabilities[name]]
    return {
        "version": "taskguard-capabilities-v1",
        "platform": platform_name,
        "python": python_version,
        "capabilities": capabilities,
        "missing": missing,
        "taskguard_supported": not missing,
    }


def detect_capabilities(platform_name: str | None = None) -> dict[str, object]:
    """Inspect the current runtime without writing files or starting processes."""

    try:
        import fcntl as _fcntl  # noqa: F401
    except ImportError:
        has_fcntl = False
    else:
        has_fcntl = True

    selected_platform = sys.platform if platform_name is None else platform_name
    posix_platform = os.name == "posix" and selected_platform != "win32"
    has_directory_flag = bool(getattr(os, "O_DIRECTORY", 0))
    has_fsync = callable(getattr(os, "fsync", None))
    facts = {
        "posix_platform": posix_platform,
        "fcntl": has_fcntl,
        "o_nofollow": bool(getattr(os, "O_NOFOLLOW", 0)),
        "o_directory": has_directory_flag,
        "directory_fsync": has_directory_flag and has_fsync,
        "process_groups": callable(getattr(os, "killpg", None))
        and callable(getattr(os, "getpgrp", None)),
        "required_signals": all(
            hasattr(signal, name) for name in ("SIGTERM", "SIGKILL")
        ),
        "git": shutil.which("git") is not None,
    }
    return evaluate_capabilities(
        selected_platform,
        facts,
        python_version=platform.python_version(),
    )


def validate_capability_report(value: object) -> dict[str, object]:
    """Reject malformed or internally contradictory injected reports."""

    fields = {
        "version",
        "platform",
        "python",
        "capabilities",
        "missing",
        "taskguard_supported",
    }
    if type(value) is not dict or set(value) != fields:
        raise ValueError("capability report has an inexact schema")
    if value["version"] != "taskguard-capabilities-v1":
        raise ValueError("capability report version is unsupported")
    if type(value["platform"]) is not str or type(value["python"]) is not str:
        raise ValueError("capability platform and python must be strings")
    facts = value["capabilities"]
    if type(facts) is not dict or tuple(facts) != _CAPABILITY_ORDER:
        raise ValueError("capability facts have an inexact schema or order")
    if any(type(facts[name]) is not bool for name in _CAPABILITY_ORDER):
        raise ValueError("capability facts must be booleans")
    expected_missing = [name for name in _CAPABILITY_ORDER if not facts[name]]
    if value["missing"] != expected_missing:
        raise ValueError("capability missing list contradicts facts")
    if type(value["taskguard_supported"]) is not bool or value[
        "taskguard_supported"
    ] is not (not expected_missing):
        raise ValueError("capability support verdict contradicts facts")
    return value


__all__ = [
    "detect_capabilities",
    "evaluate_capabilities",
    "validate_capability_report",
]
