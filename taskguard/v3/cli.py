"""Canonical command-line interface for TaskGuard protocol 3."""

from __future__ import annotations

import argparse
import sys
from typing import Any, Sequence

from ..state import StateError
from ..validation import canonical_json_bytes
from .backend import V3Backend
from .receipt_store import ReceiptIntegrityError


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="task_guard.py")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "init"):
        item = commands.add_parser(command)
        item.add_argument("--contract", required=True)
        if command == "init":
            item.add_argument("--state-dir", required=True)
    explain = commands.add_parser("explain")
    explain.add_argument("--contract")
    explain.add_argument("--state-dir")
    commands.add_parser("doctor-v3")
    commands.add_parser("provider-readiness")
    shadow = commands.add_parser("shadow")
    shadow.add_argument("--contract", required=True)
    shadow.add_argument("--action", required=True)
    for command in ("status", "export", "apply", "reconcile", "rollback", "health", "verify"):
        item = commands.add_parser(command)
        item.add_argument("--state-dir", required=True)
        item.add_argument("--action")
    plan = commands.add_parser("plan")
    plan.add_argument("--state-dir", required=True)
    plan.add_argument("--action", required=True)
    return parser


def main(argv: Sequence[str] | None = None, *, backend: V3Backend | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        payload, exit_code = (backend or V3Backend()).execute(arguments.command, vars(arguments))
    except (ValueError, KeyError, StateError, ReceiptIntegrityError) as exc:
        print(f"state/input error: {exc}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"internal error: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 4
    sys.stdout.write(canonical_json_bytes(payload).decode("ascii") + "\n")
    return exit_code
