#!/usr/bin/env python3
"""Bind a worker to one Git worktree and detect writes to protected repositories."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any


def _git(root: Path, *argv: str) -> bytes:
    result = subprocess.run(
        ["git", *argv], cwd=root, capture_output=True, check=False
    )
    if result.returncode:
        raise ValueError(result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def _repo(value: str) -> Path:
    candidate = Path(value).resolve(strict=True)
    top = Path(_git(candidate, "rev-parse", "--show-toplevel").decode().strip()).resolve()
    if candidate != top:
        raise ValueError(f"path is not the Git worktree root: {candidate}")
    return candidate


def _fingerprint(root: Path) -> dict[str, str]:
    head = _git(root, "rev-parse", "HEAD").decode().strip()
    status = _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    return {
        "root": str(root),
        "head": head,
        "status_sha256": hashlib.sha256(status).hexdigest(),
    }


def _write_state(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _read_state(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("version") != "ligong-workspace-binding-v1":
        raise ValueError("workspace binding has an unsupported version")
    return value


def _within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def bind(args: argparse.Namespace) -> dict[str, Any]:
    workspace = _repo(args.workspace)
    protected = [_repo(value) for value in args.protect]
    if any(root == workspace for root in protected):
        raise ValueError("the active workspace cannot also be protected")
    value = {
        "version": "ligong-workspace-binding-v1",
        "workspace": str(workspace),
        "protected": [_fingerprint(root) for root in protected],
    }
    _write_state(Path(args.state).resolve(), value)
    return {"status": "BOUND", **value}


def check(args: argparse.Namespace) -> dict[str, Any]:
    value = _read_state(Path(args.state).resolve(strict=True))
    workspace = _repo(value["workspace"])
    violations: list[dict[str, Any]] = []
    for expected in value["protected"]:
        actual = _fingerprint(_repo(expected["root"]))
        if actual != expected:
            violations.append({"expected": expected, "actual": actual})
    if violations:
        return {"status": "VIOLATION", "workspace": str(workspace), "violations": violations}
    return {"status": "CLEAN", "workspace": str(workspace), "violations": []}


def assert_path(args: argparse.Namespace) -> dict[str, Any]:
    value = _read_state(Path(args.state).resolve(strict=True))
    workspace = Path(value["workspace"]).resolve(strict=True)
    rejected: list[str] = []
    accepted: list[str] = []
    for raw in args.path:
        target = Path(raw)
        if not target.is_absolute():
            target = workspace / target
        target = target.resolve(strict=False)
        if _within(target, workspace):
            accepted.append(str(target))
        else:
            rejected.append(str(target))
    return {
        "status": "ALLOWED" if not rejected else "VIOLATION",
        "workspace": str(workspace),
        "accepted": accepted,
        "rejected": rejected,
    }


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="workspace_guard.py")
    commands = root.add_subparsers(dest="command", required=True)
    bind_parser = commands.add_parser("bind")
    bind_parser.add_argument("--workspace", required=True)
    bind_parser.add_argument("--state", required=True)
    bind_parser.add_argument("--protect", action="append", default=[])
    bind_parser.set_defaults(handler=bind)
    check_parser = commands.add_parser("check")
    check_parser.add_argument("--state", required=True)
    check_parser.set_defaults(handler=check)
    path_parser = commands.add_parser("assert-path")
    path_parser.add_argument("--state", required=True)
    path_parser.add_argument("--path", action="append", required=True)
    path_parser.set_defaults(handler=assert_path)
    return root


def main(argv: list[str] | None = None) -> int:
    try:
        args = parser().parse_args(argv)
        result = args.handler(args)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "ERROR", "error": str(exc)}
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] not in {"ERROR", "VIOLATION"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
