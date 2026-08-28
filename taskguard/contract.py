"""Versioned TaskGuard contract parsing and path validation."""

from __future__ import annotations

from dataclasses import dataclass, field
import fnmatch
from functools import lru_cache
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, Mapping

from .validation import load_strict_json


class ContractError(ValueError):
    """Raised when a task contract is unsafe or structurally invalid."""


@dataclass(frozen=True)
class Acceptance:
    id: str
    argv: list[str]
    cwd: str
    requires_red: bool
    expected_red_pattern: str | None
    idempotent: bool
    selector: str | None = None


@dataclass(frozen=True)
class Contract:
    version: int
    task_id: str
    goal: str
    risk: str
    repo: Path
    scope: list[str]
    acceptance: list[Acceptance]
    acknowledge_dirty: list[str] = field(default_factory=list)
    forbidden: list[dict[str, Any]] = field(default_factory=list)
    surfaces: list[dict[str, Any]] = field(default_factory=list)


_RISK_LEVELS = {"L0", "L1", "L2", "L3"}
_FORBIDDEN_MODES = {"eliminate", "no_new"}
_GLOB_MAGIC = re.compile(r"[*?[]")
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_CONTRACT_FIELDS = {"version", "task_id", "goal", "risk", "repo", "scope", "acknowledge_dirty", "acceptance", "forbidden", "surfaces"}
_CONTRACT_REQUIRED = {"version", "task_id", "goal", "risk", "repo", "scope", "acceptance"}
_ACCEPTANCE_FIELDS = {"id", "argv", "cwd", "selector", "requires_red", "expected_red_pattern", "idempotent"}
_ACCEPTANCE_REQUIRED = {"id", "argv", "cwd", "requires_red", "idempotent"}
_FORBIDDEN_FIELDS = {"id", "glob", "regex", "mode"}
_SURFACE_FIELDS = {"id", "argv", "cwd", "read_only", "allowed_writes", "normalizer_version"}


def _error(field_name: str, message: str) -> ContractError:
    return ContractError(f"{field_name}: {message}")


def _exact_fields(
    value: Mapping[str, Any],
    *,
    label: str,
    allowed: set[str],
    required: set[str],
) -> None:
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        raise _error(f"{label}.{unknown[0]}", "unknown field")
    if missing:
        raise _error(f"{label}.{missing[0]}", "required field missing")


def _nonempty_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _error(field_name, "must be a non-empty string")
    if "\x00" in value:
        raise _error(field_name, "must not contain NUL")
    return value


def _boolean(value: Any, field_name: str) -> bool:
    if type(value) is not bool:
        raise _error(field_name, "must be a boolean")
    return value


def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _git_root(repo: Path) -> Path:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    result = subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        cwd=repo,
        text=True,
        capture_output=True,
        shell=False,
        env=environment,
    )
    if result.returncode:
        raise _error("repo", "must be a Git working-tree root")
    return Path(result.stdout.strip()).resolve()


@lru_cache(maxsize=32)
def _git_admin_roots(repo: Path) -> tuple[Path, ...]:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    roots: list[Path] = []
    for flag in ("--git-dir", "--git-common-dir"):
        result = subprocess.run(
            ["git", "rev-parse", flag],
            cwd=repo,
            text=True,
            capture_output=True,
            shell=False,
            env=environment,
        )
        if result.returncode:
            raise _error("repo", f"cannot resolve Git administrative path {flag}")
        raw = Path(result.stdout.strip())
        candidate = raw if raw.is_absolute() else repo / raw
        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, RuntimeError, OSError) as exc:
            raise _error("repo", f"cannot resolve Git administrative path {flag}: {exc}") from exc
        if resolved not in roots:
            roots.append(resolved)
    return tuple(roots)


def _canonical_repo(value: Any, workspace_root: os.PathLike[str] | str | None) -> Path:
    repo_text = _nonempty_string(value, "repo")
    base = Path.cwd() if workspace_root is None else Path(workspace_root)
    base = base.resolve()
    candidate = Path(repo_text)
    if not candidate.is_absolute():
        candidate = base / candidate
    try:
        repo = candidate.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise _error("repo", f"cannot resolve repository: {exc}") from exc
    if not repo.is_dir():
        raise _error("repo", "must resolve to a directory")
    if _git_root(repo) != repo:
        raise _error("repo", "must name the Git working-tree root")
    return repo


def _lexical_relative(value: Any, field_name: str, *, allow_dot: bool) -> str:
    text = _nonempty_string(value, field_name)
    path = PurePosixPath(text)
    if path.is_absolute():
        raise _error(field_name, "must be repository-relative")
    if any(part == ".." for part in path.parts):
        raise _error(field_name, "must not contain parent traversal")
    if any(part in ("",) for part in path.parts):
        raise _error(field_name, "contains an empty path component")
    normalized = path.as_posix()
    if normalized == "." and not allow_dot:
        raise _error(field_name, "must select a path below the repository root")
    return normalized


def _inside_git_admin(path: Path, admin_roots: tuple[Path, ...]) -> bool:
    return any(_inside(path, root) for root in admin_roots)


def _open_directory(path: Path, field_name: str) -> int:
    try:
        return os.open(path, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
    except OSError as exc:
        raise _error(field_name, f"cannot open repository directory without following links: {exc}") from exc


def _open_child_directory(parent_fd: int, name: str, field_name: str, relative: str) -> int:
    try:
        return os.open(
            name,
            os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise _error(
            field_name,
            f"cannot open selected directory without following links: {relative}: {exc}",
        ) from exc


def _entry_stat(parent_fd: int, name: str, field_name: str, relative: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise _error(field_name, f"cannot inspect selected path {relative}: {exc}") from exc


def _validate_symlink_boundary(
    relative: str,
    field_name: str,
    repo: Path,
    admin_roots: tuple[Path, ...],
) -> None:
    selected = repo / relative
    try:
        target = selected.resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise _error(field_name, f"contains an unresolved symlink: {relative}") from exc
    if _inside_git_admin(target, admin_roots):
        raise _error(field_name, f"selects Git administrative data through symlink: {relative}")
    if not _inside(target, repo):
        raise _error(field_name, f"contains a symlink escape: {relative}")
    try:
        target_relative = target.relative_to(repo)
    except ValueError:
        return
    if any(part.casefold() == ".git" for part in target_relative.parts):
        raise _error(field_name, f"selects Git administrative data through symlink: {relative}")


def _directory_names(directory_fd: int, field_name: str, relative: str) -> list[str]:
    try:
        return sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise _error(field_name, f"cannot enumerate selected directory {relative}: {exc}") from exc


def _reject_nested_admin_marker(
    directory_fd: int,
    field_name: str,
    relative: str,
) -> None:
    for name in _directory_names(directory_fd, field_name, relative):
        if name.casefold() == ".git":
            marker = f"{relative}/{name}" if relative != "." else name
            raise _error(field_name, f"selects Git administrative data: {marker}")


def _scan_selected_directory(
    directory_fd: int,
    relative: str,
    field_name: str,
    repo: Path,
    admin_roots: tuple[Path, ...],
    *,
    repository_root: bool,
) -> None:
    for name in _directory_names(directory_fd, field_name, relative):
        child = name if relative == "." else f"{relative}/{name}"
        if name.casefold() == ".git":
            if repository_root and name == ".git":
                continue
            raise _error(field_name, f"selects Git administrative data: {child}")
        metadata = _entry_stat(directory_fd, name, field_name, child)
        if stat.S_ISLNK(metadata.st_mode):
            _validate_symlink_boundary(child, field_name, repo, admin_roots)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        child_fd = _open_child_directory(directory_fd, name, field_name, child)
        try:
            _scan_selected_directory(
                child_fd,
                child,
                field_name,
                repo,
                admin_roots,
                repository_root=False,
            )
        finally:
            os.close(child_fd)


def _inspect_literal_no_follow(
    path_text: str,
    field_name: str,
    repo: Path,
    admin_roots: tuple[Path, ...],
    *,
    allow_final_symlink: bool,
) -> None:
    parts = PurePosixPath(path_text).parts
    directory_fd = _open_directory(repo, field_name)
    current_fd = directory_fd
    opened_children: list[int] = []
    try:
        if not parts:
            _scan_selected_directory(
                current_fd,
                ".",
                field_name,
                repo,
                admin_roots,
                repository_root=True,
            )
            return
        traversed: list[str] = []
        for index, part in enumerate(parts):
            traversed.append(part)
            relative = "/".join(traversed)
            try:
                metadata = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                return
            except OSError as exc:
                raise _error(field_name, f"cannot inspect selected path {relative}: {exc}") from exc
            final = index == len(parts) - 1
            if stat.S_ISLNK(metadata.st_mode):
                if final and not allow_final_symlink:
                    raise _error(field_name, f"must not be a symlink: {relative}")
                _validate_symlink_boundary(relative, field_name, repo, admin_roots)
                if not final:
                    raise _error(field_name, f"contains an ancestor symlink: {relative}")
                return
            if not stat.S_ISDIR(metadata.st_mode):
                if final:
                    return
                raise _error(field_name, f"path component is not a directory: {relative}")
            child_fd = _open_child_directory(current_fd, part, field_name, relative)
            opened_children.append(child_fd)
            current_fd = child_fd
            _reject_nested_admin_marker(current_fd, field_name, relative)
            if final:
                _scan_selected_directory(
                    current_fd,
                    relative,
                    field_name,
                    repo,
                    admin_roots,
                    repository_root=False,
                )
                return
    finally:
        for descriptor in reversed(opened_children):
            os.close(descriptor)
        os.close(directory_fd)


def _epsilon_closure(states: set[int], pattern: tuple[str, ...]) -> set[int]:
    closed = set(states)
    pending = list(states)
    while pending:
        index = pending.pop()
        if index < len(pattern) and pattern[index] == "**" and index + 1 not in closed:
            closed.add(index + 1)
            pending.append(index + 1)
    return closed


def _pattern_states(parts: tuple[str, ...], pattern: tuple[str, ...]) -> set[int]:
    states = _epsilon_closure({0}, pattern)
    for part in parts:
        following: set[int] = set()
        for index in states:
            if index >= len(pattern):
                continue
            selector = pattern[index]
            if selector == "**":
                following.add(index)
            elif fnmatch.fnmatchcase(part, selector):
                following.add(index + 1)
        states = _epsilon_closure(following, pattern)
        if not states:
            break
    return states


def _selector_matches(path_text: str, selector: str) -> bool:
    """Match one canonical selector without allowing component globs across '/'."""

    candidate = PurePosixPath(path_text.rstrip("/") or ".").as_posix()
    normalized_selector = PurePosixPath(selector.rstrip("/") or ".").as_posix()
    if normalized_selector == ".":
        return True
    if not _GLOB_MAGIC.search(normalized_selector):
        return candidate == normalized_selector or candidate.startswith(
            normalized_selector + "/"
        )
    pattern = PurePosixPath(normalized_selector).parts
    states = _pattern_states(PurePosixPath(candidate).parts, pattern)
    return len(pattern) in states


def _scan_glob_matches(
    directory_fd: int,
    relative_parts: tuple[str, ...],
    pattern: tuple[str, ...],
    field_name: str,
    repo: Path,
    admin_roots: tuple[Path, ...],
) -> None:
    relative = "/".join(relative_parts) or "."
    for name in _directory_names(directory_fd, field_name, relative):
        child_parts = (*relative_parts, name)
        child = "/".join(child_parts)
        states = _pattern_states(child_parts, pattern)
        exact_match = len(pattern) in states
        descendant_match_possible = any(index < len(pattern) for index in states)
        if name.casefold() == ".git":
            if exact_match:
                raise _error(field_name, f"pattern selects Git administrative data: {child}")
            continue
        if not states:
            continue
        metadata = _entry_stat(directory_fd, name, field_name, child)
        if stat.S_ISLNK(metadata.st_mode):
            if descendant_match_possible:
                raise _error(field_name, f"pattern crosses an ancestor symlink: {child}")
            if exact_match:
                _validate_symlink_boundary(child, field_name, repo, admin_roots)
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            continue
        child_fd = _open_child_directory(directory_fd, name, field_name, child)
        try:
            if descendant_match_possible:
                _scan_glob_matches(
                    child_fd,
                    child_parts,
                    pattern,
                    field_name,
                    repo,
                    admin_roots,
                )
        finally:
            os.close(child_fd)


def _inspect_glob_no_follow(
    path_text: str,
    field_name: str,
    repo: Path,
    admin_roots: tuple[Path, ...],
) -> None:
    directory_fd = _open_directory(repo, field_name)
    try:
        _scan_glob_matches(
            directory_fd,
            (),
            PurePosixPath(path_text).parts,
            field_name,
            repo,
            admin_roots,
        )
    finally:
        os.close(directory_fd)


def _canonical_path(
    value: Any,
    field_name: str,
    repo: Path,
    *,
    allow_dot: bool,
    allow_final_symlink: bool = True,
) -> str:
    normalized = _lexical_relative(value, field_name, allow_dot=allow_dot)
    if any(part.casefold() == ".git" for part in PurePosixPath(normalized).parts):
        raise _error(field_name, "must not select Git administrative data")
    admin_roots = _git_admin_roots(repo)
    if _GLOB_MAGIC.search(normalized):
        _inspect_glob_no_follow(normalized, field_name, repo, admin_roots)
    else:
        _inspect_literal_no_follow(
            normalized,
            field_name,
            repo,
            admin_roots,
            allow_final_symlink=allow_final_symlink,
        )
    return normalized


def _acceptance_items(value: Any, repo: Path) -> list[Acceptance]:
    if not isinstance(value, list) or not value:
        raise _error("acceptance", "must be a non-empty array")
    items: list[Acceptance] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        prefix = f"acceptance[{index}]"
        if not isinstance(raw, Mapping):
            raise _error(prefix, "must be an object")
        _exact_fields(
            raw,
            label=prefix,
            allowed=_ACCEPTANCE_FIELDS,
            required=_ACCEPTANCE_REQUIRED,
        )
        item_id = _nonempty_string(raw.get("id"), f"{prefix}.id")
        if item_id in seen:
            raise _error(f"{prefix}.id", "must be unique")
        seen.add(item_id)
        argv = raw.get("argv")
        if not isinstance(argv, list) or not argv:
            raise _error(f"{prefix}.argv", "must be a non-empty string array")
        parsed_argv = [_nonempty_string(arg, f"{prefix}.argv[{arg_index}]") for arg_index, arg in enumerate(argv)]
        cwd = _canonical_path(
            raw.get("cwd", "."),
            f"{prefix}.cwd",
            repo,
            allow_dot=True,
            allow_final_symlink=False,
        )
        cwd_path = repo if cwd == "." else repo / cwd
        if not cwd_path.exists() or not cwd_path.is_dir():
            raise _error(f"{prefix}.cwd", "must resolve to an existing directory")
        requires_red = _boolean(raw.get("requires_red"), f"{prefix}.requires_red")
        idempotent = _boolean(raw.get("idempotent"), f"{prefix}.idempotent")
        expected = raw.get("expected_red_pattern")
        if requires_red:
            expected = _nonempty_string(expected, f"{prefix}.expected_red_pattern")
        elif expected is not None:
            expected = _nonempty_string(expected, f"{prefix}.expected_red_pattern")
        selector = raw.get("selector")
        if selector is not None:
            selector = _nonempty_string(selector, f"{prefix}.selector")
        items.append(
            Acceptance(
                id=item_id,
                argv=parsed_argv,
                cwd=cwd,
                requires_red=requires_red,
                expected_red_pattern=expected,
                idempotent=idempotent,
                selector=selector,
            )
        )
    return items


def _path_array(value: Any, field_name: str, repo: Path) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _error(field_name, "must be an array")
    return [
        _canonical_path(item, f"{field_name}[{index}]", repo, allow_dot=False)
        for index, item in enumerate(value)
    ]


def _forbidden_rules(value: Any, repo: Path) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _error("forbidden", "must be an array")
    parsed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        prefix = f"forbidden[{index}]"
        if not isinstance(raw, Mapping):
            raise _error(prefix, "must be an object")
        _exact_fields(raw, label=prefix, allowed=_FORBIDDEN_FIELDS, required=_FORBIDDEN_FIELDS)
        rule_id = _nonempty_string(raw.get("id"), f"{prefix}.id")
        if rule_id in seen:
            raise _error(f"{prefix}.id", "must be unique")
        seen.add(rule_id)
        glob = _canonical_path(raw.get("glob"), f"{prefix}.glob", repo, allow_dot=False)
        pattern = _nonempty_string(raw.get("regex"), f"{prefix}.regex")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise _error(f"{prefix}.regex", f"invalid regular expression: {exc}") from exc
        mode = _nonempty_string(raw.get("mode"), f"{prefix}.mode")
        if mode not in _FORBIDDEN_MODES:
            raise _error(f"{prefix}.mode", f"must be one of {sorted(_FORBIDDEN_MODES)}")
        parsed.append({"id": rule_id, "glob": glob, "regex": pattern, "mode": mode})
    return parsed


def _surface_rules(value: Any, repo: Path) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _error("surfaces", "must be an array")
    parsed: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        prefix = f"surfaces[{index}]"
        if not isinstance(raw, Mapping):
            raise _error(prefix, "must be an object")
        _exact_fields(raw, label=prefix, allowed=_SURFACE_FIELDS, required=_SURFACE_FIELDS)
        surface_id = _nonempty_string(raw.get("id"), f"{prefix}.id")
        if surface_id in seen:
            raise _error(f"{prefix}.id", "must be unique")
        seen.add(surface_id)
        argv = raw.get("argv")
        if not isinstance(argv, list) or not argv:
            raise _error(f"{prefix}.argv", "must be a non-empty string array")
        parsed_argv = [_nonempty_string(arg, f"{prefix}.argv[{i}]") for i, arg in enumerate(argv)]
        cwd = _canonical_path(
            raw.get("cwd", "."),
            f"{prefix}.cwd",
            repo,
            allow_dot=True,
            allow_final_symlink=False,
        )
        cwd_path = repo if cwd == "." else repo / cwd
        if not cwd_path.exists() or not cwd_path.is_dir():
            raise _error(f"{prefix}.cwd", "must resolve to an existing directory")
        read_only = _boolean(raw.get("read_only"), f"{prefix}.read_only")
        if not read_only:
            raise _error(f"{prefix}.read_only", "surface adapters must be read-only")
        normalizer = _nonempty_string(raw.get("normalizer_version"), f"{prefix}.normalizer_version")
        allowed_writes = _path_array(raw.get("allowed_writes", []), f"{prefix}.allowed_writes", repo)
        parsed.append(
            {
                "id": surface_id,
                "argv": parsed_argv,
                "cwd": cwd,
                "read_only": True,
                "normalizer_version": normalizer,
                "allowed_writes": allowed_writes,
            }
        )
    return parsed


def validate_contract(
    document: Any,
    workspace_root: os.PathLike[str] | str | None = None,
) -> Contract:
    """Validate and canonicalize a v2 contract without executing acceptance commands."""

    if not isinstance(document, Mapping):
        raise ContractError("contract must be a JSON object")
    _exact_fields(
        document,
        label="contract",
        allowed=_CONTRACT_FIELDS,
        required=_CONTRACT_REQUIRED,
    )
    version = document.get("version")
    if type(version) is not int or version != 2:
        raise _error("version", "must be integer 2")
    task_id = _nonempty_string(document.get("task_id"), "task_id")
    goal = _nonempty_string(document.get("goal"), "goal")
    risk = _nonempty_string(document.get("risk"), "risk")
    if risk not in _RISK_LEVELS:
        raise _error("risk", f"must be one of {sorted(_RISK_LEVELS)}")
    repo = _canonical_repo(document.get("repo"), workspace_root)
    scope_raw = document.get("scope")
    if not isinstance(scope_raw, list) or not scope_raw:
        raise _error("scope", "must be a non-empty array")
    scope = [
        _canonical_path(item, f"scope[{index}]", repo, allow_dot=True)
        for index, item in enumerate(scope_raw)
    ]
    if len(set(scope)) != len(scope):
        raise _error("scope", "must not contain duplicate paths")
    acceptance = _acceptance_items(document.get("acceptance"), repo)
    acknowledged = _path_array(document.get("acknowledge_dirty", []), "acknowledge_dirty", repo)
    if len(set(acknowledged)) != len(acknowledged):
        raise _error("acknowledge_dirty", "must not contain duplicate paths")
    forbidden = _forbidden_rules(document.get("forbidden", []), repo)
    surfaces = _surface_rules(document.get("surfaces", []), repo)
    return Contract(
        version=version,
        task_id=task_id,
        goal=goal,
        risk=risk,
        repo=repo,
        scope=scope,
        acceptance=acceptance,
        acknowledge_dirty=acknowledged,
        forbidden=forbidden,
        surfaces=surfaces,
    )


def load_contract(
    path: os.PathLike[str] | str,
    workspace_root: os.PathLike[str] | str | None = None,
) -> Contract:
    """Load JSON from *path* and validate it as a TaskGuard v2 contract."""

    contract_path = Path(path)
    try:
        document = load_strict_json(contract_path)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ContractError(f"contract file {contract_path}: {exc}") from exc
    base = contract_path.parent if workspace_root is None else Path(workspace_root)
    return validate_contract(document, workspace_root=base)
