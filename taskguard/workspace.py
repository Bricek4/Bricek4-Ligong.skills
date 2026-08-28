"""Consistent Git/index evidence and race-safe restricted workspace snapshots."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from typing import Any, Iterable, Mapping

from .contract import _selector_matches


class ScopeViolation(RuntimeError):
    """Raised when workspace evidence is unavailable or leaves declared scope."""


class _UnstableCapture(ScopeViolation):
    """Internal signal for a path or Git view that changed during capture."""


_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_MAX_CONSISTENCY_ATTEMPTS = 3
_FINGERPRINT_KINDS = {
    "missing",
    "file",
    "directory",
    "symlink",
    "ancestor-symlink",
    "ancestor-nondirectory",
    "fifo",
    "socket",
    "character-device",
    "block-device",
    "other",
}
_GIT_INDEX_MODES = {"100644", "100755", "120000", "160000"}
_HEX_OBJECT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_HEX_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ORDINARY_WORKTREE_STATES = frozenset(" MTD")
_CONFLICT_STAGES = {
    "DD": frozenset({1}),
    "AU": frozenset({2}),
    "UD": frozenset({1, 2}),
    "UA": frozenset({3}),
    "DU": frozenset({1, 3}),
    "AA": frozenset({2, 3}),
    "UU": frozenset({1, 2, 3}),
}


@dataclass(frozen=True)
class FileFingerprint:
    kind: str
    mode: int
    digest: str | None = None
    symlink_target: str | None = None

    def to_manifest(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "mode": self.mode,
            "digest": self.digest,
            "symlink_target": self.symlink_target,
        }

    @classmethod
    def from_manifest(cls, value: Mapping[str, Any]) -> "FileFingerprint":
        if type(value) is not dict:
            raise ScopeViolation("file fingerprint manifest must be an object")
        if set(value) != {"kind", "mode", "digest", "symlink_target"}:
            raise ScopeViolation("file fingerprint manifest has unexpected fields")
        kind = value.get("kind")
        mode = value.get("mode")
        digest = value.get("digest")
        target = value.get("symlink_target")
        if type(kind) is not str or kind not in _FINGERPRINT_KINDS:
            raise ScopeViolation("file fingerprint manifest has an invalid kind")
        if type(mode) is not int or not 0 <= mode <= 0o7777:
            raise ScopeViolation("file fingerprint manifest has invalid kind/mode")
        if kind == "file":
            if type(digest) is not str or not _HEX_SHA256.fullmatch(digest):
                raise ScopeViolation("file fingerprint digest must be lowercase SHA-256")
            if target is not None:
                raise ScopeViolation("regular-file fingerprint must not have a symlink target")
        elif kind in {"symlink", "ancestor-symlink"}:
            if digest is not None:
                raise ScopeViolation("symlink fingerprint must not have a content digest")
            if type(target) is not str or "\x00" in target:
                raise ScopeViolation("symlink fingerprint must have a NUL-free target")
        elif digest is not None or target is not None:
            raise ScopeViolation(f"{kind} fingerprint must not have digest/target data")
        if kind == "missing" and mode != 0:
            raise ScopeViolation("missing fingerprint mode must be zero")
        return cls(kind=kind, mode=mode, digest=digest, symlink_target=target)


@dataclass(frozen=True)
class WorkspaceComparison:
    status: str
    aggregate: str
    changed_paths: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class _GitEvidence:
    head: str
    index_entries: dict[str, tuple[tuple[str, str, int], ...]]
    status_entries: dict[str, str]


def _git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    return environment


def _run_git(repo: Path, argv: list[str], *, text: bool = True):
    result = subprocess.run(
        ["git", *argv],
        cwd=repo,
        capture_output=True,
        text=text,
        shell=False,
        env=_git_environment(),
    )
    if result.returncode:
        stderr = result.stderr if text else result.stderr.decode("utf-8", "replace")
        raise ScopeViolation(f"git {' '.join(argv)} failed: {stderr.strip()}")
    return result


def _canonical_repo(value: os.PathLike[str] | str) -> Path:
    try:
        repo = Path(value).resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        raise ScopeViolation(f"cannot resolve repository: {exc}") from exc
    if not repo.is_dir():
        raise ScopeViolation(f"repository is not a directory: {repo}")
    root_text = _run_git(repo, ["rev-parse", "--show-toplevel"]).stdout.strip()
    root = Path(root_text).resolve()
    if root != repo:
        raise ScopeViolation(f"repository must be the Git working-tree root: {repo}")
    return repo


def _canonical_selector(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ScopeViolation("scope entries must be non-empty strings without NUL")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ScopeViolation(f"scope entry must be repository-relative: {value!r}")
    if any(part.casefold() == ".git" for part in path.parts):
        raise ScopeViolation("scope must not select Git administrative data")
    normalized = path.as_posix()
    return "." if normalized == "." else normalized.rstrip("/")


def _selected(path: str, selectors: Iterable[str]) -> bool:
    return any(_selector_matches(path, selector) for selector in selectors)


def _literal_prefix(selector: str) -> str:
    parts: list[str] = []
    for part in PurePosixPath(selector).parts:
        if any(character in part for character in "*?["):
            break
        parts.append(part)
    return PurePosixPath(*parts).as_posix() if parts else "."


def _mode_kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character-device"
    if stat.S_ISBLK(mode):
        return "block-device"
    return "other"


def _hash_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    except OSError as exc:
        raise _UnstableCapture(f"cannot read scoped file descriptor: {exc}") from exc
    return digest.hexdigest()


def _metadata_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _fingerprint_child(parent_fd: int, name: str, relative: str) -> FileFingerprint:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return FileFingerprint(kind="missing", mode=0)
    except OSError as exc:
        raise _UnstableCapture(f"cannot lstat scoped path {relative}: {exc}") from exc
    permissions = stat.S_IMODE(before.st_mode)
    kind = _mode_kind(before.st_mode)
    if kind == "symlink":
        try:
            target = os.readlink(name, dir_fd=parent_fd)
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _UnstableCapture(f"cannot read scoped symlink {relative}: {exc}") from exc
        if _metadata_signature(before) != _metadata_signature(after):
            raise _UnstableCapture(f"scoped symlink changed while reading {relative}")
        return FileFingerprint(kind="symlink", mode=permissions, symlink_target=target)
    if kind != "file":
        try:
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _UnstableCapture(f"scoped path changed while reading {relative}: {exc}") from exc
        if _metadata_signature(before) != _metadata_signature(after):
            raise _UnstableCapture(f"scoped path changed while reading {relative}")
        return FileFingerprint(kind=kind, mode=permissions)
    try:
        descriptor = os.open(name, os.O_RDONLY | _NOFOLLOW | _CLOEXEC, dir_fd=parent_fd)
    except OSError as exc:
        raise _UnstableCapture(f"scoped file changed while opening {relative}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if _metadata_signature(before) != _metadata_signature(opened):
            raise _UnstableCapture(f"scoped file changed while opening {relative}")
        digest = _hash_descriptor(descriptor)
        after_descriptor = os.fstat(descriptor)
        try:
            after_path = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as exc:
            raise _UnstableCapture(
                f"scoped file pathname changed while hashing {relative}: {exc}"
            ) from exc
        if (
            _metadata_signature(opened) != _metadata_signature(after_descriptor)
            or _metadata_signature(opened) != _metadata_signature(after_path)
        ):
            raise _UnstableCapture(f"scoped file changed while hashing {relative}")
        return FileFingerprint(
            kind="file",
            mode=stat.S_IMODE(opened.st_mode),
            digest=digest,
        )
    finally:
        os.close(descriptor)


def _open_repo_directory(repo: Path) -> int:
    try:
        return os.open(repo, os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC)
    except OSError as exc:
        raise ScopeViolation(f"cannot open repository root without following symlinks: {exc}") from exc


def _secure_fingerprint(repo: Path, relative: str) -> FileFingerprint:
    if relative == ".":
        metadata = repo.lstat()
        return FileFingerprint(kind="directory", mode=stat.S_IMODE(metadata.st_mode))
    parts = PurePosixPath(relative).parts
    current_fd = _open_repo_directory(repo)
    try:
        for index, part in enumerate(parts):
            last = index == len(parts) - 1
            try:
                metadata = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            except FileNotFoundError:
                return FileFingerprint(kind="missing", mode=0)
            except OSError as exc:
                raise _UnstableCapture(f"cannot inspect scoped path {relative}: {exc}") from exc
            kind = _mode_kind(metadata.st_mode)
            if kind == "symlink":
                try:
                    target = os.readlink(part, dir_fd=current_fd)
                except OSError as exc:
                    raise _UnstableCapture(f"cannot read scoped symlink boundary {relative}: {exc}") from exc
                return FileFingerprint(
                    kind="symlink" if last else "ancestor-symlink",
                    mode=stat.S_IMODE(metadata.st_mode),
                    symlink_target=f"{'/'.join(parts[: index + 1])}:{target}",
                )
            if last:
                return _fingerprint_child(current_fd, part, relative)
            if kind != "directory":
                return FileFingerprint(
                    kind="ancestor-nondirectory",
                    mode=stat.S_IMODE(metadata.st_mode),
                )
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise _UnstableCapture(f"scoped parent changed while opening {relative}: {exc}") from exc
            os.close(current_fd)
            current_fd = next_fd
        raise AssertionError("unreachable empty scoped path")
    finally:
        os.close(current_fd)


def _open_scoped_directory(repo: Path, relative: str) -> int:
    current_fd = _open_repo_directory(repo)
    if relative == ".":
        return current_fd
    try:
        for part in PurePosixPath(relative).parts:
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise _UnstableCapture(f"scoped directory changed while opening {relative}: {exc}") from exc
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _walk_scoped_directory(
    directory_fd: int,
    relative: str,
    selectors: tuple[str, ...],
    entries: dict[str, FileFingerprint],
    *,
    repository_root: bool = False,
) -> None:
    try:
        names = sorted(os.listdir(directory_fd))
    except OSError as exc:
        raise _UnstableCapture(f"cannot enumerate scoped directory {relative}: {exc}") from exc
    for name in names:
        if repository_root and name.casefold() == ".git":
            continue
        child = name if relative == "." else f"{relative}/{name}"
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise _UnstableCapture(
                f"scoped directory entry disappeared during enumeration: {child}"
            ) from exc
        except OSError as exc:
            raise _UnstableCapture(f"cannot lstat scoped path {child}: {exc}") from exc
        kind = _mode_kind(metadata.st_mode)
        if _selected(child, selectors):
            fingerprint = _fingerprint_child(directory_fd, name, child)
            entries[child] = fingerprint
        if kind != "directory" or name.casefold() == ".git":
            continue
        try:
            child_fd = os.open(
                name,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise _UnstableCapture(f"scoped directory changed while opening {child}: {exc}") from exc
        try:
            _walk_scoped_directory(child_fd, child, selectors, entries)
        finally:
            os.close(child_fd)


def _index_entries(repo: Path) -> dict[str, tuple[tuple[str, str, int], ...]]:
    result = _run_git(repo, ["ls-files", "--stage", "-z"], text=False)
    collected: dict[str, list[tuple[str, str, int]]] = {}
    for record in result.stdout.split(b"\0"):
        if not record:
            continue
        try:
            header, raw_path = record.split(b"\t", 1)
            mode, object_id, stage_text = header.split(b" ", 2)
            stage = int(stage_text)
        except (ValueError, TypeError) as exc:
            raise ScopeViolation("git ls-files returned an invalid stage record") from exc
        path = raw_path.decode("utf-8", "surrogateescape")
        collected.setdefault(path, []).append(
            (mode.decode("ascii"), object_id.decode("ascii"), stage)
        )
    return {path: tuple(sorted(values)) for path, values in collected.items()}


def _status_entries(repo: Path) -> dict[str, str]:
    result = _run_git(
        repo,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=no"],
        text=False,
    )
    records = result.stdout.split(b"\0")
    entries: dict[str, str] = {}
    index = 0
    while index < len(records):
        record = records[index]
        index += 1
        if not record:
            continue
        if len(record) < 4 or record[2:3] != b" ":
            raise ScopeViolation("git status returned an unrecognized porcelain-v1 record")
        code = record[:2].decode("ascii")
        if not _valid_status_code(code):
            raise ScopeViolation(f"git status returned an invalid porcelain-v1 code: {code!r}")
        path = record[3:].decode("utf-8", "surrogateescape").rstrip("/")
        if path in entries:
            raise ScopeViolation(f"git status returned a duplicate path: {path}")
        entries[path] = code
        if "R" in code or "C" in code:
            if index >= len(records) or not records[index]:
                raise ScopeViolation("git status returned a truncated rename/copy record")
            source = records[index].decode("utf-8", "surrogateescape").rstrip("/")
            if source in entries:
                raise ScopeViolation(f"git status returned a duplicate path: {source}")
            entries[source] = f"{code}:source"
            index += 1
    return entries


def _valid_status_code(code: str) -> bool:
    if code == "??" or code in _CONFLICT_STAGES:
        return True
    if len(code) != 2 or code == "  ":
        return False
    index_state, worktree_state = code
    if index_state == " ":
        return worktree_state in {"M", "T", "D"}
    if index_state == "D":
        return worktree_state == " "
    return index_state in {"M", "T", "A", "R", "C"} and (
        worktree_state in _ORDINARY_WORKTREE_STATES
    )


def _collect_git_evidence(repo: Path) -> _GitEvidence:
    head = _run_git(repo, ["rev-parse", "HEAD"]).stdout.strip()
    return _GitEvidence(
        head=head,
        index_entries=_index_entries(repo),
        status_entries=_status_entries(repo),
    )


def _scope_files(
    repo: Path,
    selectors: tuple[str, ...],
    evidence: _GitEvidence,
) -> dict[str, FileFingerprint]:
    entries: dict[str, FileFingerprint] = {}
    for selector in selectors:
        prefix = _literal_prefix(selector)
        prefix_fingerprint = _secure_fingerprint(repo, prefix)
        if _selected(prefix, selectors):
            entries[prefix] = prefix_fingerprint
        if prefix_fingerprint.kind != "directory":
            continue
        directory_fd = _open_scoped_directory(repo, prefix)
        try:
            _walk_scoped_directory(
                directory_fd,
                prefix,
                selectors,
                entries,
                repository_root=prefix == ".",
            )
        finally:
            os.close(directory_fd)

    candidates = set(evidence.index_entries).union(evidence.status_entries)
    for path in sorted(path for path in candidates if _selected(path, selectors)):
        if path not in entries:
            entries[path] = _secure_fingerprint(repo, path)
    for path in sorted(evidence.status_entries):
        if path not in entries:
            entries[path] = _secure_fingerprint(repo, path)
    return entries


@dataclass(frozen=True)
class WorkspaceSnapshot:
    repo: Path
    scope: tuple[str, ...]
    acknowledged_dirty: tuple[str, ...]
    head: str
    files: dict[str, FileFingerprint]
    index_entries: dict[str, tuple[tuple[str, str, int], ...]]
    status_entries: dict[str, str]
    dirty_paths: tuple[str, ...]
    in_scope_dirty: tuple[str, ...]
    unacknowledged_dirty: tuple[str, ...]
    status: str
    warnings: list[str]
    stable: bool = True

    @classmethod
    def capture(
        cls,
        repo: os.PathLike[str] | str,
        *,
        scope: list[str],
        acknowledged_dirty: list[str] | None = None,
    ) -> "WorkspaceSnapshot":
        canonical_repo = _canonical_repo(repo)
        if not isinstance(scope, list) or not scope:
            raise ScopeViolation("scope must be a non-empty array")
        selectors = tuple(_canonical_selector(item) for item in scope)
        if len(set(selectors)) != len(selectors):
            raise ScopeViolation("scope must not contain duplicate entries")
        acknowledgments = tuple(
            _canonical_selector(item) for item in (acknowledged_dirty or [])
        )
        if len(set(acknowledgments)) != len(acknowledgments):
            raise ScopeViolation("acknowledged_dirty must not contain duplicate entries")
        last_evidence: _GitEvidence | None = None
        last_files: dict[str, FileFingerprint] = {}
        last_error: str | None = None
        for _attempt in range(_MAX_CONSISTENCY_ATTEMPTS):
            try:
                before = _collect_git_evidence(canonical_repo)
                first_files = _scope_files(canonical_repo, selectors, before)
                middle = _collect_git_evidence(canonical_repo)
                second_files = _scope_files(canonical_repo, selectors, middle)
                after = _collect_git_evidence(canonical_repo)
            except ScopeViolation as exc:
                last_error = str(exc)
                continue
            last_evidence = after
            last_files = second_files
            if before == middle == after and first_files == second_files:
                return cls._from_capture(
                    canonical_repo,
                    selectors,
                    acknowledgments,
                    after,
                    second_files,
                    stable=True,
                    extra_warning=None,
                )
            last_error = "Git or filesystem evidence changed during capture"
        evidence = last_evidence or _GitEvidence(head="", index_entries={}, status_entries={})
        return cls._from_capture(
            canonical_repo,
            selectors,
            acknowledgments,
            evidence,
            last_files,
            stable=False,
            extra_warning=f"unstable workspace evidence: {last_error or 'capture failed'}",
        )

    @classmethod
    def _from_capture(
        cls,
        repo: Path,
        selectors: tuple[str, ...],
        acknowledgments: tuple[str, ...],
        evidence: _GitEvidence,
        files: dict[str, FileFingerprint],
        *,
        stable: bool,
        extra_warning: str | None,
    ) -> "WorkspaceSnapshot":
        dirty = set(evidence.status_entries)
        in_scope = sorted(path for path in dirty if _selected(path, selectors))
        unacknowledged = sorted(
            path for path in in_scope if not _selected(path, acknowledgments)
        )
        out_of_scope = sorted(path for path in dirty if not _selected(path, selectors))
        warnings = [f"out-of-scope dirty path: {path}" for path in out_of_scope]
        if extra_warning:
            warnings.append(extra_warning)
        status = "UNKNOWN" if in_scope or not stable else "FRESH"
        return cls(
            repo=repo,
            scope=selectors,
            acknowledged_dirty=acknowledgments,
            head=evidence.head,
            files=files,
            index_entries=evidence.index_entries,
            status_entries=evidence.status_entries,
            dirty_paths=tuple(sorted(dirty)),
            in_scope_dirty=tuple(in_scope),
            unacknowledged_dirty=tuple(unacknowledged),
            status=status,
            warnings=warnings,
            stable=stable,
        )

    def to_manifest(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "repo": str(self.repo),
            "scope": list(self.scope),
            "acknowledged_dirty": list(self.acknowledged_dirty),
            "head": self.head,
            "files": [
                {"path": path, "fingerprint": fingerprint.to_manifest()}
                for path, fingerprint in sorted(self.files.items())
            ],
            "index_entries": [
                {"path": path, "entries": [list(entry) for entry in entries]}
                for path, entries in sorted(self.index_entries.items())
            ],
            "status_entries": [
                {"path": path, "code": code}
                for path, code in sorted(self.status_entries.items())
            ],
            "dirty_paths": list(self.dirty_paths),
            "in_scope_dirty": list(self.in_scope_dirty),
            "unacknowledged_dirty": list(self.unacknowledged_dirty),
            "status": self.status,
            "warnings": list(self.warnings),
            "stable": self.stable,
        }

    @classmethod
    def from_manifest(cls, value: Mapping[str, Any]) -> "WorkspaceSnapshot":
        required_fields = {
            "schema_version",
            "repo",
            "scope",
            "acknowledged_dirty",
            "head",
            "files",
            "index_entries",
            "status_entries",
            "dirty_paths",
            "in_scope_dirty",
            "unacknowledged_dirty",
            "status",
            "warnings",
            "stable",
        }
        if type(value) is not dict or set(value) != required_fields:
            raise ScopeViolation("unsupported workspace snapshot manifest")
        if type(value["schema_version"]) is not int or value["schema_version"] != 2:
            raise ScopeViolation("unsupported workspace snapshot manifest schema")
        if type(value["stable"]) is not bool:
            raise ScopeViolation("workspace snapshot stable must be a boolean")
        stable = value["stable"]

        if type(value["repo"]) is not str or not Path(value["repo"]).is_absolute():
            raise ScopeViolation("workspace snapshot repo must be an absolute canonical path")
        repo = _canonical_repo(value["repo"])
        if str(repo) != value["repo"]:
            raise ScopeViolation("workspace snapshot repo path is not canonical")

        def canonical_selectors(raw: Any, label: str, *, nonempty: bool) -> tuple[str, ...]:
            if type(raw) is not list or (nonempty and not raw):
                raise ScopeViolation(f"workspace snapshot {label} must be an array")
            parsed: list[str] = []
            for item in raw:
                if type(item) is not str:
                    raise ScopeViolation(f"workspace snapshot {label} entries must be strings")
                canonical = _canonical_selector(item)
                if canonical != item:
                    raise ScopeViolation(f"workspace snapshot {label} entry is not canonical: {item!r}")
                parsed.append(canonical)
            if len(set(parsed)) != len(parsed):
                raise ScopeViolation(f"workspace snapshot {label} contains duplicates")
            return tuple(parsed)

        def canonical_path(raw: Any, label: str, *, allow_dot: bool = False) -> str:
            if type(raw) is not str or not raw or "\x00" in raw:
                raise ScopeViolation(f"workspace snapshot {label} must be a non-empty path")
            path = PurePosixPath(raw)
            if path.is_absolute() or any(part == ".." for part in path.parts):
                raise ScopeViolation(f"workspace snapshot {label} must be repository-relative")
            if any(part.casefold() == ".git" for part in path.parts):
                raise ScopeViolation(f"workspace snapshot {label} selects Git administrative data")
            canonical = path.as_posix().rstrip("/") or "."
            if raw != canonical or (canonical == "." and not allow_dot):
                raise ScopeViolation(f"workspace snapshot {label} path is not canonical: {raw!r}")
            return canonical

        scope = canonical_selectors(value["scope"], "scope", nonempty=True)
        acknowledgments = canonical_selectors(
            value["acknowledged_dirty"],
            "acknowledged_dirty",
            nonempty=False,
        )

        if type(value["head"]) is not str:
            raise ScopeViolation("workspace snapshot head must be a string")
        head = value["head"]
        if stable and not _HEX_OBJECT_ID.fullmatch(head):
            raise ScopeViolation("stable workspace snapshot head must be a Git object ID")
        if not stable and head and not _HEX_OBJECT_ID.fullmatch(head):
            raise ScopeViolation("workspace snapshot head must be empty or a Git object ID")

        if type(value["files"]) is not list:
            raise ScopeViolation("workspace snapshot files must be an array")
        files: dict[str, FileFingerprint] = {}
        for item in value["files"]:
            if type(item) is not dict or set(item) != {"path", "fingerprint"}:
                raise ScopeViolation("workspace snapshot file record is malformed")
            path = canonical_path(item["path"], "file", allow_dot=True)
            if path in files:
                raise ScopeViolation(f"duplicate workspace snapshot file path: {path}")
            files[path] = FileFingerprint.from_manifest(item["fingerprint"])

        if type(value["index_entries"]) is not list:
            raise ScopeViolation("workspace snapshot index_entries must be an array")
        index_entries: dict[str, tuple[tuple[str, str, int], ...]] = {}
        for item in value["index_entries"]:
            if type(item) is not dict or set(item) != {"path", "entries"}:
                raise ScopeViolation("workspace snapshot index record is malformed")
            path = canonical_path(item["path"], "index path")
            if path in index_entries:
                raise ScopeViolation(f"duplicate workspace snapshot index path: {path}")
            if type(item["entries"]) is not list or not item["entries"]:
                raise ScopeViolation(f"workspace snapshot index entries are empty: {path}")
            parsed_entries: list[tuple[str, str, int]] = []
            for entry in item["entries"]:
                if type(entry) is not list or len(entry) != 3:
                    raise ScopeViolation(f"workspace snapshot index tuple is malformed: {path}")
                mode, object_id, stage = entry
                if type(mode) is not str or mode not in _GIT_INDEX_MODES:
                    raise ScopeViolation(f"workspace snapshot index mode is invalid: {path}")
                if type(object_id) is not str or not _HEX_OBJECT_ID.fullmatch(object_id):
                    raise ScopeViolation(f"workspace snapshot index object ID is invalid: {path}")
                if type(stage) is not int or stage not in {0, 1, 2, 3}:
                    raise ScopeViolation(f"workspace snapshot index stage is invalid: {path}")
                parsed_entries.append((mode, object_id, stage))
            if len(set(parsed_entries)) != len(parsed_entries):
                raise ScopeViolation(f"workspace snapshot index entries contain duplicates: {path}")
            index_entries[path] = tuple(sorted(parsed_entries))

        if type(value["status_entries"]) is not list:
            raise ScopeViolation("workspace snapshot status_entries must be an array")
        status_entries: dict[str, str] = {}
        for item in value["status_entries"]:
            if type(item) is not dict or set(item) != {"path", "code"}:
                raise ScopeViolation("workspace snapshot status record is malformed")
            path = canonical_path(item["path"], "status path")
            if path in status_entries:
                raise ScopeViolation(f"duplicate workspace snapshot status path: {path}")
            code = item["code"]
            if type(code) is not str:
                raise ScopeViolation(f"workspace snapshot status code is invalid: {path}")
            source = code.endswith(":source")
            base_code = code[:-7] if source else code
            if not _valid_status_code(base_code) or (
                source and not ({"R", "C"} & set(base_code))
            ):
                raise ScopeViolation(f"workspace snapshot status code is invalid: {path}")
            status_entries[path] = code

        rename_destinations = Counter(
            code
            for code in status_entries.values()
            if not code.endswith(":source") and ({"R", "C"} & set(code))
        )
        rename_sources = Counter(
            code[:-7]
            for code in status_entries.values()
            if code.endswith(":source")
        )
        if rename_destinations != rename_sources:
            raise ScopeViolation(
                "workspace snapshot rename/copy source evidence is inconsistent"
            )

        for path, entries in index_entries.items():
            stages = {stage for _mode, _object_id, stage in entries}
            if len(stages) != len(entries):
                raise ScopeViolation(
                    f"workspace snapshot index has duplicate stages: {path}"
                )
            if stages == {0}:
                continue
            if 0 in stages:
                raise ScopeViolation(
                    f"workspace snapshot index mixes stage zero and conflicts: {path}"
                )
            status_code = status_entries.get(path)
            if status_code not in _CONFLICT_STAGES:
                raise ScopeViolation(
                    f"workspace snapshot unmerged index lacks conflict status: {path}"
                )
            if stages != _CONFLICT_STAGES[status_code]:
                raise ScopeViolation(
                    f"workspace snapshot conflict stages are inconsistent: {path}"
                )
        for path, code in status_entries.items():
            if code in _CONFLICT_STAGES:
                entries = index_entries.get(path, ())
                stages = {stage for _mode, _object_id, stage in entries}
                if stages != _CONFLICT_STAGES[code]:
                    raise ScopeViolation(
                        f"workspace snapshot conflict status lacks matching stages: {path}"
                    )
                continue

            source = code.endswith(":source")
            base_code = code[:-7] if source else code
            stages = {
                stage for _mode, _object_id, stage in index_entries.get(path, ())
            }
            if base_code == "??":
                if stages:
                    raise ScopeViolation(
                        f"workspace snapshot untracked path exists in the index: {path}"
                    )
                continue

            index_state = base_code[0]
            if source:
                expected_stage_zero = index_state == "C"
            else:
                expected_stage_zero = index_state != "D"
            if expected_stage_zero and stages != {0}:
                raise ScopeViolation(
                    f"workspace snapshot status requires a stage-zero index entry: {path}"
                )
            if not expected_stage_zero and stages:
                raise ScopeViolation(
                    f"workspace snapshot status forbids an index entry: {path}"
                )

        dirty = tuple(sorted(status_entries))
        in_scope = tuple(sorted(path for path in dirty if _selected(path, scope)))
        unacknowledged = tuple(
            sorted(path for path in in_scope if not _selected(path, acknowledgments))
        )
        out_of_scope = tuple(path for path in dirty if not _selected(path, scope))
        if not set(dirty).issubset(files):
            raise ScopeViolation("workspace snapshot lacks exact fingerprints for dirty paths")
        if any(not (_selected(path, scope) or path in status_entries) for path in files):
            raise ScopeViolation("workspace snapshot contains an unscoped clean file fingerprint")

        def exact_string_list(raw: Any, label: str) -> list[str]:
            if type(raw) is not list or any(type(item) is not str for item in raw):
                raise ScopeViolation(f"workspace snapshot {label} must be a string array")
            return raw

        if exact_string_list(value["dirty_paths"], "dirty_paths") != list(dirty):
            raise ScopeViolation("workspace snapshot dirty_paths do not match status evidence")
        if exact_string_list(value["in_scope_dirty"], "in_scope_dirty") != list(in_scope):
            raise ScopeViolation("workspace snapshot in_scope_dirty is inconsistent")
        if exact_string_list(
            value["unacknowledged_dirty"], "unacknowledged_dirty"
        ) != list(unacknowledged):
            raise ScopeViolation("workspace snapshot unacknowledged_dirty is inconsistent")

        expected_status = "UNKNOWN" if in_scope or not stable else "FRESH"
        if type(value["status"]) is not str or value["status"] != expected_status:
            raise ScopeViolation("workspace snapshot status is inconsistent")
        warnings = exact_string_list(value["warnings"], "warnings")
        expected_warnings = [f"out-of-scope dirty path: {path}" for path in out_of_scope]
        if stable:
            if warnings != expected_warnings:
                raise ScopeViolation("stable workspace snapshot warnings are inconsistent")
        elif (
            len(warnings) != len(expected_warnings) + 1
            or warnings[: len(expected_warnings)] != expected_warnings
            or not warnings[-1].startswith("unstable workspace evidence: ")
        ):
            raise ScopeViolation("unstable workspace snapshot warnings are inconsistent")

        return cls(
            repo=repo,
            scope=scope,
            acknowledged_dirty=acknowledgments,
            head=head,
            files=files,
            index_entries=index_entries,
            status_entries=status_entries,
            dirty_paths=dirty,
            in_scope_dirty=in_scope,
            unacknowledged_dirty=unacknowledged,
            status=expected_status,
            warnings=list(warnings),
            stable=stable,
        )

    def compare_to(self, baseline: "WorkspaceSnapshot") -> WorkspaceComparison:
        if not isinstance(baseline, WorkspaceSnapshot):
            raise ScopeViolation("baseline must be a WorkspaceSnapshot")
        if self.repo != baseline.repo:
            raise ScopeViolation("cannot compare snapshots from different repositories")
        if self.scope != baseline.scope:
            raise ScopeViolation("cannot compare snapshots with different scope declarations")
        warnings = tuple(sorted(set(baseline.warnings + self.warnings)))
        if not self.stable or not baseline.stable:
            return WorkspaceComparison(
                status="UNKNOWN",
                aggregate="UNKNOWN",
                changed_paths=(),
                warnings=warnings,
            )

        file_paths = set(self.files).union(baseline.files)
        file_changes = {
            path for path in file_paths if self.files.get(path) != baseline.files.get(path)
        }
        index_paths = set(self.index_entries).union(baseline.index_entries)
        index_changes = {
            path
            for path in index_paths
            if self.index_entries.get(path) != baseline.index_entries.get(path)
        }
        status_paths = set(self.status_entries).union(baseline.status_entries)
        status_changes = {
            path
            for path in status_paths
            if self.status_entries.get(path) != baseline.status_entries.get(path)
        }
        evidence_changes = file_changes.union(index_changes, status_changes)
        out_of_scope = sorted(path for path in evidence_changes if not _selected(path, self.scope))
        if out_of_scope:
            raise ScopeViolation(
                "new out-of-scope workspace change: " + ", ".join(out_of_scope)
            )
        in_scope_changed = sorted(path for path in evidence_changes if _selected(path, self.scope))
        if self.head != baseline.head:
            in_scope_changed.append("<git-head>")
        if in_scope_changed:
            status = "STALE"
        elif self.status == "UNKNOWN" or baseline.status == "UNKNOWN":
            status = "UNKNOWN"
        else:
            status = "FRESH"
        return WorkspaceComparison(
            status=status,
            aggregate="SUPPORTED" if status == "FRESH" else status,
            changed_paths=tuple(in_scope_changed),
            warnings=warnings,
        )
