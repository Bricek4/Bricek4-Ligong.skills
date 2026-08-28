"""Checksummed, revisioned, atomic TaskGuard state storage."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
from typing import Any, Iterator, Mapping


class StateError(RuntimeError):
    """Raised when durable state is missing, malformed, or unsafe."""


class ChecksumError(StateError):
    """Raised when persisted state does not match its checksum."""


class ConcurrentUpdateError(StateError):
    """Raised for owner or optimistic-revision conflicts."""


class InterruptedWrite(StateError):
    """Deterministic test fault at a documented atomic-write boundary."""


@dataclass(frozen=True)
class Recovery:
    verdict: str
    lifecycle: str
    revision: int
    next_action: str


@dataclass(frozen=True)
class _LockToken:
    root_fd: int
    descriptor: int
    name: str
    path: Path


@dataclass(frozen=True)
class ExecutionLease:
    """An acquired lease bound to both the state root and lease-file inode."""

    descriptor: int
    root_descriptor: int
    device: int
    inode: int
    root_device: int
    root_inode: int
    root_exclusive: bool

    def to_manifest(self) -> dict[str, Any]:
        return {
            "version": "taskguard-execution-lease-v1",
            "device": self.device,
            "inode": self.inode,
            "root_device": self.root_device,
            "root_inode": self.root_inode,
        }

    def require_manifest(self, value: Any) -> None:
        expected = self.to_manifest()
        if (
            type(value) is not dict
            or set(value) != set(expected)
            or type(value.get("version")) is not str
            or any(
                type(value.get(key)) is not int or value.get(key) < 0
                for key in ("device", "inode", "root_device", "root_inode")
            )
            or value != expected
        ):
            raise StateError(
                "persisted execution lease does not match the acquired root and inode generation"
            )


_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_LIFECYCLES = {
    "NEW",
    "INITIALIZED",
    "RUNNING",
    "RETRY_WAIT",
    "VERIFYING",
    "TERMINAL_ERROR",
    "TERMINAL",
}
_VERDICTS = {"SUPPORTED", "FAILED", "STALE", "UNKNOWN", "NOT_REQUIRED"}
_PROTECTED_CREATE_FIELDS = {"schema_version", "operation_id", "owner", "revision", "checksum"}
_PROTECTED_UPDATE_FIELDS = _PROTECTED_CREATE_FIELDS | {"admission_anchor"}
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_MAX_STATE_BYTES = 8 * 1024 * 1024
_MAX_STATE_DEPTH = 64
_MAX_STATE_NODES = 100_000
_UNSUPPORTED_DIRECTORY_FSYNC = {
    value
    for value in (
        errno.EINVAL,
        getattr(errno, "ENOTSUP", None),
        getattr(errno, "EOPNOTSUPP", None),
    )
    if value is not None
}


def _normalized_root_path(root: os.PathLike[str] | str) -> Path:
    """Return an absolute lexical root with only trusted system aliases expanded."""

    absolute = Path(os.path.abspath(os.fspath(root)))
    # macOS exposes standard temporary paths through root-owned aliases such as
    # /var -> /private/var. Canonicalize only that immutable bootstrap component;
    # every remaining component is opened and revalidated with O_NOFOLLOW.
    for _attempt in range(8):
        parts = absolute.parts
        if len(parts) < 2:
            break
        prefix = Path(parts[0]) / parts[1]
        try:
            metadata = prefix.lstat()
            parent_metadata = prefix.parent.stat()
        except OSError:
            break
        trusted_alias = (
            stat.S_ISLNK(metadata.st_mode)
            and metadata.st_uid == 0
            and parent_metadata.st_uid == 0
            and not (stat.S_IMODE(parent_metadata.st_mode) & 0o022)
        )
        if not trusted_alias:
            break
        try:
            target = os.readlink(prefix)
        except OSError:
            break
        resolved_prefix = Path(
            os.path.abspath(os.path.join(os.fspath(prefix.parent), target))
        )
        absolute = resolved_prefix.joinpath(*parts[2:])
    return absolute


def _operation_id(value: Any) -> str:
    if not isinstance(value, str) or not _OPERATION_ID.fullmatch(value):
        raise StateError(
            "operation_id must match [A-Za-z0-9][A-Za-z0-9._-]{0,127}"
        )
    if value in {".", ".."}:
        raise StateError("operation_id must not be a path traversal token")
    return value


def _owner(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise StateError("owner must be a non-empty string without NUL")
    return value


def _canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    unsigned = dict(payload)
    unsigned.pop("checksum", None)
    _validate_json_resources(unsigned)
    try:
        encoded = json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise StateError(f"state is not canonical-JSON serializable: {exc}") from exc
    data = encoded.encode("ascii")
    if len(data) > _MAX_STATE_BYTES:
        raise StateError(
            f"state exceeds maximum canonical size of {_MAX_STATE_BYTES} bytes"
        )
    return data


def _checksum(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_bytes(payload)).hexdigest()


def _validate_json_resources(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 1)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_STATE_NODES:
            raise StateError(
                f"state exceeds maximum JSON node count of {_MAX_STATE_NODES}"
            )
        if depth > _MAX_STATE_DEPTH:
            raise StateError(
                f"state exceeds maximum JSON depth of {_MAX_STATE_DEPTH}"
            )
        if type(current) is dict:
            if any(type(key) is not str for key in current):
                raise StateError("state JSON object keys must be strings")
            stack.extend((child, depth + 1) for child in current.values())
        elif type(current) is list:
            stack.extend((child, depth + 1) for child in current)
        elif current is None or type(current) in {str, int, float, bool}:
            continue
        else:
            raise StateError(
                f"state contains unsupported JSON value type: {type(current).__name__}"
            )


class StateStore:
    """Store one checksummed JSON manifest per validated operation ID."""

    def __init__(self, root: os.PathLike[str] | str):
        self.root = _normalized_root_path(root)
        self._active_execution_lease: ExecutionLease | None = None

    def _verify_root_metadata(self, metadata: os.stat_result) -> None:
        if not stat.S_ISDIR(metadata.st_mode):
            raise StateError(f"state root must be a non-symlink directory: {self.root}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise StateError(f"state root must be owned by the current user: {self.root}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise StateError(f"state root must be private (mode 0700 or stricter): {self.root}")

    def _open_root_chain(self, *, create: bool) -> int:
        try:
            current_fd = os.open(
                os.path.sep,
                os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
            )
        except OSError as exc:
            raise StateError(f"cannot open filesystem root for {self.root}: {exc}") from exc

        try:
            for component in self.root.parts[1:]:
                try:
                    child_fd = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                        dir_fd=current_fd,
                    )
                except FileNotFoundError:
                    if not create:
                        raise StateError(f"state root does not exist: {self.root}")
                    try:
                        os.mkdir(component, mode=0o700, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    except OSError as exc:
                        raise StateError(
                            f"cannot create state root component {component!r}: {exc}"
                        ) from exc
                    try:
                        child_fd = os.open(
                            component,
                            os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                            dir_fd=current_fd,
                        )
                    except OSError as exc:
                        raise StateError(
                            f"cannot open newly-created state root component "
                            f"{component!r} without following symlinks: {exc}"
                        ) from exc
                except OSError as exc:
                    raise StateError(
                        f"cannot open state root component {component!r} "
                        f"without following symlinks: {exc}"
                    ) from exc

                try:
                    descriptor_metadata = os.fstat(child_fd)
                    path_metadata = os.stat(
                        component,
                        dir_fd=current_fd,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(path_metadata.st_mode) or not stat.S_ISDIR(
                        path_metadata.st_mode
                    ):
                        raise StateError(
                            f"state root component must be a non-symlink directory: "
                            f"{component!r}"
                        )
                    if not stat.S_ISDIR(descriptor_metadata.st_mode) or (
                        descriptor_metadata.st_dev,
                        descriptor_metadata.st_ino,
                    ) != (path_metadata.st_dev, path_metadata.st_ino):
                        raise StateError(
                            f"state root component changed while opened: {component!r}"
                        )
                except BaseException:
                    os.close(child_fd)
                    raise
                os.close(current_fd)
                current_fd = child_fd

            self._verify_root_metadata(os.fstat(current_fd))
            return current_fd
        except BaseException:
            os.close(current_fd)
            raise

    def _verify_root_path(self, root_fd: int) -> None:
        try:
            descriptor_metadata = os.fstat(root_fd)
        except OSError as exc:
            raise StateError(f"cannot inspect open state root {self.root}: {exc}") from exc
        self._verify_root_metadata(descriptor_metadata)
        current_fd = self._open_root_chain(create=False)
        try:
            current_metadata = os.fstat(current_fd)
            if (descriptor_metadata.st_dev, descriptor_metadata.st_ino) != (
                current_metadata.st_dev,
                current_metadata.st_ino,
            ):
                raise StateError(f"state root changed while it was opened: {self.root}")
        finally:
            os.close(current_fd)

    def _open_root(self) -> int:
        descriptor = self._open_root_chain(create=True)
        try:
            self._verify_root_path(descriptor)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _state_path(self, operation_id: str) -> Path:
        return self.root / f"{_operation_id(operation_id)}.json"

    def _lock_path(self, operation_id: str) -> Path:
        return self.root / f".{_operation_id(operation_id)}.lock"

    def _state_name(self, operation_id: str) -> str:
        return f"{_operation_id(operation_id)}.json"

    def _lock_name(self, operation_id: str) -> str:
        return f".{_operation_id(operation_id)}.lock"

    def _execution_lease_name(self, operation_id: str) -> str:
        return f".{_operation_id(operation_id)}.execution.lock"

    def _verify_regular_metadata(self, metadata: os.stat_result, *, label: str, path: Path) -> None:
        if not stat.S_ISREG(metadata.st_mode):
            raise StateError(f"{label} must be a regular file: {path}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise StateError(f"{label} must be owned by the current user: {path}")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise StateError(f"{label} must not be group/world writable: {path}")

    def _verify_name_identity(
        self,
        root_fd: int,
        name: str,
        expected: tuple[int, int],
        *,
        label: str,
        path: Path,
    ) -> os.stat_result:
        try:
            path_metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except OSError as exc:
            raise StateError(f"cannot inspect {label} path {path}: {exc}") from exc
        if stat.S_ISLNK(path_metadata.st_mode):
            raise StateError(f"{label} must not be a symlink: {path}")
        self._verify_regular_metadata(path_metadata, label=label, path=path)
        if expected != (path_metadata.st_dev, path_metadata.st_ino):
            raise StateError(f"{label} changed while it was opened: {path}")
        return path_metadata

    def _verify_name_matches_fd(
        self,
        root_fd: int,
        name: str,
        descriptor: int,
        *,
        label: str,
        path: Path,
    ) -> os.stat_result:
        try:
            metadata = os.fstat(descriptor)
        except OSError as exc:
            raise StateError(f"cannot inspect open {label} {path}: {exc}") from exc
        self._verify_regular_metadata(metadata, label=label, path=path)
        self._verify_name_identity(
            root_fd,
            name,
            (metadata.st_dev, metadata.st_ino),
            label=label,
            path=path,
        )
        return metadata

    def _open_regular(
        self,
        root_fd: int,
        name: str,
        flags: int,
        *,
        create_mode: int | None = None,
        label: str,
    ) -> int:
        path = self.root / name
        open_flags = flags | _NOFOLLOW | _CLOEXEC
        try:
            if create_mode is None:
                descriptor = os.open(name, open_flags, dir_fd=root_fd)
            else:
                descriptor = os.open(name, open_flags, create_mode, dir_fd=root_fd)
        except OSError as exc:
            raise StateError(f"cannot open {label} {path} without following symlinks: {exc}") from exc
        try:
            self._verify_name_matches_fd(
                root_fd,
                name,
                descriptor,
                label=label,
                path=path,
            )
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def _verify_operation_lock(self, token: _LockToken) -> None:
        self._verify_name_matches_fd(
            token.root_fd,
            token.name,
            token.descriptor,
            label="state lock",
            path=token.path,
        )

    def _verify_lock_token(self, token: _LockToken) -> None:
        # The root directory vnode is the non-replaceable lock generation.
        # The per-operation file is checked at acquisition as a tamper sentinel,
        # but replacing that pathname cannot split the authoritative root lock.
        self._verify_root_path(token.root_fd)

    @contextmanager
    def _lock(self, operation_id: str, *, exclusive: bool) -> Iterator[_LockToken]:
        active_lease = self._active_execution_lease
        borrowed_root = active_lease is not None
        root_fd = (
            active_lease.root_descriptor
            if active_lease is not None
            else self._open_root()
        )
        if borrowed_root:
            self._verify_root_path(root_fd)
        lock_name = self._lock_name(operation_id)
        lock_path = self._lock_path(operation_id)
        try:
            descriptor = self._open_regular(
                root_fd,
                lock_name,
                os.O_RDWR | os.O_CREAT,
                create_mode=0o600,
                label="state lock",
            )
        except BaseException:
            if not borrowed_root:
                os.close(root_fd)
            raise
        operation_locked = False
        root_locked = False
        try:
            try:
                mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
                fcntl.flock(descriptor, mode)
                operation_locked = True
                root_mode = (
                    fcntl.LOCK_EX
                    if active_lease is not None
                    and (active_lease.root_exclusive or exclusive)
                    else mode
                )
                fcntl.flock(root_fd, root_mode)
            except OSError as exc:
                raise StateError(
                    f"cannot acquire verified state lock generation: {exc}"
                ) from exc
            root_locked = True
            token = _LockToken(
                root_fd=root_fd,
                descriptor=descriptor,
                name=lock_name,
                path=lock_path,
            )
            self._verify_operation_lock(token)
            self._verify_lock_token(token)
            yield token
            self._verify_lock_token(token)
        finally:
            try:
                if root_locked:
                    if active_lease is None:
                        fcntl.flock(root_fd, fcntl.LOCK_UN)
                    else:
                        restore_mode = (
                            fcntl.LOCK_EX
                            if active_lease.root_exclusive
                            else fcntl.LOCK_SH
                        )
                        fcntl.flock(root_fd, restore_mode)
            finally:
                try:
                    if operation_locked:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    try:
                        os.close(descriptor)
                    finally:
                        if not borrowed_root:
                            os.close(root_fd)

    @contextmanager
    def execution_lease(
        self,
        operation_id: str,
        *,
        blocking: bool,
    ) -> Iterator[ExecutionLease]:
        """Hold a process-lifetime lease distinct from short state-write locks.

        Executors hold a shared lock on the verified state-root inode and
        disposition/audit requires an exclusive nonblocking root lock.  The
        root inode is therefore the authoritative, non-splittable generation;
        replacing the per-operation pathname cannot make a live executor
        disappear.  Short state writes borrow and temporarily upgrade this
        same open-root description, then restore the execution lock.
        """

        operation_id = _operation_id(operation_id)
        if type(blocking) is not bool:
            raise StateError("execution lease blocking flag must be a boolean")
        if self._active_execution_lease is not None:
            raise StateError("execution leases cannot be nested on one state store")
        root_fd = self._open_root()
        name = self._execution_lease_name(operation_id)
        path = self.root / name
        try:
            descriptor = self._open_regular(
                root_fd,
                name,
                os.O_RDWR | os.O_CREAT,
                create_mode=0o600,
                label="execution lease",
            )
        except BaseException:
            os.close(root_fd)
            raise
        acquired = False
        root_locked = False
        try:
            flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
            try:
                fcntl.flock(descriptor, flags)
            except BlockingIOError as exc:
                raise ConcurrentUpdateError(
                    f"active executor holds operation lease: {operation_id}"
                ) from exc
            except OSError as exc:
                if not blocking and exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise ConcurrentUpdateError(
                        f"active executor holds operation lease: {operation_id}"
                    ) from exc
                raise StateError(
                    f"cannot acquire execution lease {path}: {exc}"
                ) from exc
            acquired = True
            try:
                root_flags = (
                    fcntl.LOCK_SH if blocking else fcntl.LOCK_EX | fcntl.LOCK_NB
                )
                fcntl.flock(root_fd, root_flags)
            except BlockingIOError as exc:
                raise ConcurrentUpdateError(
                    "active executor holds the state-root execution generation"
                ) from exc
            except OSError as exc:
                if not blocking and exc.errno in {errno.EACCES, errno.EAGAIN}:
                    raise ConcurrentUpdateError(
                        "active executor holds the state-root execution generation"
                    ) from exc
                raise StateError(
                    f"cannot acquire state-root execution generation: {exc}"
                ) from exc
            root_locked = True
            metadata = self._verify_name_matches_fd(
                root_fd,
                name,
                descriptor,
                label="execution lease",
                path=path,
            )
            if metadata.st_nlink != 1:
                raise StateError(f"execution lease inode must have exactly one link: {path}")
            self._verify_root_path(root_fd)
            root_metadata = os.fstat(root_fd)
            lease = ExecutionLease(
                descriptor=descriptor,
                root_descriptor=root_fd,
                device=metadata.st_dev,
                inode=metadata.st_ino,
                root_device=root_metadata.st_dev,
                root_inode=root_metadata.st_ino,
                root_exclusive=not blocking,
            )
            # The descriptor may be explicitly inherited by the bounded child
            # process together with the root descriptor.  If the controller is
            # killed, both open-file-description locks remain held until that
            # active command also exits.
            self._active_execution_lease = lease
            try:
                try:
                    yield lease
                finally:
                    final_metadata = self._verify_name_matches_fd(
                        root_fd,
                        name,
                        descriptor,
                        label="execution lease",
                        path=path,
                    )
                    if final_metadata.st_nlink != 1:
                        raise StateError(
                            f"execution lease inode must have exactly one link: {path}"
                        )
                    self._verify_root_path(root_fd)
            finally:
                self._active_execution_lease = None
        finally:
            try:
                if root_locked:
                    fcntl.flock(root_fd, fcntl.LOCK_UN)
            finally:
                try:
                    if acquired:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    try:
                        os.close(descriptor)
                    finally:
                        os.close(root_fd)

    def _load_unlocked(self, operation_id: str, root_fd: int) -> dict[str, Any]:
        name = self._state_name(operation_id)
        path = self._state_path(operation_id)
        try:
            descriptor = self._open_regular(
                root_fd,
                name,
                os.O_RDONLY,
                label="state manifest",
            )
            try:
                chunks: list[bytes] = []
                while True:
                    remaining = _MAX_STATE_BYTES + 1 - sum(map(len, chunks))
                    chunk = os.read(descriptor, min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    if sum(map(len, chunks)) > _MAX_STATE_BYTES:
                        raise StateError(
                            f"state manifest exceeds maximum size of {_MAX_STATE_BYTES} bytes: {path}"
                        )
                self._verify_name_matches_fd(
                    root_fd,
                    name,
                    descriptor,
                    label="state manifest",
                    path=path,
                )
                self._verify_root_path(root_fd)
                raw = b"".join(chunks).decode("ascii")
            finally:
                os.close(descriptor)
        except StateError:
            raise
        except (OSError, UnicodeError) as exc:
            raise StateError(f"cannot read state {path}: {exc}") from exc
        try:
            payload = json.loads(raw)
        except (ValueError, RecursionError) as exc:
            raise StateError(f"state is malformed JSON: {path}: {exc}") from exc
        _validate_json_resources(payload)
        if not isinstance(payload, dict):
            raise StateError(f"state manifest must be a JSON object: {path}")
        required = {"schema_version", "operation_id", "owner", "lifecycle", "verdict", "revision", "checksum"}
        missing = sorted(required.difference(payload))
        if missing:
            raise StateError(f"state manifest missing fields {missing}: {path}")
        persisted = payload.get("checksum")
        if not isinstance(persisted, str) or not re.fullmatch(r"[0-9a-f]{64}", persisted):
            raise ChecksumError("state checksum has an invalid shape")
        expected = _checksum(payload)
        if not hmac.compare_digest(persisted, expected):
            raise ChecksumError("state checksum does not match persisted content")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 2:
            raise StateError(f"unsupported state schema: {payload['schema_version']!r}")
        if type(payload["operation_id"]) is not str:
            raise StateError("state operation_id must be a string")
        persisted_operation_id = _operation_id(payload["operation_id"])
        if persisted_operation_id != operation_id:
            raise StateError("state operation_id does not match its filename")
        _owner(payload["owner"])
        if type(payload["lifecycle"]) is not str or payload["lifecycle"] not in _LIFECYCLES:
            raise StateError(f"unknown lifecycle: {payload['lifecycle']!r}")
        if type(payload["verdict"]) is not str or payload["verdict"] not in _VERDICTS:
            raise StateError(f"unknown verdict: {payload['verdict']!r}")
        if type(payload["revision"]) is not int or payload["revision"] < 1:
            raise StateError("state revision must be a positive integer")
        return payload

    def _fsync_directory(self, root_fd: int) -> None:
        try:
            os.fsync(root_fd)
        except OSError as exc:
            if exc.errno not in _UNSUPPORTED_DIRECTORY_FSYNC:
                raise StateError(f"cannot fsync state directory: {exc}") from exc
        self._verify_root_path(root_fd)

    def _create_temp(self, root_fd: int, operation_id: str) -> tuple[int, str, tuple[int, int]]:
        for _attempt in range(128):
            name = f".{operation_id}.{secrets.token_hex(12)}.tmp"
            try:
                descriptor = os.open(
                    name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC,
                    0o600,
                    dir_fd=root_fd,
                )
            except FileExistsError:
                continue
            except OSError as exc:
                raise StateError(f"cannot create temporary state file in {self.root}: {exc}") from exc
            path = self.root / name
            try:
                metadata = self._verify_name_matches_fd(
                    root_fd,
                    name,
                    descriptor,
                    label="temporary state manifest",
                    path=path,
                )
                return descriptor, name, (metadata.st_dev, metadata.st_ino)
            except BaseException:
                os.close(descriptor)
                raise
        raise StateError("cannot allocate a unique temporary state filename")

    def _name_exists(self, root_fd: int, name: str) -> bool:
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise StateError(f"cannot inspect state entry {self.root / name}: {exc}") from exc
        return True

    def _write_unlocked(
        self,
        operation_id: str,
        payload: Mapping[str, Any],
        *,
        lock_token: _LockToken,
        fault: str | None = None,
    ) -> dict[str, Any]:
        root_fd = lock_token.root_fd
        if fault not in {None, "after_temp_fsync", "after_replace"}:
            raise StateError(f"unknown fault hook: {fault!r}")
        destination_name = self._state_name(operation_id)
        destination = self._state_path(operation_id)
        complete = dict(payload)
        complete["checksum"] = _checksum(complete)
        try:
            data = json.dumps(
                complete,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("ascii")
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise StateError(f"state is not JSON serializable: {exc}") from exc
        if len(data) > _MAX_STATE_BYTES:
            raise StateError(
                f"state exceeds maximum serialized size of {_MAX_STATE_BYTES} bytes"
            )

        temp_name: str | None = None
        temp_identity: tuple[int, int] | None = None
        replaced = False
        try:
            descriptor, temp_name, temp_identity = self._create_temp(root_fd, operation_id)
            try:
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
            except BaseException:
                # os.fdopen owns the descriptor once constructed.
                raise
            if fault == "after_temp_fsync":
                raise InterruptedWrite("interrupted after temporary-file fsync")
            self._verify_name_identity(
                root_fd,
                temp_name,
                temp_identity,
                label="temporary state manifest",
                path=self.root / temp_name,
            )
            self._verify_lock_token(lock_token)
            try:
                os.replace(
                    temp_name,
                    destination_name,
                    src_dir_fd=root_fd,
                    dst_dir_fd=root_fd,
                )
            except TypeError as exc:
                raise StateError(
                    "platform cannot atomically replace state relative to a verified root dirfd"
                ) from exc
            replaced = True
            self._verify_name_identity(
                root_fd,
                destination_name,
                temp_identity,
                label="state manifest",
                path=destination,
            )
            self._fsync_directory(root_fd)
            self._verify_lock_token(lock_token)
            if fault == "after_replace":
                raise InterruptedWrite("interrupted after atomic replace")
            return complete
        except InterruptedWrite:
            raise
        except OSError as exc:
            raise StateError(f"cannot atomically write state {destination}: {exc}") from exc
        finally:
            if not replaced and temp_name is not None and temp_identity is not None:
                try:
                    metadata = os.stat(temp_name, dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    if temp_identity == (metadata.st_dev, metadata.st_ino):
                        os.unlink(temp_name, dir_fd=root_fd)

    def create(self, operation_id: str, *, owner: str, **fields: Any) -> dict[str, Any]:
        operation_id = _operation_id(operation_id)
        owner = _owner(owner)
        forbidden = _PROTECTED_CREATE_FIELDS.intersection(fields)
        if forbidden:
            raise StateError(f"cannot override protected create fields: {sorted(forbidden)}")
        if "lifecycle" in fields or "verdict" in fields:
            raise StateError("create lifecycle and verdict are fixed")
        with self._lock(operation_id, exclusive=True) as lock_token:
            root_fd = lock_token.root_fd
            if self._name_exists(root_fd, self._state_name(operation_id)):
                raise ConcurrentUpdateError(f"state already exists: {operation_id}")
            payload: dict[str, Any] = {
                "schema_version": 2,
                "operation_id": operation_id,
                "owner": owner,
                "lifecycle": "INITIALIZED",
                "verdict": "UNKNOWN",
                "revision": 1,
            }
            payload.update(fields)
            return self._write_unlocked(
                operation_id,
                payload,
                lock_token=lock_token,
            )

    def load(self, operation_id: str) -> dict[str, Any]:
        operation_id = _operation_id(operation_id)
        with self._lock(operation_id, exclusive=False) as lock_token:
            return self._load_unlocked(operation_id, lock_token.root_fd)

    def load_snapshot(self, operation_id: str) -> dict[str, Any]:
        """Read one atomic manifest snapshot without creating lock or state files."""

        operation_id = _operation_id(operation_id)
        root_fd = self._open_root_chain(create=False)
        try:
            self._verify_root_path(root_fd)
            return self._load_unlocked(operation_id, root_fd)
        finally:
            os.close(root_fd)

    def update(
        self,
        operation_id: str,
        *,
        expected_revision: int,
        expected_owner: str,
        fault: str | None = None,
        **changes: Any,
    ) -> dict[str, Any]:
        operation_id = _operation_id(operation_id)
        expected_owner = _owner(expected_owner)
        if type(expected_revision) is not int or expected_revision < 1:
            raise StateError("expected_revision must be a positive integer")
        protected = _PROTECTED_UPDATE_FIELDS.intersection(changes)
        if protected:
            raise StateError(f"cannot update protected fields: {sorted(protected)}")
        if "lifecycle" in changes and (
            type(changes["lifecycle"]) is not str or changes["lifecycle"] not in _LIFECYCLES
        ):
            raise StateError(f"unknown lifecycle: {changes['lifecycle']!r}")
        if "verdict" in changes and (
            type(changes["verdict"]) is not str or changes["verdict"] not in _VERDICTS
        ):
            raise StateError(f"unknown verdict: {changes['verdict']!r}")
        with self._lock(operation_id, exclusive=True) as lock_token:
            current = self._load_unlocked(operation_id, lock_token.root_fd)
            if current["owner"] != expected_owner:
                raise ConcurrentUpdateError(
                    f"owner conflict for {operation_id}: expected {expected_owner!r}, "
                    f"found {current['owner']!r}"
                )
            if current["revision"] != expected_revision:
                raise ConcurrentUpdateError(
                    f"revision conflict for {operation_id}: expected {expected_revision}, "
                    f"found {current['revision']}"
                )
            next_payload = dict(current)
            next_payload.pop("checksum", None)
            next_payload.update(changes)
            next_payload["revision"] = expected_revision + 1
            return self._write_unlocked(
                operation_id,
                next_payload,
                lock_token=lock_token,
                fault=fault,
            )

    def claim(self, operation_id: str, *, owner: str) -> dict[str, Any]:
        operation_id = _operation_id(operation_id)
        owner = _owner(owner)
        with self._lock(operation_id, exclusive=True) as lock_token:
            current = self._load_unlocked(operation_id, lock_token.root_fd)
            if current["owner"] != owner:
                raise ConcurrentUpdateError(
                    f"owner conflict for {operation_id}: state belongs to {current['owner']!r}"
                )
            return current

    def recover(self, operation_id: str) -> Recovery:
        current = self.load(operation_id)
        lifecycle = current["lifecycle"]
        if lifecycle == "TERMINAL" and current["verdict"] == "SUPPORTED":
            verdict, next_action = "SUPPORTED", "reuse"
        elif lifecycle == "TERMINAL_ERROR":
            verdict, next_action = current["verdict"], "inspect_or_dispose"
        elif lifecycle == "RUNNING":
            verdict, next_action = "UNKNOWN", "explicit_disposition_required"
        else:
            verdict, next_action = "UNKNOWN", "continue"
        return Recovery(
            verdict=verdict,
            lifecycle=lifecycle,
            revision=current["revision"],
            next_action=next_action,
        )

    def is_reusable(self, operation_id: str) -> bool:
        current = self.load(operation_id)
        return current["lifecycle"] == "TERMINAL" and current["verdict"] == "SUPPORTED"

    def disposition(
        self,
        operation_id: str,
        *,
        expected_revision: int,
        expected_owner: str,
        verdict: str,
    ) -> dict[str, Any]:
        if type(verdict) is not str or verdict not in {"FAILED", "STALE", "UNKNOWN"}:
            raise StateError("disposition verdict must be FAILED, STALE, or UNKNOWN")
        return self.update(
            operation_id,
            expected_revision=expected_revision,
            expected_owner=expected_owner,
            lifecycle="TERMINAL_ERROR",
            verdict=verdict,
        )
