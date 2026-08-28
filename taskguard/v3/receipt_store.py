"""Private, content-addressed, tamper-evident receipt storage."""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import secrets
import stat

from ..receipts.refs import ReceiptRef
from ..validation import canonical_json_bytes, loads_strict_json
from .receipts import Receipt, ReceiptError


class ReceiptIntegrityError(RuntimeError):
    pass


class ReceiptGraphError(ReceiptIntegrityError):
    pass


class ReceiptStore:
    def __init__(self, root: str | Path, *, max_blob_bytes: int = 1024 * 1024) -> None:
        self.root = Path(root)
        self.receipts = self.root / "receipts"
        self.max_blob_bytes = max_blob_bytes
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in (self.root,):
            metadata = directory.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise ReceiptIntegrityError(f"receipt path is not a real directory: {directory}")
            if stat.S_IMODE(metadata.st_mode) & 0o077:
                raise ReceiptIntegrityError(f"receipt directory must be private: {directory}")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ReceiptIntegrityError(f"receipt directory must be owned by the current user: {directory}")
        self.receipts.mkdir(mode=0o700, exist_ok=True)
        metadata = self.receipts.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ReceiptIntegrityError(f"receipt path is not a real directory: {self.receipts}")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ReceiptIntegrityError(f"receipt directory must be private: {self.receipts}")
        if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
            raise ReceiptIntegrityError(f"receipt directory must be owned by the current user: {self.receipts}")

    def _path(self, ref: ReceiptRef) -> Path:
        return self.receipts / f"{ref.digest}.json"

    @contextmanager
    def _write_lock(self):
        path = self.receipts / ".store.lock"
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            metadata = os.fstat(descriptor)
            current = os.stat(path, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) & 0o077
                or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino)
            ):
                raise ReceiptIntegrityError("receipt write lock is not a private single-link regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            current = os.stat(path, follow_symlinks=False)
            if stat.S_ISLNK(current.st_mode) or (metadata.st_dev, metadata.st_ino) != (current.st_dev, current.st_ino):
                raise ReceiptIntegrityError("receipt write lock changed while acquiring it")
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)

    def _read_blob(self, path: Path) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise ReceiptIntegrityError(f"cannot open receipt without following symlinks: {path}") from exc
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ReceiptIntegrityError("receipt blob must be a single-link regular file")
            if metadata.st_size > self.max_blob_bytes:
                raise ReceiptIntegrityError("receipt exceeds maximum blob size")
            chunks: list[bytes] = []
            remaining = metadata.st_size + 1
            while remaining:
                chunk = os.read(descriptor, min(remaining, 1024 * 1024))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            current = os.stat(path, follow_symlinks=False)
            if stat.S_ISLNK(current.st_mode) or (current.st_dev, current.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise ReceiptIntegrityError("receipt path changed while it was read")
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def put(self, receipt: Receipt) -> ReceiptRef:
        with self._write_lock():
            return self._put_locked(receipt)

    def _put_locked(self, receipt: Receipt) -> ReceiptRef:
        data = canonical_json_bytes(receipt.to_manifest())
        if len(data) > self.max_blob_bytes:
            raise ReceiptIntegrityError("receipt exceeds maximum blob size")
        ref = ReceiptRef(receipt.digest(), receipt.kind)
        target = self._path(ref)
        if target.exists():
            if self._read_blob(target) != data:
                raise ReceiptIntegrityError("existing receipt blob conflicts with its digest")
            return ref
        temporary = self.receipts / f".{ref.digest}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, target, follow_symlinks=False)
            except FileExistsError:
                if self._read_blob(target) != data:
                    raise ReceiptIntegrityError("concurrent receipt blob conflicts with its digest")
            directory_fd = os.open(self.receipts, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
        return ref

    def load(self, ref: ReceiptRef) -> Receipt:
        path = self._path(ref)
        try:
            raw_bytes = self._read_blob(path)
            raw = loads_strict_json(raw_bytes.decode("utf-8"))
            receipt = Receipt.from_manifest(raw)
        except (OSError, UnicodeError, ValueError, ReceiptError) as exc:
            raise ReceiptIntegrityError(f"invalid receipt blob: {exc}") from exc
        canonical = canonical_json_bytes(receipt.to_manifest())
        if canonical != raw_bytes or receipt.digest() != ref.digest or receipt.kind != ref.kind:
            raise ReceiptIntegrityError("receipt filename, kind, bytes, or digest mismatch")
        return receipt

    def verify_graph(self, roots: tuple[ReceiptRef, ...] | list[ReceiptRef], *, max_depth: int = 64, max_count: int = 4096) -> int:
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(ref: ReceiptRef, depth: int) -> None:
            if depth > max_depth:
                raise ReceiptGraphError("receipt graph exceeds maximum depth")
            if ref.digest in visiting:
                raise ReceiptGraphError("receipt graph contains a cycle")
            if ref.digest in visited:
                return
            if len(visited) >= max_count:
                raise ReceiptGraphError("receipt graph exceeds maximum count")
            visiting.add(ref.digest)
            try:
                receipt = self.load(ref)
                for parent in receipt.parents:
                    visit(parent, depth + 1)
            except ReceiptIntegrityError as exc:
                raise ReceiptGraphError(str(exc)) from exc
            finally:
                visiting.discard(ref.digest)
            visited.add(ref.digest)

        for root in roots:
            visit(root, 0)
        return len(visited)
