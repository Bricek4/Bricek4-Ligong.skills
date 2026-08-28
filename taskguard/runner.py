"""Bounded, resumable subprocess execution for TaskGuard v2."""

from __future__ import annotations

from contextlib import contextmanager
import copy
from dataclasses import dataclass, replace
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import random
import re
import signal
import subprocess
import stat
import time
from typing import Any, Callable, Iterator, Mapping

from .state import ExecutionLease, StateError, StateStore
from .workspace import ScopeViolation, WorkspaceSnapshot


_BINDING_VERSION = "taskguard-operation-binding-v2"
_OWNERSHIP_VERSION = "taskguard-workspace-ownership-v1"
_DEFAULT_OUTPUT_LIMIT = 16 * 1024
_MAX_ATTEMPTS = 4
_PROCESS_GROUP_GRACE_SECONDS = 0.075
_PROCESS_GROUP_POLL_SECONDS = 0.01
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TRANSIENT_PHRASES = (
    "stream disconnected before completion",
    "transport error: network error",
    "error decoding response body",
    "connection reset",
    "connection closed before message completed",
)
_ATTEMPT_CLASSIFICATIONS = {
    "SUCCESS",
    "AUTH",
    "PERMISSION",
    "ASSERTION",
    "BUILD",
    "INPUT",
    "TRANSPORT",
    "TIMEOUT",
    "UNKNOWN",
}
_ATTEMPT_MARKERS = {
    "AUTH",
    "PERMISSION",
    "ASSERTION",
    "BUILD",
    "INPUT",
    "TRANSPORT",
    "TIMEOUT",
    "SIGNAL",
    "PROCESS_CONTAINMENT",
    "OUTPUT_TRUNCATED",
}
_PROCESS_GROUP_CONTAINMENT = {"GROUP_EXIT_CONFIRMED", "UNPROVEN", "NOT_STARTED"}
_PROCESS_GROUP_TERMINATION = {
    "NOT_REQUIRED",
    "NOT_STARTED",
    "TERM",
    "TERM_THEN_KILL",
    "POST_EXIT_TERM",
    "POST_EXIT_TERM_THEN_KILL",
}
_NETWORK_CONTEXT = re.compile(r"\b(network|transport|connection|stream|socket|http|response)\b", re.I)
_AUTH_FAILURE = re.compile(
    r"authentication failed|unauthorized|invalid (?:api[ _-]?key|token)|\bhttp\s*401\b|\b401 unauthorized\b",
    re.I,
)
_PERMISSION_FAILURE = re.compile(
    r"permission denied|operation not permitted|\beacces\b|\bhttp\s*403\b|\b403 forbidden\b",
    re.I,
)
_ASSERTION_FAILURE = re.compile(r"assertionerror|assertion failed|failed assertion", re.I)
_BUILD_FAILURE = re.compile(
    r"syntaxerror|compilation failed|compile error|compiler error|build failed|"
    r"modulenotfounderror|importerror|no module named|dependency (?:install|resolution) failed",
    re.I,
)
_INPUT_FAILURE = re.compile(
    r"(?:^|\n)usage:|invalid argument|unrecognized arguments?|contracterror|"
    r"valueerror|typeerror|process launch failed",
    re.I,
)
_REDACTION_PATTERNS = (
    (
        re.compile(
            r"(?i)([\"'](?:password|passwd|access[_-]?token|api[_-]?key|secret|token)"
            r"[\"']\s*:\s*[\"'])([^\"'\r\n]*)([\"'])"
        ),
        r"\1[REDACTED]\3",
    ),
    (
        re.compile(
            r"(?i)(--(?:api[-_]?key|access[-_]?token|token|password|passwd|secret)"
            r"(?:=|\s+))([^\s]+)"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([^\s,;]+)"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"(?i)(\bbearer\s+)([A-Za-z0-9._~+\-/=]{6,})"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)(\b[A-Za-z0-9_]*(?:api[_-]?key|token|password|passwd|secret)"
            r"[A-Za-z0-9_]*\s*[:=]\s*)([^\s,;]+)"
        ),
        r"\1[REDACTED]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{6,}\b"), "[REDACTED]"),
)


def _nonempty(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise ValueError(f"{label} must be a non-empty string without NUL")
    return value


def _relative_path(value: Any, label: str, *, allow_dot: bool = True) -> str:
    text = _nonempty(value, label)
    path = PurePosixPath(text)
    if path.is_absolute() or any(part == ".." for part in path.parts):
        raise ValueError(f"{label} must remain repository-relative")
    normalized = path.as_posix()
    if normalized == "." and not allow_dot:
        raise ValueError(f"{label} must name a path below the repository root")
    if any(part.casefold() == ".git" for part in path.parts):
        raise ValueError(f"{label} must not select Git administrative data")
    return normalized


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _subprocess_environment() -> dict[str, str]:
    environment = os.environ.copy()
    # Python verification commands must not manufacture scoped bytecode evidence.
    # Explicit filesystem writes remain observable through WorkspaceSnapshot.
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    return environment


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


@contextmanager
def _nofollow_runtime_cwd(
    repo: Path,
    cwd: str,
    *,
    expected_repo_identity: tuple[int, int] | None = None,
) -> Iterator[Path]:
    """Open every cwd component without following links immediately before exec."""

    relative = _relative_path(cwd, "cwd")
    if not repo.is_absolute():
        raise ValueError("runtime repository path must be absolute")
    try:
        current_fd = os.open(
            os.path.sep,
            os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
        )
    except OSError as exc:
        raise ValueError(f"cannot open filesystem root for runtime cwd: {exc}") from exc
    try:
        for component in repo.parts[1:]:
            try:
                metadata = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            except OSError as exc:
                raise ValueError(
                    f"cannot inspect runtime repository component {component!r}: {exc}"
                ) from exc
            if stat.S_ISLNK(metadata.st_mode):
                raise ValueError(
                    f"runtime repository path contains a symlink; no-follow required: {component!r}"
                )
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError(
                    f"runtime repository component is not a directory: {component!r}"
                )
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                    dir_fd=current_fd,
                )
            except OSError as exc:
                raise ValueError(
                    f"cannot open runtime repository component without following links: {component!r}: {exc}"
                ) from exc
            opened = os.fstat(next_fd)
            if _directory_identity(opened) != _directory_identity(metadata):
                os.close(next_fd)
                raise ValueError(
                    f"runtime repository component changed during no-follow validation: {component!r}"
                )
            os.close(current_fd)
            current_fd = next_fd
        repo_metadata = os.fstat(current_fd)
        if expected_repo_identity is not None and _directory_identity(repo_metadata) != expected_repo_identity:
            raise ValueError("runtime repository identity changed after controller initialization")

        if relative != ".":
            traversed: list[str] = []
            for component in PurePosixPath(relative).parts:
                traversed.append(component)
                display = "/".join(traversed)
                try:
                    metadata = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                except OSError as exc:
                    raise ValueError(f"cannot inspect runtime cwd {display!r}: {exc}") from exc
                if stat.S_ISLNK(metadata.st_mode):
                    raise ValueError(
                        f"runtime cwd contains a symlink; no-follow required: {display!r}"
                    )
                if not stat.S_ISDIR(metadata.st_mode):
                    raise ValueError(f"runtime cwd is not a directory: {display!r}")
                try:
                    next_fd = os.open(
                        component,
                        os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC,
                        dir_fd=current_fd,
                    )
                except OSError as exc:
                    raise ValueError(
                        f"cannot open runtime cwd without following links: {display!r}: {exc}"
                    ) from exc
                opened = os.fstat(next_fd)
                if _directory_identity(opened) != _directory_identity(metadata):
                    os.close(next_fd)
                    raise ValueError(f"runtime cwd changed during no-follow validation: {display!r}")
                os.close(current_fd)
                current_fd = next_fd
        yield repo if relative == "." else repo / PurePosixPath(relative)
    finally:
        os.close(current_fd)


@dataclass(frozen=True)
class Operation:
    """An immutable subprocess claim bound to its complete execution surface."""

    id: str
    argv: tuple[str, ...] | list[str]
    cwd: str
    scope: tuple[str, ...] | list[str] | str
    selector: str | None
    idempotent: bool
    timeout_seconds: float = 120.0

    def __post_init__(self) -> None:
        if not isinstance(self.id, str) or not _OPERATION_ID.fullmatch(self.id) or self.id in {".", ".."}:
            raise ValueError("operation id must be a safe state identifier")
        if not isinstance(self.argv, (tuple, list)) or not self.argv:
            raise ValueError("operation argv must be a non-empty string array")
        argv = tuple(_nonempty(argument, f"argv[{index}]") for index, argument in enumerate(self.argv))
        object.__setattr__(self, "argv", argv)
        object.__setattr__(self, "cwd", _relative_path(self.cwd, "cwd"))
        raw_scope = (self.scope,) if isinstance(self.scope, str) else self.scope
        if not isinstance(raw_scope, (tuple, list)) or not raw_scope:
            raise ValueError("operation scope must be a non-empty path array")
        scope = tuple(_relative_path(item, f"scope[{index}]") for index, item in enumerate(raw_scope))
        if len(set(scope)) != len(scope):
            raise ValueError("operation scope must not contain duplicates")
        object.__setattr__(self, "scope", scope)
        if self.selector is not None:
            object.__setattr__(self, "selector", _nonempty(self.selector, "selector"))
        if type(self.idempotent) is not bool:
            raise ValueError("operation idempotent must be a boolean")
        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, (int, float)):
            raise ValueError("operation timeout_seconds must be numeric")
        timeout = float(self.timeout_seconds)
        if not 0 < timeout <= 3600:
            raise ValueError("operation timeout_seconds must be in (0, 3600]")
        object.__setattr__(self, "timeout_seconds", timeout)

    def with_changes(self, **changes: Any) -> "Operation":
        return replace(self, **changes)

    def binding(self) -> dict[str, Any]:
        return {
            "version": _BINDING_VERSION,
            "operation_id": self.id,
            "argv": list(self.argv),
            "cwd": self.cwd,
            "scope": list(self.scope),
            "selector": self.selector,
            "idempotent": self.idempotent,
            "timeout_seconds": self.timeout_seconds,
        }


@dataclass(frozen=True)
class RetryBudget:
    """Finite exponential retry policy; production defaults are 1/2/4 seconds."""

    attempts: int = _MAX_ATTEMPTS
    sleep_scale: float = 1.0
    jitter_ratio: float = 0.2

    def __post_init__(self) -> None:
        if type(self.attempts) is not int or not 1 <= self.attempts <= _MAX_ATTEMPTS:
            raise ValueError(f"attempts must be an integer in [1, {_MAX_ATTEMPTS}]")
        for value, label in (
            (self.sleep_scale, "sleep_scale"),
            (self.jitter_ratio, "jitter_ratio"),
        ):
            if isinstance(value, bool) or not isinstance(value, (int, float)) or float(value) < 0:
                raise ValueError(f"{label} must be a non-negative number")
        if float(self.jitter_ratio) > 0.5:
            raise ValueError("jitter_ratio must be at most 0.5")

    def delay_before(self, next_attempt: int, jitter_fn: Callable[[float, float], float]) -> float:
        if not 2 <= next_attempt <= _MAX_ATTEMPTS:
            raise ValueError("next_attempt is outside the retry schedule")
        base = float(2 ** (next_attempt - 2))
        spread = base * float(self.jitter_ratio)
        jitter = float(jitter_fn(-spread, spread)) if spread else 0.0
        jitter = min(spread, max(-spread, jitter))
        return max(0.0, base + jitter) * float(self.sleep_scale)


@dataclass(frozen=True)
class RunResult:
    operation_id: str
    lifecycle: str
    verdict: str
    attempts: int
    reuse_status: str
    classification: str
    exit_code: int | None
    timed_out: bool
    stdout: str
    stderr: str
    state_revision: int
    failure_markers: tuple[str, ...] = ()
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    retry_eligible: bool = False
    workspace_snapshot: dict[str, Any] | None = None
    workspace_ownership: dict[str, Any] | None = None

    def to_manifest(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "lifecycle": self.lifecycle,
            "verdict": self.verdict,
            "attempts": self.attempts,
            "reuse_status": self.reuse_status,
            "classification": self.classification,
            "exit_code": self.exit_code,
            "timed_out": self.timed_out,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "state_revision": self.state_revision,
            "failure_markers": list(self.failure_markers),
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "retry_eligible": self.retry_eligible,
            "workspace_snapshot": self.workspace_snapshot,
            "workspace_ownership": self.workspace_ownership,
        }


def _decode_output(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return value


def _redact_and_bound(value: bytes | str | None, limit: int) -> tuple[str, bool]:
    text = _decode_output(value)
    for pattern, replacement in _REDACTION_PATTERNS:
        text = pattern.sub(replacement, text)
    encoded = text.encode("utf-8", "replace")
    if len(encoded) <= limit:
        return text, False
    marker = b"\n...[TRUNCATED]"
    prefix = encoded[: max(0, limit - len(marker))]
    while prefix:
        try:
            bounded = prefix.decode("utf-8")
            break
        except UnicodeDecodeError:
            prefix = prefix[:-1]
    else:
        bounded = ""
    return bounded + marker.decode("ascii"), True


def _display_binding(binding: Mapping[str, Any]) -> dict[str, Any]:
    """Return a bounded/redacted binding while the raw digest remains authoritative."""

    displayed = dict(binding)
    displayed_argv: list[str] = []
    redact_next = False
    credential_option = re.compile(
        r"(?i)--(?:api[-_]?key|access[-_]?token|token|password|passwd|secret)\Z"
    )
    for argument in binding.get("argv", []):
        if redact_next:
            displayed_argv.append("[REDACTED]")
            redact_next = False
            continue
        displayed_argv.append(_redact_and_bound(argument, 2048)[0])
        if credential_option.fullmatch(argument):
            redact_next = True
    displayed["argv"] = displayed_argv
    return displayed


@dataclass(frozen=True)
class _ProcessOutcome:
    exit_code: int | None
    timed_out: bool
    stdout: bytes
    stderr: bytes
    process_group: dict[str, Any]


def _latest_output(current: bytes | str | None, candidate: bytes | str | None) -> bytes:
    """TimeoutExpired output is cumulative on CPython; prefer the longest view."""

    def encoded(value: bytes | str | None) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        return value.encode("utf-8", "replace")

    first = encoded(current)
    second = encoded(candidate)
    return second if len(second) >= len(first) else first


def _process_group_exists(group_id: int) -> bool:
    try:
        os.killpg(group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_process_group(group_id: int, signum: int) -> bool:
    try:
        os.killpg(group_id, signum)
    except ProcessLookupError:
        return True
    except PermissionError:
        # On Darwin a group containing only an unreaped leader can report
        # EPERM.  The subsequent wait/revalidation decides containment; never
        # turn this ambiguous signal result into an apparent success.
        return False
    return True


def _wait_process_group_exit(group_id: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while _process_group_exists(group_id):
        if time.monotonic() >= deadline:
            return False
        time.sleep(_PROCESS_GROUP_POLL_SECONDS)
    return True


def _close_process_pipes(process: subprocess.Popen[bytes]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is not None:
            try:
                stream.close()
            except (OSError, ValueError):
                pass


def _bounded_process(
    argv: list[str],
    *,
    cwd: Path,
    timeout: float,
    lease_fd: int | None = None,
    lease_root_fd: int | None = None,
) -> _ProcessOutcome:
    """Run in a new session and never return while its process group is live.

    A descendant can deliberately create a second session.  Portable POSIX
    process groups cannot enumerate or kill that escaped session.  When an
    escaped process is observable because it retains our pipes, containment is
    marked UNPROVEN and the caller must fail closed.  A fully detached process
    that also severs every observable handle is outside this mechanism's
    capability boundary; callers must not describe this helper as a sandbox.
    """

    process = subprocess.Popen(
        argv,
        cwd=cwd,
        shell=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_subprocess_environment(),
        start_new_session=True,
        pass_fds=tuple(
            dict.fromkeys(
                descriptor
                for descriptor in (lease_fd, lease_root_fd)
                if descriptor is not None
            )
        ),
    )
    group_id = process.pid
    stdout = b""
    stderr = b""
    pipe_escape = False
    termination = "NOT_REQUIRED"
    try:
        try:
            raw_stdout, raw_stderr = process.communicate(timeout=timeout)
            stdout = _latest_output(stdout, raw_stdout)
            stderr = _latest_output(stderr, raw_stderr)
        except subprocess.TimeoutExpired as exc:
            stdout = _latest_output(stdout, exc.stdout)
            stderr = _latest_output(stderr, exc.stderr)
            termination = "TERM"
            _signal_process_group(group_id, signal.SIGTERM)
            try:
                raw_stdout, raw_stderr = process.communicate(
                    timeout=_PROCESS_GROUP_GRACE_SECONDS
                )
                stdout = _latest_output(stdout, raw_stdout)
                stderr = _latest_output(stderr, raw_stderr)
            except subprocess.TimeoutExpired as term_exc:
                stdout = _latest_output(stdout, term_exc.stdout)
                stderr = _latest_output(stderr, term_exc.stderr)
                termination = "TERM_THEN_KILL"
                _signal_process_group(group_id, signal.SIGKILL)
                try:
                    raw_stdout, raw_stderr = process.communicate(
                        timeout=_PROCESS_GROUP_GRACE_SECONDS
                    )
                    stdout = _latest_output(stdout, raw_stdout)
                    stderr = _latest_output(stderr, raw_stderr)
                except subprocess.TimeoutExpired as kill_exc:
                    stdout = _latest_output(stdout, kill_exc.stdout)
                    stderr = _latest_output(stderr, kill_exc.stderr)
                    pipe_escape = True
                    _close_process_pipes(process)
                    try:
                        process.wait(timeout=_PROCESS_GROUP_GRACE_SECONDS)
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        try:
                            process.wait(timeout=_PROCESS_GROUP_GRACE_SECONDS)
                        except subprocess.TimeoutExpired:
                            pass
            group_gone = _wait_process_group_exit(
                group_id, _PROCESS_GROUP_GRACE_SECONDS
            )
            if not group_gone:
                _signal_process_group(group_id, signal.SIGKILL)
                group_gone = _wait_process_group_exit(
                    group_id, _PROCESS_GROUP_GRACE_SECONDS
                )
            containment = "GROUP_EXIT_CONFIRMED" if group_gone and not pipe_escape else "UNPROVEN"
            if containment == "UNPROVEN":
                stderr += (
                    b"\nTaskGuard process containment is unproven; a detached session "
                    b"may retain side effects and cannot be rolled back."
                )
            return _ProcessOutcome(
                exit_code=None,
                timed_out=True,
                stdout=stdout,
                stderr=stderr,
                process_group={
                    "isolated": True,
                    "containment": containment,
                    "termination": termination,
                    "detached_sessions": "NOT_PORTABLY_OBSERVABLE",
                },
            )

        # A command can exit while same-group background workers continue with
        # redirected stdio.  Kill that remainder and reject the apparent success.
        if _process_group_exists(group_id):
            termination = "POST_EXIT_TERM"
            _signal_process_group(group_id, signal.SIGTERM)
            group_gone = _wait_process_group_exit(group_id, _PROCESS_GROUP_GRACE_SECONDS)
            if not group_gone:
                termination = "POST_EXIT_TERM_THEN_KILL"
                _signal_process_group(group_id, signal.SIGKILL)
                group_gone = _wait_process_group_exit(group_id, _PROCESS_GROUP_GRACE_SECONDS)
            stderr += b"\nTaskGuard terminated a surviving process-group descendant."
            return _ProcessOutcome(
                exit_code=None,
                timed_out=True,
                stdout=stdout,
                stderr=stderr,
                process_group={
                    "isolated": True,
                    "containment": "GROUP_EXIT_CONFIRMED" if group_gone else "UNPROVEN",
                    "termination": termination,
                    "detached_sessions": "NOT_PORTABLY_OBSERVABLE",
                },
            )
        return _ProcessOutcome(
            exit_code=process.returncode,
            timed_out=False,
            stdout=stdout,
            stderr=stderr,
            process_group={
                "isolated": True,
                "containment": "GROUP_EXIT_CONFIRMED",
                "termination": termination,
                "detached_sessions": "NOT_PORTABLY_OBSERVABLE",
            },
        )
    finally:
        if process.poll() is None:
            _signal_process_group(group_id, signal.SIGKILL)
            try:
                process.wait(timeout=_PROCESS_GROUP_GRACE_SECONDS)
            except subprocess.TimeoutExpired:
                pass
        _close_process_pipes(process)


def _deterministic_scope_failure(exc: ScopeViolation) -> bool:
    return str(exc).startswith("new out-of-scope workspace change:")


def _workspace_ownership_proof(
    origin: WorkspaceSnapshot,
    snapshot: WorkspaceSnapshot,
) -> dict[str, Any]:
    """Prove that stable dirty evidence arose in scope after an admissible origin."""

    proof: dict[str, Any] = {
        "version": _OWNERSHIP_VERSION,
        "baseline_digest": _digest(origin.to_manifest()),
        "snapshot_digest": _digest(snapshot.to_manifest()),
        "verdict": "UNKNOWN",
        "owned_paths": [],
        "reason": "workspace ownership evidence is unavailable",
    }
    if not origin.stable or not snapshot.stable:
        proof["reason"] = "workspace ownership capture is unstable"
        return proof
    if origin.status != "FRESH":
        proof["reason"] = "task baseline contains acknowledged or other in-scope pre-dirty evidence"
        return proof
    try:
        comparison = snapshot.compare_to(origin)
    except ScopeViolation as exc:
        proof["verdict"] = "FAILED" if _deterministic_scope_failure(exc) else "UNKNOWN"
        proof["reason"] = str(exc)
        return proof
    changed = list(comparison.changed_paths)
    if "<git-head>" in changed:
        proof["verdict"] = "FAILED"
        proof["reason"] = "Git HEAD changed after task admission"
        return proof
    if comparison.status not in {"FRESH", "STALE"}:
        proof["reason"] = "workspace ownership comparison is not exact"
        return proof
    proof["verdict"] = "SUPPORTED"
    proof["owned_paths"] = changed
    proof["reason"] = (
        "workspace is unchanged from the admissible task baseline"
        if not changed
        else "all post-admission changes are inside declared task scope"
    )
    return proof


def _exact_command_freshness(
    current: WorkspaceSnapshot,
    baseline: WorkspaceSnapshot,
    ownership: Mapping[str, Any],
) -> dict[str, Any]:
    """Classify command-local changes without weakening WorkspaceSnapshot globally."""

    try:
        comparison = current.compare_to(baseline)
    except ScopeViolation as exc:
        return {
            "verdict": "FAILED" if _deterministic_scope_failure(exc) else "UNKNOWN",
            "status": "FAILED" if _deterministic_scope_failure(exc) else "UNKNOWN",
            "changed_paths": [],
            "reason": str(exc),
        }
    changed = list(comparison.changed_paths)
    if "<git-head>" in changed:
        return {
            "verdict": "FAILED",
            "status": "FAILED",
            "changed_paths": changed,
            "reason": "Git HEAD changed while the operation executed",
        }
    if changed:
        return {
            "verdict": "STALE",
            "status": "STALE",
            "changed_paths": changed,
            "reason": "workspace changed while the operation executed",
        }
    if comparison.status == "FRESH":
        verdict = "SUPPORTED"
    elif (
        comparison.status == "UNKNOWN"
        and current.stable
        and baseline.stable
        and ownership.get("verdict") == "SUPPORTED"
    ):
        verdict = "SUPPORTED"
    else:
        verdict = "UNKNOWN"
    return {
        "verdict": verdict,
        "status": comparison.status,
        "changed_paths": changed,
        "reason": (
            "exact zero-change command comparison"
            if verdict == "SUPPORTED"
            else "command freshness could not be proven"
        ),
    }


def classify_failure(
    *,
    exit_code: int | None,
    timed_out: bool,
    stdout: str,
    stderr: str,
) -> str:
    """Classify a completed attempt with explicit non-transient precedence."""

    if exit_code == 0 and not timed_out:
        return "SUCCESS"
    combined = f"{stdout}\n{stderr}"
    if _AUTH_FAILURE.search(combined):
        return "AUTH"
    if _PERMISSION_FAILURE.search(combined):
        return "PERMISSION"
    if _ASSERTION_FAILURE.search(combined):
        return "ASSERTION"
    if _BUILD_FAILURE.search(combined):
        return "BUILD"
    if _INPUT_FAILURE.search(combined):
        return "INPUT"
    lowered = combined.casefold()
    if any(phrase in lowered for phrase in _TRANSIENT_PHRASES):
        return "TRANSPORT"
    if "timed out" in lowered and _NETWORK_CONTEXT.search(combined):
        return "TRANSPORT"
    if timed_out:
        return "TIMEOUT"
    return "UNKNOWN"


def _failure_markers(
    *,
    exit_code: int | None,
    timed_out: bool,
    stdout: str,
    stderr: str,
) -> tuple[str, ...]:
    """Return non-secret marker names detected from complete in-memory output."""

    combined = f"{stdout}\n{stderr}"
    lowered = combined.casefold()
    markers: set[str] = set()
    for name, pattern in (
        ("AUTH", _AUTH_FAILURE),
        ("PERMISSION", _PERMISSION_FAILURE),
        ("ASSERTION", _ASSERTION_FAILURE),
        ("BUILD", _BUILD_FAILURE),
        ("INPUT", _INPUT_FAILURE),
    ):
        if pattern.search(combined):
            markers.add(name)
    if any(phrase in lowered for phrase in _TRANSIENT_PHRASES):
        markers.add("TRANSPORT")
    if "timed out" in lowered:
        markers.add("TIMEOUT")
        if _NETWORK_CONTEXT.search(combined):
            markers.add("TRANSPORT")
    if timed_out:
        markers.add("TIMEOUT")
    if type(exit_code) is int and exit_code < 0:
        markers.add("SIGNAL")
    return tuple(sorted(markers))


def _classification_from_attempt_evidence(
    *,
    exit_code: int | None,
    timed_out: bool,
    failure_markers: set[str],
    containment: str,
    truncated: bool,
) -> str:
    """Reproduce the producer's fixed classification precedence from durable facts."""

    if truncated:
        return "UNKNOWN"
    if containment == "UNPROVEN":
        return "TIMEOUT"
    if exit_code == 0 and not timed_out:
        return "SUCCESS"
    for marker, classification in (
        ("AUTH", "AUTH"),
        ("PERMISSION", "PERMISSION"),
        ("ASSERTION", "ASSERTION"),
        ("BUILD", "BUILD"),
        ("INPUT", "INPUT"),
        ("TRANSPORT", "TRANSPORT"),
    ):
        if marker in failure_markers:
            return classification
    if timed_out:
        return "TIMEOUT"
    return "UNKNOWN"


def valid_expected_red(
    *,
    exit_code: int | None,
    timed_out: bool,
    stdout: str,
    stderr: str,
    expected_literal: str | None,
    failure_markers: tuple[str, ...] | list[str] = (),
) -> bool:
    """Accept a literal RED only for a positive nonzero, non-disqualified exit."""

    if type(exit_code) is not int or exit_code <= 0 or timed_out:
        return False
    if not isinstance(expected_literal, str):
        return False
    combined = f"{stdout}\n{stderr}"
    if expected_literal not in combined:
        return False
    if set(failure_markers).intersection(
        {
            "AUTH",
            "PERMISSION",
            "BUILD",
            "INPUT",
            "TRANSPORT",
            "TIMEOUT",
            "SIGNAL",
            "OUTPUT_TRUNCATED",
        }
    ):
        return False
    if any(
        pattern.search(combined)
        for pattern in (_AUTH_FAILURE, _PERMISSION_FAILURE, _BUILD_FAILURE, _INPUT_FAILURE)
    ):
        return False
    lowered = combined.casefold()
    if any(phrase in lowered for phrase in _TRANSIENT_PHRASES):
        return False
    if "timed out" in lowered:
        return False
    return True


class TaskRunner:
    """Execute a bound operation and persist an evidence ledger per attempt."""

    def __init__(
        self,
        *,
        state_root: os.PathLike[str] | str,
        workspace_root: os.PathLike[str] | str,
        owner: str | None = None,
        sleep_fn: Callable[[float], None] = time.sleep,
        jitter_fn: Callable[[float, float], float] = random.uniform,
        output_limit: int = _DEFAULT_OUTPUT_LIMIT,
    ) -> None:
        self.state_root = Path(state_root)
        try:
            self.workspace_root = Path(workspace_root).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ValueError(f"cannot resolve workspace root: {exc}") from exc
        if not self.workspace_root.is_dir():
            raise ValueError("workspace root must be a directory")
        try:
            workspace_metadata = self.workspace_root.lstat()
        except OSError as exc:
            raise ValueError(f"cannot inspect workspace root: {exc}") from exc
        if stat.S_ISLNK(workspace_metadata.st_mode) or not stat.S_ISDIR(workspace_metadata.st_mode):
            raise ValueError("workspace root must be a non-symlink directory")
        self._workspace_identity = _directory_identity(workspace_metadata)
        if type(output_limit) is not int or not 256 <= output_limit <= 1024 * 1024:
            raise ValueError("output_limit must be an integer in [256, 1048576]")
        self.output_limit = output_limit
        self.sleep_fn = sleep_fn
        self.jitter_fn = jitter_fn
        if owner is None:
            identity = f"{self.state_root.absolute()}\0{self.workspace_root}".encode("utf-8", "surrogateescape")
            owner = "runner-" + hashlib.sha256(identity).hexdigest()[:24]
        self.owner = _nonempty(owner, "owner")
        self.store = StateStore(self.state_root)

    def _resolved_cwd(self, operation: Operation) -> Path:
        try:
            with _nofollow_runtime_cwd(
                self.workspace_root,
                operation.cwd,
                expected_repo_identity=self._workspace_identity,
            ) as candidate:
                return candidate
        except ValueError as exc:
            raise ValueError(
                f"operation cwd escapes, follows a symlink, or is unavailable: {operation.cwd!r}: {exc}"
            ) from exc

    def _binding(self, operation: Operation) -> tuple[dict[str, Any], str]:
        binding = operation.binding()
        return binding, _digest(binding)

    def _state_exists(self, operation: Operation) -> bool:
        return os.path.lexists(self.state_root / f"{operation.id}.json")

    def _result_from_state(
        self,
        state: Mapping[str, Any],
        *,
        reuse_status: str,
        verdict: str | None = None,
        lifecycle: str | None = None,
    ) -> RunResult:
        result = state.get("result") if isinstance(state.get("result"), Mapping) else {}
        attempts = state.get("attempt_records")
        records = attempts if isinstance(attempts, list) else []
        last = records[-1] if records and isinstance(records[-1], Mapping) else {}
        workspace = state.get("workspace_success")
        ownership = state.get("workspace_ownership")
        raw_markers = result.get("failure_markers", last.get("failure_markers", []))
        markers = (
            tuple(item for item in raw_markers if isinstance(item, str))
            if isinstance(raw_markers, list)
            else ()
        )
        return RunResult(
            operation_id=str(state["operation_id"]),
            lifecycle=lifecycle or str(state["lifecycle"]),
            verdict=verdict or str(state["verdict"]),
            attempts=len(records),
            reuse_status=reuse_status,
            classification=str(result.get("classification", last.get("classification", "UNKNOWN"))),
            exit_code=result.get("exit_code", last.get("exit_code")),
            timed_out=bool(result.get("timed_out", last.get("timed_out", False))),
            stdout=str(result.get("stdout", last.get("stdout", ""))),
            stderr=str(result.get("stderr", last.get("stderr", ""))),
            state_revision=int(state["revision"]),
            failure_markers=markers,
            stdout_truncated=(
                result.get("stdout_truncated", last.get("stdout_truncated")) is True
            ),
            stderr_truncated=(
                result.get("stderr_truncated", last.get("stderr_truncated")) is True
            ),
            retry_eligible=(
                result.get("retry_eligible", last.get("retry_eligible")) is True
            ),
            workspace_snapshot=workspace if isinstance(workspace, dict) else None,
            workspace_ownership=ownership if isinstance(ownership, dict) else None,
        )

    def _validate_existing_binding(
        self,
        operation: Operation,
        state: Mapping[str, Any],
        binding: Mapping[str, Any],
        binding_digest: str,
    ) -> None:
        if state.get("binding_version") != _BINDING_VERSION:
            raise ValueError("operation binding drift: unsupported persisted binding version")
        persisted_binding = state.get("binding")
        expected_binding = _display_binding(binding)
        if (
            state.get("binding_digest") != binding_digest
            or type(persisted_binding) is not dict
            or _canonical_json(persisted_binding) != _canonical_json(expected_binding)
        ):
            raise ValueError("operation binding drift: persisted evidence belongs to different execution inputs")
        self.store.claim(operation.id, owner=self.owner)

    def _validate_ownership_binding(
        self,
        state: Mapping[str, Any],
        ownership_baseline: WorkspaceSnapshot | None,
    ) -> None:
        source = state.get("ownership_source")
        origin_manifest = state.get("ownership_origin")
        if source not in {"OPERATION_BASELINE", "EXTERNAL_TASK_BASELINE"} or not isinstance(
            origin_manifest, Mapping
        ):
            raise StateError("operation state has no valid workspace ownership binding")
        if state.get("ownership_origin_digest") != _digest(origin_manifest):
            raise StateError("operation workspace ownership binding digest is invalid")
        if source == "EXTERNAL_TASK_BASELINE":
            if not isinstance(ownership_baseline, WorkspaceSnapshot):
                raise ValueError("external workspace ownership baseline is required for reuse")
            if ownership_baseline.to_manifest() != origin_manifest:
                raise ValueError("workspace ownership baseline drift")
        elif ownership_baseline is not None:
            raise ValueError("workspace ownership baseline drift")

    def _ownership_from_state(
        self,
        state: Mapping[str, Any],
    ) -> tuple[WorkspaceSnapshot, WorkspaceSnapshot, dict[str, Any]]:
        origin_manifest = state.get("ownership_origin")
        baseline_manifest = state.get("workspace_baseline")
        persisted = state.get("workspace_ownership")
        if not all(isinstance(value, Mapping) for value in (origin_manifest, baseline_manifest, persisted)):
            raise ScopeViolation("operation state lacks complete workspace ownership evidence")
        origin = WorkspaceSnapshot.from_manifest(origin_manifest)
        baseline = WorkspaceSnapshot.from_manifest(baseline_manifest)
        recomputed = _workspace_ownership_proof(origin, baseline)
        if dict(persisted) != recomputed:
            raise ScopeViolation("persisted workspace ownership proof does not revalidate")
        return origin, baseline, recomputed

    def _try_reuse(self, operation: Operation, state: Mapping[str, Any]) -> RunResult:
        if state.get("lifecycle") in {"RUNNING", "RETRY_WAIT"}:
            return self._result_from_state(
                state,
                reuse_status="INTERRUPTED",
                verdict="UNKNOWN",
                lifecycle=str(state["lifecycle"]),
            )
        if state.get("lifecycle") != "TERMINAL" or state.get("verdict") != "SUPPORTED":
            return self._result_from_state(state, reuse_status="NOT_REUSABLE")
        try:
            self._audit_terminal_ledger(operation, state)
        except (ScopeViolation, StateError, TypeError, ValueError):
            return self._result_from_state(
                state,
                reuse_status="UNKNOWN",
                verdict="UNKNOWN",
                lifecycle="TERMINAL_ERROR",
            )
        manifest = state.get("workspace_success")
        if not isinstance(manifest, Mapping):
            return self._result_from_state(
                state,
                reuse_status="UNKNOWN",
                verdict="UNKNOWN",
                lifecycle="TERMINAL_ERROR",
            )
        records = state.get("attempt_records")
        result = state.get("result")
        last = records[-1] if isinstance(records, list) and records else None
        if (
            not isinstance(last, Mapping)
            or last.get("classification") != "SUCCESS"
            or last.get("exit_code") != 0
            or last.get("timed_out") is not False
            or not isinstance(result, Mapping)
            or result.get("classification") != "SUCCESS"
            or result.get("exit_code") != 0
            or result.get("timed_out") is not False
        ):
            return self._result_from_state(
                state,
                reuse_status="UNKNOWN",
                verdict="UNKNOWN",
                lifecycle="TERMINAL_ERROR",
            )
        try:
            _origin, baseline, ownership = self._ownership_from_state(state)
            success = WorkspaceSnapshot.from_manifest(manifest)
            receipt_freshness = _exact_command_freshness(success, baseline, ownership)
            persisted_freshness = state.get("command_freshness")
            if (
                receipt_freshness.get("verdict") != "SUPPORTED"
                or not isinstance(persisted_freshness, Mapping)
                or dict(persisted_freshness) != receipt_freshness
            ):
                raise ScopeViolation("persisted successful command freshness does not revalidate")
            current = WorkspaceSnapshot.capture(
                self.workspace_root,
                scope=list(operation.scope),
                acknowledged_dirty=list(_origin.acknowledged_dirty),
            )
            freshness = _exact_command_freshness(current, success, ownership)
        except ScopeViolation as exc:
            verdict = "FAILED" if _deterministic_scope_failure(exc) else "UNKNOWN"
            return self._result_from_state(
                state,
                reuse_status=verdict,
                verdict=verdict,
                lifecycle="TERMINAL_ERROR",
            )
        verdict = str(freshness["verdict"])
        if verdict == "SUPPORTED":
            return self._result_from_state(state, reuse_status="REUSED")
        return self._result_from_state(
            state,
            reuse_status=verdict,
            verdict=verdict,
            lifecycle="TERMINAL_ERROR",
        )

    def run(
        self,
        operation: Operation,
        *,
        budget: RetryBudget | None = None,
        ownership_baseline: WorkspaceSnapshot | None = None,
    ) -> RunResult:
        if not isinstance(operation, Operation):
            raise TypeError("operation must be an Operation")
        if ownership_baseline is not None and not isinstance(ownership_baseline, WorkspaceSnapshot):
            raise TypeError("ownership_baseline must be a WorkspaceSnapshot")
        budget = RetryBudget() if budget is None else budget
        if not isinstance(budget, RetryBudget):
            raise TypeError("budget must be a RetryBudget")
        with self.store.execution_lease(operation.id, blocking=True) as lease:
            return self._run_with_lease(
                operation,
                budget=budget,
                ownership_baseline=ownership_baseline,
                lease=lease,
            )

    def _run_with_lease(
        self,
        operation: Operation,
        *,
        budget: RetryBudget,
        ownership_baseline: WorkspaceSnapshot | None,
        lease: ExecutionLease,
    ) -> RunResult:
        self._resolved_cwd(operation)
        binding, binding_digest = self._binding(operation)
        if self._state_exists(operation):
            state = self.store.load(operation.id)
            lease.require_manifest(state.get("execution_lease"))
            self._validate_existing_binding(operation, state, binding, binding_digest)
            self._validate_ownership_binding(state, ownership_baseline)
            return self._try_reuse(operation, state)
        baseline = WorkspaceSnapshot.capture(
            self.workspace_root,
            scope=list(operation.scope),
            acknowledged_dirty=(
                list(ownership_baseline.acknowledged_dirty)
                if ownership_baseline is not None
                else None
            ),
        )
        origin = baseline if ownership_baseline is None else ownership_baseline
        ownership = _workspace_ownership_proof(origin, baseline)
        state = self.store.create(
            operation.id,
            owner=self.owner,
            binding_version=_BINDING_VERSION,
            binding=_display_binding(binding),
            binding_digest=binding_digest,
            execution_lease=lease.to_manifest(),
            attempt_records=[],
            active_attempt=None,
            ownership_source=(
                "OPERATION_BASELINE"
                if ownership_baseline is None
                else "EXTERNAL_TASK_BASELINE"
            ),
            ownership_origin=origin.to_manifest(),
            ownership_origin_digest=_digest(origin.to_manifest()),
            workspace_ownership=ownership,
            workspace_baseline=baseline.to_manifest(),
            workspace_success=None,
            result=None,
        )
        if ownership["verdict"] == "FAILED":
            result_manifest = {
                "classification": "SCOPE",
                "failure_markers": ["SCOPE"],
                "exit_code": None,
                "timed_out": False,
                "stdout": "",
                "stderr": str(ownership["reason"]),
            }
            state = self.store.update(
                operation.id,
                expected_revision=state["revision"],
                expected_owner=self.owner,
                lifecycle="TERMINAL_ERROR",
                verdict="FAILED",
                active_attempt=None,
                result=result_manifest,
                workspace_success=baseline.to_manifest(),
            )
            return self._result_from_state(state, reuse_status="EXECUTION_BLOCKED")
        return self._execute(operation, budget, state, lease=lease)

    def refresh(
        self,
        operation: Operation,
        *,
        budget: RetryBudget | None = None,
        ownership_baseline: WorkspaceSnapshot | None = None,
    ) -> RunResult:
        """Rerun only a same-binding, idempotent, stale supported receipt."""

        if not isinstance(operation, Operation):
            raise TypeError("operation must be an Operation")
        if not operation.idempotent:
            raise ValueError("safe refresh requires an explicitly idempotent operation")
        with self.store.execution_lease(operation.id, blocking=True) as lease:
            return self._refresh_with_lease(
                operation,
                budget=budget,
                ownership_baseline=ownership_baseline,
                lease=lease,
            )

    def _refresh_with_lease(
        self,
        operation: Operation,
        *,
        budget: RetryBudget | None,
        ownership_baseline: WorkspaceSnapshot | None,
        lease: ExecutionLease,
    ) -> RunResult:
        self._resolved_cwd(operation)
        binding, binding_digest = self._binding(operation)
        state = self.store.load(operation.id)
        lease.require_manifest(state.get("execution_lease"))
        self._validate_existing_binding(operation, state, binding, binding_digest)
        self._validate_ownership_binding(state, ownership_baseline)
        if state.get("lifecycle") != "TERMINAL" or state.get("verdict") != "SUPPORTED":
            raise ValueError("safe refresh requires a terminal supported receipt")
        reuse = self._try_reuse(operation, state)
        if reuse.reuse_status != "STALE":
            if reuse.reuse_status == "REUSED":
                raise ValueError("safe refresh requires stale evidence; receipt is still fresh")
            raise ValueError(
                f"safe refresh requires demonstrably stale supported evidence, got {reuse.reuse_status}"
            )
        origin, _old_baseline, _old_ownership = self._ownership_from_state(state)
        baseline = WorkspaceSnapshot.capture(
            self.workspace_root,
            scope=list(operation.scope),
            acknowledged_dirty=list(origin.acknowledged_dirty),
        )
        ownership = _workspace_ownership_proof(origin, baseline)
        if ownership["verdict"] != "SUPPORTED":
            raise ValueError(
                "safe refresh cannot establish task ownership for the stale workspace: "
                + str(ownership["reason"])
            )
        history = list(state.get("refresh_history", []))
        history.append(
            {
                "revision": state["revision"],
                "attempt_records": state.get("attempt_records", []),
                "result": state.get("result"),
                "workspace_success": state.get("workspace_success"),
                "command_freshness": state.get("command_freshness"),
            }
        )
        state = self.store.update(
            operation.id,
            expected_revision=state["revision"],
            expected_owner=self.owner,
            lifecycle="INITIALIZED",
            verdict="UNKNOWN",
            attempt_records=[],
            active_attempt=None,
            workspace_ownership=ownership,
            workspace_baseline=baseline.to_manifest(),
            workspace_success=None,
            result=None,
            command_freshness=None,
            refresh_history=history,
        )
        return self._execute(
            operation,
            budget or RetryBudget(),
            state,
            lease=lease,
        )

    def dispose(self, operation: Operation, *, verdict: str = "UNKNOWN") -> RunResult:
        """Safely disposition an interrupted operation without executing it again."""

        if not isinstance(operation, Operation):
            raise TypeError("operation must be an Operation")
        if verdict not in {"FAILED", "UNKNOWN"}:
            raise ValueError("dispose verdict must be FAILED or UNKNOWN")
        with self.store.execution_lease(operation.id, blocking=False) as lease:
            binding, binding_digest = self._binding(operation)
            state = self.store.load(operation.id)
            lease.require_manifest(state.get("execution_lease"))
            self._validate_existing_binding(operation, state, binding, binding_digest)
            if state.get("lifecycle") not in {"RUNNING", "RETRY_WAIT"}:
                raise StateError(
                    "dispose is allowed only for an interrupted RUNNING or RETRY_WAIT operation"
                )
            interruption = {
                "disposed_revision": state["revision"],
                "active_attempt": copy.deepcopy(state.get("active_attempt")),
                "retry": copy.deepcopy(state.get("retry")),
                "verdict": verdict,
                "execution_lease": "ACQUIRED_NONBLOCKING",
            }
            state = self.store.update(
                operation.id,
                expected_revision=state["revision"],
                expected_owner=self.owner,
                lifecycle="TERMINAL_ERROR",
                verdict=verdict,
                active_attempt=None,
                retry=None,
                interruption=interruption,
            )
            return self._result_from_state(state, reuse_status="DISPOSED")

    def audit(
        self,
        operation: Operation,
        *,
        ownership_baseline: WorkspaceSnapshot | None = None,
    ) -> RunResult:
        """Reconstruct a phase receipt from its checksummed operation ledger.

        No persisted verdict is accepted on its own.  The complete attempt
        sequence, final result, binding, workspace proof and terminal state are
        parsed and cross-checked while a nonblocking exclusive lease proves no
        cooperating executor is still mutating the operation.
        """

        if not isinstance(operation, Operation):
            raise TypeError("operation must be an Operation")
        if ownership_baseline is not None and not isinstance(
            ownership_baseline, WorkspaceSnapshot
        ):
            raise TypeError("ownership_baseline must be a WorkspaceSnapshot")
        with self.store.execution_lease(operation.id, blocking=False) as lease:
            binding, binding_digest = self._binding(operation)
            state = self.store.load(operation.id)
            lease.require_manifest(state.get("execution_lease"))
            self._validate_existing_binding(operation, state, binding, binding_digest)
            self._validate_ownership_binding(state, ownership_baseline)
            self._audit_terminal_ledger(operation, state)
            return self._result_from_state(state, reuse_status="EXECUTED")

    def _audit_refresh_history(
        self,
        operation: Operation,
        state: Mapping[str, Any],
        history: list[Any],
    ) -> int:
        if operation.idempotent is not True:
            raise StateError("only an idempotent operation can have refresh history")
        previous_revision = 0
        for item in history:
            if type(item) is not dict or set(item) != {
                "revision",
                "attempt_records",
                "result",
                "workspace_success",
                "command_freshness",
            }:
                raise StateError("operation refresh history item has an invalid schema")
            revision = item["revision"]
            records = item["attempt_records"]
            if type(records) is not list or not 1 <= len(records) <= _MAX_ATTEMPTS:
                raise StateError("operation refresh history attempts are invalid")
            expected_revision = previous_revision + 2 * len(records) + 1
            if type(revision) is not int or revision != expected_revision:
                raise StateError("operation refresh history revisions are inconsistent")
            previous_revision = revision
            historical_state = dict(state)
            historical_state.pop("refresh_history", None)
            historical_state.update(
                revision=revision,
                lifecycle="TERMINAL",
                verdict="SUPPORTED",
                attempt_records=item["attempt_records"],
                active_attempt=None,
                result=item["result"],
                retry=None,
                workspace_success=item["workspace_success"],
                command_freshness=item["command_freshness"],
            )
            self._audit_terminal_ledger(
                operation,
                historical_state,
                validate_refresh_history=False,
                validate_workspace=False,
            )
        return previous_revision

    def _audit_terminal_ledger(
        self,
        operation: Operation,
        state: Mapping[str, Any],
        *,
        validate_refresh_history: bool = True,
        validate_workspace: bool = True,
    ) -> None:
        required_state_fields = {
            "schema_version",
            "operation_id",
            "owner",
            "lifecycle",
            "verdict",
            "revision",
            "checksum",
            "binding_version",
            "binding",
            "binding_digest",
            "execution_lease",
            "attempt_records",
            "active_attempt",
            "ownership_source",
            "ownership_origin",
            "ownership_origin_digest",
            "workspace_ownership",
            "workspace_baseline",
            "workspace_success",
            "result",
            "retry",
        }
        optional_state_fields = {"command_freshness", "refresh_history"}
        if not required_state_fields.issubset(state) or not set(state).issubset(
            required_state_fields | optional_state_fields
        ):
            raise StateError("operation ledger has an invalid terminal state schema")
        history_revision = 0
        if "refresh_history" in state:
            history = state["refresh_history"]
            if type(history) is not list or not history:
                raise StateError("operation refresh history must be a non-empty array")
            if validate_refresh_history:
                history_revision = self._audit_refresh_history(operation, state, history)
        records = state.get("attempt_records")
        if type(records) is not list or not 1 <= len(records) <= _MAX_ATTEMPTS:
            raise StateError("operation ledger must contain one to four attempts")
        if validate_refresh_history and state.get("revision") != (
            history_revision + 2 * len(records) + 1
        ):
            raise StateError("operation terminal revision violates the production state machine")
        if state.get("active_attempt") is not None or state.get("retry") is not None:
            raise StateError("terminal operation ledger retains active or retry state")
        if state.get("lifecycle") not in {"TERMINAL", "TERMINAL_ERROR"}:
            raise StateError("operation ledger is not terminal")

        previous_end: int | None = None
        for index, record in enumerate(records, start=1):
            if type(record) is not dict or set(record) != {
                "sequence",
                "start_monotonic_ns",
                "end_monotonic_ns",
                "duration_ns",
                "exit_code",
                "timed_out",
                "classification",
                "failure_markers",
                "stdout",
                "stderr",
                "stdout_truncated",
                "stderr_truncated",
                "retry_eligible",
                "process_group",
            }:
                raise StateError("operation attempt ledger has an invalid schema")
            start = record["start_monotonic_ns"]
            end = record["end_monotonic_ns"]
            duration = record["duration_ns"]
            if any(type(value) is not int for value in (start, end, duration)):
                raise StateError("operation attempt timing must use integer nanoseconds")
            if start <= 0 or end < start or duration != end - start:
                raise StateError("operation attempt timing is inconsistent")
            if previous_end is not None and start < previous_end:
                raise StateError("operation attempts overlap or are out of order")
            previous_end = end
            if type(record["sequence"]) is not int or record["sequence"] != index:
                raise StateError("operation attempt sequence is not contiguous")
            exit_code = record["exit_code"]
            if not (exit_code is None or (type(exit_code) is int)):
                raise StateError("operation attempt exit_code must be an integer or null")
            if type(record["timed_out"]) is not bool:
                raise StateError("operation attempt timed_out must be a boolean")
            classification = record["classification"]
            if type(classification) is not str or classification not in _ATTEMPT_CLASSIFICATIONS:
                raise StateError("operation attempt classification is invalid")
            markers = record["failure_markers"]
            if (
                type(markers) is not list
                or any(type(marker) is not str or marker not in _ATTEMPT_MARKERS for marker in markers)
                or markers != sorted(set(markers))
            ):
                raise StateError("operation attempt failure markers are invalid")
            if any(type(record[key]) is not str for key in ("stdout", "stderr")):
                raise StateError("operation attempt output must be text")
            if any(
                type(record[key]) is not bool
                for key in ("stdout_truncated", "stderr_truncated")
            ):
                raise StateError("operation attempt truncation flags must be boolean")
            if type(record["retry_eligible"]) is not bool:
                raise StateError("operation attempt retry eligibility must be a boolean")
            truncated = record["stdout_truncated"] or record["stderr_truncated"]
            if ("OUTPUT_TRUNCATED" in markers) != truncated:
                raise StateError(
                    "operation attempt truncation marker contradicts persisted output"
                )
            for output_key in ("stdout", "stderr"):
                output = record[output_key]
                if len(output.encode("utf-8")) > self.output_limit:
                    raise StateError("operation attempt output exceeds the persistence cap")
                if _redact_and_bound(output, self.output_limit)[0] != output:
                    raise StateError("operation attempt output contains unredacted credentials")
                truncation_key = f"{output_key}_truncated"
                if record[truncation_key] and not output.endswith("\n...[TRUNCATED]"):
                    raise StateError(
                        "operation attempt truncation flag lacks the producer marker"
                    )
                if record[truncation_key] and len(output.encode("utf-8")) < self.output_limit - 3:
                    raise StateError(
                        "operation attempt truncation flag contradicts the persistence cap"
                    )

            group = record["process_group"]
            if type(group) is not dict or set(group) != {
                "isolated",
                "containment",
                "termination",
                "detached_sessions",
            }:
                raise StateError("operation process-group evidence has an invalid schema")
            if type(group["isolated"]) is not bool:
                raise StateError("operation process-group isolation flag is invalid")
            if group["containment"] not in _PROCESS_GROUP_CONTAINMENT:
                raise StateError("operation process-group containment is invalid")
            if group["termination"] not in _PROCESS_GROUP_TERMINATION:
                raise StateError("operation process-group termination is invalid")
            if group["detached_sessions"] != "NOT_PORTABLY_OBSERVABLE":
                raise StateError("operation detached-session boundary is invalid")
            isolated = group["isolated"]
            containment = group["containment"]
            termination = group["termination"]
            timed_out = record["timed_out"]
            if not isolated:
                if (
                    containment != "NOT_STARTED"
                    or termination != "NOT_STARTED"
                    or timed_out
                    or exit_code is not None
                    or classification != ("UNKNOWN" if truncated else "INPUT")
                    or "INPUT" not in markers
                ):
                    raise StateError(
                        "non-isolated attempt is not an exact process-launch failure"
                    )
            elif containment == "NOT_STARTED" or termination == "NOT_STARTED":
                raise StateError("isolated attempt contradicts not-started process evidence")
            if termination == "NOT_REQUIRED":
                if (
                    not isolated
                    or containment != "GROUP_EXIT_CONFIRMED"
                    or timed_out
                    or exit_code is None
                ):
                    raise StateError(
                        "non-terminated process evidence contradicts its outcome"
                    )
            elif termination == "NOT_STARTED":
                if isolated or containment != "NOT_STARTED" or timed_out or exit_code is not None:
                    raise StateError("not-started process evidence contradicts its outcome")
            elif not timed_out or exit_code is not None or not isolated:
                raise StateError("process termination evidence requires a timed-out isolated attempt")
            if timed_out != (termination not in {"NOT_REQUIRED", "NOT_STARTED"}):
                raise StateError("timeout and process termination evidence are inconsistent")
            if ("SIGNAL" in markers) != (type(exit_code) is int and exit_code < 0):
                raise StateError("signal marker contradicts the process exit code")
            if timed_out and "TIMEOUT" not in markers:
                raise StateError("timed-out process evidence lacks its failure marker")
            if ("PROCESS_CONTAINMENT" in markers) != (containment == "UNPROVEN"):
                raise StateError("process-containment marker contradicts group evidence")
            expected_classification = _classification_from_attempt_evidence(
                exit_code=exit_code,
                timed_out=timed_out,
                failure_markers=set(markers),
                containment=containment,
                truncated=truncated,
            )
            if classification != expected_classification:
                raise StateError("operation attempt classification violates fixed precedence")
            expected_retry_eligible = (
                not truncated
                and classification == "TRANSPORT"
                and operation.idempotent
                and containment == "GROUP_EXIT_CONFIRMED"
            )
            if record["retry_eligible"] is not expected_retry_eligible:
                raise StateError("operation attempt retry eligibility is inconsistent")
            if containment == "UNPROVEN":
                if termination not in {"TERM_THEN_KILL", "POST_EXIT_TERM_THEN_KILL"}:
                    raise StateError("unproven process containment did not fail closed")
            if classification == "SUCCESS":
                if exit_code != 0 or record["timed_out"]:
                    raise StateError("successful attempt lacks a zero non-timeout exit")
                if (
                    group["isolated"] is not True
                    or group["containment"] != "GROUP_EXIT_CONFIRMED"
                    or group["termination"] != "NOT_REQUIRED"
                ):
                    raise StateError(
                        "successful attempt lacks isolated, unforced process-group exit"
                    )
            elif exit_code == 0 and not record["timed_out"]:
                raise StateError("failed attempt contradicts its zero non-timeout exit")

            if not truncated:
                recomputed_markers = set(
                    _failure_markers(
                        exit_code=exit_code,
                        timed_out=record["timed_out"],
                        stdout=record["stdout"],
                        stderr=record["stderr"],
                    )
                )
                if group["containment"] == "UNPROVEN":
                    recomputed_markers.add("PROCESS_CONTAINMENT")
                if markers != sorted(recomputed_markers):
                    raise StateError("operation attempt failure markers do not revalidate")

            if index < len(records):
                if record["retry_eligible"] is not True:
                    raise StateError("operation ledger contains an unauthorized retry")

        last = records[-1]
        result = state.get("result")
        if type(result) is not dict or set(result) != {
            "classification",
            "failure_markers",
            "exit_code",
            "timed_out",
            "stdout",
            "stderr",
            "stdout_truncated",
            "stderr_truncated",
            "retry_eligible",
            "process_group",
        }:
            raise StateError("operation final result has an invalid schema")
        expected_result = {key: last[key] for key in result}
        if _canonical_json(result) != _canonical_json(expected_result):
            raise StateError("operation final result does not exactly match the last attempt")

        baseline: WorkspaceSnapshot | None = None
        ownership: Mapping[str, Any] = {}
        if validate_workspace:
            _origin, baseline, ownership = self._ownership_from_state(state)
            if ownership.get("verdict") != "SUPPORTED":
                raise StateError("operation workspace ownership is not supported")
        if last["classification"] == "SUCCESS":
            if state.get("lifecycle") != "TERMINAL" or state.get("verdict") != "SUPPORTED":
                raise StateError("successful operation ledger has a non-supported terminal state")
            success_manifest = state.get("workspace_success")
            freshness_manifest = state.get("command_freshness")
            if not isinstance(success_manifest, Mapping) or not isinstance(
                freshness_manifest, Mapping
            ):
                raise StateError("successful operation lacks workspace evidence")
            success = WorkspaceSnapshot.from_manifest(success_manifest)
            if _canonical_json(success_manifest) != _canonical_json(success.to_manifest()):
                raise StateError("successful operation workspace evidence is not canonical")
            if validate_workspace:
                if baseline is None:
                    raise StateError("successful operation lacks a workspace baseline")
                freshness = _exact_command_freshness(success, baseline, ownership)
                if (
                    freshness.get("verdict") != "SUPPORTED"
                    or _canonical_json(freshness_manifest) != _canonical_json(freshness)
                ):
                    raise StateError("successful operation freshness does not revalidate")
            elif (
                type(freshness_manifest) is not dict
                or set(freshness_manifest)
                != {"verdict", "status", "changed_paths", "reason"}
                or freshness_manifest["verdict"] != "SUPPORTED"
                or freshness_manifest["status"] not in {"FRESH", "UNKNOWN"}
                or freshness_manifest["status"] != success.status
                or freshness_manifest["changed_paths"] != []
                or freshness_manifest["reason"] != "exact zero-change command comparison"
                or success.stable is not True
            ):
                raise StateError("historical command freshness has an invalid schema")
        else:
            expected_verdict = (
                "UNKNOWN"
                if last["stdout_truncated"] or last["stderr_truncated"]
                else "FAILED"
            )
            if (
                state.get("lifecycle") != "TERMINAL_ERROR"
                or state.get("verdict") != expected_verdict
            ):
                raise StateError("failed operation ledger has an invalid terminal verdict")
            if (
                state.get("workspace_success") is not None
                or state.get("command_freshness") is not None
            ):
                raise StateError("failed operation ledger retains impossible success evidence")

    def _execute(
        self,
        operation: Operation,
        budget: RetryBudget,
        state: dict[str, Any],
        *,
        lease: ExecutionLease,
    ) -> RunResult:
        records = list(state.get("attempt_records", []))
        for sequence in range(1, budget.attempts + 1):
            started = time.monotonic_ns()
            active = {
                "sequence": sequence,
                "start_monotonic_ns": started,
                "argv_digest": hashlib.sha256("\0".join(operation.argv).encode("utf-8")).hexdigest(),
            }
            state = self.store.update(
                operation.id,
                expected_revision=state["revision"],
                expected_owner=self.owner,
                lifecycle="RUNNING",
                verdict="UNKNOWN",
                active_attempt=active,
            )
            exit_code: int | None
            timed_out = False
            process_group = {
                "isolated": False,
                "containment": "NOT_STARTED",
                "termination": "NOT_STARTED",
                "detached_sessions": "NOT_PORTABLY_OBSERVABLE",
            }
            try:
                with _nofollow_runtime_cwd(
                    self.workspace_root,
                    operation.cwd,
                    expected_repo_identity=self._workspace_identity,
                ) as cwd:
                    completed = _bounded_process(
                        list(operation.argv),
                        cwd=cwd,
                        timeout=operation.timeout_seconds,
                        lease_fd=lease.descriptor,
                        lease_root_fd=lease.root_descriptor,
                    )
                exit_code = completed.exit_code
                timed_out = completed.timed_out
                raw_stdout = completed.stdout
                raw_stderr = completed.stderr
                process_group = completed.process_group
            except OSError as exc:
                exit_code = None
                raw_stdout = b""
                raw_stderr = f"process launch failed: {exc}".encode("utf-8", "replace")
            except ValueError as exc:
                exit_code = None
                raw_stdout = b""
                raw_stderr = (
                    f"process launch failed: unsafe runtime cwd: {exc}"
                ).encode("utf-8", "replace")
            ended = time.monotonic_ns()
            marker_set = set(
                _failure_markers(
                    exit_code=exit_code,
                    timed_out=timed_out,
                    stdout=_decode_output(raw_stdout),
                    stderr=_decode_output(raw_stderr),
                )
            )
            if process_group.get("containment") == "UNPROVEN":
                marker_set.add("PROCESS_CONTAINMENT")
            stdout, stdout_truncated = _redact_and_bound(raw_stdout, self.output_limit)
            stderr, stderr_truncated = _redact_and_bound(raw_stderr, self.output_limit)
            truncated = stdout_truncated or stderr_truncated
            if truncated:
                marker_set.add("OUTPUT_TRUNCATED")
            markers = tuple(sorted(marker_set))
            classification = _classification_from_attempt_evidence(
                exit_code=exit_code,
                timed_out=timed_out,
                failure_markers=marker_set,
                containment=str(process_group.get("containment")),
                truncated=truncated,
            )
            retry_eligible = (
                not truncated
                and classification == "TRANSPORT"
                and operation.idempotent
                and process_group.get("containment") == "GROUP_EXIT_CONFIRMED"
            )
            record = {
                "sequence": sequence,
                "start_monotonic_ns": started,
                "end_monotonic_ns": ended,
                "duration_ns": ended - started,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "classification": classification,
                "failure_markers": list(markers),
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "retry_eligible": retry_eligible,
                "process_group": process_group,
            }
            records.append(record)
            result_manifest = {
                "classification": classification,
                "failure_markers": list(markers),
                "exit_code": exit_code,
                "timed_out": timed_out,
                "stdout": stdout,
                "stderr": stderr,
                "stdout_truncated": stdout_truncated,
                "stderr_truncated": stderr_truncated,
                "retry_eligible": retry_eligible,
                "process_group": process_group,
            }
            if classification == "SUCCESS":
                return self._finish_success(operation, state, records, result_manifest)
            may_retry = retry_eligible and sequence < budget.attempts
            if may_retry:
                next_attempt = sequence + 1
                delay = budget.delay_before(next_attempt, self.jitter_fn)
                state = self.store.update(
                    operation.id,
                    expected_revision=state["revision"],
                    expected_owner=self.owner,
                    lifecycle="RETRY_WAIT",
                    verdict="UNKNOWN",
                    active_attempt=None,
                    attempt_records=records,
                    result=result_manifest,
                    retry={"next_attempt": next_attempt, "delay_seconds": delay},
                )
                self.sleep_fn(delay)
                continue
            state = self.store.update(
                operation.id,
                expected_revision=state["revision"],
                expected_owner=self.owner,
                lifecycle="TERMINAL_ERROR",
                verdict="UNKNOWN" if truncated else "FAILED",
                active_attempt=None,
                attempt_records=records,
                result=result_manifest,
                retry=None,
            )
            return self._result_from_state(state, reuse_status="EXECUTED")
        raise AssertionError("finite retry loop exited without a result")

    def _finish_success(
        self,
        operation: Operation,
        state: dict[str, Any],
        records: list[dict[str, Any]],
        result_manifest: dict[str, Any],
    ) -> RunResult:
        try:
            origin_manifest = state.get("ownership_origin")
            if not isinstance(origin_manifest, Mapping):
                raise ScopeViolation("missing operation ownership origin")
            origin = WorkspaceSnapshot.from_manifest(origin_manifest)
            snapshot = WorkspaceSnapshot.capture(
                self.workspace_root,
                scope=list(operation.scope),
                acknowledged_dirty=list(origin.acknowledged_dirty),
            )
            _origin, baseline, ownership = self._ownership_from_state(state)
            freshness = _exact_command_freshness(snapshot, baseline, ownership)
        except ScopeViolation as exc:
            snapshot = WorkspaceSnapshot.capture(self.workspace_root, scope=list(operation.scope))
            freshness = {
                "verdict": "FAILED" if _deterministic_scope_failure(exc) else "UNKNOWN",
                "reason": str(exc),
            }
        if freshness["verdict"] != "SUPPORTED":
            verdict = str(freshness["verdict"])
            state = self.store.update(
                operation.id,
                expected_revision=state["revision"],
                expected_owner=self.owner,
                lifecycle="TERMINAL_ERROR",
                verdict=verdict,
                active_attempt=None,
                attempt_records=records,
                result=result_manifest,
                workspace_success=snapshot.to_manifest(),
                command_freshness=freshness,
            )
            return self._result_from_state(state, reuse_status="EXECUTED")
        return self._strict_write_supported(operation, state, records, result_manifest, snapshot)

    def _strict_write_supported(
        self,
        operation: Operation,
        state: dict[str, Any],
        records: list[dict[str, Any]],
        result_manifest: dict[str, Any],
        snapshot: WorkspaceSnapshot,
    ) -> RunResult:
        """The sole runner transition that can create TERMINAL/SUPPORTED."""

        binding, binding_digest = self._binding(operation)
        ownership: Mapping[str, Any] = {}
        try:
            _origin, baseline, ownership = self._ownership_from_state(state)
            freshness = _exact_command_freshness(snapshot, baseline, ownership)
        except (ScopeViolation, TypeError):
            freshness = {"verdict": "UNKNOWN"}
        if (
            not records
            or records[-1].get("classification") != "SUCCESS"
            or records[-1].get("exit_code") != 0
            or records[-1].get("timed_out")
            or state.get("binding") != _display_binding(binding)
            or state.get("binding_digest") != binding_digest
            or not snapshot.stable
            or ownership.get("verdict") != "SUPPORTED"
            or freshness.get("verdict") != "SUPPORTED"
        ):
            raise StateError("strict runner verifier rejected incomplete success evidence")
        state = self.store.update(
            operation.id,
            expected_revision=state["revision"],
            expected_owner=self.owner,
            lifecycle="TERMINAL",
            verdict="SUPPORTED",
            active_attempt=None,
            attempt_records=records,
            result=result_manifest,
            workspace_success=snapshot.to_manifest(),
            command_freshness=freshness,
            retry=None,
        )
        return self._result_from_state(state, reuse_status="EXECUTED")


__all__ = [
    "Operation",
    "RetryBudget",
    "RunResult",
    "TaskRunner",
    "classify_failure",
    "valid_expected_red",
]
