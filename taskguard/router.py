"""Deterministic TaskGuard protocol resolution and backend routing."""

from __future__ import annotations

from pathlib import Path
from typing import Mapping, Sequence

from .backends.base import Backend
from .backends.v2 import V2Backend
from .state import StateStore
from .validation import load_strict_json
from .v3.backend import V3Backend


class ProtocolResolutionError(ValueError):
    pass


class UnsupportedProtocol(ProtocolResolutionError):
    pass


class UnrecognizedTaskProtocol(ProtocolResolutionError):
    pass


class ProtocolMismatch(ProtocolResolutionError):
    pass


class BackendRegistry:
    def __init__(self, backends: Mapping[int, Backend]) -> None:
        self._backends = dict(backends)

    def require(self, version: int) -> Backend:
        if type(version) is not int or version not in self._backends:
            raise UnsupportedProtocol(f"unsupported TaskGuard protocol: {version!r}")
        return self._backends[version]


DEFAULT_BACKENDS = BackendRegistry({2: V2Backend(), 3: V3Backend()})
_V3_ONLY_COMMANDS = frozenset({
    "validate", "explain", "doctor-v3", "provider-readiness", "shadow", "plan",
    "apply", "reconcile", "rollback", "health",
})


def protocol_from_contract(raw: object) -> int:
    if not isinstance(raw, dict) or "version" not in raw:
        raise UnsupportedProtocol("contract has no explicit TaskGuard protocol version")
    version = raw["version"]
    if type(version) is not int or version not in {2, 3}:
        raise UnsupportedProtocol(f"unsupported TaskGuard protocol: {version!r}")
    return version


def protocol_from_task_manifest(task: object) -> int:
    if not isinstance(task, dict):
        raise UnrecognizedTaskProtocol("task state must be an object")
    if task.get("protocol_version") == 3:
        if type(task.get("protocol_version")) is int and type(task.get("task_id")) is str:
            return 3
        raise UnrecognizedTaskProtocol("malformed TaskGuard protocol-3 state")
    contract = task.get("contract")
    if (
        isinstance(contract, dict)
        and contract.get("binding_version") == "taskguard-contract-binding-v2"
        and type(contract.get("version")) is int
        and contract["version"] == 2
    ):
        return 2
    raise UnrecognizedTaskProtocol("state has no recognized TaskGuard protocol binding")


def _argument(argv: Sequence[str], name: str) -> str | None:
    try:
        index = list(argv).index(name)
    except ValueError:
        return None
    if index + 1 >= len(argv):
        return None
    return argv[index + 1]


def resolve_protocol(command: str, contract_path: str | Path | None, state_dir: str | Path | None) -> int:
    contract_version: int | None = None
    state_version: int | None = None
    if contract_path is not None:
        contract_version = protocol_from_contract(load_strict_json(contract_path))
    if state_dir is not None and command != "init":
        state_version = protocol_from_task_manifest(StateStore(state_dir).load("task"))
    if contract_version is not None and state_version is not None and contract_version != state_version:
        raise ProtocolMismatch(f"contract protocol {contract_version} does not match state protocol {state_version}")
    if command in _V3_ONLY_COMMANDS and contract_version is None and state_version is None:
        return 3
    if contract_version is not None:
        return contract_version
    if state_version is not None:
        return state_version
    if command in {"run", "verify", "status", "checkpoint", "dispose", "export"} and state_dir is None:
        return 2
    raise UnsupportedProtocol("cannot resolve TaskGuard protocol without contract or state")


def route_command(argv: Sequence[str], registry: BackendRegistry | None = None) -> Backend:
    if not argv:
        return (registry or DEFAULT_BACKENDS).require(2)
    command = argv[0]
    if any(item in {"-h", "--help"} for item in argv[1:]):
        version = 3 if command in _V3_ONLY_COMMANDS else 2
        return (registry or DEFAULT_BACKENDS).require(version)
    version = resolve_protocol(command, _argument(argv, "--contract"), _argument(argv, "--state-dir"))
    return (registry or DEFAULT_BACKENDS).require(version)


def route_main(argv: Sequence[str], registry: BackendRegistry | None = None) -> int:
    return route_command(argv, registry).main(argv)
