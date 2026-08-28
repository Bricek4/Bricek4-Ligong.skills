"""Managed SSS risk-chain state bound to a TaskGuard state directory."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
from typing import Any, Mapping

from taskguard.risk import CapsuleError, validate_capsule
from taskguard.state import StateError, StateStore
from taskguard.workspace import WorkspaceSnapshot


_CHAIN_ID = "risk-chain"
_PREVIOUS_STAGE = {"diff": "initial", "final": "diff"}


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def _final_binding(
    state_dir: os.PathLike[str] | str,
    *,
    task_id: str,
) -> dict[str, object]:
    task = StateStore(state_dir).load("task")
    contract = task.get("contract")
    if type(contract) is not dict or contract.get("task_id") != task_id:
        raise StateError("final risk stage has no matching TaskGuard task state")
    acceptance = task.get("obligations", {}).get("acceptance", {})
    required_ids = [str(item.get("id")) for item in contract.get("acceptance", [])]
    if any(
        type(acceptance.get(acceptance_id, {}).get("candidate")) is not dict
        or acceptance[acceptance_id]["candidate"].get("verdict") != "SUPPORTED"
        for acceptance_id in required_ids
    ):
        raise StateError("final risk stage requires current supported candidate evidence")
    snapshot = WorkspaceSnapshot.capture(
        Path(str(contract.get("repo"))),
        scope=list(contract.get("scope", [])),
        acknowledged_dirty=list(contract.get("acknowledge_dirty", [])),
    )
    return {
        "task_revision": task["revision"],
        "task_checksum": task["checksum"],
        "workspace_digest": _digest(snapshot.to_manifest()),
    }


def load_previous(
    state_dir: os.PathLike[str] | str,
    *,
    task_id: str,
    stage: str,
) -> dict[str, object]:
    """Load the controller-owned previous stage for a diff/final preflight."""

    if stage not in _PREVIOUS_STAGE:
        raise CapsuleError("managed previous state is only valid for diff or final")
    state = StateStore(state_dir).load(_CHAIN_ID)
    if state.get("task_id") != task_id or state.get("stage") != _PREVIOUS_STAGE[stage]:
        raise CapsuleError("managed risk chain does not bind the required task and stage")
    result = state.get("result")
    if type(result) is not dict:
        raise StateError("managed risk chain result is missing")
    return copy.deepcopy(result)


def commit_result(
    state_dir: os.PathLike[str] | str,
    result: Mapping[str, object],
    capsule: object,
) -> dict[str, Any]:
    """Create or advance one admitted chain using optimistic revision checks."""

    parsed = validate_capsule(capsule)
    binding = {
        "task_id": parsed["task_id"],
        "outcome": parsed["outcome"],
        "scope": list(parsed["scope"]),
        "risk": parsed["risk"],
    }
    if result.get("admitted") is not True:
        raise CapsuleError("only admitted risk results can advance the managed chain")
    stage = result.get("stage")
    task_id = result.get("task_id")
    if (
        stage not in {"initial", "diff", "final"}
        or type(task_id) is not str
        or task_id != binding["task_id"]
    ):
        raise CapsuleError("risk result cannot bind managed chain state")
    store = StateStore(state_dir)
    state_path = Path(state_dir) / f"{_CHAIN_ID}.json"
    if stage == "initial":
        if os.path.lexists(state_path):
            raise CapsuleError("managed risk chain already exists; initial cannot restart")
        return store.create(
            _CHAIN_ID,
            owner="risk-chain-" + secrets.token_hex(12),
            task_id=task_id,
            binding=binding,
            final_binding=None,
            stage="initial",
            result=copy.deepcopy(dict(result)),
        )
    current = store.load(_CHAIN_ID)
    if (
        current.get("task_id") != task_id
        or current.get("binding") != binding
        or current.get("stage") != _PREVIOUS_STAGE[stage]
    ):
        raise CapsuleError("managed risk chain cannot skip, restart, or cross tasks")
    previous = result.get("previous")
    if type(previous) is not dict or previous.get("result_digest") != current.get(
        "result", {}
    ).get("result_digest"):
        raise CapsuleError("risk result is not anchored to managed previous state")
    final_binding = (
        _final_binding(state_dir, task_id=task_id) if stage == "final" else None
    )
    return store.update(
        _CHAIN_ID,
        expected_revision=int(current["revision"]),
        expected_owner=str(current["owner"]),
        task_id=task_id,
        binding=binding,
        final_binding=final_binding,
        stage=stage,
        result=copy.deepcopy(dict(result)),
    )


def require_stage(
    state_dir: os.PathLike[str] | str,
    *,
    task_id: str,
    goal: str,
    scope: list[str],
    stage: str,
    risk: str,
) -> dict[str, Any]:
    """Require an admitted chain stage before TaskGuard L2 admission/completion."""

    state = StateStore(state_dir).load(_CHAIN_ID)
    result = state.get("result")
    if (
        state.get("task_id") != task_id
        or state.get("binding")
        != {"task_id": task_id, "outcome": goal, "scope": scope, "risk": risk}
        or state.get("stage") != stage
        or type(result) is not dict
        or result.get("task_id") != task_id
        or result.get("stage") != stage
        or result.get("effective_risk") != risk
        or result.get("admitted") is not True
    ):
        raise StateError("managed risk chain does not satisfy TaskGuard admission")
    if stage == "final" and state.get("final_binding") != _final_binding(
        state_dir, task_id=task_id
    ):
        raise StateError("final risk chain is stale relative to task state or workspace")
    return state


__all__ = ["commit_result", "load_previous", "require_stage"]
