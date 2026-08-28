"""Read-only, checksummed evidence export for an existing TaskGuard state."""

from __future__ import annotations

import copy
import hashlib
import json
from os import PathLike
import os
from pathlib import Path
from typing import Any

from taskguard.state import StateStore


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def export_evidence(state_dir: PathLike[str] | str) -> dict[str, Any]:
    """Return a self-digesting evidence bundle without mutating guarded state."""

    root = Path(state_dir)
    store = StateStore(root)
    task = store.load_snapshot("task")
    persisted_aggregate = str(task.get("aggregate", task["verdict"]))
    aggregate = "UNKNOWN" if persisted_aggregate == "SUPPORTED" else persisted_aggregate
    status = {
        "aggregate": aggregate,
        "freshness": "SNAPSHOT_ONLY",
        "lifecycle": task["lifecycle"],
        "persisted_aggregate": persisted_aggregate,
        "revision": task["revision"],
        "verdict": task["verdict"],
    }
    checkpoint_path = root / "checkpoint.json"
    checkpoint = (
        store.load_snapshot("checkpoint")
        if os.path.lexists(checkpoint_path)
        else None
    )
    task_binding = {
        key: copy.deepcopy(task.get(key))
        for key in (
            "operation_id",
            "owner",
            "lifecycle",
            "verdict",
            "revision",
            "checksum",
            "contract_digest",
            "admission_anchor",
            "verification_receipt",
        )
    }
    bundle: dict[str, Any] = {
        "version": "taskguard-evidence-v1",
        "status": copy.deepcopy(status),
        "task": task_binding,
        "checkpoint": copy.deepcopy(checkpoint),
    }
    bundle["task_digest"] = hashlib.sha256(_canonical_bytes(task_binding)).hexdigest()
    bundle["bundle_digest"] = hashlib.sha256(_canonical_bytes(bundle)).hexdigest()
    return bundle


__all__ = ["export_evidence"]
