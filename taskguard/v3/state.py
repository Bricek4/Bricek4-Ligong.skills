"""Protocol-3 state envelope over the hardened atomic StateStore."""

from __future__ import annotations

from pathlib import Path
import os
from typing import Any, Mapping

from ..state import StateStore


TASK_STATE_ID = "task"


class V3State:
    def __init__(self, root: str | Path) -> None:
        self.store = StateStore(root)

    def prepare(self) -> None:
        """Create and descriptor-validate the private state root before evidence writes."""

        descriptor = self.store._open_root()
        os.close(descriptor)

    def create(self, manifest: Mapping[str, Any]) -> dict[str, Any]:
        if manifest.get("protocol_version") != 3:
            raise ValueError("v3 state requires protocol_version 3")
        fields = dict(manifest)
        fields.pop("owner", None)
        return self.store.create(TASK_STATE_ID, owner="taskguard-v3", **fields)

    def load(self) -> dict[str, Any]:
        state = self.store.load(TASK_STATE_ID)
        if state.get("protocol_version") != 3:
            raise ValueError("state is not TaskGuard protocol 3")
        return state

    def update(self, state: Mapping[str, Any], **changes: Any) -> dict[str, Any]:
        return self.store.update(
            TASK_STATE_ID,
            expected_revision=state["revision"],
            expected_owner=state["owner"],
            **changes,
        )
