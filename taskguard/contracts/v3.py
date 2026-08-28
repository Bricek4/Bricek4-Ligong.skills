"""Strict immutable TaskGuard Contract v3 parser."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping

from ..contract import Acceptance, ContractError, validate_contract as validate_v2_contract
from ..validation import canonical_json_bytes, exact_object, load_strict_json


TOP_LEVEL_FIELDS = frozenset({"version", "task_id", "goal", "risk", "repo_contract", "actions"})
REPO_FIELDS = frozenset({"repo", "repo_scope", "acknowledge_dirty", "acceptance", "forbidden", "surfaces"})
ACTION_FIELDS = frozenset({
    "id", "kind", "adapter", "target", "environment", "resource_scope", "desired_state",
    "preconditions", "authority_policy", "plan_policy", "rollback_policy", "health_policy",
})
TARGET_FIELDS = frozenset({"provider", "account_id", "project_id", "resource_id"})
AUTHORITY_FIELDS = frozenset({"provider", "bind_plan", "max_uses"})
PLAN_FIELDS = frozenset({"max_age_seconds"})
ROLLBACK_FIELDS = frozenset({"required", "preauthorize", "automatic_on_health_failure"})
HEALTH_FIELDS = frozenset({"window_seconds", "minimum_samples", "required_signals"})
SUPPORTED_ACTION_KINDS = frozenset({"deploy", "write", "update", "publish"})
SUPPORTED_ENVIRONMENTS = frozenset({"sandbox", "staging", "production"})


class ContractV3Error(ContractError):
    """Strict v3 structural or policy rejection."""


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or "\x00" in value:
        raise ContractV3Error(f"{label} must be a non-empty string")
    return value


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ContractV3Error(f"{label} must be a positive integer")
    return value


def _bool(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ContractV3Error(f"{label} must be a boolean")
    return value


def _json_object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise ContractV3Error(f"{label} must be an object")
    canonical_json_bytes(value)
    return _freeze_json(value)


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _exact(value: Any, label: str, fields: frozenset[str]) -> dict[str, Any]:
    try:
        return exact_object(value, label=label, required=set(fields))
    except ValueError as exc:
        raise ContractV3Error(str(exc)) from exc


@dataclass(frozen=True, slots=True)
class ActionTarget:
    provider: str
    account_id: str
    project_id: str
    resource_id: str

    def to_manifest(self) -> dict[str, str]:
        return {
            "provider": self.provider,
            "account_id": self.account_id,
            "project_id": self.project_id,
            "resource_id": self.resource_id,
        }


@dataclass(frozen=True, slots=True)
class RepoContractV3:
    repo: Path
    repo_scope: tuple[str, ...]
    acknowledge_dirty: tuple[str, ...]
    acceptance: tuple[Acceptance, ...]
    forbidden: tuple[Mapping[str, Any], ...]
    surfaces: tuple[Mapping[str, Any], ...]

    def to_manifest(self) -> dict[str, Any]:
        return {
            "repo": str(self.repo),
            "repo_scope": list(self.repo_scope),
            "acknowledge_dirty": list(self.acknowledge_dirty),
            "acceptance": [
                {
                    "id": item.id,
                    "argv": list(item.argv),
                    "cwd": item.cwd,
                    "requires_red": item.requires_red,
                    "expected_red_pattern": item.expected_red_pattern,
                    "idempotent": item.idempotent,
                    **({"selector": item.selector} if item.selector is not None else {}),
                }
                for item in self.acceptance
            ],
            "forbidden": [dict(item) for item in self.forbidden],
            "surfaces": [dict(item) for item in self.surfaces],
        }


@dataclass(frozen=True, slots=True)
class ActionSpec:
    id: str
    kind: str
    adapter: str
    target: ActionTarget
    environment: str
    resource_scope: Mapping[str, Any]
    desired_state: Mapping[str, Any]
    preconditions: Mapping[str, Any]
    authority_policy: Mapping[str, Any]
    plan_policy: Mapping[str, Any]
    rollback_policy: Mapping[str, Any]
    health_policy: Mapping[str, Any]

    def to_manifest(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "adapter": self.adapter,
            "target": self.target.to_manifest(),
            "environment": self.environment,
            "resource_scope": _thaw_json(self.resource_scope),
            "desired_state": _thaw_json(self.desired_state),
            "preconditions": _thaw_json(self.preconditions),
            "authority_policy": dict(self.authority_policy),
            "plan_policy": dict(self.plan_policy),
            "rollback_policy": dict(self.rollback_policy),
            "health_policy": {
                **dict(self.health_policy),
                "required_signals": list(self.health_policy["required_signals"]),
            },
        }


@dataclass(frozen=True, slots=True)
class ContractV3:
    version: Literal[3]
    task_id: str
    goal: str
    risk: Literal["L3"]
    repo_contract: RepoContractV3
    actions: tuple[ActionSpec, ...]

    def to_manifest(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "task_id": self.task_id,
            "goal": self.goal,
            "risk": self.risk,
            "repo_contract": self.repo_contract.to_manifest(),
            "actions": [action.to_manifest() for action in self.actions],
        }


def _parse_repo(raw: Any, workspace_root: str | Path | None) -> RepoContractV3:
    value = _exact(raw, "repo_contract", REPO_FIELDS)
    acceptance_raw = value["acceptance"]
    if not isinstance(acceptance_raw, list):
        raise ContractV3Error("repo_contract.acceptance must be an array")
    projected_acceptance = acceptance_raw or [{
        "id": "__v3_structural_projection__",
        "argv": ["python3", "-c", "pass"],
        "cwd": ".",
        "requires_red": False,
        "expected_red_pattern": None,
        "idempotent": True,
    }]
    v2_raw = {
        "version": 2,
        "task_id": "v3-repo-projection",
        "goal": "validate v3 repository contract",
        "risk": "L2",
        "repo": value["repo"],
        "scope": value["repo_scope"],
        "acknowledge_dirty": value["acknowledge_dirty"],
        "acceptance": projected_acceptance,
        "forbidden": value["forbidden"],
        "surfaces": value["surfaces"],
    }
    try:
        parsed = validate_v2_contract(v2_raw, workspace_root=workspace_root)
    except ContractError as exc:
        raise ContractV3Error(f"repo_contract: {exc}") from exc
    return RepoContractV3(
        parsed.repo,
        tuple(parsed.scope),
        tuple(parsed.acknowledge_dirty),
        tuple(parsed.acceptance if acceptance_raw else ()),
        tuple(MappingProxyType(dict(item)) for item in parsed.forbidden),
        tuple(MappingProxyType(dict(item)) for item in parsed.surfaces),
    )


def _parse_action(raw: Any, index: int) -> ActionSpec:
    label = f"actions[{index}]"
    value = _exact(raw, label, ACTION_FIELDS)
    kind = _text(value["kind"], f"{label}.kind")
    if kind not in SUPPORTED_ACTION_KINDS:
        raise ContractV3Error(f"{label}.kind: unsupported action kind {kind!r}")
    environment = _text(value["environment"], f"{label}.environment")
    if environment not in SUPPORTED_ENVIRONMENTS:
        raise ContractV3Error(f"{label}.environment: unsupported environment")
    target_raw = _exact(value["target"], f"{label}.target", TARGET_FIELDS)
    target = ActionTarget(**{
        field: _text(target_raw[field], f"{label}.target.{field}") for field in TARGET_FIELDS
    })

    authority = _exact(value["authority_policy"], f"{label}.authority_policy", AUTHORITY_FIELDS)
    authority_parsed = MappingProxyType({
        "provider": _text(authority["provider"], f"{label}.authority_policy.provider"),
        "bind_plan": _bool(authority["bind_plan"], f"{label}.authority_policy.bind_plan"),
        "max_uses": _positive_int(authority["max_uses"], f"{label}.authority_policy.max_uses"),
    })
    plan = _exact(value["plan_policy"], f"{label}.plan_policy", PLAN_FIELDS)
    plan_parsed = MappingProxyType({
        "max_age_seconds": _positive_int(plan["max_age_seconds"], f"{label}.plan_policy.max_age_seconds")
    })
    rollback = _exact(value["rollback_policy"], f"{label}.rollback_policy", ROLLBACK_FIELDS)
    rollback_parsed = MappingProxyType({key: _bool(rollback[key], f"{label}.rollback_policy.{key}") for key in ROLLBACK_FIELDS})
    if kind in {"deploy", "write", "update", "publish"} and not rollback_parsed["required"]:
        raise ContractV3Error(f"{label}.rollback_policy.required must be true for mutating actions")
    if rollback_parsed["automatic_on_health_failure"] and not rollback_parsed["required"]:
        raise ContractV3Error(f"{label}.rollback_policy automatic rollback requires rollback")
    health = _exact(value["health_policy"], f"{label}.health_policy", HEALTH_FIELDS)
    signals = health["required_signals"]
    if not isinstance(signals, list) or not signals or any(type(item) is not str or not item for item in signals):
        raise ContractV3Error(f"{label}.health_policy.required_signals must be a non-empty string array")
    if len(signals) != len(set(signals)):
        raise ContractV3Error(f"{label}.health_policy.required_signals contains duplicates")
    health_parsed = MappingProxyType({
        "window_seconds": _positive_int(health["window_seconds"], f"{label}.health_policy.window_seconds"),
        "minimum_samples": _positive_int(health["minimum_samples"], f"{label}.health_policy.minimum_samples"),
        "required_signals": tuple(signals),
    })
    return ActionSpec(
        id=_text(value["id"], f"{label}.id"),
        kind=kind,
        adapter=_text(value["adapter"], f"{label}.adapter"),
        target=target,
        environment=environment,
        resource_scope=_json_object(value["resource_scope"], f"{label}.resource_scope"),
        desired_state=_json_object(value["desired_state"], f"{label}.desired_state"),
        preconditions=_json_object(value["preconditions"], f"{label}.preconditions"),
        authority_policy=authority_parsed,
        plan_policy=plan_parsed,
        rollback_policy=rollback_parsed,
        health_policy=health_parsed,
    )


def validate_contract_v3(raw: Any, workspace_root: str | Path | None = None) -> ContractV3:
    value = _exact(raw, "contract", TOP_LEVEL_FIELDS)
    if type(value["version"]) is not int or value["version"] != 3:
        raise ContractV3Error("contract.version must be integer 3")
    if value["risk"] != "L3":
        raise ContractV3Error("contract.risk must be L3")
    actions_raw = value["actions"]
    if not isinstance(actions_raw, list) or not actions_raw:
        raise ContractV3Error("contract.actions must be a non-empty array")
    actions = tuple(_parse_action(item, index) for index, item in enumerate(actions_raw))
    ids = [item.id for item in actions]
    if len(ids) != len(set(ids)):
        raise ContractV3Error("contract.actions contains duplicate action IDs")
    if len(actions) != 1:
        raise ContractV3Error("MULTI_ACTION_NOT_ENABLED")
    return ContractV3(
        version=3,
        task_id=_text(value["task_id"], "contract.task_id"),
        goal=_text(value["goal"], "contract.goal"),
        risk="L3",
        repo_contract=_parse_repo(value["repo_contract"], workspace_root),
        actions=actions,
    )


def load_contract_v3(path: str | Path, workspace_root: str | Path | None = None) -> ContractV3:
    source = Path(path)
    try:
        raw = load_strict_json(source)
    except (OSError, ValueError) as exc:
        raise ContractV3Error(f"contract file {source}: {exc}") from exc
    base = source.parent if workspace_root is None else workspace_root
    return validate_contract_v3(raw, workspace_root=base)


__all__ = [
    "ActionSpec", "ActionTarget", "ContractV3", "ContractV3Error", "RepoContractV3",
    "load_contract_v3", "validate_contract_v3",
]
