"""Pure, exhaustive lifecycle reducer for one external action."""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping


class ActionLifecycle(str, Enum):
    DECLARED = "DECLARED"
    PREFLIGHTED = "PREFLIGHTED"
    PLANNED = "PLANNED"
    AUTHORIZED = "AUTHORIZED"
    ROLLBACK_READY = "ROLLBACK_READY"
    APPLY_INTENT_WRITTEN = "APPLY_INTENT_WRITTEN"
    APPLYING = "APPLYING"
    EFFECT_UNKNOWN = "EFFECT_UNKNOWN"
    RECONCILING = "RECONCILING"
    NOT_APPLIED = "NOT_APPLIED"
    APPLIED = "APPLIED"
    OBSERVING = "OBSERVING"
    HEALTHY = "HEALTHY"
    HEALTH_FAILED = "HEALTH_FAILED"
    ROLLBACK_REQUIRED = "ROLLBACK_REQUIRED"
    ROLLBACK_INTENT_WRITTEN = "ROLLBACK_INTENT_WRITTEN"
    ROLLING_BACK = "ROLLING_BACK"
    ROLLBACK_UNKNOWN = "ROLLBACK_UNKNOWN"
    ROLLED_BACK = "ROLLED_BACK"
    RECOVERY_OBSERVING = "RECOVERY_OBSERVING"
    RECOVERED = "RECOVERED"
    TERMINAL = "TERMINAL"
    TERMINAL_ERROR = "TERMINAL_ERROR"


class ActionEvent(str, Enum):
    PREFLIGHT = "PREFLIGHT"
    PLAN = "PLAN"
    AUTHORIZE = "AUTHORIZE"
    PROVE_ROLLBACK_READY = "PROVE_ROLLBACK_READY"
    WRITE_APPLY_INTENT = "WRITE_APPLY_INTENT"
    START_APPLY = "START_APPLY"
    APPLY_CONFIRMED = "APPLY_CONFIRMED"
    APPLY_UNKNOWN = "APPLY_UNKNOWN"
    START_RECONCILE = "START_RECONCILE"
    RECONCILE_APPLIED = "RECONCILE_APPLIED"
    RECONCILE_NOT_APPLIED = "RECONCILE_NOT_APPLIED"
    START_OBSERVE = "START_OBSERVE"
    HEALTH_PASS = "HEALTH_PASS"
    HEALTH_FAIL = "HEALTH_FAIL"
    REQUIRE_ROLLBACK = "REQUIRE_ROLLBACK"
    WRITE_ROLLBACK_INTENT = "WRITE_ROLLBACK_INTENT"
    START_ROLLBACK = "START_ROLLBACK"
    ROLLBACK_CONFIRMED = "ROLLBACK_CONFIRMED"
    ROLLBACK_UNKNOWN = "ROLLBACK_UNKNOWN"
    START_RECOVERY_OBSERVE = "START_RECOVERY_OBSERVE"
    RECOVERY_HEALTHY = "RECOVERY_HEALTHY"
    FINALIZE_SUCCESS = "FINALIZE_SUCCESS"
    FINALIZE_ERROR = "FINALIZE_ERROR"


TRANSITIONS = MappingProxyType({
    (ActionLifecycle.DECLARED, ActionEvent.PREFLIGHT): ActionLifecycle.PREFLIGHTED,
    (ActionLifecycle.PREFLIGHTED, ActionEvent.PLAN): ActionLifecycle.PLANNED,
    (ActionLifecycle.PLANNED, ActionEvent.AUTHORIZE): ActionLifecycle.AUTHORIZED,
    (ActionLifecycle.AUTHORIZED, ActionEvent.PROVE_ROLLBACK_READY): ActionLifecycle.ROLLBACK_READY,
    (ActionLifecycle.ROLLBACK_READY, ActionEvent.WRITE_APPLY_INTENT): ActionLifecycle.APPLY_INTENT_WRITTEN,
    (ActionLifecycle.APPLY_INTENT_WRITTEN, ActionEvent.START_APPLY): ActionLifecycle.APPLYING,
    (ActionLifecycle.APPLYING, ActionEvent.APPLY_CONFIRMED): ActionLifecycle.APPLIED,
    (ActionLifecycle.APPLYING, ActionEvent.APPLY_UNKNOWN): ActionLifecycle.EFFECT_UNKNOWN,
    (ActionLifecycle.EFFECT_UNKNOWN, ActionEvent.START_RECONCILE): ActionLifecycle.RECONCILING,
    (ActionLifecycle.RECONCILING, ActionEvent.RECONCILE_APPLIED): ActionLifecycle.APPLIED,
    (ActionLifecycle.RECONCILING, ActionEvent.RECONCILE_NOT_APPLIED): ActionLifecycle.NOT_APPLIED,
    (ActionLifecycle.APPLIED, ActionEvent.START_OBSERVE): ActionLifecycle.OBSERVING,
    (ActionLifecycle.OBSERVING, ActionEvent.HEALTH_PASS): ActionLifecycle.HEALTHY,
    (ActionLifecycle.OBSERVING, ActionEvent.HEALTH_FAIL): ActionLifecycle.HEALTH_FAILED,
    (ActionLifecycle.HEALTH_FAILED, ActionEvent.REQUIRE_ROLLBACK): ActionLifecycle.ROLLBACK_REQUIRED,
    (ActionLifecycle.ROLLBACK_REQUIRED, ActionEvent.WRITE_ROLLBACK_INTENT): ActionLifecycle.ROLLBACK_INTENT_WRITTEN,
    (ActionLifecycle.ROLLBACK_INTENT_WRITTEN, ActionEvent.START_ROLLBACK): ActionLifecycle.ROLLING_BACK,
    (ActionLifecycle.ROLLING_BACK, ActionEvent.ROLLBACK_CONFIRMED): ActionLifecycle.ROLLED_BACK,
    (ActionLifecycle.ROLLING_BACK, ActionEvent.ROLLBACK_UNKNOWN): ActionLifecycle.ROLLBACK_UNKNOWN,
    (ActionLifecycle.ROLLED_BACK, ActionEvent.START_RECOVERY_OBSERVE): ActionLifecycle.RECOVERY_OBSERVING,
    (ActionLifecycle.ROLLBACK_UNKNOWN, ActionEvent.START_RECOVERY_OBSERVE): ActionLifecycle.RECOVERY_OBSERVING,
    (ActionLifecycle.RECOVERY_OBSERVING, ActionEvent.RECOVERY_HEALTHY): ActionLifecycle.RECOVERED,
    (ActionLifecycle.HEALTHY, ActionEvent.FINALIZE_SUCCESS): ActionLifecycle.TERMINAL,
    (ActionLifecycle.NOT_APPLIED, ActionEvent.FINALIZE_ERROR): ActionLifecycle.TERMINAL_ERROR,
    (ActionLifecycle.HEALTH_FAILED, ActionEvent.FINALIZE_ERROR): ActionLifecycle.TERMINAL_ERROR,
    (ActionLifecycle.RECOVERED, ActionEvent.FINALIZE_ERROR): ActionLifecycle.TERMINAL_ERROR,
})


class InvalidTransition(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class ActionState:
    lifecycle: ActionLifecycle
    revision: int
    evidence: tuple[str, ...] = ()
    failure_reason: str | None = None


def reduce_action(state: ActionState, event: ActionEvent, payload: Mapping[str, Any] | None = None) -> ActionState:
    try:
        lifecycle = TRANSITIONS[(state.lifecycle, event)]
    except KeyError as exc:
        raise InvalidTransition(f"invalid action transition: {state.lifecycle.value}/{event.value}") from exc
    value = dict(payload or {})
    evidence_ref = value.get("evidence_ref")
    if evidence_ref is not None and (type(evidence_ref) is not str or not evidence_ref):
        raise InvalidTransition("event evidence_ref must be non-empty")
    failure = value.get("failure_reason")
    if event in {ActionEvent.APPLY_UNKNOWN, ActionEvent.HEALTH_FAIL, ActionEvent.ROLLBACK_UNKNOWN, ActionEvent.FINALIZE_ERROR}:
        if type(failure) is not str or not failure:
            raise InvalidTransition(f"{event.value} requires failure_reason")
    return replace(
        state,
        lifecycle=lifecycle,
        revision=state.revision + 1,
        evidence=state.evidence + ((evidence_ref,) if evidence_ref else ()),
        failure_reason=failure if failure is not None else state.failure_reason,
    )
