"""Closed, explicit provider registration by identity/action/environment."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Iterable


class AdapterRegistrationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AdapterContext:
    mode: str
    endpoint: str | None = None


@dataclass(frozen=True, slots=True)
class AdapterRegistration:
    adapter_id: str
    adapter_version: str
    supported_actions: tuple[str, ...]
    allowed_environments: tuple[str, ...]
    factory: Callable[[AdapterContext], Any]
    production_enabled: bool = False

    def __post_init__(self) -> None:
        values = (self.adapter_id, self.adapter_version, *self.supported_actions, *self.allowed_environments)
        if any(type(item) is not str or not item or any(token in item for token in ("*", "?", "[", "]")) for item in values):
            raise AdapterRegistrationError("adapter registration requires exact non-wildcard values")
        if not self.supported_actions or not self.allowed_environments:
            raise AdapterRegistrationError("adapter registration requires actions and environments")


class AdapterRegistrationRegistry:
    def __init__(self, registrations: Iterable[AdapterRegistration] = (), *, allow_production: bool = False) -> None:
        values: dict[str, AdapterRegistration] = {}
        for registration in registrations:
            if registration.adapter_id in values:
                raise AdapterRegistrationError(f"duplicate adapter registration: {registration.adapter_id}")
            if registration.production_enabled and not allow_production:
                raise AdapterRegistrationError("production registration requires an explicitly trusted registry")
            values[registration.adapter_id] = registration
        self._values = values

    def registrations(self) -> tuple[AdapterRegistration, ...]:
        return tuple(self._values[key] for key in sorted(self._values))

    def resolve(self, adapter_id: str, *, action_kind: str, environment: str) -> AdapterRegistration | None:
        registration = self._values.get(adapter_id)
        if registration is None:
            return None
        if action_kind not in registration.supported_actions or environment not in registration.allowed_environments:
            return None
        if environment == "production" and not registration.production_enabled:
            return None
        return registration

    def instantiate(self, adapter_id: str, *, action_kind: str, environment: str, context: AdapterContext) -> Any | None:
        registration = self.resolve(adapter_id, action_kind=action_kind, environment=environment)
        if registration is None:
            return None
        adapter = registration.factory(context)
        if (
            getattr(adapter, "adapter_id", None) != registration.adapter_id
            or getattr(adapter, "adapter_version", None) != registration.adapter_version
        ):
            raise AdapterRegistrationError("adapter factory returned a mismatched identity")
        return adapter


def default_adapter_registry() -> AdapterRegistrationRegistry:
    return AdapterRegistrationRegistry()
