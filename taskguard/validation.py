"""Shared strict JSON and canonicalization primitives."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any, Iterable, Mapping


class StrictJSONError(ValueError):
    """Raised when JSON is ambiguous, non-finite, or non-canonicalizable."""


def _pairs(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StrictJSONError(f"duplicate JSON key: {key}")
        if "\x00" in key:
            raise StrictJSONError("JSON keys must not contain NUL")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise StrictJSONError(f"non-finite JSON number: {value}")


def _reject_nul(value: Any) -> None:
    if isinstance(value, str):
        if "\x00" in value:
            raise StrictJSONError("JSON strings must not contain NUL")
    elif isinstance(value, list):
        for item in value:
            _reject_nul(item)
    elif isinstance(value, Mapping):
        for key, item in value.items():
            _reject_nul(key)
            _reject_nul(item)
    elif isinstance(value, float) and not math.isfinite(value):
        raise StrictJSONError("non-finite JSON number")


def loads_strict_json(text: str) -> Any:
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant)
    except StrictJSONError:
        raise
    except (json.JSONDecodeError, UnicodeError, RecursionError) as exc:
        raise StrictJSONError(str(exc)) from exc
    _reject_nul(value)
    return value


def load_strict_json(path: str | Path, *, max_bytes: int = 4 * 1024 * 1024) -> Any:
    source = Path(path)
    data = source.read_bytes()
    if len(data) > max_bytes:
        raise StrictJSONError(f"JSON document exceeds {max_bytes} bytes")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise StrictJSONError("JSON document must be UTF-8") from exc
    return loads_strict_json(text)


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise StrictJSONError(f"value is not canonical JSON: {exc}") from exc


def sha256_digest(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def freeze_json(value: Any) -> Any:
    """Detach and deeply freeze a value already proven to be canonical JSON."""

    canonical_json_bytes(value)
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze_json(item) for key, item in value.items()})
    if isinstance(value, list) or isinstance(value, tuple):
        return tuple(freeze_json(item) for item in value)
    return value


def thaw_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def exact_object(
    value: Any,
    *,
    label: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StrictJSONError(f"{label} must be an object")
    allowed = required | (optional or set())
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        raise StrictJSONError(f"{label}.{unknown[0]}: unknown field")
    if missing:
        raise StrictJSONError(f"{label}.{missing[0]}: required field missing")
    return value
