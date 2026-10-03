"""Parse Admin API bodies for sources by hand (spec 015 "Admin API", "Security").

Pure. Every refusal is a ``BodyError`` with fixed text that echoes nothing from the
request: no credential, setting value or unknown key. Types and setting keys are checked
against ``connector_types``; setting values are the worker's to check.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..cataloging import connector_types

_NAME_MAX = 200
_VALUE_MAX = 1000
_INT_MAX = 2**31 - 1
_CREATE_KEYS = frozenset({"name", "type", "settings", "credentials", "credentials_expire_at", "max_values"})
_UPDATE_KEYS = frozenset({"name", "settings", "credentials", "credentials_expire_at", "max_values", "status"})


class BodyError(ValueError):
    """A malformed request body; ``str()`` is safe to return (400)."""


@dataclass(frozen=True)
class NewSource:
    """A parsed ``POST /sources`` body."""

    name: str
    connector_type: str
    settings: dict
    secrets: dict
    credentials_expire_at: datetime | None
    max_values: int | None


@dataclass(frozen=True)
class SourceChange:
    """A parsed ``PATCH /sources/{id}`` body; ``None`` leaves a field as it is."""

    name: str | None = None
    settings: dict | None = None
    secrets: dict | None = None
    status: str | None = None
    max_values: int | None = None
    expiry_given: bool = False  # credentials_expire_at present (null clears it)
    credentials_expire_at: datetime | None = None


def _object(value: Any, allowed: frozenset[str]) -> dict:
    if not isinstance(value, dict):
        raise BodyError("request body must be a JSON object")
    if any(k not in allowed for k in value):
        raise BodyError("request body has an unknown field")
    return value


def _name(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _NAME_MAX:
        raise BodyError("name must be a non-empty string")
    return value


def _settings(value: Any, ctype: connector_types.ConnectorType) -> dict:
    if not isinstance(value, dict):
        raise BodyError("settings must be an object")
    if connector_types.unknown_keys(ctype, value):
        raise BodyError("settings contain a key this connector type does not allow")
    return value


def _secrets(value: Any) -> dict:
    if not isinstance(value, dict):
        raise BodyError("credentials must be an object")
    return value


def _expiry(value: Any) -> datetime | None:
    if value is None:
        return None
    bad = BodyError("credentials_expire_at must be an ISO 8601 time with a timezone")
    if not isinstance(value, str):
        raise bad
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise bad from None
    if parsed.tzinfo is None:
        raise bad
    return parsed


def _max_values(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= _INT_MAX:
        raise BodyError("max_values must be a positive integer")
    return value


def _ctype(value: Any) -> connector_types.ConnectorType:
    ctype = connector_types.get(value) if isinstance(value, str) else None
    if ctype is None:
        raise BodyError("unknown connector type")
    return ctype


def parse_create(raw: Any) -> NewSource:
    """Validate a create body; a Pro type without erebus-pro is an unknown type."""
    raw = _object(raw, _CREATE_KEYS)
    name = _name(raw.get("name"))
    ctype = _ctype(raw.get("type"))
    return NewSource(
        name=name,
        connector_type=ctype.id,
        settings=_settings(raw.get("settings", {}), ctype),
        secrets=_secrets(raw.get("credentials", {})),
        credentials_expire_at=_expiry(raw.get("credentials_expire_at")),
        max_values=_max_values(raw.get("max_values")),
    )


def parse_update(raw: Any, connector_type: str | None = None) -> SourceChange:
    """Validate a PATCH body; settings are checked against the source's stored type."""
    raw = _object(raw, _UPDATE_KEYS)
    if not raw:
        raise BodyError("nothing to update")
    status = raw.get("status")
    if status is not None and status not in ("active", "paused"):
        raise BodyError("status must be active or paused")
    settings = None
    if "settings" in raw:
        settings = _settings(raw["settings"], _ctype(connector_type))
    return SourceChange(
        name=_name(raw["name"]) if "name" in raw else None,
        settings=settings,
        secrets=_secrets(raw["credentials"]) if "credentials" in raw else None,
        status=status,
        max_values=_max_values(raw.get("max_values")),
        expiry_given="credentials_expire_at" in raw,
        credentials_expire_at=_expiry(raw.get("credentials_expire_at")),
    )


def parse_decision(raw: Any) -> str:
    """``confirmed`` or ``ignored`` from a field PATCH body."""
    raw = _object(raw, frozenset({"decision"}))
    if raw.get("decision") not in ("confirmed", "ignored"):
        raise BodyError("decision must be confirmed or ignored")
    return raw["decision"]


def parse_erase(raw: Any) -> str:
    """The value to erase; it is never echoed back."""
    raw = _object(raw, frozenset({"value"}))
    value = raw.get("value")
    if not isinstance(value, str) or not value.strip() or len(value) > _VALUE_MAX:
        raise BodyError("value must be a non-empty string")
    return value


def parse_id(value: str | None) -> uuid.UUID | None:
    """A path or query id, or ``None`` when it is not a UUID (the API answers 404)."""
    try:
        return uuid.UUID(value or "")
    except ValueError:
        return None


def parse_limit(value: str | None) -> int:
    """The ``limit`` query parameter of the jobs list, 1..500 (default 50)."""
    if value is None:
        return 50
    try:
        limit = int(value)
    except ValueError:
        limit = 0
    if not 0 < limit <= 500:
        raise BodyError("limit must be an integer from 1 to 500")
    return limit
