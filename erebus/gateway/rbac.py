"""Two-level privilege model for the gateway's admin gate (010 FR-004).

Pure logic, no database and no process-global mutable state (FR-043). Authority comes
only from the privilege stored on the credential at issuance, never from the request:
``operator`` may perform every admin action, ``tenant`` none. An unknown privilege
(including the retired role names) or an unknown action is always denied.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class Privilege(StrEnum):
    """The privilege stored on a credential at issuance (010)."""

    OPERATOR = "operator"
    TENANT = "tenant"


# Plain-str values, what the directory stores.
OPERATOR: str = Privilege.OPERATOR.value
TENANT: str = Privilege.TENANT.value


class Action(StrEnum):
    """Privileged actions guarded by the admin gate."""

    REVEAL = "REVEAL"
    MANAGE_KEYS = "MANAGE_KEYS"
    MANAGE_POLICY = "MANAGE_POLICY"
    READ_AUDIT = "READ_AUDIT"
    PROVISION = "PROVISION"


# Immutable privilege -> allowed-actions mapping (no process-global mutable state, FR-043).
_PRIVILEGE_ACTIONS: Mapping[Privilege, frozenset[Action]] = MappingProxyType(
    {
        Privilege.OPERATOR: frozenset(Action),
        Privilege.TENANT: frozenset(),
    }
)


def _coerce_privilege(privilege: object) -> Privilege | None:
    if isinstance(privilege, Privilege):
        return privilege
    try:
        return Privilege(privilege)
    except (ValueError, TypeError):
        return None


def _coerce_action(action: Action | str) -> Action | None:
    if isinstance(action, Action):
        return action
    try:
        return Action(action)
    except (ValueError, TypeError):
        return None


def is_operator(privilege: object) -> bool:
    """True iff ``privilege`` is the operator privilege."""
    return _coerce_privilege(privilege) is Privilege.OPERATOR


def allowed_actions(privilege: Privilege | str) -> frozenset[Action]:
    """Return the actions granted to ``privilege``; empty for an unknown privilege."""
    resolved = _coerce_privilege(privilege)
    if resolved is None:
        return frozenset()
    return _PRIVILEGE_ACTIONS[resolved]


def authorize(privilege: Privilege | str, action: Action | str) -> bool:
    """Return True iff ``privilege`` may perform ``action`` (default-deny on unknown)."""
    resolved_action = _coerce_action(action)
    if resolved_action is None:
        return False
    return resolved_action in allowed_actions(privilege)
