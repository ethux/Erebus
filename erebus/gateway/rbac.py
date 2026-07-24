"""Roles and authorization with separation of duties (FR-016/FR-017).

Pure logic, no database and no process-global mutable state (FR-043). The gateway
maps a fixed set of operator roles to the privileged actions each may perform and
authorizes a ``(role, action)`` pair with a strict default-deny: unknown roles and
unknown actions are always denied.

Separation of duties (FR-016/FR-017) is structural, not advisory: the four most
sensitive actions -- REVEAL, MANAGE_KEYS, READ_AUDIT, PROVISION -- are partitioned
so that no single role can ever hold all four. REVEAL is held only by
REVEAL_REVIEWER, MANAGE_KEYS only by KEY_MANAGER, and READ_AUDIT only by AUDITOR;
the operational roles (POLICY_ADMIN, GATEWAY_OPERATOR) may MANAGE_POLICY and
PROVISION but can never reveal de-tokenized values, manage keys, or read the audit
trail. A module-level invariant check enforces this at import time.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType


class Role(StrEnum):
    """Operator roles recognized by the gateway."""

    GATEWAY_OPERATOR = "GATEWAY_OPERATOR"
    POLICY_ADMIN = "POLICY_ADMIN"
    KEY_MANAGER = "KEY_MANAGER"
    REVEAL_REVIEWER = "REVEAL_REVIEWER"
    AUDITOR = "AUDITOR"


class Action(StrEnum):
    """Privileged actions guarded by RBAC."""

    REVEAL = "REVEAL"
    MANAGE_KEYS = "MANAGE_KEYS"
    MANAGE_POLICY = "MANAGE_POLICY"
    READ_AUDIT = "READ_AUDIT"
    PROVISION = "PROVISION"


# The four actions that separation of duties keeps disjoint across roles: no single
# role may hold all of them at once (FR-016/FR-017).
SENSITIVE_ACTIONS: frozenset[Action] = frozenset(
    {Action.REVEAL, Action.MANAGE_KEYS, Action.READ_AUDIT, Action.PROVISION}
)


def _frozen(*actions: Action) -> frozenset[Action]:
    return frozenset(actions)


# Immutable role -> allowed-actions mapping. ``MappingProxyType`` + frozensets keep
# the policy read-only (no process-global mutable state, FR-043).
_ROLE_ACTIONS: Mapping[Role, frozenset[Action]] = MappingProxyType(
    {
        Role.GATEWAY_OPERATOR: _frozen(Action.MANAGE_POLICY, Action.PROVISION),
        Role.POLICY_ADMIN: _frozen(Action.MANAGE_POLICY, Action.PROVISION),
        Role.KEY_MANAGER: _frozen(Action.MANAGE_KEYS),
        Role.REVEAL_REVIEWER: _frozen(Action.REVEAL),
        Role.AUDITOR: _frozen(Action.READ_AUDIT),
    }
)


def _coerce_role(role: Role | str) -> Role | None:
    if isinstance(role, Role):
        return role
    try:
        return Role(role)
    except ValueError:
        return None


def _coerce_action(action: Action | str) -> Action | None:
    if isinstance(action, Action):
        return action
    try:
        return Action(action)
    except ValueError:
        return None


def allowed_actions(role: Role | str) -> frozenset[Action]:
    """Return the actions granted to ``role``; empty for an unknown role."""
    resolved = _coerce_role(role)
    if resolved is None:
        return frozenset()
    return _ROLE_ACTIONS[resolved]


def authorize(role: Role | str, action: Action | str) -> bool:
    """Return True iff ``role`` may perform ``action`` (default-deny on unknown)."""
    resolved_action = _coerce_action(action)
    if resolved_action is None:
        return False
    return resolved_action in allowed_actions(role)


def _assert_separation_of_duties() -> None:
    """No single role may hold all four sensitive actions (FR-016/FR-017)."""
    for role, actions in _ROLE_ACTIONS.items():
        if actions >= SENSITIVE_ACTIONS:
            raise AssertionError(
                f"separation-of-duties violation: {role.value} holds all sensitive actions"
            )


_assert_separation_of_duties()
