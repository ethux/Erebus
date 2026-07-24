"""RBAC separation-of-duties unit tests (FR-016/FR-017).

Pure logic, no database. Verifies default-deny on unknown role/action, that each
role grants only its own actions, that no single role holds all four sensitive
actions (REVEAL/MANAGE_KEYS/READ_AUDIT/PROVISION), and that GATEWAY_OPERATOR can
never REVEAL.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.rbac import (
    SENSITIVE_ACTIONS,
    Action,
    Role,
    allowed_actions,
    authorize,
)

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


# The intended grant per role (the spec's role->allowed-actions mapping).
_EXPECTED: dict[Role, set[Action]] = {
    Role.GATEWAY_OPERATOR: {Action.MANAGE_POLICY, Action.PROVISION},
    Role.POLICY_ADMIN: {Action.MANAGE_POLICY, Action.PROVISION},
    Role.KEY_MANAGER: {Action.MANAGE_KEYS},
    Role.REVEAL_REVIEWER: {Action.REVEAL},
    Role.AUDITOR: {Action.READ_AUDIT},
}


def main():
    print("\n=== Gateway RBAC separation of duties (FR-016/FR-017) ===\n")

    # Default-deny on unknown role / unknown action.
    check(
        "unknown role denied for every action",
        all(not authorize("NOT_A_ROLE", a) for a in Action),
    )
    check(
        "unknown action denied for every role",
        all(not authorize(r, "NOT_AN_ACTION") for r in Role),
    )
    check("unknown role has no allowed actions", allowed_actions("NOT_A_ROLE") == frozenset())
    check("None role/action denied", not authorize(None, None))  # type: ignore[arg-type]

    # Each role grants exactly its own actions and nothing else.
    for role, expected in _EXPECTED.items():
        check(f"{role.value} grants exactly {sorted(a.value for a in expected)}",
              set(allowed_actions(role)) == expected)
        for action in Action:
            want = action in expected
            check(
                f"authorize({role.value}, {action.value}) == {want}",
                authorize(role, action) is want,
            )

    # Sensitive-action ownership is unique where the spec requires it.
    check("REVEAL belongs only to REVEAL_REVIEWER",
          {r for r in Role if authorize(r, Action.REVEAL)} == {Role.REVEAL_REVIEWER})
    check("MANAGE_KEYS belongs only to KEY_MANAGER",
          {r for r in Role if authorize(r, Action.MANAGE_KEYS)} == {Role.KEY_MANAGER})
    check("READ_AUDIT belongs only to AUDITOR",
          {r for r in Role if authorize(r, Action.READ_AUDIT)} == {Role.AUDITOR})
    check("MANAGE_POLICY held by POLICY_ADMIN and GATEWAY_OPERATOR only",
          {r for r in Role if authorize(r, Action.MANAGE_POLICY)}
          == {Role.POLICY_ADMIN, Role.GATEWAY_OPERATOR})
    check("PROVISION held by POLICY_ADMIN and GATEWAY_OPERATOR only",
          {r for r in Role if authorize(r, Action.PROVISION)}
          == {Role.POLICY_ADMIN, Role.GATEWAY_OPERATOR})

    # Separation of duties: no single role holds all four sensitive actions.
    check("SENSITIVE_ACTIONS is the four-action set",
          frozenset(
              {Action.REVEAL, Action.MANAGE_KEYS, Action.READ_AUDIT, Action.PROVISION}) == SENSITIVE_ACTIONS)
    for role in Role:
        check(f"{role.value} does NOT hold all four sensitive actions",
              not allowed_actions(role) >= SENSITIVE_ACTIONS)

    # Explicit guard called out by the spec.
    check("GATEWAY_OPERATOR cannot REVEAL", not authorize(Role.GATEWAY_OPERATOR, Action.REVEAL))
    check("GATEWAY_OPERATOR cannot MANAGE_KEYS",
          not authorize(Role.GATEWAY_OPERATOR, Action.MANAGE_KEYS))
    check("GATEWAY_OPERATOR cannot READ_AUDIT",
          not authorize(Role.GATEWAY_OPERATOR, Action.READ_AUDIT))

    # String-keyed calls behave identically to enum-keyed calls (API ergonomics).
    check("string role/action authorizes like enums",
          authorize("AUDITOR", "READ_AUDIT") and not authorize("AUDITOR", "REVEAL"))

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
