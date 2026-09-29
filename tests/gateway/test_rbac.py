"""Two-level privilege model unit tests (010 FR-004).

Pure logic, no database. The privilege stored on a credential is the only authorization
input: ``operator`` may perform every admin action, ``tenant`` none. Unknown privileges,
the retired role names and unknown actions are all denied.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway import rbac
from erebus.gateway.rbac import (
    OPERATOR,
    TENANT,
    Action,
    Privilege,
    allowed_actions,
    authorize,
    is_operator,
)

_passed = 0

_LEGACY = ("GATEWAY_OPERATOR", "POLICY_ADMIN", "KEY_MANAGER", "REVEAL_REVIEWER", "AUDITOR", "OPERATOR",
           "TENANT", "", None, 1)


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def main():
    print("\n=== Gateway two-level privilege model (010 FR-004) ===\n")

    check("OPERATOR/TENANT are the plain strings the directory stores",
          OPERATOR == "operator" and TENANT == "tenant"
          and type(OPERATOR) is str and type(TENANT) is str)
    check("Privilege has exactly operator and tenant", {p.value for p in Privilege} == {"operator", "tenant"})

    check("operator allows every action", allowed_actions(Privilege.OPERATOR) == frozenset(Action))
    check("tenant allows no action", allowed_actions(Privilege.TENANT) == frozenset())
    for action in Action:
        check(f"authorize(operator, {action.value}) is True", authorize(Privilege.OPERATOR, action) is True)
        check(f"authorize(tenant, {action.value}) is False", authorize(Privilege.TENANT, action) is False)

    check("string privileges behave like the enum members",
          allowed_actions("operator") == frozenset(Action) and allowed_actions("tenant") == frozenset()
          and authorize("operator", "READ_AUDIT") and not authorize("tenant", "READ_AUDIT"))
    check("is_operator only for operator", is_operator("operator") and is_operator(Privilege.OPERATOR)
          and not is_operator("tenant") and not is_operator(Privilege.TENANT))

    for name in _LEGACY:
        check(f"retired or unknown privilege {name!r} holds nothing",
              allowed_actions(name) == frozenset() and not is_operator(name)
              and not any(authorize(name, a) for a in Action))

    check("unknown action denied for both privileges",
          not authorize("operator", "NOT_AN_ACTION") and not authorize("tenant", "NOT_AN_ACTION"))
    check("None privilege/action denied", not authorize(None, None))  # type: ignore[arg-type]

    check("the retired Role enum is gone", not hasattr(rbac, "Role"))
    check("the separation-of-duties set is gone", not hasattr(rbac, "SENSITIVE_ACTIONS"))

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
