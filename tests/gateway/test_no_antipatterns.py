"""Structural anti-pattern guard for the gateway (T019, FR-041..043).

This test owns no module: it is a static guard that walks every ``.py`` file
under ``erebus/gateway/`` and fails if any of them reintroduces one of the
forbidden token-recovery / cross-tenant-state patterns the spec outlaws.

It enforces three invariants, all by parsing source text / the AST (no import or
execution of gateway code, so a violation cannot hide behind a side effect):

* FR-041 -- no audit-recovery path. The audit log is append-only evidence, never
  a way to read back de-tokenized values. No gateway file may import or reference
  ``erebus.audit.logger.lookup_token_values`` (or any ``lookup_token_values``
  attribute/call) or otherwise treat the audit log as a token-recovery channel.
* FR-042 -- no plaintext mirror. No gateway file may import the legacy
  known-values transient cache (``erebus.core.knownvalues._TRANSIENT_TOKENS``) or
  the legacy ``token_map.json`` export surface
  (``config.save_token_map`` / ``_export_legacy``).
* FR-043 -- no process-global mutable state usable as cross-tenant state. No
  gateway file may define a module-level mutable container (a top-level
  assignment whose value is a ``{}`` / ``[]`` / ``set()`` / ``dict()`` /
  ``list()`` literal-or-call) that is later mutated in place.

The FR-043 heuristic is deliberately conservative so it is not falsely strict:

* only **module-level** (``ast.Module`` body) assignments count -- class-level
  state and instance state (``self.x = {}``, e.g. ``LocalKms``'s in-process
  keystore, a documented appliance KMS) are allowed;
* an empty container is only a violation if it is **also mutated in place**
  somewhere in the same file (``.append``/``.add``/``.update``/``.pop``/
  ``setdefault``/ ``x[k] = ...`` / augmented assignment / ``del x[...]``);
* immutable module constants are never flagged: ``frozenset(...)``,
  ``MappingProxyType(...)``, tuples, and names following the
  underscore-constant / UPPER_SNAKE registry conventions that are only ever
  read are inert because they are never mutated.

Run directly (``python tests/gateway/test_no_antipatterns.py``); prints
``N/N passed`` and exits nonzero on the first violating file.
"""

from __future__ import annotations

import ast
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

_GATEWAY_DIR = Path(__file__).resolve().parent.parent.parent / "erebus" / "gateway"

# (a) FR-041: audit log must never be a token-recovery path.
_FORBIDDEN_RECOVERY_ATTRS: frozenset[str] = frozenset({"lookup_token_values"})
_FORBIDDEN_RECOVERY_DOTTED: frozenset[str] = frozenset(
    {"erebus.audit.logger.lookup_token_values"}
)

# (b) FR-042: legacy plaintext-mirror surfaces.
_FORBIDDEN_KNOWNVALUES_NAMES: frozenset[str] = frozenset({"_TRANSIENT_TOKENS"})
_FORBIDDEN_KNOWNVALUES_MODULE = "erebus.core.knownvalues"
_FORBIDDEN_LEGACY_ATTRS: frozenset[str] = frozenset({"save_token_map", "_export_legacy"})

# (c) FR-043: in-place mutation method names that mark a container as mutable state.
_MUTATING_METHODS: frozenset[str] = frozenset(
    {"append", "extend", "insert", "add", "update", "pop", "popitem",
     "setdefault", "remove", "discard", "clear", "__setitem__"}
)

_passed = 0


def check(name: str, cond: bool) -> None:
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _gateway_files() -> list[Path]:
    files = sorted(p for p in _GATEWAY_DIR.rglob("*.py"))
    if not files:
        raise AssertionError(f"no gateway .py files found under {_GATEWAY_DIR}")
    return files


def _dotted_name(node: ast.AST) -> str | None:
    """Return the dotted path for an ``a.b.c`` Attribute/Name chain, else None."""
    parts: list[str] = []
    cur: ast.AST | None = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
        return ".".join(reversed(parts))
    return None


def _scan_recovery(tree: ast.AST) -> list[str]:
    """FR-041: any reference to an audit-log token-recovery path."""
    hits: list[str] = []
    for node in ast.walk(tree):
        # `from erebus.audit.logger import lookup_token_values`
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name in _FORBIDDEN_RECOVERY_ATTRS:
                    hits.append(f"import of {alias.name} from {node.module!r}")
        # `import erebus.audit.logger` then ...lookup_token_values, or any attr access
        elif isinstance(node, ast.Attribute):
            if node.attr in _FORBIDDEN_RECOVERY_ATTRS:
                hits.append(f"attribute reference {node.attr!r}")
            dotted = _dotted_name(node)
            if dotted in _FORBIDDEN_RECOVERY_DOTTED:
                hits.append(f"dotted reference {dotted!r}")
        # bare `lookup_token_values(...)` call / name reference
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_RECOVERY_ATTRS:
            hits.append(f"name reference {node.id!r}")
    return hits


def _scan_legacy(tree: ast.AST) -> list[str]:
    """FR-042: legacy knownvalues transient cache / token_map.json export surface."""
    hits: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                if (
                    module == _FORBIDDEN_KNOWNVALUES_MODULE
                    and alias.name in _FORBIDDEN_KNOWNVALUES_NAMES
                ):
                    hits.append(f"import {alias.name} from {module}")
                if alias.name in _FORBIDDEN_LEGACY_ATTRS:
                    hits.append(f"import legacy export {alias.name} from {module!r}")
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == _FORBIDDEN_KNOWNVALUES_MODULE:
                    hits.append(f"import module {alias.name}")
        elif isinstance(node, ast.Attribute):
            if node.attr in _FORBIDDEN_LEGACY_ATTRS:
                hits.append(f"attribute reference {node.attr!r}")
            if node.attr in _FORBIDDEN_KNOWNVALUES_NAMES:
                dotted = _dotted_name(node)
                if dotted and dotted.startswith(_FORBIDDEN_KNOWNVALUES_MODULE):
                    hits.append(f"dotted reference {dotted!r}")
        elif isinstance(node, ast.Name) and node.id in _FORBIDDEN_KNOWNVALUES_NAMES:
            hits.append(f"name reference {node.id!r}")
    return hits


def _is_empty_container_value(value: ast.expr) -> bool:
    """True for ``{}`` / ``[]`` / ``set()`` / ``dict()`` / ``list()`` (mutable seeds)."""
    if isinstance(value, ast.Dict) and not value.keys:
        return True
    if isinstance(value, ast.List) and not value.elts:
        return True
    return (
        isinstance(value, ast.Call)
        and isinstance(value.func, ast.Name)
        and value.func.id in {"set", "dict", "list"}
        and not value.args
        and not value.keywords
    )


def _module_level_container_targets(tree: ast.Module) -> dict[str, ast.AST]:
    """Top-level names bound to an empty mutable container (the FR-043 candidates)."""
    candidates: dict[str, ast.AST] = {}
    for stmt in tree.body:  # module body only -- excludes class/instance/function scope
        if isinstance(stmt, ast.Assign) and _is_empty_container_value(stmt.value):
            for target in stmt.targets:
                if isinstance(target, ast.Name):
                    candidates[target.id] = stmt
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.value is not None
            and _is_empty_container_value(stmt.value)
        ):
            candidates[stmt.target.id] = stmt
    return candidates


def _names_mutated_in_place(tree: ast.Module, names: set[str]) -> set[str]:
    """Subset of ``names`` mutated in place anywhere in the file."""
    mutated: set[str] = set()
    for node in ast.walk(tree):
        # x.append(...) / x.update(...) / x[k] = ... via attribute-call
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in _MUTATING_METHODS
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in names
        ):
            mutated.add(node.func.value.id)
        # x[k] = ...  /  del x[k]
        elif isinstance(node, (ast.Assign, ast.AugAssign, ast.Delete)):
            targets = node.targets if isinstance(node, ast.Assign) else (
                [node.target] if isinstance(node, ast.AugAssign) else node.targets
            )
            for target in targets:
                if (
                    isinstance(target, ast.Subscript)
                    and isinstance(target.value, ast.Name)
                    and target.value.id in names
                ):
                    mutated.add(target.value.id)
                # x += [...] rebinds/mutates the bound name in place
                if (
                    isinstance(node, ast.AugAssign)
                    and isinstance(target, ast.Name)
                    and target.id in names
                ):
                    mutated.add(target.id)
    return mutated


def _scan_global_mutable_state(tree: ast.Module) -> list[str]:
    """FR-043: module-level mutable container that is later mutated in place."""
    candidates = _module_level_container_targets(tree)
    if not candidates:
        return []
    mutated = _names_mutated_in_place(tree, set(candidates))
    return [f"module-level mutable global {name!r} is mutated in place" for name in sorted(mutated)]


def main() -> None:
    print("\n=== Gateway structural anti-pattern guard (FR-041..043) ===\n")

    files = _gateway_files()
    check(f"discovered {len(files)} gateway .py files to scan", len(files) > 0)

    recovery_violations: dict[str, list[str]] = {}
    legacy_violations: dict[str, list[str]] = {}
    state_violations: dict[str, list[str]] = {}

    for path in files:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        rel = path.relative_to(_GATEWAY_DIR.parent.parent)

        if hits := _scan_recovery(tree):
            recovery_violations[str(rel)] = hits
        if hits := _scan_legacy(tree):
            legacy_violations[str(rel)] = hits
        if hits := _scan_global_mutable_state(tree):
            state_violations[str(rel)] = hits

    # (a) FR-041 -- no audit-recovery path.
    check(
        "FR-041: no file references an audit-log token-recovery path "
        f"(lookup_token_values); offenders={recovery_violations}",
        not recovery_violations,
    )

    # (b) FR-042 -- no legacy plaintext-mirror surfaces.
    check(
        "FR-042: no file imports the legacy knownvalues transient cache or "
        f"token_map.json export; offenders={legacy_violations}",
        not legacy_violations,
    )

    # (c) FR-043 -- no process-global mutable cross-tenant state.
    check(
        "FR-043: no file defines a module-level mutable global container that is "
        f"mutated in place; offenders={state_violations}",
        not state_violations,
    )

    # Self-check: the heuristics actually fire on the patterns they target, so a
    # passing run means "scanned and clean", not "scanner is inert".
    _self_test()

    print(f"\n{_passed}/{_passed} passed\n")


def _self_test() -> None:
    """Prove each detector trips on a synthetic offender (and stays quiet on allowed code)."""
    recovery_src = (
        "from erebus.audit.logger import lookup_token_values\n"
        "x = lookup_token_values()\n"
    )
    check("FR-041 detector trips on lookup_token_values import",
          bool(_scan_recovery(ast.parse(recovery_src))))

    legacy_src = (
        "from erebus.core.knownvalues import _TRANSIENT_TOKENS\n"
        "import config\n"
        "config.save_token_map()\n"
    )
    check("FR-042 detector trips on _TRANSIENT_TOKENS / save_token_map",
          len(_scan_legacy(ast.parse(legacy_src))) >= 2)

    mutable_src = "REGISTRY = {}\ndef reg(k, v):\n    REGISTRY[k] = v\n"
    check("FR-043 detector trips on a mutated module-level dict",
          bool(_scan_global_mutable_state(ast.parse(mutable_src))))

    # Allowed: an empty container that is never mutated (read-only placeholder).
    inert_src = "EMPTY = {}\nvalue = EMPTY.get('k')\n"
    check("FR-043 detector ignores an unmutated module-level container",
          not _scan_global_mutable_state(ast.parse(inert_src)))

    # Allowed: class-level / instance state like LocalKms's in-process keystore.
    class_src = (
        "class LocalKms:\n"
        "    def __init__(self):\n"
        "        self._keks = {}\n"
        "    def put(self, k, v):\n"
        "        self._keks[k] = v\n"
    )
    check("FR-043 detector ignores class/instance mutable state (appliance KMS)",
          not _scan_global_mutable_state(ast.parse(class_src)))

    # Allowed: immutable registries (frozenset / MappingProxyType) are never flagged.
    immutable_src = (
        "from types import MappingProxyType\n"
        "ROLES = MappingProxyType({'a': frozenset({'x'})})\n"
        "SENSITIVE = frozenset({'x', 'y'})\n"
    )
    check("FR-043 detector ignores immutable frozenset/MappingProxyType registries",
          not _scan_global_mutable_state(ast.parse(immutable_src)))


if __name__ == "__main__":
    main()
