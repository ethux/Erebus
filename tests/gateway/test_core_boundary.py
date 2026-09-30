"""Core never reaches into Erebus Pro or checks a license (spec 015 D6).

Walks the AST of every ``.py`` file under ``erebus/`` and fails on: an import of
``erebus_pro`` (statement or a module-name string such as ``importlib.import_module``
takes), a read of an ``EREBUS_LICENSE_*`` variable (any string constant naming one),
and any use of the entitlements Pro attaches to the app (``erebus_entitlements``).
Pro gates itself; core only offers seams. Pure: parses source, imports nothing.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path

_CORE = Path(__file__).resolve().parents[2] / "erebus"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _docstring_ids(tree: ast.AST) -> set[int]:
    """ids of the string nodes that are docstrings (prose may name Pro freely)."""
    ids = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                ids.add(id(body[0].value))
    return ids


def _is_pro_module(name: str) -> bool:
    return name == "erebus_pro" or name.startswith("erebus_pro.")


def violations(source: str) -> list[str]:
    """Return one message per D6 violation in ``source`` (a module's text)."""
    tree = ast.parse(source)
    docstrings = _docstring_ids(tree)
    found = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found += [f"imports {a.name}" for a in node.names if _is_pro_module(a.name)]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and _is_pro_module(node.module or ""):
            found.append(f"imports from {node.module}")
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and id(node) not in docstrings:
            if _is_pro_module(node.value):
                found.append(f"names module {node.value!r}")
            if "EREBUS_LICENSE" in node.value:
                found.append("reads a license variable")
        elif getattr(node, "attr", None) == "erebus_entitlements" or getattr(node, "id", None) == "erebus_entitlements":
            found.append("uses Pro entitlements")
    return found


def _check_detector():
    """The guard itself catches each shape it claims to (so a clean tree means something)."""
    check("flags `import erebus_pro`", violations("import erebus_pro\n"))
    check("flags `from erebus_pro.license import from_env`",
          violations("from erebus_pro.license import from_env\n"))
    check("flags importlib.import_module('erebus_pro.connectors')",
          violations("import importlib\nimportlib.import_module('erebus_pro.connectors')\n"))
    check("flags an EREBUS_LICENSE_KEY read", violations("import os\nos.environ.get('EREBUS_LICENSE_KEY')\n"))
    check("flags app.state.erebus_entitlements", violations("x = app.state.erebus_entitlements.has('a')\n"))
    check("ignores a docstring that names erebus_pro", not violations('"""Pro lives in erebus_pro."""\n'))
    check("ignores a relative import of a core module", not violations("from .erebus_pro_like import x\n"))


def main():
    print("\n=== Core/Pro boundary (spec 015 D6) ===\n")
    _check_detector()
    files = sorted(p for p in _CORE.rglob("*.py") if "__pycache__" not in p.parts)
    check("the scan covers the core package", len(files) > 50)
    bad = {}
    for path in files:
        found = violations(path.read_text(encoding="utf-8"))
        if found:
            bad[str(path.relative_to(_CORE.parent))] = found
    for name, found in bad.items():
        print(f"  ✗ {name}: {', '.join(found)}", file=sys.stderr)
    check("no core module imports erebus_pro, reads EREBUS_LICENSE_* or checks entitlements", not bad)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
