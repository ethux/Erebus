#!/usr/bin/env python3
"""Static boundary audit (spec FR-008, T033).

The privacy invariant is owned by exactly one place: erebus/core/. This stdlib
AST checker proves it statically. Run it as a script or import `audit_tree`.

Outside erebus/core/ the following are FORBIDDEN (each finding is one
``VIOLATION path:line: reason`` line; non-zero exit on any):

  * calls to the tokenize/detokenize family
    (tokenize, detokenize, cached_tokenize, cached_tokenize_many,
     _store_tokenize_result, _predict_entities, _predict_entities_many)
    EXCEPT when the called name was bound by an import from the blessed
    erebus.filter compat facade (contracts/compat-surface.md): such a call
    routes through the allowlisted facade into core. This is import
    provenance, not a path allowlist — the same name bound any other way
    (deep import, local def, store helpers from erebus.config) stays flagged.
  * calls to the Known-Value-DB / token-map lifecycle family
    (open_known_values, save_token_map, load_token_map, lookup_token_values,
     _persist_token_map, _refresh_token_map_from_disk)
  * deep imports of erebus.core.<submodule>; only ``from erebus.core import
    NAME``, ``import erebus.core``, or relative ``from ..core import NAME`` are
    allowed
  * the token-map / Known-Value-DB filenames ('token_map.json',
    'known_values.db') used in an open()/Path() context
  * a re-implementation of the canonical TOKEN_RE shape compiled for .sub/.subn
    (substitution); read-only copies for matching/scanning are allowed

ALLOWLIST (path-based, one comment each): see ALLOWLIST below. Additionally,
erebus/filter.py is a re-export-only facade: it may contain imports,
assignments, __getattr__, and the documented dead-code shim only — any other
top-level def is a violation.

This contract mirrors specs/004-core-pii-boundary/contracts/boundary-api.md;
that contract wins on drift.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

# Repo root = two levels up from this file (tests/audit_boundary.py).
REPO_ROOT = Path(__file__).resolve().parent.parent
EREBUS_DIR = REPO_ROOT / "erebus"
CORE_DIR = EREBUS_DIR / "core"

# ── Forbidden call names ──────────────────────────────────────────────────────
TOKENIZE_FAMILY = frozenset({
    "tokenize",
    "detokenize",
    "cached_tokenize",
    "cached_tokenize_many",
    "_store_tokenize_result",
    "_predict_entities",
    "_predict_entities_many",
})
STORE_FAMILY = frozenset({
    "open_known_values",
    "save_token_map",
    "load_token_map",
    "lookup_token_values",
    "_persist_token_map",
    "_refresh_token_map_from_disk",
})
FORBIDDEN_CALLS = TOKENIZE_FAMILY | STORE_FAMILY

# ── Forbidden file-path literals (in open()/Path() context) ───────────────────
STORE_FILENAMES = frozenset({"token_map.json", "known_values.db"})
PATH_CALL_NAMES = frozenset({"open", "Path"})

# ── Token-shape re-implementation heuristic (conservative) ────────────────────
# A regex pattern is "token-shaped" when it brackets a LABEL_<n>_<hex> body; we
# only flag such a pattern when it is compiled/used for substitution (.sub/.subn
# or re.sub/re.subn). Read-only copies (finditer/findall/fullmatch) are allowed.
TOKEN_SHAPE_MARKERS = ("[A-Z_]+_", "0-9a-f]")
SUB_METHODS = frozenset({"sub", "subn"})

# ── Path-based allowlist (FR-008). One comment per entry. ─────────────────────
# Paths are relative to the repo root, POSIX-style.
ALLOWLIST = {
    "erebus/config.py": "storage primitives: owns load/save_token_map + paths",
    "erebus/audit/logger.py": "audit-recovery source: lookup_token_values + erase",
    "erebus/filter.py": "re-export-only facade (extra structural check applies)",
    "erebus/commands/check_file.py": "real-world-sink scanner: read-only on-disk token check",
    "erebus/commands/reveal.py": "real-world-sink CLI: reads legacy token map for the user",
    "erebus/runtime/mcp_server.py": "FR-019 reveal: reads the DB to emit masked previews only",
}


def _is_allowlisted(rel_posix: str) -> bool:
    if rel_posix in ALLOWLIST:
        return True
    # tests/ is allowlisted wholesale.
    return rel_posix.startswith("tests/")


# ── Blessed-facade import provenance ──────────────────────────────────────────
# erebus/filter.py is the blessed compat facade (compat-surface.md): a bare call
# to a tokenize/detokenize-family NAME is not a leak when that NAME was bound by
# ``from erebus.filter import NAME`` (absolute or relative) — the call routes
# through the allowlisted facade into core. Store-family names never get this
# relief; they are owned by erebus/config.py and core.
_FACADE_MODULE = "erebus.filter"


def _resolve_relative_module(rel_posix: str, module: str, level: int) -> str:
    """Absolute dotted path of a (possibly relative) ImportFrom target."""
    if level == 0:
        return module
    pkg = rel_posix.split("/")[:-1]  # drop the filename; works for __init__.py too
    base = pkg[: len(pkg) - (level - 1)] if level - 1 <= len(pkg) else []
    return ".".join([*base, module] if module else base)


def _facade_bound_names(tree: ast.Module, rel_posix: str) -> frozenset[str]:
    """Tokenize-family names this module bound via a facade import."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if _resolve_relative_module(rel_posix, node.module or "", node.level) != _FACADE_MODULE:
            continue
        for alias in node.names:
            if alias.name in TOKENIZE_FAMILY:
                names.add(alias.asname or alias.name)
    return frozenset(names)


# ── AST helpers ───────────────────────────────────────────────────────────────

def _call_name(func: ast.expr) -> str | None:
    """Resolve the callee's simple name (Name.id or Attribute.attr)."""
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _string_constants(node: ast.expr) -> list[str]:
    """Every string Constant directly reachable in a Path()/open() arg tree.

    Walks Constants, BinOp (the ``Path.home() / "x.json"`` idiom), and the
    direct args/elements so a literal filename anywhere in the call is seen.
    """
    out: list[str] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
            out.append(sub.value)
    return out


def _is_token_shaped(pattern: str) -> bool:
    return all(marker in pattern for marker in TOKEN_SHAPE_MARKERS)


class _BoundaryVisitor(ast.NodeVisitor):
    """Collect FR-008 violations in one module's AST."""

    def __init__(self, rel_posix: str, facade_names: frozenset[str] = frozenset()) -> None:
        self.rel = rel_posix
        self.findings: list[tuple[int, str]] = []
        # tokenize-family names bound by a blessed-facade import: bare calls to
        # these are facade-routed, not boundary leaks (see _facade_bound_names).
        self._facade_names = facade_names
        # token-shaped regexes assigned to a name -> defining lineno, so a later
        # ``NAME.sub(...)`` can be attributed to the re-implementation site.
        self._token_regex_names: dict[str, int] = {}

    def _add(self, lineno: int, reason: str) -> None:
        self.findings.append((lineno, reason))

    # -- definitions (re-implementation of a boundary function) --------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_def_name(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_def_name(node)
        self.generic_visit(node)

    def _check_def_name(self, node) -> None:
        if node.name in FORBIDDEN_CALLS:
            self._add(node.lineno,
                      f"re-implements forbidden boundary function "
                      f"'def {node.name}(...)' (must live in erebus/core/)")

    # -- imports -------------------------------------------------------------

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.name
            if name.startswith("erebus.core.") and name != "erebus.core":
                self._add(node.lineno,
                          f"deep import of core submodule '{name}' "
                          f"(import only 'erebus.core')")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        # Absolute: from erebus.core.<sub> import ...
        if module.startswith("erebus.core."):
            self._add(node.lineno,
                      f"deep import 'from {module} import ...' "
                      f"(use 'from erebus.core import NAME')")
        # Relative: from ..core.<sub> import ...  (level>=1, module='core.<sub>')
        elif node.level >= 1 and (module == "core." or module.startswith("core.")):
            dots = "." * node.level
            self._add(node.lineno,
                      f"deep import 'from {dots}{module} import ...' "
                      f"(use 'from {dots[:-1]}.core import NAME')")
        self.generic_visit(node)

    # -- assignments (token-regex tracking) ----------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        self._track_token_regex(node.targets, node.value)
        self.generic_visit(node)

    def _track_token_regex(self, targets: list[ast.expr], value: ast.expr) -> None:
        """Remember names bound to a token-shaped re.compile(...) result."""
        if not (isinstance(value, ast.Call) and _call_name(value.func) == "compile"):
            return
        for pattern in self._call_pattern_literals(value):
            if _is_token_shaped(pattern):
                for tgt in targets:
                    if isinstance(tgt, ast.Name):
                        self._token_regex_names[tgt.id] = value.lineno

    @staticmethod
    def _call_pattern_literals(call: ast.Call) -> list[str]:
        out: list[str] = []
        if call.args and isinstance(call.args[0], ast.Constant) \
                and isinstance(call.args[0].value, str):
            out.append(call.args[0].value)
        return out

    # -- calls ---------------------------------------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        name = _call_name(node.func)
        if name in FORBIDDEN_CALLS and not self._is_facade_call(node.func):
            self._add(node.lineno, f"call to forbidden boundary function '{name}()'")
        if name in PATH_CALL_NAMES:
            self._check_store_filename(node)
        if name in SUB_METHODS:
            self._check_token_sub(node)
        self.generic_visit(node)

    def _is_facade_call(self, func: ast.expr) -> bool:
        """True for a bare NAME(...) call where NAME was facade-bound.

        Attribute calls (obj.tokenize(...)) never qualify: the receiver's
        provenance is unknowable statically, so they stay flagged.
        """
        return isinstance(func, ast.Name) and func.id in self._facade_names

    def _check_store_filename(self, node: ast.Call) -> None:
        for literal in _string_constants(node):
            if literal in STORE_FILENAMES:
                self._add(node.lineno,
                          f"store filename {literal!r} used in a "
                          f"{_call_name(node.func)}() context")
                return

    def _check_token_sub(self, node: ast.Call) -> None:
        """Flag .sub/.subn substitution driven by a token-shaped pattern."""
        if not isinstance(node.func, ast.Attribute):
            return
        receiver = node.func.value
        # NAME.sub(...) where NAME is a token-shaped compiled regex.
        if isinstance(receiver, ast.Name) and receiver.id in self._token_regex_names:
            self._add(node.lineno,
                      f"token-shaped regex re-implementation used for "
                      f".{node.func.attr}() substitution")
            return
        # re.sub("<token-shaped literal>", ...): inline pattern.
        if isinstance(receiver, ast.Name) and receiver.id == "re" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) \
                    and _is_token_shaped(first.value):
                self._add(node.lineno,
                          f"token-shaped regex literal re-implementation used "
                          f"for re.{node.func.attr}() substitution")


# ── filter.py structural check ────────────────────────────────────────────────

# filter.py is a re-export-only facade; only __getattr__ is an allowed top-level def.
_FILTER_ALLOWED_DEFS = frozenset({"__getattr__"})


def _check_filter_facade(tree: ast.Module, rel: str) -> list[tuple[int, str]]:
    """erebus/filter.py may hold imports/assignments/__getattr__ only.
    Any other top-level def is a violation."""
    out: list[tuple[int, str]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name not in _FILTER_ALLOWED_DEFS:
                out.append((node.lineno,
                            f"facade must be re-export-only: unexpected "
                            f"top-level def '{node.name}' in {rel}"))
        elif isinstance(node, ast.ClassDef):
            out.append((node.lineno,
                        f"facade must be re-export-only: unexpected "
                        f"top-level class '{node.name}' in {rel}"))
    return out


# ── tree walk ─────────────────────────────────────────────────────────────────

def _iter_target_files() -> list[Path]:
    """Every erebus/**/*.py OUTSIDE erebus/core/, sorted, no __pycache__."""
    files = [
        path for path in EREBUS_DIR.rglob("*.py")
        if CORE_DIR not in path.parents and "__pycache__" not in path.parts
    ]
    return sorted(files)


def audit_file(path: Path, root: Path = REPO_ROOT) -> list[str]:
    """Return ``path:line: reason`` strings for one file (allowlist applied)."""
    rel_posix = path.relative_to(root).as_posix()
    if _is_allowlisted(rel_posix) and not rel_posix.endswith("filter.py"):
        return []

    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    findings: list[tuple[int, str]] = []
    if rel_posix.endswith("filter.py"):
        # filter.py is allowlisted for the forbidden families but still gets the
        # stricter re-export-only structural check.
        findings.extend(_check_filter_facade(tree, rel_posix))
    else:
        visitor = _BoundaryVisitor(rel_posix, _facade_bound_names(tree, rel_posix))
        visitor.visit(tree)
        findings.extend(visitor.findings)

    findings.sort()
    return [f"{rel_posix}:{lineno}: {reason}" for lineno, reason in findings]


def audit_tree(target_dir: Path | None = None, root: Path | None = None) -> tuple[list[str], int]:
    """Audit a directory tree. Returns (violation_lines, files_scanned).

    Without ``target_dir`` the real erebus/ tree (minus core) is scanned. With
    one, every ``*.py`` under it is scanned (used by the self-test fixture dir).
    """
    if target_dir is None:
        files = _iter_target_files()
        base = root or REPO_ROOT
    else:
        files = sorted(
            p for p in target_dir.rglob("*.py") if "__pycache__" not in p.parts
        )
        base = root or target_dir

    violations: list[str] = []
    for path in files:
        violations.extend(audit_file(path, root=base))
    return violations, len(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Static boundary audit (FR-008).")
    parser.add_argument("--dir", type=Path, default=None,
                        help="Audit this directory instead of the real erebus/ tree "
                             "(every *.py is scanned; no path allowlist relief).")
    args = parser.parse_args(argv)

    if args.dir is not None:
        violations, count = audit_tree(target_dir=args.dir, root=args.dir)
    else:
        violations, count = audit_tree()

    for line in violations:
        print(f"VIOLATION {line}")

    if violations:
        print(f"\nboundary audit: {len(violations)} violation(s) in {count} files",
              file=sys.stderr)
        return 1
    print(f"boundary audit: clean ({count} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
