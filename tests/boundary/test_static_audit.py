"""Self-test for the FR-008 static boundary audit (spec FR-010f, T034).

The audit (tests/audit_boundary.py) is the gateway that proves PII tokenization
lives only in erebus/core/. A gateway is only trustworthy if it provably
catches a cheat, so this test points the audit at a synthetic adapter that
breaks the invariant three ways and asserts every cheat is named. It then
asserts the audit passes on the real erebus/ tree (no violations).

Real-world artifact under assertion: the audit's emitted findings (the lines a
maintainer or CI reads), not any model-side view.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from tests import audit_boundary as audit

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def test_audit_flags_every_cheat_in_the_fixture():
    """The cheating adapter trips all three forbidden categories."""
    violations, scanned = audit.audit_tree(target_dir=FIXTURES_DIR, root=FIXTURES_DIR)
    assert scanned >= 1, "fixtures dir scanned no files"

    blob = "\n".join(violations)
    # (a) re-implements detokenize  (tokenize/detokenize family)
    assert any("detokenize" in v and "cheating_adapter.py" in v for v in violations), (
        f"audit missed the re-implemented detokenize; got:\n{blob}")
    # (b) calls open_known_values  (DB-lifecycle family)
    assert any("open_known_values" in v for v in violations), (
        f"audit missed the open_known_values call; got:\n{blob}")
    # (c) opens 'known_values.db' directly  (forbidden file path)
    assert any("known_values.db" in v for v in violations), (
        f"audit missed the direct known_values.db open; got:\n{blob}")

    # Findings are real path:line: reason lines pointing at the fixture.
    for line in violations:
        head = line.split(":", 1)[0]
        assert head.endswith(".py"), f"finding is not a path:line: line: {line!r}"


def test_audit_exit_code_nonzero_on_fixture():
    """main(--dir fixtures) returns 1 (the CI-visible failure signal)."""
    rc = audit.main(["--dir", str(FIXTURES_DIR)])
    assert rc == 1, f"audit exit code on a cheating tree should be 1, got {rc}"


def test_audit_passes_on_the_real_tree():
    """The real erebus/ tree (minus core) must be boundary-clean."""
    violations, scanned = audit.audit_tree()
    assert scanned > 0, "audit scanned no files on the real tree"
    assert violations == [], (
        "boundary audit found violations on the real erebus/ tree:\n"
        + "\n".join(violations))


if __name__ == "__main__":
    from helpers import run
    run([
        test_audit_flags_every_cheat_in_the_fixture,
        test_audit_exit_code_nonzero_on_fixture,
        test_audit_passes_on_the_real_tree,
    ], "static boundary audit self-test (FR-010f)")
