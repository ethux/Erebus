"""FR-018 policy=block must actually drop the side effect (not just warn).

Regression for the 2026-06-11 audit: config.unresolved_token_action = "block"
was read only to interpolate it into the warning string; no code path enforced
it. The shim file write-back now refuses to finalize a file that would still
contain unresolved tokens under policy=block.
"""
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.core import Boundary
from erebus.shim import incoming

UNRESOLVED = "[PERSON_9_" "deadbe]"  # shaped like a token, never minted -> unresolvable
RESOLVED = "[PERSON_1_" "ab12cd]"     # this one resolves to a real value
RESOLVED_VALUE = "Jan Modaal"      # synthetic fixture


def test_boundary_block_policy_reads_config():
    warn = Boundary(SimpleNamespace(unresolved_token_action="warn"), "/tmp", "t")
    block = Boundary(SimpleNamespace(unresolved_token_action="block"), "/tmp", "t")
    assert warn.block_on_unresolved() is False
    assert block.block_on_unresolved() is True
    # default (attribute absent) is warn, never block
    assert Boundary(SimpleNamespace(), "/tmp", "t").block_on_unresolved() is False
    print("  ✓ block_on_unresolved reflects config, defaults to warn")


class _StubBoundary:
    """Resolves RESOLVED, leaves UNRESOLVED literal; policy is configurable.
    This partial resolution is what makes block vs warn observably different."""

    def __init__(self, block: bool):
        self._block = block

    def from_model(self, text: str):
        fixed = text.replace(RESOLVED, RESOLVED_VALUE)
        return fixed, [UNRESOLVED] if UNRESOLVED in fixed else []

    def block_on_unresolved(self) -> bool:
        return self._block


def _run_detokenize_file(block: bool) -> str:
    tmp = Path(tempfile.mktemp(suffix=".txt"))
    tmp.write_text(f"Contact {RESOLVED} and {UNRESOLVED} today\n", encoding="utf-8")
    try:
        with (
            patch.object(incoming._state, "get_boundary", return_value=_StubBoundary(block)),
            patch.object(incoming, "TOKEN_MAP", {"x": "y"}),  # non-empty so the guard passes
            patch.object(incoming, "CWD", str(tmp.parent)),
            patch.object(incoming, "detokenize", lambda text, _map: text),  # mirror resolves nothing
            patch.object(incoming._state, "_safe_log_event", lambda *a, **k: None),
        ):
            incoming._detokenize_file(str(tmp))
        return tmp.read_text(encoding="utf-8")
    finally:
        tmp.unlink(missing_ok=True)


def test_block_policy_drops_partial_write():
    # Under block, the whole write-back is dropped: the file keeps BOTH original
    # tokens, so the partially-resolved value never lands.
    out = _run_detokenize_file(block=True)
    assert RESOLVED in out and UNRESOLVED in out, "block must drop the entire write-back"
    assert RESOLVED_VALUE not in out, "block must not finalize the partially-resolved file"
    print("  ✓ policy=block drops the write-back when any token is unresolved")


def test_warn_policy_writes_partial_resolution():
    # Under warn (default), best-effort proceeds: the resolvable value lands,
    # the unresolved token stays literal.
    out = _run_detokenize_file(block=False)
    assert RESOLVED_VALUE in out, "warn must write the best-effort partial resolution"
    assert UNRESOLVED in out, "warn leaves the unresolved token literal"
    print("  ✓ policy=warn writes best-effort partial resolution")


if __name__ == "__main__":
    tests = [
        test_boundary_block_policy_reads_config,
        test_block_policy_drops_partial_write,
        test_warn_policy_writes_partial_resolution,
    ]
    print("\n=== Unresolved-token block policy (FR-018) ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as exc:
            print(f"  FAIL {t.__name__}: {exc}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
