"""
Tests for the verifier framework in filter._run_verifiers.

The framework itself is verifier-agnostic - it dispatches names to
concrete modules (added in follow-up commits) and handles dedup,
allowlist filtering, in-token avoidance, and graceful failure. These
tests exercise that framework with hand-crafted Span objects so they
don't need any model installed.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus import filter as erebus_filter
from erebus.filter import tokenize
from erebus.verifiers import Span, parse_verifier_list


def _no_gliner(fn):
    def wrapper(*a, **kw):
        with patch.object(erebus_filter, "_predict_entities", return_value=[]):
            return fn(*a, **kw)
    wrapper.__name__ = fn.__name__
    return wrapper


# ── parse_verifier_list ──────────────────────────────────────────────────────

def test_parse_verifier_empty():
    assert parse_verifier_list("") == []
    assert parse_verifier_list("   ") == []
    print("  ✓ empty config parses to no verifiers")


def test_parse_verifier_list_trimmed_and_lowercased():
    assert parse_verifier_list("Foo, BAR") == ["foo", "bar"]
    assert parse_verifier_list(" bar ,, foo") == ["bar", "foo"]
    print("  ✓ verifier spec is trimmed + lowercased + skips blanks")


# ── _run_verifiers framework ─────────────────────────────────────────────────

@_no_gliner
def test_unknown_verifier_name_is_ignored():
    """An unknown verifier name shouldn't crash - it just contributes no spans."""
    text = "Nothing to see"
    sanitized, tokens = tokenize(text, verifiers=["does-not-exist"])
    assert sanitized == text
    assert tokens == {}
    print("  ✓ unknown verifier name is a no-op (doesn't crash)")


@_no_gliner
def test_no_verifiers_argument_is_noop():
    """Passing no verifiers must not change behavior at all."""
    text = "Hello world"
    a, _ = tokenize(text)
    b, _ = tokenize(text, verifiers=[])
    assert a == b == text
    print("  ✓ tokenize without verifiers is identical to tokenize with empty list")


# ── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_verifier_empty,
        test_parse_verifier_list_trimmed_and_lowercased,
        test_unknown_verifier_name_is_ignored,
        test_no_verifiers_argument_is_noop,
    ]
    print("\n=== Verifier Framework Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
