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


def test_parse_verifier_keeps_only_first_ner():
    """piiranha + openai-pf together is wasteful; keep the first NER only."""
    assert parse_verifier_list("piiranha,openai-pf") == ["piiranha"]
    assert parse_verifier_list("openai-pf,piiranha") == ["openai-pf"]
    # Non-NER verifiers (e.g. gemma) are unaffected
    assert parse_verifier_list("piiranha,gemma,openai-pf") == ["piiranha", "gemma"]
    assert parse_verifier_list("openai-pf,gemma,piiranha") == ["openai-pf", "gemma"]
    print("  ✓ only one NER verifier survives parse")


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


# ── Piiranha integration ─────────────────────────────────────────────────────

@_no_gliner
def test_piiranha_span_is_tokenized():
    """A Piiranha-flagged span that GLiNER missed should be tokenized."""
    text = "The contact is Aisha Khan, age 34."
    mocked = [Span(start=15, end=25, text="Aisha Khan", label="PERSON")]
    with patch("erebus.verifiers.piiranha.predict", return_value=mocked):
        sanitized, tokens = tokenize(text, verifiers=["piiranha"])
    assert "Aisha Khan" not in sanitized
    assert any(k.startswith("[VERIFIED_PERSON_") for k in tokens)
    print(f"  ✓ Piiranha span tokenized: {sanitized}")


@_no_gliner
def test_verifier_skips_existing_token_region():
    """A span landing inside an existing [TOKEN_...] must be ignored."""
    text = "Hello [PERSON_1_abc123] how are you?"
    mocked = [Span(start=6, end=22, text="[PERSON_1_abc123]", label="PERSON")]
    with patch("erebus.verifiers.piiranha.predict", return_value=mocked):
        sanitized, tokens = tokenize(text, verifiers=["piiranha"])
    assert sanitized == text
    assert tokens == {}
    print("  ✓ verifier ignores spans inside existing tokens")


@_no_gliner
def test_verifier_skips_allowed_names():
    """A span matching an allowlist entry must pass through."""
    text = "Google is a company."
    mocked = [Span(start=0, end=6, text="Google", label="ORGANIZATION")]
    with patch("erebus.verifiers.piiranha.predict", return_value=mocked):
        sanitized, _tokens = tokenize(text, verifiers=["piiranha"])
    assert "Google" in sanitized
    print("  ✓ verifier respects allowlist (Google)")


# ── OpenAI privacy-filter integration ────────────────────────────────────────

@_no_gliner
def test_openai_pf_span_is_tokenized():
    text = "Email Carol Brown today."
    mocked = [Span(start=6, end=17, text="Carol Brown", label="PERSON")]
    with patch("erebus.verifiers.openai_pf.predict", return_value=mocked):
        sanitized, tokens = tokenize(text, verifiers=["openai-pf"])
    assert "Carol Brown" not in sanitized
    assert any(k.startswith("[VERIFIED_PERSON_") for k in tokens)
    print(f"  ✓ openai-pf span tokenized: {sanitized}")


@_no_gliner
def test_openai_pf_remote_url_is_used():
    """When verifier_openai_pf_url is set, predict() is called with that url."""
    text = "Email Carol Brown today."
    captured = {}
    def _fake_predict(t, url="", **kw):
        captured["url"] = url
        return []
    with patch("erebus.verifiers.openai_pf.predict", side_effect=_fake_predict):
        tokenize(text, verifiers=["openai-pf"],
                 verifier_openai_pf_url="https://gpu.box/predict")
    assert captured["url"] == "https://gpu.box/predict"
    print("  ✓ openai-pf remote URL is plumbed through")


@_no_gliner
def test_verifier_failure_is_silent():
    """If a verifier raises, tokenize must still return un-altered text."""
    text = "Hello world"
    def _boom(*_a, **_kw):
        raise RuntimeError("model unavailable")
    with patch("erebus.verifiers.piiranha.predict", side_effect=_boom):
        sanitized, tokens = tokenize(text, verifiers=["piiranha"])
    assert sanitized == text
    assert tokens == {}
    print("  ✓ verifier exceptions are swallowed")


# ── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_parse_verifier_empty,
        test_parse_verifier_list_trimmed_and_lowercased,
        test_parse_verifier_keeps_only_first_ner,
        test_unknown_verifier_name_is_ignored,
        test_no_verifiers_argument_is_noop,
        test_piiranha_span_is_tokenized,
        test_verifier_skips_existing_token_region,
        test_verifier_skips_allowed_names,
        test_openai_pf_span_is_tokenized,
        test_openai_pf_remote_url_is_used,
        test_verifier_failure_is_silent,
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
