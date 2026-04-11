"""
End-to-end tests for the PII filter pipeline.

Tests the full tokenize → detokenize round-trip across all three filter modes.
GLiNER is mocked via _predict_entities so the tests don't depend on the daemon
or the ~1.8GB model being loaded.

Style matches the other test files in this directory: plain functions with a
manual runner — no pytest dependency.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.filter import (
    MODES,
    _parse_escapes,
    detokenize,
    tokenize,
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fake_entities(text, entities):
    """Build GLiNER-style entity dicts with correct offsets in the given text."""
    result = []
    for value, label in entities:
        start = text.find(value)
        if start == -1:
            continue
        result.append({
            "start": start,
            "end": start + len(value),
            "text": value,
            "label": label,
        })
    return result


def _tokenize_mocked(text, entities, **kwargs):
    """Run tokenize() with _predict_entities mocked to return `entities`."""
    def mock_predict(t):
        return _fake_entities(t, entities)
    with patch("erebus.filter._predict_entities", side_effect=mock_predict):
        return tokenize(text, **kwargs)


# ── Round-trip ────────────────────────────────────────────────────────────────

def test_secret_round_trip():
    text = "Use key sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456 for auth"
    sanitized, tokens = tokenize(text)
    assert detokenize(sanitized, tokens) == text
    print("  ✓ Secret round-trip")


def test_password_round_trip():
    text = "password: SuperSecret123!"
    sanitized, tokens = tokenize(text)
    assert detokenize(sanitized, tokens) == text
    print("  ✓ Password round-trip")


def test_multiple_secrets_round_trip():
    text = (
        "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456\n"
        "tok glpat-xxxxxxxxxxxxxxxxxxxx\n"
        "password: MyP@ssw0rd!"
    )
    sanitized, tokens = tokenize(text)
    assert detokenize(sanitized, tokens) == text
    print("  ✓ Multiple secrets round-trip")


def test_person_round_trip_balanced():
    """Balanced mode tokenizes only the last name; round-trip restores the full name."""
    text = "Contact John Smith about the project"
    sanitized, tokens = _tokenize_mocked(
        text, [("John Smith", "person")], mode="balanced"
    )
    assert "John" in sanitized
    assert "Smith" not in sanitized
    assert "John Smith" in detokenize(sanitized, tokens)
    print("  ✓ Balanced person round-trip")


def test_custom_entity_round_trip():
    text = "Working with Acme BV on the deal"
    sanitized, tokens = tokenize(text, extra_entities=["Acme BV"])
    assert detokenize(sanitized, tokens) == text
    print("  ✓ Custom entity round-trip")


# ── Mode behavior: person names ──────────────────────────────────────────────

def test_strict_tokenizes_full_name():
    sanitized, _ = _tokenize_mocked(
        "Ask John Smith about the bug", [("John Smith", "person")], mode="strict"
    )
    assert "John" not in sanitized and "Smith" not in sanitized
    assert "[PERSON_" in sanitized
    print("  ✓ Strict tokenizes full name")


def test_strict_tokenizes_single_name():
    sanitized, _ = _tokenize_mocked(
        "Ask John about the bug", [("John", "person")], mode="strict"
    )
    assert "John" not in sanitized
    assert "[PERSON_" in sanitized
    print("  ✓ Strict tokenizes single name")


def test_balanced_keeps_first_name():
    sanitized, _ = _tokenize_mocked(
        "Ask John Smith about the bug", [("John Smith", "person")], mode="balanced"
    )
    assert "John" in sanitized
    assert "Smith" not in sanitized
    assert "[PERSON_" in sanitized
    print("  ✓ Balanced keeps first name")


def test_balanced_keeps_single_name():
    sanitized, tokens = _tokenize_mocked(
        "Ask John about the bug", [("John", "person")], mode="balanced"
    )
    assert "John" in sanitized
    assert len(tokens) == 0
    print("  ✓ Balanced keeps single name")


def test_balanced_three_part_name():
    """'Jan de Vries' — keep 'Jan de', tokenize 'Vries'."""
    sanitized, _ = _tokenize_mocked(
        "Contact Jan de Vries for the review",
        [("Jan de Vries", "person")],
        mode="balanced",
    )
    assert "Jan de" in sanitized
    assert "Vries" not in sanitized
    print("  ✓ Balanced three-part name")


def test_relaxed_keeps_all_names():
    sanitized, tokens = _tokenize_mocked(
        "Ask John Smith about the bug", [("John Smith", "person")], mode="relaxed"
    )
    assert "John Smith" in sanitized
    assert len(tokens) == 0
    print("  ✓ Relaxed keeps all names")


# ── Mode behavior: organizations ─────────────────────────────────────────────

def test_strict_tokenizes_any_org():
    sanitized, _ = _tokenize_mocked(
        "Contract with Acme", [("Acme", "organization")], mode="strict"
    )
    assert "Acme" not in sanitized
    assert "[ORGANIZATION_" in sanitized
    print("  ✓ Strict tokenizes single-word org")


def test_balanced_keeps_single_word_org():
    sanitized, tokens = _tokenize_mocked(
        "Contract with Acme", [("Acme", "organization")], mode="balanced"
    )
    assert "Acme" in sanitized
    assert len(tokens) == 0
    print("  ✓ Balanced keeps single-word org")


def test_balanced_tokenizes_multi_word_org():
    sanitized, _ = _tokenize_mocked(
        "Contract with Acme Corp", [("Acme Corp", "organization")], mode="balanced"
    )
    assert "Acme Corp" not in sanitized
    assert "[ORGANIZATION_" in sanitized
    print("  ✓ Balanced tokenizes multi-word org")


def test_relaxed_keeps_all_orgs():
    sanitized, tokens = _tokenize_mocked(
        "Contract with Acme Corp", [("Acme Corp", "organization")], mode="relaxed"
    )
    assert "Acme Corp" in sanitized
    assert len(tokens) == 0
    print("  ✓ Relaxed keeps all orgs")


# ── Secrets are always tokenized ──────────────────────────────────────────────

def test_password_tokenized_in_all_modes():
    for mode in MODES:
        sanitized, _ = tokenize("password: SuperSecret123!", mode=mode)
        assert "SuperSecret123" not in sanitized, f"password leaked in {mode} mode"
    print("  ✓ Passwords tokenized in all modes")


def test_github_token_tokenized_in_all_modes():
    for mode in MODES:
        sanitized, _ = tokenize(
            "Use ghp_abcdefghijklmnopqrstuvwxyz1234567890 for auth", mode=mode
        )
        assert "ghp_" not in sanitized, f"GitHub token leaked in {mode} mode"
    print("  ✓ GitHub tokens tokenized in all modes")


def test_private_key_tokenized_in_all_modes():
    for mode in MODES:
        sanitized, _ = tokenize("-----BEGIN RSA PRIVATE KEY----- is here", mode=mode)
        assert "PRIVATE KEY" not in sanitized, f"private key leaked in {mode} mode"
    print("  ✓ Private keys tokenized in all modes")


# ── Escape character through the full pipeline ───────────────────────────────

def test_escaped_name_not_tokenized():
    """A name with ~ should pass through even in strict mode."""
    sanitized, tokens = _tokenize_mocked(
        "Ask John Smith~ about the bug", [("John Smith", "person")], mode="strict"
    )
    assert "John Smith" in sanitized
    assert "~" not in sanitized
    assert len(tokens) == 0
    print("  ✓ Escaped name survives strict mode")


def test_escaped_name_with_punctuation():
    sanitized, _ = _tokenize_mocked(
        "Talk to Smith~. He knows.", [("Smith", "person")], mode="strict"
    )
    assert "Smith" in sanitized
    assert "~" not in sanitized
    assert sanitized.startswith("Talk to Smith.")
    print("  ✓ Escape with trailing punctuation")


def test_partial_escape_mixed():
    """One name escaped, another not — only the unescaped one should be tokenized."""
    sanitized, tokens = _tokenize_mocked(
        "Ask John Smith~ and Jane Doe about it",
        [("John Smith", "person"), ("Jane Doe", "person")],
        mode="strict",
    )
    assert "John Smith" in sanitized
    assert "Jane Doe" not in sanitized
    assert len(tokens) == 1
    print("  ✓ Partial escape mixes correctly")


def test_escape_does_not_block_secrets():
    """Escaping a word should not prevent nearby secrets from being tokenized."""
    sanitized, _ = _tokenize_mocked(
        "Smith~ uses password: SuperSecret123!",
        [("Smith", "person")],
        mode="strict",
    )
    assert "Smith" in sanitized
    assert "SuperSecret123" not in sanitized
    print("  ✓ Escape doesn't block secrets")


def test_escape_multiword_dutch_name():
    """'Jan Willem de Vries~' — all 4 parts escaped through the full pipeline."""
    sanitized, tokens = _tokenize_mocked(
        "Contact Jan Willem de Vries~ for the review",
        [("Jan Willem de Vries", "person")],
        mode="strict",
    )
    assert "Jan Willem de Vries" in sanitized
    assert "~" not in sanitized
    assert len(tokens) == 0
    print("  ✓ Multi-word Dutch name escape")


# ── Mixed content (real-world scenarios) ──────────────────────────────────────

def test_balanced_mixed_message():
    text = (
        "Ask John Smith to send the contract. "
        "Use key sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456 "
        "for Acme Corp access."
    )
    sanitized, tokens = _tokenize_mocked(
        text,
        [("John Smith", "person"), ("Acme Corp", "organization")],
        mode="balanced",
    )
    assert "John" in sanitized
    assert "Smith" not in sanitized
    assert "Acme Corp" not in sanitized
    assert "sk-ant" not in sanitized
    restored = detokenize(sanitized, tokens)
    assert "Smith" in restored and "sk-ant" in restored
    print("  ✓ Balanced mixed message")


def test_relaxed_only_tokenizes_secrets():
    sanitized, _ = _tokenize_mocked(
        "Ask John Smith about password: SuperSecret123! for Acme Corp.",
        [("John Smith", "person"), ("Acme Corp", "organization")],
        mode="relaxed",
    )
    assert "John Smith" in sanitized
    assert "Acme Corp" in sanitized
    assert "SuperSecret123" not in sanitized
    print("  ✓ Relaxed only tokenizes secrets")


def test_custom_entities_always_tokenized():
    for mode in MODES:
        sanitized, _ = _tokenize_mocked(
            "Project Phoenix is on track",
            [],
            extra_entities=["Project Phoenix"],
            mode=mode,
        )
        assert "Project Phoenix" not in sanitized, f"custom entity leaked in {mode}"
    print("  ✓ Custom entities tokenized in all modes")


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_empty_string():
    sanitized, tokens = tokenize("")
    assert sanitized == ""
    assert tokens == {}
    print("  ✓ Empty string")


def test_clean_text_no_pii():
    text = "Write a function to sort a list"
    for mode in MODES:
        sanitized, tokens = tokenize(text, mode=mode)
        assert sanitized == text
        assert tokens == {}
    print("  ✓ Clean text unchanged across all modes")


def test_only_tildes():
    sanitized, _ = tokenize("word~ another~ third~")
    assert "~" not in sanitized
    print("  ✓ Only tildes")


def test_invalid_mode_uses_default():
    sanitized, _ = tokenize("password: MySecret123!", mode="nonexistent")
    assert "MySecret123" not in sanitized
    print("  ✓ Invalid mode falls back to default")


def test_detokenize_empty_map():
    """Detokenize with an empty map should return text unchanged."""
    text = "Nothing to detokenize [PERSON_1_abc123] here"
    assert detokenize(text, {}) == text
    print("  ✓ Detokenize with empty map")


if __name__ == "__main__":
    tests = [
        test_secret_round_trip,
        test_password_round_trip,
        test_multiple_secrets_round_trip,
        test_person_round_trip_balanced,
        test_custom_entity_round_trip,
        test_strict_tokenizes_full_name,
        test_strict_tokenizes_single_name,
        test_balanced_keeps_first_name,
        test_balanced_keeps_single_name,
        test_balanced_three_part_name,
        test_relaxed_keeps_all_names,
        test_strict_tokenizes_any_org,
        test_balanced_keeps_single_word_org,
        test_balanced_tokenizes_multi_word_org,
        test_relaxed_keeps_all_orgs,
        test_password_tokenized_in_all_modes,
        test_github_token_tokenized_in_all_modes,
        test_private_key_tokenized_in_all_modes,
        test_escaped_name_not_tokenized,
        test_escaped_name_with_punctuation,
        test_partial_escape_mixed,
        test_escape_does_not_block_secrets,
        test_escape_multiword_dutch_name,
        test_balanced_mixed_message,
        test_relaxed_only_tokenizes_secrets,
        test_custom_entities_always_tokenized,
        test_empty_string,
        test_clean_text_no_pii,
        test_only_tildes,
        test_invalid_mode_uses_default,
        test_detokenize_empty_map,
    ]
    print("\n=== Erebus PII Filter E2E Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
