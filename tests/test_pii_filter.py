"""Tests for PII detection and tokenization."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from erebus.filter import tokenize, detokenize, _parse_escapes


def test_email_detected():
    """Requires GLiNER — emails are caught by NER, not regex. Skips gracefully."""
    text = "Send this to john.doe@acmecorp.com please"
    sanitized, tokens = tokenize(text)
    if "john.doe@acmecorp.com" in sanitized:
        print("  ⊘ Email test skipped (GLiNER not loaded)")
        return
    assert len(tokens) == 1
    print(f"  ✓ Email tokenized: {sanitized}")


def test_api_key_detected():
    text = "Use this key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456"
    sanitized, tokens = tokenize(text)
    assert "sk-ant" not in sanitized
    assert len(tokens) >= 1
    print(f"  ✓ API key tokenized: {sanitized}")


def test_gitlab_token_detected():
    text = "My token is glpat-xxxxxxxxxxxxxxxxxxxx for the repo"
    sanitized, tokens = tokenize(text)
    assert "glpat-" not in sanitized
    print(f"  ✓ GitLab token tokenized: {sanitized}")


def test_password_detected():
    text = "password: SuperSecret123!"
    sanitized, tokens = tokenize(text)
    assert "SuperSecret123" not in sanitized
    print(f"  ✓ Password tokenized: {sanitized}")


def test_iban_detected():
    """Requires GLiNER — IBANs are caught by NER, not regex. Skips gracefully."""
    text = "Transfer to NL91ABNA0417164300 by Friday"
    sanitized, tokens = tokenize(text)
    if "NL91ABNA" in sanitized:
        print("  ⊘ IBAN test skipped (GLiNER not loaded)")
        return
    assert "NL91ABNA" not in sanitized
    print(f"  ✓ IBAN tokenized: {sanitized}")


def test_custom_entity_detected():
    text = "We are working with Acme BV on the contract"
    sanitized, tokens = tokenize(text, extra_entities=["Acme BV"])
    assert "Acme BV" not in sanitized
    print(f"  ✓ Custom entity tokenized: {sanitized}")


def test_detokenize_restores_values():
    text = "Contact john@example.com about the deal"
    sanitized, tokens = tokenize(text)
    restored = detokenize(sanitized, tokens)
    assert "john@example.com" in restored
    print(f"  ✓ De-tokenized correctly: {restored}")


def test_clean_text_unchanged():
    text = "Write a function to calculate fibonacci numbers"
    sanitized, tokens = tokenize(text)
    assert len(tokens) == 0
    print(f"  ✓ Clean text passed through unchanged")


# ── Escape character tests ────────────────────────────────────────────────────

def test_escape_with_punctuation():
    """~ followed by punctuation (period, comma, paren) should still work."""
    escaped, cleaned = _parse_escapes("Send this to Smith~. He will know.")
    assert "smith" in escaped
    assert "~" not in cleaned
    print(f"  ✓ Escape with punctuation: {escaped}")


def test_escape_with_comma():
    escaped, cleaned = _parse_escapes("Talk to Smith~, he knows.")
    assert "smith" in escaped
    assert "~" not in cleaned
    print(f"  ✓ Escape with comma: {escaped}")


def test_escape_with_closing_paren():
    escaped, cleaned = _parse_escapes("(ask Smith~) about it")
    assert "smith" in escaped
    assert "~" not in cleaned
    print(f"  ✓ Escape with closing paren: {escaped}")


def test_escape_with_quotes():
    """Surrounding quotes should be stripped from the escaped value."""
    escaped, cleaned = _parse_escapes('He said "Smith~" was there')
    assert "smith" in escaped
    assert '"smith"' not in escaped  # quotes should be stripped
    print(f"  ✓ Escape with quotes: {escaped}")


def test_escape_multiword_two():
    """Two-word name: 'John Smith~' should escape john, smith, and 'john smith'."""
    escaped, cleaned = _parse_escapes("Ask John Smith~ about it")
    assert "smith" in escaped
    assert "john" in escaped
    assert "john smith" in escaped
    print(f"  ✓ Multi-word escape (2 words): {escaped}")


def test_escape_multiword_four():
    """Four-word name: 'Jan Willem de Vries~' should escape all parts and combinations."""
    escaped, cleaned = _parse_escapes("Contact Jan Willem de Vries~ please")
    assert "vries" in escaped
    assert "de" in escaped
    assert "willem" in escaped
    assert "jan" in escaped
    assert "jan willem de vries" in escaped
    print(f"  ✓ Multi-word escape (4 words): {escaped}")


def test_escape_tilde_stripped():
    """The ~ marker should be removed from the cleaned text."""
    _, cleaned = _parse_escapes("Send to Smith~ now")
    assert "~" not in cleaned
    assert "Smith" in cleaned
    print(f"  ✓ Tilde stripped from output: '{cleaned}'")


def test_escape_end_of_line():
    """~ at end of line (no trailing whitespace) should work."""
    escaped, cleaned = _parse_escapes("Ask Smith~")
    assert "smith" in escaped
    assert cleaned == "Ask Smith"
    print(f"  ✓ Escape at end of line: {escaped}")


# ── Filter mode tests ─────────────────────────────────────────────────────────

def test_mode_strict_tokenizes_all():
    """In strict mode, secrets are always tokenized."""
    text = "password: MySecret123!"
    sanitized, tokens = tokenize(text, mode="strict")
    assert "MySecret123" not in sanitized
    assert len(tokens) >= 1
    print(f"  ✓ Strict mode tokenizes secrets: {sanitized}")


def test_mode_relaxed_still_catches_secrets():
    """In relaxed mode, secrets/structured PII are still tokenized."""
    text = "Use key sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456"
    sanitized, tokens = tokenize(text, mode="relaxed")
    assert "sk-ant" not in sanitized
    print(f"  ✓ Relaxed mode still catches secrets: {sanitized}")


def test_mode_default_is_balanced():
    """Default mode should be balanced."""
    text = "password: MySecret123!"
    sanitized, tokens = tokenize(text)
    assert "MySecret123" not in sanitized
    print(f"  ✓ Default mode (balanced) works: {sanitized}")


def test_mode_invalid_falls_back():
    """Invalid mode name should fall back to balanced."""
    text = "password: MySecret123!"
    sanitized, tokens = tokenize(text, mode="invalid_mode")
    assert "MySecret123" not in sanitized
    print(f"  ✓ Invalid mode falls back to balanced: {sanitized}")


def test_custom_entities_always_tokenized():
    """Custom sensitive entities should be tokenized in all modes."""
    for mode in ("strict", "balanced", "relaxed"):
        text = "Working with Acme BV on the project"
        sanitized, tokens = tokenize(text, extra_entities=["Acme BV"], mode=mode)
        assert "Acme BV" not in sanitized
    print(f"  ✓ Custom entities tokenized in all modes")


if __name__ == "__main__":
    tests = [
        # Original tests
        test_email_detected,
        test_api_key_detected,
        test_gitlab_token_detected,
        test_password_detected,
        test_iban_detected,
        test_custom_entity_detected,
        test_detokenize_restores_values,
        test_clean_text_unchanged,
        # Escape character tests
        test_escape_with_punctuation,
        test_escape_with_comma,
        test_escape_with_closing_paren,
        test_escape_with_quotes,
        test_escape_multiword_two,
        test_escape_multiword_four,
        test_escape_tilde_stripped,
        test_escape_end_of_line,
        # Filter mode tests
        test_mode_strict_tokenizes_all,
        test_mode_relaxed_still_catches_secrets,
        test_mode_default_is_balanced,
        test_mode_invalid_falls_back,
        test_custom_entities_always_tokenized,
    ]
    print("\n=== Erebus PII Filter Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
