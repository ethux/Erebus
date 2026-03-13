"""Tests for PII detection and tokenization."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from erebus.filter import tokenize, detokenize


def test_email_detected():
    text = "Send this to john.doe@acmecorp.com please"
    sanitized, tokens = tokenize(text)
    assert "john.doe@acmecorp.com" not in sanitized
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
    text = "Transfer to NL91ABNA0417164300 by Friday"
    sanitized, tokens = tokenize(text)
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


if __name__ == "__main__":
    tests = [
        test_email_detected,
        test_api_key_detected,
        test_gitlab_token_detected,
        test_password_detected,
        test_iban_detected,
        test_custom_entity_detected,
        test_detokenize_restores_values,
        test_clean_text_unchanged,
    ]
    print("\n=== PII Filter Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
