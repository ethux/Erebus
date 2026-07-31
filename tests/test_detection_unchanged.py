"""Detection-output-unchanged guardrail (spec 011, FR-007 / SC-006).

Spec 011 is availability-only: it must NOT change what PII is detected or how it
is tokenized and restored. This pins the deterministic detection layer (the
regex/blacklist backstop, GLiNER off) against a fixed corpus so any change to
what is caught, or to round-trip restoration, fails the gate. The daemon-
reliability fixes touch only lifecycle/availability, never this path, so the
snapshot must stay green across the change.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["EREBUS_DISABLE_GLINER"] = "1"  # deterministic: regex/blacklist only

from erebus.filter import detokenize, tokenize

# (input, must-be-redacted values, expected token type marker, expected token count)
CORPUS = [
    ("Email me at anna.smit@voorbeeld-bv.test today",
     ["anna.smit@voorbeeld-bv.test"], "[EMAIL_ADDRESS_", 1),
    ("Contact: <bram@voorbeeld-warehouse.test>",
     ["bram@voorbeeld-warehouse.test"], "[EMAIL_ADDRESS_", 1),
    ("Bel me op +31 6 12345678 vanavond",
     ["+31 6 12345678", "12345678"], "[PHONE_NUMBER_", 1),
    ("US line +1 (555) 123-4567 ok",
     ["+1 (555) 123-4567"], "[PHONE_NUMBER_", 1),
    ("Use key sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456 now",
     ["sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456"], "[API_KEY_", 1),
    ("Repo token glpat-xxxxxxxxxxxxxxxxxxxx here",
     ["glpat-xxxxxxxxxxxxxxxxxxxx"], "[", 1),
]

CLEAN = [
    "Write a function to calculate fibonacci numbers",
    "The build passed on C++ with score +5 today",
    "Refactor the parser and bump to +2.0 next week",
]


def test_fixed_corpus_detection_and_tokenization_unchanged():
    for text, must_redact, marker, expected_tokens in CORPUS:
        sanitized, tokens = tokenize(text, mode="relaxed")
        for raw in must_redact:
            assert raw not in sanitized, f"{raw!r} leaked in {sanitized!r}"
        assert marker in sanitized, f"expected {marker} in {sanitized!r}"
        assert len(tokens) == expected_tokens, (
            f"{text!r}: {len(tokens)} tokens, expected {expected_tokens}")
        # Round-trip: detokenize restores the exact original.
        assert detokenize(sanitized, tokens) == text, f"round-trip changed {text!r}"
    print("  ok fixed PII corpus: detection spans + tokenization stable")


def test_clean_corpus_passes_through_untouched():
    for text in CLEAN:
        sanitized, tokens = tokenize(text, mode="relaxed")
        assert len(tokens) == 0, f"{text!r} over-matched into {tokens}"
        assert sanitized == text, f"clean text altered: {sanitized!r}"
    print("  ok clean corpus passes through with zero tokens")


if __name__ == "__main__":
    tests = [
        test_fixed_corpus_detection_and_tokenization_unchanged,
        test_clean_corpus_passes_through_untouched,
    ]
    print("\n=== Detection-unchanged corpus tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  x {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    if passed != len(tests):
        sys.exit(1)
