"""Degraded-state safety guard (spec 011, US3 / SC-005).

When the detector is genuinely unavailable, detection MUST stay in the explicit
degraded state, the regex/blacklist backstop MUST still redact structured PII
(email, an international-format phone, an API key), and no raw value the backstop
should have caught may be forwarded. Recovery is on the next request once the
detector is back. This asserts unchanged behavior — no detection logic is
modified by spec 011.
"""

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.core import state
from erebus.filter import tokenize

_EMAIL = "jan.jansen@voorbeeld-bv.test"
_PHONE = "+31 6 12345678"
_APIKEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456"


def test_backstop_redacts_structured_pii_while_degraded():
    """Detector off -> explicit degraded state, but the deterministic backstop
    still catches structured PII and forwards no raw value."""
    text = f"Mail {_EMAIL}, bel {_PHONE}, key {_APIKEY}"
    with patch.dict(os.environ, {"EREBUS_DISABLE_GLINER": "1"}):
        sanitized, tokens = tokenize(text, mode="relaxed")
        degraded = state.detector_degraded()

    assert degraded, "detector-unavailable must be an explicit degraded signal"
    assert _EMAIL not in sanitized
    assert _PHONE not in sanitized and "12345678" not in sanitized
    assert _APIKEY not in sanitized and "sk-ant" not in sanitized
    assert "[EMAIL_ADDRESS_" in sanitized
    assert "[PHONE_NUMBER_" in sanitized
    assert len(tokens) >= 3
    print(f"  ok backstop redacts structured PII while degraded: {sanitized}")


def test_detection_recovers_on_next_request():
    """Once the detector is back, the next request uses NER (not degraded)."""
    person = "Marieke de Boer"

    def _fake_entities(text, *a, **k):
        idx = text.find(person)
        if idx == -1:
            return []
        return [{"start": idx, "end": idx + len(person),
                 "label": "person", "text": person}]

    with patch("erebus.core.detect._predict_entities", side_effect=_fake_entities):
        sanitized, tokens = tokenize(f"Vraag het aan {person}", mode="strict")
        degraded = state.detector_degraded()

    assert person not in sanitized, "NER-caught name must be tokenized on recovery"
    assert not degraded, "a served request must not be marked degraded"
    assert len(tokens) >= 1
    print(f"  ok detection recovers and uses NER on the next request: {sanitized}")


if __name__ == "__main__":
    tests = [
        test_backstop_redacts_structured_pii_while_degraded,
        test_detection_recovers_on_next_request,
    ]
    print("\n=== Degraded backstop tests ===\n")
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
