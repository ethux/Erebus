"""The shim must apply Boundary rewrites even when zero new tokens are minted.

Regression for 2026-06-10: _process_text_block swapped in the sanitized text
only when new tokens were minted. The known-value pre-scan rewrites text while
minting nothing, so already-known values reached the model RAW. The rule (same
as the proxy adapter): apply the sanitized text whenever it differs.

Uses a stub boundary — no detector, no model, no real Known-Value DB.
"""
import os
import sys
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.shim import _state, outgoing

NAME = "Jan Modaal"            # synthetic fixture, never a real name
TOKEN = "[PERSON_1_" "aaaaaa]"


class _StubBoundary:
    """Rewrites via a fixed mapping and never mints — the pre-scan-only case."""

    def __init__(self, mapping: dict):
        self.mapping = mapping

    def to_model(self, text: str):
        out = text
        for value, token in self.mapping.items():
            out = out.replace(value, token)
        return out, {}

    @contextmanager
    def turn(self):
        yield SimpleNamespace(degraded=False, degraded_reason="")


def _patched(stub: _StubBoundary):
    return (
        patch.object(_state, "get_boundary", return_value=stub),
        patch.object(outgoing.REPO_CONFIG, "log_enabled", False),
    )


def test_text_block_applies_retokenized_text_without_new_mints():
    block = {"type": "text", "text": f"Stuur dit naar {NAME} vandaag"}
    p1, p2 = _patched(_StubBoundary({NAME: TOKEN}))
    with p1, p2:
        minted, rewrote = outgoing._process_text_block(block)
    assert block["text"] == f"Stuur dit naar {TOKEN} vandaag", block["text"]
    assert minted == {} and rewrote is True
    print("  ✓ user text rewritten by known-value retokenization is applied")


def test_tool_result_string_applies_retokenized_text():
    block = {"type": "tool_result", "content": f"Owner: {NAME}"}
    p1, p2 = _patched(_StubBoundary({NAME: TOKEN}))
    with p1, p2:
        _minted, rewrote = outgoing._process_tool_result_block(block)
    assert block["content"] == f"Owner: {TOKEN}", block["content"]
    assert rewrote is True
    print("  ✓ tool result (string) rewritten by retokenization is applied")


def test_tool_result_list_applies_retokenized_text():
    block = {"type": "tool_result", "content": [{"type": "text", "text": f"cc {NAME}"}]}
    p1, p2 = _patched(_StubBoundary({NAME: TOKEN}))
    with p1, p2:
        _minted, rewrote = outgoing._process_tool_result_block(block)
    assert block["content"][0]["text"] == f"cc {TOKEN}", block["content"]
    assert rewrote is True
    print("  ✓ tool result (list) rewritten by retokenization is applied")


def test_clean_text_is_left_untouched():
    original = "niets bijzonders hier"
    block = {"type": "text", "text": original}
    p1, p2 = _patched(_StubBoundary({}))
    with p1, p2:
        minted, rewrote = outgoing._process_text_block(block)
    assert block["text"] == original
    assert minted == {} and rewrote is False
    print("  ✓ clean text passes through unchanged")


def test_retokenized_only_message_still_gets_token_hint():
    """A message rewritten purely via known values must carry the <pii-filter>
    hint, or the model sees bare bracketed tokens with no explanation."""
    import json
    line = json.dumps({"type": "user", "message": {"role": "user", "content": [
        {"type": "text", "text": f"Bel {NAME} vanmiddag"}]}})
    p1, p2 = _patched(_StubBoundary({NAME: TOKEN}))
    with p1, p2, patch.object(_state, "mark_outgoing_sent", lambda turn_type: None):
        out = json.loads(outgoing.process_outgoing(line))
    text = out["message"]["content"][0]["text"]
    assert TOKEN in text, text
    assert "<pii-filter>" in text, "retokenized-only turn lost the token hint"
    print("  ✓ retokenized-only message keeps the token hint")


def test_string_form_message_content_is_tokenized():
    """Claude's wire format allows message.content to be a plain string; the
    shim must tokenize it like a text block (it previously bypassed entirely)."""
    import json
    line = json.dumps({"type": "user", "message": {"role": "user",
                                                   "content": f"Bel {NAME} morgen"}})
    p1, p2 = _patched(_StubBoundary({NAME: TOKEN}))
    with p1, p2, patch.object(_state, "mark_outgoing_sent", lambda turn_type: None):
        out = json.loads(outgoing.process_outgoing(line))
    content = out["message"]["content"]
    assert TOKEN in content, content
    assert NAME not in content, "string-form content leaked the raw value"
    assert "<pii-filter>" in content, "string-form content lost the token hint"
    print("  ✓ string-form message content is tokenized and hinted")


if __name__ == "__main__":
    tests = [
        test_text_block_applies_retokenized_text_without_new_mints,
        test_tool_result_string_applies_retokenized_text,
        test_tool_result_list_applies_retokenized_text,
        test_clean_text_is_left_untouched,
        test_retokenized_only_message_still_gets_token_hint,
        test_string_form_message_content_is_tokenized,
    ]
    print("\n=== Shim Retokenize Gate Tests ===\n")
    passed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as exc:
            print(f"  FAIL {test.__name__}: {exc}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
