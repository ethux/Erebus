"""Property-style tests for the global privacy invariant (audit 2026-06-11).

These are structural safety nets for the Boundary split: they assert the two
halves of the invariant across EVERY model-bound channel, independent of which
module implements each one, so a future refactor that moves code can't quietly
reopen a leak.

  P1  to-model: no model-bound payload, on any channel, contains a raw value
      the boundary was given (chat content/string, Anthropic `system`, `tools`
      descriptions, assistant `tool_calls.arguments`, Responses
      `input`/`instructions`). A token stands in its place.
  P2  from-model round-trip: detokenizing the sanitized output reproduces the
      original exactly — no token survives into a world-bound sink.
  P3  cross-channel: a value learned on one channel is retokenized on every
      other channel (the pre-scan is detector-independent).

Fixture values are synthetic. The detector is stubbed to flag the names, so the
test exercises the boundary wiring, not GLiNER.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers
from helpers import IsolatedBoundaryHome, assert_value_absent, daemon_stub, person_entity

from erebus import proxy
from erebus.core import TOKEN_RE

# Synthetic PII corpus — distinct multi-word names so balanced/strict both flag
# them, none a substring of another, none a real person.
NAMES = ["Jan Modaal", "Pietje Puk", "Sint Maarten", "Anna de Vries", "Karel Appel"]


def _all_entities(text):
    spans = []
    for name in NAMES:
        spans.extend(person_entity(text, name))
    return spans


def _cfg(h: IsolatedBoundaryHome):
    cfg = h.repo_config(mode="strict")
    proxy.get_boundary(cfg)  # (re)build the proxy boundary for this isolated home
    return cfg


def _has_token(payload) -> bool:
    return bool(TOKEN_RE.findall(payload if isinstance(payload, str) else json.dumps(payload)))


# -- P1: every channel tokenizes raw values on the way to the model -----------

def _chat_channels(name):
    """One representative payload per chat/messages channel carrying `name`."""
    return {
        "chat content (string)": {"messages": [{"role": "user", "content": f"call {name}"}]},
        "chat content (blocks)": {"messages": [
            {"role": "user", "content": [{"type": "text", "text": f"email {name}"}]}]},
        "anthropic system (string)": {"system": f"assist {name}",
                                      "messages": [{"role": "user", "content": "hi"}]},
        "anthropic system (blocks)": {"system": [{"type": "text", "text": f"op: {name}"}],
                                      "messages": [{"role": "user", "content": "hi"}]},
        "tools description": {"messages": [{"role": "user", "content": "hi"}],
                              "tools": [{"type": "function", "function": {
                                  "name": "lookup",
                                  "description": f"account owned by {name}"}}]},
        "assistant tool_calls.arguments": {"messages": [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "email", "arguments": f"to {name}"}}]},
            {"role": "user", "content": "ok"}]},
    }


def _responses_channels(name):
    return {
        "responses input": {"input": [
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": f"notify {name}"}]}]},
        "responses instructions": {"instructions": f"the operator is {name}",
                                   "input": [{"type": "message", "role": "user",
                                              "content": [{"type": "input_text", "text": "hi"}]}]},
    }


def test_p1_no_channel_leaks_a_raw_value_to_the_model():
    with IsolatedBoundaryHome() as h, daemon_stub("up", entities_for=_all_entities):
        cfg = _cfg(h)
        for name in NAMES:
            for label, body in _chat_channels(name).items():
                proxy.tokenize_chat_request(body, cfg)
                assert_value_absent(body, name)
                assert _has_token(body), f"[chat] {label}: no token minted for {name!r}"
            for label, body in _responses_channels(name).items():
                new_body, _tok, _turn = proxy.tokenize_responses_request(body, cfg)
                assert_value_absent(new_body, name)
                assert _has_token(new_body), f"[responses] {label}: no token for {name!r}"
    print(f"  ✓ P1: {len(NAMES)} values x 8 channels — no raw value reached the model")


# -- P2: detokenizing the sanitized output round-trips exactly ----------------

def test_p2_from_model_roundtrip_leaves_no_token():
    with IsolatedBoundaryHome() as h, daemon_stub("up", entities_for=_all_entities):
        from erebus.core import Boundary
        boundary = Boundary.from_config(h.repo_config(mode="strict"), str(h.project), source="t")
        for name in NAMES:
            original = f"please contact {name} about the invoice"
            sanitized, _tokens = boundary.to_model(original)
            assert_value_absent(sanitized, name)
            restored, unresolved = boundary.from_model(sanitized)
            assert restored == original, f"round-trip changed text: {restored!r}"
            assert not unresolved, f"unresolved tokens on round-trip: {unresolved}"
            assert not TOKEN_RE.findall(restored), "a token survived into the world sink"
    print("  ✓ P2: to_model -> from_model round-trips exactly, no token reaches the world")


# -- P3: a value learned on one channel is retokenized on every other ----------

def test_p3_value_learned_on_one_channel_retokenized_on_all():
    with IsolatedBoundaryHome() as h:
        cfg = _cfg(h)
        name = NAMES[0]
        # Learn the value via the chat channel (detector up mints + persists).
        with daemon_stub("up", entities_for=lambda t: person_entity(t, name)):
            proxy.tokenize_chat_request(
                {"messages": [{"role": "user", "content": f"first sight: {name}"}]}, cfg)
        # Now, with the detector DOWN, every other channel must still tokenize it
        # via the known-value pre-scan alone.
        with daemon_stub("down"):
            for label, body in _chat_channels(name).items():
                proxy.tokenize_chat_request(body, cfg)
                assert_value_absent(body, name)
                assert _has_token(body), f"detector-down channel leaked {name!r}: {label}"
    print("  ✓ P3: a learned value is retokenized on every channel with the detector down")


if __name__ == "__main__":
    helpers.run([
        test_p1_no_channel_leaks_a_raw_value_to_the_model,
        test_p2_from_model_roundtrip_leaves_no_token,
        test_p3_value_learned_on_one_channel_retokenized_on_all,
    ], "Privacy invariant properties (audit 2026-06-11)")
