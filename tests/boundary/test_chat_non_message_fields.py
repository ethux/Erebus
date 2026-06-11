"""Chat/messages request fields OUTSIDE `messages` must cross the boundary.

Regression for the 2026-06-11 audit:
  * blocker: Anthropic /messages carries the system prompt as top-level
    `system` (string or block list); it was forwarded to the model RAW.
  * should-fix: `tools[].description` (function/tool schemas) was forwarded raw.
  * nit: assistant `tool_calls[].function.arguments` was not tokenized.

All three are now tokenized by tokenize_chat_request via the shared payload
walk. Fixture value is synthetic ('Jan Modaal'); asserts on real artifacts
(the request body after tokenization).
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers
from helpers import IsolatedBoundaryHome, assert_value_absent, daemon_stub, person_entity

from erebus import proxy

NAME = "Jan Modaal"  # synthetic fixture, never a real name


def _cfg(h: IsolatedBoundaryHome):
    cfg = h.repo_config(mode="strict")
    proxy.get_boundary(cfg)  # (re)build the proxy boundary for this isolated home
    return cfg


def test_anthropic_system_string_is_tokenized():
    with IsolatedBoundaryHome() as h, daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        cfg = _cfg(h)
        body = {"system": f"You assist {NAME} with billing.",
                "messages": [{"role": "user", "content": "hi"}]}
        new_tokens, _turn, _subj = proxy.tokenize_chat_request(body, cfg)
        assert_value_absent(body["system"], NAME)
        assert NAME in new_tokens.values(), f"system name not tokenized: {new_tokens}"
    print("  ✓ Anthropic top-level system string is tokenized")


def test_anthropic_system_block_list_is_tokenized():
    with IsolatedBoundaryHome() as h, daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        cfg = _cfg(h)
        body = {"system": [{"type": "text", "text": f"Operator: {NAME}."}],
                "messages": [{"role": "user", "content": "hi"}]}
        proxy.tokenize_chat_request(body, cfg)
        assert_value_absent(body["system"][0]["text"], NAME)
    print("  ✓ Anthropic system block-list is tokenized")


def test_tools_description_is_tokenized():
    with IsolatedBoundaryHome() as h, daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        cfg = _cfg(h)
        body = {
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {
                "name": "lookup",  # name must NOT be tokenized (routing)
                "description": f"Look up the account owned by {NAME}.",
                "parameters": {"type": "object"}}}],
        }
        proxy.tokenize_chat_request(body, cfg)
        fn = body["tools"][0]["function"]
        assert_value_absent(fn["description"], NAME)
        assert fn["name"] == "lookup", "tool name must be left intact for routing"
    print("  ✓ tools[].description is tokenized; tool name preserved")


def test_assistant_tool_call_arguments_are_tokenized():
    with IsolatedBoundaryHome() as h, daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        cfg = _cfg(h)
        body = {"messages": [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "call_1", "type": "function",
                 "function": {"name": "email", "arguments": f"to {NAME} now"}}]},
            {"role": "user", "content": "ok"},
        ]}
        proxy.tokenize_chat_request(body, cfg)
        args = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
        assert_value_absent(args, NAME)
    print("  ✓ assistant tool_calls[].arguments are tokenized")


if __name__ == "__main__":
    helpers.run([
        test_anthropic_system_string_is_tokenized,
        test_anthropic_system_block_list_is_tokenized,
        test_tools_description_is_tokenized,
        test_assistant_tool_call_arguments_are_tokenized,
    ], "Chat non-message field tokenization (audit 2026-06-11)")
