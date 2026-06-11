"""Boundary tests (FR-010, SC-007): NON-streaming tool-call args, from-model.

When a chat completion comes back WITHOUT streaming (erebus/proxy/regular.py),
the whole response body is JSON-decoded and run through the Boundary
(_detokenize_payload -> from_model_payload) before being returned to the
client. A model that issues a tool call frames its arguments as a JSON-encoded
STRING inside choices[].message.tool_calls[].function.arguments. Every token in
that argument string must resolve to its real value before the client executes
the tool.

The streaming counterpart of this cell is already covered by
test_streaming_holdback.py (StreamDetokenizer). The genuine gap is the
non-streaming path: a complete OpenAI chat-completion envelope whose tool-call
arguments carry tokens, resolved in one shot via from_model_payload. This test
also pins that the regular-path content field (an assistant reply with a token)
resolves in the same walk.

Tokens are minted through to_model first (daemon up for the name, regex for the
email), then embedded into the response envelope. Assertions run on the
real-world side: the executed argument string and the resolved envelope must
carry the real values and no surviving token shape.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers

NAME = "Jan Modaal"
EMAIL = "fake@example.test"
SEED_TEXT = f"{NAME} {EMAIL}"


def _seed_tokens(env):
    """Build a Boundary and mint tokens for NAME and EMAIL via to_model()."""
    from erebus.core import Boundary

    cfg = env.repo_config(mode="strict")
    boundary = Boundary.from_config(cfg, str(env.project), source="test")

    tokenized, new_tokens = boundary.to_model(SEED_TEXT)
    helpers.assert_value_absent(tokenized, NAME)
    helpers.assert_value_absent(tokenized, EMAIL)

    by_value = {value: token for token, value in new_tokens.items()}
    tok_name, tok_email = by_value.get(NAME), by_value.get(EMAIL)
    assert tok_name and tok_email, (
        f"seed did not mint both tokens; minted: {sorted(new_tokens.values())!r}"
    )
    return boundary, tok_name, tok_email


def test_nonstreaming_toolcall_arguments_resolve_to_real_values():
    """A non-streaming chat completion whose tool_call arguments carry tokens
    resolves them to real values in one from_model_payload walk."""
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock(), \
            helpers.daemon_stub("up", entities_for=lambda t: helpers.person_entity(t, NAME)):
        boundary, tok_name, tok_email = _seed_tokens(env)

        # OpenAI chat-completion non-streaming envelope: tool-call arguments are
        # a JSON-ENCODED STRING (the wire shape regular.py decodes and walks).
        arguments = json.dumps({
            "to": tok_email,
            "body": f"Hallo {tok_name}, bevestiging volgt.",
        })
        response = {
            "id": "chatcmpl-x",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": f"Ik mail {tok_name} nu.",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "send_email", "arguments": arguments},
                    }],
                },
                "finish_reason": "tool_calls",
            }],
        }

        resolved, unresolved = boundary.from_model_payload(response)
        assert unresolved == [], f"unexpected unresolved tokens: {unresolved!r}"

        # The executed tool argument string is the real-world side: it must
        # carry the real values once re-decoded.
        arg_str = resolved["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
        arg_obj = json.loads(arg_str)
        assert arg_obj["to"] == EMAIL, "real email missing from executed tool argument"
        assert NAME in arg_obj["body"], "real name missing from executed tool argument"

        # The assistant reply text in the same envelope resolves too.
        reply = resolved["choices"][0]["message"]["content"]
        assert NAME in reply, "real name missing from resolved assistant reply"

        # No token shape may survive anywhere in the returned envelope.
        survivors = helpers.TOKEN_RE.findall(json.dumps(resolved))
        assert not survivors, f"token(s) survived in non-streaming response: {survivors}"


def test_nonstreaming_clean_response_passes_through():
    """A non-streaming response with no tokens is returned unchanged and reports
    no unresolved tokens (the cheap passthrough path)."""
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock(), \
            helpers.daemon_stub("up", entities_for=lambda t: helpers.person_entity(t, NAME)):
        boundary, _tok_name, _tok_email = _seed_tokens(env)

        response = {
            "choices": [{
                "message": {"role": "assistant", "content": "Niets te doen hier."},
                "finish_reason": "stop",
            }],
        }
        resolved, unresolved = boundary.from_model_payload(response)
        assert unresolved == [], f"clean response reported unresolved: {unresolved!r}"
        assert resolved == response, "clean response was altered by the walk"


if __name__ == "__main__":
    from helpers import run

    run([
        test_nonstreaming_toolcall_arguments_resolve_to_real_values,
        test_nonstreaming_clean_response_passes_through,
    ], "Non-streaming tool-call args from_model_payload (FR-010, SC-007)")
