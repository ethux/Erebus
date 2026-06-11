"""Boundary tests for US1 / FR-011: tool-result channel, to-model direction.

Tool output flows back to the model inside agent-specific envelopes. Two
shapes are exercised here, each carrying the same synthetic person name and
email in its inner string:

  * Claude-style user message: {type: 'user', message: {content: [
        {type: 'tool_result', content: '...'}]}}
  * Codex-style item:          {type: 'function_call_output', output: '...'}

The adapter extracts the inner string and passes it through
Boundary.to_model with the detector daemon 'up'. The model-bound string
(and the re-assembled envelope around it) must contain neither real value,
and token-shaped replacements must be present.

All fixture values are synthetic; assertions are limited to absence of real
values in model-bound output plus token-shape checks on minted tokens.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import copy

from helpers import (
    TOKEN_RE,
    IsolatedBoundaryHome,
    assert_value_absent,
    daemon_stub,
    fake_clock,
    person_entity,
)

NAME = "Jan Modaal"
EMAIL = "fake@example.test"
TOOL_OUTPUT = f"output: {NAME} <{EMAIL}>"


def _make_boundary(env):
    from erebus.core import Boundary
    cfg = env.repo_config(mode="strict")
    return Boundary.from_config(cfg, str(env.project), source="test")


def _assert_model_bound_clean(tokenized: str, new_tokens: dict):
    assert_value_absent(tokenized, NAME)
    assert_value_absent(tokenized, EMAIL)
    tokens_in_text = TOKEN_RE.findall(tokenized)
    assert len(set(tokens_in_text)) >= 2, (
        f"expected distinct tokens for name and email, got {tokens_in_text!r}"
    )
    for token in new_tokens:
        assert TOKEN_RE.fullmatch(token), f"bad token shape minted: {token!r}"
        assert token in tokenized, (
            f"minted token {token!r} missing from model-bound text"
        )
    minted_values = set(new_tokens.values())
    assert NAME in minted_values, "no token minted for the person name"
    assert EMAIL in minted_values, "no token minted for the email address"


def test_claude_tool_result_inner_string_tokenized():
    with IsolatedBoundaryHome() as env, fake_clock(), \
            daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        boundary = _make_boundary(env)

        message = {
            "type": "user",
            "message": {
                "content": [
                    {"type": "tool_result", "content": TOOL_OUTPUT},
                ],
            },
        }

        inner = message["message"]["content"][0]["content"]
        tokenized, new_tokens = boundary.to_model(inner)
        _assert_model_bound_clean(tokenized, new_tokens)

        # The envelope the adapter would forward to the model must be clean
        # once the tokenized string is substituted back in.
        model_bound = copy.deepcopy(message)
        model_bound["message"]["content"][0]["content"] = tokenized
        assert_value_absent(model_bound, NAME)
        assert_value_absent(model_bound, EMAIL)


def test_codex_function_call_output_tokenized():
    with IsolatedBoundaryHome() as env, fake_clock(), \
            daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        boundary = _make_boundary(env)

        item = {"type": "function_call_output", "output": TOOL_OUTPUT}

        tokenized, new_tokens = boundary.to_model(item["output"])
        _assert_model_bound_clean(tokenized, new_tokens)

        model_bound = dict(item, output=tokenized)
        assert_value_absent(model_bound, NAME)
        assert_value_absent(model_bound, EMAIL)


if __name__ == "__main__":
    from helpers import run
    run([
        test_claude_tool_result_inner_string_tokenized,
        test_codex_function_call_output_tokenized,
    ], "Boundary.to_model tool-result channel (US1 / FR-011)")
