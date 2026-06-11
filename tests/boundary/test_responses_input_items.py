"""Boundary tests (FR-010, SC-007): proxy Responses 'input' items, to-model.

The OpenAI Responses request carries an `input` list whose items each frame a
model-bound string differently. The proxy walk (erebus/proxy/responses.py)
collects every tokenizable string across the whole list and runs them through
Boundary.to_model_many, so PII riding ANY item type must reach the model only
as a token. The grid cell already exercised elsewhere is a single
`function_call_output` string through to_model; the genuine gap here is the
multi-item input walk carrying two distinct item shapes at once:

  * function_call_output item: {type: 'function_call_output', output: '...'}
    (a tool result returning to the model)
  * input_text item:           {type: 'input_text', text: '...'}
    (typed user content inside a structured input message)

Each inner string carries the SAME synthetic person name and email. After the
walk, neither real value may survive in any model-bound item, and a token must
stand in its place. Names come from the stubbed NER daemon; the email is caught
by the regex pass under EREBUS_DISABLE_GLINER.

All fixture values are synthetic; assertions run on the model-bound items only
for ABSENCE of real values plus token-shape presence.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers

NAME = "Jan Modaal"
EMAIL = "fake@example.test"
TOOL_OUTPUT = f"result for {NAME} <{EMAIL}>"
TYPED_TEXT = f"please email {NAME} at {EMAIL}"


def _make_boundary(env):
    from erebus.core import Boundary

    cfg = env.repo_config(mode="strict")
    return Boundary.from_config(cfg, str(env.project), source="test")


def _assert_item_clean(item: dict, key: str):
    """A walked input item: real values gone, the framed string is a token."""
    helpers.assert_value_absent(item, NAME)
    helpers.assert_value_absent(item, EMAIL)
    framed = item[key]
    tokens = helpers.TOKEN_RE.findall(framed)
    assert len(set(tokens)) >= 2, (
        f"expected distinct tokens for name+email in {key!r}, got {tokens!r}"
    )


def test_input_items_tokenize_both_item_shapes():
    """function_call_output and input_text items in one input list both have
    their real values tokenized through to_model_many."""
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock(), \
            helpers.daemon_stub("up", entities_for=lambda t: helpers.person_entity(t, NAME)):
        boundary = _make_boundary(env)

        # The proxy collects the framed strings (output / text) across the whole
        # input list and batches them through to_model_many. Mirror that here.
        items = [
            {"type": "function_call_output", "call_id": "c1", "output": TOOL_OUTPUT},
            {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": TYPED_TEXT}]},
        ]
        framed = [items[0]["output"], items[1]["content"][0]["text"]]

        results = boundary.to_model_many(framed)
        assert len(results) == 2, f"to_model_many dropped items: {results!r}"

        items[0]["output"] = results[0][0]
        items[1]["content"][0]["text"] = results[1][0]

        _assert_item_clean(items[0], "output")
        _assert_item_clean(items[1]["content"][0], "text")

        # The whole input list the proxy would forward must be value-free.
        helpers.assert_value_absent(items, NAME)
        helpers.assert_value_absent(items, EMAIL)

        # Both values were actually minted across the two item shapes.
        minted = set()
        for _text, new_tokens in results:
            minted.update(new_tokens.values())
        assert NAME in minted, "person name never minted across input items"
        assert EMAIL in minted, "email never minted across input items"


def test_value_from_earlier_item_turn_reuses_one_token():
    """A value learned from an earlier input item (the previous request's walk)
    is re-tokenized to the SAME token when it reappears in a later input batch,
    so resent conversation history shows the model one consistent value. This is
    the cross-turn stability the Known-Value DB guarantees (design §7)."""
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock(), \
            helpers.daemon_stub("up", entities_for=lambda t: helpers.person_entity(t, NAME)):
        boundary = _make_boundary(env)

        # Turn 1: the email crosses once and is committed to the DB.
        first = boundary.to_model_many([f"tool output to {EMAIL}"])
        first_tok = helpers.TOKEN_RE.search(first[0][0])
        assert first_tok, f"email not tokenized on first item turn: {first[0][0]!r}"

        # Turn 2: a fresh input batch (distinct strings, no result-cache hit)
        # carries the same email in two more items; both reuse the stable token.
        second = boundary.to_model_many([
            f"user note about {EMAIL}",
            f"reminder for {EMAIL}",
        ])
        for text, _new in second:
            helpers.assert_value_absent(text, EMAIL)
            tok = helpers.TOKEN_RE.search(text)
            assert tok, f"email not tokenized in later item: {text!r}"
            assert tok.group(0) == first_tok.group(0), (
                f"known email minted a fresh token across turns: "
                f"{tok.group(0)!r} vs {first_tok.group(0)!r}"
            )


if __name__ == "__main__":
    from helpers import run

    run([
        test_input_items_tokenize_both_item_shapes,
        test_value_from_earlier_item_turn_reuses_one_token,
    ], "Responses input-items to_model walk (FR-010, SC-007)")
