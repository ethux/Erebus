"""Boundary tests (FR-010, SC-007): web/search content intake, to-model.

The channel grid (design §5) lists "web / search content in" as a to_model
crossing. In practice web/search results do not have their own wire envelope:
they arrive as the OUTPUT of a web-search / fetch tool, i.e. a tool_result
subtype carrying a free-text blob. This test documents that web content rides
the tool_result channel and is tokenized by the same to_model pipeline.

A search-result blob embeds a synthetic person name and email (the kind of
contact detail a search snippet would surface). After to_model the model-bound
blob (and the tool_result envelope it sits in) must contain neither real value,
with a token standing in for each. The name comes from the stubbed NER daemon;
the email is caught by the regex pass under EREBUS_DISABLE_GLINER.

All fixture values are synthetic; assertions run on the model-bound side only
for ABSENCE of real values plus token-shape presence.
"""
import copy
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers

NAME = "Jan Modaal"
EMAIL = "fake@example.test"
SEARCH_BLOB = (
    "Top result: Acme contact page lists "
    f"{NAME} as the press lead, reachable at {EMAIL}. "
    "Snippet 2: no contact details found."
)


def _make_boundary(env):
    from erebus.core import Boundary

    cfg = env.repo_config(mode="strict")
    return Boundary.from_config(cfg, str(env.project), source="test")


def _assert_blob_clean(tokenized: str):
    helpers.assert_value_absent(tokenized, NAME)
    helpers.assert_value_absent(tokenized, EMAIL)
    tokens = helpers.TOKEN_RE.findall(tokenized)
    assert len(set(tokens)) >= 2, (
        f"expected distinct tokens for name+email in web blob, got {tokens!r}"
    )


def test_web_search_result_blob_tokenized():
    """A web-search tool-result blob is tokenized through to_model; neither the
    name nor the email reaches the model, and the tool_result envelope the
    adapter forwards is value-free once the blob is substituted back in."""
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock(), \
            helpers.daemon_stub("up", entities_for=lambda t: helpers.person_entity(t, NAME)):
        boundary = _make_boundary(env)

        # Web content rides the tool_result channel: the search tool returns its
        # findings as a tool_result content blob.
        envelope = {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": "web_search_1",
                "content": SEARCH_BLOB,
            }]},
        }

        blob = envelope["message"]["content"][0]["content"]
        tokenized, new_tokens = boundary.to_model(blob)
        _assert_blob_clean(tokenized)

        assert NAME in set(new_tokens.values()), "name from web content never minted"
        assert EMAIL in set(new_tokens.values()), "email from web content never minted"

        model_bound = copy.deepcopy(envelope)
        model_bound["message"]["content"][0]["content"] = tokenized
        helpers.assert_value_absent(model_bound, NAME)
        helpers.assert_value_absent(model_bound, EMAIL)


def test_web_content_structured_block_subtype_tokenized():
    """Some web/search tools return tool_result content as a list of structured
    text blocks; the blob inside each block is tokenized just the same."""
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock(), \
            helpers.daemon_stub("up", entities_for=lambda t: helpers.person_entity(t, NAME)):
        boundary = _make_boundary(env)

        block = {"type": "text", "text": SEARCH_BLOB}
        tokenized, _new = boundary.to_model(block["text"])
        block["text"] = tokenized

        _assert_blob_clean(block["text"])
        helpers.assert_value_absent(block, NAME)
        helpers.assert_value_absent(block, EMAIL)


if __name__ == "__main__":
    from helpers import run

    run([
        test_web_search_result_blob_tokenized,
        test_web_content_structured_block_subtype_tokenized,
    ], "Web/search content intake via tool_result (FR-010, SC-007)")
