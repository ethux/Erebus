"""Boundary test: MCP erebus_reveal returns MASKED previews only (FR-019, edge case h).

The MCP server is a model-invocable interface: its tool output enters the model's
context. This test drives _handle_request for tools/call erebus_reveal (all tokens
+ a specific token) and erebus_status, then asserts on the returned strings (the
real-world artifact the model would see):

  * no real value ever appears,
  * masked previews + entity KINDs + the CLI pointer line do appear.

Tokens are seeded through the Known-Value DB (the preferred source), so the test
exercises the DB path end to end.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import IsolatedBoundaryHome, fake_clock

PERSON_VALUE = "Jan Modaal"
EMAIL_VALUE = "fake@example.test"


def _seed_db(h):
    """Mint two values via the Known-Value DB; return (person_token, email_token)."""
    db = h.open_db(scope="global")
    try:
        person_tok = db.mint(PERSON_VALUE, "PERSON")
        email_tok = db.mint(EMAIL_VALUE, "EMAIL_ADDRESS")
    finally:
        db.close()
    return person_tok, email_tok


def _call(server, tool, arguments=None):
    """Drive _handle_request for one tools/call and return the text content."""
    msg = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": arguments or {}},
    }
    resp = server._handle_request(msg)
    return resp["result"]["content"][0]["text"]


def _import_server():
    from erebus.runtime import mcp_server
    return mcp_server


def _assert_no_real_values(text):
    assert PERSON_VALUE not in text, f"person value leaked into model context: {text!r}"
    assert EMAIL_VALUE not in text, f"email value leaked into model context: {text!r}"


def test_mask_value_format():
    """Deterministic preview: first char + asterisks + length hint; '*' for <=1 char."""
    server = _import_server()
    assert server.mask_value("Jan Modaal") == "J********* (10)"
    assert server.mask_value("fake@example.test") == "f**************** (17)"
    assert server.mask_value("A") == "* (1)"
    assert server.mask_value("") == "* (0)"
    # never contains the tail of the input
    assert "Modaal" not in server.mask_value("Jan Modaal")


def test_reveal_all_tokens_masked():
    """erebus_reveal (no args): masked previews + kinds + pointer, no real values."""
    with IsolatedBoundaryHome() as h, fake_clock():
        person_tok, email_tok = _seed_db(h)
        server = _import_server()
        text = _call(server, "erebus_reveal")

        _assert_no_real_values(text)
        assert "J********* (10)" in text, text
        assert "f**************** (17)" in text, text
        assert "(PERSON)" in text and "(EMAIL_ADDRESS)" in text, text
        assert person_tok in text and email_tok in text, text
        assert "erebus-reveal CLI" in text, "missing CLI pointer line"


def test_reveal_specific_token_masked():
    """A specific-token request still returns a masked preview, never the value."""
    with IsolatedBoundaryHome() as h, fake_clock():
        person_tok, _email_tok = _seed_db(h)
        server = _import_server()
        text = _call(server, "erebus_reveal", {"token": person_tok})

        _assert_no_real_values(text)
        assert person_tok in text, text
        assert "J********* (10)" in text, text
        assert "(PERSON)" in text, text
        assert "erebus-reveal CLI" in text, "missing CLI pointer line"


def test_status_counts_only():
    """erebus_status emits counts only: the active count, no real or masked PII value."""
    with IsolatedBoundaryHome() as h, fake_clock():
        _seed_db(h)
        server = _import_server()
        text = _call(server, "erebus_status")

        _assert_no_real_values(text)
        assert "Active tokens: 2" in text, text
        # status is counts only: never even a masked entity preview (no asterisks).
        assert "*" not in text, f"status leaked a preview: {text!r}"


if __name__ == "__main__":
    from helpers import run

    run([
        test_mask_value_format,
        test_reveal_all_tokens_masked,
        test_reveal_specific_token_masked,
        test_status_counts_only,
    ], "MCP erebus_reveal masking (FR-019)")
