"""Boundary tests for FR-017: tool-call channel of the outbound boundary.

A model-issued tool call (here a Write-tool payload with nested JSON
arguments) must have every token inside its arguments replaced with the
real value before the tool executes. We seed real tokens through
boundary.to_model() (daemon up, strict mode), embed them in a nested
payload, run it through boundary.from_model_payload(), and assert that
the executed-argument strings carry the real values while no token
shape survives anywhere in the payload. All fixture values are
synthetic Dutch-sounding fakes.
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


def _seed_boundary(env):
    """Build a Boundary and mint tokens for NAME and EMAIL via to_model().

    Returns (boundary, tok_name, tok_email) with the REAL minted token
    strings (bracket-delimited, TOKEN_RE-shaped).
    """
    from erebus.core import Boundary

    cfg = env.repo_config(mode="strict")
    boundary = Boundary.from_config(cfg, str(env.project), source="test")

    tokenized, new_tokens = boundary.to_model(SEED_TEXT)
    helpers.assert_value_absent(tokenized, NAME)
    helpers.assert_value_absent(tokenized, EMAIL)

    by_value = {value: token for token, value in new_tokens.items()}
    tok_name = by_value.get(NAME)
    tok_email = by_value.get(EMAIL)
    assert tok_name is not None and tok_email is not None, (
        f"seed did not mint tokens for both values; minted: "
        f"{sorted(new_tokens.values())!r}"
    )
    assert helpers.TOKEN_RE.fullmatch(tok_name), f"bad token shape: {tok_name!r}"
    assert helpers.TOKEN_RE.fullmatch(tok_email), f"bad token shape: {tok_email!r}"
    return boundary, tok_name, tok_email


def test_tool_call_payload_resolves_nested_args_to_real_values():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock(), \
            helpers.daemon_stub("up", entities_for=lambda t: helpers.person_entity(t, NAME)):
        boundary, tok_name, tok_email = _seed_boundary(env)

        payload = {
            "name": "Write",
            "input": {
                "file_path": "/tmp/x",
                "content": f"mail {tok_email} about {tok_name}",
            },
        }

        resolved, _unres = boundary.from_model_payload(payload)
        assert _unres == [], f"unexpected unresolved tokens: {_unres!r}"

        # The executed-argument strings are the real-world side of a tool
        # call: they must carry the real values.
        assert isinstance(resolved, dict), f"payload shape changed: {type(resolved).__name__}"
        content_arg = resolved["input"]["content"]
        assert NAME in content_arg, "real name missing from executed tool argument"
        assert EMAIL in content_arg, "real email missing from executed tool argument"
        assert resolved["input"]["file_path"] == "/tmp/x", "token-free arg was altered"
        assert resolved["name"] == "Write", "tool name was altered"

        # No token shape may survive anywhere in the executed payload.
        survivors = helpers.TOKEN_RE.findall(json.dumps(resolved))
        assert not survivors, f"token(s) survived in executed tool payload: {survivors}"


if __name__ == "__main__":
    from helpers import run
    run([
        test_tool_call_payload_resolves_nested_args_to_real_values,
    ], "from_model_payload tool-call channel (FR-017)")
