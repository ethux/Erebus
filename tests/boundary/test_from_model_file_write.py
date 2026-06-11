"""Boundary tests for FR-017: file-write channel of the outbound boundary.

Model output headed for a file write must have every token replaced with
its real value before the bytes hit disk. We seed real tokens through
boundary.to_model() (daemon up, strict mode), build Write-tool-style
content out of the minted token strings, run it through
boundary.from_model(), and then assert ONLY on the real-world artifact:
the file bytes on disk contain the real values and zero token-shaped
strings. All fixture values are synthetic Dutch-sounding fakes.
"""
import os
import sys
from pathlib import Path

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

    # Model-bound output may never carry the real values (absence check is
    # the one allowed model-side assertion).
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


def test_file_write_resolves_all_tokens_to_real_values():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock(), \
            helpers.daemon_stub("up", entities_for=lambda t: helpers.person_entity(t, NAME)):
        boundary, tok_name, tok_email = _seed_boundary(env)

        # Write-tool-style content built from the REAL minted token strings.
        content = f"Note for {tok_name} at {tok_email}\n"

        resolved, _unres = boundary.from_model(content)
        assert _unres == [], f"unexpected unresolved tokens: {_unres!r}"

        # The side effect: bytes on disk (temp project dir).
        path = env.project / "note.txt"
        path.write_text(resolved, encoding="utf-8")

        # Real-world artifact assertions only.
        helpers.assert_no_tokens_in_file(path)
        raw = Path(path).read_text(encoding="utf-8")
        assert NAME in raw, "real name missing from written file bytes"
        assert EMAIL in raw, "real email missing from written file bytes"


if __name__ == "__main__":
    from helpers import run
    run([
        test_file_write_resolves_all_tokens_to_real_values,
    ], "from_model file-write channel (FR-017)")
