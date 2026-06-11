"""Boundary tests for US1 / FR-011: file-read channel, to-model direction.

A real file on disk contains a synthetic person name and a synthetic email.
The adapter's tool-result intake is simulated by a plain Path.read_text();
the raw content is then passed through Boundary.to_model with the detector
daemon 'up'. The model-bound result must contain neither real value and must
carry token-shaped replacements; the source file on disk must stay raw
(real values, zero tokens) because tokenization happens only at the boundary.

All fixture values are synthetic (Dutch-sounding fake name, .test domain).
Assertions run only on real-world artifacts (disk bytes) or on the absence
of real values in the model-bound output.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from pathlib import Path

from helpers import (
    TOKEN_RE,
    IsolatedBoundaryHome,
    assert_no_tokens_in_file,
    assert_value_absent,
    daemon_stub,
    fake_clock,
    person_entity,
)

NAME = "Jan Modaal"
EMAIL = "fake@example.test"
FILE_CONTENT = f"dossier of {NAME}\ncontact {EMAIL}"


def _make_boundary(env):
    from erebus.core import Boundary
    cfg = env.repo_config(mode="strict")
    return Boundary.from_config(cfg, str(env.project), source="test")


def _write_dossier(env) -> Path:
    path = env.project / "dossier.txt"
    path.write_text(FILE_CONTENT, encoding="utf-8")
    return path


def test_file_read_content_tokenized_for_model():
    with IsolatedBoundaryHome() as env, fake_clock(), \
            daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        path = _write_dossier(env)
        boundary = _make_boundary(env)

        # Simulate the adapter's tool-result intake: a plain read of the file.
        raw = path.read_text(encoding="utf-8")
        tokenized, new_tokens = boundary.to_model(raw)

        # Neither real value may reach the model-bound text.
        assert_value_absent(tokenized, NAME)
        assert_value_absent(tokenized, EMAIL)

        # Token shapes are present: one per protected value, well-formed.
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


def test_file_read_source_file_stays_raw_on_disk():
    with IsolatedBoundaryHome() as env, fake_clock(), \
            daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        path = _write_dossier(env)
        boundary = _make_boundary(env)

        boundary.to_model(path.read_text(encoding="utf-8"))

        # Real-world artifact: the file on disk is untouched by the boundary.
        on_disk = path.read_text(encoding="utf-8")
        assert on_disk == FILE_CONTENT, (
            "boundary.to_model mutated the source file on disk"
        )
        assert_no_tokens_in_file(path)


if __name__ == "__main__":
    from helpers import run
    run([
        test_file_read_content_tokenized_for_model,
        test_file_read_source_file_stays_raw_on_disk,
    ], "Boundary.to_model file-read channel (US1 / FR-011)")
