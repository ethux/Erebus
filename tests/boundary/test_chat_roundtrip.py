"""Boundary tests: chat message round-trip through the Boundary facade (spec US1).

Covers acceptance scenario 3 of User Story 1: a payload crossing toward the
model has detected PII replaced by tokens (to_model), and a payload crossing
away from it has tokens replaced by real values (from_model). Also pins the
no-duplicate-mint guarantee: tokenizing the same input twice reuses the
existing tokens instead of minting fresh ones.

All assertions run against real-world artifacts (sqlite rows, returned
real-world strings) or against the ABSENCE of real values in model-bound
output. Fixture values are synthetic Dutch-sounding fakes, never real PII.
"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import (
    TOKEN_RE,
    IsolatedBoundaryHome,
    assert_value_absent,
    daemon_stub,
    fake_clock,
    person_entity,
)

NAME = "Jan Modaal"            # synthetic fixture, never a real name
EMAIL = "fake@example.test"    # synthetic fixture, reserved test domain
MESSAGE = f"Hoi, ik ben {NAME} en je bereikt me via {EMAIL}."


def _make_boundary(h: IsolatedBoundaryHome):
    from erebus.core import Boundary
    cfg = h.repo_config(mode="strict")  # strict: names always tokenize
    return Boundary.from_config(cfg, str(h.project), source="test")


# -- raw sqlite readers (assert on rows, not on the boundary's own view) ------

def _known_value_rows(db_path) -> dict[str, str]:
    con = sqlite3.connect(db_path)
    try:
        return dict(con.execute("SELECT token, value FROM known_values").fetchall())
    finally:
        con.close()


def _tokens_for_value(db_path, value: str) -> list[str]:
    con = sqlite3.connect(db_path)
    try:
        return [t for (t,) in con.execute(
            "SELECT token FROM known_values WHERE value = ?", (value,))]
    finally:
        con.close()


# -- tests ---------------------------------------------------------------------


def test_chat_message_is_tokenized_to_model():
    """to_model strips both the detected name and the email from the
    model-bound text; minted tokens are well-formed and persisted to sqlite
    before the call returns."""
    with IsolatedBoundaryHome() as h, fake_clock(), \
         daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        boundary = _make_boundary(h)

        tokenized, new_tokens = boundary.to_model(MESSAGE)

        assert_value_absent(tokenized, NAME)
        assert_value_absent(tokenized, EMAIL)

        assert {NAME, EMAIL} <= set(new_tokens.values()), (
            f"expected fresh tokens for both values, got {new_tokens}")
        for token in new_tokens:
            assert TOKEN_RE.fullmatch(token), f"malformed token minted: {token!r}"
            assert token in tokenized, f"minted token {token!r} absent from output"

        # contract: new_tokens are persisted to the DB before to_model returns
        rows = _known_value_rows(h.global_db_path())
        for token, value in new_tokens.items():
            assert rows.get(token) == value, (
                f"minted pair ({token!r}, {value!r}) missing from sqlite: {rows}")


def test_reply_tokens_restore_real_values():
    """from_model on a model reply embedding live tokens restores the exact
    real values; nothing is left unresolved and no token survives in the
    real-world-bound text."""
    with IsolatedBoundaryHome() as h, fake_clock(), \
         daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        boundary = _make_boundary(h)

        _, new_tokens = boundary.to_model(MESSAGE)
        by_value = {value: token for token, value in new_tokens.items()}
        name_token = by_value[NAME]
        email_token = by_value[EMAIL]

        reply = f"Beste {name_token}, ik heb een bevestiging naar {email_token} gestuurd."
        detokenized, unresolved = boundary.from_model(reply)

        assert detokenized == (
            f"Beste {NAME}, ik heb een bevestiging naar {EMAIL} gestuurd.")
        assert unresolved == [], f"tokens left unresolved: {unresolved}"
        assert not TOKEN_RE.search(detokenized), (
            "token survived into real-world-bound text")


def test_repeat_to_model_reuses_existing_tokens():
    """Tokenizing the same input twice returns the SAME tokens: the second
    call's text equals the first call's, no fresh mints are reported, and the
    DB holds exactly one row per value."""
    with IsolatedBoundaryHome() as h, fake_clock(), \
         daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        boundary = _make_boundary(h)

        first_text, first_new = boundary.to_model(MESSAGE)
        assert {NAME, EMAIL} <= set(first_new.values())

        second_text, second_new = boundary.to_model(MESSAGE)

        assert second_text == first_text, (
            "second tokenization of identical input produced different text "
            "(duplicate tokens minted?)")
        assert second_new == {}, (
            f"second call minted fresh tokens for known values: {second_new}")

        # real-world artifact: exactly one sqlite row per value, no duplicates
        for value in (NAME, EMAIL):
            tokens = _tokens_for_value(h.global_db_path(), value)
            assert len(tokens) == 1, (
                f"expected one DB row for {value!r}, found tokens {tokens}")


if __name__ == "__main__":
    from helpers import run
    run([
        test_chat_message_is_tokenized_to_model,
        test_reply_tokens_restore_real_values,
        test_repeat_to_model_reuses_existing_tokens,
    ], "Chat message round-trip (US1)")
