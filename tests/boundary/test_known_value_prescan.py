"""Boundary tests for the unconditional known-value pre-scan (FR-011, SC-008).

The pre-scan retokenizes any value the Known-Value DB already holds BEFORE the
detector runs. It is a deterministic, detector-independent pass: a value learned
in one message is replaced by its existing token in every later message, even
when the detector is down and even when the same value arrives over a different
channel (file-read text vs. chat text).

All assertions run against real-world artifacts:
  * the ABSENCE of the real value in the model-bound string (assert_value_absent)
  * the presence of the EXISTING token (the one minted on first sight)
  * sqlite row counts read straight from the known_values table

Fixture values are synthetic ('Jan Modaal', a reserved .test email), never PII.
"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers
from helpers import (
    IsolatedBoundaryHome,
    assert_value_absent,
    daemon_stub,
    fake_clock,
    person_entity,
)

NAME = "Jan Modaal"            # synthetic fixture, never a real name
EMAIL = "kees@example.test"    # synthetic fixture, reserved test domain


def _make_boundary(h: IsolatedBoundaryHome):
    from erebus.core import Boundary
    cfg = h.repo_config(mode="strict")  # strict: names always tokenize
    return Boundary.from_config(cfg, str(h.project), source="test")


# -- raw sqlite readers (assert on rows, not on the boundary's own view) ------


def _count_rows_for_value(db_path, value: str) -> int:
    con = sqlite3.connect(db_path)
    try:
        (count,) = con.execute(
            "SELECT COUNT(*) FROM known_values WHERE value = ?", (value,)).fetchone()
        return count
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


def test_prescan_retokenizes_known_value_with_detector_down():
    """Detector OFF, value already in the store. Seed the name with the daemon
    up so a token is minted and persisted; then, with the daemon DOWN, a NEW
    message containing the same name still has it replaced by the SAME existing
    token. The pre-scan is the only thing that can do this with the detector
    down, so it proves the pass is deterministic and detector-independent."""
    with IsolatedBoundaryHome() as h, fake_clock():
        boundary = _make_boundary(h)

        # Seed: with the daemon UP, first sight mints + persists a token.
        with daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
            seed_text = f"Hoi, ik ben {NAME} en ik bel je morgen."
            _, new_tokens = boundary.to_model(seed_text)
        by_value = {value: token for token, value in new_tokens.items()}
        assert NAME in by_value, f"name not minted on first sight: {new_tokens}"
        name_token = by_value[NAME]

        # real-world artifact: exactly one persisted row for the seeded value.
        assert _count_rows_for_value(h.global_db_path(), NAME) == 1

        # Detector DOWN on a brand-new text carrying the same value.
        with daemon_stub("down"):
            new_text = f"Stuur het rapport naar {NAME} voor vrijdag, alstublieft."
            out, minted = boundary.to_model(new_text)

        # The value is gone from model-bound text and the EXISTING token is back.
        assert_value_absent(out, NAME)
        assert name_token in out, (
            f"pre-scan did not reuse existing token {name_token!r} with the "
            f"detector down; output was {out!r}")
        assert NAME not in minted.values(), (
            f"pre-scan minted a fresh token for a known value: {minted}")

        # No duplicate row: the value still maps to exactly one token.
        assert _count_rows_for_value(h.global_db_path(), NAME) == 1
        assert _tokens_for_value(h.global_db_path(), NAME) == [name_token]


def test_prescan_shares_one_token_across_channels():
    """Same value seen via a file-read-style text and a chat-style text gets the
    same token: the second channel does not mint a duplicate. Proven on rows:
    the store has exactly one known_values row for the value."""
    with IsolatedBoundaryHome() as h, fake_clock(), \
         daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        boundary = _make_boundary(h)

        # Channel A: a file-read-style block (e.g. a tool result reading a doc).
        file_text = f"# contacts.md\n\nOwner: {NAME}\nNotes: primary reviewer\n"
        _, file_tokens = boundary.to_model(file_text)
        file_token = {v: t for t, v in file_tokens.items()}[NAME]

        assert _count_rows_for_value(h.global_db_path(), NAME) == 1

        # Channel B: a chat-style message naming the same person.
        chat_text = f"Kun je {NAME} vragen het document te bekijken?"
        chat_out, chat_tokens = boundary.to_model(chat_text)

        assert_value_absent(chat_out, NAME)
        assert file_token in chat_out, (
            f"second channel did not reuse the first channel's token "
            f"{file_token!r}; output was {chat_out!r}")
        assert NAME not in chat_tokens.values(), (
            f"second channel minted a duplicate token for a known value: "
            f"{chat_tokens}")

        # real-world artifact: exactly one row for the value across both channels.
        assert _count_rows_for_value(h.global_db_path(), NAME) == 1
        assert _tokens_for_value(h.global_db_path(), NAME) == [file_token]


def test_prescan_retokenizes_known_email_via_regex_path():
    """Email tokenized by the regex pass (GLiNER disabled) is retokenized to its
    existing token on a later message. The regex pass mints on first sight; the
    pre-scan reuses that token afterwards. No GLiNER involved either time."""
    prev = os.environ.get("EREBUS_DISABLE_GLINER")
    os.environ["EREBUS_DISABLE_GLINER"] = "1"
    try:
        with IsolatedBoundaryHome() as h, fake_clock():
            boundary = _make_boundary(h)

            # First message: the regex pass catches and mints the email.
            first = f"Mail me op {EMAIL} voor de details."
            first_out, first_tokens = boundary.to_model(first)
            assert_value_absent(first_out, EMAIL)
            by_value = {v: t for t, v in first_tokens.items()}
            assert EMAIL in by_value, (
                f"email not minted by the regex pass: {first_tokens}")
            email_token = by_value[EMAIL]

            assert _count_rows_for_value(h.global_db_path(), EMAIL) == 1

            # Later message with the same email: pre-scan reuses the token.
            second = f"Ter herinnering: bevestiging gaat naar {EMAIL}."
            second_out, second_tokens = boundary.to_model(second)

            assert_value_absent(second_out, EMAIL)
            assert email_token in second_out, (
                f"pre-scan did not reuse existing email token {email_token!r}; "
                f"output was {second_out!r}")
            assert EMAIL not in second_tokens.values(), (
                f"a duplicate token was minted for a known email: {second_tokens}")

            # real-world artifact: still exactly one row for the email.
            assert _count_rows_for_value(h.global_db_path(), EMAIL) == 1
            assert _tokens_for_value(h.global_db_path(), EMAIL) == [email_token]
    finally:
        if prev is None:
            os.environ.pop("EREBUS_DISABLE_GLINER", None)
        else:
            os.environ["EREBUS_DISABLE_GLINER"] = prev


def test_prescan_ignores_degenerate_stored_value():
    """A degenerate (1-char) stored value must never drive replacements.

    Regression for 2026-06-10: a legacy token_map import seeded a single-letter
    PERSON value; the pre-scan then rewrote that letter everywhere it appeared
    in prose, mangling model-bound text. The row is seeded with raw sqlite
    (the ingest guard now refuses it, so this simulates pre-guard pollution)."""
    with IsolatedBoundaryHome() as h, fake_clock():
        boundary = _make_boundary(h)
        with daemon_stub("down"):
            boundary.to_model("warm up the store")  # creates the schema

        con = sqlite3.connect(h.global_db_path())
        try:
            con.execute(
                "INSERT INTO known_values (token, value, label, created_at, last_seen_at, source)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("[PERSON_1_" "def001]", "e", "PERSON", "2026-01-01", "2026-01-01", "test"))
            con.execute("UPDATE meta SET generation = generation + 1")
            con.commit()
        finally:
            con.close()

        with daemon_stub("down"):
            text = "deze zin heeft veel letters e erin"
            out, minted = boundary.to_model(text)

        assert out == text, (
            f"degenerate stored value rewrote prose: {out!r}")
        assert minted == {}
    print("  ✓ degenerate stored value never drives pre-scan replacements")


def test_ingest_keeps_degenerate_value_transient_only():
    """db.ingest must keep degenerate values out of the durable store while the
    in-flight mapping stays resolvable (the token may already be in model-bound
    text)."""
    with IsolatedBoundaryHome() as h, fake_clock():
        db = h.open_db()
        db.ingest("[PERSON_1_" "def002]", "Q", source="test")
        assert _count_rows_for_value(h.global_db_path(), "Q") == 0, (
            "degenerate value was persisted into the Known-Value DB")
        assert db.lookup_value("[PERSON_1_" "def002]") == "Q", (
            "in-flight degenerate mapping must stay resolvable (transient)")
    print("  ✓ degenerate values stay transient-only but resolvable")


def test_prescan_short_value_replaces_word_bounded():
    """Short stored values (balanced-mode surnames) stay protected by the
    pre-scan, but only at word boundaries: a stored 2-char surname must
    tokenize standalone mentions without mangling words containing it."""
    with IsolatedBoundaryHome() as h, fake_clock():
        boundary = _make_boundary(h)
        with daemon_stub("down"):
            boundary.to_model("warm up the store")  # creates the schema

        con = sqlite3.connect(h.global_db_path())
        try:
            con.execute(
                "INSERT INTO known_values (token, value, label, created_at, last_seen_at, source)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                ("[PERSON_1_" "def003]", "Li", "PERSON", "2026-01-01", "2026-01-01", "test"))
            con.execute("UPDATE meta SET generation = generation + 1")
            con.commit()
        finally:
            con.close()

        with daemon_stub("down"):
            out, _ = boundary.to_model("ask Li about the Lithium supplies")

        assert "[PERSON_1_" "def003]" in out, f"standalone short surname not retokenized: {out!r}"
        assert "Lithium" in out, f"short value mangled a containing word: {out!r}"
        assert " Li " not in f" {out} ", f"standalone short surname leaked raw: {out!r}"
    print("  ✓ short stored values replace word-bounded (protected, no mangling)")


def test_escape_marker_overrides_prescan():
    """A trailing ``~`` escape must beat the pre-scan for KNOWN values.

    Regression for 2026-06-11: escapes were parsed only inside tokenize(),
    which runs AFTER the pre-scan — so once a value was in the store it was
    impossible to escape. The escape must shield the value for this call and
    grant the FR-013 time-boxed allowance."""
    with IsolatedBoundaryHome() as h, fake_clock():
        boundary = _make_boundary(h)
        with daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
            boundary.to_model(f"eerste keer: {NAME} hoort getokeniseerd")
        assert _count_rows_for_value(h.global_db_path(), NAME) == 1

        with daemon_stub("down"):
            out, minted = boundary.to_model(f"{NAME}~ moet zichtbaar blijven")

        assert NAME in out, f"escaped known value was retokenized anyway: {out!r}"
        assert "~" not in out, f"escape marker leaked into model-bound text: {out!r}"
        assert minted == {}
        db = h.open_db()
        allowed = {value.lower() for value in db.active_allowances()}
        assert NAME.lower() in allowed, f"escape did not grant an allowance: {allowed}"
    print("  ✓ trailing ~ escape beats the pre-scan and grants an allowance")


def test_allowed_names_override_prescan():
    """Values in repo_config.allowed_names must never be retokenized by the
    pre-scan, even when already stored (e.g. balanced-mode first names the
    user wants to keep visible)."""
    with IsolatedBoundaryHome() as h, fake_clock():
        seeder = _make_boundary(h)
        with daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
            seeder.to_model(f"registratie: {NAME} in de store")
        assert _count_rows_for_value(h.global_db_path(), NAME) == 1

        from erebus.core import Boundary
        cfg = h.repo_config(mode="strict", allowed_names=[NAME])
        allowing = Boundary.from_config(cfg, str(h.project), source="test")
        with daemon_stub("down"):
            out, _ = allowing.to_model(f"graag {NAME} zichtbaar laten")

        assert NAME in out, f"allowed_names value was retokenized by the pre-scan: {out!r}"
    print("  ✓ allowed_names values stay visible through the pre-scan")


if __name__ == "__main__":
    helpers.run([
        test_prescan_retokenizes_known_value_with_detector_down,
        test_prescan_shares_one_token_across_channels,
        test_prescan_retokenizes_known_email_via_regex_path,
        test_prescan_ignores_degenerate_stored_value,
        test_ingest_keeps_degenerate_value_transient_only,
        test_prescan_short_value_replaces_word_bounded,
        test_escape_marker_overrides_prescan,
        test_allowed_names_override_prescan,
    ], "Known-value pre-scan (FR-011, SC-008)")
