"""Boundary tests: legacy token_map.json -> KnownValueDB migration (spec FR-010c).

Covers: one-time seeding from an unexpired legacy map, the seeded_from_legacy
guard against re-import, write-through export back to the legacy JSON, and
refusal to import an expired legacy map.

All assertions run against real-world artifacts: sqlite rows and file bytes.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import sys
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import TOKEN_RE, IsolatedBoundaryHome, fake_clock

SEED_TOKEN = "[PERSON_1_" "aaaa01]"  # synthetic fixture token, never a live value
SEED_VALUE = "Seed Person"

EMAIL_TOKEN_RE = re.compile(r"\[EMAIL_ADDRESS_\d+_[0-9a-f]{6,}\]")


# -- raw sqlite readers (assert on rows, not on the handle's own view) --------

def _known_value_rows(db_path) -> dict[str, str]:
    con = sqlite3.connect(db_path)
    try:
        return dict(con.execute("SELECT token, value FROM known_values").fetchall())
    finally:
        con.close()


def _seeded_flag(db_path) -> int:
    con = sqlite3.connect(db_path)
    try:
        return con.execute("SELECT seeded_from_legacy FROM meta").fetchone()[0]
    finally:
        con.close()


def _delete_token_row(db_path, token: str) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.execute("DELETE FROM known_values WHERE token = ?", (token,))
        con.commit()
    finally:
        con.close()


# -- tests ---------------------------------------------------------------------


def test_legacy_map_seeds_empty_db():
    """Empty DB + unexpired legacy map -> entries imported, seeded flag set."""
    with IsolatedBoundaryHome() as h, fake_clock():
        h.write_legacy_map({SEED_TOKEN: SEED_VALUE})

        db = h.open_db(scope="global")
        try:
            assert db.lookup_value(SEED_TOKEN) == SEED_VALUE
        finally:
            db.close()

        rows = _known_value_rows(h.global_db_path())
        assert rows.get(SEED_TOKEN) == SEED_VALUE, f"seed row missing from sqlite: {rows}"
        assert _seeded_flag(h.global_db_path()) == 1


def test_reopen_does_not_reseed():
    """seeded_from_legacy=1 guards against re-import: a row deleted straight
    from sqlite stays absent across reopen even though the legacy map still
    contains it."""
    with IsolatedBoundaryHome() as h, fake_clock():
        h.write_legacy_map({SEED_TOKEN: SEED_VALUE})

        db = h.open_db(scope="global")
        db.close()
        assert _seeded_flag(h.global_db_path()) == 1

        _delete_token_row(h.global_db_path(), SEED_TOKEN)
        assert SEED_TOKEN not in _known_value_rows(h.global_db_path())

        db = h.open_db(scope="global")
        try:
            assert db.lookup_value(SEED_TOKEN) is None, "reopen re-imported the legacy map"
        finally:
            db.close()

        rows = _known_value_rows(h.global_db_path())
        assert SEED_TOKEN not in rows, f"deleted row reappeared after reopen: {rows}"
        assert _seeded_flag(h.global_db_path()) == 1


def test_write_through_export_mirrors_db():
    """Every committed write exports the full map to the legacy JSON (v2)."""
    with IsolatedBoundaryHome() as h, fake_clock():
        db = h.open_db(scope="global")
        try:
            token = db.mint("fresh@example.test", "EMAIL_ADDRESS")
        finally:
            db.close()

        assert TOKEN_RE.fullmatch(token), f"minted token has wrong shape: {token!r}"
        assert EMAIL_TOKEN_RE.fullmatch(token), f"label not encoded in token: {token!r}"

        rows = _known_value_rows(h.global_db_path())
        assert rows.get(token) == "fresh@example.test"

        legacy = h.legacy_map_path()
        assert legacy.exists(), "write-through export did not create the legacy map"
        payload = json.loads(legacy.read_text(encoding="utf-8"))
        assert payload.get("version") == 2
        assert "created_at" in payload
        entries = payload.get("entries")
        assert isinstance(entries, dict)
        assert entries == rows, f"legacy export {entries} != sqlite rows {rows}"


def test_expired_legacy_map_is_not_imported():
    """A legacy map older than the retention window is dropped, not seeded.

    config.load_token_map compares created_at against the real wall clock, so
    the stale timestamp is built from datetime.now(), not the fake clock.
    """
    with IsolatedBoundaryHome() as h, fake_clock():
        stale = datetime.now(UTC) - timedelta(days=30)
        h.write_legacy_map({SEED_TOKEN: SEED_VALUE}, created_at=stale)

        db = h.open_db(scope="global")
        try:
            assert db.lookup_value(SEED_TOKEN) is None
        finally:
            db.close()

        rows = _known_value_rows(h.global_db_path())
        assert rows == {}, f"expired legacy entries were imported: {rows}"

        # load_token_map's expiry handling normally unlinks the stale file; a
        # rewrite-through-export of the (empty) DB is acceptable too. Either
        # way the stale entry must not survive on disk as importable content.
        legacy = h.legacy_map_path()
        if legacy.exists():
            payload = json.loads(legacy.read_text(encoding="utf-8"))
            entries = payload.get("entries") if isinstance(payload, dict) else payload
            assert not entries or SEED_TOKEN not in entries, (
                f"stale legacy entry still importable from disk: {entries}")


if __name__ == "__main__":
    from helpers import run
    run([
        test_legacy_map_seeds_empty_db,
        test_reopen_does_not_reseed,
        test_write_through_export_mirrors_db,
        test_expired_legacy_map_is_not_imported,
    ], "KnownValueDB legacy migration (FR-010c)")
