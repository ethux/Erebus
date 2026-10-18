"""A value erased from disk must stay erased while sessions keep running.

Regression 2026-10-16: a live shim re-ingested its whole in-memory mirror on
every persist, so a Known-Value row deleted mid-session came back, and the
legacy JSON export regained it too.
"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

import helpers
from helpers import IsolatedBoundaryHome, daemon_stub, fake_clock

# Split-literal tokens: immune to detokenize-on-write rewriting this source.
ERASED = "[PERSON_1_" "def005]"
FRESH = "[PERSON_1_" "def006]"
LEGACY = "[PERSON_1_" "def007]"


def _rows(db_path, token: str) -> int:
    con = sqlite3.connect(db_path)
    try:
        return con.execute("SELECT COUNT(*) FROM known_values WHERE token = ?", (token,)).fetchone()[0]
    finally:
        con.close()


def _write(db_path, sql: str, args: tuple) -> None:
    con = sqlite3.connect(db_path)
    try:
        con.execute(sql, args)
        con.execute("UPDATE meta SET generation = generation + 1")
        con.commit()
    finally:
        con.close()


def test_persist_mirror_does_not_resurrect_erased_values():
    from erebus import config
    from erebus.core import Boundary

    with IsolatedBoundaryHome() as h, fake_clock():
        boundary = Boundary.from_config(h.repo_config(mode="strict"), str(h.project), source="test")
        with daemon_stub("down"):
            boundary.to_model("warm up the store")  # creates the schema
        db = h.global_db_path()
        _write(db, "INSERT INTO known_values (token, value, label, created_at, last_seen_at, source)"
                   " VALUES (?, ?, ?, ?, ?, ?)", (ERASED, "Bell", "PERSON", "2026-01-01", "2026-01-01", "test"))

        mirror: dict = {}
        boundary.persist_mirror(mirror)  # the session syncs: it now holds the value in memory
        assert mirror.get(ERASED) == "Bell"

        # The user erases it from both stores while the session keeps running.
        _write(db, "DELETE FROM known_values WHERE token = ?", (ERASED,))
        legacy = {t: v for t, v in config.load_token_map().items() if t != ERASED}
        config.save_token_map({**legacy, LEGACY: "Kees"})  # a pair only the JSON holds

        mirror[FRESH] = "Pietje"  # never on disk: this session's own pair
        boundary.persist_mirror(mirror)

        assert _rows(db, ERASED) == 0, "erased value was re-ingested from a session's memory"
        assert ERASED not in config.load_token_map(), "erased value was re-exported to the legacy JSON"
        assert _rows(db, FRESH) == 1, "a session's own pair was not persisted"
        assert config.load_token_map().get(FRESH) == "Pietje"
        assert _rows(db, LEGACY) == 1, "a JSON-only pair must still reach the store"
        assert mirror.get(ERASED) == "Bell", "old context must still detokenize in-session"
    print("  ✓ erased values stay erased while a session runs")


if __name__ == "__main__":
    helpers.run([test_persist_mirror_does_not_resurrect_erased_values], "Erasure sticks (live sessions)")
