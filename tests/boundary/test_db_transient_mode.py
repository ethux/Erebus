"""Boundary tests for FR-010g / FR-012: degraded transient-token mode.

When the known-values DB path cannot be opened (here: the .db path is a
directory, so sqlite3 cannot open it), the handle must fall back to a
process-local transient store: mint() still issues tokens, lookups resolve
them, and the detector-degraded turn flag fires. On the next successful DB
operation the transient pairs are flushed durably into sqlite, and only
then may anything be exported to the legacy JSON map.

All assertions run against real-world artifacts (sqlite rows read with a
direct connection, file bytes on disk) inside an isolated temp HOME.
"""
import json
import os
import shutil
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers

EMAIL = "jan@example.test"
EMAIL_2 = "piet@example.test"


def _block_db_path(env):
    """Make the global DB path unopenable: a directory where the file goes."""
    blocker = env.global_db_path()
    blocker.mkdir(parents=True, exist_ok=True)
    return blocker


def test_transient_mint_and_lookup_when_db_unopenable():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        blocker = _block_db_path(env)

        db = env.open_db(scope="global")
        try:
            token = db.mint(EMAIL, "EMAIL_ADDRESS")
            assert isinstance(token, str), f"mint returned {type(token).__name__}"
            assert helpers.TOKEN_RE.fullmatch(token), f"bad token shape: {token!r}"
            assert db.lookup_value(token) == EMAIL, "transient store did not resolve token"
            # The path is still blocked: nothing durable can exist yet.
            assert blocker.is_dir(), "DB path blocker vanished mid-test"
        finally:
            db.close()


def test_degraded_turn_flag_fires_on_transient_mint():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        _block_db_path(env)

        import erebus.filter as flt
        flt.begin_detection_turn()

        db = env.open_db(scope="global")
        try:
            token = db.mint(EMAIL, "EMAIL_ADDRESS")
            assert helpers.TOKEN_RE.fullmatch(token)
            assert flt.turn_degraded(), (
                "turn_degraded() not set after mint with unopenable DB"
            )
            assert flt.detector_degraded(), (
                "detector_degraded() not set after mint with unopenable DB"
            )
        finally:
            db.close()


def test_recovery_flushes_first_token_durably_into_sqlite():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        blocker = _block_db_path(env)
        db_path = env.global_db_path()

        db = env.open_db(scope="global")
        try:
            first = db.mint(EMAIL, "EMAIL_ADDRESS")
            assert helpers.TOKEN_RE.fullmatch(first)

            # Unblock the path, then trigger any DB operation: the handle
            # must flush the transient pairs into sqlite.
            shutil.rmtree(blocker)
            second = db.mint(EMAIL_2, "EMAIL_ADDRESS")
            assert helpers.TOKEN_RE.fullmatch(second)
        finally:
            db.close()

        # The FIRST token's pair must now be durable on disk: read the file
        # directly with sqlite3, no KnownValueDB involved.
        assert db_path.is_file(), "no sqlite file written after recovery"
        conn = sqlite3.connect(str(db_path))
        try:
            rows = dict(
                conn.execute("SELECT token, value FROM known_values").fetchall()
            )
        finally:
            conn.close()
        assert rows.get(first) == EMAIL, (
            f"transient pair not flushed to sqlite: {first!r} -> {rows.get(first)!r}"
        )
        assert rows.get(second) == EMAIL_2, "post-recovery mint not in sqlite"

        # And a fresh handle resolves the first token from the durable store.
        fresh = env.open_db(scope="global")
        try:
            assert fresh.lookup_value(first) == EMAIL, (
                "fresh handle cannot resolve flushed token"
            )
        finally:
            fresh.close()


def test_no_legacy_export_while_transient_export_after_flush():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        blocker = _block_db_path(env)
        legacy = env.legacy_map_path()

        db = env.open_db(scope="global")
        try:
            first = db.mint(EMAIL, "EMAIL_ADDRESS")

            # While the store is transient nothing may reach legacy JSON.
            if legacy.exists():
                helpers.assert_no_tokens_in_file(legacy)
                raw = legacy.read_text(encoding="utf-8")
                assert EMAIL not in raw, "raw value exported to legacy JSON while transient"
            # (Strict expectation: no committed write happened, so no export.)
            assert not legacy.exists(), "legacy JSON written while store was transient"

            # Recover and trigger a committed write: export must follow the flush.
            shutil.rmtree(blocker)
            second = db.mint(EMAIL_2, "EMAIL_ADDRESS")
        finally:
            db.close()

        assert legacy.exists(), "legacy JSON not exported after committed write"
        data = json.loads(legacy.read_text(encoding="utf-8"))
        entries = data.get("entries", data) if isinstance(data, dict) else {}
        assert entries.get(first) == EMAIL, (
            "flushed transient pair missing from legacy export"
        )
        assert entries.get(second) == EMAIL_2, (
            "post-recovery pair missing from legacy export"
        )


if __name__ == "__main__":
    from helpers import run
    run([
        test_transient_mint_and_lookup_when_db_unopenable,
        test_degraded_turn_flag_fires_on_transient_mint,
        test_recovery_flushes_first_token_durably_into_sqlite,
        test_no_legacy_export_while_transient_export_after_flush,
    ], "KnownValueDB degraded transient-token mode (FR-010g / FR-012)")
