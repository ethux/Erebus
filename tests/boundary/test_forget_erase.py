"""Gateway test: erebus-forget erases a value from the Known-Value DB,
its escape allowances, the legacy token-map export, AND the audit log.

Release condition (spec FR-016): right-to-be-forgotten covers every store
that holds the value. Assertions run on real-world artifacts only: sqlite
rows and exported file bytes.
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import IsolatedBoundaryHome, fake_clock


def _forget(term: str) -> int:
    """Invoke main_forget the way the CLI does, non-interactively."""
    import unittest.mock as mock

    from erebus.audit import logger
    with mock.patch.object(sys, "argv", ["erebus-forget", term, "--yes"]):
        return logger.main_forget()


def test_forget_erases_db_export_and_audit_log():
    with IsolatedBoundaryHome() as h, fake_clock():
        from erebus.audit import logger
        logger.init_db()
        db = h.open_db()
        token = db.mint("Jan Modaal", "PERSON", source="test")
        db.grant_allowance("Jan Modaal", 5)
        keep_token = db.mint("fake@example.test", "EMAIL_ADDRESS", source="test")
        logger.log_event("s", "pii_detected", raw="met Jan Modaal",
                         tokens_map={token: "Jan Modaal"})
        db.close()

        rc = _forget("Jan Modaal")
        assert rc == 0, "erebus-forget reported failure"

        # DB rows gone (value, token, allowance) — unrelated entry survives.
        conn = sqlite3.connect(h.global_db_path())
        rows = conn.execute("SELECT value FROM known_values").fetchall()
        allowances = conn.execute("SELECT value FROM escape_allowances").fetchall()
        conn.close()
        values = {r[0] for r in rows}
        assert "Jan Modaal" not in values, "value survived in known_values"
        assert "fake@example.test" in values, "unrelated entry was erased"
        assert ("Jan Modaal",) not in allowances, "allowance survived erasure"

        # Legacy export re-written without the erased pair.
        legacy = json.loads(h.legacy_map_path().read_text())
        entries = legacy.get("entries", legacy)
        assert token not in entries, "token survived in legacy export"
        assert "Jan Modaal" not in entries.values(), "value survived in legacy export"
        assert keep_token in entries, "unrelated token lost from legacy export"

        # Audit log no longer mentions the value.
        from erebus import config
        conn = sqlite3.connect(config.DB_PATH)
        hits = conn.execute(
            "SELECT COUNT(*) FROM events WHERE IFNULL(raw,'') LIKE ? "
            "OR IFNULL(tokens_map,'') LIKE ?",
            ("%Jan Modaal%", "%Jan Modaal%")).fetchone()[0]
        conn.close()
        assert hits == 0, "audit log still mentions the erased value"


def test_forget_unknown_value_is_clean_noop():
    with IsolatedBoundaryHome() as h, fake_clock():
        db = h.open_db()
        db.mint("fake@example.test", "EMAIL_ADDRESS", source="test")
        db.close()
        rc = _forget("Nooit Bestaan")
        assert rc == 0, "no-match forget must still exit 0"
        conn = sqlite3.connect(h.global_db_path())
        count = conn.execute("SELECT COUNT(*) FROM known_values").fetchone()[0]
        conn.close()
        assert count == 1, "no-op forget must not delete anything"


if __name__ == "__main__":
    from helpers import run
    run([
        test_forget_erases_db_export_and_audit_log,
        test_forget_unknown_value_is_clean_noop,
    ], "Forget / Erasure Gateway Tests")
