"""
Tests for the GDPR hygiene layer:

  * 0600/0700 permissions on the log DB, token map, blacklist files, and
    the ~/.erebus/ directory.
  * Log retention via `erebus-log --prune --days N` and targeted erasure
    via `erebus-forget <term>` (Articles 5(1)(e) and 17).
  * Token map age-rotation in config.load_token_map / save_token_map.
"""
import json
import os
import stat
import sqlite3
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus import config, logger


# ── Fixtures ─────────────────────────────────────────────────────────────────

def _iso_temp_home():
    """Return a fresh temp dir that will stand in for ~/.erebus/."""
    return Path(tempfile.mkdtemp(prefix="erebus-gdpr-test-"))


def _with_isolated_paths(fn):
    """Decorator: run fn with DB_PATH + TOKEN_MAP_PATH redirected to a tmp dir."""
    def wrapper():
        home = _iso_temp_home()
        erebus_dir = home / ".erebus"
        orig_db = config.DB_PATH
        orig_tmap = config.TOKEN_MAP_PATH
        config.DB_PATH = erebus_dir / "log.db"
        config.TOKEN_MAP_PATH = erebus_dir / "token_map.json"
        logger.DB_PATH = config.DB_PATH
        with patch.object(Path, "home", return_value=home):
            try:
                fn(home)
            finally:
                config.DB_PATH = orig_db
                config.TOKEN_MAP_PATH = orig_tmap
                logger.DB_PATH = orig_db
    wrapper.__name__ = fn.__name__
    return wrapper


# ── Permissions ──────────────────────────────────────────────────────────────

@_with_isolated_paths
def test_init_db_chmods_to_0600(home: Path):
    logger.init_db()
    m = stat.S_IMODE(os.stat(config.DB_PATH).st_mode)
    assert m == 0o600, f"expected 0600, got {oct(m)}"
    print("  ✓ log DB is chmod'd to 0600 after init")


@_with_isolated_paths
def test_save_token_map_chmods_to_0600(home: Path):
    config.save_token_map({"[TOK_1_abc]": "Alice"})
    m = stat.S_IMODE(os.stat(config.TOKEN_MAP_PATH).st_mode)
    assert m == 0o600, f"expected 0600, got {oct(m)}"
    print("  ✓ token_map.json is chmod'd to 0600 after write")


@_with_isolated_paths
def test_ensure_erebus_dir_chmods_to_0700(home: Path):
    d = config.ensure_erebus_dir()
    m = stat.S_IMODE(os.stat(d).st_mode)
    assert m == 0o700, f"expected 0700, got {oct(m)}"
    print("  ✓ ~/.erebus/ is chmod'd to 0700")


# ── Log retention (Article 5(1)(e)) ──────────────────────────────────────────

@_with_isolated_paths
def test_prune_log_deletes_old_rows(home: Path):
    logger.init_db()
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        "INSERT INTO events (session_id, event_type, timestamp) VALUES (?,?,datetime('now','-30 days'))",
        ("s1", "prompt"),
    )
    conn.execute(
        "INSERT INTO events (session_id, event_type, timestamp) VALUES (?,?,datetime('now','-1 days'))",
        ("s2", "prompt"),
    )
    conn.commit()
    conn.close()

    removed = logger.prune_log(7)
    assert removed == 1, f"expected 1 removed, got {removed}"
    conn = sqlite3.connect(config.DB_PATH)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    conn.close()
    print("  ✓ prune_log deletes rows older than N days")


@_with_isolated_paths
def test_prune_log_zero_days_wipes_all(home: Path):
    logger.init_db()
    # Insert with explicit past timestamps — prune_log uses strict '<' against
    # datetime('now'), and SQLite timestamps are second-precision so rows
    # inserted in the same second as the delete query wouldn't match.
    conn = sqlite3.connect(config.DB_PATH)
    conn.execute(
        "INSERT INTO events (session_id, event_type, timestamp) VALUES (?,?,datetime('now','-1 seconds'))",
        ("s", "prompt"),
    )
    conn.execute(
        "INSERT INTO events (session_id, event_type, timestamp) VALUES (?,?,datetime('now','-1 seconds'))",
        ("s", "prompt"),
    )
    conn.commit()
    conn.close()
    removed = logger.prune_log(0)
    assert removed == 2, f"expected 2, got {removed}"
    print("  ✓ prune_log(0) wipes everything")


@_with_isolated_paths
def test_prune_log_no_db_is_noop(home: Path):
    removed = logger.prune_log(7)
    assert removed == 0
    print("  ✓ prune_log with no DB is a no-op")


# ── Targeted erasure (Article 17) ────────────────────────────────────────────

@_with_isolated_paths
def test_forget_term_removes_matching_rows(home: Path):
    logger.init_db()
    logger.log_event("s", "prompt", raw="Email jan@example.com about deal",
                     sanitized="Email [EMAIL_1_abc] about deal")
    logger.log_event("s", "prompt", raw="Call Bob tomorrow",
                     sanitized="Call Bob tomorrow")
    logger.log_event("s", "prompt", raw="Jan's birthday party",
                     sanitized="[PERSON_1_x]'s birthday party")

    removed = logger.forget_term("jan")
    assert removed == 2, f"expected 2 (the two 'jan'/'Jan' rows), got {removed}"
    conn = sqlite3.connect(config.DB_PATH)
    remaining = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    assert remaining == 1
    print("  ✓ forget_term erases every row mentioning the value (case-insensitive)")


@_with_isolated_paths
def test_forget_term_also_searches_tokens_map_and_metadata(home: Path):
    logger.init_db()
    logger.log_event("s", "prompt", sanitized="redacted",
                     tokens_map={"[EMAIL_1_abc]": "carol@example.com"},
                     metadata={"source": "tool_result"})
    logger.log_event("s", "prompt", sanitized="unrelated")
    removed = logger.forget_term("carol@example.com")
    assert removed == 1
    print("  ✓ forget_term searches tokens_map + metadata too")


@_with_isolated_paths
def test_forget_term_empty_string_is_noop(home: Path):
    logger.init_db()
    logger.log_event("s", "prompt", sanitized="anything")
    assert logger.forget_term("") == 0
    assert logger.forget_term("   ") == 0
    conn = sqlite3.connect(config.DB_PATH)
    assert conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] == 1
    conn.close()
    print("  ✓ forget_term with empty input is a no-op (no accidental mass wipe)")


# ── Token map age rotation ───────────────────────────────────────────────────

@_with_isolated_paths
def test_save_then_load_roundtrip(home: Path):
    config.save_token_map({"[TOK_1_abc]": "Alice", "[TOK_2_def]": "Bob"})
    loaded = config.load_token_map()
    assert loaded == {"[TOK_1_abc]": "Alice", "[TOK_2_def]": "Bob"}
    print("  ✓ save -> load roundtrip preserves entries")


@_with_isolated_paths
def test_expired_map_wiped_on_load(home: Path):
    config.save_token_map({"[TOK_1_abc]": "Alice"})
    # Hand-edit the stored created_at to be 30 days old.
    data = json.loads(config.TOKEN_MAP_PATH.read_text())
    data["created_at"] = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    config.TOKEN_MAP_PATH.write_text(json.dumps(data))

    loaded = config.load_token_map(max_age_days=7)
    assert loaded == {}, f"expected expired map to load empty, got {loaded}"
    assert not config.TOKEN_MAP_PATH.exists(), "expired file should be wiped"
    print("  ✓ load_token_map wipes expired file")


@_with_isolated_paths
def test_fresh_write_does_not_renew_old_window(home: Path):
    """A write to an already-young file keeps the original created_at, so the
    max-age guarantee is honest and can't be extended by constant writes."""
    config.save_token_map({"[A]": "alice"})
    first = json.loads(config.TOKEN_MAP_PATH.read_text())["created_at"]
    config.save_token_map({"[A]": "alice", "[B]": "bob"})
    second = json.loads(config.TOKEN_MAP_PATH.read_text())["created_at"]
    assert first == second, "created_at must not reset on young writes"
    print("  ✓ writes don't renew created_at — age window stays honest")


@_with_isolated_paths
def test_legacy_v1_flat_map_tolerated(home: Path):
    """Old installs have a flat {token: value} file. load_token_map must read it."""
    config.TOKEN_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.TOKEN_MAP_PATH.write_text(json.dumps({"[LEGACY_1_a]": "Alice"}))
    loaded = config.load_token_map()
    assert loaded == {"[LEGACY_1_a]": "Alice"}
    # A subsequent save upgrades to v2
    config.save_token_map(loaded)
    data = json.loads(config.TOKEN_MAP_PATH.read_text())
    assert data.get("version") == 2
    assert data["entries"] == {"[LEGACY_1_a]": "Alice"}
    print("  ✓ legacy flat-dict token_map is read + upgraded to v2")


# ── Runner ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    tests = [
        test_init_db_chmods_to_0600,
        test_save_token_map_chmods_to_0600,
        test_ensure_erebus_dir_chmods_to_0700,
        test_prune_log_deletes_old_rows,
        test_prune_log_zero_days_wipes_all,
        test_prune_log_no_db_is_noop,
        test_forget_term_removes_matching_rows,
        test_forget_term_also_searches_tokens_map_and_metadata,
        test_forget_term_empty_string_is_noop,
        test_save_then_load_roundtrip,
        test_expired_map_wiped_on_load,
        test_fresh_write_does_not_renew_old_window,
        test_legacy_v1_flat_map_tolerated,
    ]
    print("\n=== GDPR Hygiene Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
