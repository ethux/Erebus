import sqlite3
import json
from datetime import datetime
from pathlib import Path
from .config import DB_PATH


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            cwd TEXT,
            started_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            event_type TEXT,        -- 'prompt', 'response', 'file_read', 'file_blocked', 'pii_detected', 'secret_detected'
            raw TEXT,               -- original content (may contain PII - stored locally only)
            sanitized TEXT,         -- tokenized version sent to Claude
            tokens_map TEXT,        -- JSON mapping of token -> real value
            metadata TEXT           -- JSON extras (filename, model used, etc.)
        );
    """)
    conn.commit()
    conn.close()


def tail_log(n: int = 20):
    """Print last N events in human-readable format."""
    if not DB_PATH.exists():
        print("No log file yet — wrapper hasn't run.")
        return
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT timestamp, session_id, event_type, sanitized, tokens_map, metadata FROM events ORDER BY id DESC LIMIT ?",
        (n,)
    ).fetchall()
    conn.close()

    if not rows:
        print("Log is empty.")
        return

    print(f"\n{'─'*70}")
    print(f"  erebus — last {n} events")
    print(f"{'─'*70}\n")
    for ts, sid, etype, sanitized, tokens_map, metadata in reversed(rows):
        tokens = json.loads(tokens_map) if tokens_map else {}
        meta = json.loads(metadata) if metadata else {}
        icon = {"pii_detected": "!!", "session_start": "+>", "prompt": ">>",
                "response": "<", "file_blocked": "XX"}.get(etype, "--")
        print(f"{icon}  [{ts}] [{sid}] {etype.upper()}")
        if tokens:
            print(f"   Tokens replaced: {', '.join(tokens.keys())}")
        if meta.get("mode"):
            print(f"   mode: {meta['mode']}")
        if meta.get("cwd"):
            print(f"   cwd: {meta['cwd']}")
        if sanitized:
            preview = sanitized[:120].replace("\n", " ")
            print(f"   Preview: {preview}{'...' if len(sanitized) > 120 else ''}")
        print()


def main_log():
    import argparse
    parser = argparse.ArgumentParser(description="View erebus log")
    parser.add_argument("-n", type=int, default=20, help="Number of recent events to show")
    args = parser.parse_args()
    tail_log(args.n)


def log_event(session_id: str, event_type: str, raw: str = None,
              sanitized: str = None, tokens_map: dict = None, metadata: dict = None):
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO events (session_id, event_type, raw, sanitized, tokens_map, metadata) VALUES (?,?,?,?,?,?)",
        (
            session_id,
            event_type,
            raw,
            sanitized,
            json.dumps(tokens_map) if tokens_map else None,
            json.dumps(metadata) if metadata else None,
        )
    )
    conn.commit()
    conn.close()
