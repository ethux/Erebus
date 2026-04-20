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


USAGE_FIELDS = (
    "input_tokens",
    "output_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


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
                "response": "<", "file_blocked": "XX",
                "token_usage": "$$"}.get(etype, "--")
        print(f"{icon}  [{ts}] [{sid}] {etype.upper()}")
        if tokens:
            print(f"   Tokens replaced: {', '.join(tokens.keys())}")
        if meta.get("mode"):
            print(f"   mode: {meta['mode']}")
        if meta.get("cwd"):
            print(f"   cwd: {meta['cwd']}")
        if etype == "token_usage":
            parts = [f"{f.replace('_tokens','').replace('_input','')}={meta.get(f, 0):,}"
                     for f in USAGE_FIELDS if meta.get(f)]
            if parts:
                print(f"   tokens: {'  '.join(parts)}")
            if meta.get("model"):
                print(f"   model: {meta['model']}")
        if sanitized:
            preview = sanitized[:120].replace("\n", " ")
            print(f"   Preview: {preview}{'...' if len(sanitized) > 120 else ''}")
        print()


def usage_summary(days: int = None, session: str = None):
    """Aggregate token_usage events and print a summary."""
    if not DB_PATH.exists():
        print("No log file yet — wrapper hasn't run.")
        return

    conn = sqlite3.connect(DB_PATH)
    clauses = ["event_type = 'token_usage'"]
    params: list = []
    if days is not None:
        clauses.append("timestamp >= datetime('now', ?)")
        params.append(f"-{days} days")
    if session:
        clauses.append("session_id = ?")
        params.append(session)

    where = " AND ".join(clauses)
    rows = conn.execute(
        f"SELECT session_id, timestamp, metadata FROM events WHERE {where}",
        params,
    ).fetchall()

    # Also include legacy response events that have usage buried in their text,
    # so historical data isn't invisible.
    legacy_rows = []
    if not session:
        legacy_rows = conn.execute(
            "SELECT session_id, timestamp, sanitized FROM events WHERE event_type='response'"
            + (" AND timestamp >= datetime('now', ?)" if days is not None else ""),
            ([f"-{days} days"] if days is not None else []),
        ).fetchall()
    conn.close()

    totals = {f: 0 for f in USAGE_FIELDS}
    by_session: dict[str, dict[str, int]] = {}
    turn_count = 0

    def _add(sid: str, counts: dict):
        nonlocal turn_count
        turn_count += 1
        for k in USAGE_FIELDS:
            v = int(counts.get(k, 0) or 0)
            totals[k] += v
            by_session.setdefault(sid, {f: 0 for f in USAGE_FIELDS})[k] += v

    for sid, _ts, md in rows:
        try:
            meta = json.loads(md) if md else {}
        except Exception:
            continue
        _add(sid, meta)

    # Legacy fallback: for each session, take the MAX cumulative usage per
    # field across all response events in that session. This approximates
    # that session's total token cost without double-counting the cumulative
    # streaming deltas. It's still a lower bound — any session that never
    # logged a response event (272 of 314 in the original DB) is invisible.
    legacy_turns = 0
    legacy_session_max: dict[str, dict[str, int]] = {}
    for sid, _ts, txt in legacy_rows:
        if not txt:
            continue
        try:
            m = json.loads(txt)
            usage = m.get("message", {}).get("usage")
        except Exception:
            continue
        if not isinstance(usage, dict):
            continue
        legacy_turns += 1
        bucket = legacy_session_max.setdefault(sid, {f: 0 for f in USAGE_FIELDS})
        for f in USAGE_FIELDS:
            v = int(usage.get(f, 0) or 0)
            if v > bucket[f]:
                bucket[f] = v
    for sid, counts in legacy_session_max.items():
        for f in USAGE_FIELDS:
            totals[f] += counts[f]
            by_session.setdefault(sid, {g: 0 for g in USAGE_FIELDS})[f] += counts[f]

    label = []
    if days is not None:
        label.append(f"last {days}d")
    if session:
        label.append(f"session {session}")
    scope = f" ({', '.join(label)})" if label else ""

    print(f"\n{'─'*70}")
    print(f"  erebus — token usage{scope}")
    print(f"{'─'*70}\n")
    legacy_sessions = len(legacy_session_max)
    print(f"  turns logged:         {turn_count:,}")
    if legacy_sessions:
        print(f"  legacy sessions:      {legacy_sessions:,}  "
              f"(approx: per-session max across {legacy_turns:,} pre-upgrade response events)")
    print()
    for f in USAGE_FIELDS:
        print(f"  {f:<32} {totals[f]:>15,}")
    grand = sum(totals.values())
    billable_input = totals["input_tokens"] + totals["cache_creation_input_tokens"] + totals["cache_read_input_tokens"]
    hit_ratio = totals["cache_read_input_tokens"] / max(1, billable_input)
    print(f"  {'─'*48}")
    print(f"  TOTAL                            {grand:>15,}")
    print(f"  cache hit ratio                  {hit_ratio:>15.1%}")

    if by_session and not session:
        print("\n  Top 5 sessions by total tokens:")
        ranked = sorted(by_session.items(),
                        key=lambda x: sum(x[1].values()), reverse=True)[:5]
        for sid, c in ranked:
            total = sum(c.values())
            print(f"    {sid}  total={total:>12,}  cache_read={c['cache_read_input_tokens']:>12,}")
    print()


def main_log():
    import argparse
    parser = argparse.ArgumentParser(description="View erebus log")
    parser.add_argument("-n", type=int, default=20, help="Number of recent events to show")
    parser.add_argument("--usage", action="store_true",
                        help="Show token usage summary instead of event tail")
    parser.add_argument("--days", type=int, default=None,
                        help="With --usage: only consider the last N days")
    parser.add_argument("--session", default=None,
                        help="With --usage: filter to a single session id")
    args = parser.parse_args()
    if args.usage:
        usage_summary(days=args.days, session=args.session)
    else:
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
