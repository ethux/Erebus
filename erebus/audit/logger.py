from __future__ import annotations

import json
import sqlite3

from ..config import DB_PATH, ensure_erebus_dir, secure_path


def init_db():
    ensure_erebus_dir()
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
    """)  # noqa: E501
    conn.commit()
    conn.close()
    secure_path(DB_PATH, 0o600)


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
        "SELECT timestamp, session_id, event_type, sanitized, tokens_map, metadata FROM events ORDER BY id DESC LIMIT ?",  # noqa: E501
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
                "token_usage": "$$", "tokenize_latency": "TT"}.get(etype, "--")
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
            if meta.get("turn_latency_ms"):
                src = meta.get("source", "?")
                editor = "Claude (shim)" if src == "shim" else "Codex (proxy)" if src == "proxy" else src
                tt = meta.get("turn_type", "")
                tt_label = f"  type: {tt}" if tt else ""
                out_tok = int(meta.get("output_tokens", 0) or 0)
                ms = meta["turn_latency_ms"]
                speed = f"  {out_tok / (ms / 1000):.0f} tok/s" if out_tok and ms else ""
                print(f"   turn: {ms}ms  via {editor}{tt_label}{speed}")
        if etype == "tokenize_latency":
            src = meta.get("source", "?")
            editor = "Claude (shim)" if src == "shim" else "Codex (proxy)" if src == "proxy" else src
            ms = meta.get("latency_ms", 0)
            pii = meta.get("pii_found", False)
            tc = meta.get("token_count", 0)
            print(f"   editor: {editor}  latency: {ms}ms  pii: {pii}  tokens: {tc}")
        if sanitized:
            preview = sanitized[:120].replace("\n", " ")
            print(f"   Preview: {preview}{'...' if len(sanitized) > 120 else ''}")
        print()


def usage_summary(days: int | None = None, session: str | None = None):  # noqa: C901
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


def prune_log(days: int) -> int:
    """Delete all events older than `days` days. Returns the row count removed.

    Supports GDPR Article 5(1)(e) — storage limitation. Raw prompts that may
    contain PII the filter missed should not accumulate indefinitely.
    """
    if days < 0:
        raise ValueError("days must be >= 0")
    if not DB_PATH.exists():
        return 0
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        "DELETE FROM events WHERE timestamp < datetime('now', ?)",
        (f"-{days} days",),
    )
    removed = cur.rowcount
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    return removed


def forget_term(term: str) -> int:
    """Delete every event mentioning `term` in any of its text columns.

    Case-insensitive substring match over raw, sanitized, tokens_map, and
    metadata. Supports GDPR Article 17 — right to erasure. Returns the
    number of rows removed.
    """
    term = term.strip()
    if not term:
        return 0
    if not DB_PATH.exists():
        return 0
    like = f"%{term}%"
    conn = sqlite3.connect(DB_PATH)
    cur = conn.execute(
        """
        DELETE FROM events
        WHERE IFNULL(raw, '')        LIKE ? COLLATE NOCASE
           OR IFNULL(sanitized, '')  LIKE ? COLLATE NOCASE
           OR IFNULL(tokens_map, '') LIKE ? COLLATE NOCASE
           OR IFNULL(metadata, '')   LIKE ? COLLATE NOCASE
        """,
        (like, like, like, like),
    )
    removed = cur.rowcount
    conn.commit()
    conn.execute("VACUUM")
    conn.close()
    return removed


def lookup_token_values(tokens: set[str]) -> dict[str, str]:
    """Look up exact token placeholders from logged token maps.

    This is a recovery path for long-running conversations: the live token map
    can be rotated or overwritten while Claude still has older placeholders in
    context. Only the structured tokens_map column is searched.
    """
    wanted = {token for token in tokens if token}
    if not wanted or not DB_PATH.exists():
        return {}

    found: dict[str, str] = {}
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        "SELECT tokens_map FROM events WHERE tokens_map IS NOT NULL ORDER BY id DESC"
    ).fetchall()
    conn.close()

    for (tokens_map,) in rows:
        try:
            mapping = json.loads(tokens_map) if tokens_map else {}
        except Exception:
            continue
        if not isinstance(mapping, dict):
            continue
        for token in list(wanted - found.keys()):
            value = mapping.get(token)
            if isinstance(value, str):
                found[token] = value
        if wanted <= found.keys():
            break
    return found


def _print_latency_table(label: str, by_source: dict[str, list[float]]):
    """Print a latency stats table grouped by source."""
    for src, values in sorted(by_source.items()):
        editor = "Claude (shim)" if src == "shim" else "Codex (proxy)" if src == "proxy" else src
        values.sort()
        n = len(values)
        avg = sum(values) / n
        p50 = values[n // 2]
        p95 = values[int(n * 0.95)]
        p99 = values[int(n * 0.99)]
        mn = values[0]
        mx = values[-1]
        print(f"  {editor}")
        print(f"    requests:  {n:>8,}")
        print(f"    avg:       {avg:>8.1f} ms")
        print(f"    p50:       {p50:>8.1f} ms")
        print(f"    p95:       {p95:>8.1f} ms")
        print(f"    p99:       {p99:>8.1f} ms")
        print(f"    min:       {mn:>8.1f} ms")
        print(f"    max:       {mx:>8.1f} ms")
        print()


def latency_summary(days: int | None = None):  # noqa: C901
    """Show per-editor tokenization and turn latency stats."""
    if not DB_PATH.exists():
        print("No log file yet.")
        return

    conn = sqlite3.connect(DB_PATH)
    time_clause = ""
    params: list = []
    if days is not None:
        time_clause = " AND timestamp >= datetime('now', ?)"
        params.append(f"-{days} days")

    tok_rows = conn.execute(
        f"SELECT metadata FROM events WHERE event_type = 'tokenize_latency'{time_clause}",
        params,
    ).fetchall()

    turn_rows = conn.execute(
        f"SELECT metadata FROM events WHERE event_type = 'token_usage'{time_clause}",
        params[:],
    ).fetchall()
    conn.close()

    tok_by_source: dict[str, list[float]] = {}
    for (md,) in tok_rows:
        try:
            meta = json.loads(md) if md else {}
        except Exception:
            continue
        src = meta.get("source", "unknown")
        ms = meta.get("latency_ms")
        if ms is not None:
            tok_by_source.setdefault(src, []).append(float(ms))

    # Parse turn latency, grouped by source and turn_type
    turn_by_source: dict[str, list[float]] = {}
    turn_by_type: dict[str, dict[str, list[float]]] = {}  # source -> type -> latencies
    speed_by_source: dict[str, list[float]] = {}  # source -> tokens/sec samples
    for (md,) in turn_rows:
        try:
            meta = json.loads(md) if md else {}
        except Exception:
            continue
        src = meta.get("source", "unknown")
        ms = meta.get("turn_latency_ms")
        tt = meta.get("turn_type", "unknown")
        if ms is not None:
            turn_by_source.setdefault(src, []).append(float(ms))
            turn_by_type.setdefault(src, {}).setdefault(tt, []).append(float(ms))
            out_tok = int(meta.get("output_tokens", 0) or 0)
            if out_tok > 0 and ms > 0:
                speed_by_source.setdefault(src, []).append(out_tok / (ms / 1000))

    if not tok_by_source and not turn_by_source:
        print("No latency events recorded yet.")
        return

    label = f" (last {days}d)" if days is not None else ""
    print(f"\n{'='*60}")
    print(f"  erebus -- latency{label}")
    print(f"{'='*60}")

    if tok_by_source:
        print("\n  --- Tokenization (Erebus overhead) ---\n")
        _print_latency_table("tokenize", tok_by_source)

    if turn_by_source:
        print("  --- Turn round-trip (includes upstream API) ---\n")
        _print_latency_table("turn", turn_by_source)

    # Break down by turn type per editor
    for src in sorted(turn_by_type):
        types = turn_by_type[src]
        if len(types) <= 1:
            continue
        editor = "Claude (shim)" if src == "shim" else "Codex (proxy)" if src == "proxy" else src
        print(f"  --- {editor} by turn type ---\n")
        labeled = {}
        for tt, vals in types.items():
            key = f"{tt} turns"
            labeled[key] = vals
        _print_latency_table("type", labeled)

    if speed_by_source:
        print("  --- Output speed (tokens/sec) ---\n")
        for src, values in sorted(speed_by_source.items()):
            editor = "Claude (shim)" if src == "shim" else "Codex (proxy)" if src == "proxy" else src
            values.sort()
            n = len(values)
            avg = sum(values) / n
            p50 = values[n // 2]
            print(f"  {editor}")
            print(f"    samples:   {n:>8,}")
            print(f"    avg:       {avg:>8.1f} tok/s")
            print(f"    p50:       {p50:>8.1f} tok/s")
            print(f"    min:       {values[0]:>8.1f} tok/s")
            print(f"    max:       {values[-1]:>8.1f} tok/s")
            print()


def main_log():
    import argparse

    from ..perf import perf_summary
    parser = argparse.ArgumentParser(description="View or manage the erebus log")
    parser.add_argument("-n", type=int, default=20, help="Number of recent events to show")
    parser.add_argument("--usage", action="store_true",
                        help="Show token usage summary instead of event tail")
    parser.add_argument("--latency", action="store_true",
                        help="Show per-editor tokenization latency stats")
    parser.add_argument("--perf", action="store_true",
                        help="Show Erebus CPU/cache telemetry")
    parser.add_argument("--days", type=int, default=None,
                        help="With --usage, --latency, or --prune: limit to the last N days")
    parser.add_argument("--session", default=None,
                        help="With --usage: filter to a single session id")
    parser.add_argument("--prune", action="store_true",
                        help="Delete events older than --days (GDPR storage limitation)")
    args = parser.parse_args()
    if args.prune:
        if args.days is None:
            parser.error("--prune requires --days")
        removed = prune_log(args.days)
        print(f"Removed {removed} events older than {args.days} day(s).")
        return
    if args.perf:
        perf_summary()
    elif args.latency:
        latency_summary(days=args.days)
    elif args.usage:
        usage_summary(days=args.days, session=args.session)
    else:
        tail_log(args.n)


def main_forget():
    """CLI entry point for erebus-forget — GDPR Article 17 erasure."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="erebus-forget",
        description="Delete every log entry mentioning a given value (GDPR right to erasure).",
    )
    parser.add_argument("term", help="value to erase from the log (e.g. a name or email)")
    parser.add_argument("--yes", action="store_true",
                        help="skip the confirmation prompt")
    args = parser.parse_args()

    if not args.yes:
        print(f"This will permanently delete every log entry mentioning: {args.term}")
        ans = input("Continue? [y/N] ").strip().lower()
        if ans not in ("y", "yes"):
            print("Aborted.")
            return 1
    removed = forget_term(args.term)
    print(f"Removed {removed} events mentioning {args.term!r}.")

    # Right-to-be-forgotten must also cover the Known-Value DB (the single
    # source of truth for value<->token pairs) and, via its write-through
    # export, the legacy token_map.json: erasure drops the value row, its
    # token, and any escape allowances in one transaction.
    import os
    import sys
    try:
        from ..config import load_repo_config
        from ..core import open_known_values
        db = open_known_values(load_repo_config(), os.getcwd())
        erased = db.erase(args.term)
        db.close()
        if erased:
            print(f"Removed {args.term!r} from the known-value store and token map.")
        else:
            print("No known-value entry matched.")
    except Exception as e:  # audit-log erasure above already succeeded
        print(f"warning: known-value store erasure failed: {e}", file=sys.stderr)
        return 1
    return 0


def log_event(session_id: str, event_type: str, raw: str | None = None,
              sanitized: str | None = None, tokens_map: dict | None = None, metadata: dict | None = None):
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
