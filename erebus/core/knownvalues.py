"""Durable known-value token store (FR-010..FR-018): SQLite WAL store with scope resolution,
legacy token_map.json seed/export, allowances, retention, transient fallback. Time via core.clock."""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .. import config
from . import clock

TOKEN_RE = re.compile(r"\[([A-Z_]+)_(\d+)_([0-9a-f]{6,})\]")

_SCHEMA = """PRAGMA busy_timeout=2000;
CREATE TABLE IF NOT EXISTS known_values (id INTEGER PRIMARY KEY, token TEXT UNIQUE NOT NULL, value TEXT NOT NULL, label TEXT NOT NULL, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, source TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_known_values_value ON known_values(value);
CREATE INDEX IF NOT EXISTS idx_known_values_created_at ON known_values(created_at);
CREATE TABLE IF NOT EXISTS escape_allowances (id INTEGER PRIMARY KEY, value TEXT NOT NULL, granted_at TEXT NOT NULL, expires_at TEXT NOT NULL, source TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_escape_allowances_value ON escape_allowances(value);
CREATE TABLE IF NOT EXISTS meta (schema_version INTEGER NOT NULL, generation INTEGER NOT NULL DEFAULT 0, seeded_from_legacy INTEGER NOT NULL DEFAULT 0);
"""  # noqa: E501

_INSERT_KV = ("INSERT OR IGNORE INTO known_values (token, value, label, created_at, last_seen_at, source)"
              " VALUES (?, ?, ?, ?, ?, ?)")

# Degraded transient-token mode (FR-012): process-local fallback shared by every handle.
_degraded = False
_TRANSIENT_TOKENS: dict[str, tuple[str, str, str]] = {}  # token -> (value, label, source)
_TRANSIENT_PAIRS: dict[tuple[str, str], str] = {}        # (value, label) -> token
_TRANSIENT_ALLOWANCES: dict[str, datetime] = {}          # value -> expires_at

class _Unchanged(Exception):
    """Raised inside a write txn to roll back without a generation bump."""

def db_degraded() -> bool:
    return _degraded
def _set_degraded(flag: bool) -> None:
    global _degraded
    _degraded = flag
    if flag:
        with suppress(Exception):  # lazy: avoid importing state (and its deps) on the happy path
            from .state import _mark_detector_degraded
            _mark_detector_degraded("knownvalue_db_unavailable")
def _normalize_label(label: str) -> str:
    norm = (label or "").upper().replace(" ", "_")
    return re.sub(r"[^A-Z_]", "_", norm).strip("_") or "VALUE"
def _parse_iso(text: str) -> datetime | None:
    t = (text or "").strip()
    with suppress(ValueError):
        dt = datetime.fromisoformat(t[:-1] + "+00:00" if t.endswith("Z") else t)
        return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
    return None
def _label_of(token: str, fallback: str) -> str:
    return m.group(1) if (m := TOKEN_RE.fullmatch(token)) else fallback
def _max_counter(tokens, norm_label: str) -> int:  # highest per-label counter among token strings
    return max((int(m.group(2)) for t in tokens
                if (m := TOKEN_RE.fullmatch(t)) and m.group(1) == norm_label), default=0)
def _store_transient(token: str, value: str, label: str, source: str) -> None:
    _TRANSIENT_TOKENS[token] = (value, label, source)
    _TRANSIENT_PAIRS[(value, label)] = token


def _durable_value(value: str) -> bool:
    """Degenerate values (stripped length < 2) never enter the durable store:
    one poisoned row would make the pre-scan rewrite that character everywhere
    it appears in prose (seen live via a legacy token_map import). In-flight
    mappings are kept transient instead so round-trips still resolve."""
    return len(value.strip()) >= 2
def _q(conn: sqlite3.Connection, sql: str, params=()) -> list[sqlite3.Row]:
    try:  # read query that degrades to "no rows" instead of raising
        return conn.execute(sql, params).fetchall()
    except sqlite3.OperationalError:
        return []

@dataclass
class KnownValueView:
    """Generation-tagged in-memory snapshot of the store."""
    token_view: dict[str, str] = field(default_factory=dict)  # token -> value
    value_view: dict[str, str] = field(default_factory=dict)  # value -> token
    generation: int = 0

def open_known_values(repo_config, project_dir: str) -> KnownValueDB:
    """Open the known-value store for the configured scope (FR-015)."""
    return KnownValueDB(repo_config, project_dir)

class KnownValueDB:
    def __init__(self, repo_config, project_dir: str):
        self._scope = getattr(repo_config, "known_values_scope", "global") or "global"
        self._retention = getattr(repo_config, "known_values_retention", "days:7") or "days:7"
        self._project_dir = Path(project_dir)
        self._session_only = self._retention == "session"
        self._conns: list[tuple[object, sqlite3.Connection | None]] = []  # read-ordered; [0] = mint target
        for i, path in enumerate(self._read_paths()):
            try:
                conn = self._open_conn(path)
            except sqlite3.Error as exc:
                conn = None
                print(f"erebus: cannot open known-values DB {path}: {exc}", file=sys.stderr)
                if i == 0:
                    _set_degraded(True)
            self._conns.append((path, conn))
        self._seed_from_legacy()

    def _read_paths(self) -> list[object]:
        if self._session_only:
            return [":memory:"]  # 'session' retention never touches disk (FR-016)
        proj = self._project_dir / ".erebus" / "known_values.db"
        glob = Path.home() / ".erebus" / "known_values.db"
        return {"project": [proj], "hybrid": [proj, glob]}.get(self._scope, [glob])  # hybrid reads proj first

    def _open_conn(self, path: object) -> sqlite3.Connection:
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            config.secure_path(Path(path).parent, 0o700)
        conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        if conn.execute("SELECT COUNT(*) FROM meta").fetchone()[0] == 0:
            conn.execute("INSERT INTO meta (schema_version, generation, seeded_from_legacy) VALUES (1, 0, 0)")
        if path != ":memory:":
            config.secure_path(Path(path), 0o600)
        return conn

    @property
    def _write_conn(self) -> sqlite3.Connection | None:
        return self._conns[0][1] if self._conns else None

    def _live_conns(self) -> list[sqlite3.Connection]:
        return [conn for _, conn in self._conns if conn is not None]

    def _write_txn(self, fn):
        """Run fn(conn) under BEGIN IMMEDIATE; bump generation; export legacy map."""
        conn = self._write_conn
        if conn is None:
            raise sqlite3.OperationalError("known-values DB unavailable")
        conn.execute("BEGIN IMMEDIATE")
        try:
            result = fn(conn)
            conn.execute("UPDATE meta SET generation = generation + 1")
            conn.execute("COMMIT")
        except BaseException:
            with suppress(sqlite3.Error):
                conn.execute("ROLLBACK")
            raise
        _set_degraded(False)
        self._export_legacy()
        return result

    def _safe_write(self, fn):
        """_write_txn, but DB failure flips to degraded mode instead of raising."""
        try:
            return self._write_txn(fn)
        except sqlite3.OperationalError:
            _set_degraded(True)
            return None

    def _export_legacy(self) -> None:
        """Write-through export of the full map to legacy token_map.json (FR-010c)."""
        if self._session_only:
            return
        try:
            config.save_token_map({row["token"]: row["value"] for conn in self._live_conns()
                                   for row in _q(conn, "SELECT token, value FROM known_values")})
        except Exception as exc:  # logged, never fatal, never rolls back the txn
            print(f"erebus: known-values legacy export failed: {exc}", file=sys.stderr)

    def _seed_from_legacy(self) -> None:
        """One-time import of legacy token_map.json into the mint DB (FR-010c)."""
        if self._session_only or self._write_conn is None:
            return
        rows = _q(self._write_conn, "SELECT seeded_from_legacy FROM meta")
        if (rows and rows[0]["seeded_from_legacy"]) or not config.TOKEN_MAP_PATH.exists():
            return
        created = self._legacy_created_at() or clock.now().isoformat()
        entries = config.load_token_map()  # handles v2 format + expiry (wipes if stale)
        def _do(c):
            for token, value in entries.items():
                # _durable_value: the original poisoning vector — a degenerate
                # 1-char value in the legacy map must not enter the store.
                if isinstance(token, str) and isinstance(value, str) and _durable_value(value):
                    c.execute(_INSERT_KV, (token, value, _label_of(token, "LEGACY"),
                                           created, created, "legacy_import"))
            c.execute("UPDATE meta SET seeded_from_legacy = 1")
        self._safe_write(_do)

    @staticmethod
    def _legacy_created_at() -> str | None:
        with suppress(Exception):
            data = json.loads(config.TOKEN_MAP_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict) and isinstance(data.get("created_at"), str):
                return data["created_at"]
        return None

    def _try_recover(self) -> None:
        """Reopen failed connections and flush transient pairs into the DB (FR-012)."""
        # Degenerate-valued transients are deliberately NOT flushable: they stay
        # in-memory forever (resolvable, never durable) and must not retrigger
        # the flush transaction on every read.
        flushable = (any(_durable_value(value) for value, _label, _source in _TRANSIENT_TOKENS.values())
                     or bool(_TRANSIENT_ALLOWANCES))
        if not _degraded and not flushable and self._conns and all(c is not None for _, c in self._conns):
            return
        for i, (path, conn) in enumerate(self._conns):
            if conn is None:
                with suppress(sqlite3.Error):
                    self._conns[i] = (path, self._open_conn(path))
        if self._write_conn is None or not flushable:
            return
        now = clock.now()
        def _do(c):
            for token, (value, label, source) in _TRANSIENT_TOKENS.items():
                if not _durable_value(value):
                    continue
                c.execute(_INSERT_KV, (token, value, label, now.isoformat(), now.isoformat(), source))
            for value, expires in _TRANSIENT_ALLOWANCES.items():
                if expires > now:
                    c.execute("INSERT INTO escape_allowances (value, granted_at, expires_at, source)"
                              " VALUES (?, ?, ?, 'transient_recovery')",
                              (value, now.isoformat(), expires.isoformat()))
            return True
        if self._safe_write(_do):
            retained = {token: entry for token, entry in _TRANSIENT_TOKENS.items()
                        if not _durable_value(entry[0])}
            retained_pairs = {pair: token for pair, token in _TRANSIENT_PAIRS.items()
                              if token in retained}
            _TRANSIENT_TOKENS.clear()
            _TRANSIENT_TOKENS.update(retained)
            _TRANSIENT_PAIRS.clear()
            _TRANSIENT_PAIRS.update(retained_pairs)
            _TRANSIENT_ALLOWANCES.clear()

    def lookup_value(self, token: str) -> str | None:
        self._try_recover()
        for conn in self._live_conns():
            if rows := _q(conn, "SELECT value FROM known_values WHERE token = ?", (token,)):
                return rows[0]["value"]
        return entry[0] if (entry := _TRANSIENT_TOKENS.get(token)) else None

    def lookup_token(self, value: str, label: str) -> str | None:
        self._try_recover()
        return self._find_pair(value, _normalize_label(label))[1]

    def _find_pair(self, value: str, norm_label: str) -> tuple[int, str | None]:
        """(conn_index, token) for a pair; labels compared normalized (stored raw), project DB wins."""
        for i, (_, conn) in enumerate(self._conns):
            for row in (_q(conn, "SELECT token, label FROM known_values WHERE value = ?"
                                 " ORDER BY id", (value,)) if conn else []):
                if _normalize_label(row["label"]) == norm_label:
                    return i, row["token"]
        return -1, _TRANSIENT_PAIRS.get((value, norm_label))

    def mint(self, value: str, label: str, source: str = "") -> str:
        """Idempotent per (value, label): returns the existing token if any (FR-011)."""
        self._try_recover()
        norm = _normalize_label(label)
        idx, existing = self._find_pair(value, norm)
        if existing is not None:
            if idx == 0:  # refresh last_seen_at only on the mint-target DB
                self._safe_write(lambda c: c.execute(
                    "UPDATE known_values SET last_seen_at = ? WHERE token = ?",
                    (clock.now().isoformat(), existing)))
            return existing
        def _do(c):
            kept = [r["token"] for r in c.execute("SELECT token FROM known_values")]
            n = max(_max_counter(kept, norm), _max_counter(_TRANSIENT_TOKENS, norm)) + 1
            token = f"[{norm}_{n}_{secrets.token_hex(3)}]"
            c.execute(_INSERT_KV, (token, value, label, (ts := clock.now().isoformat()), ts, source))
            return token
        token = self._safe_write(_do)
        if token is None:  # degraded: hand out a process-local transient token (FR-012)
            token = f"[{norm}_{_max_counter(_TRANSIENT_TOKENS, norm) + 1}_{secrets.token_hex(3)}]"
            _store_transient(token, value, norm, source)
        return token

    def ingest(self, token: str, value: str, label: str = "", source: str = "") -> None:
        """Adopt an externally minted (token, value) pair; no-op when the token is already stored."""
        if self.lookup_value(token) is not None:
            return
        lbl = label or _label_of(token, "INGESTED")
        if not _durable_value(value):
            # The token may already sit in model-bound text, so the mapping must
            # stay resolvable — but only transiently, never in the durable DB.
            # lookup_value() sees transients, so this logs once per token.
            print(f"erebus: keeping degenerate value for {token} transient only "
                  f"(len<2, source={source!r})", file=sys.stderr)
            _store_transient(token, value, _normalize_label(lbl), source)
            return
        ts = clock.now().isoformat()
        if self._safe_write(lambda c: c.execute(_INSERT_KV, (token, value, lbl, ts, ts, source))) is None:
            _store_transient(token, value, _normalize_label(lbl), source)

    def bulk_view(self) -> KnownValueView:
        self._try_recover()
        token_view: dict[str, str] = {}
        value_view: dict[str, str] = {}
        for _, conn in reversed(self._conns):  # low priority first so project overwrites
            for row in (_q(conn, "SELECT token, value FROM known_values") if conn else []):
                token_view[row["token"]] = row["value"]
                value_view[row["value"]] = row["token"]
        for token, (value, _label, _src) in _TRANSIENT_TOKENS.items():
            token_view.setdefault(token, value)
            value_view.setdefault(value, token)
        return KnownValueView(token_view, value_view, self._current_generation())

    def revalidate(self, view: KnownValueView) -> KnownValueView:
        # Cheap generation probe; reloads the view only on mismatch.
        return view if self._current_generation() == view.generation else self.bulk_view()

    def _current_generation(self) -> int:
        # Sum across scope DBs: strictly increases on any committed write.
        return sum((rows[0]["generation"] if (rows := _q(conn, "SELECT generation FROM meta")) else 0)
                   for conn in self._live_conns())

    def resolve_missing(self, tokens: set[str]) -> dict[str, str]:
        """Recover unknown tokens from the audit log and persist them (FR-018)."""
        resolved = {t: v for t in tokens if (v := self.lookup_value(t)) is not None}
        missing = tokens - resolved.keys()
        if not missing:
            return resolved
        try:  # lazy import: the audit logger lives outside core
            from ..audit.logger import lookup_token_values
            found = lookup_token_values(missing)
        except Exception as exc:
            print(f"erebus: audit-log token recovery failed: {exc}", file=sys.stderr)
            found = {}
        if found:
            now_iso = clock.now().isoformat()
            def _do(c):
                for token, value in found.items():
                    c.execute(_INSERT_KV, (token, value, _label_of(token, "RECOVERED"),
                                           now_iso, now_iso, "audit_recovery"))
                return True
            if not self._safe_write(_do):
                for token, value in found.items():
                    _store_transient(token, value, _label_of(token, "RECOVERED"), "audit_recovery")
            resolved.update(found)
        return resolved

    def grant_allowance(self, value: str, window_min: int, source: str = "") -> None:
        """Record a user escape: the value may pass unprotected until expiry (FR-013)."""
        self._try_recover()
        now = clock.now()
        expires = now + timedelta(minutes=window_min)
        ok = self._safe_write(lambda c: c.execute(
            "INSERT INTO escape_allowances (value, granted_at, expires_at, source) VALUES (?, ?, ?, ?)",
            (value, now.isoformat(), expires.isoformat(), source)))
        if ok is None:  # degraded: keep the allowance in memory so escapes still work
            prev = _TRANSIENT_ALLOWANCES.get(value)
            _TRANSIENT_ALLOWANCES[value] = max(expires, prev) if prev else expires

    def active_allowances(self) -> dict[str, datetime]:
        """value -> expires_at for every non-expired allowance (FR-013/FR-014)."""
        self._try_recover()
        now = clock.now()
        out: dict[str, datetime] = {}
        rows = [(row["value"], _parse_iso(row["expires_at"])) for conn in self._live_conns()
                for row in _q(conn, "SELECT value, expires_at FROM escape_allowances")]
        for value, expires in rows + list(_TRANSIENT_ALLOWANCES.items()):
            if expires and expires > now and expires > out.get(value, now):
                out[value] = expires
        return out

    def sweep(self) -> int:
        """Rotate aged values + expired allowances; no-op for 'permanent' (FR-016)."""
        if self._retention == "permanent":
            return 0
        self._try_recover()
        now = clock.now()
        cutoff, days = None, 7
        if self._retention.startswith("days:"):
            with suppress(ValueError):
                days = int(self._retention.split(":", 1)[1])
            cutoff = (now - timedelta(days=days)).isoformat()
        def _do(c):
            removed = 0
            if cutoff is not None:
                removed += c.execute("DELETE FROM known_values WHERE created_at < ?", (cutoff,)).rowcount or 0
            removed += c.execute("DELETE FROM escape_allowances WHERE expires_at <= ?",
                                 (now.isoformat(),)).rowcount or 0
            if removed == 0:
                raise _Unchanged()  # roll back: no visible change, no generation bump
            return removed
        removed = 0
        with suppress(_Unchanged):
            removed = self._safe_write(_do) or 0
        for value in [v for v, e in _TRANSIENT_ALLOWANCES.items() if e <= now]:
            del _TRANSIENT_ALLOWANCES[value]
        return removed

    def erase(self, value: str) -> bool:
        """Delete a value's row + its allowances in ONE txn per scope DB (erebus-forget)."""
        self._try_recover()
        erased = False
        for i, (_, conn) in enumerate(self._conns):
            if conn is None:
                continue
            try:
                conn.execute("BEGIN IMMEDIATE")
                n = conn.execute("DELETE FROM known_values WHERE value = ?", (value,)).rowcount or 0
                n += conn.execute("DELETE FROM escape_allowances WHERE value = ?", (value,)).rowcount or 0
                if n:
                    conn.execute("UPDATE meta SET generation = generation + 1")
                    erased = True
                conn.execute("COMMIT")
            except sqlite3.OperationalError:
                with suppress(sqlite3.Error):
                    conn.execute("ROLLBACK")
                if i == 0:
                    _set_degraded(True)
        for token, (v, label, _src) in list(_TRANSIENT_TOKENS.items()):
            if v == value:
                del _TRANSIENT_TOKENS[token]
                _TRANSIENT_PAIRS.pop((v, label), None)
                erased = True
        erased = _TRANSIENT_ALLOWANCES.pop(value, None) is not None or erased
        if erased:
            self._export_legacy()  # the value must leave the legacy JSON too
        return erased

    def close(self) -> None:
        for _, conn in self._conns:
            if conn is not None:
                with suppress(sqlite3.Error):
                    conn.close()
        self._conns = []
