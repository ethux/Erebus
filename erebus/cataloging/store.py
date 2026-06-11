# pylint: disable=too-many-lines  # legacy size, slated to shrink in 004 restructure
"""Local PII catalog storage and domain operations.

The catalog is Erebus's durable source of accepted known values. It stores
read-only source registrations, scan findings, stable catalog tokens, review
decisions, reveal policy, and sanitized audit events in the local Erebus
SQLite database.
"""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .. import config

CATALOG_DB_PATH: Path | None = None

SOURCE_STATUS_ACTIVE = "active"
SOURCE_STATUS_DISABLED = "disabled"
SOURCE_STATUS_ERROR = "error"

SCAN_PENDING = "pending"
SCAN_RUNNING = "running"
SCAN_COMPLETED = "completed"
SCAN_COMPLETED_WITH_ERRORS = "completed_with_errors"
SCAN_FAILED = "failed"
SCAN_CANCELLED = "cancelled"

FINDING_CANDIDATE = "candidate"
FINDING_ACCEPTED = "accepted"
FINDING_REJECTED = "rejected"
FINDING_REMOVED = "removed"
FINDING_STALE = "stale"

ENTRY_ACTIVE = "active"
ENTRY_STALE = "stale"
ENTRY_REMOVED = "removed"

POLICY_NAME_DEFAULT = "default"
MAX_REVEAL_MINUTES = 24 * 60

_EMAIL_RE = re.compile(r"(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}")
_PHONE_RE = re.compile(r"\+?[\d\s().-]{7,}")
_SECRET_ASSIGNMENT_RE = re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+")


@dataclass
class ExternalDataSource:
    id: int
    name: str
    type: str
    location_ref: str = ""
    connector_config: dict[str, Any] = field(default_factory=dict)
    secret_refs: dict[str, str] = field(default_factory=dict)
    status: str = SOURCE_STATUS_ACTIVE
    last_error: str = ""
    created_at: str = ""
    updated_at: str = ""


@dataclass
class ScanScope:
    id: int
    source_id: int
    dataset: str
    columns: list[str] = field(default_factory=list)
    row_limit: int | None = None
    field_roles: dict[str, str] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class ScanRun:
    id: int
    source_id: int
    started_at: str = ""
    finished_at: str = ""
    status: str = SCAN_PENDING
    scopes: list[dict[str, Any]] = field(default_factory=list)
    rows_seen: int = 0
    findings_total: int = 0
    accepted_total: int = 0
    uncertain_total: int = 0
    rejected_total: int = 0
    error_summary: str = ""


@dataclass
class PIIFinding:
    id: int
    scan_run_id: int
    source_id: int
    source_ref: dict[str, Any]
    category: str
    value: str
    normalized_value: str
    confidence: str
    detection_reason: str
    status: str = FINDING_CANDIDATE
    catalog_entry_id: int | None = None
    created_at: str = ""
    reviewed_at: str = ""


@dataclass
class CatalogEntry:
    id: int
    category: str
    value: str
    normalized_value: str
    token: str
    status: str = ENTRY_ACTIVE
    first_seen_at: str = ""
    last_seen_at: str = ""
    source_count: int = 0
    review_status: str = "auto_accepted"


@dataclass
class SourceReference:
    id: int
    catalog_entry_id: int
    source_id: int
    dataset: str
    column: str
    row_ref: str
    last_seen_scan_run_id: int | None = None
    last_seen_at: str = ""


@dataclass
class RevealPolicy:
    id: int
    name: str = POLICY_NAME_DEFAULT
    name_mode: str = "balanced"
    allow_first_name: bool = True
    strict_near_identifiers: bool = True
    temporary_reveal_minutes: int = 30
    enabled: bool = True


@dataclass
class RevealGrant:
    id: int
    catalog_entry_id: int
    reason: str
    created_at: str
    expires_at: str
    status: str = "active"


@dataclass
class ReviewDecision:
    id: int
    finding_id: int
    action: str
    previous_status: str
    new_status: str
    reason: str = ""
    created_at: str = ""


@dataclass
class CatalogAuditEvent:
    id: int
    event_type: str
    created_at: str
    summary: str
    metadata: dict[str, Any] = field(default_factory=dict)


def _db_path() -> Path:
    return CATALOG_DB_PATH or config.DB_PATH


def _json_dumps(value: Any) -> str:
    return json.dumps(value if value is not None else {}, sort_keys=True)


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return fallback


def _now() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def _parse_time(value: str) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1]
    return datetime.fromisoformat(text)


def connect() -> sqlite3.Connection:
    """Open the local catalog database with secure parent/file permissions."""
    config.ensure_erebus_dir()
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row
    config.secure_path(_db_path(), 0o600)
    return conn


def init_catalog_db() -> None:
    conn = connect()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS catalog_sources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            type TEXT NOT NULL,
            location_ref TEXT DEFAULT '',
            connector_config TEXT DEFAULT '{}',
            secret_refs TEXT DEFAULT '{}',
            status TEXT DEFAULT 'active',
            last_error TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS catalog_scopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            dataset TEXT NOT NULL,
            columns TEXT DEFAULT '[]',
            row_limit INTEGER,
            field_roles TEXT DEFAULT '{}',
            enabled INTEGER DEFAULT 1,
            FOREIGN KEY(source_id) REFERENCES catalog_sources(id)
        );

        CREATE TABLE IF NOT EXISTS catalog_scan_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_id INTEGER NOT NULL,
            started_at TEXT DEFAULT CURRENT_TIMESTAMP,
            finished_at TEXT DEFAULT '',
            status TEXT DEFAULT 'pending',
            scopes TEXT DEFAULT '[]',
            rows_seen INTEGER DEFAULT 0,
            findings_total INTEGER DEFAULT 0,
            accepted_total INTEGER DEFAULT 0,
            uncertain_total INTEGER DEFAULT 0,
            rejected_total INTEGER DEFAULT 0,
            error_summary TEXT DEFAULT '',
            FOREIGN KEY(source_id) REFERENCES catalog_sources(id)
        );

        CREATE TABLE IF NOT EXISTS catalog_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            category TEXT NOT NULL,
            value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'active',
            first_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
            source_count INTEGER DEFAULT 0,
            review_status TEXT DEFAULT 'auto_accepted'
        );

        CREATE INDEX IF NOT EXISTS idx_catalog_entries_lookup
            ON catalog_entries(category, normalized_value, status);

        CREATE TABLE IF NOT EXISTS catalog_findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL,
            source_id INTEGER NOT NULL,
            source_ref TEXT DEFAULT '{}',
            category TEXT NOT NULL,
            value TEXT NOT NULL,
            normalized_value TEXT NOT NULL,
            confidence TEXT NOT NULL,
            detection_reason TEXT DEFAULT '',
            status TEXT DEFAULT 'candidate',
            catalog_entry_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            reviewed_at TEXT DEFAULT '',
            FOREIGN KEY(scan_run_id) REFERENCES catalog_scan_runs(id),
            FOREIGN KEY(source_id) REFERENCES catalog_sources(id),
            FOREIGN KEY(catalog_entry_id) REFERENCES catalog_entries(id)
        );

        CREATE TABLE IF NOT EXISTS catalog_source_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            catalog_entry_id INTEGER NOT NULL,
            source_id INTEGER NOT NULL,
            dataset TEXT NOT NULL,
            column TEXT NOT NULL,
            row_ref TEXT DEFAULT '',
            last_seen_scan_run_id INTEGER,
            last_seen_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(catalog_entry_id) REFERENCES catalog_entries(id),
            FOREIGN KEY(source_id) REFERENCES catalog_sources(id),
            UNIQUE(catalog_entry_id, source_id, dataset, column, row_ref)
        );

        CREATE TABLE IF NOT EXISTS catalog_reveal_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE DEFAULT 'default',
            name_mode TEXT DEFAULT 'balanced',
            allow_first_name INTEGER DEFAULT 1,
            strict_near_identifiers INTEGER DEFAULT 1,
            temporary_reveal_minutes INTEGER DEFAULT 30,
            enabled INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS catalog_reveal_grants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            catalog_entry_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT NOT NULL,
            status TEXT DEFAULT 'active',
            FOREIGN KEY(catalog_entry_id) REFERENCES catalog_entries(id)
        );

        CREATE TABLE IF NOT EXISTS catalog_review_decisions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            previous_status TEXT DEFAULT '',
            new_status TEXT DEFAULT '',
            reason TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(finding_id) REFERENCES catalog_findings(id)
        );

        CREATE TABLE IF NOT EXISTS catalog_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            summary TEXT DEFAULT '',
            metadata TEXT DEFAULT '{}'
        );
        """
    )
    conn.execute(
        """
        INSERT OR IGNORE INTO catalog_reveal_policies
            (name, name_mode, allow_first_name, strict_near_identifiers,
             temporary_reveal_minutes, enabled)
        VALUES (?, 'balanced', 1, 1, 30, 1)
        """,
        (POLICY_NAME_DEFAULT,),
    )
    conn.commit()
    conn.close()
    config.secure_path(_db_path(), 0o600)


def normalize_value(value: str) -> str:
    return " ".join(str(value).strip().casefold().split())


def mask_value(value: str, keep: int = 2) -> str:
    value = str(value)
    if not value:
        return ""
    if _EMAIL_RE.fullmatch(value):
        user, domain = value.split("@", 1)
        return f"{user[:1]}***@{domain}"
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * min(8, max(3, len(value) - keep))}"


def sanitize_error(exc: BaseException | str) -> str:
    text = str(exc)
    text = _EMAIL_RE.sub("[EMAIL]", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _PHONE_RE.sub("[PHONE]", text)
    return text[:500]


def generate_catalog_token(category: str) -> str:
    label = re.sub(r"[^A-Z0-9_]", "_", category.upper()).strip("_") or "SENSITIVE"
    return f"[CATALOG_{label}_{uuid.uuid4().hex[:10]}]"


def _source_from_row(row: sqlite3.Row) -> ExternalDataSource:
    return ExternalDataSource(
        id=row["id"],
        name=row["name"],
        type=row["type"],
        location_ref=row["location_ref"] or "",
        connector_config=_json_loads(row["connector_config"], {}),
        secret_refs=_json_loads(row["secret_refs"], {}),
        status=row["status"] or SOURCE_STATUS_ACTIVE,
        last_error=row["last_error"] or "",
        created_at=row["created_at"] or "",
        updated_at=row["updated_at"] or "",
    )


def _scope_from_row(row: sqlite3.Row) -> ScanScope:
    return ScanScope(
        id=row["id"],
        source_id=row["source_id"],
        dataset=row["dataset"],
        columns=_json_loads(row["columns"], []),
        row_limit=row["row_limit"],
        field_roles=_json_loads(row["field_roles"], {}),
        enabled=bool(row["enabled"]),
    )


def _scan_run_from_row(row: sqlite3.Row) -> ScanRun:
    return ScanRun(
        id=row["id"],
        source_id=row["source_id"],
        started_at=row["started_at"] or "",
        finished_at=row["finished_at"] or "",
        status=row["status"] or SCAN_PENDING,
        scopes=_json_loads(row["scopes"], []),
        rows_seen=row["rows_seen"] or 0,
        findings_total=row["findings_total"] or 0,
        accepted_total=row["accepted_total"] or 0,
        uncertain_total=row["uncertain_total"] or 0,
        rejected_total=row["rejected_total"] or 0,
        error_summary=row["error_summary"] or "",
    )


def _finding_from_row(row: sqlite3.Row) -> PIIFinding:
    return PIIFinding(
        id=row["id"],
        scan_run_id=row["scan_run_id"],
        source_id=row["source_id"],
        source_ref=_json_loads(row["source_ref"], {}),
        category=row["category"],
        value=row["value"],
        normalized_value=row["normalized_value"],
        confidence=row["confidence"],
        detection_reason=row["detection_reason"] or "",
        status=row["status"] or FINDING_CANDIDATE,
        catalog_entry_id=row["catalog_entry_id"],
        created_at=row["created_at"] or "",
        reviewed_at=row["reviewed_at"] or "",
    )


def _entry_from_row(row: sqlite3.Row) -> CatalogEntry:
    return CatalogEntry(
        id=row["id"],
        category=row["category"],
        value=row["value"],
        normalized_value=row["normalized_value"],
        **{"token": row["token"]},
        status=row["status"] or ENTRY_ACTIVE,
        first_seen_at=row["first_seen_at"] or "",
        last_seen_at=row["last_seen_at"] or "",
        source_count=row["source_count"] or 0,
        review_status=row["review_status"] or "auto_accepted",
    )


def _policy_from_row(row: sqlite3.Row) -> RevealPolicy:
    return RevealPolicy(
        id=row["id"],
        name=row["name"] or POLICY_NAME_DEFAULT,
        name_mode=row["name_mode"] or "balanced",
        allow_first_name=bool(row["allow_first_name"]),
        strict_near_identifiers=bool(row["strict_near_identifiers"]),
        temporary_reveal_minutes=row["temporary_reveal_minutes"] or 30,
        enabled=bool(row["enabled"]),
    )


def _grant_from_row(row: sqlite3.Row) -> RevealGrant:
    return RevealGrant(
        id=row["id"],
        catalog_entry_id=row["catalog_entry_id"],
        reason=row["reason"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        status=row["status"],
    )


def _audit_from_row(row: sqlite3.Row) -> CatalogAuditEvent:
    return CatalogAuditEvent(
        id=row["id"],
        event_type=row["event_type"],
        created_at=row["created_at"],
        summary=row["summary"] or "",
        metadata=_json_loads(row["metadata"], {}),
    )


def add_source(name: str, connector_type: str, location_ref: str = "",
               connector_config: dict[str, Any] | None = None,
               secret_refs: dict[str, str] | None = None) -> ExternalDataSource:
    init_catalog_db()
    now = _now()
    conn = connect()
    cur = conn.execute(
        """
        INSERT INTO catalog_sources
            (name, type, location_ref, connector_config, secret_refs,
             status, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            type=excluded.type,
            location_ref=excluded.location_ref,
            connector_config=excluded.connector_config,
            secret_refs=excluded.secret_refs,
            status='active',
            updated_at=excluded.updated_at
        """,
        (
            name,
            connector_type,
            location_ref,
            _json_dumps(connector_config or {}),
            _json_dumps(secret_refs or {}),
            SOURCE_STATUS_ACTIVE,
            now,
            now,
        ),
    )
    source_id = cur.lastrowid or conn.execute(
        "SELECT id FROM catalog_sources WHERE name=?", (name,)
    ).fetchone()["id"]
    row = conn.execute("SELECT * FROM catalog_sources WHERE id=?", (source_id,)).fetchone()
    conn.commit()
    conn.close()
    return _source_from_row(row)


def list_sources() -> list[ExternalDataSource]:
    init_catalog_db()
    conn = connect()
    rows = conn.execute("SELECT * FROM catalog_sources ORDER BY name").fetchall()
    conn.close()
    return [_source_from_row(row) for row in rows]


def get_source(source: str | int) -> ExternalDataSource | None:
    init_catalog_db()
    conn = connect()
    if isinstance(source, int) or str(source).isdigit():
        row = conn.execute("SELECT * FROM catalog_sources WHERE id=?", (int(source),)).fetchone()
    else:
        row = conn.execute("SELECT * FROM catalog_sources WHERE name=?", (str(source),)).fetchone()
    conn.close()
    return _source_from_row(row) if row else None


def add_scope(source_id: int, dataset: str, columns: list[str] | None = None,
              row_limit: int | None = None,
              field_roles: dict[str, str] | None = None,
              enabled: bool = True) -> ScanScope:
    init_catalog_db()
    conn = connect()
    cur = conn.execute(
        """
        INSERT INTO catalog_scopes
            (source_id, dataset, columns, row_limit, field_roles, enabled)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            source_id,
            dataset,
            _json_dumps(columns or []),
            row_limit,
            _json_dumps(field_roles or {}),
            1 if enabled else 0,
        ),
    )
    row = conn.execute("SELECT * FROM catalog_scopes WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.commit()
    conn.close()
    return _scope_from_row(row)


def list_scopes(source_id: int) -> list[ScanScope]:
    init_catalog_db()
    conn = connect()
    rows = conn.execute(
        "SELECT * FROM catalog_scopes WHERE source_id=? ORDER BY id",
        (source_id,),
    ).fetchall()
    conn.close()
    return [_scope_from_row(row) for row in rows]


def create_scan_run(source_id: int, scopes: list[dict[str, Any]] | None = None,
                    status: str = SCAN_RUNNING) -> ScanRun:
    init_catalog_db()
    conn = connect()
    cur = conn.execute(
        """
        INSERT INTO catalog_scan_runs (source_id, started_at, status, scopes)
        VALUES (?, ?, ?, ?)
        """,
        (source_id, _now(), status, _json_dumps(scopes or [])),
    )
    row = conn.execute("SELECT * FROM catalog_scan_runs WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.commit()
    conn.close()
    return _scan_run_from_row(row)


def finish_scan_run(scan_run_id: int, status: str = SCAN_COMPLETED,
                    rows_seen: int | None = None,
                    error_summary: str = "") -> ScanRun:
    init_catalog_db()
    conn = connect()
    if rows_seen is None:
        rows_seen = conn.execute(
            "SELECT rows_seen FROM catalog_scan_runs WHERE id=?",
            (scan_run_id,),
        ).fetchone()["rows_seen"]
    counts = conn.execute(
        """
        SELECT
            COUNT(*) AS findings_total,
            SUM(CASE WHEN status='accepted' THEN 1 ELSE 0 END) AS accepted_total,
            SUM(CASE WHEN status='candidate' THEN 1 ELSE 0 END) AS uncertain_total,
            SUM(CASE WHEN status='rejected' THEN 1 ELSE 0 END) AS rejected_total
        FROM catalog_findings
        WHERE scan_run_id=?
        """,
        (scan_run_id,),
    ).fetchone()
    conn.execute(
        """
        UPDATE catalog_scan_runs
        SET finished_at=?, status=?, rows_seen=?, findings_total=?,
            accepted_total=?, uncertain_total=?, rejected_total=?, error_summary=?
        WHERE id=?
        """,
        (
            _now(),
            status,
            rows_seen,
            counts["findings_total"] or 0,
            counts["accepted_total"] or 0,
            counts["uncertain_total"] or 0,
            counts["rejected_total"] or 0,
            sanitize_error(error_summary) if error_summary else "",
            scan_run_id,
        ),
    )
    row = conn.execute("SELECT * FROM catalog_scan_runs WHERE id=?", (scan_run_id,)).fetchone()
    conn.commit()
    conn.close()
    return _scan_run_from_row(row)


def create_finding(scan_run_id: int, source_id: int, source_ref: dict[str, Any],
                   category: str, value: str, confidence: str,
                   detection_reason: str = "",
                   status: str = FINDING_CANDIDATE,
                   catalog_entry_id: int | None = None) -> PIIFinding:
    init_catalog_db()
    normalized = normalize_value(value)
    conn = connect()
    cur = conn.execute(
        """
        INSERT INTO catalog_findings
            (scan_run_id, source_id, source_ref, category, value,
             normalized_value, confidence, detection_reason, status,
             catalog_entry_id, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_run_id,
            source_id,
            _json_dumps(source_ref),
            category,
            value,
            normalized,
            confidence,
            detection_reason,
            status,
            catalog_entry_id,
            _now(),
        ),
    )
    row = conn.execute("SELECT * FROM catalog_findings WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.commit()
    conn.close()
    return _finding_from_row(row)


def list_findings(status: str | None = None, source_id: int | None = None) -> list[PIIFinding]:
    init_catalog_db()
    clauses = []
    params: list[Any] = []
    if status:
        clauses.append("status=?")
        params.append(status)
    if source_id is not None:
        clauses.append("source_id=?")
        params.append(source_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    conn = connect()
    rows = conn.execute(f"SELECT * FROM catalog_findings {where} ORDER BY id", params).fetchall()
    conn.close()
    return [_finding_from_row(row) for row in rows]


def get_finding(finding_id: int) -> PIIFinding | None:
    init_catalog_db()
    conn = connect()
    row = conn.execute("SELECT * FROM catalog_findings WHERE id=?", (finding_id,)).fetchone()
    conn.close()
    return _finding_from_row(row) if row else None


def get_or_create_catalog_entry(category: str, value: str,
                                review_status: str = "auto_accepted") -> CatalogEntry:
    init_catalog_db()
    normalized = normalize_value(value)
    conn = connect()
    row = conn.execute(
        """
        SELECT * FROM catalog_entries
        WHERE category=? AND normalized_value=? AND status != 'removed'
        ORDER BY id LIMIT 1
        """,
        (category, normalized),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE catalog_entries SET last_seen_at=?, status='active' WHERE id=?",
            (_now(), row["id"]),
        )
        updated = conn.execute("SELECT * FROM catalog_entries WHERE id=?", (row["id"],)).fetchone()
        conn.commit()
        conn.close()
        return _entry_from_row(updated)
    cur = conn.execute(
        """
        INSERT INTO catalog_entries
            (category, value, normalized_value, token, status, first_seen_at,
             last_seen_at, review_status)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
        """,
        (
            category,
            value,
            normalized,
            generate_catalog_token(category),
            _now(),
            _now(),
            review_status,
        ),
    )
    row = conn.execute("SELECT * FROM catalog_entries WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.commit()
    conn.close()
    return _entry_from_row(row)


def list_catalog_entries(active_only: bool = False) -> list[CatalogEntry]:
    init_catalog_db()
    conn = connect()
    if active_only:
        rows = conn.execute(
            "SELECT * FROM catalog_entries WHERE status='active' ORDER BY LENGTH(value) DESC"
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM catalog_entries ORDER BY id").fetchall()
    conn.close()
    return [_entry_from_row(row) for row in rows]


def add_source_reference(catalog_entry_id: int, source_id: int, dataset: str,
                         column: str, row_ref: str = "",
                         scan_run_id: int | None = None) -> SourceReference:
    init_catalog_db()
    conn = connect()
    conn.execute(
        """
        INSERT INTO catalog_source_references
            (catalog_entry_id, source_id, dataset, column, row_ref,
             last_seen_scan_run_id, last_seen_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(catalog_entry_id, source_id, dataset, column, row_ref)
        DO UPDATE SET
            last_seen_scan_run_id=excluded.last_seen_scan_run_id,
            last_seen_at=excluded.last_seen_at
        """,
        (catalog_entry_id, source_id, dataset, column, row_ref, scan_run_id, _now()),
    )
    row = conn.execute(
        """
        SELECT * FROM catalog_source_references
        WHERE catalog_entry_id=? AND source_id=? AND dataset=? AND column=? AND row_ref=?
        """,
        (catalog_entry_id, source_id, dataset, column, row_ref),
    ).fetchone()
    conn.execute(
        """
        UPDATE catalog_entries
        SET source_count=(
            SELECT COUNT(*) FROM catalog_source_references
            WHERE catalog_entry_id=?
        )
        WHERE id=?
        """,
        (catalog_entry_id, catalog_entry_id),
    )
    conn.commit()
    conn.close()
    return SourceReference(
        id=row["id"],
        catalog_entry_id=row["catalog_entry_id"],
        source_id=row["source_id"],
        dataset=row["dataset"],
        column=row["column"],
        row_ref=row["row_ref"] or "",
        last_seen_scan_run_id=row["last_seen_scan_run_id"],
        last_seen_at=row["last_seen_at"] or "",
    )


def list_source_references(catalog_entry_id: int | None = None) -> list[SourceReference]:
    init_catalog_db()
    conn = connect()
    if catalog_entry_id is None:
        rows = conn.execute(
            "SELECT * FROM catalog_source_references ORDER BY catalog_entry_id, id"
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT * FROM catalog_source_references
            WHERE catalog_entry_id=?
            ORDER BY id
            """,
            (catalog_entry_id,),
        ).fetchall()
    conn.close()
    return [
        SourceReference(
            id=row["id"],
            catalog_entry_id=row["catalog_entry_id"],
            source_id=row["source_id"],
            dataset=row["dataset"],
            column=row["column"],
            row_ref=row["row_ref"] or "",
            last_seen_scan_run_id=row["last_seen_scan_run_id"],
            last_seen_at=row["last_seen_at"] or "",
        )
        for row in rows
    ]


def accept_finding(finding_id: int, review_status: str = "user_accepted") -> CatalogEntry:
    init_catalog_db()
    conn = connect()
    row = conn.execute("SELECT * FROM catalog_findings WHERE id=?", (finding_id,)).fetchone()
    conn.close()
    if row is None:
        raise ValueError(f"Finding not found: {finding_id}")
    finding = _finding_from_row(row)
    entry = get_or_create_catalog_entry(finding.category, finding.value, review_status)
    source_ref = finding.source_ref or {}
    add_source_reference(
        entry.id,
        finding.source_id,
        source_ref.get("dataset") or source_ref.get("collection") or "",
        source_ref.get("column") or source_ref.get("field") or "",
        str(source_ref.get("row_ref") or ""),
        finding.scan_run_id,
    )
    conn = connect()
    conn.execute(
        """
        UPDATE catalog_findings
        SET status='accepted', catalog_entry_id=?, reviewed_at=?
        WHERE id=?
        """,
        (entry.id, _now(), finding_id),
    )
    conn.commit()
    conn.close()
    add_review_decision(finding_id, "accept", finding.status, FINDING_ACCEPTED)
    log_audit_event(
        "catalog_review",
        "Accepted catalog finding",
        {
            "finding_id": finding_id,
            "catalog_entry_id": entry.id,
            "category": finding.category,
            "review_status": review_status,
        },
    )
    return entry


def reject_finding(finding_id: int, reason: str = "") -> None:
    init_catalog_db()
    conn = connect()
    row = conn.execute("SELECT status FROM catalog_findings WHERE id=?", (finding_id,)).fetchone()
    if row is None:
        conn.close()
        raise ValueError(f"Finding not found: {finding_id}")
    previous = row["status"]
    conn.execute(
        "UPDATE catalog_findings SET status='rejected', reviewed_at=? WHERE id=?",
        (_now(), finding_id),
    )
    conn.commit()
    conn.close()
    add_review_decision(finding_id, "reject", previous, FINDING_REJECTED, reason)
    log_audit_event(
        "catalog_review",
        "Rejected catalog finding",
        {
            "finding_id": finding_id,
            "previous_status": previous,
            "reason": sanitize_error(reason),
        },
    )


def get_reveal_policy(name: str = POLICY_NAME_DEFAULT) -> RevealPolicy:
    init_catalog_db()
    conn = connect()
    row = conn.execute("SELECT * FROM catalog_reveal_policies WHERE name=?", (name,)).fetchone()
    conn.close()
    if row:
        return _policy_from_row(row)
    return set_reveal_policy(name=name)


def set_reveal_policy(name: str = POLICY_NAME_DEFAULT, name_mode: str = "balanced",
                      allow_first_name: bool = True,
                      strict_near_identifiers: bool = True,
                      temporary_reveal_minutes: int = 30,
                      enabled: bool = True) -> RevealPolicy:
    init_catalog_db()
    if name_mode not in {"strict", "balanced", "relaxed"}:
        raise ValueError("Reveal policy name_mode must be strict, balanced, or relaxed")
    if temporary_reveal_minutes <= 0 or temporary_reveal_minutes > MAX_REVEAL_MINUTES:
        raise ValueError(f"Reveal duration must be between 1 and {MAX_REVEAL_MINUTES} minutes")
    conn = connect()
    conn.execute(
        """
        INSERT INTO catalog_reveal_policies
            (name, name_mode, allow_first_name, strict_near_identifiers,
             temporary_reveal_minutes, enabled)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            name_mode=excluded.name_mode,
            allow_first_name=excluded.allow_first_name,
            strict_near_identifiers=excluded.strict_near_identifiers,
            temporary_reveal_minutes=excluded.temporary_reveal_minutes,
            enabled=excluded.enabled
        """,
        (
            name,
            name_mode,
            1 if allow_first_name else 0,
            1 if strict_near_identifiers else 0,
            temporary_reveal_minutes,
            1 if enabled else 0,
        ),
    )
    row = conn.execute("SELECT * FROM catalog_reveal_policies WHERE name=?", (name,)).fetchone()
    conn.commit()
    conn.close()
    policy = _policy_from_row(row)
    log_audit_event(
        "catalog_reveal",
        "Updated reveal policy",
        {
            "policy": policy.name,
            "name_mode": policy.name_mode,
            "allow_first_name": policy.allow_first_name,
            "strict_near_identifiers": policy.strict_near_identifiers,
            "temporary_reveal_minutes": policy.temporary_reveal_minutes,
        },
    )
    return policy


def create_reveal_grant(catalog_entry_id: int, reason: str,
                        minutes: int = 30) -> RevealGrant:
    init_catalog_db()
    if minutes <= 0 or minutes > MAX_REVEAL_MINUTES:
        raise ValueError(f"Reveal duration must be between 1 and {MAX_REVEAL_MINUTES} minutes")
    if not reason.strip():
        raise ValueError("Reveal reason is required")
    created = datetime.utcnow()
    expires = created + timedelta(minutes=minutes)
    conn = connect()
    entry = conn.execute(
        "SELECT id FROM catalog_entries WHERE id=? AND status='active'",
        (catalog_entry_id,),
    ).fetchone()
    if entry is None:
        conn.close()
        raise ValueError(f"Catalog entry not found: {catalog_entry_id}")
    cur = conn.execute(
        """
        INSERT INTO catalog_reveal_grants
            (catalog_entry_id, reason, created_at, expires_at, status)
        VALUES (?, ?, ?, ?, 'active')
        """,
        (
            catalog_entry_id,
            reason,
            created.replace(microsecond=0).isoformat() + "Z",
            expires.replace(microsecond=0).isoformat() + "Z",
        ),
    )
    row = conn.execute("SELECT * FROM catalog_reveal_grants WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.commit()
    conn.close()
    grant = _grant_from_row(row)
    log_audit_event(
        "catalog_reveal",
        "Created temporary reveal grant",
        {
            "catalog_entry_id": catalog_entry_id,
            "grant_id": grant.id,
            "expires_at": grant.expires_at,
        },
    )
    return grant


def expire_reveal_grants() -> int:
    init_catalog_db()
    conn = connect()
    cur = conn.execute(
        """
        UPDATE catalog_reveal_grants
        SET status='expired'
        WHERE status='active' AND expires_at <= ?
        """,
        (_now(),),
    )
    conn.commit()
    count = cur.rowcount if cur.rowcount is not None else 0
    conn.close()
    return count


def list_reveal_grants(catalog_entry_id: int | None = None,
                       active_only: bool = False) -> list[RevealGrant]:
    init_catalog_db()
    expire_reveal_grants()
    clauses = []
    params: list[Any] = []
    if catalog_entry_id is not None:
        clauses.append("catalog_entry_id=?")
        params.append(catalog_entry_id)
    if active_only:
        clauses.append("status='active'")
        clauses.append("expires_at > ?")
        params.append(_now())
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    conn = connect()
    rows = conn.execute(
        f"SELECT * FROM catalog_reveal_grants {where} ORDER BY id",
        params,
    ).fetchall()
    conn.close()
    return [_grant_from_row(row) for row in rows]


def has_active_reveal_grant(catalog_entry_id: int) -> bool:
    return bool(list_reveal_grants(catalog_entry_id, active_only=True))


def add_review_decision(finding_id: int, action: str, previous_status: str,
                        new_status: str, reason: str = "") -> ReviewDecision:
    init_catalog_db()
    conn = connect()
    cur = conn.execute(
        """
        INSERT INTO catalog_review_decisions
            (finding_id, action, previous_status, new_status, reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (finding_id, action, previous_status, new_status, reason, _now()),
    )
    row = conn.execute(
        "SELECT * FROM catalog_review_decisions WHERE id=?",
        (cur.lastrowid,),
    ).fetchone()
    conn.commit()
    conn.close()
    return ReviewDecision(
        id=row["id"],
        finding_id=row["finding_id"],
        action=row["action"],
        previous_status=row["previous_status"] or "",
        new_status=row["new_status"] or "",
        reason=row["reason"] or "",
        created_at=row["created_at"] or "",
    )


def log_audit_event(event_type: str, summary: str = "",
                    metadata: dict[str, Any] | None = None) -> CatalogAuditEvent:
    init_catalog_db()
    conn = connect()
    cur = conn.execute(
        """
        INSERT INTO catalog_audit_events
            (event_type, created_at, summary, metadata)
        VALUES (?, ?, ?, ?)
        """,
        (event_type, _now(), sanitize_error(summary), _json_dumps(metadata or {})),
    )
    row = conn.execute("SELECT * FROM catalog_audit_events WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.commit()
    conn.close()
    return _audit_from_row(row)


def list_audit_events(event_type: str | None = None) -> list[CatalogAuditEvent]:
    init_catalog_db()
    conn = connect()
    if event_type:
        rows = conn.execute(
            "SELECT * FROM catalog_audit_events WHERE event_type=? ORDER BY id",
            (event_type,),
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM catalog_audit_events ORDER BY id").fetchall()
    conn.close()
    return [_audit_from_row(row) for row in rows]


def mark_entries_stale_for_source(source_id: int, seen_entry_ids: set[int]) -> int:
    init_catalog_db()
    conn = connect()
    rows = conn.execute(
        """
        SELECT DISTINCT r.catalog_entry_id
        FROM catalog_source_references r
        JOIN catalog_entries e ON e.id = r.catalog_entry_id
        WHERE r.source_id=? AND e.status != 'removed'
        """,
        (source_id,),
    ).fetchall()
    stale_ids = [row["catalog_entry_id"] for row in rows if row["catalog_entry_id"] not in seen_entry_ids]
    if not stale_ids:
        conn.close()
        return 0
    placeholders = ",".join("?" for _ in stale_ids)
    conn.execute(
        f"UPDATE catalog_entries SET status='stale' WHERE id IN ({placeholders})",
        stale_ids,
    )
    conn.commit()
    conn.close()
    log_audit_event(
        "catalog_refresh",
        "Marked missing catalog entries stale",
        {"source_id": source_id, "stale_count": len(stale_ids)},
    )
    return len(stale_ids)


def forget_catalog_value(term: str) -> int:
    """Remove catalog entries and searchable references mentioning `term`."""
    term = term.strip()
    if not term:
        return 0
    init_catalog_db()
    like = f"%{term}%"
    conn = connect()
    rows = conn.execute(
        """
        SELECT id FROM catalog_entries
        WHERE value LIKE ? COLLATE NOCASE
           OR normalized_value LIKE ? COLLATE NOCASE
        """,
        (like, like),
    ).fetchall()
    entry_ids = [row["id"] for row in rows]
    if not entry_ids:
        conn.close()
        return 0
    placeholders = ",".join("?" for _ in entry_ids)
    conn.execute(
        f"UPDATE catalog_entries SET status='removed' WHERE id IN ({placeholders})",
        entry_ids,
    )
    conn.execute(
        f"DELETE FROM catalog_source_references WHERE catalog_entry_id IN ({placeholders})",
        entry_ids,
    )
    conn.execute(
        f"UPDATE catalog_findings SET status='removed' WHERE catalog_entry_id IN ({placeholders})",
        entry_ids,
    )
    conn.execute(
        """
        DELETE FROM catalog_audit_events
        WHERE IFNULL(summary, '') LIKE ? COLLATE NOCASE
           OR IFNULL(metadata, '') LIKE ? COLLATE NOCASE
        """,
        (like, like),
    )
    conn.commit()
    conn.close()
    log_audit_event("catalog_forget", "Removed catalog value", {"count": len(entry_ids)})
    return len(entry_ids)
