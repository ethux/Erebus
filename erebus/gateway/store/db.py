"""Postgres connection + idempotent migration runner (sync psycopg3).

Sync because the privacy engine is synchronous and runs in a threadpool on the
gateway (research R2); the FastAPI layer offloads store calls there.
"""
from __future__ import annotations

import os
from pathlib import Path

import psycopg

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"
_DEFAULT_DSN = "postgresql:///erebus_gateway"


def connect(dsn: str | None = None) -> psycopg.Connection:
    return psycopg.connect(dsn or os.environ.get("EREBUS_PG_DSN", _DEFAULT_DSN))


def _statements(sql: str) -> list[str]:
    """Split a controlled migration file into individual statements.

    Strips ``--`` line comments first (a comment may contain a semicolon), then
    splits on ``;``. The migration SQL is hand-written with no dollar-quoted
    bodies or string literals containing ``--``/``;``, so this is safe here.
    """
    stripped = []
    for line in sql.splitlines():
        idx = line.find("--")
        stripped.append(line if idx == -1 else line[:idx])
    return [s.strip() for s in "\n".join(stripped).split(";") if s.strip()]


def run_migrations(conn: psycopg.Connection, schema_dir: Path | None = None) -> list[str]:
    """Apply un-applied *.sql files in name order; record each in _migrations."""
    schema_dir = schema_dir or _SCHEMA_DIR
    with conn.transaction():
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _migrations "
            "(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
    done = {r[0] for r in conn.execute("SELECT name FROM _migrations").fetchall()}
    applied: list[str] = []
    for path in sorted(schema_dir.glob("*.sql")):
        if path.name in done:
            continue
        with conn.transaction():
            for stmt in _statements(path.read_text()):
                conn.execute(stmt)
            conn.execute("INSERT INTO _migrations (name) VALUES (%s)", (path.name,))
        applied.append(path.name)
    return applied
