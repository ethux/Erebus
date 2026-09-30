"""Postgres connection + idempotent migration runner (sync psycopg3).

Sync because the privacy engine is synchronous and runs in a threadpool on the
gateway (research R2); the FastAPI layer offloads store calls there.
"""
from __future__ import annotations

import os
import re
from collections.abc import Iterable
from importlib import metadata
from pathlib import Path
from typing import Any

import psycopg

_SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schema"
_DEFAULT_DSN = "postgresql:///erebus_gateway"
# Advisory lock key shared by every process that migrates (arbitrary, fixed).
_MIGRATION_LOCK = 0x45524542_4D494752
# Extensions ship schema files through this entry point group; each names a directory.
SCHEMA_GROUP = "erebus.schema"
_EXTENSION_NAME = re.compile(r"[a-z][a-z0-9]*")


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


def extension_schema_dirs(eps: Iterable[Any] | None = None) -> list[tuple[str, Path]]:
    """``(name, directory)`` of every ``erebus.schema`` entry point, in entry point order.

    An entry point loads to a directory path. Its name must be a lowercase word, used
    once, and every ``*.sql`` file in it must start with ``<name>_`` (Pro: ``pro_``), so
    extension files can never shadow core's numbered ones in ``_migrations``. Anything
    else raises ``ValueError``; load errors propagate.
    """
    entries = metadata.entry_points(group=SCHEMA_GROUP) if eps is None else eps
    dirs: list[tuple[str, Path]] = []
    for ep in entries:
        if not _EXTENSION_NAME.fullmatch(ep.name) or any(name == ep.name for name, _ in dirs):
            raise ValueError(f"schema extension name {ep.name!r} is malformed or used twice")
        path = Path(ep.load())
        if not path.is_dir():
            raise ValueError(f"schema extension {ep.name!r}: not a directory")
        if any(not p.name.startswith(f"{ep.name}_") for p in path.glob("*.sql")):
            raise ValueError(f"schema extension {ep.name!r}: every file must start with {ep.name}_")
        dirs.append((ep.name, path))
    return dirs


def migration_files(schema_dir: Path | None = None, extensions: Iterable[Any] | None = None) -> list[Path]:
    """The files to migrate: core's (or only ``schema_dir``'s), then each extension's.

    With no ``schema_dir`` the installed ``erebus.schema`` extensions are included, or
    ``extensions`` (fake entry points) when given; an explicit ``schema_dir`` stands alone
    unless ``extensions`` is passed too.
    """
    files = sorted((schema_dir or _SCHEMA_DIR).glob("*.sql"))
    if schema_dir is None or extensions is not None:
        for _name, path in extension_schema_dirs(extensions):
            files += sorted(path.glob("*.sql"))
    return files


def run_migrations(conn: psycopg.Connection, schema_dir: Path | None = None, *,
                   extensions: Iterable[Any] | None = None) -> list[str]:
    """Apply un-applied *.sql files (see :func:`migration_files`); record each in _migrations.

    One transaction under a transaction-level advisory lock, so gateway replicas and the
    sync worker can start together: a second migrator waits for the first to commit, then
    finds nothing left to apply. On a connection with an open transaction the lock is held
    until the caller commits. Extension files are checked before anything is applied.
    """
    files = migration_files(schema_dir, extensions)
    applied: list[str] = []
    with conn.transaction():
        conn.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK,))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _migrations "
            "(name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())"
        )
        done = {r[0] for r in conn.execute("SELECT name FROM _migrations").fetchall()}
        for path in files:
            if path.name in done:
                continue
            for stmt in _statements(path.read_text()):
                conn.execute(stmt)
            conn.execute("INSERT INTO _migrations (name) VALUES (%s)", (path.name,))
            applied.append(path.name)
    return applied
