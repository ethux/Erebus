"""Shared gateway test harness (T003) for the enterprise server gateway (specs/007).

This is a *test utility*, intentionally living under ``tests/gateway/`` and not
under ``erebus/`` so it never ships in the gateway package. It bundles the
boilerplate every DB-backed gateway test repeats: standing up a fresh database
with all gateway migrations applied, provisioning a scope, building a
deterministic fixture detector, and a capturing stub provider, all on top of the
real ``erebus.gateway`` store / crypto / tenancy modules (no re-implementations,
no plaintext mirror, no process-global mutable state; FR-041..043).

sys.path bootstrap
------------------
There is no ``tests/gateway/__init__.py`` (the gateway tests are run as scripts,
not a package), so a test importing this harness must put both the repo root and
its own directory on ``sys.path`` before importing it, e.g.::

    import os, sys
    _HERE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.join(_HERE, "..", ".."))  # repo root -> erebus.*
    sys.path.insert(0, _HERE)                              # this dir   -> helpers
    from helpers import fresh_db, provision, fake_detector, StubProvider

``fresh_db`` itself performs the repo-root bootstrap defensively so it works even
if a caller forgets it.
"""
from __future__ import annotations

import os
import subprocess
import sys
import uuid
from pathlib import Path

import psycopg

# Defensive repo-root bootstrap so ``erebus.gateway.*`` imports resolve even when
# a caller imported this module without first extending sys.path.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from erebus.gateway.crypto.keyprovider import KeyProvider  # noqa: E402
from erebus.gateway.store import db  # noqa: E402
from erebus.gateway.store.known_value_store import (  # noqa: E402
    KnownValueStore,
    open_store,
    provision_scope,
)

# Tolerated when re-applying schema objects a prior run already created.
_DUPLICATE = (psycopg.errors.DuplicateObject, psycopg.errors.DuplicateTable)


def fresh_db(name: str) -> psycopg.Connection:
    """Return a connection to a fresh ``name`` DB with all gateway migrations applied.

    ``createdb`` is best-effort (an "already exists" is fine), then
    ``erebus.gateway.store.db.run_migrations`` applies the *entire* gateway schema
    directory in name order. ``scopes`` is then TRUNCATEd CASCADE so every tenant
    table starts empty; the whole routine is idempotent and tolerant of being
    re-run against a database left over from an earlier test (FR-005/036).

    The DSN honours ``EREBUS_PG_DSN`` (so a CI server can override it), defaulting
    to a local ``postgresql:///<name>`` socket connection.
    """
    subprocess.run(["createdb", name], capture_output=True)  # ignore "already exists"
    dsn = os.environ.get("EREBUS_PG_DSN", f"postgresql:///{name}")
    conn = psycopg.connect(dsn)
    conn.autocommit = False
    # run_migrations is idempotent (it records applied files in _migrations); if a
    # half-applied object from an aborted run trips a duplicate, fall back to
    # applying statement-by-statement, each in its own savepoint.
    try:
        db.run_migrations(conn)
    except _DUPLICATE:
        conn.rollback()
        _apply_all_tolerant(conn)
    with conn.transaction():
        conn.execute("TRUNCATE scopes CASCADE")
    return conn


def _apply_all_tolerant(conn: psycopg.Connection) -> None:
    """Apply every gateway migration statement, tolerating already-present objects."""
    schema_dir = _REPO_ROOT / "erebus" / "gateway" / "schema"
    for path in sorted(schema_dir.glob("*.sql")):
        for stmt in db._statements(path.read_text()):
            try:
                with conn.transaction():
                    conn.execute(stmt)
            except _DUPLICATE:
                pass  # object already exists from a prior run


def provision(conn: psycopg.Connection, kms: KeyProvider, scope_key: str) -> uuid.UUID:
    """Provision a scope (scope row + wrapped DEK) and return its id (FR-005/036).

    A thin wrapper over ``known_value_store.provision_scope`` so tests do not import
    the store directly just to stand up a tenant.
    """
    return provision_scope(conn, kms, scope_key)


def open_scope_store(
    conn: psycopg.Connection, kms: KeyProvider, scope_id: uuid.UUID
) -> KnownValueStore:
    """Open the tenant-scoped token store for an already-provisioned scope."""
    return open_store(conn, kms, scope_id)


def fake_detector(needles):
    """Build a deterministic detector callable from ``(value, label)`` fixtures.

    Returns a ``text -> list[(start, end, label)]`` callable matching the gateway
    ``Detector`` seam: it finds every occurrence of each needle so tokenization is
    repeatable in tests without loading a real PII model. Example::

        detector = fake_detector([("John Smith", "PERSON"), ("john@corp.com", "EMAIL")])

    Spans are returned sorted by start offset; the tokenizer drops overlaps itself.
    """
    pairs = [(str(value), str(label)) for value, label in needles]

    def detect(text: str):
        spans: list[tuple[int, int, str]] = []
        for value, label in pairs:
            if not value:
                continue
            start = text.find(value)
            while start != -1:
                spans.append((start, start + len(value), label))
                start = text.find(value, start + len(value))
        spans.sort(key=lambda s: s[0])
        return spans

    return detect


class StubProvider:
    """Async stub upstream that captures egress and echoes content back.

    Stands in for the real model provider on the gateway request path so a test can
    assert what actually left the gateway (token-only egress, FR-001) and that the
    restore step rehydrates the response. Every payload forwarded to it is appended
    to :attr:`egress`; its reply echoes the last user message in the OpenAI
    chat-completions response shape so the gateway's restore path has tokens to
    rehydrate.
    """

    def __init__(self) -> None:
        self.egress: list[dict] = []

    async def __call__(self, payload: dict) -> dict:
        self.egress.append(payload)
        messages = payload.get("messages", [])
        last = messages[-1].get("content", "") if messages else ""
        return {
            "choices": [
                {"message": {"role": "assistant", "content": "Re: " + str(last)}}
            ]
        }
