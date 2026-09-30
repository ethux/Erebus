"""Data sources of a tenant (spec 015 "Data model": ``sources``).

Credentials are sealed with the tenant key (``ScopeCrypto``, AES-GCM) under an AAD bound
to the source id, so a ciphertext copied onto another source row does not open. The
gateway only seals (create, PATCH replaces the blob whole); ``read_secrets`` is for the
sync worker and for writing back rotated tokens. ``SourceInfo`` carries no secret.
Errors are fixed text: nothing here echoes a credential or a database message.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from .. import catalog
from ..crypto.envelope import ScopeCrypto
from ..store import catalog_versions
from ..store.scope_context import scoped

STATUSES = ("active", "paused", "needs_attention")
_AAD_PREFIX = b"erebus/source-secrets/v1:"
_COLUMNS = (
    "id, scope_id, name, connector_type, settings, credentials_expire_at, cursor, status, "
    "max_values, created_at, updated_at, pending_job"
)
_UNSET: Any = object()


class SourceBusy(Exception):
    """The source has a running sync job (the API answers 409)."""

    def __init__(self) -> None:
        super().__init__("a sync job is running for this source")


class SecretsUnreadable(Exception):
    """Stored credentials do not open under this tenant key and source id."""

    def __init__(self) -> None:
        super().__init__("source credentials cannot be read")


@dataclass(frozen=True)
class SourceInfo:
    """A source row without its credentials."""

    id: uuid.UUID
    scope_id: uuid.UUID
    name: str
    connector_type: str
    settings: dict
    credentials_expire_at: datetime | None
    cursor: dict
    status: str
    max_values: int
    created_at: datetime
    updated_at: datetime
    pending_job: str | None = None  # owed once the active job ends or the source resumes


def _aad(source_id: uuid.UUID) -> bytes:
    return _AAD_PREFIX + source_id.bytes


def seal_secrets(crypto: ScopeCrypto, source_id: uuid.UUID, secrets: dict) -> tuple[bytes, bytes]:
    """Return ``(nonce, ciphertext)`` of ``secrets`` bound to ``source_id``."""
    if not isinstance(secrets, dict):
        raise ValueError("source credentials must be an object")
    plain = json.dumps(secrets, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return crypto.encrypt(plain, aad=_aad(source_id))


def open_secrets(crypto: ScopeCrypto, source_id: uuid.UUID, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt a sealed blob; raises ``InvalidTag`` for another source id or key."""
    return crypto.decrypt(nonce, ciphertext, aad=_aad(source_id))


def create_source(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    *,
    name: str,
    connector_type: str,
    settings: dict,
    secrets: dict,
    credentials_expire_at: datetime | None = None,
    max_values: int | None = None,
) -> uuid.UUID:
    """Insert a source with sealed credentials; return its id."""
    source_id = uuid.uuid4()
    nonce, ct = seal_secrets(crypto, source_id, secrets)
    with scoped(conn, scope_id):
        conn.execute(
            "INSERT INTO sources (id, scope_id, name, connector_type, settings, secrets_ciphertext, "
            "secrets_nonce, secrets_key_version, credentials_expire_at, max_values) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, COALESCE(%s, 1000000))",
            (source_id, scope_id, name, connector_type, Jsonb(settings), ct, nonce, crypto.key_version,
             credentials_expire_at, max_values),
        )
    return source_id


def _info(row) -> SourceInfo:
    return SourceInfo(*row[:4], dict(row[4] or {}), row[5], dict(row[6] or {}), *row[7:])


def get_source(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID) -> SourceInfo | None:
    """The source, or ``None`` when it is not in this scope."""
    with scoped(conn, scope_id):
        row = conn.execute(
            f"SELECT {_COLUMNS} FROM sources WHERE scope_id = %s AND id = %s", (scope_id, source_id)
        ).fetchone()
    return _info(row) if row else None


def list_sources(conn: psycopg.Connection, scope_id: uuid.UUID) -> list[SourceInfo]:
    """Every source of the scope, oldest first."""
    with scoped(conn, scope_id):
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM sources WHERE scope_id = %s ORDER BY created_at, id", (scope_id,)
        ).fetchall()
    return [_info(r) for r in rows]


def update_source(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    source_id: uuid.UUID,
    *,
    name: str | None = None,
    settings: dict | None = None,
    secrets: dict | None = None,
    status: str | None = None,
    credentials_expire_at: Any = _UNSET,
    max_values: int | None = None,
) -> bool:
    """Change the given fields (credentials are replaced whole); ``False`` if not found."""
    sets: list[str] = []
    params: list[Any] = []
    if name is not None:
        sets.append("name = %s")
        params.append(name)
    if settings is not None:
        sets.append("settings = %s")
        params.append(Jsonb(settings))
    if secrets is not None:
        nonce, ct = seal_secrets(crypto, source_id, secrets)
        sets.append("secrets_ciphertext = %s, secrets_nonce = %s, secrets_key_version = %s")
        params += [ct, nonce, crypto.key_version]
    if status is not None:
        if status not in STATUSES:
            raise ValueError("unknown source status")
        sets.append("status = %s")
        params.append(status)
    if credentials_expire_at is not _UNSET:
        sets.append("credentials_expire_at = %s")
        params.append(credentials_expire_at)
    if max_values is not None:
        sets.append("max_values = %s")
        params.append(max_values)
    sets.append("updated_at = now()")
    with scoped(conn, scope_id):
        row = conn.execute(
            f"UPDATE sources SET {', '.join(sets)} WHERE scope_id = %s AND id = %s RETURNING 1",
            (*params, scope_id, source_id),
        ).fetchone()
    return row is not None


def read_secrets(conn: psycopg.Connection, crypto: ScopeCrypto, scope_id: uuid.UUID, source_id: uuid.UUID) -> dict:
    """Decrypt a source's credentials (sync worker only).

    Raises ``KeyError`` for a source outside this scope and ``SecretsUnreadable`` when
    the blob does not open (other key version, tampered, or moved from another row).
    """
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT secrets_nonce, secrets_ciphertext, secrets_key_version FROM sources "
            "WHERE scope_id = %s AND id = %s",
            (scope_id, source_id),
        ).fetchone()
    if row is None:
        raise KeyError("source not found")
    if row[2] != crypto.key_version:
        raise SecretsUnreadable()
    try:
        return json.loads(open_secrets(crypto, source_id, bytes(row[0]), bytes(row[1])))
    except Exception:
        raise SecretsUnreadable() from None


def set_cursor(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID, cursor: dict) -> bool:
    """Store the incremental cursor (an opaque string per collection)."""
    with scoped(conn, scope_id):
        row = conn.execute(
            "UPDATE sources SET cursor = %s, updated_at = now() WHERE scope_id = %s AND id = %s RETURNING 1",
            (Jsonb(cursor), scope_id, source_id),
        ).fetchone()
    return row is not None


def delete_source(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID) -> int | None:
    """Remove a source and retire the entries only it held; return how many retired.

    ``None`` when the source is not in this scope; ``SourceBusy`` while a job runs. One
    transaction locks the source's queued jobs first, so no worker claims one meanwhile
    (claims skip locked rows), then cascades the delete and bumps the catalog version.
    """
    with scoped(conn, scope_id):
        found = conn.execute(
            "SELECT 1 FROM sources WHERE scope_id = %s AND id = %s FOR UPDATE", (scope_id, source_id)
        ).fetchone()
        if found is None:
            return None
        active = conn.execute(
            "SELECT status FROM sync_jobs WHERE scope_id = %s AND source_id = %s "
            "AND status IN ('queued', 'running') FOR UPDATE",
            (scope_id, source_id),
        ).fetchall()
        if any(r[0] == "running" for r in active):
            raise SourceBusy()
        retired = catalog.unlink_source(conn, scope_id, source_id)
        conn.execute("DELETE FROM sources WHERE scope_id = %s AND id = %s", (scope_id, source_id))
        catalog_versions.bump(conn, scope_id)
    return retired
