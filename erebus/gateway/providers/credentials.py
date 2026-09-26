"""Centralized provider credentials + approved egress routes (FR-020/021/022).

Provider API keys are held centrally and encrypted at rest under the per-scope DEK
via :class:`~erebus.gateway.crypto.envelope.ScopeCrypto` (ciphertext + nonce +
key_version stored, never plaintext; FR-020). Egress is gated by an explicit
allowlist of approved routes: :func:`egress_allowed` returns ``True`` only when an
approved route exists for the scope/provider, and :func:`select_route` returns the
highest-priority approved route or ``None`` (FR-021/022). All reads and writes run
inside :func:`~erebus.gateway.store.scope_context.scoped` so RLS confines them to
the scope; no plaintext credential is ever mirrored or logged (FR-041..043).
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import psycopg

from ..crypto.envelope import ScopeCrypto
from ..store.scope_context import scoped


@dataclass(frozen=True)
class ProviderRoute:
    """An approved (or pending) upstream egress target for one scope/provider."""

    id: uuid.UUID
    scope_id: uuid.UUID
    provider: str
    base_url: str
    model_allowlist: list[str]
    approved: bool
    residency_region: str | None
    priority: int


def store_credential(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    provider: str,
    secret: str,
) -> uuid.UUID:
    """Encrypt and persist (or replace) the credential for ``provider`` in this scope.

    The plaintext secret is encrypted under the scope DEK; only ciphertext + nonce +
    key_version land in Postgres (FR-020). Returns the credential row id.
    """
    nonce, ct = crypto.encrypt(secret.encode("utf-8"))
    with scoped(conn, scope_id):
        row = conn.execute(
            "INSERT INTO provider_credentials "
            "(scope_id, provider, credential_ciphertext, value_nonce, key_version) "
            "VALUES (%s, %s, %s, %s, %s) "
            "ON CONFLICT (scope_id, provider) DO UPDATE SET "
            "credential_ciphertext = EXCLUDED.credential_ciphertext, "
            "value_nonce = EXCLUDED.value_nonce, "
            "key_version = EXCLUDED.key_version, "
            "rotated_at = now() "
            "RETURNING id",
            (scope_id, provider, ct, nonce, crypto.key_version),
        ).fetchone()
    return row[0]


def get_credential(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    provider: str,
) -> str | None:
    """Decrypt and return the stored credential, or ``None`` if none is set."""
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT value_nonce, credential_ciphertext FROM provider_credentials "
            "WHERE scope_id = %s AND provider = %s",
            (scope_id, provider),
        ).fetchone()
    if not row:
        return None
    return crypto.decrypt(bytes(row[0]), bytes(row[1])).decode("utf-8")


def rotate_credential(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    provider: str,
    secret: str,
) -> uuid.UUID:
    """Replace the credential with a freshly encrypted ``secret`` (re-encrypts at rest).

    Re-uses :func:`store_credential`, whose upsert refreshes the ciphertext, nonce and
    ``rotated_at`` in place.
    """
    return store_credential(conn, crypto, scope_id, provider, secret)


def add_route(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    provider: str,
    base_url: str,
    model_allowlist: list[str] | None = None,
    *,
    approved: bool = False,
    residency_region: str | None = None,
    priority: int = 0,
) -> uuid.UUID:
    """Register an egress route for ``provider``; unapproved by default (FR-021/022)."""
    allowlist = json.dumps(list(model_allowlist or []))
    with scoped(conn, scope_id):
        row = conn.execute(
            "INSERT INTO provider_routes "
            "(scope_id, provider, base_url, model_allowlist, approved, residency_region, priority) "
            "VALUES (%s, %s, %s, %s::jsonb, %s, %s, %s) "
            "ON CONFLICT (scope_id, provider, base_url) DO UPDATE SET "
            "model_allowlist = EXCLUDED.model_allowlist, "
            "approved = EXCLUDED.approved, "
            "residency_region = EXCLUDED.residency_region, "
            "priority = EXCLUDED.priority "
            "RETURNING id",
            (scope_id, provider, base_url, allowlist, approved, residency_region, priority),
        ).fetchone()
    return row[0]


def approve_route(conn: psycopg.Connection, scope_id: uuid.UUID, route_id: uuid.UUID) -> bool:
    """Mark a route approved so egress through it is allowed; ``True`` if it existed."""
    with scoped(conn, scope_id):
        row = conn.execute(
            "UPDATE provider_routes SET approved = true "
            "WHERE scope_id = %s AND id = %s RETURNING id",
            (scope_id, route_id),
        ).fetchone()
    return row is not None


def select_route(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    provider: str,
) -> ProviderRoute | None:
    """Return the highest-priority approved route for the provider, or ``None`` (FR-021)."""
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT id, scope_id, provider, base_url, model_allowlist, approved, "
            "residency_region, priority FROM provider_routes "
            "WHERE scope_id = %s AND provider = %s AND approved = true "
            "ORDER BY priority DESC, created_at ASC LIMIT 1",
            (scope_id, provider),
        ).fetchone()
    if not row:
        return None
    return ProviderRoute(
        id=row[0],
        scope_id=row[1],
        provider=row[2],
        base_url=row[3],
        model_allowlist=list(row[4] or []),
        approved=row[5],
        residency_region=row[6],
        priority=row[7],
    )


def egress_allowed(conn: psycopg.Connection, scope_id: uuid.UUID, provider: str) -> bool:
    """``True`` iff an approved route exists for the scope/provider (FR-022)."""
    return select_route(conn, scope_id, provider) is not None
