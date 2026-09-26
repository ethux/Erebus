"""Credential -> scope directory for dynamic, restart-free tenant resolution (008 R3).

API credentials are high-entropy random tokens (``egw_`` + ``secrets.token_urlsafe(32)``),
so resolution is an O(1) deterministic lookup keyed by ``sha256(credential)``, UNIQUE-indexed
in ``scope_credentials``. The credential plaintext is never stored: only its hash lands in
Postgres, so the directory is not a secret store (the salt is ``b''`` because the input
already carries full entropy, so a plain SHA-256 is not dictionary-attackable).

This table is the *pre-scope* directory: it is consulted before a scope is known, so it
carries no per-scope RLS and is queried directly. Lookups match only ``status='active'`` so
a revoked credential resolves to nothing (FR-006).
"""
from __future__ import annotations

import hashlib
import secrets
import uuid

import psycopg

_CREDENTIAL_PREFIX = "egw_"


def mint_credential() -> str:
    """Return a fresh high-entropy API credential (``egw_`` + 256 bits url-safe)."""
    return _CREDENTIAL_PREFIX + secrets.token_urlsafe(32)


def hash_credential(credential: str) -> bytes:
    """Deterministic ``sha256`` of the credential for O(1) lookup.

    No keyed hash (pepper): the credential is a high-entropy random token, so a plain
    SHA-256 is not dictionary-attackable. A low-entropy credential type, if ever added,
    would reintroduce a keyed hash deliberately.
    """
    return hashlib.sha256(credential.encode("utf-8")).digest()


def provision(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    scope_key: str,
    *,
    label: str = "",
) -> str:
    """Mint, hash and insert a credential for ``scope_id``; return the plaintext ONCE.

    The returned plaintext is the only time the credential is available: Postgres holds
    only ``credential_hash`` (the plaintext is never stored). The salt is ``b''`` because
    the credential already carries full entropy.
    """
    credential = mint_credential()
    digest = hash_credential(credential)
    with conn.transaction():
        conn.execute(
            "INSERT INTO scope_credentials "
            "(credential_hash, credential_salt, scope_id, scope_key, status, label) "
            "VALUES (%s, %s, %s, %s, 'active', %s)",
            (digest, b"", scope_id, scope_key, label),
        )
    return credential


def resolve(
    conn: psycopg.Connection,
    credential: str,
) -> tuple[uuid.UUID, str] | None:
    """Resolve an active credential to ``(scope_id, scope_key)`` via sha256, else ``None``.

    Only ``status='active'`` rows match, so an unknown or revoked credential resolves to
    nothing. No per-scope RLS applies (this is the pre-scope directory), so the row is read
    directly.
    """
    if not credential:
        return None
    digest = hash_credential(credential)
    row = conn.execute(
        "SELECT scope_id, scope_key FROM scope_credentials "
        "WHERE credential_hash = %s AND status = 'active'",
        (digest,),
    ).fetchone()
    if not row:
        return None
    return row[0], row[1]


def revoke(conn: psycopg.Connection, credential_id: uuid.UUID) -> bool:
    """Flip a credential to ``status='revoked'``; ``True`` if the row existed."""
    with conn.transaction():
        row = conn.execute(
            "UPDATE scope_credentials SET status = 'revoked' "
            "WHERE id = %s AND status = 'active' RETURNING id",
            (credential_id,),
        ).fetchone()
    return row is not None
