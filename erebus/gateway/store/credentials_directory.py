"""Credential -> scope directory for dynamic, restart-free tenant resolution (008 R3).

API credentials are high-entropy random tokens (``egw_`` + ``secrets.token_urlsafe(32)``),
so resolution is an O(1) deterministic lookup keyed by ``sha256(credential)``, UNIQUE-indexed
in ``scope_credentials``. The credential plaintext is never stored: only its hash lands in
Postgres, so the directory is not a secret store (the salt is ``b''`` because the input
already carries full entropy, so a plain SHA-256 is not dictionary-attackable).

This table is the *pre-scope* directory: it is consulted before a scope is known, so it
carries no per-scope RLS and is queried directly. Lookups match only ``status='active'`` so
a revoked credential resolves to nothing (FR-006). Each row carries the privilege it was
issued with (``operator`` or ``tenant``, 010) and :func:`lookup` returns it with the scope.
"""
from __future__ import annotations

import hashlib
import secrets
import uuid
from typing import NamedTuple

import psycopg

from .. import rbac

_CREDENTIAL_PREFIX = "egw_"

# Reserved home scope for operator credentials: scope_id stays NOT NULL and operator
# actions get their own audit chain. Tenant scope keys may not start with '_'.
OPERATOR_SCOPE_KEY = "_operators"


class CredentialRecord(NamedTuple):
    """An active directory row: who the credential is and what it may do."""

    credential_id: uuid.UUID
    scope_id: uuid.UUID
    scope_key: str
    privilege: str


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


def issue(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    scope_key: str,
    *,
    label: str = "",
    privilege: str = rbac.TENANT,
) -> tuple[uuid.UUID, str]:
    """Mint, hash and insert a credential; return ``(credential_id, plaintext)`` ONCE.

    ``privilege`` is fixed at issuance (010): ``tenant`` (the default) or ``operator``.
    """
    if privilege not in (rbac.OPERATOR, rbac.TENANT):
        raise ValueError("privilege must be 'operator' or 'tenant'")
    credential = mint_credential()
    digest = hash_credential(credential)
    with conn.transaction():
        row = conn.execute(
            "INSERT INTO scope_credentials "
            "(credential_hash, credential_salt, scope_id, scope_key, status, label, privilege) "
            "VALUES (%s, %s, %s, %s, 'active', %s, %s) RETURNING id",
            (digest, b"", scope_id, scope_key, label, str(privilege)),
        ).fetchone()
    return row[0], credential


def provision(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    scope_key: str,
    *,
    label: str = "",
    privilege: str = rbac.TENANT,
) -> str:
    """Mint, hash and insert a credential for ``scope_id``; return the plaintext ONCE.

    The returned plaintext is the only time the credential is available: Postgres holds
    only ``credential_hash`` (the plaintext is never stored). The salt is ``b''`` because
    the credential already carries full entropy.
    """
    return issue(conn, scope_id, scope_key, label=label, privilege=privilege)[1]


def lookup(conn: psycopg.Connection, credential: str) -> CredentialRecord | None:
    """Resolve an active credential to its :class:`CredentialRecord` via sha256, else ``None``."""
    if not credential:
        return None
    digest = hash_credential(credential)
    row = conn.execute(
        "SELECT id, scope_id, scope_key, privilege FROM scope_credentials "
        "WHERE credential_hash = %s AND status = 'active'",
        (digest,),
    ).fetchone()
    return CredentialRecord(*row) if row else None


def resolve(
    conn: psycopg.Connection,
    credential: str,
) -> tuple[uuid.UUID, str] | None:
    """Resolve an active credential to ``(scope_id, scope_key)`` via sha256, else ``None``.

    Only ``status='active'`` rows match, so an unknown or revoked credential resolves to
    nothing. No per-scope RLS applies (this is the pre-scope directory), so the row is read
    directly.
    """
    record = lookup(conn, credential)
    return (record.scope_id, record.scope_key) if record is not None else None


def revoke(conn: psycopg.Connection, credential_id: uuid.UUID) -> bool:
    """Flip a credential to ``status='revoked'``; ``True`` if the row existed."""
    with conn.transaction():
        row = conn.execute(
            "UPDATE scope_credentials SET status = 'revoked' "
            "WHERE id = %s AND status = 'active' RETURNING id",
            (credential_id,),
        ).fetchone()
    return row is not None
