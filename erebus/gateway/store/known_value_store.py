"""Tenant-scoped token store on Postgres (FR-005/006/036; replaces the local KnownValueDB).

Mints and resolves placeholders for exactly one scope. Values are encrypted under
the scope key; lookups are RLS-filtered to the scope; a value->token blind index
gives idempotent dedupe without storing plaintext. Token recovery is confined to
this encrypted, key-isolated table: no audit-log fallback, no process-global
mirror (FR-041..043).
"""
from __future__ import annotations

import re
import secrets
import uuid

import psycopg

from ..crypto.envelope import ScopeCrypto
from ..crypto.keyprovider import KeyProvider
from .scope_context import scoped

# A minted token is ``[<LABEL>_<n>_<hex6>]`` and the gateway's restore regex
# (tokenizer/streaming_restore ``_TOKEN_RE``) matches the label as ``[A-Z_]+``.
# A label carrying a digit, lowercase, hyphen, or space (e.g. a catalog label
# like "project2" or "Org-Name") would therefore mint a token that restore could
# never match, leaving raw model output un-restored. We normalize the label into
# that exact character class at mint, so every token mint produces is restorable.
# We deliberately do NOT broaden the restore regex toward core's
# ``CATALOG_<NAME>_<hex>`` shape: the gateway mints every token (detector and
# catalog spans alike) through this one ``mint`` and never emits that core form.
_LABEL_NON_CLASS = re.compile(r"[^A-Z_]+")


def _normalize_label(label: str) -> str:
    """Coerce ``label`` into the restore pattern's ``[A-Z_]+`` character class.

    Uppercases, replaces every run of out-of-class characters with a single
    underscore, and trims leading/trailing underscores; falls back to a fixed
    in-class label if nothing survives, so the result is always non-empty and
    matchable by the restore regex.
    """
    collapsed = _LABEL_NON_CLASS.sub("_", label.upper()).strip("_")
    return collapsed or "VALUE"


def provision_scope(conn: psycopg.Connection, provider: KeyProvider, scope_key: str) -> uuid.UUID:
    """Create a scope and its wrapped DEK; return the scope id. Idempotent on scope_key."""
    with conn.transaction():
        row = conn.execute(
            "INSERT INTO scopes (scope_key) VALUES (%s) "
            "ON CONFLICT (scope_key) DO UPDATE SET status = 'active' RETURNING id",
            (scope_key,),
        ).fetchone()
    scope_id: uuid.UUID = row[0]
    _crypto, wrapped = ScopeCrypto.create(provider, str(scope_id))
    with scoped(conn, scope_id):
        conn.execute(
            "INSERT INTO tenant_keys (scope_id, wrapped_dek) VALUES (%s, %s) "
            "ON CONFLICT (scope_id) DO NOTHING",
            (scope_id, wrapped),
        )
    return scope_id


def open_store(conn: psycopg.Connection, provider: KeyProvider, scope_id: uuid.UUID) -> KnownValueStore:
    """Open the store for a provisioned scope (raises if crypto-erased or unknown)."""
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT wrapped_dek, key_version FROM tenant_keys WHERE scope_id = %s",
            (scope_id,),
        ).fetchone()
    if not row:
        raise KeyError(f"scope {scope_id} not provisioned")
    crypto = ScopeCrypto.open(provider, str(scope_id), bytes(row[0]), row[1])
    return KnownValueStore(conn, scope_id, crypto)


class KnownValueStore:
    """Mint/resolve tokens for one scope; the store interface the engine seam will use."""

    def __init__(self, conn: psycopg.Connection, scope_id: uuid.UUID, crypto: ScopeCrypto) -> None:
        self._conn = conn
        self._scope_id = scope_id
        self._crypto = crypto

    def mint(self, value: str, label: str = "PERSON") -> str:
        """Return a stable placeholder for ``value`` in this scope, minting if new."""
        # Normalize the label into the restore regex's [A-Z_]+ class so the minted
        # token is always restorable (an out-of-class catalog/detector label would
        # otherwise produce a token restore could never match). In-class labels
        # like PERSON / INTERNAL_ID are unchanged, so existing dedupe is untouched.
        label = _normalize_label(label)
        bidx = self._crypto.blind_index(value, label)
        with scoped(self._conn, self._scope_id):
            existing = self._conn.execute(
                "SELECT token FROM token_maps WHERE scope_id = %s AND value_blind_index = %s",
                (self._scope_id, bidx),
            ).fetchone()
            if existing:
                return existing[0]
            n = self._conn.execute(
                "SELECT count(*) + 1 FROM token_maps WHERE scope_id = %s AND label = %s",
                (self._scope_id, label),
            ).fetchone()[0]
            token = f"[{label}_{n}_{secrets.token_hex(3)}]"
            nonce, ct = self._crypto.encrypt(value.encode("utf-8"))
            self._conn.execute(
                "INSERT INTO token_maps "
                "(scope_id, token, label, value_nonce, value_ciphertext, value_blind_index, key_version) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (self._scope_id, token, label, nonce, ct, bidx, self._crypto.key_version),
            )
            return token

    def lookup(self, token: str) -> str | None:
        """Resolve a token to its value within this scope, or None (incl. cross-scope)."""
        with scoped(self._conn, self._scope_id):
            row = self._conn.execute(
                "SELECT value_nonce, value_ciphertext FROM token_maps "
                "WHERE scope_id = %s AND token = %s",
                (self._scope_id, token),
            ).fetchone()
        if not row:
            return None
        return self._crypto.decrypt(bytes(row[0]), bytes(row[1])).decode("utf-8")

    def resolve(self, tokens) -> dict[str, str]:
        """Resolve many tokens to their values in ONE RLS-scoped round-trip (FR-008).

        Replaces a per-token ``lookup()`` loop with a single ``token = ANY(%s)``
        set-membership query, so an N-token reveal is one query, not N. The result
        shape is unchanged: a ``{token: value}`` map containing only the tokens that
        exist in this scope (unknown/cross-scope tokens are simply absent), and RLS
        confines the query to this scope exactly as ``lookup`` does.
        """
        wanted = list({t for t in tokens})
        if not wanted:
            return {}
        with scoped(self._conn, self._scope_id):
            rows = self._conn.execute(
                "SELECT token, value_nonce, value_ciphertext FROM token_maps "
                "WHERE scope_id = %s AND token = ANY(%s)",
                (self._scope_id, wanted),
            ).fetchall()
        out: dict[str, str] = {}
        for tok, nonce, ct in rows:
            out[tok] = self._crypto.decrypt(bytes(nonce), bytes(ct)).decode("utf-8")
        return out
