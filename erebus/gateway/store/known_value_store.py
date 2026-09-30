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


def normalize_label(label: str) -> str:
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
        return self.mint_many([(value, label)])[(value, label)]

    def mint_many(self, items) -> dict[tuple[str, str], str]:
        """Return a token per ``(value, label)``, minting the missing ones in one go.

        One query when every value has a token; otherwise at most four: the select,
        advisory locks on the misses' blind indexes in sorted order (no deadlock),
        one re-read of the misses plus per-label counts, one insert. The locks make
        concurrent mints of one new value agree on a single row; where duplicates
        predate them, the oldest row wins. Labels are normalized into the restore
        regex's ``[A-Z_]+`` class so every token stays restorable.
        """
        wanted: dict[tuple[str, str], bytes] = {}
        fresh: dict[bytes, tuple[str, str]] = {}
        for value, label in items:
            norm = normalize_label(label)
            bidx = self._crypto.blind_index(value, norm)
            wanted[(value, label)] = bidx
            fresh.setdefault(bidx, (value, norm))
        if not wanted:
            return {}
        indexes = sorted(fresh)
        with scoped(self._conn, self._scope_id):
            found = self._oldest_tokens(indexes)
            misses = [b for b in indexes if b not in found]
            if misses:
                self._conn.execute(
                    "SELECT pg_advisory_xact_lock(h) FROM unnest(%s::bigint[]) AS h",
                    (sorted({int.from_bytes(b[:8], "big", signed=True) for b in misses}),),
                )
                counts = self._reread(misses, sorted({fresh[b][1] for b in misses}), found)
                self._insert_new([b for b in misses if b not in found], fresh, counts, found)
        return {key: found[bidx] for key, bidx in wanted.items()}

    _OLDEST = (
        "SELECT DISTINCT ON (value_blind_index) value_blind_index, token FROM token_maps "
        "WHERE scope_id = %s AND value_blind_index = ANY(%s) ORDER BY value_blind_index, created_at, id"
    )

    def _oldest_tokens(self, indexes: list[bytes]) -> dict[bytes, str]:
        rows = self._conn.execute(self._OLDEST, (self._scope_id, indexes)).fetchall()
        return {bytes(b): tok for b, tok in rows}

    def _reread(self, misses: list[bytes], labels: list[str], found: dict[bytes, str]) -> dict[str, int]:
        """Under the locks: tokens a concurrent mint added meanwhile, and per-label counts."""
        rows = self._conn.execute(
            f"SELECT h.value_blind_index, h.token, NULL::bigint FROM ({self._OLDEST}) h "
            "UNION ALL SELECT NULL, label, count(*) FROM token_maps "
            "WHERE scope_id = %s AND label = ANY(%s) GROUP BY label",
            (self._scope_id, misses, self._scope_id, labels),
        ).fetchall()
        counts: dict[str, int] = {}
        for bidx, text, n in rows:
            if bidx is None:
                counts[text] = n
            else:
                found[bytes(bidx)] = text
        return counts

    def _insert_new(self, new: list[bytes], fresh: dict, counts: dict[str, int], found: dict[bytes, str]) -> None:
        if not new:
            return
        tokens, labels, nonces, cts = [], [], [], []
        for bidx in new:
            value, label = fresh[bidx]
            counts[label] = counts.get(label, 0) + 1
            token = f"[{label}_{counts[label]}_{secrets.token_hex(3)}]"
            nonce, ct = self._crypto.encrypt(value.encode("utf-8"))
            tokens.append(token)
            labels.append(label)
            nonces.append(nonce)
            cts.append(ct)
            found[bidx] = token
        self._conn.execute(
            "INSERT INTO token_maps "
            "(scope_id, token, label, value_nonce, value_ciphertext, value_blind_index, key_version) "
            "SELECT %s, t.tok, t.l, t.n, t.c, t.b, %s "
            "FROM unnest(%s::text[], %s::text[], %s::bytea[], %s::bytea[], %s::bytea[]) AS t(tok, l, n, c, b)",
            (self._scope_id, self._crypto.key_version, tokens, labels, nonces, cts, new),
        )

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
