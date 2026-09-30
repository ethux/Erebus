"""Per-scope known-value catalog (T009; FR-009 known-value enforcement).

The generic detector finds well-known PII shapes, but every organization also has
its own values that must never reach a provider: project code names, internal IDs,
unlisted customer names. Admins curate those here. Values are encrypted at rest
under the scope DEK (FR-036); lookup/dedupe runs through a scope-keyed blind index
so equality leaks only within the scope and never across scopes (FR-008/009).
``match`` decrypts a scope's catalog transiently in memory for the request that
already holds that scope's ``ScopeCrypto`` and returns the spans to tokenize, so
no plaintext known value is ever persisted or mirrored (FR-041..043).
"""
from __future__ import annotations

import uuid
from collections.abc import Collection, Iterable, Iterator
from dataclasses import dataclass

import psycopg

from ..cataloging.stop_words import STOP_WORDS
from .connectors.policy import MIN_VALUE_CHARS, clean_value, reject_reason
from .crypto.envelope import ScopeCrypto
from .crypto.keyprovider import KeyProvider
from .known_values import KnownValueMatcher
from .store import catalog_versions
from .store.known_value_store import normalize_label, open_scope_crypto
from .store.scope_context import scoped


class TenantCapExceeded(Exception):
    """A sync would pass the tenant's active known-value cap (the sync fails incomplete)."""

    def __init__(self) -> None:
        super().__init__("tenant known-value cap reached")


@dataclass(frozen=True)
class UpsertResult:
    """Counts of one ``upsert_values`` batch."""

    added: int  # new entries plus retired ones made active again
    seen: int  # entries linked to the source in this sync
    rejected: int  # short, numeric, single-word PERSON, stop-listed or erased values


@dataclass(frozen=True)
class ErasedCounts:
    """Rows removed by ``erase_value``."""

    entries: int
    tokens: int


def _suppressed(conn: psycopg.Connection, scope_id: uuid.UUID, indexes: list[bytes]) -> set[bytes]:
    rows = conn.execute(
        "SELECT value_index FROM catalog_suppressions WHERE scope_id = %s AND value_index = ANY(%s)",
        (scope_id, indexes),
    ).fetchall()
    return {bytes(r[0]) for r in rows}


def add_known_value(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    value: str,
    label: str,
) -> uuid.UUID:
    """Register ``value`` as a manual known value for ``scope_id``; return its row id.

    Test-only caller. The label is normalized as token labels are, so the catalog and
    ``token_maps`` blind indexes agree. Idempotent per (normalized value, label): a
    re-add returns the existing row, re-activates it and marks it manual. A value
    under 3 characters or one that was erased raises ``ValueError``.
    """
    label = normalize_label(label)
    cleaned = clean_value(value)
    if len(cleaned) < MIN_VALUE_CHARS:
        raise ValueError("known value too short")
    bidx = crypto.blind_index(cleaned, label)
    nonce, ct = crypto.encrypt(cleaned.encode("utf-8"))
    with scoped(conn, scope_id):
        if _suppressed(conn, scope_id, [crypto.blind_index(cleaned, "")]):
            raise ValueError("known value was erased")
        row = conn.execute(
            "INSERT INTO catalog_entries "
            "(scope_id, label, value_ciphertext, value_nonce, value_blind_index, key_version, origin) "
            "VALUES (%s, %s, %s, %s, %s, %s, 'manual') "
            "ON CONFLICT (scope_id, value_blind_index) DO UPDATE SET "
            "origin = 'manual', status = 'active', retired_at = NULL "
            "RETURNING id",
            (scope_id, label, ct, nonce, bidx, crypto.key_version),
        ).fetchone()
        catalog_versions.bump(conn, scope_id)
    return row[0]


def upsert_values(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    source_id: uuid.UUID,
    sync_id: uuid.UUID,
    items: Iterable[tuple[str, str]],
    *,
    stop_words: Collection[str] = STOP_WORDS,
    tenant_max: int | None = None,
) -> UpsertResult:
    """Upsert one batch of ``(value, label)`` seen by a source and link each to ``sync_id``.

    One transaction. Rejects what ``policy.reject_reason`` rejects (by default with the
    bundled stop-list) and every value suppressed by an erasure (label-free). An existing entry keeps its origin (manual
    stays manual) and becomes active again. Rows are written in blind-index order, the
    order ``retire_unseen`` locks in, so concurrent syncs cannot deadlock on entries.
    Raises ``TenantCapExceeded`` (batch rolled back) when active entries pass
    ``tenant_max``. The caller bumps the catalog version once the sync is done.
    """
    rejected = 0
    batch: dict[bytes, tuple[str, str]] = {}
    for value, label in items:
        norm = normalize_label(label)
        if reject_reason(value, norm, stop_words=stop_words):
            rejected += 1
            continue
        cleaned = clean_value(value)
        batch.setdefault(crypto.blind_index(cleaned, norm), (cleaned, norm))
    if not batch:
        return UpsertResult(0, 0, rejected)
    free = {bidx: crypto.blind_index(v, "") for bidx, (v, _l) in batch.items()}
    with scoped(conn, scope_id):
        erased = _suppressed(conn, scope_id, sorted(set(free.values())))
        keep = sorted(b for b in batch if free[b] not in erased)
        rejected += len(batch) - len(keep)
        if not keep:
            return UpsertResult(0, 0, rejected)
        retired = {
            bytes(r[0])
            for r in conn.execute(
                "SELECT value_blind_index FROM catalog_entries "
                "WHERE scope_id = %s AND value_blind_index = ANY(%s) AND status = 'retired'",
                (scope_id, keep),
            ).fetchall()
        }
        sealed = [crypto.encrypt(batch[b][0].encode("utf-8")) for b in keep]
        rows = conn.execute(
            "INSERT INTO catalog_entries "
            "(scope_id, label, value_ciphertext, value_nonce, value_blind_index, key_version, origin) "
            "SELECT %s, t.l, t.c, t.n, t.b, %s, 'source' "
            "FROM unnest(%s::text[], %s::bytea[], %s::bytea[], %s::bytea[]) AS t(l, c, n, b) ORDER BY t.b "
            "ON CONFLICT (scope_id, value_blind_index) DO UPDATE SET status = 'active', retired_at = NULL "
            "RETURNING id, value_blind_index, (xmax = 0)",
            (scope_id, crypto.key_version, [batch[b][1] for b in keep], [ct for _n, ct in sealed],
             [n for n, _ct in sealed], keep),
        ).fetchall()
        added = sum(1 for _id, bidx, inserted in rows if inserted or bytes(bidx) in retired)
        conn.execute(
            "INSERT INTO catalog_entry_sources (scope_id, entry_id, source_id, last_seen_sync_id) "
            "SELECT %s, e, %s, %s FROM unnest(%s::uuid[]) AS e ORDER BY e "
            "ON CONFLICT (scope_id, entry_id, source_id) DO UPDATE SET last_seen_sync_id = EXCLUDED.last_seen_sync_id",
            (scope_id, source_id, sync_id, [r[0] for r in rows]),
        )
        if tenant_max is not None and added:
            active = conn.execute(
                "SELECT count(*) FROM catalog_entries WHERE scope_id = %s AND status = 'active'", (scope_id,)
            ).fetchone()[0]
            if active > tenant_max:
                raise TenantCapExceeded()
    return UpsertResult(added, len(rows), rejected)


def _retire_unlinked(conn: psycopg.Connection, scope_id: uuid.UUID, unlink_sql: str, params: tuple) -> int:
    """Run ``unlink_sql`` (a DELETE on links RETURNING entry_id); retire the orphans.

    The candidates are locked first, in blind-index order; the retire then re-reads
    links in a new statement, so a link a concurrent sync committed meanwhile counts.
    Only ``origin = 'source'`` entries retire; manual ones never do.
    """
    locked = conn.execute(
        f"WITH gone AS ({unlink_sql}) "
        "SELECT e.id FROM catalog_entries e JOIN gone g ON g.entry_id = e.id "
        "WHERE e.scope_id = %s AND e.origin = 'source' AND e.status = 'active' "
        "ORDER BY e.value_blind_index FOR UPDATE OF e",
        (*params, scope_id),
    ).fetchall()
    if not locked:
        return 0
    return conn.execute(
        "UPDATE catalog_entries e SET status = 'retired', retired_at = now() "
        "WHERE e.scope_id = %s AND e.id = ANY(%s) AND e.status = 'active' AND NOT EXISTS ("
        "  SELECT 1 FROM catalog_entry_sources l WHERE l.scope_id = e.scope_id AND l.entry_id = e.id)",
        (scope_id, [r[0] for r in locked]),
    ).rowcount


def retire_unseen(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID, sync_id: uuid.UUID) -> int:
    """After a complete full sync: drop the source's links not seen in ``sync_id`` and
    retire the source entries left with no link. Returns how many retired."""
    with scoped(conn, scope_id):
        return _retire_unlinked(
            conn, scope_id,
            "DELETE FROM catalog_entry_sources WHERE scope_id = %s AND source_id = %s "
            "AND last_seen_sync_id <> %s RETURNING entry_id",
            (scope_id, source_id, sync_id),
        )


def unlink_source(conn: psycopg.Connection, scope_id: uuid.UUID, source_id: uuid.UUID) -> int:
    """Drop every link of a source being deleted; retire what only it held."""
    with scoped(conn, scope_id):
        return _retire_unlinked(
            conn, scope_id,
            "DELETE FROM catalog_entry_sources WHERE scope_id = %s AND source_id = %s RETURNING entry_id",
            (scope_id, source_id),
        )


def erase_value(conn: psycopg.Connection, crypto: ScopeCrypto, scope_id: uuid.UUID, value: str) -> ErasedCounts:
    """Erase ``value`` under every label in use: its entries (links cascade) and its
    ``token_maps`` rows (old tokens stay unrestored), then suppress it so no sync
    re-adds it under any label. Bumps the catalog version."""
    cleaned = clean_value(value)
    with scoped(conn, scope_id):
        labels = [
            r[0]
            for r in conn.execute(
                "SELECT label FROM catalog_entries WHERE scope_id = %s "
                "UNION SELECT label FROM token_maps WHERE scope_id = %s",
                (scope_id, scope_id),
            ).fetchall()
        ]
        indexes = [crypto.blind_index(cleaned, label) for label in labels]
        entries = conn.execute(
            "DELETE FROM catalog_entries WHERE scope_id = %s AND value_blind_index = ANY(%s)", (scope_id, indexes)
        ).rowcount
        tokens = conn.execute(
            "DELETE FROM token_maps WHERE scope_id = %s AND value_blind_index = ANY(%s)", (scope_id, indexes)
        ).rowcount
        conn.execute(
            "INSERT INTO catalog_suppressions (scope_id, value_index) VALUES (%s, %s) ON CONFLICT DO NOTHING",
            (scope_id, crypto.blind_index(cleaned, "")),
        )
        catalog_versions.bump(conn, scope_id)
    return ErasedCounts(entries, tokens)


def iter_active_values(
    conn: psycopg.Connection, crypto: ScopeCrypto, scope_id: uuid.UUID, *, batch: int = 5000
) -> Iterator[tuple[str, str]]:
    """Yield ``(value, label)`` of every active entry: manual first, then the oldest.

    That order is the label pick when a value has several labels (the matcher keeps the
    first). One server-side cursor in ``scoped()`` streams ``batch`` rows at a time and
    one cipher decrypts them all, so a 1M-value tenant is never held as rows.
    """
    decrypt = crypto.decryptor()
    with scoped(conn, scope_id), conn.cursor(name="erebus_known_values") as cur:
        cur.execute(
            "SELECT value_nonce, value_ciphertext, label FROM catalog_entries "
            "WHERE scope_id = %s AND status = 'active' "
            "ORDER BY (origin <> 'manual'), created_at, id",
            (scope_id,),
        )
        while rows := cur.fetchmany(batch):
            for nonce, ct, label in rows:
                yield decrypt(bytes(nonce), bytes(ct)).decode("utf-8"), label


def load_matcher(
    conn: psycopg.Connection, provider: KeyProvider, scope_id: uuid.UUID, *, batch: int = 5000
) -> KnownValueMatcher:
    """Build the tenant's matcher from its active entries (raises ``CryptoErased`` or
    ``KeyError`` for an erased or unknown tenant)."""
    crypto = open_scope_crypto(conn, provider, scope_id)
    return KnownValueMatcher.build(iter_active_values(conn, crypto, scope_id, batch=batch))


def match(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    text: str,
) -> list[tuple[int, int, str]]:
    """Return ``(start, end, label)`` spans of every known value occurring in ``text``.

    Matching is case-insensitive, longest-first, and non-overlapping: where two
    known values would cover the same characters the longer one wins, so a
    project name is preferred over a shorter substring of it. The scope catalog
    is decrypted transiently here under the request-held ``ScopeCrypto`` and is
    never written back in plaintext (FR-009/041..043). RLS confines the rows
    loaded to ``scope_id``, so another scope's known values can never match.
    """
    with scoped(conn, scope_id):
        rows = conn.execute(
            "SELECT value_nonce, value_ciphertext, label FROM catalog_entries "
            "WHERE scope_id = %s AND status = 'active'",
            (scope_id,),
        ).fetchall()

    # Decrypt each known value transiently in memory; never persisted.
    known: list[tuple[str, str]] = []
    for nonce, ct, label in rows:
        value = crypto.decrypt(bytes(nonce), bytes(ct)).decode("utf-8")
        if value:
            known.append((value, label))

    haystack = text.casefold()
    # Longest-first so a longer known value claims its span before any substring.
    known.sort(key=lambda kv: len(kv[0]), reverse=True)

    spans: list[tuple[int, int, str]] = []
    taken = [False] * len(text)
    for value, label in known:
        needle = value.casefold()
        n = len(needle)
        if n == 0:
            continue
        start = haystack.find(needle)
        while start != -1:
            end = start + n
            if not any(taken[start:end]):
                spans.append((start, end, label))
                for i in range(start, end):
                    taken[i] = True
            start = haystack.find(needle, start + 1)

    spans.sort(key=lambda s: s[0])
    return spans
