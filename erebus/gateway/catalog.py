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

import psycopg

from .crypto.envelope import ScopeCrypto
from .store.scope_context import scoped


def add_known_value(
    conn: psycopg.Connection,
    crypto: ScopeCrypto,
    scope_id: uuid.UUID,
    value: str,
    label: str,
) -> uuid.UUID:
    """Register ``value`` as a known value for ``scope_id``; return its row id.

    Encrypts ``value`` under the scope key and indexes it by a scope-keyed blind
    index, so it is idempotent: re-adding the same value (any casing/whitespace
    variant, since the blind index normalizes) returns the existing row's id
    rather than duplicating it (FR-009/036).
    """
    bidx = crypto.blind_index(value, label)
    nonce, ct = crypto.encrypt(value.encode("utf-8"))
    with scoped(conn, scope_id):
        row = conn.execute(
            "INSERT INTO catalog_entries "
            "(scope_id, label, value_ciphertext, value_nonce, value_blind_index, key_version) "
            "VALUES (%s, %s, %s, %s, %s, %s) "
            "ON CONFLICT (scope_id, value_blind_index) DO UPDATE SET label = EXCLUDED.label "
            "RETURNING id",
            (scope_id, label, ct, nonce, bidx, crypto.key_version),
        ).fetchone()
    return row[0]


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
            "WHERE scope_id = %s",
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
