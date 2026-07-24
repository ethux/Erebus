"""No-raw-egress attestation + tokenization-escape incidents (FR-003).

Every turn the gateway protects some set of raw values (PII the privacy engine
detected and replaced with placeholders). Before model output leaves the gateway,
``attest`` scans that egress against the raw values it protected this turn: if any
raw value is still present, tokenization let a value escape, so the turn is flagged
as an incident (``escape_detected=True``, ``token_only=False``); otherwise the
egress is certified token-only.

The stored row is deliberately CONTENT-FREE (FR-003): it records only the boolean
verdicts and the *categories* of the escaped values (e.g. ``["PERSON","EMAIL"]``),
never the raw value that escaped. The attestation table is therefore not a plaintext
mirror (FR-041), not a value-recovery channel (FR-042), and holds no process-global
mutable state (FR-043) -- all state lives in Postgres under row-level security, and
every access is wrapped in ``scoped(...)`` so RLS confines it to the caller's scope.
"""
from __future__ import annotations

import json
import uuid
from collections.abc import Iterable, Mapping
from typing import Any

import psycopg

from ..store.scope_context import scoped


def _escaped_categories(
    egress_text: str, known_raw_values: Mapping[str, str] | Iterable[str] | None
) -> list[str]:
    """Return the sorted, de-duplicated categories of raw values still in egress.

    ``known_raw_values`` may be a mapping ``raw_value -> category`` (preferred, so a
    content-free category label can be recorded) or a bare iterable of raw values
    (each then recorded under the generic ``"value"`` category). Empty/blank raw
    values are ignored so they cannot spuriously match. The raw value itself is used
    only transiently for the substring scan and never returned or stored (FR-003).
    """
    if not known_raw_values:
        return []
    if isinstance(known_raw_values, Mapping):
        pairs = known_raw_values.items()
    else:
        pairs = ((v, "value") for v in known_raw_values)
    categories: set[str] = set()
    for raw, category in pairs:
        if not raw:
            continue
        if raw in egress_text:
            categories.add(str(category) if category else "value")
    return sorted(categories)


def attest(
    conn: psycopg.Connection,
    scope_id: uuid.UUID,
    request_id: str | None,
    egress_text: str,
    known_raw_values: Mapping[str, str] | Iterable[str] | None,
) -> dict[str, Any]:
    """Attest one turn's egress as token-only, or flag a tokenization escape (FR-003).

    Scans ``egress_text`` for any of ``known_raw_values`` (the raw values the gateway
    protected this turn). If any is present, the turn is a flagged incident:
    ``escape_detected=True`` and ``token_only=False``, with the *categories* of the
    escaped values recorded. Otherwise the egress is certified ``token_only=True``.

    The persisted row is content-free: it never stores a raw value, only verdicts and
    category labels (FR-003). Returns the stored row.
    """
    categories = _escaped_categories(egress_text, known_raw_values)
    escape_detected = bool(categories)
    token_only = not escape_detected
    with scoped(conn, scope_id):
        row = conn.execute(
            "INSERT INTO egress_attestations "
            "(scope_id, request_id, token_only, escape_detected, escaped_categories) "
            "VALUES (%s, %s, %s, %s, %s::jsonb) "
            "RETURNING id, scope_id, request_id, token_only, escape_detected, "
            "          escaped_categories, ts",
            (scope_id, request_id, token_only, escape_detected, json.dumps(categories)),
        ).fetchone()
    return {
        "id": row[0],
        "scope_id": row[1],
        "request_id": row[2],
        "token_only": row[3],
        "escape_detected": row[4],
        "escaped_categories": row[5],
        "ts": row[6],
    }


def is_escape(row: Mapping[str, Any]) -> bool:
    """Return True iff an attestation row is a flagged tokenization-escape incident."""
    return bool(row["escape_detected"])
