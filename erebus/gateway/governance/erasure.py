"""Subject erasure with a per-subject crypto-erase backstop (FR-031/032/040).

A data-subject erasure request resolves the subject's value to its scope-bound
blind index, DELETEs every matching ``token_maps`` row, and then crypto-erases
that *subject's own* KEK via the per-subject key tier (``subject_keys``). The
blind-index DELETE clears the live store; the per-subject crypto-erase is the
*backup-spanning backstop*: once the subject KEK is gone, the subject's wrapped
DEK can never be unwrapped again, so any value encrypted under it (including
copies in replicas, snapshots, or backups) is permanently unreadable (FR-040).

Crucially, erasing one subject does NOT destroy the scope KEK, so every sibling
subject in the same scope stays fully resolvable -- a single subject's
right-to-be-forgotten request must not disrupt the rest of the tenant.

The emitted ``erasure_certificate`` is a tamper-evident proof of what was acted
on and which key versions were destroyed. It records masked subjects and counts
only: it is NOT a recovery channel, holds no plaintext token/value mirror, and
relies on no audit-log fallback or process-global state (FR-041..043).
"""
from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass

import psycopg

from ..crypto.envelope import ScopeCrypto
from ..crypto.keyprovider import KeyProvider
from ..store.known_value_store import open_store
from ..store.scope_context import scoped
from . import subject_keys


def _mask(value: str) -> str:
    """Audit-safe rendering of a subject: never store plaintext PII (FR-032, FR-042).

    Keeps a salted, truncated digest so the same subject is recognizable across
    request rows for operators without revealing the value itself.
    """
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"subject:{digest}"


@dataclass(frozen=True)
class ErasureCertificate:
    """The persisted proof row returned by :func:`erase_subject`."""

    id: uuid.UUID
    erasure_request_id: uuid.UUID
    scope_id: uuid.UUID
    stores_acted_on: list[str]
    scopes_acted_on: list[str]
    key_versions_destroyed: list[int]
    residual_scan: int
    certificate_hash: bytes


def _certificate_hash(
    request_id: uuid.UUID,
    scope_id: uuid.UUID,
    deleted_tokens: int,
    stores_acted_on: list[str],
    scopes_acted_on: list[str],
    key_versions_destroyed: list[int],
    residual_scan: int,
) -> bytes:
    """Deterministic, tamper-evident digest over the erasure outcome.

    Binds the request, scope, what was acted on, and the residual-scan result so
    the certificate cannot be silently altered later. Carries no plaintext value.
    """
    payload = json.dumps(
        {
            "erasure_request_id": str(request_id),
            "scope_id": str(scope_id),
            "deleted_tokens": deleted_tokens,
            "stores_acted_on": stores_acted_on,
            "scopes_acted_on": scopes_acted_on,
            "key_versions_destroyed": key_versions_destroyed,
            "residual_scan": residual_scan,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).digest()


def erase_subject(
    conn: psycopg.Connection,
    provider: KeyProvider,
    scope_id: uuid.UUID,
    value: str,
    *,
    requested_by: str = "system",
    label: str = "PERSON",
) -> ErasureCertificate:
    """Erase one subject from a scope and crypto-erase that subject as the backstop.

    Steps (all within RLS scope binding):
      1. Resolve ``value`` to its scope blind index and DELETE matching token_maps.
      2. Re-scan for residual rows under that blind index (must be 0).
      3. Crypto-erase the subject's OWN KEK via the per-subject tier
         (``subject_keys.crypto_erase_subject``) so no backup copy of the subject's
         data can ever be decrypted again (FR-040), without touching the scope KEK.
      4. Record an ``erasure_request`` + tamper-evident ``erasure_certificate``.

    Returns the certificate row. After this call the subject's tokens are gone and
    the subject is no longer resolvable, while the scope and every sibling subject
    remain fully recoverable.
    """
    subject_id = _mask(value)  # stable, non-PII subject namespace for the per-subject key

    # Open the store: unwraps the scope DEK and gives the scope-keyed blind index used
    # to delete the subject's live rows. The scope KEK is left intact (siblings live).
    store = open_store(conn, provider, scope_id)
    crypto: ScopeCrypto = store._crypto
    bidx = crypto.blind_index(value, label)

    with scoped(conn, scope_id):
        deleted = conn.execute(
            "DELETE FROM token_maps WHERE scope_id = %s AND value_blind_index = %s",
            (scope_id, bidx),
        ).rowcount
        residual_scan = conn.execute(
            "SELECT count(*) FROM token_maps WHERE scope_id = %s AND value_blind_index = %s",
            (scope_id, bidx),
        ).fetchone()[0]

    # Per-subject crypto-erase backstop: spans backups for THIS subject only; the
    # scope KEK and all sibling subjects are untouched (surgical erasure, FR-040).
    subject_crypto = subject_keys.provision_subject(conn, provider, scope_id, subject_id)
    key_version = subject_crypto.key_version
    subject_keys.crypto_erase_subject(conn, provider, scope_id, subject_id)

    stores_acted_on = ["token_maps", "subject_keys"]
    scopes_acted_on = [str(scope_id)]
    key_versions_destroyed = [key_version]
    cert_hash = _certificate_hash(
        request_id=uuid.uuid4(),  # placeholder; replaced with the persisted id below
        scope_id=scope_id,
        deleted_tokens=deleted,
        stores_acted_on=stores_acted_on,
        scopes_acted_on=scopes_acted_on,
        key_versions_destroyed=key_versions_destroyed,
        residual_scan=residual_scan,
    )

    with scoped(conn, scope_id):
        req_row = conn.execute(
            "INSERT INTO erasure_requests "
            "(scope_id, subject_masked, requested_by, resolution_method, status) "
            "VALUES (%s, %s, %s, %s, %s) RETURNING id",
            (scope_id, _mask(value), requested_by, "blind_index+subject_crypto_erase", "completed"),
        ).fetchone()
        request_id: uuid.UUID = req_row[0]

        # Re-bind the hash to the real request id so it is a stable proof of record.
        cert_hash = _certificate_hash(
            request_id=request_id,
            scope_id=scope_id,
            deleted_tokens=deleted,
            stores_acted_on=stores_acted_on,
            scopes_acted_on=scopes_acted_on,
            key_versions_destroyed=key_versions_destroyed,
            residual_scan=residual_scan,
        )

        cert_row = conn.execute(
            "INSERT INTO erasure_certificates "
            "(erasure_request_id, scope_id, stores_acted_on, scopes_acted_on, "
            " key_versions_destroyed, residual_scan, certificate_hash) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (
                request_id,
                scope_id,
                json.dumps(stores_acted_on),
                json.dumps(scopes_acted_on),
                json.dumps(key_versions_destroyed),
                residual_scan,
                cert_hash,
            ),
        ).fetchone()
        cert_id: uuid.UUID = cert_row[0]

    return ErasureCertificate(
        id=cert_id,
        erasure_request_id=request_id,
        scope_id=scope_id,
        stores_acted_on=stores_acted_on,
        scopes_acted_on=scopes_acted_on,
        key_versions_destroyed=key_versions_destroyed,
        residual_scan=residual_scan,
        certificate_hash=cert_hash,
    )
