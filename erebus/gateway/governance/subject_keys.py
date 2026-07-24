"""Per-subject DEK sub-tier for surgical, backup-spanning GDPR erasure (T007/FR-031/032/040).

Scope-level crypto-erase (governance/erasure.py) destroys an entire tenant scope's
KEK, which is the right backstop for a whole-scope wipe but too coarse when a single
data subject inside an otherwise-live scope exercises their right to be forgotten.

This module adds a finer tier: every subject gets its OWN DEK, wrapped by a per-subject
KEK that lives only inside the KeyProvider under the composite key id
``f"{scope_id}:{subject_id}"``. Only the wrapped DEK is persisted in ``subject_keys``
(never the raw key). Crypto-erasing one subject destroys only that subject's KEK
(``provider.destroy_kek`` on the composite id), so the subject's data becomes
permanently undecryptable across every replica/snapshot/backup (FR-040) while the
scope and every other subject remain fully recoverable.

Standalone tier: it does NOT modify or depend on governance/erasure.py. It holds no
plaintext subject mirror, no audit-recovery channel, and no process-global mutable
state (FR-041..043): subject resolvability is decided solely by whether the wrapped
DEK still unwraps under the (possibly destroyed) per-subject KEK.
"""
from __future__ import annotations

import uuid

import psycopg

from ..crypto.envelope import ScopeCrypto
from ..crypto.keyprovider import KeyProvider
from ..store.scope_context import scoped


def _composite_key_id(scope_id: uuid.UUID, subject_id: str) -> str:
    """Provider key-namespace for a subject's KEK/DEK: ``"{scope_id}:{subject_id}"``.

    Using a per-subject namespace is what makes erasure surgical: ``destroy_kek`` on
    this id tombstones only this subject in the provider, never the scope's own KEK
    (``str(scope_id)``) nor any sibling subject (FR-040).
    """
    return f"{scope_id}:{subject_id}"


def provision_subject(
    conn: psycopg.Connection,
    provider: KeyProvider,
    scope_id: uuid.UUID,
    subject_id: str,
) -> ScopeCrypto:
    """Create (or reopen) a subject DEK wrapped under its per-subject KEK (FR-031/032).

    Mints a fresh DEK via ``provider.generate_dek`` under the composite key id and
    persists ONLY the wrapped DEK in ``subject_keys`` (raw key never touches the DB).
    Idempotent on ``(scope_id, subject_id)``: a second call reopens the existing
    wrapped DEK rather than re-minting. Returns a ``ScopeCrypto`` bound to the subject.
    """
    key_id = _composite_key_id(scope_id, subject_id)
    with scoped(conn, scope_id):
        existing = conn.execute(
            "SELECT wrapped_dek, key_version FROM subject_keys "
            "WHERE scope_id = %s AND subject_id = %s AND status = 'active'",
            (scope_id, subject_id),
        ).fetchone()
        if existing:
            return ScopeCrypto.open(provider, key_id, bytes(existing[0]), existing[1])

        crypto, wrapped = ScopeCrypto.create(provider, key_id)
        conn.execute(
            "INSERT INTO subject_keys (scope_id, subject_id, wrapped_dek, key_version) "
            "VALUES (%s, %s, %s, %s) "
            "ON CONFLICT (scope_id, subject_id) DO NOTHING",
            (scope_id, subject_id, wrapped, crypto.key_version),
        )
    return crypto


def crypto_erase_subject(
    conn: psycopg.Connection,
    provider: KeyProvider,
    scope_id: uuid.UUID,
    subject_id: str,
) -> None:
    """Crypto-erase ONE subject: destroy its KEK and tombstone the row (FR-040).

    Destroys only the per-subject KEK (``provider.destroy_kek`` on the composite id),
    so this subject's wrapped DEK can never be unwrapped again, rendering every copy
    of the subject's data (including backups/replicas) permanently unreadable. The
    scope's KEK and all sibling subjects are untouched. The row is marked
    ``status='crypto_erased'`` as a tombstone, not a recovery channel (FR-041..043).
    """
    key_id = _composite_key_id(scope_id, subject_id)
    provider.destroy_kek(key_id)
    with scoped(conn, scope_id):
        conn.execute(
            "UPDATE subject_keys SET status = 'crypto_erased' "
            "WHERE scope_id = %s AND subject_id = %s",
            (scope_id, subject_id),
        )


def subject_resolvable(
    conn: psycopg.Connection,
    provider: KeyProvider,
    scope_id: uuid.UUID,
    subject_id: str,
) -> bool:
    """True iff the subject's wrapped DEK still unwraps under its per-subject KEK.

    Resolvability is derived purely from the crypto state: a crypto-erased subject's
    KEK is gone, so ``ScopeCrypto.open`` raises and we return False. No status flag or
    audit log is trusted as the source of truth (FR-041..043).
    """
    key_id = _composite_key_id(scope_id, subject_id)
    with scoped(conn, scope_id):
        row = conn.execute(
            "SELECT wrapped_dek, key_version FROM subject_keys "
            "WHERE scope_id = %s AND subject_id = %s",
            (scope_id, subject_id),
        ).fetchone()
    if not row:
        return False
    try:
        ScopeCrypto.open(provider, key_id, bytes(row[0]), row[1])
    except Exception:  # KEK destroyed (CryptoErased) or otherwise unrecoverable
        return False
    return True
