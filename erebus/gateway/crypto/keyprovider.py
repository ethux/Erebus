"""KMS-agnostic key provider (FR-040, FR-048; research R4).

A per-scope key-encryption key (KEK) lives only inside the provider and wraps a
per-scope data-encryption key (DEK); only the wrapped DEK is ever persisted. The
self-hosted appliance uses ``LocalKms`` (a real deployment backs it with an
HSM/Vault); a future managed SaaS swaps in a customer-held-key provider (BYOK)
behind this same interface, so it is a provider swap rather than a redesign.
"""
from __future__ import annotations

import abc
import base64
import binascii
import os
import uuid

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap


class CryptoErased(KeyError):
    """Raised when a scope's key material has been crypto-erased (FR-040)."""


class KeyProvider(abc.ABC):
    """Wrap/unwrap per-scope DEKs without ever exposing the KEK."""

    @abc.abstractmethod
    def generate_dek(self, scope_id: str) -> tuple[bytes, bytes]:
        """Return ``(plaintext_dek, wrapped_dek)``; the DEK is 32 bytes (AES-256)."""

    @abc.abstractmethod
    def unwrap_dek(self, scope_id: str, wrapped_dek: bytes) -> bytes:
        """Return the plaintext DEK; refuse across scope boundaries and after erase."""

    @abc.abstractmethod
    def rotate_kek(self, scope_id: str) -> None:
        """Add a new KEK version for new wraps; prior wrapped DEKs still unwrap (SC-008)."""

    @abc.abstractmethod
    def destroy_kek(self, scope_id: str) -> None:
        """Crypto-erase: every subsequent unwrap for this scope fails forever (FR-040)."""


class LocalKms(KeyProvider):
    """In-process software KMS for unit tests and evaluation only.

    KEKs are held in memory, so they DO NOT survive a process restart; a deployed
    service must use :class:`MasterKeyKms`, which persists each KEK wrapped by an
    operator master key. Each scope's KEK is versioned: rotation prepends a new
    version used for new wraps while older versions stay available, so previously
    wrapped DEKs still unwrap (the "rotate KEK, re-wrap DEK, prior tokens still
    restore" property). Crypto-erase drops all versions and tombstones the scope.
    """

    def __init__(self) -> None:
        self._keks: dict[str, list[bytes]] = {}   # scope_id -> [newest, ..., oldest]
        self._erased: set[str] = set()

    def _current(self, scope_id: str) -> bytes:
        if scope_id in self._erased:
            raise CryptoErased(scope_id)
        versions = self._keks.get(scope_id)
        if not versions:
            versions = [os.urandom(32)]
            self._keks[scope_id] = versions
        return versions[0]

    def generate_dek(self, scope_id: str) -> tuple[bytes, bytes]:
        dek = os.urandom(32)
        return dek, aes_key_wrap(self._current(scope_id), dek)

    def unwrap_dek(self, scope_id: str, wrapped_dek: bytes) -> bytes:
        if scope_id in self._erased:
            raise CryptoErased(scope_id)
        last_err: Exception | None = None
        for kek in self._keks.get(scope_id, []):
            try:
                return aes_key_unwrap(kek, wrapped_dek)
            except Exception as exc:  # wrong KEK version or a foreign scope's wrapped DEK
                last_err = exc
        raise KeyError(f"cannot unwrap DEK for scope {scope_id!r}: {last_err}")

    def rotate_kek(self, scope_id: str) -> None:
        if scope_id in self._erased:
            raise CryptoErased(scope_id)
        self._keks.setdefault(scope_id, [os.urandom(32)]).insert(0, os.urandom(32))

    def destroy_kek(self, scope_id: str) -> None:
        self._keks.pop(scope_id, None)
        self._erased.add(scope_id)


class KeyWrapper(abc.ABC):
    """Seals a per-scope KEK so only the holder of the root secret can unseal it.

    Indirection point for key custody: ``AesKeyWrapper`` uses an operator software
    master key today; an external KMS/HSM wrapper drops in here later (FR-012)
    without changing the tenant model.
    """

    @abc.abstractmethod
    def wrap(self, key: bytes) -> tuple[bytes, bytes]:
        """Return ``(wrapped_key, nonce)``."""

    @abc.abstractmethod
    def unwrap(self, wrapped_key: bytes, nonce: bytes) -> bytes:
        """Return the plaintext key; raise on tamper or wrong root secret."""


class AesKeyWrapper(KeyWrapper):
    """AES-256-GCM wrap of a KEK under an operator-supplied software master key."""

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("master key must be 32 bytes (AES-256)")
        self._aead = AESGCM(master_key)

    def wrap(self, key: bytes) -> tuple[bytes, bytes]:
        nonce = os.urandom(12)
        return self._aead.encrypt(nonce, key, None), nonce

    def unwrap(self, wrapped_key: bytes, nonce: bytes) -> bytes:
        return self._aead.decrypt(nonce, wrapped_key, None)


class MasterKeyKms(KeyProvider):
    """Restart-safe software KMS: per-scope KEKs persisted wrapped by a master key.

    Unlike :class:`LocalKms` (in-memory, test-only), KEKs survive a process restart
    because they live in ``scope_keks`` sealed under the operator master key (supplied
    via env, never stored). The hierarchy is master key -> per-scope KEK (persisted
    wrapped, versioned) -> per-scope DEK (wrapped by the KEK via RFC-3394, exactly as
    ``LocalKms``, so the existing store is unchanged). Crypto-erase overwrites and
    tombstones the wrapped KEK so the scope can never be unwrapped or re-provisioned.

    Owns its own connection pool because the ``KeyProvider`` interface takes no
    connection; each call checks out its own connection, so it is concurrency-safe.
    """

    def __init__(self, dsn: str, master_key_b64: str, *, min_size: int = 1, max_size: int = 4) -> None:
        from psycopg_pool import ConnectionPool  # lazy: keep LocalKms importable without the pool
        try:
            master_key = base64.b64decode(master_key_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("EREBUS_GATEWAY_MASTER_KEY must be valid base64") from exc
        self._wrapper = AesKeyWrapper(master_key)  # raises ValueError unless 32 bytes
        self._pool = ConnectionPool(dsn, min_size=min_size, max_size=max_size, open=True)

    def close(self) -> None:
        self._pool.close()

    def health(self) -> bool:
        """Return True iff the custody store is reachable over the KMS's own pool (FR-012).

        Checks out a pooled connection and runs a bare ``SELECT 1`` against ``scope_keks``,
        the same store ``unwrap_dek`` relies on, so a custody outage is surfaced to
        ``/readyz`` without unwrapping any KEK/DEK or touching wrapped material. Never raises
        and never reads or logs key bytes: any failure returns False so the probe can drain
        the replica rather than take it down or leak a secret.
        """
        try:
            with self._pool.connection() as conn:
                conn.execute("SELECT 1 FROM scope_keks LIMIT 1")
            return True
        except Exception:
            return False

    def _load(self, scope_id: str) -> tuple[list[tuple[int, bytes]], bool]:
        """Return ``([(version, kek) newest-first], erased)`` for the scope."""
        from ..store.scope_context import scoped
        sid = uuid.UUID(str(scope_id))
        with self._pool.connection() as conn, scoped(conn, sid):
            rows = conn.execute(
                "SELECT key_version, wrapped_kek, wrap_nonce, status FROM scope_keks "
                "WHERE scope_id = %s ORDER BY key_version DESC",
                (sid,),
            ).fetchall()
        erased = any(r[3] == "crypto_erased" for r in rows)
        keks = [(r[0], self._wrapper.unwrap(bytes(r[1]), bytes(r[2])))
                for r in rows if r[3] in ("active", "rotated")]
        return keks, erased

    def _insert_kek(self, sid: uuid.UUID, version: int, kek: bytes, status: str = "active") -> None:
        from ..store.scope_context import scoped
        wrapped, nonce = self._wrapper.wrap(kek)
        with self._pool.connection() as conn, scoped(conn, sid):
            conn.execute(
                "INSERT INTO scope_keks (scope_id, key_version, wrapped_kek, wrap_nonce, status) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (scope_id, key_version) DO NOTHING",
                (sid, version, wrapped, nonce, status),
            )

    def generate_dek(self, scope_id: str) -> tuple[bytes, bytes]:
        keks, erased = self._load(scope_id)
        if erased:
            raise CryptoErased(scope_id)
        if not keks:  # first provisioning of this scope: mint and persist a KEK
            self._insert_kek(uuid.UUID(str(scope_id)), 1, os.urandom(32), "active")
            keks, _ = self._load(scope_id)  # re-read the winner (race-safe via ON CONFLICT)
        kek = keks[0][1]
        dek = os.urandom(32)
        return dek, aes_key_wrap(kek, dek)

    def unwrap_dek(self, scope_id: str, wrapped_dek: bytes) -> bytes:
        keks, erased = self._load(scope_id)
        if erased or not keks:
            raise CryptoErased(scope_id)
        last_err: Exception | None = None
        for _version, kek in keks:
            try:
                return aes_key_unwrap(kek, wrapped_dek)
            except Exception as exc:  # wrong KEK version or a foreign scope's wrapped DEK
                last_err = exc
        raise KeyError(f"cannot unwrap DEK for scope {scope_id!r}: {last_err}")

    def rotate_kek(self, scope_id: str) -> None:
        from ..store.scope_context import scoped
        keks, erased = self._load(scope_id)
        if erased:
            raise CryptoErased(scope_id)
        sid = uuid.UUID(str(scope_id))
        next_version = (keks[0][0] + 1) if keks else 1
        wrapped, nonce = self._wrapper.wrap(os.urandom(32))
        with self._pool.connection() as conn, scoped(conn, sid):  # atomic: retire + add
            conn.execute(
                "UPDATE scope_keks SET status='rotated' WHERE scope_id=%s AND status='active'",
                (sid,),
            )
            conn.execute(
                "INSERT INTO scope_keks (scope_id, key_version, wrapped_kek, wrap_nonce, status) "
                "VALUES (%s, %s, %s, %s, 'active') ON CONFLICT (scope_id, key_version) DO NOTHING",
                (sid, next_version, wrapped, nonce),
            )

    def destroy_kek(self, scope_id: str) -> None:
        from ..store.scope_context import scoped
        sid = uuid.UUID(str(scope_id))
        with self._pool.connection() as conn, scoped(conn, sid):
            # Crypto-erase: overwrite the wrapped KEK material and tombstone every
            # version so no subsequent unwrap or re-provisioning can succeed (FR-040).
            updated = conn.execute(
                "UPDATE scope_keks SET status='crypto_erased', wrapped_kek=%s, wrap_nonce=%s "
                "WHERE scope_id=%s",
                (b"", b"", sid),
            ).rowcount
            if updated == 0:  # never provisioned: leave a tombstone so it cannot be re-keyed
                conn.execute(
                    "INSERT INTO scope_keks (scope_id, key_version, wrapped_kek, wrap_nonce, status) "
                    "VALUES (%s, 0, %s, %s, 'crypto_erased') ON CONFLICT (scope_id, key_version) DO NOTHING",
                    (sid, b"", b""),
                )
