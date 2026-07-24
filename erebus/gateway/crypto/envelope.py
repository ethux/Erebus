"""App-layer envelope encryption (AES-256-GCM) under a per-scope DEK (FR-036; research R4).

Postgres stores only ciphertext + nonce + key_version; the DEK is wrapped by the
scope KEK in the KeyProvider and never persisted in plaintext, so a stolen disk,
replica, or backup yields only ciphertext (SC-004). ``ScopeCrypto`` binds the
KeyProvider, the HKDF purpose keys, and AES-GCM together for one scope.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .keyprovider import KeyProvider
from .purposekeys import blind_index, derive_keys


def encrypt(k_enc: bytes, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Return ``(nonce, ciphertext)`` where ciphertext carries the GCM tag."""
    nonce = os.urandom(12)
    return nonce, AESGCM(k_enc).encrypt(nonce, plaintext, aad)


def decrypt(k_enc: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    return AESGCM(k_enc).decrypt(nonce, ciphertext, aad)


@dataclass(frozen=True)
class ScopeCrypto:
    """Crypto facade bound to one organization/tenant/group scope."""

    scope_id: str
    key_version: int
    _k_enc: bytes = field(repr=False)   # repr=False: never leak key bytes in logs/tracebacks
    _k_tok: bytes = field(repr=False)

    @classmethod
    def create(cls, provider: KeyProvider, scope_id: str,
               key_version: int = 1) -> tuple[ScopeCrypto, bytes]:
        """Mint a new scope DEK; return ``(ScopeCrypto, wrapped_dek)`` to persist."""
        dek, wrapped = provider.generate_dek(scope_id)
        k_enc, k_tok = derive_keys(dek)
        return cls(scope_id, key_version, k_enc, k_tok), wrapped

    @classmethod
    def open(cls, provider: KeyProvider, scope_id: str, wrapped_dek: bytes,
             key_version: int = 1) -> ScopeCrypto:
        """Reopen an existing scope from its wrapped DEK (raises if crypto-erased)."""
        dek = provider.unwrap_dek(scope_id, wrapped_dek)
        k_enc, k_tok = derive_keys(dek)
        return cls(scope_id, key_version, k_enc, k_tok)

    def encrypt(self, plaintext: bytes, aad: bytes = b"") -> tuple[bytes, bytes]:
        return encrypt(self._k_enc, plaintext, aad)

    def decrypt(self, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
        return decrypt(self._k_enc, nonce, ciphertext, aad)

    def blind_index(self, value: str, label: str = "") -> bytes:
        return blind_index(self._k_tok, value, label)
