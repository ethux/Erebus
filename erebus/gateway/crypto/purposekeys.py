"""Per-scope purpose keys derived from one scope DEK (FR-006/008/009; research R4).

From a single scope DEK, HKDF derives two purpose keys so one secret governs both
confidentiality and tokenization and a single destroy kills both:

  K_enc  AES-256-GCM key that encrypts stored values at rest (FR-036)
  K_tok  HMAC key for a scope-bound, non-correlatable blind lookup handle (FR-008/009)

Pure functions over bytes; no module-global state.
"""
from __future__ import annotations

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_ENC_INFO = b"erebus/gateway/enc/v1"
_TOK_INFO = b"erebus/gateway/tok/v1"


def _derive(dek: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(dek)


def derive_keys(dek: bytes) -> tuple[bytes, bytes]:
    """Return ``(k_enc, k_tok)`` for a scope DEK."""
    return _derive(dek, _ENC_INFO), _derive(dek, _TOK_INFO)


def normalize_value(value: str) -> str:
    """Case/whitespace-folded form so casing and spacing variants share a blind index."""
    return " ".join(value.split()).casefold()


def blind_index(k_tok: bytes, value: str, label: str = "") -> bytes:
    """Deterministic, scope-keyed handle for value->token dedupe and subject resolution.

    Leaks equality WITHIN a scope by design (it is the lookup index) but is
    non-correlatable across scopes because ``k_tok`` differs per scope (FR-008/009).
    """
    mac = hmac.HMAC(k_tok, hashes.SHA256())
    mac.update(normalize_value(value).encode("utf-8"))
    mac.update(b"\x00")
    mac.update(label.encode("utf-8"))
    return mac.finalize()
