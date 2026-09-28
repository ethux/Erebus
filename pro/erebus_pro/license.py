# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Offline verification of Erebus Pro license keys.

A key is ``erebus1.<claims>.<signature>``: base64url JSON claims, Ed25519-signed over
``erebus1.<claims>``. Only the embedded public keys are needed, so air-gapped
deployments work. License problems never stop the gateway; they switch Pro features off.
Errors never echo the key.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

PREFIX = "erebus1"
GRACE_SECONDS = 14 * 86400

# kid -> base64url raw Ed25519 public key. Rotate by adding a kid; never reuse or remove one
# while licenses signed with it are still live.
PUBLIC_KEYS: dict[str, str] = {
    "2026-09": "T3uIv8BofmhNrXg0m82iJxUT7WV01RmfzkgsRhQ-ULA",  # private half: maintainer's secret store
}


class LicenseError(ValueError):
    """The key is malformed, tampered with, or signed by an unknown key."""


class Status(StrEnum):
    NONE = "none"
    VALID = "valid"
    GRACE = "grace"
    EXPIRED = "expired"
    INVALID = "invalid"


@dataclass(frozen=True)
class License:
    license_id: str
    customer: str
    features: frozenset[str]
    issued_at: int
    expires_at: int


def _b64decode(part: str) -> bytes:
    return base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))


def _claims_to_license(claims: object) -> License:
    if not isinstance(claims, dict):
        raise LicenseError("license key is missing required claims")
    features = claims.get("features")
    if not isinstance(features, list) or not all(isinstance(f, str) for f in features):
        raise LicenseError("license key is missing required claims")
    try:
        return License(license_id=str(claims["lid"]), customer=str(claims["sub"]),
                       features=frozenset(features), issued_at=int(claims["iat"]),
                       expires_at=int(claims["exp"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise LicenseError("license key is missing required claims") from exc


def verify(token: str, public_keys: Mapping[str, str] | None = None) -> License:
    """Return the verified license in ``token`` or raise ``LicenseError``."""
    keys = PUBLIC_KEYS if public_keys is None else public_keys
    parts = token.strip().split(".")
    if len(parts) != 3 or parts[0] != PREFIX:
        raise LicenseError("not an Erebus license key")
    try:
        signature = _b64decode(parts[2])
        claims = json.loads(_b64decode(parts[1]))
    except (binascii.Error, ValueError, RecursionError) as exc:
        raise LicenseError("license key is not decodable") from exc
    kid = claims.get("kid") if isinstance(claims, dict) else None
    if not isinstance(kid, str) or kid not in keys:
        raise LicenseError("license key is signed by an unknown key")
    public = Ed25519PublicKey.from_public_bytes(_b64decode(keys[kid]))
    try:
        public.verify(signature, f"{PREFIX}.{parts[1]}".encode())
    except InvalidSignature as exc:
        raise LicenseError("license key signature is invalid") from exc
    return _claims_to_license(claims)


def status_of(lic: License | None, now: float) -> Status:
    if lic is None:
        return Status.NONE
    if now < lic.expires_at:
        return Status.VALID
    if now < lic.expires_at + GRACE_SECONDS:
        return Status.GRACE
    return Status.EXPIRED


class Entitlements:
    """What this deployment may use now. Status is recomputed per call so expiry needs no restart."""

    def __init__(self, lic: License | None, *, error: str | None = None,
                 clock: Callable[[], float] = time.time) -> None:
        self._lic = lic
        self._error = error
        self._clock = clock

    @property
    def status(self) -> Status:
        if self._error is not None:
            return Status.INVALID
        return status_of(self._lic, self._clock())

    def has(self, feature: str) -> bool:
        return self.status in (Status.VALID, Status.GRACE) and self._lic is not None \
            and feature in self._lic.features

    def public_view(self) -> dict:
        view: dict = {"status": self.status.value, "features": [], "expires_at": None}
        if self._lic is not None:
            view["features"] = sorted(self._lic.features)
            view["expires_at"] = self._lic.expires_at
        if self._error is not None:
            view["error"] = self._error
        return view


def from_env(env: Mapping[str, str] | None = None, *, public_keys: Mapping[str, str] | None = None,
             clock: Callable[[], float] = time.time) -> Entitlements:
    """Load ``EREBUS_LICENSE_KEY`` (or ``EREBUS_LICENSE_FILE``); never raises."""
    env = os.environ if env is None else env
    token = env.get("EREBUS_LICENSE_KEY", "").strip()
    path = env.get("EREBUS_LICENSE_FILE", "").strip()
    if not token and path:
        try:
            # utf-8-sig drops the BOM Notepad adds; UTF-16 (PowerShell's >) or binary is a bad file, not a crash.
            token = Path(path).read_text(encoding="utf-8-sig").strip()
        except OSError as exc:
            return Entitlements(None, error=f"cannot read EREBUS_LICENSE_FILE: {exc.strerror}", clock=clock)
        except ValueError:
            return Entitlements(None, error="EREBUS_LICENSE_FILE is not UTF-8 text", clock=clock)
    if not token:
        return Entitlements(None, clock=clock)
    try:
        return Entitlements(verify(token, public_keys), clock=clock)
    except LicenseError as exc:
        return Entitlements(None, error=str(exc), clock=clock)
