# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Maintainer tool for Erebus Pro license keys. Not shipped in the image.

Pass `-` to keep the private key off disk: `keygen --out -` prints JSON to pipe straight
into a secret store, and `issue --key -` reads the PEM from stdin.

  python pro/tools/license_admin.py keygen --out - | <write the JSON to your secret store>
  <read private_key_pem from your secret store> \\
    | python pro/tools/license_admin.py issue --key - --kid 2026-09 \\
        --customer "Acme BV" --features kms,siem --days 365
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PREFIX = "erebus1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _generate() -> tuple[bytes, str]:
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())
    return pem, _b64(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def keygen(out: Path) -> str:
    """Write a new PKCS8 private key to ``out`` (mode 600); return the public key for PUBLIC_KEYS."""
    pem, public = _generate()
    out.write_bytes(pem)
    out.chmod(0o600)
    return public


def issue(private_pem: bytes, *, kid: str, customer: str, features: list[str], days: int,
          now: float | None = None) -> str:
    """Return a signed ``erebus1.<claims>.<signature>`` license key."""
    key = serialization.load_pem_private_key(private_pem, password=None)
    issued = int(time.time() if now is None else now)
    claims = {"kid": kid, "lid": str(uuid.uuid4()), "sub": customer, "features": sorted(features),
              "iat": issued, "exp": issued + days * 86400}
    payload = _b64(json.dumps(claims, separators=(",", ":")).encode())
    signature = _b64(key.sign(f"{PREFIX}.{payload}".encode()))
    return f"{PREFIX}.{payload}.{signature}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    gen = sub.add_parser("keygen")
    gen.add_argument("--out", type=Path, required=True)
    iss = sub.add_parser("issue")
    iss.add_argument("--key", type=Path, required=True)
    iss.add_argument("--kid", required=True)
    iss.add_argument("--customer", required=True)
    iss.add_argument("--features", required=True, help="comma-separated")
    iss.add_argument("--days", type=int, required=True)
    args = parser.parse_args()
    if args.cmd == "keygen":
        if str(args.out) == "-":
            pem, public = _generate()
            print(json.dumps({"private_key_pem": pem.decode(), "public_key": public}))
        else:
            print(keygen(args.out))
    else:
        pem = sys.stdin.buffer.read() if str(args.key) == "-" else args.key.read_bytes()
        features = [f.strip() for f in args.features.split(",") if f.strip()]
        print(issue(pem, kid=args.kid, customer=args.customer, features=features, days=args.days))


if __name__ == "__main__":
    main()
