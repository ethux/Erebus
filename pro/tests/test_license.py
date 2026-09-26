# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Offline license verification: format, signature, kid, expiry/grace, env loading."""
import base64
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

from cryptography.hazmat.primitives import serialization
from erebus_pro.license import GRACE_SECONDS, LicenseError, Status, from_env, status_of, verify
from license_admin import _b64, issue, keygen

_passed = 0
NOW = 1_800_000_000


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _raises(token, keys, needle):
    try:
        verify(token, keys)
    except LicenseError as exc:
        return needle in str(exc) and token.strip() not in str(exc)
    return False


def main():
    tmp = Path(tempfile.mkdtemp())
    pub = keygen(tmp / "k")
    other_pub = keygen(tmp / "other")
    pem = (tmp / "k").read_bytes()
    keys = {"t1": pub}
    token = issue(pem, kid="t1", customer="Acme BV", features=["kms", "siem"], days=30, now=NOW)

    lic = verify(token, keys)
    check("valid key verifies", lic.customer == "Acme BV" and lic.features == frozenset({"kms", "siem"}))
    check("expiry is iat + days", lic.expires_at == NOW + 30 * 86400)
    check("trailing newline and spaces are tolerated", verify(f"  {token}\n", keys) == lic)

    prefix, payload, sig = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims["features"].append("everything")
    forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    check("tampered claims are rejected", _raises(f"{prefix}.{forged}.{sig}", keys, "signature"))
    check("unknown kid is rejected", _raises(token, {"t2": pub}, "unknown key"))
    check("wrong public key is rejected", _raises(token, {"t1": other_pub}, "signature"))
    check("wrong prefix is rejected", _raises(f"erebus2.{payload}.{sig}", keys, "not an Erebus license key"))
    check("garbage is rejected", _raises("hello", keys, "not an Erebus license key"))
    check("undecodable payload is rejected", _raises(f"{prefix}.!!!.{sig}", keys, "not decodable"))

    bad = issue(pem, kid="t1", customer="X", features=["a"], days=1, now=NOW)
    p2, pay2, _ = bad.split(".")
    c2 = json.loads(base64.urlsafe_b64decode(pay2 + "=" * (-len(pay2) % 4)))
    c2["features"] = "kms"
    signer = serialization.load_pem_private_key(pem, password=None)
    pay3 = _b64(json.dumps(c2).encode())
    string_features = f"{p2}.{pay3}.{_b64(signer.sign(f'{p2}.{pay3}'.encode()))}"
    check("features must be a list of strings", _raises(string_features, keys, "claims"))

    check("no license -> none", status_of(None, NOW) is Status.NONE)
    check("before expiry -> valid", status_of(lic, lic.expires_at - 1) is Status.VALID)
    check("at expiry -> grace", status_of(lic, lic.expires_at) is Status.GRACE)
    check("last grace second -> grace", status_of(lic, lic.expires_at + GRACE_SECONDS - 1) is Status.GRACE)
    check("after grace -> expired", status_of(lic, lic.expires_at + GRACE_SECONDS) is Status.EXPIRED)

    clock = [NOW]
    ent = from_env({"EREBUS_LICENSE_KEY": token}, public_keys=keys, clock=lambda: clock[0])
    check("env key -> valid", ent.status is Status.VALID and ent.has("kms"))
    check("unlicensed feature is off", not ent.has("sso"))
    clock[0] = lic.expires_at + 1
    check("grace keeps features on", ent.status is Status.GRACE and ent.has("kms"))
    clock[0] = lic.expires_at + GRACE_SECONDS
    check("expiry lands without restart", ent.status is Status.EXPIRED and not ent.has("kms"))

    none = from_env({}, public_keys=keys)
    check("no env -> none, nothing enabled", none.status is Status.NONE and not none.has("kms"))

    invalid = from_env({"EREBUS_LICENSE_KEY": token + "x"}, public_keys=keys)
    view = invalid.public_view()
    check("invalid env key -> invalid", invalid.status is Status.INVALID and not invalid.has("kms"))
    check("public view never echoes the key", token not in json.dumps(view) and "error" in view)

    key_file = tmp / "license.key"
    key_file.write_text(token + "\n")
    from_file = from_env({"EREBUS_LICENSE_FILE": str(key_file)}, public_keys=keys, clock=lambda: NOW)
    check("mounted key file with newline verifies", from_file.status is Status.VALID)
    missing = from_env({"EREBUS_LICENSE_FILE": str(tmp / "nope")}, public_keys=keys)
    check("unreadable key file -> invalid, not a crash", missing.status is Status.INVALID)

    view = from_env({"EREBUS_LICENSE_KEY": token}, public_keys=keys, clock=lambda: NOW).public_view()
    check("public view has status, features, expiry and no customer",
          view == {"status": "valid", "features": ["kms", "siem"], "expires_at": lic.expires_at})

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
