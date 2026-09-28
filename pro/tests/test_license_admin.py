# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""license_admin pipes: keygen --out - and issue --key - keep the private key off disk."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from erebus_pro.license import Status, from_env

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools", "license_admin.py")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _run(args, stdin=""):
    return subprocess.run([sys.executable, TOOL, *args], input=stdin, capture_output=True, text=True, check=True)


def main():
    generated = json.loads(_run(["keygen", "--out", "-"]).stdout)
    check("keygen --out - prints private key and public key as JSON",
          set(generated) == {"private_key_pem", "public_key"}
          and generated["private_key_pem"].startswith("-----BEGIN PRIVATE KEY-----"))

    token = _run(["issue", "--key", "-", "--kid", "t", "--customer", "Acme", "--features", "kms", "--days", "1"],
                 stdin=generated["private_key_pem"]).stdout.strip()
    ent = from_env({"EREBUS_LICENSE_KEY": token}, public_keys={"t": generated["public_key"]})
    check("issue --key - reads the private key from stdin and signs a valid key", ent.status is Status.VALID)

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
