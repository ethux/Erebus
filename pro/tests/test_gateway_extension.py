# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Pro registers /v1/license and never blocks startup, whatever the key state."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools"))

from erebus_pro import license as lic_mod
from erebus_pro.gateway import register
from fastapi import FastAPI
from fastapi.testclient import TestClient
from license_admin import issue, keygen

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _app_with(env):
    old = {k: os.environ.pop(k, None) for k in ("EREBUS_LICENSE_KEY", "EREBUS_LICENSE_FILE")}
    os.environ.update(env)
    try:
        app = FastAPI()
        register(app, None)
        return app
    finally:
        for k in ("EREBUS_LICENSE_KEY", "EREBUS_LICENSE_FILE"):
            os.environ.pop(k, None)
            if old[k] is not None:
                os.environ[k] = old[k]


def main():
    tmp = Path(tempfile.mkdtemp())
    lic_mod.PUBLIC_KEYS["test"] = keygen(tmp / "k")
    token = issue((tmp / "k").read_bytes(), kid="test", customer="Acme", features=["kms"], days=30)

    app = _app_with({})
    body = TestClient(app).get("/v1/license").json()
    check("no key: starts, status none", body["status"] == "none")
    check("entitlements exposed on app.state", not app.state.erebus_entitlements.has("kms"))

    app = _app_with({"EREBUS_LICENSE_KEY": token})
    check("valid key: status valid", TestClient(app).get("/v1/license").json()["status"] == "valid")
    check("valid key: feature on", app.state.erebus_entitlements.has("kms"))

    app = _app_with({"EREBUS_LICENSE_KEY": "garbage"})
    body = TestClient(app).get("/v1/license").json()
    check("bad key: still starts, status invalid", body["status"] == "invalid")

    del lic_mod.PUBLIC_KEYS["test"]
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
