# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""How Pro connector types and connectors plug into core (spec 015 D6, D7, "Architecture").

Pure. erebus-pro declares its types (Snowflake, BigQuery: Pro warehouses that take an
account or project id, never a host or DSN) in a data-only module on the
``erebus.source_types`` entry point, so the gateway accepts them without loading a
connector or driver. Each Pro connector gates itself: without its license feature
``connectors.<type>`` (no key, another feature, expired past grace) ``connect`` raises
``LicenseRequired`` before reading a credential; a license in grace still syncs. The
default entitlements come from the worker's license environment.
"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from warehouse_backends import declared_entry_points, licensed

from erebus.cataloging import connector_types
from erebus.cataloging.connector_errors import LicenseRequired

_PRO = Path(__file__).resolve().parents[1]
_passed = 0
_BANNED = {"dsn", "host", "hostaddr", "port", "api_endpoint", "endpoint", "url", "passfile", "sslkey",
           "sslrootcert", "password", "private_key", "service_account_key", "options"}


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _check_types():
    eps = declared_entry_points(connector_types.GROUP)
    check("erebus-pro declares one erebus.source_types entry point", len(eps) == 1)
    types = connector_types.load_types(eps=eps)
    for tid in ("snowflake", "bigquery"):
        t = types.get(tid)
        check(f"{tid} is a Pro warehouse type with no host to dial",
              t is not None and t.family == "warehouse" and t.tier == "pro" and t.default_port is None)
    check("snowflake takes an account id, user, database, warehouse, role, schemas and collections",
          types["snowflake"].setting_keys == {"account", "user", "database", "warehouse", "role", "schemas",
                                              "collections"})
    check("bigquery takes a project, location, byte cap, auth mode, datasets (schemas) and collections",
          types["bigquery"].setting_keys == {"project", "location", "max_bytes_billed", "auth", "schemas",
                                             "collections"})
    check("no Pro type takes a host, DSN, endpoint or credential as a setting",
          not any(t.setting_keys & _BANNED for t in types.values() if t.tier == "pro"))
    check("the free types are unchanged", types["postgres"].tier == "free" and types["sqlite"].tier == "free")


def _check_data_only():
    code = ("import sys; import erebus_pro.source_types;"
            "print([m for m in sys.modules if m.startswith(('erebus_pro.connectors', 'snowflake', 'google.cloud',"
            " 'fakesnow', 'erebus.cataloging.connectors'))])")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                         cwd=_PRO.parent, env={**os.environ, "PYTHONPATH": f"{_PRO}{os.pathsep}{_PRO.parent}"})
    check("the types module loads no connector module or driver (the gateway imports it)",
          out.stdout.strip() == "[]")


class _Probe:
    """A secrets dict that records whether anyone read it."""

    def __init__(self):
        self.touched = False

    def get(self, *_a):
        self.touched = True

    def __getitem__(self, _k):
        self.touched = True


def _check_gate():
    from erebus_pro.connectors._licensed import LicensedConnector
    from erebus_pro.license import GRACE_SECONDS, from_env

    class Dummy(LicensedConnector):
        type_id = "snowflake"

        def connect(self, settings, secrets):
            self.require_license()
            secrets.get("private_key")
            return "connected"

    feature = "connectors.snowflake"
    refused = {
        "no license key": from_env({}),
        "a license without the feature": licensed(["connectors.bigquery", "sync.schedule"]),
        "a license expired past its grace period": licensed([feature], expires_in=-GRACE_SECONDS - 60),
    }
    for case, ents in refused.items():
        probe = _Probe()
        try:
            Dummy(ents).connect({}, probe)
            exc = None
        except LicenseRequired as raised:
            exc = raised
        check(f"{case}: connect raises LicenseRequired naming connectors.snowflake",
              exc is not None and str(exc) == f"requires Erebus Pro (feature {feature})")
        check(f"{case}: before reading a credential", not probe.touched)
    check("a licensed connector connects", Dummy(licensed([feature])).connect({}, {}) == "connected")
    check("a license in its grace period still syncs (D7: license problems never weaken filtering)",
          Dummy(licensed([feature], expires_in=-60)).connect({}, {}) == "connected")
    check("the connector id is its type", Dummy().connector_id() == "snowflake")

    saved = {k: os.environ.pop(k, None) for k in ("EREBUS_LICENSE_KEY", "EREBUS_LICENSE_FILE")}
    try:
        from erebus_pro.connectors import _licensed
        _licensed.default_entitlements.cache_clear()
        try:
            Dummy().connect({}, {})
            refused_default = False
        except LicenseRequired:
            refused_default = True
        check("without entitlements given, the worker's license environment decides", refused_default)
    finally:
        os.environ.update({k: v for k, v in saved.items() if v is not None})
        _licensed.default_entitlements.cache_clear()


def main():
    print("\n=== Pro connector groundwork (spec 015 D6) ===\n")
    _check_types()
    _check_data_only()
    _check_gate()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
