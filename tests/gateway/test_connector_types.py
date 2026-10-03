"""Connector types as data, and the fixed-text connector errors (spec 015 "Architecture").

Pure: ``connector_types`` names each type's family, tier and allowed setting keys and
loads Pro's types from the ``erebus.source_types`` entry-point group without loading a
connector; a raw DSN or libpq key is never allowed. ``ConnectorError`` carries only its
class's fixed text, whatever detail a connector passed; ``LicenseRequired`` is a
PermissionError naming the feature.
"""
import os
import sys
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.cataloging import connector_types
from erebus.cataloging.connector_errors import CONNECTOR_TEXT, ConnectorError, LicenseRequired
from erebus.cataloging.connector_types import ConnectorType
from erebus.gateway.connectors import policy

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _raises(exc_type, fn):
    try:
        fn()
    except exc_type:
        return True
    return False


class _EP:
    def __init__(self, name, obj):
        self.name = name
        self._obj = obj

    def load(self):
        return self._obj


class _Module:
    TYPES = (ConnectorType("snowflake", "warehouse", "pro", frozenset({"account", "warehouse"})),)


def _check_types():
    pg = connector_types.get("postgres")
    check("postgres is a free database type", pg.family == "database" and pg.tier == "free")
    check("postgres allows host, port, dbname, user, sslmode, schemas, collections",
          pg.setting_keys == {"host", "port", "dbname", "user", "sslmode", "schemas", "collections"})
    check("postgres and mysql name their default ports",
          pg.default_port == 5432 and connector_types.get("mysql").default_port == 3306)
    check("mysql is a free database type", connector_types.get("mysql").family == "database")
    sqlite = connector_types.get("sqlite")
    check("sqlite is a free file type with a path", sqlite.family == "file" and "path" in sqlite.setting_keys)
    check("an unknown type is None", connector_types.get("oracle") is None)
    banned = {"dsn", "passfile", "service", "sslkey", "sslrootcert", "sslcert", "hostaddr", "options",
              "local_infile", "init_command", "password"}
    check("no type allows a raw DSN, libpq file key or secret",
          all(not (t.setting_keys & banned) for t in connector_types.builtin_types()))
    check("unknown_keys names keys outside the type's set",
          connector_types.unknown_keys(pg, {"host": "x", "passfile": "/etc/p", "dsn": "y"}) == ["dsn", "passfile"])
    check("unknown_keys is empty for allowed keys", connector_types.unknown_keys(pg, {"host": "x", "port": 1}) == [])


def _check_entry_points():
    found = connector_types.load_types(eps=[_EP("pro", _Module)])
    check("a data-only module adds its types", found["snowflake"].tier == "pro" and "postgres" in found)
    check("a module cannot replace a built-in type", _raises(
        ValueError,
        lambda: connector_types.load_types(eps=[_EP("x", type("M", (), {"TYPES": (ConnectorType(
            "postgres", "database", "pro", frozenset()),)}))])))
    check("a broken types module fails closed",
          _raises(RuntimeError, lambda: connector_types.load_types(eps=[_EP("bad", _Broken())])))


class _Broken:
    @property
    def TYPES(self):
        raise RuntimeError("broken")


def _check_errors():
    err = ConnectorError("auth")
    check("a connector error carries its class", err.kind == "auth")
    check("its text is the fixed text", str(err) == CONNECTOR_TEXT["auth"] == "authentication failed")
    check("an unknown class is refused", _raises(ValueError, lambda: ConnectorError("oops")))
    check("a connector may refuse its own settings with the worker's fixed text",
          str(ConnectorError("settings")) == policy.ERROR_TEXT["settings"] == "source settings are not valid"
          and policy.failure_outcome("settings", attempts=0, limited_since=None, now=datetime.now(UTC),
                                     timings=policy.JobTimings()).needs_attention)
    limited = ConnectorError("limit", reset_at="2026-10-01T00:00:00Z")
    check("a limit error may carry its reset time", limited.reset_at == "2026-10-01T00:00:00Z")
    check("the connector texts are the job texts",
          all(policy.ERROR_TEXT[k] == v for k, v in CONNECTOR_TEXT.items()))
    lic = LicenseRequired("connectors.snowflake")
    check("LicenseRequired is a PermissionError", isinstance(lic, PermissionError))
    check("LicenseRequired names the feature", str(lic) == "requires Erebus Pro (feature connectors.snowflake)")
    check("a malformed feature is refused", _raises(ValueError, lambda: LicenseRequired("a b")))
    from erebus.cataloging import sources
    check("the contract re-exports both", sources.ConnectorError is ConnectorError
          and sources.LicenseRequired is LicenseRequired)


def main():
    print("\n=== Connector types and errors (spec 015) ===\n")
    _check_types()
    _check_entry_points()
    _check_errors()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
