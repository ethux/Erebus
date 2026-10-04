# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The Snowflake connector at the driver boundary (spec 015 "Warehouse connectors", D10).

On fakesnow. A service user signs in with its key pair (JWT): the connector hands the
driver the account id, user and the key as DER bytes, never a password or host; an
encrypted key opens with its passphrase. Every session is tagged, has a statement
timeout and keeps no session alive. Identifiers in settings must be plain Snowflake
identifiers, so nothing typed into a setting reaches SQL; a ``schemas`` entry matches the
schema as Snowflake stores an unquoted name (upper case). The driver's own log stays at
warning level, so its connection chatter never reaches the worker log.
"""
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from warehouse_backends import SnowflakeBackend, rsa_pem

from erebus.cataloging.connector_errors import ConnectorError

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _Capture:
    """Record the keyword arguments the connector passes to ``snowflake.connector.connect``."""

    def __enter__(self):
        import snowflake.connector
        self.calls = []
        self.real = snowflake.connector.connect

        def capture(**kwargs):
            self.calls.append(kwargs)
            return self.real(**kwargs)
        snowflake.connector.connect = capture
        return self

    def __exit__(self, *_exc):
        import snowflake.connector
        snowflake.connector.connect = self.real


def _kind(fn):
    try:
        fn()
    except ConnectorError as exc:
        return exc.kind
    return None


def _check_key_pair(b):
    connector = b.connector()
    logging.getLogger("snowflake.connector").setLevel(logging.DEBUG)  # as a verbose worker log would leave it
    with _Capture() as cap:
        connector.connect(b.settings(), {**b.secrets(), "password": "Zq-never-sent"}).close()
    kw = cap.calls[0]
    check("signs in with the key pair (JWT)", kw.get("authenticator") == "SNOWFLAKE_JWT")
    check("hands the key as DER bytes", isinstance(kw.get("private_key"), bytes) and kw["private_key"][:1] == b"\x30")
    check("never sends a password, host, port or protocol",
          not {"password", "host", "port", "protocol", "token"} & set(kw) and "Zq-never-sent" not in str(kw))
    check("passes the account id, user, database, warehouse and role as set",
          (kw["account"], kw["user"], kw["database"], kw["warehouse"], kw["role"])
          == ("acme-zq", "SVC_EREBUS_ZQ", "CONTRACT_DB", "SYNC_WH", "EREBUS_READER"))
    params = kw.get("session_parameters", {})
    check("tags the session and caps every statement",
          params.get("QUERY_TAG") == "erebus-sync" and params.get("STATEMENT_TIMEOUT_IN_SECONDS") == 600)
    check("keeps no session alive and times out the login",
          kw.get("client_session_keep_alive") is False and kw.get("login_timeout") == 10)
    check("never probes cloud metadata addresses to detect its platform (the worker refuses them)",
          kw.get("platform_detection_timeout_seconds") == 0.0)
    check("lowers the driver's log to warning level (its connection chatter names hosts)",
          logging.getLogger("snowflake.connector").getEffectiveLevel() >= logging.WARNING)

    wrapped = rsa_pem("Zq-right-phrase")
    src = connector.connect(b.settings(), {"private_key": wrapped, "private_key_passphrase": "Zq-right-phrase"})
    try:
        check("an encrypted key opens with its passphrase", len(src.list_collections()) >= 2)
    finally:
        src.close()


def _check_settings(b):
    connector = b.connector()
    for key, value in (("database", 'CRM"; DROP TABLE x; --'), ("warehouse", "WH; SELECT 1"),
                       ("role", "a b"), ("user", ""), ("account", "acme.evil.example/x")):
        check(f"a malformed {key} is a settings error",
              _kind(lambda key=key, value=value: connector.connect(b.settings(**{key: value}), b.secrets()))
              == "settings")
    check("an account id is required", _kind(lambda: connector.connect(
        {k: v for k, v in b.settings().items() if k != "account"}, b.secrets())) == "settings")
    with _Capture() as cap:
        kind = _kind(lambda: connector.connect({k: v for k, v in b.settings().items() if k != "warehouse"},
                                               b.secrets()))
    check("a warehouse is required (without one every query fails), refused before signing in",
          kind == "settings" and not cap.calls)
    check("... and the connector says so", connector.connector_metadata().settings_schema["warehouse"]
          == {"required": True})
    src = connector.connect(b.settings(schemas=["crm"]), b.secrets())
    try:
        names = [c.name for c in src.list_collections()]
    finally:
        src.close()
    check("a lower-case schemas entry matches the unquoted (upper-case) schema",
          names and all(n.startswith("CRM.") for n in names))
    src = connector.connect(b.settings(), b.secrets())
    try:
        refs = [r.record_ref for r in src.iter_records("CRM.customers", limit=10, page_size=2)]
    finally:
        src.close()
    check("records page through the cursor and keep distinct refs", len(refs) == 5 and len(set(refs)) == 5)


def main():
    print("\n=== Snowflake connector (spec 015) ===\n")
    b = SnowflakeBackend()
    reason = b.unavailable()
    if reason:
        if os.environ.get("EREBUS_REQUIRE_SNOWFLAKE") == "1":
            raise AssertionError(reason)
        print(f"  - skipped ({reason})")
        return
    b.setup()
    try:
        _check_key_pair(b)
        _check_settings(b)
    finally:
        b.teardown()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
