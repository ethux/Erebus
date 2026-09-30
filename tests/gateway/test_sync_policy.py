"""Sync worker config and network policy (spec 015 "Security", "Config and deploy"; SC-9).

Pure: a fake resolver stands in for DNS. The worker needs only the DSN and the master
key (never EREBUS_GATEWAY_PROVIDER); its timings come from EREBUS_SYNC_*. Settings take
only the type's keys with checked values; the host is resolved once and every address
must pass the deny list (default: the gateway's DB host, loopback, link-local and cloud
metadata) and the allow list when set; the connector gets the checked address as
``hostaddr``. SQLite paths must resolve inside EREBUS_SYNC_SQLITE_DIR.
"""
import base64
import os
import socket
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.cataloging import connector_types
from erebus.gateway.config import ConfigError
from erebus.sync import netpolicy
from erebus.sync.config import SyncConfig
from erebus.sync.netpolicy import PolicyError

_KEY = base64.b64encode(b"k" * 32).decode()
_ENV = {"EREBUS_PG_DSN": "postgresql://erebus:pw@gwdb.internal:5432/erebus_gateway", "EREBUS_GATEWAY_MASTER_KEY": _KEY}
_PG = connector_types.get("postgres")
_SQLITE = connector_types.get("sqlite")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _raises(exc_type, fn, kind=None):
    try:
        fn()
    except exc_type as exc:
        return kind is None or getattr(exc, "kind", None) == kind
    return False


def _dns(table):
    """A getaddrinfo stand-in answering from ``table`` (name -> list of addresses)."""
    calls = []

    def resolve(host, port, *_a, **_k):
        calls.append(host)
        if host not in table:
            raise socket.gaierror("unknown host")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port))
                for a in table[host]]

    resolve.calls = calls
    return resolve


def _cfg_error_text(env):
    try:
        SyncConfig.from_env(env)
    except ConfigError as exc:
        return str(exc)
    return ""


def _check_config():
    cfg = SyncConfig.from_env(dict(_ENV))
    check("the worker starts without EREBUS_GATEWAY_PROVIDER", cfg.dsn == _ENV["EREBUS_PG_DSN"])
    check("defaults follow the spec",
          (cfg.poll_s, cfg.concurrency, cfg.tenant_max_values) == (5, 2, 1_000_000)
          and cfg.timings.heartbeat_s == 30 and cfg.timings.lease_s == 600
          and cfg.timings.backoff_s == (60, 300, 900) and cfg.timings.limit_wait_s == 172800)
    check("detection is on unless EREBUS_DISABLE_GLINER", not cfg.detection_disabled
          and SyncConfig.from_env({**_ENV, "EREBUS_DISABLE_GLINER": "1"}).detection_disabled)
    check("SQLite is off by default", cfg.policy.sqlite_dir is None)
    tuned = SyncConfig.from_env({**_ENV, "EREBUS_SYNC_POLL_S": "2", "EREBUS_SYNC_CONCURRENCY": "4",
                                 "EREBUS_SYNC_HEARTBEAT_S": "5", "EREBUS_SYNC_LEASE_S": "60",
                                 "EREBUS_SYNC_BACKOFF_S": "1, 2,3", "EREBUS_SYNC_LIMIT_WAIT_S": "100",
                                 "EREBUS_SYNC_TENANT_MAX_VALUES": "50"})
    check("every EREBUS_SYNC_* timing is read",
          (tuned.poll_s, tuned.concurrency, tuned.timings.heartbeat_s, tuned.timings.lease_s,
           tuned.timings.backoff_s, tuned.timings.limit_wait_s, tuned.tenant_max_values)
          == (2, 4, 5, 60, (1, 2, 3), 100, 50))
    check("the DSN is required", "EREBUS_PG_DSN" in _cfg_error_text({"EREBUS_GATEWAY_MASTER_KEY": _KEY}))
    check("the master key is required", "EREBUS_GATEWAY_MASTER_KEY" in _cfg_error_text({"EREBUS_PG_DSN": "x"}))
    bad = _cfg_error_text({**_ENV, "EREBUS_GATEWAY_MASTER_KEY": "not-base64-Zq9"})
    check("a bad master key is refused without echoing it", bad and "Zq9" not in bad)
    check("a heartbeat not under the lease is refused",
          "EREBUS_SYNC_HEARTBEAT_S" in _cfg_error_text({**_ENV, "EREBUS_SYNC_HEARTBEAT_S": "600"}))
    check("a malformed backoff is refused", "EREBUS_SYNC_BACKOFF_S" in _cfg_error_text(
        {**_ENV, "EREBUS_SYNC_BACKOFF_S": "1,x"}))
    check("a zero concurrency is refused", "EREBUS_SYNC_CONCURRENCY" in _cfg_error_text(
        {**_ENV, "EREBUS_SYNC_CONCURRENCY": "0"}))
    check("a missing SQLite directory is refused", "EREBUS_SYNC_SQLITE_DIR" in _cfg_error_text(
        {**_ENV, "EREBUS_SYNC_SQLITE_DIR": "/no/such/dir-erebus"}))
    check("a malformed deny entry is refused", "EREBUS_SYNC_DENIED_HOSTS" in _cfg_error_text(
        {**_ENV, "EREBUS_SYNC_DENIED_HOSTS": "10.0.0.0/33"}))


def _check_default_deny():
    policy = SyncConfig.from_env(dict(_ENV)).policy
    dns = _dns({"gwdb.internal": ["10.9.9.9"], "crm.example": ["203.0.113.7"], "gw-alias.example": ["10.9.9.9"],
                "localhost": ["127.0.0.1", "::1"], "meta.example": ["169.254.169.254"],
                "v6meta.example": ["fd00:ec2::254"], "mapped.example": ["::ffff:127.0.0.1"],
                "zero.example": ["0.0.0.0"], "ali.example": ["100.100.100.200"]})
    ok = netpolicy.check_host(policy, "crm.example", 5432, resolve=dns)
    check("a public source host passes and yields its address", ok == "203.0.113.7")
    for host, why in (("gwdb.internal", "the gateway's DB host"), ("gw-alias.example", "another name for the DB host"),
                      ("localhost", "loopback"), ("127.0.0.1", "a loopback literal"),
                      ("meta.example", "the cloud metadata address"), ("v6meta.example", "AWS IPv6 metadata"),
                      ("mapped.example", "an IPv4-mapped loopback"), ("zero.example", "the unspecified address"),
                      ("ali.example", "Alibaba metadata"), ("169.254.1.1", "link-local")):
        check(f"denies {why} by default",
              _raises(PolicyError, lambda h=host: netpolicy.check_host(policy, h, 5432, resolve=dns), "denied"))
    rebinding = _dns({"rebind.example": ["203.0.113.7", "127.0.0.1"]})
    check("an answer mixing a public and a denied address is refused (rebinding)",
          _raises(PolicyError, lambda: netpolicy.check_host(policy, "rebind.example", 5432, resolve=rebinding),
                  "denied"))
    check("a name that does not resolve is unreachable",
          _raises(PolicyError, lambda: netpolicy.check_host(policy, "nx.example", 5432, resolve=dns), "unreachable"))
    unix = SyncConfig.from_env({**_ENV, "EREBUS_PG_DSN": "postgresql:///erebus_gateway"}).policy
    check("a socket DSN still denies loopback",
          _raises(PolicyError, lambda: netpolicy.check_host(unix, "localhost", 5432, resolve=dns), "denied"))


def _check_lists():
    dns = _dns({"crm.example": ["203.0.113.7"], "other.example": ["198.51.100.4"], "localhost": ["127.0.0.1"],
                "blocked.example": ["198.51.100.9"]})
    custom = SyncConfig.from_env({**_ENV, "EREBUS_SYNC_DENIED_HOSTS": "blocked.example, 198.51.100.0/30"}).policy
    check("a set deny list replaces the defaults (loopback allowed)",
          netpolicy.check_host(custom, "localhost", 5432, resolve=dns) == "127.0.0.1")
    check("a denied name is refused",
          _raises(PolicyError, lambda: netpolicy.check_host(custom, "blocked.example", 1, resolve=dns), "denied"))
    check("a denied network is refused",
          _raises(PolicyError, lambda: netpolicy.check_host(custom, "198.51.100.2", 1, resolve=dns), "denied"))
    none = SyncConfig.from_env({**_ENV, "EREBUS_SYNC_DENIED_HOSTS": "none"}).policy
    check("'none' denies nothing", netpolicy.check_host(none, "localhost", 1, resolve=dns) == "127.0.0.1")
    allow = SyncConfig.from_env({**_ENV, "EREBUS_SYNC_ALLOWED_HOSTS": "crm.example,198.51.100.0/24"}).policy
    check("an allowed name passes", netpolicy.check_host(allow, "crm.example", 1, resolve=dns) == "203.0.113.7")
    check("an address in an allowed network passes",
          netpolicy.check_host(allow, "other.example", 1, resolve=dns) == "198.51.100.4")
    check("a host outside the allow list is refused",
          _raises(PolicyError, lambda: netpolicy.check_host(
              SyncConfig.from_env({**_ENV, "EREBUS_SYNC_ALLOWED_HOSTS": "crm.example"}).policy,
              "other.example", 1, resolve=dns), "denied"))
    both = SyncConfig.from_env({**_ENV, "EREBUS_SYNC_ALLOWED_HOSTS": "127.0.0.0/8"}).policy
    check("the deny list wins over the allow list",
          _raises(PolicyError, lambda: netpolicy.check_host(both, "localhost", 1, resolve=dns), "denied"))


def _check_settings():
    policy = SyncConfig.from_env({**_ENV, "EREBUS_SYNC_DENIED_HOSTS": "none"}).policy
    dns = _dns({"crm.example": ["203.0.113.7"]})
    stored = {"host": "crm.example", "dbname": "crm", "user": "reader", "sslmode": "verify-full",
              "schemas": ["public"]}
    out = netpolicy.prepare_settings(policy, _PG, stored, resolve=dns)
    check("the connector gets the checked address and the default port",
          out["hostaddr"] == "203.0.113.7" and out["port"] == 5432 and out["host"] == "crm.example")
    check("the stored settings are not changed in place", "hostaddr" not in stored and "port" not in stored)
    for bad, why in (({"host": "crm.example", "passfile": "/etc/pgpass"}, "a libpq file key"),
                     ({"host": "crm.example", "dsn": "postgresql://x"}, "a raw DSN"),
                     ({"host": "crm.example", "hostaddr": "127.0.0.1"}, "a caller-set hostaddr"),
                     ({"dbname": "crm"}, "a missing host"),
                     ({"host": "crm.example", "port": "5432"}, "a string port"),
                     ({"host": "crm.example", "port": 70000}, "a port out of range"),
                     ({"host": "crm.example", "port": True}, "a boolean port"),
                     ({"host": "crm.example", "sslmode": "allow-anything"}, "an unknown sslmode"),
                     ({"host": "crm example"}, "a host with a space"),
                     ({"host": "crm.example", "user": "a\x00b"}, "a NUL in a value"),
                     ({"host": "crm.example", "schemas": "public"}, "schemas not a list"),
                     ({"host": "crm.example", "collections": [1]}, "a non-text collection")):
        check(f"refuses {why}",
              _raises(PolicyError, lambda b=bad: netpolicy.prepare_settings(policy, _PG, b, resolve=dns), "settings"))
    check("resolution happens only after the settings passed", "crm.example" in dns.calls)


def _check_sqlite():
    with tempfile.TemporaryDirectory() as root:
        base = Path(root) / "sources"
        base.mkdir()
        (base / "crm.db").write_bytes(b"")
        outside = Path(root) / "secret.db"
        outside.write_bytes(b"")
        (base / "link.db").symlink_to(outside)
        off = SyncConfig.from_env(dict(_ENV)).policy
        check("SQLite is refused when no directory is set",
              _raises(PolicyError, lambda: netpolicy.prepare_settings(off, _SQLITE, {"path": "crm.db"}), "denied"))
        policy = SyncConfig.from_env({**_ENV, "EREBUS_SYNC_SQLITE_DIR": str(base)}).policy
        out = netpolicy.prepare_settings(policy, _SQLITE, {"path": "crm.db"})
        check("a path inside the directory resolves to it", out["path"] == str((base / "crm.db").resolve()))
        check("an absolute path inside passes",
              netpolicy.prepare_settings(policy, _SQLITE, {"path": str(base / "crm.db")})["path"].endswith("crm.db"))
        for path, why in (("../secret.db", "a parent escape"), (str(outside), "an absolute path outside"),
                          ("link.db", "a symlink out"), ("crm.db?mode=rw", "URI parameters"),
                          ("crm%2edb", "percent escapes")):
            check(f"refuses {why}", _raises(
                PolicyError, lambda p=path: netpolicy.prepare_settings(policy, _SQLITE, {"path": p}), "denied"))
        check("a missing file is unreachable",
              _raises(PolicyError, lambda: netpolicy.prepare_settings(policy, _SQLITE, {"path": "nope.db"}),
                      "unreachable"))


def main():
    print("\n=== Sync worker config and network policy (spec 015) ===\n")
    _check_config()
    _check_default_deny()
    _check_lists()
    _check_settings()
    _check_sqlite()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
