# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""MSSQL hosts and the address pymssql dials (spec 015 "Security": network).

FreeTDS takes the address to dial and the TLS settings from the connector's private
configuration section for ``host``; a host FreeTDS could not match to that section would
let it resolve the name and dial on its own, with TLS unchecked. So an MSSQL host is a
DNS name or an IPv4 address of at most 230 characters, and anything else is a
``settings`` error before dialling. A TLS-only TDS listener (``tds_fake``) stands in for
the server: one at an address the worker never approved must see nothing, and the
approved path still dials the checked address and checks the certificate name.
"""
import contextlib
import os
import socket
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from tds_fake import TestCa, tds_listener
from warehouse_backends import licensed

from erebus.cataloging.connector_errors import ConnectorError

_passed = 0
_BASE = {"database": "crm", "user": "erebus_sync"}


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _connect(settings):
    """The error kind of a connect through the MSSQL connector, or None."""
    from erebus_pro.connectors.mssql import MssqlConnector
    try:
        MssqlConnector(licensed(["connectors.mssql"])).connect({**_BASE, **settings}, {"password": "Pw-zq-hosts"})
    except ConnectorError as exc:
        return exc.kind
    return None


@contextlib.contextmanager
def _env(**values):
    saved = {k: os.environ.get(k) for k in values}
    for k, v in values.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _name(length, suffix):
    """A DNS name of exactly ``length`` characters ending in ``suffix``, labels under 64."""
    labels, left = [], length - len(suffix)
    while left > 0:
        size = min(62, left - 1) if left > 63 else left
        labels.append("a" * size)
        left -= size + (1 if left > size else 0)
    return ".".join(labels) + suffix


def _port_below_10000():
    """A free port of at most four digits (it then reads as one IPv6 group too)."""
    for port in range(3900, 10000):
        with socket.socket() as probe:
            try:
                probe.bind(("127.0.0.1", port))
            except OSError:
                continue
            return port
    raise OSError("no free port below 10000")


def _seen(events, expect_any):
    """What the listener recorded once the client is done with it."""
    for _ in range(100 if expect_any else 4):
        if any(e in ("login", "failed") for e, _ in events):
            break
        time.sleep(0.05)
    return list(events)


def _check_refused_hosts():
    import pymssql
    real, calls = pymssql.connect, []
    pymssql.connect = lambda **kw: calls.append(kw)
    try:
        for case, host in {"an IPv6 address": "::1", "an IPv6 address ending in a port-like group": "::1:2900",
                           "a bracketed IPv6 address": "[2001:db8::1]", "a host with a port": "db.zq.test:1433",
                           "a host over 230 characters": _name(231, ".zq.test")}.items():
            calls.clear()
            check(f"{case} is a settings error, before dialling",
                  _connect({"host": host, "hostaddr": "127.0.0.1"}) == "settings" and not calls)
    finally:
        pymssql.connect = real


def _check_unapproved_addresses(ca):
    port = _port_below_10000()
    with tds_listener(ca, "untrusted.zq.test", port=port) as (port, events), _env(SSL_CERT_FILE=None):
        host = f"::ffff:7f00:1:{port}"  # an ordinary IPv6 address; "::ffff:7f00:1" is 127.0.0.1
        kind = _connect({"host": host, "hostaddr": host, "port": 1433})
        check("an IPv6 host never reaches the address its last group reads as a port: no TLS handshake, no login",
              kind == "settings" and not _seen(events, False))
        events.clear()
        host = _name(250, ".localhost")  # resolves to loopback; the approved address is ::1
        kind = _connect({"host": host, "hostaddr": "::1", "port": port})
        check("a long host is never resolved by FreeTDS itself: no TLS handshake, no login",
              kind == "settings" and not _seen(events, False))


def _check_freetds_directory(ca):
    """FreeTDS looks for ``host:port`` in ``$FREETDS/etc/freetds.conf`` before it drops the port."""
    tmp = tempfile.TemporaryDirectory()
    os.makedirs(os.path.join(tmp.name, "etc"))
    try:
        with tds_listener(ca, "untrusted.zq.test") as (port, events), _env(SSL_CERT_FILE=None, FREETDS=tmp.name):
            Path(tmp.name, "etc", "freetds.conf").write_text(
                f"[db.zq.test:{port}]\nhost = 127.0.0.1\nport = {port}\nencryption = require\n", encoding="utf-8")
            kind = _connect({"host": "db.zq.test", "hostaddr": "::1", "port": port})
            check("a FreeTDS directory in the environment does not send the connection elsewhere",
                  kind == "unreachable" and not _seen(events, False) and "FREETDS" not in os.environ)
    finally:
        tmp.cleanup()


def _check_approved_path(ca):
    tmp = tempfile.TemporaryDirectory()
    ca_file = os.path.join(tmp.name, "ca.pem")
    Path(ca_file).write_text(ca.pem, encoding="utf-8")
    try:
        with _env(SSL_CERT_FILE=ca_file):
            for host in ("db.zq.test", _name(230, ".zq.test")):  # .zq.test never resolves
                with tds_listener(ca, host) as (port, events):
                    kind = _connect({"host": host, "hostaddr": "127.0.0.1", "port": port})
                    logins = [d for e, d in _seen(events, True) if e == "login"]
                    check(f"a {len(host)}-character host dials the checked address, the login naming the host "
                          "(at most 128 characters fit)", kind == "unreachable" and len(logins) == 1
                          and logins[0]["server"] == host[:128])
                with tds_listener(ca, "other.zq.test") as (port, events):
                    kind = _connect({"host": host, "hostaddr": "127.0.0.1", "port": port})
                    check(f"... and a certificate for another name gets no password ({len(host)} characters)",
                          kind == "unreachable" and not [e for e, _ in _seen(events, True) if e == "login"])
    finally:
        tmp.cleanup()


def _certificate_hostname(settings):
    """The ``certificate hostname`` FreeTDS would get for ``settings`` (None without one)."""
    import pymssql
    real, seen = pymssql.connect, []

    def capture(**_kw):
        text = Path(os.environ["FREETDSCONF"]).read_text(encoding="utf-8")
        seen.append(dict(line.split(" = ", 1) for line in text.splitlines() if " = " in line))
        raise pymssql.OperationalError((20009, b"DB-Lib error message 20009, severity 9:\nUnable to connect\n"))
    pymssql.connect = capture
    try:
        _connect({"hostaddr": "127.0.0.1", **settings})
    finally:
        pymssql.connect = real
    return seen[0].get("certificate hostname")


def _check_azure_zones(ca):
    """FreeTDS (as bundled with pymssql) matches no wildcard certificate against a host name,
    and Azure SQL presents ``*.database.windows.net``: for Azure SQL's zones the name checked
    is the zone's wildcard, as Microsoft recommends for HostNameInCertificate."""
    for zone in ("database.windows.net", "database.usgovcloudapi.net", "database.chinacloudapi.cn"):
        check(f"verify-full on a host under {zone} checks the certificate against *.{zone}",
              _certificate_hostname({"host": f"zqserver.{zone}"}) == f"*.{zone}")
    check("... only under the zone: the zone itself or a look-alike is checked as given",
          _certificate_hostname({"host": "database.windows.net"}) == "database.windows.net"
          and _certificate_hostname({"host": "zq.database.windows.net.zq.test"}) == "zq.database.windows.net.zq.test"
          and _certificate_hostname({"host": "zqdatabase.windows.net"}) == "zqdatabase.windows.net")
    check("... and verify-ca checks no name", _certificate_hostname({"host": "zqserver.database.windows.net",
                                                                     "sslmode": "verify-ca"}) is None)
    tmp = tempfile.TemporaryDirectory()
    ca_file = os.path.join(tmp.name, "ca.pem")
    Path(ca_file).write_text(ca.pem, encoding="utf-8")
    cases = [("zqserver.database.windows.net", "*.database.windows.net", True),
             ("zqmi.zq123.database.windows.net", "*.zq123.database.windows.net", True),
             ("zqserver.database.windows.net", "zqserver.database.windows.net", True),
             ("zqserver.database.windows.net", "*.windows.net", False),
             ("zqserver.database.windows.net", "zqserver.database.windows.net.zq.test", False),
             ("zqserver.database.windows.net", "db.zq.test", False),
             ("db.zq.test", "*.zq.test", False)]
    try:
        with _env(SSL_CERT_FILE=ca_file):
            for host, name, accepted in cases:
                with tds_listener(ca, name) as (port, events):
                    kind = _connect({"host": host, "hostaddr": "127.0.0.1", "port": port})
                    logins = [d for e, d in _seen(events, True) if e == "login"]
                check(f"verify-full, host {host}, certificate {name}: "
                      + ("the password is sent, the login naming the host" if accepted else "no password"),
                      kind == "unreachable" and (logins == [] if not accepted
                                                 else len(logins) == 1 and logins[0]["server"] == host))
    finally:
        tmp.cleanup()


def main():
    print("\n=== MSSQL hosts and the address pymssql dials (spec 015) ===\n")
    try:
        import pymssql  # noqa: F401
    except ImportError:
        if os.environ.get("EREBUS_REQUIRE_MSSQL") == "1":
            raise
        print("  - skipped (pymssql is not installed)")
        return
    ca = TestCa()
    _check_refused_hosts()
    _check_unapproved_addresses(ca)
    _check_freetds_directory(ca)
    _check_approved_path(ca)
    _check_azure_zones(ca)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
