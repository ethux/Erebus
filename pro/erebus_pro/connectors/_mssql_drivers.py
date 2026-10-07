# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The two drivers behind the MSSQL connector, and how their failures are classed.

**pymssql** (FreeTDS) signs in SQL logins. FreeTDS resolves server names itself and reads
its settings from ``freetds.conf`` and ``TDS*`` environment variables, so the connector
writes a private configuration (a 0700 directory, a 0600 file, no credential in it) whose
one section, named ``<host>``, sends FreeTDS to the checked ``hostaddr`` and sets TLS.
pymssql asks for ``<host>:<port>``; no section has that name, so FreeTDS drops the port,
reads the ``<host>`` section and names exactly ``host`` in the login. That holds only for
a host without ``:`` and short enough for FreeTDS's 256-byte lines, so the connector takes
DNS names and IPv4 addresses of up to 230 characters. TLS: ``encryption = require``; for
``verify-*`` a copy of the system CA bundle as ``ca file``; for ``verify-full`` the
certificate's name checked against ``host`` (``certificate hostname``, FreeTDS's
``HostNameInCertificate``). FreeTDS checks the name after the handshake and before it
sends the login, so a wrong name never gets the password. The FreeTDS bundled with
pymssql matches no wildcard certificate against a host name, and Azure SQL presents its
zone's wildcard (``*.database.windows.net``), so for a host in one of Azure SQL's zones
the name checked is that wildcard, as Microsoft recommends for ``HostNameInCertificate``;
any other wildcard certificate fails the check. ``FREETDSCONF`` points at that
file and ``TDSHOST``, ``TDSPORT``, ``TDSVER``, ``TDSDUMP``, ``TDSDUMPCONFIG`` and
``FREETDS`` are dropped from the environment, since FreeTDS reads them during ``dbopen``;
connects are serialized and the file is emptied afterwards. Before it drops the port,
FreeTDS also looks for ``<host>:<port>`` in the worker user's ``~/.freetds.conf`` and
``~/.config/freetds.conf``, as for any pymssql client: the worker should have neither.
The login asks for read-only intent (``ApplicationIntent=ReadOnly``).

**mssql-python** signs in an Entra service principal (``ActiveDirectoryServicePrincipal``
with the client id and secret) through Microsoft's ODBC driver, which it bundles under
Microsoft's license. It is only the optional extra ``erebus-pro[mssql-entra]``; without
it ``DriverMissing`` names the extra. The connection string names ``host`` as the server,
dials ``tcp:<hostaddr>,<port>`` (``Addr``) and checks the certificate against ``host``, or
an Azure SQL zone's wildcard (``HostNameInCertificate``).

Errors are classed by the SQL Server message number (pymssql) or the driver's text
(mssql-python), which is read only for that and never shown.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import shutil
import ssl
import tempfile
import threading
from typing import Any

from erebus.cataloging.connector_errors import ConnectorError, DriverMissing

from . import _warehouse

ENTRA_EXTRA = "erebus-pro[mssql-entra]"
_TDS_ENV = ("TDSHOST", "TDSPORT", "TDSVER", "TDSDUMP", "TDSDUMPCONFIG", "FREETDS")
_CA_BUNDLES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem")
_AZURE_ZONES = ("database.windows.net", "database.usgovcloudapi.net", "database.chinacloudapi.cn")
_LOCK = threading.Lock()
_DIR: list[str] = []

# SQL Server message numbers, and FreeTDS's own (200xx). Azure SQL refuses a login naming
# no server it knows (40531, 40532) and a client address its firewall does not allow
# (40615): both stay refused until an admin acts, so neither is retried as unreachable.
_AUTH = frozenset({18456, 18470, 18486, 18487, 18488, 40531, 40532})
_PERMISSION = frozenset({229, 230, 262, 297, 300, 916, 3906, 4060, 40615})
_UNREACHABLE = frozenset({20002, 20003, 20004, 20006, 20009, 20017, 20047, 40197, 40501, 40613})
_DBLIB = re.compile(rb"DB-Lib error message (\d+)")
_SERVER_SAID = 20018  # FreeTDS: "General SQL Server error: Check messages from the SQL Server"
# What mssql-python's errors say (lower case), for classing only, in order: Azure's
# firewall refusal (40615) may come as an authorization error.
_ENTRA_MARKS = (
    ("permission", ("is not allowed to access the server",)),
    ("auth", ("login failed", "aadsts", "invalid authorization specification", "server name cannot be determined")),
    ("permission", ("permission was denied", "is not able to access the database", "cannot open database")),
)
_ENTRA_UNREACHABLE = ("client unable to establish connection", "communication link failure", "timeout expired",
                      "tcp provider", "ssl provider")


def pymssql_kind(exc: BaseException, *, connecting: bool) -> str:
    """The class of a pymssql error. pymssql reports the last server message number; when
    the server said nothing this time (no DB-Lib 20018) that number is stale, and
    FreeTDS's own first DB-Lib number decides."""
    first = exc.args[0] if exc.args else None
    code, message = first if isinstance(first, tuple) and len(first) == 2 else (first, b"")
    dblib = [int(n) for n in _DBLIB.findall(message)] if isinstance(message, bytes) else []
    if dblib and _SERVER_SAID not in dblib:
        code = dblib[0]
    if code in _AUTH:
        return "auth"
    if code in _PERMISSION:
        return "permission"
    if connecting or code in _UNREACHABLE:
        return "unreachable"
    return "query"


def entra_kind(exc: BaseException, *, connecting: bool) -> str:
    text = str(exc).lower()
    for kind, marks in _ENTRA_MARKS:
        if any(mark in text for mark in marks):
            return kind
    if connecting or any(mark in text for mark in _ENTRA_UNREACHABLE):
        return "unreachable"
    return "query"


def certificate_name(host: str) -> str:
    """The name the server's certificate must carry: ``host``, or for a host in one of
    Azure SQL's zones the zone's wildcard, which is what Azure SQL presents."""
    for zone in _AZURE_ZONES:
        if host.endswith("." + zone):
            return "*." + zone
    return host


def _system_cas() -> str | None:
    """The system CA bundle (``SSL_CERT_FILE`` first, as OpenSSL reads it)."""
    paths = ssl.get_default_verify_paths()
    for path in (paths.cafile, paths.openssl_cafile, *_CA_BUNDLES):
        if path and os.path.isfile(path):
            return path
    try:
        import certifi
    except ImportError:
        return None
    return certifi.where()


def _private_dir() -> str:
    if not _DIR:
        _DIR.append(tempfile.mkdtemp(prefix="erebus-freetds-"))  # mode 0700
    return _DIR[0]


def _write(path: str, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def _configure(p: dict[str, Any]) -> str:
    """Write the FreeTDS section for this connection and point FreeTDS at it."""
    where = _private_dir()
    lines = [f"[{p['host']}]", f"host = {p['hostaddr']}", f"port = {p['port']}", "tds version = 7.4",
             f"encryption = {'off' if p['sslmode'] == 'disable' else 'require'}"]
    if p["sslmode"] in ("verify-full", "verify-ca"):
        cas = _system_cas()
        if cas is None:
            raise ConnectorError("unreachable") from None  # nothing to verify the server against
        shutil.copyfile(cas, os.path.join(where, "ca.pem"))
        lines.append(f"ca file = {os.path.join(where, 'ca.pem')}")
    lines.append(f"check certificate hostname = {'yes' if p['sslmode'] == 'verify-full' else 'no'}")
    if p["sslmode"] == "verify-full":
        lines.append(f"certificate hostname = {certificate_name(p['host'])}")
    conf = os.path.join(where, "freetds.conf")
    _write(conf, "\n".join(lines) + "\n")
    for name in _TDS_ENV:
        os.environ.pop(name, None)
    if os.environ.get("FREETDSCONF") != conf:
        os.environ["FREETDSCONF"] = conf
    return conf


def connect_pymssql(p: dict[str, Any], password: str) -> Any:
    """A pymssql connection for a SQL login; driver errors propagate."""
    import pymssql

    with _LOCK:
        conf = _configure(p)
        try:
            return pymssql.connect(server=p["host"], port=str(p["port"]), user=p["user"], password=password,
                                   database=p["database"], login_timeout=_warehouse.LOGIN_TIMEOUT_S,
                                   timeout=_warehouse.STATEMENT_TIMEOUT_S, appname=_warehouse.QUERY_TAG,
                                   read_only=True, autocommit=True, tds_version="7.4",
                                   encryption="off" if p["sslmode"] == "disable" else "require")
        finally:
            _write(conf, "")


def _brace(value: str) -> str:
    return "{" + value.replace("}", "}}") + "}"


def entra_string(p: dict[str, Any], secret: str) -> str:
    """The ODBC connection string for a service principal; every value braced.

    ``Server`` names ``host`` (Azure SQL finds the database by the server name in the login)
    and ``Addr`` dials the checked address: per Microsoft's ODBC documentation ``Addr``
    (``Address``) takes precedence over ``Server`` for the network connection. That is not
    verified against the real driver here, which is never installed (Microsoft's license)."""
    addr = p["hostaddr"]
    if ipaddress.ip_address(addr).version == 6:
        addr = f"[{addr}]"
    keys = {"Server": f"tcp:{p['host']},{p['port']}", "Addr": f"tcp:{addr},{p['port']}", "Database": p["database"],
            "Authentication": "ActiveDirectoryServicePrincipal", "UID": p["client_id"], "PWD": secret,
            "Encrypt": "yes", "TrustServerCertificate": "no" if p["sslmode"] == "verify-full" else "yes"}
    if p["sslmode"] == "verify-full":
        keys["HostNameInCertificate"] = certificate_name(p["host"])
    keys.update(ApplicationIntent="ReadOnly", ConnectRetryCount="0")
    return ";".join(f"{k}={_brace(v)}" for k, v in keys.items())


def entra_driver() -> Any:
    try:
        import mssql_python
    except ImportError:
        raise DriverMissing(ENTRA_EXTRA) from None
    logging.getLogger("mssql_python").setLevel(logging.WARNING)
    return mssql_python


def connect_entra(driver: Any, p: dict[str, Any], secret: str) -> Any:
    """An mssql-python connection for a service principal; driver errors propagate."""
    conn = driver.connect(entra_string(p, secret), autocommit=True, timeout=_warehouse.LOGIN_TIMEOUT_S)
    conn.timeout = _warehouse.STATEMENT_TIMEOUT_S
    return conn
