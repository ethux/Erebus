# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The MSSQL / Azure SQL connector at the driver boundary and on a live server (spec 015
"Warehouse connectors", "Security").

Two drivers, chosen by ``auth``. SQL logins (the default) go through pymssql (FreeTDS),
which ships in the image. Entra service principals go through Microsoft's mssql-python,
which is only an optional extra (``erebus-pro[mssql-entra]``): it bundles Microsoft's
ODBC driver under Microsoft's license, so the image does not ship it, and without it an
Entra source fails with a fixed text naming the extra. mssql-python is never installed
here: a stand-in module records what the connector hands it.

Either way the connector dials the address the sync worker checked (``hostaddr``), asks
for read-only intent, and checks TLS against ``host``: by default with the certificate
verified against the system CAs and its name matched before the password is sent;
``verify-ca``, ``require`` and ``disable`` relax that. FreeTDS gets a private
configuration naming exactly that address; no TDS environment variable applies. A
TLS-only TDS listener stands in for the server in the TLS checks.

The live checks need the throwaway server named by ``EREBUS_TEST_MSSQL_DSN`` (skipped
without it unless ``EREBUS_REQUIRE_MSSQL=1``): an encrypted, tagged session, text
values over 4,000 characters skipped, and the README's least-privilege grants enough.
"""
import contextlib
import os
import re
import stat
import sys
import tempfile
import time
import tomllib
import types
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from connector_contract import _READ, _shown
from mssql_backend import MssqlBackend
from tds_fake import TestCa, tds_listener
from warehouse_backends import licensed

from erebus.cataloging import sources
from erebus.cataloging.connector_errors import ConnectorError, DriverMissing

_ROOT = Path(__file__).resolve().parents[2]
_passed = 0
_BASE = {"host": "db.zq.test", "hostaddr": "127.0.0.1", "port": 1433, "database": "crm", "user": "erebus_sync"}
_CLIENT_ID = "3f2c5d1e-8a4b-4c6d-9e0f-1a2b3c4d5e6f"
_ENTRA = {**{k: v for k, v in _BASE.items() if k != "user"}, "auth": "entra", "client_id": _CLIENT_ID}


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _connector():
    from erebus_pro.connectors.mssql import MssqlConnector
    return MssqlConnector(licensed(["connectors.mssql"]))


def _error(fn):
    try:
        fn()
    except (ConnectorError, DriverMissing) as exc:
        return exc
    return None


def _kind(fn):
    exc = _error(fn)
    return getattr(exc, "kind", None)


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


class _Capture:
    """Swap ``pymssql.connect`` for a recorder that refuses, noting the FreeTDS
    configuration it would have read."""

    def __enter__(self):
        import pymssql
        self.calls, self.confs = [], []
        self.real = pymssql.connect

        def capture(**kwargs):
            self.calls.append(kwargs)
            path = os.environ.get("FREETDSCONF", "")
            text = Path(path).read_text(encoding="utf-8") if os.path.isfile(path) else ""
            ca = re.search(r"ca file = (.+)", text)
            self.confs.append({"path": path, "text": text,
                               "dir_mode": stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) if path else None,
                               "mode": stat.S_IMODE(os.stat(path).st_mode) if text else None,
                               "ca": Path(ca.group(1)).read_text(encoding="utf-8") if ca else None})
            raise pymssql.OperationalError((20009, b"DB-Lib error message 20009, severity 9:\nUnable to connect: "
                                                   b"Adaptive Server is unavailable (db.zq.test:1433)\n"))
        pymssql.connect = capture
        return self

    def __exit__(self, *_exc):
        import pymssql
        pymssql.connect = self.real


def _sent(settings, secrets):
    with _Capture() as cap:
        exc = _error(lambda: _connector().connect(settings, secrets))
    return exc, (cap.calls[0] if cap.calls else None), (cap.confs[0] if cap.confs else None)


def _conf(text):
    """The FreeTDS configuration as {section: {key: value}}."""
    out, section = {}, None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = out.setdefault(line[1:-1], {})
        elif "=" in line and section is not None:
            key, value = line.split("=", 1)
            section[key.strip()] = value.strip()
    return out


def _check_driver_params():
    with _env(SSL_CERT_FILE=None):
        exc, kw, conf = _sent(_BASE, {"password": "Pw-zq-never-shown"})
    check("a refused connection is 'unreachable', with fixed text, not chained",
          exc.kind == "unreachable" and exc.__cause__ is None and exc.__suppress_context__
          and "db.zq.test" not in _shown(exc) and "Pw-zq" not in _shown(exc))
    check("SQL logins go through pymssql with the user, password and database",
          (kw["user"], kw["password"], kw["database"]) == ("erebus_sync", "Pw-zq-never-shown", "crm"))
    check("... asking for read-only intent (ApplicationIntent=ReadOnly), tagged, failing fast",
          kw["read_only"] is True and kw["appname"] == "erebus-sync" and kw["login_timeout"] == 10
          and kw["timeout"] == 600 and kw["autocommit"] is True)
    sections = _conf(conf["text"])
    check("FreeTDS gets one section, named by host (pymssql asks for host:port, FreeTDS then drops the port)",
          list(sections) == ["db.zq.test"] and (kw["server"], kw["port"]) == ("db.zq.test", "1433"))
    section = sections["db.zq.test"]
    check("... which dials the checked address, never the name",
          (section["host"], section["port"]) == ("127.0.0.1", "1433"))
    check("verify-full: TLS required, the certificate verified and its name checked against host",
          section["encryption"] == "require" and kw["encryption"] == "require" and section["tds version"] == "7.4"
          and section["check certificate hostname"] == "yes" and section["certificate hostname"] == "db.zq.test"
          and conf["ca"] and "-----BEGIN CERTIFICATE-----" in conf["ca"])
    check("the configuration is private and holds no credential",
          conf["dir_mode"] == 0o700 and conf["mode"] == 0o600 and "Pw-zq" not in conf["text"]
          and "erebus_sync" not in conf["text"])
    check("... and is emptied once connect returns",
          not os.path.isfile(conf["path"]) or Path(conf["path"]).read_text(encoding="utf-8") == "")

    _, _, conf = _sent({**_BASE, "sslmode": "verify-ca"}, {"password": "x"})
    section = _conf(conf["text"])["db.zq.test"]
    check("verify-ca: the certificate verified, no name check",
          section["check certificate hostname"] == "no" and "certificate hostname" not in section and conf["ca"])
    _, kw, conf = _sent({**_BASE, "sslmode": "require"}, {"password": "x"})
    section = _conf(conf["text"])["db.zq.test"]
    check("require: TLS without verification", section["encryption"] == "require" and "ca file" not in section)
    _, kw, conf = _sent({**_BASE, "sslmode": "disable"}, {"password": "x"})
    section = _conf(conf["text"])["db.zq.test"]
    check("disable: no TLS asked for", section["encryption"] == "off" and kw["encryption"] == "off")
    _, kw, conf = _sent({**_BASE, "port": 14330}, {"password": "x"})
    check("another port is dialled",
          _conf(conf["text"])["db.zq.test"]["port"] == "14330" and kw["port"] == "14330")


def _check_settings():
    bad = {"database name with brackets": {"database": "crm]; DROP DATABASE x"},
           "user with a semicolon": {"user": "a;b"}, "sslmode prefer": {"sslmode": "prefer"},
           "unknown auth mode": {"auth": "kerberos"}, "port as text": {"port": "1433"},
           "Entra client id that is not a GUID": {"auth": "entra", "client_id": "app;PWD=x"},
           "Entra with verify-ca (the ODBC driver checks both or neither)": {**_ENTRA, "sslmode": "verify-ca"},
           "Entra without TLS": {**_ENTRA, "sslmode": "disable"}}
    for case, over in bad.items():
        with _Capture() as cap:
            kind = _kind(lambda over=over: _connector().connect({**_BASE, **over}, {"password": "x",
                                                                                   "client_secret": "x"}))
        check(f"a {case} is a settings error, before dialling", kind == "settings" and not cap.calls)
    exc, kw, _ = _sent({k: v for k, v in _BASE.items() if k != "database"}, {"password": "x"})
    check("a database is required", exc.kind == "settings" and kw is None)
    exc, kw, _ = _sent(_BASE, {})
    check("no password is an auth error, before dialling", exc.kind == "auth" and kw is None)
    try:
        _connector().connect({k: v for k, v in _BASE.items() if k != "hostaddr"}, {"password": "x"})
        refused = False
    except ValueError:
        refused = True
    check("refuses to dial without a checked hostaddr", refused)


def _check_error_classes():
    import pymssql
    from erebus_pro.connectors._mssql_drivers import pymssql_kind

    def kind(code, text, connecting=False):
        return pymssql_kind(pymssql.OperationalError((code, text)), connecting=connecting)
    server = b"DB-Lib error message 20018, severity 14:\nGeneral SQL Server error: Check messages from the SQL Server\n"
    check("a server message decides: login failed is 'auth'", kind(18456, b"Login failed for user 'x'." + server,
                                                                  connecting=True) == "auth")
    check("... a denied write or read is 'permission'", kind(229, b"The INSERT permission was denied." + server)
          == "permission")
    check("... an unknown object is 'query'", kind(208, b"Invalid object name 'x'." + server) == "query")
    check("a failure only FreeTDS reports ignores the stale server number pymssql carries",
          kind(18456, b"DB-Lib error message 20009, severity 9:\nUnable to connect\n", connecting=True)
          == "unreachable" and kind(229, b"DB-Lib error message 20047, severity 9:\nDBPROCESS is dead\n")
          == "unreachable")
    azure = {40531: (b"Server name cannot be determined.", "auth"),
             40532: (b"Cannot open server \"zq\" requested by the login. The login failed.", "auth"),
             40615: (b"Cannot open server 'zq' requested by the login. Client with IP address '203.0.113.7' is not "
                     b"allowed to access the server.", "permission")}
    check("Azure SQL refusing the server named in the login (40531, 40532) is 'auth', its firewall (40615) "
          "'permission'", all(kind(code, text + server, connecting=True) == want
                              for code, (text, want) in azure.items()))


def _check_tds_environment():
    with _env(TDSHOST="203.0.113.9", TDSPORT="1", TDSDUMP="/tmp/erebus-zq-tds.log", FREETDSCONF="/nonexistent"):
        _, _, conf = _sent(_BASE, {"password": "x"})
        leaked = {k for k in ("TDSHOST", "TDSPORT", "TDSDUMP") if k in os.environ}
    check("FreeTDS reads the connector's configuration, and no TDS variable redirects or dumps the session",
          conf["text"] and not leaked and not os.path.exists("/tmp/erebus-zq-tds.log"))


# --- TLS against the name, on a TLS-only TDS listener ---------------------------------

def _dial(port, events, host, sslmode="verify-full"):
    """Connect through the listener; return (error kind, what the listener saw)."""
    events.clear()
    settings = {**_BASE, "host": host, "port": port, "sslmode": sslmode}
    kind = _kind(lambda: _connector().connect(settings, {"password": "Pw-zq-tls"}))
    for _ in range(100):
        if any(e in ("login", "failed") for e, _ in events):
            break
        time.sleep(0.05)
    logins = [detail for e, detail in events if e == "login"]
    return kind, logins


def _check_tls(ca):
    tmp = tempfile.TemporaryDirectory()
    ca_file = os.path.join(tmp.name, "ca.pem")
    Path(ca_file).write_text(ca.pem, encoding="utf-8")
    try:
        with tds_listener(ca, "db.zq.test") as (port, events):
            with _env(SSL_CERT_FILE=ca_file, TDSHOST="203.0.113.9"):
                kind, logins = _dial(port, events, "db.zq.test")
                check("verify-full: the checked address is dialled and the password sent once the certificate "
                      "matches host", kind == "unreachable" and len(logins) == 1)
                check("... the login asks for read-only intent, as the configured user, tagged erebus-sync",
                      logins[0]["read_only"] is True and logins[0]["user"] == "erebus_sync"
                      and logins[0]["app"] == "erebus-sync")
                kind, logins = _dial(port, events, "other.zq.test")
                check("verify-full: a certificate for another name gets no password", kind == "unreachable"
                      and not logins)
                kind, logins = _dial(port, events, "other.zq.test", "verify-ca")
                check("verify-ca: the chain is checked, the name is not", len(logins) == 1)
            with _env(SSL_CERT_FILE=None):
                kind, logins = _dial(port, events, "db.zq.test")
                check("verify-full: a certificate from a CA the system does not trust gets no password",
                      kind == "unreachable" and not logins)
                kind, logins = _dial(port, events, "db.zq.test", "verify-ca")
                check("verify-ca: an untrusted chain gets no password", not logins)
                kind, logins = _dial(port, events, "other.zq.test", "require")
                check("require: TLS without verification", len(logins) == 1)
    finally:
        tmp.cleanup()


# --- Entra through mssql-python (a stand-in module) -----------------------------------

def _parse_odbc(text):
    """An ODBC connection string as {key: value}, braces unescaped."""
    out, i = {}, 0
    while i < len(text):
        eq = text.index("=", i)
        key = text[i:eq]
        i = eq + 1
        if text[i] == "{":
            j, value = i + 1, ""
            while True:
                if text[j] == "}" and text[j + 1:j + 2] == "}":
                    value, j = value + "}", j + 2
                elif text[j] == "}":
                    break
                else:
                    value, j = value + text[j], j + 1
            i = j + 1
        else:
            j = text.find(";", i)
            j = len(text) if j < 0 else j
            value, i = text[i:j], j
        out[key] = value
        i += 1 if i < len(text) and text[i] == ";" else 0
    return out


class _FakeCursor:
    def __init__(self, conn):
        self.conn, self._rows = conn, []

    def execute(self, query):
        self.conn.statements.append(query)
        if self.conn.fail_queries:
            raise self.conn.module.ProgrammingError("Driver Error: Syntax error or access violation; DDBC Error: "
                                                    "The SELECT permission was denied on the object 'customers', "
                                                    "database 'crm', schema 'sales'.")
        if "INFORMATION_SCHEMA.COLUMNS" in query:
            self._rows = [("sales", "customers", "id", "int", "NO", None), ("sales", "customers", "email",
                                                                             "nvarchar", "YES", 200),
                          ("sys_zq", "t", "x", "int", "YES", None)]
        elif "TABLE_CONSTRAINTS" in query:
            self._rows = [("sales", "customers", "id")]
        else:
            self._rows = [(0, "zq@acme.example")]

    def fetchmany(self, size=1):
        rows, self._rows = self._rows[:size], self._rows[size:]
        return rows

    def close(self):
        pass


class _FakeConnection:
    def __init__(self, module):
        self.module, self.statements, self.fail_queries, self.timeout = module, [], False, 0

    def cursor(self):
        return _FakeCursor(self)

    def close(self):
        pass


def _fake_mssql_python():
    module = types.ModuleType("mssql_python")

    class Error(Exception):
        pass

    class DatabaseError(Error):
        pass

    class OperationalError(DatabaseError):
        pass

    class ProgrammingError(DatabaseError):
        pass

    module.Error, module.DatabaseError = Error, DatabaseError
    module.OperationalError, module.ProgrammingError = OperationalError, ProgrammingError
    module.calls, module.refuse = [], None

    def connect(connection_str="", autocommit=False, attrs_before=None, timeout=0, **kwargs):
        module.calls.append({"keys": _parse_odbc(connection_str), "autocommit": autocommit, "timeout": timeout,
                             "attrs_before": attrs_before, "kwargs": kwargs})
        if module.refuse is not None:
            raise module.refuse
        module.conn = _FakeConnection(module)
        return module.conn
    module.connect = connect
    return module


@contextlib.contextmanager
def _driver(module):
    saved = sys.modules.get("mssql_python", "absent")
    sys.modules["mssql_python"] = module
    try:
        yield module
    finally:
        if saved == "absent":
            sys.modules.pop("mssql_python", None)
        else:
            sys.modules["mssql_python"] = saved


def _check_entra():
    secret = "Sec;ret}zq=" + os.urandom(4).hex()
    with _driver(None):
        with _Capture() as cap:
            exc = _error(lambda: _connector().connect(_ENTRA, {"client_secret": secret}))
    check("Entra without mssql-python fails naming the extra to install, unretried",
          isinstance(exc, DriverMissing) and str(exc) == "requires the erebus-pro[mssql-entra] extra"
          and exc.__cause__ is None and secret not in _shown(exc) and not cap.calls)

    with _driver(_fake_mssql_python()) as fake, _Capture() as cap:
        src = _connector().connect(_ENTRA, {"client_secret": secret})
        call = fake.calls[0]
        keys = call["keys"]
        check("Entra goes through mssql-python, never pymssql", not cap.calls and len(fake.calls) == 1)
        check("... as the service principal (client id and secret)",
              keys["Authentication"] == "ActiveDirectoryServicePrincipal" and keys["UID"] == _CLIENT_ID
              and keys["PWD"] == secret)
        check("... naming the host as the server and dialling the checked address (Addr), the database named",
              keys["Server"] == "tcp:db.zq.test,1433" and keys["Addr"] == "tcp:127.0.0.1,1433"
              and keys["Database"] == "crm")
        check("... encrypted, the certificate verified and checked against host",
              keys["Encrypt"] == "yes" and keys["TrustServerCertificate"] == "no"
              and keys["HostNameInCertificate"] == "db.zq.test")
        check("... with read-only intent, no retries, a login timeout, and no Driver or APP (mssql-python owns them)",
              keys["ApplicationIntent"] == "ReadOnly" and keys["ConnectRetryCount"] == "0"
              and call["timeout"] == 10 and call["autocommit"] is True and not {"Driver", "APP"} & set(keys))
        check("... and a statement timeout", fake.conn.timeout == 600)
        names = [c.name for c in src.list_collections()]
        check("lists the collections from INFORMATION_SCHEMA", names == ["sales.customers", "sys_zq.t"])
        fields = {f.name: f for f in src.list_fields("sales.customers")}
        check("... with types, nullability and the primary key", fields["id"].primary_key
              and fields["email"].db_type == "nvarchar(200)" and fields["email"].nullable)
        got = list(sources.distinct_groups(src, "sales.customers", [["email"]], 10))
        check("distinct values come from one query per table", got == [(0, ("zq@acme.example",))]
              and sum("SELECT DISTINCT" in s for s in fake.conn.statements) == 1)
        check("only single SELECT statements are sent", all(_READ.fullmatch(s) for s in fake.conn.statements))
        fake.conn.fail_queries = True
        exc = _error(lambda: list(src.iter_records("sales.customers")))
        check("a refused read is a fixed 'permission' error", exc.kind == "permission"
              and "customers" not in _shown(exc) and exc.__cause__ is None)
        src.close()

        fake.calls.clear()
        _connector().connect({**_ENTRA, "sslmode": "require"}, {"client_secret": secret}).close()
        keys = fake.calls[0]["keys"]
        check("Entra require: encrypted, the certificate not verified",
              keys["Encrypt"] == "yes" and keys["TrustServerCertificate"] == "yes"
              and "HostNameInCertificate" not in keys)
        _connector().connect({**_ENTRA, "host": "zqserver.database.windows.net", "hostaddr": "2001:db8::5"},
                             {"client_secret": secret}).close()
        keys = fake.calls[1]["keys"]
        check("Entra on Azure SQL: the server named, an IPv6 address dialled, the certificate checked "
              "against the zone's wildcard", keys["Server"] == "tcp:zqserver.database.windows.net,1433"
              and keys["Addr"] == "tcp:[2001:db8::5],1433"
              and keys["HostNameInCertificate"] == "*.database.windows.net")

        sql = "DDBC Error: [Microsoft][ODBC Driver 18 for SQL Server][SQL Server]"
        cases = [("a rejected secret", "auth", "Driver Error: Invalid authorization specification; DDBC Error: Login "
                  "failed for user '<token-identified principal>'. AADSTS7000215: Invalid client secret"),
                 ("Azure SQL refusing the server named (40532)", "auth", "Driver Error: Server rejected the "
                  f"connection; {sql}Cannot open server \"zq\" requested by the login. The login failed."),
                 ("Azure SQL not finding the server name (40531)", "auth", "Driver Error: Client unable to establish "
                  f"connection; {sql}Server name cannot be determined. It must appear as the first segment of the "
                  "server's dns name (servername.database.windows.net)."),
                 ("Azure SQL's firewall (40615)", "permission", "Driver Error: Invalid authorization specification; "
                  f"{sql}Cannot open server 'zq' requested by the login. Client with IP address '203.0.113.7' is not "
                  "allowed to access the server."),
                 ("a refused TCP connection", "unreachable", "Driver Error: Client unable to establish connection; "
                  "DDBC Error: TCP Provider: Error code 0x2749 (db.zq.test)")]
        for case, kind, text in cases:
            fake.refuse = fake.OperationalError(f"{text} {secret}")
            exc = _error(lambda: _connector().connect(_ENTRA, {"client_secret": secret}))
            check(f"Entra: {case} is a fixed '{kind}' error without the secret, host or driver text",
                  exc.kind == kind and exc.__cause__ is None and exc.__suppress_context__
                  and not any(h in _shown(exc) for h in (secret, "db.zq.test", "AADSTS", "TCP Provider", "zq'")))
        exc = _error(lambda: _connector().connect({**_ENTRA, "client_id": None}, {"client_secret": secret}))
        check("Entra needs a client id", exc.kind == "settings")
        fake.refuse = None
        exc = _error(lambda: _connector().connect(_ENTRA, {}))
        check("Entra without a client secret is an auth error, before dialling",
              exc.kind == "auth" and len(fake.calls) == 7)


def _check_packaging():
    with open(_ROOT / "pro" / "pyproject.toml", "rb") as fh:
        project = tomllib.load(fh)["project"]
    deps = " ".join(project["dependencies"]).lower()
    extra = project["optional-dependencies"].get("mssql-entra", [])
    check("pymssql is a dependency: it ships in the image", "pymssql" in deps)
    check("mssql-python is only the optional extra mssql-entra", "mssql-python" not in deps
          and len(extra) == 1 and extra[0].startswith("mssql-python"))
    installs = " ".join(line for line in (_ROOT / "deploy" / "Dockerfile").read_text(encoding="utf-8").splitlines()
                        if "pip install" in line or line.strip().startswith("&&"))
    check("the image installs erebus-pro without the mssql-entra extra",
          "./pro" in installs and "mssql-entra" not in installs and "mssql-python" not in installs)
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    check("CI does not install the extra either (its driver comes under Microsoft's license)",
          "mssql-entra" not in ci and "mssql-python" not in ci)


# --- live --------------------------------------------------------------------------

def _check_live(b):
    src = b.connector().connect(b.settings(), b.secrets())
    try:
        encrypted, program = b.session(src)
        check("the session is encrypted and tagged erebus-sync", encrypted is True and program == "erebus-sync")
        coll = b.collection("customers")
        types_ = {f.name: f.db_type for f in src.list_fields(coll)}
        check("db types as SQL Server names them", types_["id"] == "int" and types_["email"] == "nvarchar(200)"
              and types_["notes"] == "ntext" and types_["signup"] == "date" and types_["active"] == "bit")
        admin = b.admin_cursor()
        admin.execute("UPDATE crm.customers SET notes = %s WHERE id = 4", ("Zyx " * 1500,))
        admin.execute("UPDATE crm.customers SET notes = %s WHERE id = 3", ("x" * 3999 + "é",))
        notes = {row[0] for row in sources.distinct_values(src, coll, ["notes"], 100)}
        check("text values are read up to 4,000 characters; longer ones are skipped",
              notes == {"vip", "x" * 3999 + "é"})
        record = next(r for r in src.iter_records(coll) if r.record_ref == f"{coll}:4")
        check("sample rows read long text cut at 4,000 characters", record.values["notes"] == ("Zyx " * 1000))
        dates = set(sources.distinct_values(src, coll, ["signup"], 10))
        check("dates read as ISO text", ("2026-01-02",) in dates)
    finally:
        src.close()
    settings, secrets = b.least_privileged()
    src = b.connector().connect(settings, secrets)
    try:
        check("with the README's grants only the granted table is listed",
              [c.name for c in src.list_collections()] == [b.collection("customers")])
        check("... and its distinct values read",
              len(list(sources.distinct_values(src, b.collection("customers"), ["email"], 10))) == 3)
    finally:
        src.close()


def main():
    print("\n=== MSSQL / Azure SQL connector (spec 015) ===\n")
    try:
        import pymssql  # noqa: F401
    except ImportError:
        if os.environ.get("EREBUS_REQUIRE_MSSQL") == "1":
            raise
        print("  - skipped (pymssql is not installed)")
        return
    _check_packaging()
    _check_settings()
    _check_driver_params()
    _check_error_classes()
    _check_tds_environment()
    _check_tls(TestCa())
    _check_entra()
    b = MssqlBackend()
    reason = b.unavailable()
    if reason:
        if os.environ.get("EREBUS_REQUIRE_MSSQL") == "1":
            raise AssertionError(reason)
        print(f"  - live checks skipped ({reason})")
    else:
        b.setup()
        try:
            _check_live(b)
        finally:
            b.teardown()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
