# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The Oracle connector at the driver boundary and on a live database (spec 015
"Warehouse connectors", "Security").

python-oracledb in thin mode. The connector dials the address the sync worker checked
(``hostaddr``) and checks TLS against ``host``: by default TCPS with the certificate
verified and its name matched during the handshake; ``verify-ca``, ``require`` and
``disable`` relax that as for Postgres; there is no ``prefer``. A wallet (``wallet_pem``)
adds mutual TLS and, with ``auth: wallet``, signs in by certificate alone; it is written
to a private temporary directory only while connecting. No connect string or worker
file is used. Settings that reach the driver are plain names, checked here.

Driver-boundary and TLS checks always run (a local TLS listener stands in for the
database). The live checks need the throwaway database named by
``EREBUS_TEST_ORACLE_DSN`` (skipped without it unless ``EREBUS_REQUIRE_ORACLE=1``):
thin mode, Oracle-maintained schemas left out, a write refused before any read, CLOB
values over 1,000 characters skipped, the session tagged, and the README's
least-privilege grants enough to sync.
"""
import contextlib
import datetime
import os
import ssl
import stat
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oracle_backend import CRM, OracleBackend
from warehouse_backends import licensed

from erebus.cataloging import sources
from erebus.cataloging.connector_errors import ConnectorError

_passed = 0
_BASE = {"host": "db.zq.test", "hostaddr": "127.0.0.1", "port": 1521, "service_name": "CRMPDB", "user": "EREBUS_SYNC"}


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _connector():
    from erebus_pro.connectors.oracle import OracleConnector
    return OracleConnector(licensed(["connectors.oracle"]))


def _kind(fn):
    try:
        fn()
    except ConnectorError as exc:
        return exc.kind
    return None


class _Capture:
    """Swap ``oracledb.connect`` for a recorder that refuses, noting the wallet it saw."""

    def __enter__(self):
        import oracledb
        self.calls, self.wallets = [], []
        self.real = oracledb.connect

        def capture(**kwargs):
            self.calls.append(kwargs)
            where = kwargs.get("wallet_location")
            if where:
                pem = os.path.join(where, "ewallet.pem")
                with open(pem, encoding="utf-8") as fh:
                    content = fh.read()
                self.wallets.append((where, stat.S_IMODE(os.stat(where).st_mode), stat.S_IMODE(os.stat(pem).st_mode),
                                     content))
            raise oracledb.OperationalError("DPY-6005: cannot connect to database (CONNECTION_ID=zq)")
        oracledb.connect = capture
        return self

    def __exit__(self, *_exc):
        import oracledb
        oracledb.connect = self.real


def _sent(settings, secrets):
    with _Capture() as cap:
        kind = _kind(lambda: _connector().connect(settings, secrets))
    return kind, (cap.calls[0] if cap.calls else None), cap.wallets


def _check_driver_params():
    kind, kw, _ = _sent(_BASE, {"password": "Pw-zq-never-shown"})
    check("a refused connection is 'unreachable'", kind == "unreachable")
    check("dials the checked address, port and service name, never a connect string",
          (kw["host"], kw["port"], kw["service_name"]) == ("127.0.0.1", 1521, "CRMPDB")
          and not {"dsn", "config_dir", "params"} & set(kw))
    check("TCPS by default", kw["protocol"] == "tcps")
    ctx = kw["ssl_context"]
    check("... the certificate verified, and its name checked against host in the handshake",
          ctx.verify_mode == ssl.CERT_REQUIRED and getattr(ctx, "server_name", None) == "db.zq.test"
          and kw["ssl_server_dn_match"] is False)
    check("signs in with the user and password", kw["user"] == "EREBUS_SYNC" and kw["password"] == "Pw-zq-never-shown"
          and not kw.get("externalauth"))
    check("tags the session and fails fast", kw["program"] == "erebus-sync" and kw["tcp_connect_timeout"] == 10
          and kw["retry_count"] == 0)

    _, kw, _ = _sent({**_BASE, "sslmode": "verify-ca"}, {"password": "x"})
    check("verify-ca: the certificate verified, no name check",
          kw["ssl_context"].verify_mode == ssl.CERT_REQUIRED and not getattr(kw["ssl_context"], "server_name", None)
          and kw["ssl_server_dn_match"] is False)
    _, kw, _ = _sent({**_BASE, "sslmode": "require"}, {"password": "x"})
    check("require: TLS without verification", kw["protocol"] == "tcps"
          and kw["ssl_context"].verify_mode == ssl.CERT_NONE and kw["ssl_server_dn_match"] is False)
    _, kw, _ = _sent({**_BASE, "sslmode": "disable"}, {"password": "x"})
    check("disable: plain TCP", kw["protocol"] == "tcp" and "ssl_context" not in kw)


def _check_settings():
    bad = {"service name with connect-descriptor syntax": {"service_name": "X)(HOST=evil.example"},
           "user with proxy syntax": {"user": "a[b]"}, "sslmode prefer": {"sslmode": "prefer"},
           "unknown auth mode": {"auth": "kerberos"}, "port as text": {"port": "1521"}}
    for case, over in bad.items():
        with _Capture() as cap:
            kind = _kind(lambda over=over: _connector().connect({**_BASE, **over}, {"password": "x"}))
        check(f"a {case} is a settings error, before dialling", kind == "settings" and not cap.calls)
    kind, kw, _ = _sent({k: v for k, v in _BASE.items() if k != "service_name"}, {"password": "x"})
    check("a service name is required", kind == "settings" and kw is None)
    kind, kw, _ = _sent(_BASE, {})
    check("no password is an auth error, before dialling", kind == "auth" and kw is None)
    kind, kw, _ = _sent({**_BASE, "sslmode": "disable"}, {"password": "x", "wallet_pem": _ca().pem})
    check("a wallet over plain TCP is a settings error", kind == "settings" and kw is None)


def _check_wallet():
    pem = _ca().pem
    kind, kw, wallets = _sent(_BASE, {"password": "x", "wallet_pem": pem, "wallet_password": "Wp-zq"})
    where, dir_mode, file_mode, seen = wallets[0]
    check("a wallet is written as ewallet.pem in a private directory while connecting",
          seen == pem and dir_mode == 0o700 and file_mode == 0o600 and kw["wallet_password"] == "Wp-zq")
    check("... and removed when connect returns, even after a failure",
          kind == "unreachable" and not os.path.exists(where))
    kind, kw, wallets = _sent({**_BASE, "auth": "wallet"}, {"wallet_pem": pem})
    check("auth: wallet signs in by certificate alone (external authentication)",
          kw["externalauth"] is True and "password" not in kw and "user" not in kw and kw["protocol"] == "tcps")
    kind, kw, _ = _sent({**_BASE, "auth": "wallet"}, {"password": "x"})
    check("auth: wallet without a wallet is an auth error", kind == "auth" and kw is None)
    kind, kw, _ = _sent(_BASE, {"password": "x", "wallet_pem": "not a wallet zq"})
    check("a wallet that is not PEM is an auth error", kind == "auth" and kw is None)


# --- TLS against the name, on a local listener ------------------------------------

class _Ca:
    def __init__(self):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        self._x509, self._hashes, self._ser, self._ec = x509, hashes, serialization, ec
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Erebus Test CA zq")])
        self.cert = self._build(name, name, self.key.public_key(), ca=True)
        self.pem = self.cert.public_bytes(serialization.Encoding.PEM).decode()

    def _build(self, subject, issuer, public_key, *, ca=False, dns=None, client=False):
        x509 = self._x509
        now = datetime.datetime.now(datetime.UTC)
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(public_key)
                   .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
                   .not_valid_after(now + datetime.timedelta(hours=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if dns:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
        if client:
            builder = builder.add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        if ca:
            builder = builder.add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False),
                                            critical=True)
        return builder.sign(self.key, self._hashes.SHA256())

    def issue(self, cn, *, client=False):
        """(key PEM, cert PEM) for ``cn`` signed by this CA."""
        key = self._ec.generate_private_key(self._ec.SECP256R1())
        subject = self._x509.Name([self._x509.NameAttribute(self._x509.oid.NameOID.COMMON_NAME, cn)])
        cert = self._build(subject, self.cert.subject, key.public_key(), dns=None if client else cn, client=client)
        return (key.private_bytes(self._ser.Encoding.PEM, self._ser.PrivateFormat.PKCS8,
                                  self._ser.NoEncryption()).decode(),
                cert.public_bytes(self._ser.Encoding.PEM).decode())


_CA = []


def _ca():
    if not _CA:
        _CA.append(_Ca())
    return _CA[0]


@contextlib.contextmanager
def _tls_listener(server_name, *, want_client_cert=False):
    """A TLS listener on 127.0.0.1 with a certificate for ``server_name``; it records each
    handshake (completed, SNI, client certificate subject) and then hangs up."""
    ca = _ca()
    key, cert = ca.issue(server_name)
    tmp = tempfile.TemporaryDirectory()
    chain = os.path.join(tmp.name, "server.pem")
    with open(chain, "w", encoding="utf-8") as fh:
        fh.write(key + cert)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(chain)
    if want_client_cert:
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=ca.pem)
    seen = []
    ctx.sni_callback = lambda _sock, name, _ctx: seen.append(("sni", name))
    import socket
    srv = socket.create_server(("127.0.0.1", 0))
    srv.settimeout(10)

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    peer = tls.getpeercert()
                    seen.append(("done", dict(x[0] for x in peer["subject"])["commonName"] if peer else None))
            except (ssl.SSLError, OSError):
                seen.append(("failed", None))
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1], seen
    finally:
        srv.close()
        thread.join(5)
        tmp.cleanup()


def _dial(port, seen, host, sslmode="verify-full", **secrets):
    """Connect through the listener; return the error kind once the listener has recorded the handshake."""
    seen.clear()
    settings = {**_BASE, "host": host, "port": port, "sslmode": sslmode}
    kind = _kind(lambda: _connector().connect(settings, {"password": "Pw-zq", **secrets}))
    for _ in range(100):
        if any(event in ("done", "failed") for event, _ in seen):
            break
        time.sleep(0.05)
    return kind


def _check_tls():
    ca = _ca().pem
    with _tls_listener("db.zq.test") as (port, seen):
        kind = _dial(port, seen, "db.zq.test", wallet_pem=ca)
        check("verify-full: the handshake to the checked address succeeds for the right name, sent as SNI",
              ("done", None) in seen and ("sni", "db.zq.test") in seen and kind == "unreachable")
        _dial(port, seen, "other.zq.test", wallet_pem=ca)
        check("verify-full: a certificate for another name is refused in the handshake",
              seen == [("sni", "other.zq.test"), ("failed", None)])
        _dial(port, seen, "db.zq.test")
        check("verify-full: a certificate from a CA neither the system nor the wallet trusts is refused",
              seen == [("sni", "db.zq.test"), ("failed", None)])
        _dial(port, seen, "other.zq.test", "verify-ca", wallet_pem=ca)
        check("verify-ca: the chain is checked, the name is not", ("done", None) in seen)
        _dial(port, seen, "other.zq.test", "verify-ca")
        check("verify-ca: an untrusted chain is refused", ("failed", None) in seen and ("done", None) not in seen)
        _dial(port, seen, "other.zq.test", "require")
        check("require: TLS without verification", ("done", None) in seen)
    key, cert = _ca().issue("erebus-sync-client", client=True)
    with _tls_listener("db.zq.test", want_client_cert=True) as (port, seen):
        _dial(port, seen, "db.zq.test", wallet_pem=key + cert + ca)
        check("a wallet's client certificate is presented (mutual TLS)", ("done", "erebus-sync-client") in seen)


# --- live --------------------------------------------------------------------------

def _check_live(b):
    connector = b.connector()
    src = connector.connect(b.settings(), b.secrets())
    try:
        check("the driver runs in thin mode (no Instant Client)", src.conn.thin is True)
        try:
            b.write_probe(src)
            refused = None
        except Exception as exc:
            refused = exc
        check("a write is refused before any read (the connection rests in a read-only transaction)",
              refused is not None and b.is_write_refusal(refused))
        check("every round trip has a call timeout", src.conn.call_timeout == 600_000)
        cur = b.admin_cursor()
        cur.execute("SELECT COUNT(*) FROM V$SESSION WHERE PROGRAM = 'erebus-sync'")
        check("the session is tagged erebus-sync", cur.fetchone()[0] >= 1)
        owners = {c.name.split(".")[0] for c in src.list_collections()}
        check("signed in as SYSTEM, only non-Oracle-maintained schemas are listed",
              owners and owners <= {CRM, "EREBUS_OTHER"} and not owners & {"SYS", "SYSTEM", "XDB", "MDSYS"})
        coll = b.collection("customers")
        types = {f.name: f.db_type for f in src.list_fields(coll)}
        check("db types as Oracle names them", types["id"] == "NUMBER(10,0)" and types["email"] == "VARCHAR2"
              and types["notes"] == "CLOB" and types["signup"] == "DATE" and types["active"] == "BOOLEAN")
        cur.execute(f'UPDATE {CRM}."customers" SET "notes" = :n WHERE "id" = 4', n="Zyx " * 300)
        cur.execute(f'UPDATE {CRM}."customers" SET "notes" = :n WHERE "id" = 3', n="x" * 999 + "é")
        b.admin.commit()
        notes = {row[0] for row in sources.distinct_values(src, coll, ["notes"], 100)}
        check("CLOB values are read up to 1,000 characters; longer ones are skipped",
              notes == {"vip", "x" * 999 + "é"})
        record = next(r for r in src.iter_records(coll) if r.record_ref == f"{coll}:4")
        check("sample rows read a CLOB as text, cut at 1,000 characters", record.values["notes"] == ("Zyx " * 250))
    finally:
        src.close()
    settings, secrets = b.least_privileged()
    src = connector.connect(settings, secrets)
    try:
        check("with the README's grants only the granted table is listed",
              [c.name for c in src.list_collections()] == [b.collection("customers")])
        check("... and its distinct values read", len(list(sources.distinct_values(
            src, b.collection("customers"), ["email"], 10))) == 3)
    finally:
        src.close()


def main():
    print("\n=== Oracle connector (spec 015) ===\n")
    try:
        import oracledb  # noqa: F401
    except ImportError:
        if os.environ.get("EREBUS_REQUIRE_ORACLE") == "1":
            raise
        print("  - skipped (oracledb is not installed)")
        return
    _check_driver_params()
    _check_settings()
    _check_wallet()
    _check_tls()
    b = OracleBackend()
    reason = b.unavailable()
    if reason:
        if os.environ.get("EREBUS_REQUIRE_ORACLE") == "1":
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
