# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""An Oracle listener's redirect against the sync worker.

python-oracledb in thin mode follows a listener's REDIRECT before it signs in: it dials
whatever address the listener sends (a RAC SCAN listener does so by design). A fake
listener stands in for the database and answers the connect packet with a redirect to a
second listener. Outside the worker the driver dials it; in a sync job only the address
the worker checked may be dialled, so the redirect is refused, the job fails as denied
and the second listener is never reached. A redirect to the cloud metadata address is
refused the same way.

Needs oracledb; the job part also needs Postgres on a throwaway database
(``EREBUS_PG_DSN``) and erebus-pro's connector types, skipped without them unless
``EREBUS_REQUIRE_ORACLE=1``.
"""
import contextlib
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "tests", "gateway"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from _pg import temp_database
from warehouse_backends import licensed

from erebus.cataloging import connector_types
from erebus.cataloging.connector_errors import ConnectorError

_passed = 0
_SETTINGS = {"host": "127.0.0.1", "service_name": "CRMPDB", "user": "EREBUS_SYNC", "sslmode": "disable"}
_SECRETS = {"password": "Pw-zq-redirect"}


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _packet(kind, body):
    """A TNS packet: length, checksum, type, flags, header checksum, then the body."""
    return struct.pack(">HHBBH", 8 + len(body), 0, kind, 0, 0) + body


@contextlib.contextmanager
def _serve(handle):
    """A listener on 127.0.0.1 noting each connection as it is accepted, then handing it to
    ``handle``; yields (port, accepted)."""
    srv = socket.create_server(("127.0.0.1", 0))
    seen = []

    def serve(conn):
        with conn:
            handle(conn)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            seen.append("accepted")
            threading.Thread(target=serve, args=(conn,), daemon=True).start()
    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1], seen
    finally:
        srv.close()
        thread.join(2)


def _redirect_to(host, port):
    """A handler answering the connect packet with a REDIRECT to ``host:port``: the
    redirect packet carries the data length, a data packet the address and descriptor."""
    data = (f"(ADDRESS=(PROTOCOL=TCP)(HOST={host})(PORT={port}))\x00"
            "(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=CRMPDB)))").encode()

    def handle(conn):
        conn.settimeout(5)
        try:
            conn.recv(4096)
            conn.sendall(_packet(5, struct.pack(">H", len(data))) + _packet(6, b"\x00\x00" + data))
            conn.recv(1)  # until the client hangs up
        except OSError:
            pass
    return handle


def _target(conn):
    conn.settimeout(5)
    try:
        conn.recv(4096)
    except OSError:
        pass


def _accepted(seen, count):
    """Whether a listener accepted exactly ``count`` connections (waiting up to 3 seconds
    for one to show, and a moment longer for a stray one)."""
    for _ in range(60):
        if len(seen) >= count:
            break
        time.sleep(0.05)
    time.sleep(0.2)
    return len(seen) == count


def _connector():
    from erebus_pro.connectors.oracle import OracleConnector
    return OracleConnector(licensed(["connectors.oracle"]))


def _kind(fn):
    try:
        fn()
    except ConnectorError as exc:
        return exc.kind
    return None


def _check_driver_follows():
    with _serve(_target) as (target, reached), _serve(_redirect_to("127.0.0.1", target)) as (port, redirected):
        kind = _kind(lambda: _connector().connect({**_SETTINGS, "hostaddr": "127.0.0.1", "port": port}, _SECRETS))
        check("outside the worker the driver follows a listener's redirect (what the worker must stop)",
              _accepted(redirected, 1) and _accepted(reached, 1) and kind == "unreachable")


def _run_job(dsn, port):
    """Run one sample job for an Oracle source at 127.0.0.1:``port``; return the job row."""
    import psycopg
    from psycopg_pool import ConnectionPool
    from sync_fakes import config

    from erebus.gateway.connectors import jobs, sources
    from erebus.gateway.crypto.keyprovider import LocalKms
    from erebus.gateway.store import db
    from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
    from erebus.sync.worker import Worker

    conn = psycopg.connect(dsn)
    db.run_migrations(conn)
    conn.commit()
    kms = LocalKms()
    pool = ConnectionPool(dsn, min_size=1, max_size=3, open=True)
    try:
        scope_id = provision_scope(conn, kms, "tenant-oracle-redirect")
        source_id = sources.create_source(conn, open_scope_crypto(conn, kms, scope_id), scope_id, name="erp",
                                          connector_type="oracle", settings={**_SETTINGS, "port": port},
                                          secrets=_SECRETS)
        job, _ = jobs.enqueue(conn, scope_id, source_id, "sample")
        conn.commit()
        Worker(config(dsn), pool=pool, provider=kms, connectors={"oracle": _connector()}.get).run_once()
        return jobs.get_job(conn, scope_id, job.id)
    finally:
        pool.close()
        conn.close()


def _check_job(dsn):
    with _serve(_target) as (target, reached), _serve(_redirect_to("127.0.0.1", target)) as (port, redirected):
        job = _run_job(dsn, port)
        check("in a sync job the checked listener is dialled", _accepted(redirected, 1))
        check("... its redirect to another address is refused: the target is never reached", _accepted(reached, 0))
        check("... and the job fails as denied, unretried",
              job.status == "failed" and job.attempts == 1 and job.error == "source address is not allowed")


def _check_guard():
    from erebus.sync import egress
    from erebus.sync.netpolicy import NetworkPolicy, PolicyError, parse_hosts

    egress.install()
    policy = NetworkPolicy(denied=parse_hosts("169.254.0.0/16"))
    oracle = connector_types.get("oracle") or connector_types.ConnectorType("oracle", "database", "pro",
                                                                            frozenset(), 1521)
    for host, port, why in (("127.0.0.1", None, "another port on the checked address"),
                            ("169.254.169.254", 80, "the cloud metadata address")):
        with _serve(_target) as (target, reached), \
                _serve(_redirect_to(host, port or target)) as (listener, redirected):
            settings = {**_SETTINGS, "hostaddr": "127.0.0.1", "port": listener}
            guard = egress.Guard.for_source(policy, oracle, settings)
            try:
                guard.call(_connector().connect, settings, _SECRETS)
                kind = None
            except PolicyError as exc:
                kind = exc.kind
            check(f"a redirect to {why} is refused as denied", kind == "denied" and _accepted(redirected, 1)
                  and _accepted(reached, 0))


def main():
    print("\n=== Oracle listener redirects against the sync worker ===\n")
    try:
        import oracledb  # noqa: F401
    except ImportError:
        if os.environ.get("EREBUS_REQUIRE_ORACLE") == "1":
            raise
        print("  - skipped (oracledb is not installed)")
        return
    _check_driver_follows()
    with temp_database("oracle_redirect") as dsn:
        reason = None
        if dsn is None:
            reason = "EREBUS_PG_DSN is not set"
        elif connector_types.get("oracle") is None:
            reason = "erebus-pro is not installed (pip install -e ./pro)"
        if reason:
            if os.environ.get("EREBUS_REQUIRE_ORACLE") == "1":
                raise AssertionError(reason)
            print(f"  - job checks skipped ({reason})")
        else:
            _check_job(dsn)
    _check_guard()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
