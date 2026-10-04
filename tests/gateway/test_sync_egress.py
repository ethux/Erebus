"""The sync worker's connect guard (spec 015 "Security": network; SC-9).

Pure: local listeners only. The worker installs an audit hook that sees every Python
socket connect. While a job's connector runs (``Guard.call``), a type that dials a host
reaches only the checked ``(hostaddr, port)``; a warehouse type reaches anything off the
deny list and, when an allow list is set, on it (a network, or what a lookup of a listed
name returned during the job); SQLite reaches nothing. Deny-listed addresses, host names,
Unix sockets and the cloud metadata address are refused; threads a connector starts
inherit its guard; concurrent jobs keep their own. Outside a connector call nothing is
refused, so the worker's own connections work. A connector call that fails after a
refusal is the fixed-text, unretried ``denied`` failure. An HTTP connector's transport
asks the job's guard for the one checked address of its host before it connects.
"""
import contextlib
import ipaddress
import os
import socket
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.cataloging import connector_types
from erebus.cataloging.connector_errors import ConnectorError
from erebus.cataloging.connector_types import ConnectorType
from erebus.gateway.connectors import policy as job_policy
from erebus.sync import egress, runner
from erebus.sync.netpolicy import DEFAULT_DENIED_NETWORKS, HostList, NetworkPolicy, PolicyError, parse_hosts

_passed = 0
_PG = connector_types.get("postgres")
_SQLITE = connector_types.get("sqlite")
_WAREHOUSE = ConnectorType("zq-warehouse", "warehouse", "pro", frozenset({"account"}))
# The default networks without loopback, so local listeners stand in for sources.
_NO_LOOPBACK = parse_hosts(",".join(n for n in DEFAULT_DENIED_NETWORKS if n not in ("127.0.0.0/8", "::1/128")))


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _policy(denied=_NO_LOOPBACK, allowed=None):
    return NetworkPolicy(denied=denied, allowed=allowed)


@contextlib.contextmanager
def _listener(host="127.0.0.1", family=socket.AF_INET):
    """A TCP listener recording each connection it accepts; yields (port, accepted)."""
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.bind((host, 0))
    srv.listen(8)
    accepted = []

    def serve():
        while True:
            try:
                conn, peer = srv.accept()
            except OSError:
                return
            accepted.append(peer)
            conn.close()
    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield srv.getsockname()[1], accepted
    finally:
        srv.close()
        thread.join(2)


@contextlib.contextmanager
def _unix_listener():
    with tempfile.TemporaryDirectory(dir="/tmp") as root:
        path = os.path.join(root, "s")
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(path)
        srv.listen(1)
        try:
            yield path
        finally:
            srv.close()


def _count(seen, n):
    """Whether ``seen`` (a listener's accepted connections) reaches ``n`` within a second."""
    for _ in range(100):
        if len(seen) >= n:
            break
        time.sleep(0.01)
    return len(seen) == n


def _dial(addr, family=socket.AF_INET):
    """'ok', 'refused' (the guard) or 'error' (any other OSError) for one connect."""
    sock = socket.socket(family, socket.SOCK_STREAM)
    sock.settimeout(0.5)
    try:
        sock.connect(addr)
        return "ok"
    except egress.Refused:
        return "refused"
    except OSError:
        return "error"
    finally:
        sock.close()


def _in(guard, fn, *args):
    """Run ``fn`` as connector code under ``guard`` (a refusal inside stays a plain result)."""
    return guard.call(fn, *args)


def _ipv6_loopback():
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


def _check_outside_jobs():
    egress.install()
    egress.install()
    guard = egress.Guard(_policy(parse_hosts("127.0.0.0/8")), "host", approved=("127.0.0.1", 9))
    with _listener() as (port, accepted):
        check("outside a connector call nothing is refused, not even a deny-listed address",
              _dial(("127.0.0.1", port)) == "ok" and _count(accepted, 1))
        check("... and the same connect inside the job's guard is refused",
              _in(guard, _dial, ("127.0.0.1", port)) == "refused" and _count(accepted, 1))
        check("installing twice hooks once (one refusal counted per connect)", guard.refusals == 1)
    with _unix_listener() as path:
        check("a Unix socket outside a connector call works (the GLiNER daemon)",
              _dial(path, socket.AF_UNIX) == "ok")
        check("a Unix socket inside one is refused", _in(guard, _dial, path, socket.AF_UNIX) == "refused")


def _check_host_types():
    with _listener() as (port, accepted), _listener() as (other, other_seen):
        guard = egress.Guard.for_source(_policy(), _PG, {"hostaddr": "127.0.0.1", "port": port})
        check("a host type reaches the checked address and port", _in(guard, _dial, ("127.0.0.1", port)) == "ok"
              and _count(accepted, 1))
        check("... but not another port on it", _in(guard, _dial, ("127.0.0.1", other)) == "refused"
              and not other_seen)
        check("... nor another address", _in(guard, _dial, ("10.255.255.1", port)) == "refused")
        check("... nor the cloud metadata address", _in(guard, _dial, ("169.254.169.254", 80)) == "refused")
        for host, why in (("localhost", "a host name, even one resolving to the checked address"),
                          ("", "an empty host (the unspecified address)"), ("<broadcast>", "'<broadcast>'"),
                          ("127.1", "a short-form address")):
            check(f"... nor {why}", _in(guard, _dial, (host, port)) == "refused")
        before = len(accepted)
        mapped = _in(guard, _dial, ("::ffff:127.0.0.1", port, 0, 0), socket.AF_INET6)
        check("... and an IPv4-mapped form of the checked address is that address",
              mapped != "refused" and (mapped != "ok" or _count(accepted, before + 1)))
        denied = egress.Guard.for_source(_policy(parse_hosts("127.0.0.0/8")), _PG,
                                         {"hostaddr": "127.0.0.1", "port": port})
        before = len(accepted)
        check("a deny-listed address is refused even when it is the checked one",
              _in(denied, _dial, ("127.0.0.1", port)) == "refused" and _count(accepted, before))
    if _ipv6_loopback():
        with _listener("::1", socket.AF_INET6) as (port, accepted):
            guard = egress.Guard.for_source(_policy(), _PG, {"hostaddr": "::1", "port": port})
            check("IPv6: the checked address and port pass",
                  _in(guard, _dial, ("::1", port, 0, 0), socket.AF_INET6) == "ok" and _count(accepted, 1))
            check("IPv6: another port is refused",
                  _in(guard, _dial, ("::1", port + 1 if port < 65535 else port - 1, 0, 0), socket.AF_INET6)
                  == "refused")
    with _listener() as (port, accepted):
        sqlite = egress.Guard.for_source(_policy(HostList()), _SQLITE, {"path": "/x.db"})
        check("SQLite reaches nothing", _in(sqlite, _dial, ("127.0.0.1", port)) == "refused" and not accepted)


def _check_vendor_types():
    def fake_dns(host, port, *_a, **_k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))] if host == "gwdb.zq.test" else []

    with _listener() as (port, accepted):
        open_guard = egress.Guard.for_source(_policy(), _WAREHOUSE, {"account": "acme"})
        check("a warehouse type without an allow list reaches an address off the deny list",
              _in(open_guard, _dial, ("127.0.0.1", port)) == "ok")
        check("... never a deny-listed one (cloud metadata)", _in(open_guard, _dial, ("169.254.169.254", 80))
              == "refused")
        check("... nor its IPv4-mapped form", _in(open_guard, _dial, ("::ffff:169.254.169.254", 80, 0, 0),
                                                 socket.AF_INET6) == "refused")
        named = egress.Guard.for_source(_policy(HostList(_NO_LOOPBACK.networks, ("gwdb.zq.test",))), _WAREHOUSE,
                                        {}, resolve=fake_dns)
        check("... nor the address of a deny-listed name (the gateway's DB host)",
              _in(named, _dial, ("127.0.0.1", port)) == "refused")
        nets = egress.Guard.for_source(_policy(allowed=parse_hosts("127.0.0.0/8")), _WAREHOUSE, {})
        check("with an allow list, an address in an allowed network passes", _in(nets, _dial, ("127.0.0.1", port))
              == "ok")
        check("... one outside it is refused", _in(nets, _dial, ("10.255.255.1", port)) == "refused")
        wins = egress.Guard.for_source(_policy(parse_hosts("127.0.0.1"), parse_hosts("127.0.0.0/8")), _WAREHOUSE, {})
        check("... and the deny list wins over it", _in(wins, _dial, ("127.0.0.1", port)) == "refused")
        names = egress.Guard.for_source(_policy(allowed=parse_hosts("localhost")), _WAREHOUSE, {})
        check("an allowed name does not admit its address before the job looked it up",
              _in(names, _dial, ("127.0.0.1", port)) == "refused")

        def by_name():
            socket.create_connection(("localhost", port), timeout=1).close()
            return "ok"
        before = len(accepted)
        check("... and admits exactly what the driver's own lookup returned (no second resolution)",
              _in(names, by_name) == "ok" and _count(accepted, before + 1))
        try:
            import urllib3
        except ImportError:
            urllib3 = None
        if urllib3 is not None:  # the HTTP stack under the Snowflake, BigQuery and Databricks drivers
            def http(host):
                try:
                    urllib3.PoolManager(retries=False).request("GET", f"http://{host}:{port}/", timeout=1)
                except urllib3.exceptions.ProtocolError:
                    return "ok"  # connected; the listener hung up without an answer
                except urllib3.exceptions.NewConnectionError:
                    return "refused"
                return "ok"
            fresh = egress.Guard.for_source(_policy(allowed=parse_hosts("localhost")), _WAREHOUSE, {})
            check("through urllib3: an allowed name connects; an address its lookup did not return is refused",
                  _in(fresh, http, "localhost") == "ok" and _in(fresh, http, "127.0.0.2") == "refused"
                  and fresh.refusals == 1)
        excepted = egress.Guard.for_source(_policy(parse_hosts("127.0.0.0/8")), _WAREHOUSE, {},
                                           exceptions=[("127.0.0.1", port)])
        check("an address and port the connector declares pass the deny list",
              _in(excepted, _dial, ("127.0.0.1", port)) == "ok")
        check("... only that port", _in(excepted, _dial, ("127.0.0.1", port + 1 if port < 65535 else 1)) == "refused")
    check("a declared exception must be an address and a port",
          _raises(ValueError, lambda: egress.Guard.for_source(_policy(), _WAREHOUSE, {},
                                                              exceptions=[("metadata.zq.test", 80)])))


def _check_checked_address():
    app = ConnectorType("zq-app", "app", "pro", frozenset({"url"}))
    table = {"crm.zq.test": "127.0.0.1", "meta.zq.test": "169.254.169.254"}

    def fake_dns(host, port, *_a, **_k):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (table[host], port))] if host in table else []

    def kind(fn):
        try:
            fn()
        except PolicyError as exc:
            return exc.kind
        return "ok"

    with _listener() as (port, _accepted):
        guard = egress.Guard.for_source(_policy(allowed=parse_hosts("crm.zq.test")), app, {}, resolve=fake_dns)
        addr = guard.checked_address("crm.zq.test", port)
        check("an HTTP transport gets the one checked address of an allowed name", addr == "127.0.0.1")
        check("... which the connect guard then lets through (the lookup was noted)",
              _in(guard, _dial, (addr, port)) == "ok")
        check("a name resolving to a deny-listed address is refused before any connect",
              kind(lambda: guard.checked_address("meta.zq.test", 80)) == "denied")
        other = egress.Guard.for_source(_policy(allowed=parse_hosts("other.zq.test")), app, {}, resolve=fake_dns)
        check("a name off the allow list is refused", kind(lambda: other.checked_address("crm.zq.test", port))
              == "denied")
        check("a name that does not resolve is unreachable",
              kind(lambda: guard.checked_address("gone.zq.test", port)) == "unreachable")


def _raises(exc_type, fn):
    try:
        fn()
    except exc_type:
        return True
    return False


def _check_threads():
    with _listener() as (port, _), _listener() as (other, other_seen):
        guard = egress.Guard.for_source(_policy(), _PG, {"hostaddr": "127.0.0.1", "port": port})
        seen = {}

        def spawn():
            t = threading.Thread(target=lambda: seen.setdefault("thread", _dial(("127.0.0.1", other))))
            t.start()
            t.join()
            with ThreadPoolExecutor(max_workers=2) as pool:
                seen["pool"] = pool.submit(_dial, ("127.0.0.1", other)).result()
        _in(guard, spawn)
        check("a thread the connector starts inherits its guard", seen["thread"] == "refused")
        check("... so do a pool's worker threads", seen["pool"] == "refused" and not other_seen)
        outside = []
        t = threading.Thread(target=lambda: outside.append(_dial(("127.0.0.1", other))))
        t.start()
        t.join()
        check("a thread started outside a connector call is not guarded", outside == ["ok"])

        a = egress.Guard.for_source(_policy(), _PG, {"hostaddr": "127.0.0.1", "port": port})
        b = egress.Guard.for_source(_policy(), _PG, {"hostaddr": "127.0.0.1", "port": other})
        barrier = threading.Barrier(2)
        results = {}

        def job(name, guard_, mine, theirs):
            def work():
                barrier.wait()
                results[name] = (_dial(("127.0.0.1", mine)), _dial(("127.0.0.1", theirs)))
            _in(guard_, work)
        threads = [threading.Thread(target=job, args=("a", a, port, other)),
                   threading.Thread(target=job, args=("b", b, other, port))]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        check("concurrent jobs keep their own guard", results == {"a": ("ok", "refused"), "b": ("ok", "refused")})


def _check_surfacing():
    guard = egress.Guard.for_source(_policy(), _PG, {"hostaddr": "127.0.0.1", "port": 9})
    check("a refusal reaches the driver as an OSError naming no address",
          issubclass(egress.Refused, OSError) and "169.254" not in str(egress.Refused()))

    def driver_fails():
        try:
            socket.create_connection(("169.254.169.254", 80), timeout=0.5)
        except OSError:
            raise ConnectorError("unreachable") from None
    try:
        guard.call(driver_fails)
        err = None
    except PolicyError as exc:
        err = exc
    check("a connector call failing after a refusal is the 'denied' policy error",
          err is not None and err.kind == "denied" and str(err) == "source address is not allowed")
    failure = runner.classify(err)
    outcome = job_policy.failure_outcome(failure.error_class, attempts=0, limited_since=None, now=datetime.now(UTC),
                                         timings=job_policy.JobTimings())
    check("... a fixed-text failure that is not retried and flags the source",
          failure.error_class == "denied" and outcome.status == "failed" and outcome.needs_attention
          and outcome.error == "source address is not allowed")

    def driver_copes():
        return _dial(("169.254.169.254", 80))
    check("a connector that copes with a refusal goes on (the connect never happened)",
          guard.call(driver_copes) == "refused")

    def auth_fails():
        raise ConnectorError("auth")
    try:
        guard.call(auth_fails)
        kind = None
    except ConnectorError as exc:
        kind = exc.kind
    check("a failure without a refusal keeps its own class", kind == "auth")


class _Source:
    def __init__(self, port):
        self.port = port
        self.closed = []

    def list_collections(self):
        return [_dial(("127.0.0.1", self.port))]

    def iter_records(self, collection):
        try:
            yield collection
            if _dial(("127.0.0.1", self.port)) == "refused":
                raise ConnectorError("query")
            yield "never"
        finally:
            self.closed.append(_dial(("127.0.0.1", self.port)))

    def close(self):
        self.closed.append("closed")


def _check_guarded_source():
    with _listener() as (port, _):
        guard = egress.Guard.for_source(_policy(), _PG, {"hostaddr": "127.0.0.1", "port": port + 1 if port < 65535
                                                         else 1})
        src = egress.GuardedSource(_Source(port), guard)
        inner = src._inner
        check("a source's calls run in the job's guard", src.list_collections() == ["refused"])
        rows = src.iter_records("customers")
        check("... and every step of an iterator it returns", next(rows) == "customers"
              and _raises(PolicyError, lambda: next(rows)))
        rows = src.iter_records("customers")
        next(rows)
        inner.closed.clear()
        rows.close()
        check("... and the cleanup of an iterator closed early", inner.closed == ["refused"])
        check("an optional method the source lacks stays absent", getattr(src, "iter_distinct_groups", None) is None)
        src.close()
        check("close reaches the source", inner.closed[-1] == "closed")
    check("lookups outside a job are passed through unchanged",
          ipaddress.ip_address(socket.getaddrinfo("127.0.0.1", 1, type=socket.SOCK_STREAM)[0][4][0]).is_loopback)


def main():
    print("\n=== Sync worker connect guard (spec 015) ===\n")
    _check_outside_jobs()
    _check_host_types()
    _check_vendor_types()
    _check_checked_address()
    _check_threads()
    _check_surfacing()
    _check_guarded_source()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
