# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The shared HTTP base of the Pro app connectors (spec 015 "App connectors", SC-7, SC-9).

Pure, with local listeners and ``respx``. Every connection goes through the worker's
network policy: a denied address is refused before any byte is sent, an allowed one is
reached at the one checked address, and outside a sync job nothing connects. Redirects
are not followed and environment proxies are ignored. TLS is checked against the URL's
host name while the connection goes to the checked address; a certificate for another
name fails at once, unretried. Limits: a 429 or 503 waits as long
as ``Retry-After`` asks, backs off when it names nothing, and reschedules (``limit``
with a reset time) past the bounds or on a daily-limit signal; a header budget pauses
the next call; ``min_interval`` paces calls. No 4xx but 429 is retried, a 401 once after
a token refresh; a 500 is a query error, a 502/504 and network errors are retried and
then ``unreachable``. Errors are fixed text. Keyset paging and the overlap window.
"""
import contextlib
import datetime as dt
import http.server
import os
import ssl
import sys
import tempfile
import threading
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import httpx

from erebus.cataloging.connector_errors import ConnectorError
from erebus.cataloging.connector_types import ConnectorType
from erebus.sync import egress
from erebus.sync.netpolicy import DEFAULT_DENIED_NETWORKS, NetworkPolicy, PolicyError, parse_hosts

_passed = 0
_OPEN = NetworkPolicy(denied=parse_hosts(",".join(n for n in DEFAULT_DENIED_NETWORKS if n != "127.0.0.0/8")))
_DEFAULT = NetworkPolicy(denied=parse_hosts(",".join(DEFAULT_DENIED_NETWORKS)))
_BASE = "https://crm.zq.example"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _error(fn):
    """The ``ConnectorError`` (or ``PolicyError``) ``fn`` raised, or ``None``."""
    try:
        fn()
    except (ConnectorError, PolicyError) as exc:
        return exc
    return None


@contextlib.contextmanager
def _server(status=200, headers=None):
    """A loopback HTTP server answering every GET with ``status``; yields (port, hits)."""
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(status)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"{}")

        def log_message(self, *_args):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield srv.server_address[1], hits
    finally:
        srv.shutdown()
        srv.server_close()


class _Clock:
    """A fake clock that ``sleep`` advances; records every sleep."""

    def __init__(self):
        self.now = 1000.0
        self.slept = []

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(round(seconds, 3))
        self.now += seconds


def _http(**kw):
    from erebus_pro.connectors.http import AppHttp, guard_checker
    clock = kw.pop("clock", None) or _Clock()
    return AppHttp(_BASE, check=guard_checker(_OPEN), sleep=clock.sleep, clock=clock, **kw), clock


def _check_transport():
    from erebus_pro.connectors.http import AppHttp, guard_checker

    with _server() as (port, hits):
        url = f"http://127.0.0.1:{port}"
        denied = AppHttp(url, check=guard_checker(_DEFAULT))
        check("a deny-listed address is refused before any byte is sent",
              isinstance(_error(lambda: denied.request("GET", "/x")), PolicyError) and hits == [])
        allowed = AppHttp(url, check=guard_checker(_OPEN))
        check("an address the policy allows is reached", allowed.request("GET", "/x").status_code == 200
              and hits == ["/x"])
        outside = AppHttp(url, check=guard_checker())
        check("outside a sync job, with no policy, nothing connects",
              isinstance(_error(lambda: outside.request("GET", "/y")), PolicyError) and hits == ["/x"])
        app = ConnectorType("zq-app", "app", "pro", frozenset({"url"}))
        guard = egress.Guard.for_source(_OPEN, app, {})
        check("inside a sync job the job's guard checks the connection",
              guard.call(lambda: outside.request("GET", "/z").status_code) == 200 and hits[-1] == "/z")
        strict = egress.Guard.for_source(_DEFAULT, app, {})
        check("... and refuses a denied one", isinstance(_error(lambda: strict.call(outside.request, "GET", "/w")),
                                                         PolicyError) and hits[-1] == "/z")
        old = os.environ.get("HTTP_PROXY")
        os.environ["HTTP_PROXY"] = "http://192.0.2.1:9"
        try:
            check("proxy settings from the environment are ignored",
                  AppHttp(url, check=guard_checker(_OPEN)).request("GET", "/p").status_code == 200)
        finally:
            if old is None:
                del os.environ["HTTP_PROXY"]
            else:
                os.environ["HTTP_PROXY"] = old
    with _server(302, {"Location": "http://169.254.169.254/latest"}) as (port, hits):
        err = _error(lambda: AppHttp(f"http://127.0.0.1:{port}", check=guard_checker(_OPEN)).request("GET", "/r"))
        check("a redirect is not followed; it fails as bad settings", err is not None and err.kind == "settings"
              and hits == ["/r"])


def _cert(directory, name):
    """A self-signed certificate (its own CA) for ``name``; returns (cert path, key path)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = dt.datetime.now(dt.UTC)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_path, key_path = os.path.join(directory, f"{name}.pem"), os.path.join(directory, f"{name}.key")
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_path, "wb") as fh:
        fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    return cert_path, key_path


def _tls_request(served, trusted):
    """GET https://crm.zq.test/t from a loopback server presenting ``served``, trusting
    ``trusted``; returns (error, paths served, checker calls, sleeps)."""
    from erebus_pro.connectors.http import AppHttp

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(*served)
    hits, asked = [], []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    old = os.environ.get("SSL_CERT_FILE")
    os.environ["SSL_CERT_FILE"] = trusted
    clock = _Clock()
    try:
        client = AppHttp(f"https://crm.zq.test:{srv.server_address[1]}",
                         check=lambda host, port: asked.append((host, port)) or "127.0.0.1",
                         sleep=clock.sleep, clock=clock)
        err = _error(lambda: client.request("GET", "/t"))
    finally:
        if old is None:
            del os.environ["SSL_CERT_FILE"]
        else:
            os.environ["SSL_CERT_FILE"] = old
        srv.shutdown()
        srv.server_close()
    return err, hits, [h for h, _p in asked], clock.slept


def _check_tls():
    with tempfile.TemporaryDirectory() as tmp:
        good = _cert(tmp, "crm.zq.test")
        other = _cert(tmp, "other.zq.test")
        err, hits, asked, _slept = _tls_request(good, good[0])
        check("TLS is checked against the URL's name while the connection goes to the checked address",
              err is None and hits == ["/t"] and asked == ["crm.zq.test"])
        err, hits, _asked, slept = _tls_request(other, good[0])
        check("a certificate for another name fails at once as unreachable, unretried",
              err is not None and err.kind == "unreachable" and hits == [] and slept == [])


def _check_urls():
    from erebus_pro.connectors.http import app_url, is_host
    check("an HTTPS URL is reduced to scheme, host and port",
          app_url("https://Acme.odoo.com/") == "https://acme.odoo.com" and app_url("https://h.zq:8443") ==
          "https://h.zq:8443")
    check("plain HTTP only to loopback", app_url("http://127.0.0.1:18069") == "http://127.0.0.1:18069"
          and _error(lambda: app_url("http://crm.zq.example")).kind == "settings")
    check("credentials, paths, queries and other schemes are refused",
          all(_error(lambda u=u: app_url(u)).kind == "settings" for u in (
              "https://u:p@h.zq", "https://h.zq/odoo", "https://h.zq?db=x", "ftp://h.zq", "h.zq", "", None,
              "https://h.zq:99999")))
    check("hosts match a domain and its subdomains only",
          is_host("https://acme.odoo.com", "odoo.com") and not is_host("https://evilodoo.com", "odoo.com"))


def _check_limits():
    import respx
    from erebus_pro.connectors.http import LimitRules

    with respx.mock(base_url=_BASE, assert_all_called=False) as mock:
        route = mock.get("/a").mock(side_effect=[httpx.Response(429, headers={"Retry-After": "7"}),
                                                 httpx.Response(200, json={"ok": True})])
        http_, clock = _http()
        check("a 429 waits as long as Retry-After asks, then succeeds",
              http_.request("GET", "/a").json() == {"ok": True} and clock.slept == [7.0] and route.call_count == 2)

        route = mock.get("/b").mock(return_value=httpx.Response(429))
        http_, clock = _http()
        err = _error(lambda: http_.request("GET", "/b"))
        check("a 429 naming no wait backs off exponentially, then reschedules",
              clock.slept == [2.0, 4.0, 8.0, 16.0] and err.kind == "limit" and route.call_count == 5
              and err.reset_at > datetime.now(UTC))

        route = mock.get("/c").mock(return_value=httpx.Response(429, headers={"Retry-After": "3600"}))
        http_, clock = _http()
        err = _error(lambda: http_.request("GET", "/c"))
        check("a wait past the bound reschedules at once, at the time asked",
              err.kind == "limit" and clock.slept == [] and route.call_count == 1
              and timedelta(minutes=59) < err.reset_at - datetime.now(UTC) <= timedelta(hours=1))

        mock.get("/d").mock(side_effect=[httpx.Response(503, headers={"Retry-After": "1"}), httpx.Response(200)])
        http_, clock = _http()
        check("a 503 with Retry-After slows down too", http_.request("GET", "/d").status_code == 200
              and clock.slept == [1.0])

        class Daily(LimitRules):
            def reschedule_at(self, response):
                return datetime(2030, 1, 1, tzinfo=UTC) if response.status_code == 403 else None
        mock.get("/e").mock(return_value=httpx.Response(403))
        err = _error(lambda: _http(limits=Daily())[0].request("GET", "/e"))
        check("an app's daily-limit signal reschedules at its reset time",
              err.kind == "limit" and err.reset_at == datetime(2030, 1, 1, tzinfo=UTC))

        class Budget(LimitRules):
            def pause_after(self, response):
                return 30.0 if response.headers.get("X-Left") == "0" else 0.0
        mock.get("/f").mock(return_value=httpx.Response(200, headers={"X-Left": "0"}))
        http_, clock = _http(limits=Budget())
        http_.request("GET", "/f")
        http_.request("GET", "/f")
        check("a spent header budget pauses before the next call", clock.slept == [30.0])

        mock.get("/g").mock(return_value=httpx.Response(200))
        http_, clock = _http(min_interval=1.0)
        for _ in range(3):
            http_.request("GET", "/g")
        check("min_interval paces calls", clock.slept == [1.0, 1.0])


def _check_errors():
    import respx

    with respx.mock(base_url=_BASE, assert_all_called=False) as mock:
        for status, kind in ((400, "query"), (403, "permission"), (404, "query"), (422, "query"), (500, "query")):
            route = mock.get(f"/s{status}").mock(return_value=httpx.Response(status, text="Zyx Qorbel secret"))
            err = _error(lambda s=status: _http()[0].request("GET", f"/s{s}"))
            check(f"a {status} is not retried and fails as {kind}, in fixed text",
                  err.kind == kind and route.call_count == 1 and "Qorbel" not in str(err) and "zq" not in str(err))

        route = mock.get("/auth").mock(return_value=httpx.Response(401))
        err = _error(lambda: _http()[0].request("GET", "/auth"))
        check("a 401 without a refresh fails as auth at once", err.kind == "auth" and route.call_count == 1)
        refreshed = []
        route = mock.get("/ref").mock(side_effect=[httpx.Response(401), httpx.Response(200)])
        http_, _ = _http(refresh=lambda: refreshed.append(1) or {"Authorization": "Bearer new"})
        check("a 401 refreshes the token once and retries", http_.request("GET", "/ref").status_code == 200
              and refreshed == [1] and route.calls[-1].request.headers["Authorization"] == "Bearer new")
        route = mock.get("/ref2").mock(return_value=httpx.Response(401))
        refreshed.clear()
        err = _error(lambda: _http(refresh=lambda: refreshed.append(1) or {})[0].request("GET", "/ref2"))
        check("... only once", err.kind == "auth" and refreshed == [1] and route.call_count == 2)

        route = mock.get("/gw").mock(side_effect=[httpx.Response(502), httpx.Response(504), httpx.Response(200)])
        check("a 502 or 504 is retried", _http()[0].request("GET", "/gw").status_code == 200
              and route.call_count == 3)
        route = mock.get("/down").mock(side_effect=httpx.ConnectError("boom zq.example"))
        http_, clock = _http()
        err = _error(lambda: http_.request("GET", "/down"))
        check("network errors are retried with backoff, then unreachable",
              err.kind == "unreachable" and route.call_count == 5 and clock.slept == [2.0, 4.0, 8.0, 16.0])


def _check_paging():
    from erebus_pro.connectors.http import keyset_pages, overlap_since
    items = list(range(1, 8))
    asked = []

    def fetch(after, size):
        asked.append(after)
        start = 0 if after is None else items.index(after) + 1
        return items[start:start + size]
    check("keyset paging reads every item, asking after the last key",
          list(keyset_pages(fetch, lambda i: i, 3)) == items and asked == [None, 3, 6])
    check("the overlap window starts before the cursor",
          overlap_since(datetime(2026, 1, 1, 12, tzinfo=UTC), timedelta(minutes=5))
          == datetime(2026, 1, 1, 11, 55, tzinfo=UTC))


def main():
    print("\n=== Shared HTTP base of the app connectors (spec 015) ===\n")
    try:
        import respx  # noqa: F401
    except ImportError:
        if os.environ.get("EREBUS_REQUIRE_RESPX") == "1":
            raise
        print("  - skipped (respx is not installed: pip install './pro[test]')")
        return
    _check_transport()
    _check_tls()
    _check_urls()
    _check_limits()
    _check_errors()
    _check_paging()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
