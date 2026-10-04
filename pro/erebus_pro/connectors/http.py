# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""What every Pro app connector shares: HTTP that stays inside the worker's network
policy and inside the app's limits.

* **Checked transport.** Every connection resolves its host once, checks every answer
  against the worker's deny and allow lists (``EREBUS_SYNC_DENIED_HOSTS``,
  ``EREBUS_SYNC_ALLOWED_HOSTS``) and connects to exactly that address, with TLS checked
  against the host name. Redirects are never followed and proxy settings from the
  environment are ignored, so nothing reaches a host the policy did not check. Outside a
  sync job (no guard, no policy given) nothing connects.
* **Limits.** ``LimitRules`` reads an app's limit signal: a slow-down (429, 503) waits
  as long as ``Retry-After`` or the app's reset header asks, with exponential backoff
  when it names nothing, a bounded number of times; a longer wait, or a daily limit,
  raises ``ConnectorError("limit", reset_at=...)`` so the worker reschedules the job; a
  spent header budget pauses before the next call. ``min_interval`` paces calls (one at
  a time). No 4xx is retried except 429, and a 401 once after ``refresh``; a 500 is a
  ``query`` error, a 502, 503 or 504 and network errors are retried, then
  ``unreachable``; a certificate that fails the check is ``unreachable`` at once.
* **Cursors.** ``overlap_since`` and ``keyset_pages`` for modified-since reads that
  re-read an overlap window and page by a stable key.

Errors are fixed text (``ConnectorError``); no URL, host, header or body reaches them
or the log.
"""
from __future__ import annotations

import ipaddress
import logging
import ssl
import time
import urllib.parse
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

from erebus.cataloging.connector_errors import ConnectorError
from erebus.sync import egress
from erebus.sync.netpolicy import NetworkPolicy, PolicyError, check_host

from ._licensed import LicensedConnector

USER_AGENT = "erebus-sync"
_LOOPBACK_NAMES = frozenset({"localhost"})
_RETRY_STATUS = frozenset({502, 503, 504})
Checker = Callable[[str, int], str]


def app_url(value: Any) -> str:
    """``scheme://host[:port]`` of an app's URL setting, or ``ConnectorError("settings")``.

    HTTPS only; plain HTTP only to a loopback address, where nothing crosses a network.
    No credentials, path, query or fragment.
    """
    if not isinstance(value, str) or not 0 < len(value) <= 256 or not value.isprintable():
        raise ConnectorError("settings") from None
    try:
        parts = urllib.parse.urlsplit(value.strip())
        port = parts.port
    except ValueError:
        raise ConnectorError("settings") from None
    host = parts.hostname or ""
    if parts.scheme not in ("https", "http") or not host or parts.username or parts.password \
            or parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ConnectorError("settings") from None
    if parts.scheme == "http" and not _loopback(host):
        raise ConnectorError("settings") from None
    netloc = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{netloc}" + (f":{port}" if port else "")


def _loopback(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def is_host(url: str, suffix: str) -> bool:
    """Whether ``url``'s host is ``suffix`` or a subdomain of it."""
    host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
    return host == suffix or host.endswith("." + suffix)


def retry_after(response: httpx.Response, *, now: datetime | None = None) -> float | None:
    """Seconds ``Retry-After`` asks to wait (delta seconds or an HTTP date), or ``None``."""
    raw = response.headers.get("retry-after", "").strip()
    if not raw:
        return None
    if raw.isdigit():
        return float(raw)
    try:
        when = parsedate_to_datetime(raw)
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())


class LimitRules:
    """How an app signals its limits; an app connector overrides what differs.

    ``wait_for`` names the wait a slow-down response asks for (``0``: none named, back
    off), ``None`` for a response that is no slow-down. ``reschedule_at`` names when a
    stop-and-reschedule signal (a daily limit) resets. ``pause_after`` reads a header
    budget on any response: seconds to hold off before the next call.
    """

    max_wait_s = 60.0  # a slow-down asking longer reschedules the job instead
    max_retries = 4
    backoff_s = 2.0  # first wait when the app names none; doubles each time

    def wait_for(self, response: httpx.Response) -> float | None:
        if response.status_code in (429, 503):
            return retry_after(response) or 0.0
        return None

    def reschedule_at(self, response: httpx.Response) -> datetime | None:
        return None

    def pause_after(self, response: httpx.Response) -> float:
        return 0.0


def _class(status: int) -> str:
    if status == 401:
        return "auth"
    if status == 403:
        return "permission"
    if 300 <= status < 400:
        return "settings"  # a redirect: the URL is not the app's API
    if status in _RETRY_STATUS:
        return "unreachable"
    return "query"


class CheckedNetwork:
    """An ``httpcore`` network backend connecting only to the address ``check`` returns."""

    def __init__(self, check: Checker) -> None:
        import httpcore

        self._check = check
        self._inner = httpcore.SyncBackend()

    def connect_tcp(self, host: str, port: int, timeout: float | None = None, local_address: str | None = None,
                    socket_options: Any = None) -> Any:
        return self._inner.connect_tcp(self._check(host, port), port, timeout=timeout, local_address=local_address,
                                       socket_options=socket_options)

    def connect_unix_socket(self, *_args: Any, **_kwargs: Any) -> Any:
        raise PolicyError("denied")

    def sleep(self, seconds: float) -> None:
        self._inner.sleep(seconds)


class CheckedTransport(httpx.HTTPTransport):
    """``httpx.HTTPTransport`` whose every connection goes through ``CheckedNetwork``."""

    def __init__(self, check: Checker) -> None:  # pylint: disable=super-init-not-called
        import httpcore

        # Certificates are checked against certifi's CAs, or SSL_CERT_FILE / SSL_CERT_DIR when set
        # (a private CA); proxy variables stay ignored (the client does not trust the environment).
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=True), max_connections=1, retries=0,
            network_backend=CheckedNetwork(check))


def _bad_certificate(exc: BaseException) -> bool:
    seen: BaseException | None = exc
    for _ in range(8):
        if seen is None:
            return False
        if isinstance(seen, ssl.SSLCertVerificationError):
            return True
        seen = seen.__cause__ or seen.__context__
    return False


def guard_checker(policy: NetworkPolicy | None = None) -> Checker:
    """Check against ``policy``, or else against the running sync job's guard; with
    neither, refuse every connection."""
    def check(host: str, port: int) -> str:
        if policy is not None:
            return check_host(policy, host, port)
        guard = egress.current()
        if guard is None:
            raise PolicyError("denied")
        return guard.checked_address(host, port)
    return check


class AppHttp:
    """One app's HTTP client: sequential calls to ``base_url`` within its limits."""

    def __init__(self, base_url: str, *, check: Checker, headers: dict[str, str] | None = None,
                 limits: LimitRules | None = None, min_interval: float = 0.0,
                 refresh: Callable[[], dict[str, str]] | None = None, timeout: float = 60.0,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
        self._client = httpx.Client(base_url=base_url, transport=CheckedTransport(check), follow_redirects=False,
                                    trust_env=False, timeout=timeout,
                                    headers={"User-Agent": USER_AGENT, **(headers or {})})
        self._limits = limits or LimitRules()
        self._min_interval = min_interval
        self._refresh = refresh
        self._sleep = sleep
        self._clock = clock
        self._next_at = 0.0
        self.calls = 0

    def _pace(self) -> None:
        wait = self._next_at - self._clock()
        if wait > 0:
            self._sleep(wait)
        self._next_at = self._clock() + self._min_interval

    def _send(self, method: str, path: str, kwargs: dict) -> httpx.Response | None:
        """One attempt; ``None`` after a network error (the caller retries). A certificate
        that fails the check will not pass on a retry: ``unreachable`` at once."""
        self._pace()
        self.calls += 1
        try:
            return self._client.request(method, path, **kwargs)
        except httpx.TransportError as exc:
            if _bad_certificate(exc):
                raise ConnectorError("unreachable") from None
            return None

    def _backoff(self, attempt: int, asked: float | None) -> None:
        """Wait before retry ``attempt`` (1-based), or raise ``limit`` past the bounds."""
        wait = asked if asked else self._limits.backoff_s * 2 ** (attempt - 1)
        if attempt > self._limits.max_retries or wait > self._limits.max_wait_s:
            raise ConnectorError("limit", reset_at=datetime.now(UTC) + timedelta(seconds=wait)) from None
        self._sleep(wait)

    def request(self, method: str, path: str, *, accept: frozenset[int] = frozenset(), **kwargs: Any
                ) -> httpx.Response:
        """Send one request within the app's limits; the 2xx response (or one whose status
        is in ``accept``), else ``ConnectorError``."""
        attempt = 0
        refreshed = False
        while True:
            response = self._send(method, path, kwargs)
            if response is None:
                attempt += 1
                if attempt > self._limits.max_retries:
                    raise ConnectorError("unreachable") from None
                self._sleep(self._limits.backoff_s * 2 ** (attempt - 1))
                continue
            reset = self._limits.reschedule_at(response)
            if reset is not None:
                raise ConnectorError("limit", reset_at=reset) from None
            asked = self._limits.wait_for(response)
            if asked is not None:
                attempt += 1
                self._backoff(attempt, asked)
                continue
            if response.status_code == 401 and self._refresh is not None and not refreshed:
                refreshed = True
                self._client.headers.update(self._refresh())
                continue
            if not 200 <= response.status_code < 300 and response.status_code not in accept:
                kind = _class(response.status_code)
                if kind == "unreachable" and attempt < self._limits.max_retries:
                    attempt += 1
                    self._sleep(self._limits.backoff_s * 2 ** (attempt - 1))
                    continue
                raise ConnectorError(kind) from None
            pause = self._limits.pause_after(response)
            if pause > 0:
                self._next_at = max(self._next_at, self._clock() + pause)
            return response

    def close(self) -> None:
        self._client.close()


def overlap_since(cursor_time: datetime, overlap: timedelta) -> datetime:
    """Where a modified-since read starts: the cursor minus the overlap window, so a
    change committed late (a long transaction) is read again rather than missed."""
    return cursor_time - overlap


def keyset_pages(fetch: Callable[[Any, int], list], key: Callable[[Any], Any], page_size: int) -> Iterator[Any]:
    """Every item ``fetch(after, page_size)`` returns, page after page: ``after`` is the
    ``key`` of the last item read (``None`` first), so a change during the read neither
    skips nor repeats an item the way offset paging does. A short page ends the read."""
    after = None
    while True:
        page = fetch(after, page_size)
        yield from page
        if len(page) < page_size:
            return
        after = key(page[-1])


class HttpAppConnector(LicensedConnector):
    """Base of a Pro app connector over HTTP.

    ``policy`` checks connections outside the sync worker (tests); in the worker the
    running job's guard does. ``sleep`` and ``clock`` drive pacing and backoff.
    """

    def __init__(self, entitlements: Any = None, *, policy: NetworkPolicy | None = None,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.monotonic) -> None:
        super().__init__(entitlements)
        self._policy = policy
        self._sleep = sleep
        self._clock = clock

    def open_http(self, base_url: str, **kwargs: Any) -> AppHttp:
        """An ``AppHttp`` for ``base_url`` under this connector's policy, pacing and clock."""
        # httpx logs every request URL at info level; the worker log keeps none of it.
        for name in ("httpx", "httpcore"):
            logging.getLogger(name).setLevel(logging.WARNING)
        return AppHttp(base_url, check=guard_checker(self._policy), sleep=self._sleep, clock=self._clock, **kwargs)
