"""What a sync job's connector may connect to, checked at every connect (spec 015
"Security": network; SC-9).

``netpolicy`` checks a source's host before its connector runs, but a driver can be sent
elsewhere afterwards: an Oracle listener redirects the client before sign-in (RAC SCAN
listeners do so by design), and the Snowflake, BigQuery and Databricks drivers talk to
vendor hosts no setting names. So the worker installs one audit hook
(``sys.addaudithook``) that sees every connect of a Python socket in the process. While
a job's connector runs (``Guard.call``; ``GuardedSource`` runs every call of a source,
and every step of an iterator it returns, that way) the hook refuses:

* an address on the deny list, always;
* for a type that dials a host (``default_port``: Postgres, MySQL, Oracle, MSSQL), any
  address and port but the checked ``(hostaddr, port)``;
* for the other types (Snowflake, BigQuery, Databricks), an address off the allow list
  when one is set: in none of its networks, and not what a lookup of one of its names
  returned during the job (the worker wraps ``socket.getaddrinfo`` to note the answers,
  so a name is never resolved a second time to check it);
* for SQLite, anything;
* a host name in place of an address (connect would resolve it where the answer cannot
  be checked) and any family but IPv4 and IPv6, such as a Unix socket.

An ``(address, port)`` the connector declares with ``egress_exceptions(settings)`` passes
both lists (the metadata server, for BigQuery's identity attached to the worker). Threads
a connector starts inherit its guard. Outside a connector call nothing is checked: the
worker's own Postgres connections and the GLiNER daemon socket are the worker's.

Native code is out of reach. libpq (Postgres) dials the pinned ``hostaddr`` and follows
no redirect; FreeTDS and Microsoft's ODBC driver (MSSQL) follow a server's routing
redirect (Azure SQL's Redirect policy) unchecked. Network egress rules are the guard
there, as for anything that bypasses Python's sockets.

A refused connect raises ``Refused`` (an ``OSError``) inside the driver, which fails or
carries on as after any network error; a connector call that fails after a refusal
raises ``PolicyError("denied")``, a fixed-text failure the worker does not retry.
"""
from __future__ import annotations

import contextvars
import errno
import functools
import socket
import sys
import threading
import weakref
from collections.abc import Callable, Iterable, Iterator
from typing import Any

from ..cataloging.connector_types import ConnectorType
from .netpolicy import Address, NetworkPolicy, PolicyError, address, resolve_names

_INET = frozenset({socket.AF_INET, socket.AF_INET6})
_THREAD_START = frozenset({"_thread.start_new_thread", "_thread.start_joinable_thread"})
_ACTIVE: contextvars.ContextVar[Guard | None] = contextvars.ContextVar("erebus_sync_guard", default=None)
_INHERITED: weakref.WeakKeyDictionary[threading.Thread, Guard] = weakref.WeakKeyDictionary()
_LOCK = threading.Lock()
_INSTALLED: list[bool] = []


class Refused(PermissionError):
    """A connect the job's guard refused, raised inside the driver; it names no address."""

    def __init__(self) -> None:
        super().__init__(errno.EACCES, "connection refused by the sync worker's network policy")


def _target(addr: Any, port: Any) -> tuple[Address, int]:
    if not isinstance(addr, str) or type(port) is not int or not 0 < port < 65536:
        raise ValueError("a guard target is an address and a port")
    return address(addr), port


class Guard:
    """What one job's connector may connect to. ``mode`` is ``host`` (only ``approved``),
    ``vendor`` (the deny and allow lists) or ``none``."""

    def __init__(self, policy: NetworkPolicy, mode: str, *, approved: tuple[str, int] | None = None,
                 exceptions: Iterable[tuple[str, int]] = (), resolve: Callable[..., list] = socket.getaddrinfo):
        if mode not in ("host", "vendor", "none") or (mode == "host") != (approved is not None):
            raise ValueError("malformed guard")
        self._policy = policy
        self._mode = mode
        self._approved = _target(*approved) if approved else None
        self._exceptions = frozenset(_target(a, p) for a, p in exceptions)
        # A deny-listed name's addresses, looked up once when the job starts.
        self._denied = resolve_names(policy.denied.names, 0, resolve)
        self._denied_names = frozenset(policy.denied.names)
        self._allowed_names = frozenset(policy.allowed.names if policy.allowed else ())
        self._seen: dict[Address, set[str]] = {}
        self.refusals = 0

    @classmethod
    def for_source(cls, policy: NetworkPolicy, ctype: ConnectorType, settings: dict[str, Any], *,
                   exceptions: Iterable[tuple[str, int]] = (), resolve: Callable[..., list] = socket.getaddrinfo
                   ) -> Guard:
        """The guard for a source of ``ctype`` with the settings ``prepare_settings`` returned."""
        if ctype.family == "file":
            return cls(policy, "none", exceptions=exceptions, resolve=resolve)
        if ctype.default_port is not None:
            return cls(policy, "host", approved=(settings["hostaddr"], settings["port"]), exceptions=exceptions,
                       resolve=resolve)
        return cls(policy, "vendor", exceptions=exceptions, resolve=resolve)

    def note(self, host: Any, answers: list) -> None:
        """Remember which addresses a lookup of a listed name returned."""
        name = host.lower().rstrip(".") if isinstance(host, str) else None
        if name not in self._denied_names and name not in self._allowed_names:
            return
        for answer in answers:
            try:
                self._seen.setdefault(address(answer[4][0]), set()).add(name)
            except (ValueError, TypeError, IndexError):
                continue

    def allows(self, family: Any, addr: Any) -> bool:
        """Whether a socket of ``family`` may connect to ``addr``."""
        if family not in _INET or not isinstance(addr, tuple) or len(addr) < 2 or not isinstance(addr[0], str):
            return False
        try:
            ip = address(addr[0])
        except ValueError:
            return False
        target = (ip, addr[1])
        if target in self._exceptions:
            return True
        names = self._seen.get(ip, set())
        if ip in self._denied or names & self._denied_names or any(ip in n for n in self._policy.denied.networks):
            return False
        if self._mode != "vendor":
            return target == self._approved
        allowed = self._policy.allowed
        return allowed is None or bool(names & self._allowed_names) or any(ip in n for n in allowed.networks)

    def check(self, family: Any, addr: Any) -> None:
        """Raise ``Refused`` for a connect this guard does not allow."""
        try:
            ok = self.allows(family, addr)
        except Exception:  # fail closed
            ok = False
        if not ok:
            self.refusals += 1
            raise Refused()

    def call(self, fn: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        """Run connector code under this guard; ``PolicyError("denied")`` if it fails after a refusal."""
        before = self.refusals
        token = _ACTIVE.set(self)
        try:
            return fn(*args, **kwargs)
        except Exception as exc:
            if self.refusals != before and not isinstance(exc, StopIteration):
                raise PolicyError("denied") from None
            raise
        finally:
            _ACTIVE.reset(token)


class GuardedSource:
    """A source whose every call, and every step of an iterator a call returns, runs in ``guard``."""

    def __init__(self, inner: Any, guard: Guard) -> None:
        self._inner = inner
        self._guard = guard

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr

        @functools.wraps(attr)
        def guarded(*args: Any, **kwargs: Any) -> Any:
            result = self._guard.call(attr, *args, **kwargs)
            return self._steps(result) if isinstance(result, Iterator) else result
        return guarded

    def _steps(self, it: Iterator) -> Iterator:
        try:
            while True:
                try:
                    item = self._guard.call(next, it)
                except StopIteration:
                    return
                yield item
        finally:
            close = getattr(it, "close", None)
            if close is not None:
                self._guard.call(close)


def current() -> Guard | None:
    """The guard of the connector code running in this thread, or ``None``."""
    guard = _ACTIVE.get()
    if guard is None and _INHERITED:
        guard = _INHERITED.get(threading.current_thread())
    return guard


def _hook(event: str, args: tuple) -> None:
    if event == "socket.connect":
        guard = current()
        if guard is not None:
            guard.check(getattr(args[0], "family", None), args[1])
    elif event in _THREAD_START:
        guard = current()
        thread = getattr(args[0], "__self__", None)
        if guard is not None and isinstance(thread, threading.Thread):
            with _LOCK:
                _INHERITED[thread] = guard


def _noting(real: Callable[..., list]) -> Callable[..., list]:
    @functools.wraps(real)
    def getaddrinfo(host: Any, port: Any, *args: Any, **kwargs: Any) -> list:
        answers = real(host, port, *args, **kwargs)
        guard = current()
        if guard is not None:
            guard.note(host, answers)
        return answers
    return getaddrinfo


def install() -> None:
    """Install the connect hook and the lookup wrapper, once per process (the sync worker's)."""
    with _LOCK:
        if _INSTALLED:
            return
        sys.addaudithook(_hook)
        socket.getaddrinfo = _noting(socket.getaddrinfo)
        _INSTALLED.append(True)
