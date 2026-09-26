"""Gateway availability and graceful overload, pure logic (FR-047).

The gateway is the sole sanctioned AI path, so when it runs out of capacity it
must shed load *gracefully*: a rejected request is told, explicitly and
retryably, to come back later. Overload is never silently dropped and protection
is never weakened to stay under capacity -- shedding returns a retryable signal,
not a bypass.

This module is the pure admission-control core used by the request path. It holds
no database and no process-global mutable state (FR-041..043): each
:class:`Limiter` owns its own counters, so distinct instances never interfere.

A :class:`Limiter` models two finite resources:

* ``max_concurrent`` -- the number of requests that may be in flight at once.
* ``max_queue`` -- the number of requests that may wait for an in-flight slot to
  free up before further requests are shed.

:meth:`Limiter.acquire` admits a request when a concurrency slot is free, places
it in the queue when slots are full but queue space remains, and otherwise raises
:class:`Overloaded` (``retryable=True``) carrying a retry hint. :meth:`Limiter.release`
returns a slot or queue place; a queued request is promoted to in-flight when a
slot frees. The limiter never admits beyond ``max_concurrent + max_queue``, so it
can never silently exceed its protective bound.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field
from enum import StrEnum

# Default seconds the gateway suggests a shed caller wait before retrying. Chosen
# as a small, client-friendly backoff; callers may override per Limiter.
DEFAULT_RETRY_AFTER_SECONDS = 1.0


class Overloaded(Exception):
    """Raised when the gateway sheds a request because it is at capacity (FR-047).

    The gateway is the sole sanctioned AI path, so a shed request is signalled as
    *retryable*: ``retryable`` is always ``True`` and ``retry_after_seconds`` is a
    suggested backoff hint. This is a load-shedding signal, never a protection
    bypass -- the caller is asked to retry, not routed around the gateway.
    """

    def __init__(
        self,
        message: str = "gateway at capacity; retry later",
        *,
        retry_after_seconds: float = DEFAULT_RETRY_AFTER_SECONDS,
    ) -> None:
        super().__init__(message)
        # Shedding always yields a retryable signal (FR-047): there is no code path
        # that constructs a non-retryable Overloaded.
        self.retryable: bool = True
        self.retry_after_seconds: float = retry_after_seconds


class _State(StrEnum):
    """Lifecycle of an admitted request's token."""

    RUNNING = "RUNNING"
    QUEUED = "QUEUED"
    RELEASED = "RELEASED"


@dataclass
class Token:
    """An admission grant returned by :meth:`Limiter.acquire`.

    ``state`` is ``RUNNING`` when the request holds a concurrency slot or ``QUEUED``
    when it is waiting for one. The token identity (``id``) lets a limiter release
    exactly the resource it granted; it carries no request payload or PII.
    """

    id: int
    state: _State


@dataclass
class Limiter:
    """Bounded admission control with graceful, retryable overload (FR-047).

    Admits up to ``max_concurrent`` requests in flight plus ``max_queue`` waiting.
    Beyond that the limiter sheds load by raising :class:`Overloaded` rather than
    admitting work it cannot protect -- it never silently exceeds its bound and
    never weakens protection to absorb more load.

    Holds no process-global state (FR-043): all counters are instance-owned.
    """

    max_concurrent: int
    max_queue: int = 0
    retry_after_seconds: float = DEFAULT_RETRY_AFTER_SECONDS
    _running: dict[int, Token] = field(default_factory=dict, init=False, repr=False)
    _queued: list[Token] = field(default_factory=list, init=False, repr=False)
    _ids: itertools.count[int] = field(
        default_factory=lambda: itertools.count(1), init=False, repr=False
    )

    def __post_init__(self) -> None:
        if self.max_concurrent < 1:
            raise ValueError("max_concurrent must be >= 1")
        if self.max_queue < 0:
            raise ValueError("max_queue must be >= 0")
        if self.retry_after_seconds < 0:
            raise ValueError("retry_after_seconds must be >= 0")

    @property
    def running(self) -> int:
        """Number of requests currently holding a concurrency slot."""
        return len(self._running)

    @property
    def queued(self) -> int:
        """Number of requests currently waiting for a slot."""
        return len(self._queued)

    @property
    def capacity(self) -> int:
        """Total admissions allowed in flight plus queued (the protective bound)."""
        return self.max_concurrent + self.max_queue

    def acquire(self) -> Token:
        """Admit a request, or shed it with a retryable :class:`Overloaded`.

        Returns a ``RUNNING`` token when a concurrency slot is free, a ``QUEUED``
        token when slots are full but queue space remains, and raises
        :class:`Overloaded` (``retryable=True``) when both are full. The limiter
        never admits beyond :attr:`capacity`.
        """
        if self.running < self.max_concurrent:
            token = Token(id=next(self._ids), state=_State.RUNNING)
            self._running[token.id] = token
            return token
        if self.queued < self.max_queue:
            token = Token(id=next(self._ids), state=_State.QUEUED)
            self._queued.append(token)
            return token
        # Both slots and queue are full: shed, never silently drop or bypass.
        raise Overloaded(retry_after_seconds=self.retry_after_seconds)

    def release(self, token: Token) -> None:
        """Release a token's slot or queue place; promote a waiter if a slot frees.

        Idempotent per token: releasing an already-released token is a no-op so a
        caller's error path can release without double-accounting. Promotion keeps
        the running set full whenever requests are waiting, preserving FIFO order.
        """
        if token.state is _State.RELEASED:
            return
        if token.state is _State.RUNNING:
            self._running.pop(token.id, None)
        elif token.state is _State.QUEUED:
            try:
                self._queued.remove(token)
            except ValueError:
                pass
        token.state = _State.RELEASED
        self._promote()

    def _promote(self) -> None:
        """Move queued requests into freed concurrency slots (FIFO).

        A promoted token's ``state`` flips to ``RUNNING`` in place, so the caller
        holding that token releases the correct (running) resource later.
        """
        while self._queued and self.running < self.max_concurrent:
            promoted = self._queued.pop(0)
            promoted.state = _State.RUNNING
            self._running[promoted.id] = promoted
