"""Per-request runtime plumbing for the gateway app (extracted from app.py).

Authentication off the event loop (009 R5), the pooled-connection offload (:func:`_db`),
masked telemetry recording, the per-tenant concurrency slot, and the overload-admission gate
- the shared helpers every route handler builds on. Kept in its own module so ``app.py`` stays
within the line budget; nothing here imports the handlers or ``create_app``, so there is no
import cycle.
"""
from __future__ import annotations

import contextlib
import re
import uuid
from collections.abc import Callable
from typing import Any

import anyio
from fastapi import HTTPException

from .deps import GatewayDeps
from .governance import audit
from .observability import Metric
from .overload import Limiter, Overloaded

_DENIED = HTTPException(status_code=401, detail="invalid credential")



def _event(event_type: str, outcome: str) -> dict:
    return {"event_type": event_type, "actor_id": "gateway", "actor_role": "gateway",
            "request_id": None, "masked_value": None, "category": "request",
            "outcome": outcome, "metadata": {}}


def _resolve_identity(deps: GatewayDeps, cred: str) -> tuple[str, uuid.UUID] | None:
    """Resolve a credential to ``(scope_key, scope_id)`` in a SINGLE lookup (009 R5).

    The dynamic resolver returns the scope id alongside the key in one directory read, so the
    deployed path no longer runs the scope-id ``SELECT`` twice (no double lookup, no TOCTOU
    ``KeyError``). The static ``ScopeResolver`` + ``scope_ids`` dict path is kept as a fallback
    so every 007 test resolves unchanged. Synchronous DB work -- runs off the event loop.
    """
    resolve_full = getattr(deps.scopes, "resolve_full", None)
    if resolve_full is not None:
        resolved = resolve_full(cred)  # (scope_id, scope_key) | None, one lookup
        if resolved is None:
            return None
        scope_id, scope_key = resolved
        return scope_key, scope_id
    # Static fallback (007 tests): resolve the key, then the id from the supplied dict.
    scope_key = deps.scopes.resolve(cred)
    if not scope_key or scope_key not in deps.scope_ids:
        return None
    return scope_key, deps.scope_ids[scope_key]


async def _auth(deps: GatewayDeps, authorization: str | None) -> tuple[str, uuid.UUID]:
    """Authenticate a request to ``(scope_key, scope_id)`` off the event loop (009 R5/FR-003).

    The whole resolution (a single directory lookup for the dynamic path) runs in the
    threadpool so the synchronous psycopg work never blocks the loop. A miss -- unknown,
    revoked, or a tenant removed mid-resolution -- raises a clean 401, never a 500.
    """
    cred = re.sub(r"^Bearer ", "", authorization or "").strip()
    resolved = await anyio.to_thread.run_sync(lambda: _resolve_identity(deps, cred))
    if resolved is None:
        raise _DENIED
    return resolved


async def _acquire(deps: GatewayDeps):
    """Check out a connection: a pooled one per request, or the shared conn."""
    if deps.pool is None:
        return deps.conn
    return await anyio.to_thread.run_sync(deps.pool.getconn)


async def _release(deps: GatewayDeps, conn) -> None:
    if deps.pool is not None:
        await anyio.to_thread.run_sync(lambda: deps.pool.putconn(conn))


async def _db(deps: GatewayDeps, fn: Callable[[Any], Any]):
    """Run a sync DB unit on its own checked-out connection (concurrency-safe)."""
    conn = await _acquire(deps)
    try:
        return await anyio.to_thread.run_sync(lambda: fn(conn))
    finally:
        await _release(deps, conn)


async def _audit(deps: GatewayDeps, scope_id: uuid.UUID, event_type: str, outcome: str) -> None:
    await _db(deps, lambda c: audit.append(c, scope_id, _event(event_type, outcome)))


def _slot(deps: GatewayDeps, scope_key: str):
    """Per-tenant concurrency slot so one tenant's burst cannot starve another (FR-038)."""
    if deps.concurrency_cap <= 0:
        return contextlib.nullcontext()
    sem = deps._sems.get(scope_key)
    if sem is None:
        sem = anyio.Semaphore(deps.concurrency_cap)
        deps._sems[scope_key] = sem
    return sem


def _record(deps: GatewayDeps, scope_id: uuid.UUID, metric: Metric, n: int = 1) -> None:
    """Record a masked counter for ``scope_id`` when telemetry is wired (008 T042/FR-011).

    Telemetry is opt-in and best-effort: with no ``Metrics`` instance this is a no-op,
    and a recording failure never breaks the request path. Only integer counts keyed by
    the scope id are stored -- never a raw value, prompt, or secret (the registry rejects
    anything but ints by construction).
    """
    if deps.metrics is None:
        return
    with contextlib.suppress(Exception):
        deps.metrics.record(str(scope_id), metric, n)


def _admit(deps: GatewayDeps, scope_key: str):
    """Acquire a per-tenant overload admission token, or shed 503 + Retry-After (FR-047).

    Each tenant gets its OWN :class:`Limiter` (cloned from the configured one), so a
    saturated tenant is shed against its own bound while every other tenant keeps its full
    capacity -- per-tenant fairness, never a global failure. Returns a context manager that
    releases the token on exit; with no limiter configured admission is a no-op. A shed
    request raises a 503 carrying the limiter's retry hint.
    """
    if deps.limiter is None:
        return contextlib.nullcontext()
    limiter = deps._limiters.get(scope_key)
    if limiter is None:
        limiter = Limiter(
            max_concurrent=deps.limiter.max_concurrent,
            max_queue=deps.limiter.max_queue,
            retry_after_seconds=deps.limiter.retry_after_seconds,
        )
        deps._limiters[scope_key] = limiter
    try:
        token = limiter.acquire()
    except Overloaded as exc:
        raise HTTPException(
            status_code=503, detail="gateway overloaded; retry later",
            headers={"Retry-After": str(int(exc.retry_after_seconds) or 1)},
        ) from exc

    @contextlib.contextmanager
    def _holding():
        try:
            yield
        finally:
            limiter.release(token)

    return _holding()
