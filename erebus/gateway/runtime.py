"""Per-request runtime plumbing for the gateway app (extracted from app.py).

Authentication off the event loop (009 R5), the operator gate (:func:`require_operator`, 010),
the pooled-connection offload (:func:`_db`), the fail-closed quota reservation, masked telemetry
recording, the per-tenant concurrency slot, and the overload-admission gate - the shared helpers
every route handler builds on. Kept in its own module so ``app.py`` stays
within the line budget; nothing here imports the handlers or ``create_app``, so there is no
import cycle.
"""
from __future__ import annotations

import contextlib
import re
import uuid
from collections.abc import Callable
from typing import Any, NamedTuple

import anyio
from fastapi import HTTPException

from . import catalog, rbac
from .deps import GatewayDeps
from .governance import audit
from .known_values import KnownValueMatcher
from .observability import Metric
from .overload import Limiter, Overloaded
from .providers import quota

_DENIED = HTTPException(status_code=401, detail="invalid credential")


class Identity(NamedTuple):
    """The authenticated caller: its scope and the privilege issued with its credential."""

    scope_key: str
    scope_id: uuid.UUID
    credential_id: str | None  # directory row id (never the token); None on the static resolver
    privilege: str


def _event(event_type: str, outcome: str, actor: Identity | None = None, metadata: dict | None = None) -> dict:
    """Audit fields; an admin action records the caller's credential id and privilege (010).

    ``metadata`` carries ids and counts only, never a value or credential (spec 015).
    """
    return {"event_type": event_type,
            "actor_id": (actor.credential_id or "static") if actor else "gateway",
            "actor_role": actor.privilege if actor else "gateway",
            "request_id": None, "masked_value": None, "category": "request",
            "outcome": outcome, "metadata": dict(metadata or {})}


def _resolve_identity(deps: GatewayDeps, cred: str, *, fresh: bool = False) -> Identity | None:
    """Resolve a credential to its :class:`Identity` in a SINGLE lookup (009 R5).

    The dynamic resolver returns the scope id, key and privilege in one directory read
    (``fresh`` bypasses its TTL cache). The static ``ScopeResolver`` + ``scope_ids`` dict path
    is kept as a fallback so every 007 test resolves unchanged. Synchronous DB work -- runs
    off the event loop.
    """
    resolve_record = getattr(deps.scopes, "resolve_record", None)
    if resolve_record is not None:
        record = resolve_record(cred, fresh=fresh)
        if record is None:
            return None
        return Identity(record.scope_key, record.scope_id, str(record.credential_id), record.privilege)
    # Static fallback (007 tests): resolve the key, then the id from the supplied dict.
    scope_key = deps.scopes.resolve(cred)
    if not scope_key or scope_key not in deps.scope_ids:
        return None
    privilege = getattr(deps.scopes, "privilege", lambda _c: rbac.TENANT)(cred)
    return Identity(scope_key, deps.scope_ids[scope_key], None, privilege)


async def _identify(deps: GatewayDeps, authorization: str | None, *, fresh: bool = False) -> Identity:
    """Authenticate a request to its :class:`Identity` off the event loop (009 R5/FR-003).

    The whole resolution (a single directory lookup for the dynamic path) runs in the
    threadpool so the synchronous psycopg work never blocks the loop. A miss -- unknown,
    revoked, or a tenant removed mid-resolution -- raises a clean 401, never a 500.
    """
    cred = re.sub(r"^Bearer ", "", authorization or "").strip()
    ident = await anyio.to_thread.run_sync(lambda: _resolve_identity(deps, cred, fresh=fresh))
    if ident is None:
        raise _DENIED
    return ident


async def _auth(deps: GatewayDeps, authorization: str | None) -> tuple[str, uuid.UUID]:
    """Authenticate a request to ``(scope_key, scope_id)``; the chat paths' contract."""
    ident = await _identify(deps, authorization)
    return ident.scope_key, ident.scope_id


async def require_operator(deps: GatewayDeps, authorization: str | None, *,
                           event: str = "admin") -> Identity:
    """Admit only a credential issued operator privilege (010 FR-001..003).

    Nothing in the body, headers or query is consulted. The directory is read fresh, so a
    revoked operator is refused at once on every replica. Missing/unknown/revoked -> 401; a
    tenant -> 403, audited ``forbidden`` on its own scope as ``event``. Neither discloses data.
    """
    ident = await _identify(deps, authorization, fresh=True)
    if rbac.is_operator(ident.privilege):
        return ident
    if deps.pool is not None or deps.conn is not None:
        with contextlib.suppress(Exception):  # the denial stands even if the audit write fails
            await _audit(deps, ident.scope_id, event, "forbidden", ident)
    raise HTTPException(status_code=403, detail="forbidden")


def _scope_id_for(conn, scope_key: str) -> uuid.UUID | None:
    with conn.transaction():  # no implicit transaction left open on a shared connection
        row = conn.execute(
            "SELECT id FROM scopes WHERE scope_key = %s AND status = 'active'", (scope_key,)
        ).fetchone()
    return row[0] if row else None


async def _target_scope(deps: GatewayDeps, ident: Identity, scope_key: object, *,
                        required: bool = False) -> uuid.UUID:
    """The scope an admin call acts on (010): the named ``scope_key``, else the caller's own."""
    if scope_key is None or scope_key == "":
        if required:
            raise HTTPException(status_code=400, detail="scope_key required")
        return ident.scope_id
    if not isinstance(scope_key, str):
        raise HTTPException(status_code=400, detail="scope_key must be a string")
    sid = await _db(deps, lambda c: _scope_id_for(c, scope_key))
    if sid is None:
        raise HTTPException(status_code=404, detail="scope not found")
    return sid


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


async def _audit(deps: GatewayDeps, scope_id: uuid.UUID, event_type: str, outcome: str,
                 actor: Identity | None = None, metadata: dict | None = None) -> None:
    await _db(deps, lambda c: audit.append(c, scope_id, _event(event_type, outcome, actor, metadata)))


async def _reserve_or_429(deps: GatewayDeps, scope_id: uuid.UUID, event: str) -> None:
    try:
        await _db(deps, lambda c: quota.check_and_reserve(c, scope_id))
    except quota.QuotaExceeded as exc:
        await _audit(deps, scope_id, event, "quota_rejected")
        _record(deps, scope_id, Metric.QUOTA_REJECTIONS)  # masked 429 telemetry (FR-011)
        raise HTTPException(status_code=429, detail="quota exceeded",
                            headers={"Retry-After": "1"}) from exc


async def _known_matcher(deps: GatewayDeps, scope_id: uuid.UUID, event: str) -> KnownValueMatcher | None:
    """The tenant's known-value matcher, or 503 before any quota is spent (spec 015).

    A tenant the builder has not decided on yet (onboarded since its last pass) is served
    with an empty matcher when its catalog is empty; otherwise the builder is woken and the
    request refused. Crypto-erased, unprovisioned and inactive tenants have no matcher.
    """
    registry = deps.known_values
    if registry is None:
        return None
    matcher = registry.get(scope_id)
    if matcher is None and not registry.attempted(scope_id):
        try:
            empty = not await _db(deps, lambda c: catalog.has_active_values(c, scope_id))
        except Exception:
            empty = False
        matcher = registry.adopt_empty(scope_id) if empty else None
        if matcher is None:
            registry.wake()
    if matcher is None:
        await _audit(deps, scope_id, event, "fail_closed")
        _record(deps, scope_id, Metric.BLOCKED_EGRESS)
        raise HTTPException(status_code=503, detail="known values unavailable")
    return matcher


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
