"""FastAPI gateway app (research R2) wiring the per-scope services into the path.

Chat path: authenticate -> resolve scope + tokenization mode -> per-tenant
concurrency slot -> fail-closed quota reservation -> gate every message part
(text tokenized, tool-call args tokenized, non-text modalities blocked) ->
forward token-only -> restore (streamed or whole) -> audit. Governed routes (operator
credential only, 010; handlers in :mod:`.admin`): /v1/reveal (+ grant + rate-limited),
GET /v1/audit, POST /v1/admin/keys, POST /v1/admin/scopes, POST/DELETE /v1/admin/tenants,
POST /v1/admin/operators, GET /metrics.

Every database operation runs through :func:`_db`, which checks out its own
connection (from the pool when one is supplied) so concurrent requests across
scopes never share a connection or race on the per-scope ``set_config`` RLS
binding. Sync engine/DB work runs in a threadpool; the provider call is async.
"""
from __future__ import annotations

import contextlib
import uuid
from collections.abc import AsyncIterator
from typing import Any

import anyio
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import StreamingResponse

from .admin import (
    _handle_audit_query,
    _handle_issue_operator,
    _handle_key_op,
    _handle_metrics,
    _handle_onboard_tenant,
    _handle_provision,
    _handle_reveal,
    _handle_revoke_tenant,
)
from .crypto.keyprovider import CryptoErased, KeyProvider
from .deps import (
    DetectorPosture,
    Egress,
    EgressStream,
    GatewayDeps,
    KmsHealth,
    ProviderCall,
    ProviderStream,
    ShutdownHook,
)
from .detection import DetectionUnavailable
from .gating import BlockedModality, EdgeRawError, restore_payload, tokenize_payload
from .modalities import Decision
from .observability import Metric, Metrics
from .overload import Limiter
from .runtime import (
    _acquire,
    _admit,
    _audit,
    _auth,
    _db,
    _record,
    _release,
    _reserve_or_429,
    _slot,
)
from .store.known_value_store import open_store
from .streaming_restore import StreamRestorer
from .tenancy import ScopeResolver
from .tokenizer import Detector
from .transport import EgressDenied


async def _sanitize_or_fail(deps: GatewayDeps, scope_id: uuid.UUID, mode: str, payload: dict) -> dict:
    try:
        return await _db(deps, lambda c: tokenize_payload(
            deps.key_provider, deps.detector, deps.modality_policy, c, scope_id, mode, payload))
    except EdgeRawError as exc:
        await _audit(deps, scope_id, "chat", "edge_raw_blocked")
        raise HTTPException(status_code=400, detail="edge payload contains raw PII") from exc
    except BlockedModality as exc:
        await _audit(deps, scope_id, "chat", "modality_blocked")
        _record(deps, scope_id, Metric.BLOCKED_EGRESS)  # masked 415 modality-block telemetry
        raise HTTPException(status_code=415, detail=f"modality blocked: {exc}") from exc
    except DetectionUnavailable as exc:
        # Production detection was unreachable/degraded mid-tokenization (FR-007): NER did
        # not run, so untokenized PII could otherwise ride to the provider. Fail closed
        # exactly like the CryptoErased branch -- no raw egress, audited 'fail_closed'.
        await _audit(deps, scope_id, "chat", "fail_closed")
        _record(deps, scope_id, Metric.BLOCKED_EGRESS)  # masked 503 detection-down telemetry
        raise HTTPException(status_code=503, detail="detection unavailable") from exc
    except CryptoErased as exc:
        await _audit(deps, scope_id, "chat", "fail_closed")
        raise HTTPException(status_code=503, detail="protection unavailable") from exc


async def _egress(deps: GatewayDeps, scope_id: uuid.UUID, sanitized: dict) -> dict:
    """Forward token-only egress: scope-aware seam when wired, else the 007 provider_call.

    When ``deps.egress`` is set, the per-tenant central credential + approved route are
    injected (008 R1); a route/model/credential refusal surfaces as ``EgressDenied`` and
    is mapped to a fail-closed 502 (no raw PII ever left the gateway).
    """
    if deps.egress is None:
        return await deps.provider_call(sanitized)  # token-only egress (FR-001)
    try:
        return await deps.egress(scope_id, sanitized)
    except EgressDenied as exc:
        await _audit(deps, scope_id, "chat", "egress_refused")
        _record(deps, scope_id, Metric.BLOCKED_EGRESS)  # masked 502 blocked-egress telemetry
        raise HTTPException(status_code=502, detail="egress refused") from exc


async def _handle_chat(deps: GatewayDeps, authorization: str | None, payload: dict) -> dict:
    scope_key, scope_id = await _auth(deps, authorization)
    with _admit(deps, scope_key):  # per-tenant graceful-overload admission (FR-047/FR-010)
        async with _slot(deps, scope_key):
            await _reserve_or_429(deps, scope_id, "chat")
            sanitized = await _sanitize_or_fail(deps, scope_id, deps.modes.get(scope_key, "gateway"), payload)
            upstream = await _egress(deps, scope_id, sanitized)  # token-only egress (FR-001/003)
            try:
                restored = await _db(deps, lambda c: restore_payload(
                    deps.key_provider, deps.detector, c, scope_id, upstream))
            except CryptoErased as exc:
                await _audit(deps, scope_id, "chat", "fail_closed")
                raise HTTPException(status_code=503, detail="restore unavailable") from exc
            await _audit(deps, scope_id, "chat", "ok")
            _record(deps, scope_id, Metric.REQUESTS)  # masked served-request telemetry (FR-011)
            return restored


async def _handle_chat_stream(deps: GatewayDeps, authorization: str | None, payload: dict) -> StreamingResponse:
    scope_key, scope_id = await _auth(deps, authorization)
    admission = _admit(deps, scope_key)  # shed 503 before any work if the tenant is saturated
    admission.__enter__()
    try:
        await _reserve_or_429(deps, scope_id, "chat_stream")
        sanitized = await _sanitize_or_fail(deps, scope_id, deps.modes.get(scope_key, "gateway"), payload)
        conn = await _acquire(deps)  # held for the stream: store.lookup runs on it
    except BaseException:
        admission.__exit__(None, None, None)
        raise
    try:
        store = await anyio.to_thread.run_sync(lambda: open_store(conn, deps.key_provider, scope_id))
    except BaseException:
        await _release(deps, conn)
        admission.__exit__(None, None, None)
        raise
    restorer = StreamRestorer(store.lookup)
    # Scope-aware egress_stream injects the central credential (008); else the 007 seam.
    source = (lambda p: deps.egress_stream(scope_id, p)) if deps.egress_stream is not None else deps.provider_stream

    async def gen() -> AsyncIterator[bytes]:
        try:
            async for frag in source(sanitized):
                out = await anyio.to_thread.run_sync(lambda f=frag: restorer.feed(f))
                if out:
                    yield f"data: {out}\n\n".encode()
            tail = await anyio.to_thread.run_sync(restorer.flush)
            if tail:
                yield f"data: {tail}\n\n".encode()
            yield b"data: [DONE]\n\n"
            await _audit(deps, scope_id, "chat_stream", "ok")
            _record(deps, scope_id, Metric.REQUESTS)  # masked served-request telemetry (FR-011)
        except Exception:  # any restore/isolation failure -> abort fail-closed, no [DONE]
            await _audit(deps, scope_id, "chat_stream", "fail_closed")
            return
        finally:
            await _release(deps, conn)
            admission.__exit__(None, None, None)  # release the per-tenant admission token

    return StreamingResponse(gen(), media_type="text/event-stream")


async def _no_provider_call(_payload: dict) -> dict:
    """Fallback provider_call when only the scope-aware egress is wired (008).

    The chat handler only reaches this when both ``egress`` and ``provider_call`` are
    absent, which is a wiring error, so it fails closed rather than egressing raw.
    """
    raise HTTPException(status_code=502, detail="egress not configured")


def create_app(*, conn=None, key_provider: KeyProvider, detector: Detector,
               provider_call: ProviderCall | None = None, scopes: ScopeResolver,
               scope_ids: dict[str, uuid.UUID], modes: dict[str, str] | None = None,
               provider_stream: ProviderStream | None = None, concurrency_cap: int = 0,
               pool: Any = None, modality_policy: dict[str, Decision] | None = None,
               egress: Egress | None = None, egress_stream: EgressStream | None = None,
               kms_health: KmsHealth | None = None,
               detector_posture: DetectorPosture | None = None,
               metrics: Metrics | None = None, metrics_enabled: bool = False,
               limiter: Limiter | None = None,
               on_shutdown: ShutdownHook | None = None) -> FastAPI:
    """Build the gateway app; route handlers live at module level for clarity.

    Supply ``pool`` (a psycopg_pool ConnectionPool) for real concurrency: each
    request checks out its own connection. ``conn`` alone is fine for sequential
    use. ``modality_policy`` opts specific non-text modalities past the gate. When
    ``egress``/``egress_stream`` are supplied the chat path injects the per-tenant
    central credential through them instead of the scope-agnostic ``provider_call``
    (008 R1); ``kms_health``/``detector_posture`` extend ``/readyz`` (008 R7).

    Operability (008 US4): ``metrics`` (a :class:`~erebus.gateway.observability.Metrics`)
    records masked per-scope telemetry; with ``metrics_enabled`` a config-gated
    ``GET /metrics`` exposes the snapshot. ``limiter`` (an
    :class:`~erebus.gateway.overload.Limiter`) applies per-tenant graceful-overload
    admission, shedding saturated requests 503 + Retry-After while preserving per-tenant
    fairness. ``on_shutdown`` is an async hook run by the FastAPI lifespan after the
    service stops accepting new work, so the server can drain its pool + httpx client
    (FR-015). All four are optional and opt-in, so 007/US1-3 wiring is unchanged.
    """
    deps = GatewayDeps(conn, key_provider, detector,
                       provider_call if provider_call is not None else _no_provider_call,
                       scopes, scope_ids, modes or {}, provider_stream, concurrency_cap,
                       pool, modality_policy or {},
                       egress=egress, egress_stream=egress_stream,
                       kms_health=kms_health, detector_posture=detector_posture,
                       metrics=metrics, metrics_enabled=metrics_enabled, limiter=limiter)
    app = FastAPI(title="Erebus Gateway", lifespan=_make_lifespan(on_shutdown))

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz() -> dict:
        return await _readyz(deps)

    @app.post("/v1/chat/completions")
    async def chat(request: Request, authorization: str | None = Header(default=None)):
        payload = await request.json()
        has_stream = deps.egress_stream is not None or deps.provider_stream is not None
        if payload.get("stream") and has_stream:
            return await _handle_chat_stream(deps, authorization, payload)
        return await _handle_chat(deps, authorization, payload)

    @app.post("/v1/reveal")
    async def reveal_route(request: Request, authorization: str | None = Header(default=None)) -> dict:
        return await _handle_reveal(deps, authorization, await request.json())

    @app.get("/v1/audit")
    async def audit_route(authorization: str | None = Header(default=None), scope_key: str = "") -> dict:
        return await _handle_audit_query(deps, authorization, scope_key)

    @app.post("/v1/admin/keys")
    async def keys_route(request: Request, authorization: str | None = Header(default=None)) -> dict:
        return await _handle_key_op(deps, authorization, await request.json())

    @app.post("/v1/admin/scopes")
    async def provision_route(request: Request, authorization: str | None = Header(default=None)) -> dict:
        return await _handle_provision(deps, authorization, await request.json())

    @app.post("/v1/admin/tenants")
    async def onboard_route(request: Request, authorization: str | None = Header(default=None)) -> dict:
        return await _handle_onboard_tenant(deps, authorization, await request.json())

    @app.delete("/v1/admin/tenants/{credential_id}")
    async def revoke_tenant_route(credential_id: str, authorization: str | None = Header(default=None)) -> dict:
        return await _handle_revoke_tenant(deps, authorization, credential_id)

    @app.post("/v1/admin/operators")
    async def operators_route(request: Request, authorization: str | None = Header(default=None)) -> dict:
        body = {}
        with contextlib.suppress(Exception):  # the JSON body is optional
            body = await request.json()
        return await _handle_issue_operator(deps, authorization, body if isinstance(body, dict) else {})

    if metrics_enabled and metrics is not None:
        @app.get("/metrics")
        async def metrics_route(authorization: str | None = Header(default=None)) -> dict:
            return await _handle_metrics(deps, authorization)

    return app


def _make_lifespan(on_shutdown: ShutdownHook | None):
    """Build the FastAPI lifespan that runs ``on_shutdown`` on graceful shutdown (FR-015).

    ASGI stops routing new requests once the lifespan begins teardown, so running the hook
    after ``yield`` drains in-flight work and releases resources only after the server has
    stopped accepting new connections. In-flight streams that are still active abort
    fail-closed (the stream generator already does so on any exception), never emitting an
    unresolved token or raw PII. The hook is awaited best-effort: a teardown error is
    swallowed so shutdown always completes.
    """
    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            if on_shutdown is not None:
                with contextlib.suppress(Exception):
                    await on_shutdown()

    return lifespan


def _state_ready(conn) -> bool:
    try:
        conn.execute("SELECT 1")
        return True
    except Exception:
        return False


async def _readyz(deps: GatewayDeps) -> dict:
    """Readiness over every critical dependency (008 R7/FR-008).

    Ready only when shared state, key custody, and detection are all healthy. A
    missing probe is treated as "not configured here" and skipped, so the basic 007
    state-only readiness keeps working when the custody/detection probes are absent.
    Detection ``regex-only`` is a deliberate, healthy posture (ready); only ``degraded``
    is not-ready. Any probe failure -> 503 so a load balancer drains the replica.
    """
    try:
        state_ok = await _db(deps, _state_ready)
    except Exception:
        state_ok = False
    if not state_ok:
        raise HTTPException(status_code=503, detail="state layer unavailable")

    if deps.kms_health is not None:
        try:
            custody_ok = await anyio.to_thread.run_sync(deps.kms_health)
        except Exception:
            custody_ok = False
        if not custody_ok:
            raise HTTPException(status_code=503, detail="key custody unavailable")

    posture = "available"
    if deps.detector_posture is not None:
        try:
            posture = await anyio.to_thread.run_sync(deps.detector_posture)
        except Exception:
            posture = "degraded"
        if posture == "degraded":
            raise HTTPException(status_code=503, detail="detection unavailable")
    return {"status": "ready", "detection": posture}
