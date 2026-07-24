"""FastAPI gateway app (research R2) wiring the per-scope services into the path.

Chat path: authenticate -> resolve scope + tokenization mode -> per-tenant
concurrency slot -> fail-closed quota reservation -> gate every message part
(text tokenized, tool-call args tokenized, non-text modalities blocked) ->
forward token-only -> restore (streamed or whole) -> audit. Governed routes:
/v1/reveal (RBAC + grant + rate-limited), GET /v1/audit (auditor), POST
/v1/admin/keys (key manager), POST /v1/admin/scopes (provisioning).

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

from . import rbac
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
from .governance import audit, reveal
from .modalities import Decision
from .observability import Metric, Metrics
from .overload import Limiter
from .providers import credentials, quota
from .runtime import (
    _acquire,
    _admit,
    _audit,
    _auth,
    _db,
    _record,
    _release,
    _slot,
)
from .store import credentials_directory
from .store.known_value_store import open_store, provision_scope
from .streaming_restore import StreamRestorer
from .tenancy import ScopeResolver
from .tokenizer import Detector
from .transport import EgressDenied


async def _reserve_or_429(deps: GatewayDeps, scope_id: uuid.UUID, event: str) -> None:
    try:
        await _db(deps, lambda c: quota.check_and_reserve(c, scope_id))
    except quota.QuotaExceeded as exc:
        await _audit(deps, scope_id, event, "quota_rejected")
        _record(deps, scope_id, Metric.QUOTA_REJECTIONS)  # masked 429 telemetry (FR-011)
        raise HTTPException(status_code=429, detail="quota exceeded",
                            headers={"Retry-After": "1"}) from exc


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


async def _handle_reveal(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    _scope_key, scope_id = await _auth(deps, authorization)
    await _reserve_or_429(deps, scope_id, "reveal")  # rate-limit detokenization (FR-018)
    grantee, role = body.get("grantee", ""), body.get("role", "")
    tokens = list(body.get("tokens", []))

    def _do(conn) -> tuple[dict | None, str]:
        if not rbac.authorize(role, rbac.Action.REVEAL):           # separation of duties (FR-016)
            return None, "rbac_denied"
        if not reveal.authorize_reveal(conn, scope_id, grantee, reveal.REVEAL_ROLE, set(tokens)):
            return None, "grant_denied"                            # scoped, justified grant (FR-015)
        store = open_store(conn, deps.key_provider, scope_id)
        return {t: store.lookup(t) for t in tokens}, "ok"

    values, outcome = await _db(deps, _do)
    await _audit(deps, scope_id, "reveal", outcome)
    if values is None:
        raise HTTPException(status_code=403, detail=f"reveal denied: {outcome}")
    return {"values": values}


async def _handle_audit_query(deps: GatewayDeps, authorization: str | None, role: str) -> dict:
    _scope_key, scope_id = await _auth(deps, authorization)
    if not rbac.authorize(role, rbac.Action.READ_AUDIT):  # auditor only (FR-016/029)
        raise HTTPException(status_code=403, detail="audit read denied")
    rows = await _db(deps, lambda c: audit.query(c, scope_id))
    return {"events": [{k: str(v) for k, v in r.items()} for r in rows]}


async def _handle_key_op(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    _scope_key, scope_id = await _auth(deps, authorization)
    role, op = body.get("role", ""), body.get("op", "")
    if not rbac.authorize(role, rbac.Action.MANAGE_KEYS):  # key manager only (FR-016/040)
        raise HTTPException(status_code=403, detail="key management denied")
    if op == "rotate":
        await anyio.to_thread.run_sync(lambda: deps.key_provider.rotate_kek(str(scope_id)))
    elif op == "crypto_erase":
        await anyio.to_thread.run_sync(lambda: deps.key_provider.destroy_kek(str(scope_id)))
    else:
        raise HTTPException(status_code=400, detail="unknown key op")
    await _audit(deps, scope_id, "key_op", op)
    return {"op": op, "status": "done"}


async def _handle_provision(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    """Declaratively provision a scope (org/tenant/group) with its own key (FR-005/047)."""
    _scope_key, scope_id = await _auth(deps, authorization)
    role, new_key = body.get("role", ""), body.get("scope_key", "")
    if not rbac.authorize(role, rbac.Action.PROVISION):  # operator / policy-admin only (FR-016)
        raise HTTPException(status_code=403, detail="provision denied")
    if not new_key:
        raise HTTPException(status_code=400, detail="scope_key required")
    sid = await _db(deps, lambda c: provision_scope(c, deps.key_provider, new_key))
    await _audit(deps, scope_id, "provision", "ok")
    return {"scope_key": new_key, "scope_id": str(sid)}


def _nonneg_int(value: object, field: str) -> int:
    """Parse ``value`` as a non-negative int, raising ``ValueError`` on anything malformed.

    ``bool`` is rejected (it is an ``int`` subclass but never a quota number), as are
    non-numeric strings and negative values, so a malformed quota fails validation up front
    rather than provisioning a half-built tenant (009 R4).
    """
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field} must be a non-negative integer") from exc
    if parsed < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return parsed


def _nonneg_decimal(value: object, field: str) -> None:
    """Validate ``value`` parses as a non-negative decimal, raising ``ValueError`` otherwise.

    The spend budget is stored as a Postgres numeric; a non-numeric or negative budget is a
    malformed quota and must be refused up front (009 R4) rather than surfacing later.
    """
    from decimal import Decimal, InvalidOperation
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a non-negative number")
    try:
        parsed = Decimal(str(value))
    except (TypeError, ValueError, InvalidOperation) as exc:
        raise ValueError(f"{field} must be a non-negative number") from exc
    if parsed < 0:
        raise ValueError(f"{field} must be a non-negative number")


def _validate_onboard(body: dict) -> None:
    """Validate an onboarding body BEFORE any write; raise ``ValueError`` on malformed input.

    ``scope_key``/``provider``/``central_credential`` must be non-empty strings, each route
    must carry a non-empty ``base_url``, and the quota numbers must parse as non-negative
    values. Validating up front means a bad request is refused with a 400 and zero rows
    created, never a partially-provisioned tenant (009 R4/FR-004).
    """
    for field in ("scope_key", "provider", "central_credential"):
        value = body.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} must be a non-empty string")
    for route in body.get("routes", []):
        if not route.get("base_url"):
            raise ValueError("each route requires a base_url")
    q = body.get("quota") or {}
    _nonneg_int(q.get("rate_limit", 0), "quota.rate_limit")
    _nonneg_int(q.get("window_seconds", 60), "quota.window_seconds")
    _nonneg_int(q.get("concurrency_cap", 0), "quota.concurrency_cap")
    _nonneg_decimal(q.get("spend_budget", 0), "quota.spend_budget")


def _onboard_tenant(deps: GatewayDeps, conn, body: dict) -> tuple[uuid.UUID, str]:
    """Wire a whole tenant atomically: scope + KEK, then credential + provider + routes + quota.

    Reuses the existing per-scope modules end to end. Inputs are validated first (a malformed
    route/quota raises before any write). The scope row + its KEK are provisioned by
    ``provision_scope``, whose KEK insert runs on the key provider's own connection and so must
    see a committed scope row; the rest -- API credential, central credential, routes, quota --
    then runs inside a SINGLE ``conn.transaction()``. If any of those steps fails the whole
    transaction rolls back AND the just-created scope is deleted (``ON DELETE CASCADE`` clears
    its KEK), so a failed onboard leaves ZERO rows -- never a partially-provisioned tenant
    (009 R4/FR-004). A scope that already existed is left intact on failure (idempotent
    re-onboard never destroys a live tenant). The API credential plaintext is returned ONCE
    (only its hash is stored). No 'policy' field is interpreted: per-tenant modality policy
    stays a deployment-level config (a supplied ``policy`` is ignored for beta).
    """
    _validate_onboard(body)
    scope_key = body["scope_key"]
    provider = body["provider"]
    q = body.get("quota") or {}
    # Read pre-existence in its own committed transaction so no implicit transaction stays
    # open: provision_scope must commit its scope-row insert (its OWN outermost transaction)
    # before the key provider, on its separate connection, inserts the KEK that FKs to it.
    with conn.transaction():
        pre_existing = conn.execute(
            "SELECT id FROM scopes WHERE scope_key = %s", (scope_key,)
        ).fetchone()
    sid = provision_scope(conn, deps.key_provider, scope_key)  # scope row + KEK (own txns)
    try:
        with conn.transaction():  # one txn: any failure here rolls back every tenant-visible row
            crypto = open_store(conn, deps.key_provider, sid)._crypto
            api_credential = credentials_directory.provision(conn, sid, scope_key, label=body.get("label", ""))
            credentials.store_credential(conn, crypto, sid, provider, body["central_credential"])
            for route in body.get("routes", []):
                rid = credentials.add_route(
                    conn, sid, provider, route["base_url"],
                    model_allowlist=route.get("model_allowlist"),
                )
                credentials.approve_route(conn, sid, rid)
            quota.set_quota(
                conn, sid,
                _nonneg_int(q.get("rate_limit", 0), "quota.rate_limit"),
                q.get("spend_budget", 0),
                _nonneg_int(q.get("window_seconds", 60), "quota.window_seconds"),
                _nonneg_int(q.get("concurrency_cap", 0), "quota.concurrency_cap"),
            )
    except BaseException:
        if pre_existing is None:  # we created the scope: undo it (cascade clears the KEK)
            with contextlib.suppress(Exception), conn.transaction():
                conn.execute("DELETE FROM scopes WHERE id = %s", (sid,))
        raise
    return sid, api_credential


async def _handle_onboard_tenant(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    """Onboard a tenant end-to-end in one operator call; serve it with no restart (008 US3).

    Operator-authenticated and RBAC-gated to PROVISION (operator / policy-admin only). All the
    wiring runs on one checked-out connection so the new tenant is resolvable immediately. The
    returned ``api_credential`` is the only time the plaintext is available (FR-006).
    """
    _scope_key, operator_scope_id = await _auth(deps, authorization)
    role = body.get("role", "")
    if not rbac.authorize(role, rbac.Action.PROVISION):  # operator / policy-admin only (FR-016)
        raise HTTPException(status_code=403, detail="onboard denied")
    if not body.get("scope_key") or not body.get("provider") or not body.get("central_credential"):
        raise HTTPException(status_code=400, detail="scope_key, provider, central_credential required")
    try:
        sid, api_credential = await _db(deps, lambda c: _onboard_tenant(deps, c, body))
    except (ValueError, KeyError) as exc:  # malformed route/quota: refuse 400, nothing written
        await _audit(deps, operator_scope_id, "onboard", "rejected")
        raise HTTPException(status_code=400, detail="invalid onboarding request") from exc
    except CryptoErased as exc:  # scope previously crypto-erased: refuse fail-closed
        await _audit(deps, operator_scope_id, "onboard", "fail_closed")
        raise HTTPException(status_code=503, detail="protection unavailable") from exc
    await _audit(deps, operator_scope_id, "onboard", "ok")
    return {"scope_id": str(sid), "api_credential": api_credential}


async def _handle_revoke_tenant(deps: GatewayDeps, authorization: str | None,
                                credential_id: str, role: str) -> dict:
    """Revoke an API credential (status -> revoked); operator-only, audited (008 US3).

    After revocation the credential resolves to nothing, so subsequent requests are rejected
    within the resolver cache TTL (FR-006).
    """
    _scope_key, operator_scope_id = await _auth(deps, authorization)
    if not rbac.authorize(role, rbac.Action.PROVISION):  # operator / policy-admin only (FR-016)
        raise HTTPException(status_code=403, detail="revoke denied")
    try:
        cred_uuid = uuid.UUID(credential_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid credential_id") from exc
    revoked = await _db(deps, lambda c: credentials_directory.revoke(c, cred_uuid))
    await _audit(deps, operator_scope_id, "revoke_tenant", "ok" if revoked else "not_found")
    if not revoked:
        raise HTTPException(status_code=404, detail="credential not found or already revoked")
    return {"credential_id": credential_id, "status": "revoked"}


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
    async def audit_route(authorization: str | None = Header(default=None),
                          x_role: str = Header(default="")) -> dict:
        return await _handle_audit_query(deps, authorization, x_role)

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
    async def revoke_tenant_route(credential_id: str, request: Request,
                                  authorization: str | None = Header(default=None),
                                  x_role: str = Header(default="")) -> dict:
        body = {}
        with contextlib.suppress(Exception):
            body = await request.json()
        role = body.get("role") or x_role
        return await _handle_revoke_tenant(deps, authorization, credential_id, role)

    if metrics_enabled and metrics is not None:
        @app.get("/metrics")
        async def metrics_route(authorization: str | None = Header(default=None),
                                x_role: str = Header(default="")) -> dict:
            return await _handle_metrics(deps, authorization, x_role)

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


def _metrics_authorized(role: str) -> bool:
    """``True`` iff ``role`` may observe the masked telemetry: an operator OR an auditor.

    Reuses the existing RBAC surface (009 R2): the audit-reader (AUDITOR) and the operational
    roles (GATEWAY_OPERATOR / POLICY_ADMIN, which hold PROVISION) may read the snapshot; every
    other role -- and an unknown role -- is denied by default.
    """
    return rbac.authorize(role, rbac.Action.READ_AUDIT) or rbac.authorize(role, rbac.Action.PROVISION)


async def _handle_metrics(deps: GatewayDeps, authorization: str | None, role: str) -> dict:
    """Return the masked per-scope telemetry snapshot, authenticated + RBAC-gated (009 R2/FR-002).

    The surface was previously open to any caller (it returned every scope id and counter).
    Now it requires an authenticated credential (else 401) AND an operator/auditor role (else
    403), like the other administrative routes; an unauthorized response discloses no scope
    ids or counters. The authorized body is ``{scope_id: {metric_name: count}}`` -- integer
    counters only, carrying no raw PII, prompt, credential, or other secret.
    """
    await _auth(deps, authorization)  # 401 on a missing/invalid credential; nothing disclosed
    if not _metrics_authorized(role):  # operator / auditor only -> 403, nothing disclosed
        raise HTTPException(status_code=403, detail="metrics read denied")
    if deps.metrics is None:
        return {"scopes": {}}
    return {"scopes": deps.metrics.snapshot_all()}


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
    Detection ``disabled`` is a deliberate, healthy posture (ready); only ``degraded``
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
