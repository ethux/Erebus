"""Admin API for data sources (spec 015 "Admin API"), under ``/v1/admin/scopes/{scope_id}``.

Every handler calls :func:`~erebus.gateway.runtime.require_operator` first, so a tenant
credential gets 403 before anything is parsed or written. The target tenant is the path's
``scope_id``; every query filters on it, so another scope's source is 404. Credentials are
write-only: sealed on create or PATCH, never returned. Bodies are parsed by hand
(:mod:`.sources_body`) and every error is fixed text. Nothing here loads a connector or
contacts a source system (D1); the sync worker does.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request

from . import catalog
from .connectors import fields, jobs, sources
from .crypto.keyprovider import CryptoErased
from .deps import GatewayDeps
from .runtime import Identity, _audit, _db, require_operator
from .sources_body import BodyError, parse_create, parse_decision, parse_erase, parse_id, parse_limit, parse_update
from .store.known_value_store import open_scope_crypto

PREFIX = "/v1/admin/scopes/{scope_id}"


def _not_found(what: str = "source") -> HTTPException:
    return HTTPException(status_code=404, detail=f"{what} not found")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _source_json(s: sources.SourceInfo) -> dict:
    return {"id": str(s.id), "scope_id": str(s.scope_id), "name": s.name, "type": s.connector_type,
            "settings": s.settings, "status": s.status, "credentials_expire_at": _iso(s.credentials_expire_at),
            "max_values": s.max_values, "created_at": _iso(s.created_at), "updated_at": _iso(s.updated_at),
            "pending_job": s.pending_job}


def _job_json(j: jobs.Job | None) -> dict | None:
    if j is None:
        return None
    return {"id": str(j.id), "source_id": str(j.source_id), "kind": j.kind, "status": j.status,
            "attempts": j.attempts, "created_at": _iso(j.created_at), "not_before": _iso(j.not_before),
            "started_at": _iso(j.started_at), "heartbeat_at": _iso(j.heartbeat_at),
            "finished_at": _iso(j.finished_at), "rows_seen": j.rows_seen, "values_added": j.values_added,
            "values_retired": j.values_retired, "error": j.error}


def _field_json(f: fields.SourceField) -> dict:
    return {"id": str(f.id), "collection": f.collection, "field": f.field, "db_type": f.db_type,
            "label": f.label, "decision": f.decision, "reason": f.reason, "confirmable": f.confirmable,
            "decided_by": f.decided_by}


async def _json(request: Request) -> Any:
    try:
        return await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="request body must be a JSON object") from None


async def _run(deps: GatewayDeps, fn: Callable[[Any], Any]):
    """Run ``fn`` on a pooled connection; fixed-text errors for bad bodies and erased keys."""
    try:
        return await _db(deps, fn)
    except BodyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except CryptoErased:
        raise HTTPException(status_code=503, detail="protection unavailable") from None


def _is_tenant_scope(conn, scope_id: uuid.UUID) -> bool:
    with conn.transaction():
        row = conn.execute("SELECT scope_key FROM scopes WHERE id = %s AND status = 'active'", (scope_id,)).fetchone()
    return row is not None and not row[0].startswith("_")  # '_' keys are reserved (operator home)


async def _gate(deps: GatewayDeps, authorization: str | None, raw_scope: str, event: str
                ) -> tuple[Identity, uuid.UUID]:
    """Operator first (010), then the target tenant; a missing or reserved scope is 404."""
    ident = await require_operator(deps, authorization, event=event)
    scope_id = parse_id(raw_scope)
    if scope_id is None or not await _db(deps, lambda c: _is_tenant_scope(c, scope_id)):
        raise HTTPException(status_code=404, detail="scope not found")
    return ident, scope_id


def _source_or_404(conn, scope_id: uuid.UUID, raw_id: str) -> sources.SourceInfo:
    source_id = parse_id(raw_id)
    info = sources.get_source(conn, scope_id, source_id) if source_id is not None else None
    if info is None:
        raise _not_found()
    return info


def _queue(conn, info: sources.SourceInfo, kind: str) -> tuple[jobs.Job, bool]:
    if info.status == "paused":
        raise HTTPException(status_code=409, detail="source is paused")
    try:
        return jobs.enqueue(conn, info.scope_id, info.id, kind)
    except KeyError:
        raise _not_found() from None


def _audit_meta(info: sources.SourceInfo, job: jobs.Job | None = None, **counts: Any) -> dict:
    meta = {"source_id": str(info.id), "type": info.connector_type, **counts}
    if job is not None:
        meta.update(job_id=str(job.id), kind=job.kind)
    return meta


async def create_source(deps: GatewayDeps, authorization: str | None, raw_scope: str, request: Request) -> dict:
    ident, scope_id = await _gate(deps, authorization, raw_scope, "source_create")
    raw = await _json(request)

    def _do(conn):
        new = parse_create(raw)
        crypto = open_scope_crypto(conn, deps.key_provider, scope_id)
        with conn.transaction():
            source_id = sources.create_source(
                conn, crypto, scope_id, name=new.name, connector_type=new.connector_type, settings=new.settings,
                secrets=new.secrets, credentials_expire_at=new.credentials_expire_at, max_values=new.max_values)
            job, _ = jobs.enqueue(conn, scope_id, source_id, "sample")
            return sources.get_source(conn, scope_id, source_id), job

    info, job = await _run(deps, _do)
    await _audit(deps, scope_id, "source_create", "ok", ident, _audit_meta(info, job))
    return {"source": _source_json(info), "job": _job_json(job)}


async def list_sources(deps: GatewayDeps, authorization: str | None, raw_scope: str) -> dict:
    _ident, scope_id = await _gate(deps, authorization, raw_scope, "source_list")
    rows = await _run(deps, lambda c: sources.list_sources(c, scope_id))
    return {"sources": [_source_json(s) for s in rows]}


async def update_source(deps: GatewayDeps, authorization: str | None, raw_scope: str, raw_id: str,
                        request: Request) -> dict:
    ident, scope_id = await _gate(deps, authorization, raw_scope, "source_update")
    raw = await _json(request)

    def _do(conn):
        with conn.transaction():
            old = _source_or_404(conn, scope_id, raw_id)
            change = parse_update(raw, old.connector_type)
            crypto = open_scope_crypto(conn, deps.key_provider, scope_id) if change.secrets is not None else None
            extra = {"credentials_expire_at": change.credentials_expire_at} if change.expiry_given else {}
            sources.update_source(conn, crypto, scope_id, old.id, name=change.name, settings=change.settings,
                                  secrets=change.secrets, status=change.status, max_values=change.max_values,
                                  **extra)
            # A new field map is needed when what the worker reads changed (spec 015 "Sync behaviour").
            resample = change.secrets is not None or (change.settings is not None and change.settings != old.settings)
            # Owed while paused or while a job that read the old state is active; a resume queues it.
            job = jobs.request(conn, scope_id, old.id, "sample" if resample else None)
            new = sources.get_source(conn, scope_id, old.id)
            return new, job, sorted(raw)  # field names only; parse_update refused unknown ones

    info, job, changed = await _run(deps, _do)
    await _audit(deps, scope_id, "source_update", "ok", ident, _audit_meta(info, job, changed=changed))
    return {"source": _source_json(info), "job": _job_json(job)}


async def delete_source(deps: GatewayDeps, authorization: str | None, raw_scope: str, raw_id: str) -> dict:
    ident, scope_id = await _gate(deps, authorization, raw_scope, "source_delete")
    source_id = parse_id(raw_id)
    if source_id is None:
        raise _not_found()

    def _do(conn):
        try:
            return sources.delete_source(conn, scope_id, source_id)
        except sources.SourceBusy:
            raise HTTPException(status_code=409, detail="a sync job is running for this source") from None

    retired = await _run(deps, _do)
    if retired is None:
        raise _not_found()
    await _audit(deps, scope_id, "source_delete", "ok", ident, {"source_id": str(source_id),
                                                                "values_retired": retired})
    return {"id": str(source_id), "status": "deleted", "values_retired": retired}


async def queue_job(deps: GatewayDeps, authorization: str | None, raw_scope: str, raw_id: str, kind: str) -> dict:
    """``POST .../sample`` and "sync now" (a full job): queue it or return the active one."""
    ident, scope_id = await _gate(deps, authorization, raw_scope, "source_sync")

    def _do(conn):
        return _queue(conn, _source_or_404(conn, scope_id, raw_id), kind)

    job, created = await _run(deps, _do)
    await _audit(deps, scope_id, "source_sync", "queued" if created else "already_active", ident,
                 {"source_id": str(job.source_id), "job_id": str(job.id), "kind": job.kind})
    return {"job": _job_json(job), "created": created}


async def list_fields(deps: GatewayDeps, authorization: str | None, raw_scope: str, raw_id: str) -> dict:
    _ident, scope_id = await _gate(deps, authorization, raw_scope, "source_field")

    def _do(conn):
        return fields.list_fields(conn, scope_id, _source_or_404(conn, scope_id, raw_id).id)

    return {"fields": [_field_json(f) for f in await _run(deps, _do)]}


async def decide_field(deps: GatewayDeps, authorization: str | None, raw_scope: str, raw_id: str, raw_field: str,
                       request: Request) -> dict:
    """Confirm or ignore a field; queues a full sync, which retires what is no longer read."""
    ident, scope_id = await _gate(deps, authorization, raw_scope, "source_field")
    raw = await _json(request)

    def _do(conn):
        decision = parse_decision(raw)
        with conn.transaction():
            info = _source_or_404(conn, scope_id, raw_id)
            field_id = parse_id(raw_field)
            try:
                field = fields.decide_field(conn, scope_id, info.id, field_id, decision) if field_id else None
            except fields.FieldNotConfirmable:
                raise HTTPException(status_code=409, detail="this field cannot be confirmed") from None
            if field is None:
                raise _not_found("field")
            job = jobs.request(conn, scope_id, info.id, "full")  # owed if an active job read the old map
            return info, field, job, sources.get_source(conn, scope_id, info.id).pending_job

    info, field, job, pending = await _run(deps, _do)
    await _audit(deps, scope_id, "source_field", field.decision, ident,
                 _audit_meta(info, job, field_id=str(field.id)))
    return {"field": _field_json(field), "job": _job_json(job), "pending_job": pending}


async def list_jobs(deps: GatewayDeps, authorization: str | None, raw_scope: str, raw_source: str | None,
                    raw_limit: str | None) -> dict:
    _ident, scope_id = await _gate(deps, authorization, raw_scope, "sync_jobs")

    def _do(conn):
        limit = parse_limit(raw_limit)
        source_id = _source_or_404(conn, scope_id, raw_source).id if raw_source is not None else None
        return jobs.list_jobs(conn, scope_id, source_id=source_id, limit=limit)

    return {"jobs": [_job_json(j) for j in await _run(deps, _do)]}


async def erase_value(deps: GatewayDeps, authorization: str | None, raw_scope: str, request: Request) -> dict:
    """Erase a value under every label, links and tokens included, and suppress it."""
    ident, scope_id = await _gate(deps, authorization, raw_scope, "known_value_erase")
    raw = await _json(request)

    def _do(conn):
        value = parse_erase(raw)
        return catalog.erase_value(conn, open_scope_crypto(conn, deps.key_provider, scope_id), scope_id, value)

    counts = await _run(deps, _do)
    if deps.known_values is not None:
        deps.known_values.wake()  # rebuild here now; other replicas follow the version bump
    out = {"entries_removed": counts.entries, "tokens_removed": counts.tokens}
    await _audit(deps, scope_id, "known_value_erase", "ok", ident, out)
    return out


def register(app: FastAPI, deps: GatewayDeps) -> None:
    """Add the source routes to ``app``."""
    auth = Header(default=None)

    @app.post(f"{PREFIX}/sources")
    async def create_route(scope_id: str, request: Request, authorization: str | None = auth) -> dict:
        return await create_source(deps, authorization, scope_id, request)

    @app.get(f"{PREFIX}/sources")
    async def list_route(scope_id: str, authorization: str | None = auth) -> dict:
        return await list_sources(deps, authorization, scope_id)

    @app.patch(f"{PREFIX}/sources/{{source_id}}")
    async def update_route(scope_id: str, source_id: str, request: Request, authorization: str | None = auth) -> dict:
        return await update_source(deps, authorization, scope_id, source_id, request)

    @app.delete(f"{PREFIX}/sources/{{source_id}}")
    async def delete_route(scope_id: str, source_id: str, authorization: str | None = auth) -> dict:
        return await delete_source(deps, authorization, scope_id, source_id)

    @app.post(f"{PREFIX}/sources/{{source_id}}/sample")
    async def sample_route(scope_id: str, source_id: str, authorization: str | None = auth) -> dict:
        return await queue_job(deps, authorization, scope_id, source_id, "sample")

    @app.post(f"{PREFIX}/sources/{{source_id}}/sync")
    async def sync_route(scope_id: str, source_id: str, authorization: str | None = auth) -> dict:
        return await queue_job(deps, authorization, scope_id, source_id, "full")

    @app.get(f"{PREFIX}/sources/{{source_id}}/fields")
    async def fields_route(scope_id: str, source_id: str, authorization: str | None = auth) -> dict:
        return await list_fields(deps, authorization, scope_id, source_id)

    @app.patch(f"{PREFIX}/sources/{{source_id}}/fields/{{field_id}}")
    async def field_route(scope_id: str, source_id: str, field_id: str, request: Request,
                          authorization: str | None = auth) -> dict:
        return await decide_field(deps, authorization, scope_id, source_id, field_id, request)

    @app.get(f"{PREFIX}/sync-jobs")
    async def jobs_route(scope_id: str, source_id: str | None = None, limit: str | None = None,
                         authorization: str | None = auth) -> dict:
        return await list_jobs(deps, authorization, scope_id, source_id, limit)

    @app.post(f"{PREFIX}/known-values/erase")
    async def erase_route(scope_id: str, request: Request, authorization: str | None = auth) -> dict:
        return await erase_value(deps, authorization, scope_id, request)
