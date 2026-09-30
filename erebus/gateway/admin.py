"""Governed admin route handlers for the gateway app (extracted from app.py).

Every handler here calls :func:`~erebus.gateway.runtime.require_operator` before any side
effect, so authority comes only from the privilege stored on the caller's credential (010):
no body ``role`` field or ``X-Role`` header is consulted. Operators live in a reserved home
scope, so audit, key and reveal calls name their target with an explicit ``scope_key``.
Nothing here imports ``app.py``, so there is no import cycle.
"""
from __future__ import annotations

import contextlib
import uuid

import anyio
from fastapi import HTTPException

from . import rbac
from .crypto.keyprovider import CryptoErased
from .deps import GatewayDeps
from .governance import audit, reveal
from .providers import credentials, quota
from .runtime import _audit, _db, _reserve_or_429, _target_scope, require_operator
from .store import credentials_directory
from .store.known_value_store import open_store, provision_scope


def _tenant_scope_key(value: object) -> str:
    """A non-empty tenant scope key; ``_``-prefixed keys are reserved (010: operator home)."""
    if not isinstance(value, str) or not value:
        raise ValueError("scope_key must be a non-empty string")
    if value.startswith("_"):
        raise ValueError("scope_key may not start with '_' (reserved)")
    return value


async def _handle_reveal(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    ident = await require_operator(deps, authorization, event="reveal")  # role gate (010)
    scope_id = await _target_scope(deps, ident, body.get("scope_key"))
    await _reserve_or_429(deps, scope_id, "reveal")  # rate-limit detokenization on the target (FR-018)
    grantee = body.get("grantee", "")
    tokens = list(body.get("tokens", []))

    def _do(conn) -> tuple[dict | None, str]:
        if not reveal.authorize_reveal(conn, scope_id, grantee, reveal.REVEAL_ROLE, set(tokens)):
            return None, "grant_denied"                            # scoped, justified grant (FR-015)
        store = open_store(conn, deps.key_provider, scope_id)
        return {t: store.lookup(t) for t in tokens}, "ok"

    values, outcome = await _db(deps, _do)
    await _audit(deps, scope_id, "reveal", outcome, ident)
    if values is None:
        raise HTTPException(status_code=403, detail=f"reveal denied: {outcome}")
    return {"values": values}


async def _handle_audit_query(deps: GatewayDeps, authorization: str | None, scope_key: str) -> dict:
    ident = await require_operator(deps, authorization, event="audit_read")
    scope_id = await _target_scope(deps, ident, scope_key)  # default: the operator's own chain
    rows = await _db(deps, lambda c: audit.query(c, scope_id))
    return {"events": [{k: str(v) for k, v in r.items()} for r in rows]}


async def _handle_key_op(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    ident = await require_operator(deps, authorization, event="key_op")
    op = body.get("op", "")
    if op not in ("rotate", "crypto_erase"):
        raise HTTPException(status_code=400, detail="unknown key op")
    # Irreversible, so the target is never defaulted to the caller's own scope.
    scope_id = await _target_scope(deps, ident, body.get("scope_key"), required=True)
    if op == "rotate":
        await anyio.to_thread.run_sync(lambda: deps.key_provider.rotate_kek(str(scope_id)))
    else:
        await anyio.to_thread.run_sync(lambda: deps.key_provider.destroy_kek(str(scope_id)))
    await _audit(deps, scope_id, "key_op", op, ident)
    return {"op": op, "status": "done"}


async def _handle_provision(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    """Declaratively provision a scope (org/tenant/group) with its own key (FR-005/047)."""
    ident = await require_operator(deps, authorization, event="provision")
    try:
        new_key = _tenant_scope_key(body.get("scope_key"))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="scope_key required (may not start with '_')") from exc
    sid = await _db(deps, lambda c: provision_scope(c, deps.key_provider, new_key))
    await _audit(deps, ident.scope_id, "provision", "ok", ident)
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

    ``scope_key``/``provider``/``central_credential`` must be non-empty strings (and the scope
    key may not use the reserved ``_`` prefix), each route must carry a non-empty ``base_url``,
    and the quota numbers must parse as non-negative values. Validating up front means a bad
    request is refused with a 400 and zero rows created, never a partially-provisioned tenant
    (009 R4/FR-004).
    """
    for field in ("scope_key", "provider", "central_credential"):
        value = body.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"{field} must be a non-empty string")
    _tenant_scope_key(body["scope_key"])
    for route in body.get("routes", []):
        if not route.get("base_url"):
            raise ValueError("each route requires a base_url")
    q = body.get("quota") or {}
    _nonneg_int(q.get("rate_limit", 0), "quota.rate_limit")
    _nonneg_int(q.get("window_seconds", 60), "quota.window_seconds")
    _nonneg_int(q.get("concurrency_cap", 0), "quota.concurrency_cap")
    _nonneg_decimal(q.get("spend_budget", 0), "quota.spend_budget")


def _onboard_tenant(deps: GatewayDeps, conn, body: dict) -> tuple[uuid.UUID, uuid.UUID, str]:
    """Wire a whole tenant atomically: scope + KEK, then credential + provider + routes + quota.

    Reuses the existing per-scope modules end to end. Inputs are validated first (a malformed
    route/quota raises before any write). The scope row + its KEK are provisioned by
    ``provision_scope``, whose KEK insert runs on the key provider's own connection and so must
    see a committed scope row; the rest -- API credential, central credential, routes, quota --
    then runs inside a SINGLE ``conn.transaction()``. If any of those steps fails the whole
    transaction rolls back AND the just-created scope is deleted (``ON DELETE CASCADE`` clears
    its KEK), so a failed onboard leaves ZERO rows -- never a partially-provisioned tenant
    (009 R4/FR-004). A scope that already existed is left intact on failure (idempotent
    re-onboard never destroys a live tenant). Returns ``(scope_id, credential_id, plaintext)``;
    the API credential plaintext is returned ONCE (only its hash is stored) and is always a
    TENANT credential: no body field can elevate it (010). No 'policy' field is interpreted:
    per-tenant modality policy stays a deployment-level config (ignored for beta).
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
            cred_id, api_credential = credentials_directory.issue(
                conn, sid, scope_key, label=body.get("label", ""), privilege=rbac.TENANT)
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
    return sid, cred_id, api_credential


async def _handle_onboard_tenant(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    """Onboard a tenant end-to-end in one operator call; serve it with no restart (008 US3).

    Operator-credential only (010). All the wiring runs on one checked-out connection so the
    new tenant is resolvable immediately. The returned ``api_credential`` is the only time the
    plaintext is available (FR-006); ``credential_id`` is what DELETE revokes by.
    """
    ident = await require_operator(deps, authorization, event="onboard")
    if not body.get("scope_key") or not body.get("provider") or not body.get("central_credential"):
        raise HTTPException(status_code=400, detail="scope_key, provider, central_credential required")
    try:
        sid, cred_id, api_credential = await _db(deps, lambda c: _onboard_tenant(deps, c, body))
    except (ValueError, KeyError) as exc:  # malformed route/quota: refuse 400, nothing written
        await _audit(deps, ident.scope_id, "onboard", "rejected", ident)
        raise HTTPException(status_code=400, detail="invalid onboarding request") from exc
    except CryptoErased as exc:  # scope previously crypto-erased: refuse fail-closed
        await _audit(deps, ident.scope_id, "onboard", "fail_closed", ident)
        raise HTTPException(status_code=503, detail="protection unavailable") from exc
    await _audit(deps, ident.scope_id, "onboard", "ok", ident)
    return {"scope_id": str(sid), "credential_id": str(cred_id), "api_credential": api_credential}


async def _handle_revoke_tenant(deps: GatewayDeps, authorization: str | None, credential_id: str) -> dict:
    """Revoke any API credential, tenant or operator (status -> revoked); operator-only, audited.

    The gate runs before the id is parsed, so a tenant learns nothing about ids. Admin routes
    re-read the directory, so a revoked operator loses admin rights at once; chat catches up
    within the resolver cache TTL (FR-006).
    """
    ident = await require_operator(deps, authorization, event="revoke_tenant")
    try:
        cred_uuid = uuid.UUID(credential_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid credential_id") from exc
    revoked = await _db(deps, lambda c: credentials_directory.revoke(c, cred_uuid))
    await _audit(deps, ident.scope_id, "revoke_tenant", "ok" if revoked else "not_found", ident)
    if not revoked:
        raise HTTPException(status_code=404, detail="credential not found or already revoked")
    return {"credential_id": credential_id, "status": "revoked"}


async def _handle_issue_operator(deps: GatewayDeps, authorization: str | None, body: dict) -> dict:
    """Issue another operator credential; operator-only, plaintext returned ONCE (010 US4).

    The new credential is bound to the caller's home scope. This is the only HTTP path that
    mints operator privilege; tenant onboarding never does.
    """
    ident = await require_operator(deps, authorization, event="issue_operator")
    label = body.get("label", "")
    if not isinstance(label, str):
        raise HTTPException(status_code=400, detail="label must be a string")
    cred_id, token = await _db(deps, lambda c: credentials_directory.issue(
        c, ident.scope_id, ident.scope_key, label=label, privilege=rbac.OPERATOR))
    await _audit(deps, ident.scope_id, "issue_operator", "ok", ident)
    return {"credential_id": str(cred_id), "api_credential": token}


async def _handle_metrics(deps: GatewayDeps, authorization: str | None) -> dict:
    """Return the masked per-scope telemetry snapshot to an operator credential (009 R2, 010).

    A missing/unknown credential gets 401 and a tenant 403; neither discloses scope ids or
    counters. The authorized body is ``{scope_id: {metric_name: count}}`` -- integer counters
    only, carrying no raw PII, prompt, credential, or other secret.
    """
    await require_operator(deps, authorization, event="metrics")
    if deps.metrics is None:
        return {"scopes": {}}
    return {"scopes": deps.metrics.snapshot_all()}
