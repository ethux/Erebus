"""Scope-aware egress seam (008 T023; research R1, FR-003/020/021/022).

The 007 chat handler carries no scope context, so the tested credential-injection
transport (:func:`erebus.gateway.transport.build_upstream_call`) never reaches the
live request path. This module supplies that missing thread: an ``Egress`` callable
``(scope_id, sanitized_payload) -> response`` that, per request, checks out a pooled
connection, opens the scope's crypto/store, resolves the request's provider from the
operator config (model -> provider, default), and invokes the existing upstream
transport. ``build_upstream_call`` injects the central, scope-encrypted provider
credential and selects the approved route; this seam strips any client-supplied
credential from the payload BEFORE the transport runs, so the central credential is the
only Authorization that reaches the provider (FR-003).

Egress fails closed: a missing/unapproved route, a disallowed model, a missing model when
the route requires one, a missing/revoked central credential, a quota refusal, or any
crypto/state failure raises :class:`~erebus.gateway.transport.EgressDenied` so the caller
can return a fail-closed status (502) without leaking raw PII.
"""
from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable

import anyio

from .config import GatewayConfig
from .crypto.keyprovider import KeyProvider
from .providers import credentials
from .providers.quota import QuotaExceeded
from .store.known_value_store import open_store
from .transport import EgressDenied, HttpPost, ModelNotAllowed

Egress = Callable[[uuid.UUID, dict], Awaitable[dict]]              # (scope_id, payload) -> response
EgressStream = Callable[[uuid.UUID, dict], AsyncIterator[str]]      # scope-aware streaming

# (url, headers, payload) -> async iterator of SSE fragments; the streaming poster.
HttpStream = Callable[[str, dict, dict], AsyncIterator[str]]

# Top-level payload keys a client might use to smuggle its own provider credential into
# the request body. The gateway injects the per-tenant CENTRAL credential as the upstream
# Authorization header, so any client-supplied credential is dropped before egress (FR-003):
# the central credential is the ONLY Authorization that reaches the provider. Matched
# case-insensitively (and ignoring '-'/'_') so "api-key"/"api_key"/"X-Api-Key" all drop.
_CLIENT_CREDENTIAL_KEYS = frozenset({
    "authorization", "apikey", "xapikey", "apersonalapikey",
    "openaiapikey", "anthropicapikey", "key", "secret", "credential", "token",
})


def _drop_client_credential(payload: dict) -> dict:
    """Return a shallow copy of ``payload`` with any client-supplied credential key removed.

    A client could place its own provider key in the request body (e.g. ``authorization``,
    ``api_key``, ``x-api-key``) hoping it rides upstream. The gateway never forwards it
    (FR-003): we strip those keys here, BEFORE :func:`build_upstream_call`, so the only
    Authorization the provider sees is the tenant's central credential. Non-credential
    fields (model, messages, stream, ...) are untouched.
    """
    out = {}
    for key, value in payload.items():
        normalized = str(key).replace("-", "").replace("_", "").casefold()
        if normalized in _CLIENT_CREDENTIAL_KEYS:
            continue  # client credential never egresses (FR-003)
        out[key] = value
    return out


def _open_scope(conn, kms: KeyProvider, scope_id: uuid.UUID):
    """Open the scope's crypto on a checked-out connection (raises if unprovisioned/erased)."""
    return open_store(conn, kms, scope_id)._crypto


def _resolve_egress(conn, crypto, scope_id: uuid.UUID, provider: str,
                    model: str | None) -> tuple[str, str]:
    """Resolve the approved route + central credential ONCE, fail-closed (R1/R3, FR-001).

    Runs the synchronous allow/route/credential lookups together (the caller offloads this
    whole unit onto a worker thread so the event loop stays unblocked; R3/FR-003) and
    returns ``(base_url, secret)``. A missing/unapproved route, a model absent from the
    route allowlist, or a missing/erased credential raises :class:`EgressDenied` (FR-001):
    every ``... | None`` return is guarded here so the send-site never dereferences ``None``
    nor builds a ``Bearer None`` header.
    """
    if not credentials.egress_allowed(conn, scope_id, provider):
        raise EgressDenied(provider)
    route = credentials.select_route(conn, scope_id, provider)
    if route is None:
        # Revoked/unapproved in the window after the pre-check: fail closed (FR-001).
        raise EgressDenied(provider)
    if route.model_allowlist and model not in route.model_allowlist:
        raise ModelNotAllowed(f"{provider}:{model}")  # block disallowed models (FR-021)
    secret = credentials.get_credential(conn, crypto, scope_id, provider)
    if not secret:
        # Crypto-erased/deleted in the window: refuse before building any header (FR-001).
        raise EgressDenied(provider)
    return route.base_url, secret


def build_egress(pool, kms: KeyProvider, config: GatewayConfig, http_post: HttpPost) -> Egress:
    """Return an ``Egress`` that egresses token-only via the per-tenant central credential.

    Per request: pooled conn -> open scope crypto -> resolve provider from the payload's
    model (``config.provider_for``) -> drop any client credential from the payload -> fail
    closed if the central credential is missing/revoked -> :func:`build_upstream_call` (binds
    the approved route + model allowlist) -> invoke. The central credential is the only
    Authorization sent; the client's is never forwarded (FR-003). A missing/unapproved route,
    a disallowed/missing model, a missing credential, a quota refusal, or any crypto/state
    failure surfaces fail-closed as :class:`EgressDenied`.
    """

    async def egress(scope_id: uuid.UUID, payload: dict) -> dict:
        provider = config.provider_for(payload.get("model"))
        model = payload.get("model")
        # Drop any client-supplied credential BEFORE the transport runs, so the only
        # Authorization reaching the provider is the tenant's central credential (FR-003).
        sanitized = _drop_client_credential(payload)
        conn = await anyio.to_thread.run_sync(pool.getconn)
        try:
            crypto = await anyio.to_thread.run_sync(lambda: _open_scope(conn, kms, scope_id))
            # Resolve allow/route/credential ONCE, OFF the event-loop thread, so the sync DB
            # work no longer blocks the loop (R3/FR-003). Every None is guarded inside
            # _resolve_egress so the send-site never builds 'Bearer None' (R1/FR-001).
            base_url, secret = await anyio.to_thread.run_sync(
                lambda: _resolve_egress(conn, crypto, scope_id, provider, model)
            )
            headers = {"Authorization": f"Bearer {secret}"}  # central credential, never the client's
            return await http_post(base_url, headers, sanitized)
        except EgressDenied:
            raise  # already a fail-closed signal (no route / model not allowed / no credential)
        except QuotaExceeded as exc:  # a quota refusal must fail closed, not leak (FR-039)
            raise EgressDenied(f"{provider}: quota refused") from exc
        except Exception as exc:  # missing credential / crypto-erased / state failure
            raise EgressDenied(f"{provider}: egress unavailable") from exc
        finally:
            await anyio.to_thread.run_sync(lambda: pool.putconn(conn))

    return egress


def build_egress_stream(pool, kms: KeyProvider, config: GatewayConfig,
                        http_stream: HttpStream) -> EgressStream:
    """Return an ``EgressStream`` mirroring :func:`build_egress` for streaming responses.

    Resolves the provider, opens the scope crypto, and enforces the approved route +
    model allowlist + central credential exactly as the non-streaming path (so a client
    credential is never forwarded and an unapproved route fails closed), then streams the
    upstream SSE fragments. The pooled connection is held for the lifetime of the stream
    and released when it ends or aborts.
    """

    async def egress_stream(scope_id: uuid.UUID, payload: dict) -> AsyncIterator[str]:
        provider = config.provider_for(payload.get("model"))
        model = payload.get("model")
        # Drop any client-supplied credential before streaming upstream, mirroring the
        # non-streaming path: the central credential is the only Authorization sent (FR-003).
        sanitized = _drop_client_credential(payload)
        conn = await anyio.to_thread.run_sync(pool.getconn)
        try:
            crypto = await anyio.to_thread.run_sync(lambda: _open_scope(conn, kms, scope_id))
            try:
                # Resolve allow/route/credential ONCE, off-loop, exactly like the
                # non-streaming path. Every None (route revoked / credential erased in the
                # race) is guarded inside _resolve_egress, so the stream never dereferences
                # None nor builds 'Bearer None' (R1/FR-001); model allowlist is enforced too.
                base_url, secret = await anyio.to_thread.run_sync(
                    lambda: _resolve_egress(conn, crypto, scope_id, provider, model)
                )
                headers = {"Authorization": f"Bearer {secret}"}  # central credential, never the client's
            except EgressDenied:
                raise
            except QuotaExceeded as exc:  # a quota refusal must fail closed, not leak (FR-039)
                raise EgressDenied(f"{provider}: quota refused") from exc
            except Exception as exc:  # crypto-erased / state failure
                raise EgressDenied(f"{provider}: egress unavailable") from exc
            async for frag in http_stream(base_url, headers, sanitized):
                yield frag
        finally:
            await anyio.to_thread.run_sync(lambda: pool.putconn(conn))

    return egress_stream
