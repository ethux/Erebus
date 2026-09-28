"""Default upstream transport: central provider credential + approved route (FR-020/021/022).

The gateway never forwards the client's credential. It selects the tenant's approved
route and injects the centrally held, scope-encrypted provider credential. The HTTP
poster is injected so the credential/route selection is testable without a network.
"""
from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable

from .crypto.envelope import ScopeCrypto
from .providers import credentials

HttpPost = Callable[[str, dict, dict], Awaitable[dict]]  # (url, headers, payload) -> response


class EgressDenied(Exception):
    """Egress to a provider with no approved route for the scope (FR-021)."""


class ModelNotAllowed(EgressDenied):
    """The requested model is not on the approved route's allowlist (FR-021)."""


def build_upstream_call(conn, scope_id: uuid.UUID, crypto: ScopeCrypto, provider: str,
                        http_post: HttpPost) -> Callable[[dict], Awaitable[dict]]:
    """Return an async provider_call that injects the central credential and approved route."""

    async def call(payload: dict) -> dict:
        if not credentials.egress_allowed(conn, scope_id, provider):
            raise EgressDenied(provider)
        route = credentials.select_route(conn, scope_id, provider)
        if route is None:
            # The route was revoked/unapproved in the window after the egress_allowed
            # pre-check: fail closed rather than dereference None (FR-001).
            raise EgressDenied(provider)
        model = payload.get("model")
        if route.model_allowlist and model not in route.model_allowlist:
            raise ModelNotAllowed(f"{provider}:{model}")  # block disallowed models (FR-021)
        secret = credentials.get_credential(conn, crypto, scope_id, provider)
        if not secret:
            # The central credential was crypto-erased/deleted in the window: refuse before
            # building a header, so 'Bearer None' never reaches the provider (FR-001).
            raise EgressDenied(provider)
        headers = {"Authorization": f"Bearer {secret}"}  # central credential, never the client's
        return await http_post(route.base_url, headers, payload)

    return call
