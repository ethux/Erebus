"""What gateway extensions may use (spec 015 D6): ``app.state.erebus``.

Extensions reach core only through this facade, the worker hooks and the schema entry
point, so core never needs to know what an extension is. Nothing here checks a license:
an extension that needs one gates itself.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable
from typing import Any, NamedTuple

from ..cataloging import connector_types
from .connectors import sources
from .deps import GatewayDeps
from .runtime import Identity, _audit, _db, _identify, require_operator
from .sources_api import _is_tenant_scope
from .sources_body import parse_id
from .store.known_value_store import open_scope_crypto
from .store.scope_context import scoped


class SourceRef(NamedTuple):
    """A tenant's source as an extension sees it: no settings, no credentials."""

    id: uuid.UUID
    scope_id: uuid.UUID
    connector_type: str
    family: str | None  # None for a type this deployment does not know
    status: str


class SealedSecrets(NamedTuple):
    """Source credentials sealed under the tenant key, bound to the source id."""

    nonce: bytes
    ciphertext: bytes
    key_version: int


def _as_id(value: object) -> uuid.UUID | None:
    return value if isinstance(value, uuid.UUID) else parse_id(value) if isinstance(value, str) else None


class ErebusFacade:
    """The gateway seams for extensions; one per app, on ``app.state.erebus``."""

    scoped = staticmethod(scoped)  # (conn, scope_id): a transaction bound to the tenant for RLS

    def __init__(self, deps: GatewayDeps) -> None:
        self._deps = deps

    async def authenticate(self, authorization: str | None) -> Identity:
        """The caller's :class:`Identity`; 401 for a missing, unknown or revoked credential."""
        return await _identify(self._deps, authorization)

    async def require_operator(self, authorization: str | None, *, event: str = "admin") -> Identity:
        """Admit only an operator credential: 401 as above, 403 (audited) for a tenant."""
        return await require_operator(self._deps, authorization, event=event)

    async def db(self, fn: Callable[[Any], Any]) -> Any:
        """Run ``fn(conn)`` on a pooled connection off the event loop."""
        return await _db(self._deps, fn)

    async def audit(self, scope_id: uuid.UUID, event_type: str, outcome: str, actor: Identity | None = None,
                    metadata: dict | None = None) -> None:
        """Append an event to the tenant's audit chain; ``metadata`` holds ids and counts only."""
        await _audit(self._deps, scope_id, event_type, outcome, actor, metadata)

    async def target_scope(self, raw: object) -> uuid.UUID | None:
        """The active tenant scope ``raw`` names, or ``None`` (unknown, malformed or reserved)."""
        scope_id = _as_id(raw)
        if scope_id is None or not await _db(self._deps, lambda c: _is_tenant_scope(c, scope_id)):
            return None
        return scope_id

    async def source(self, scope_id: uuid.UUID, raw: object) -> SourceRef | None:
        """The tenant's source ``raw`` names, or ``None`` (another scope's source included)."""
        source_id = _as_id(raw)
        if source_id is None:
            return None
        info = await _db(self._deps, lambda c: sources.get_source(c, scope_id, source_id))
        if info is None:
            return None
        ctype = connector_types.get(info.connector_type)
        return SourceRef(info.id, info.scope_id, info.connector_type, ctype.family if ctype else None, info.status)

    def encrypt_source_secrets(self, conn, scope_id: uuid.UUID, source_id: uuid.UUID, secrets: dict
                               ) -> SealedSecrets:
        """Seal ``secrets`` for the source's ``secrets_*`` columns (call inside :meth:`db`)."""
        crypto = open_scope_crypto(conn, self._deps.key_provider, scope_id)
        nonce, ciphertext = sources.seal_secrets(crypto, source_id, secrets)
        return SealedSecrets(nonce, ciphertext, crypto.key_version)
