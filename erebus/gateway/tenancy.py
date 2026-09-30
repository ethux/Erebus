"""Resolve a request credential to a scope (FR-014).

``ScopeResolver`` is the static MVP/test double: a ``credential -> scope_key`` map.
``DbScopeResolver`` is the production implementation (008 R3): it resolves live against
the ``scope_credentials`` directory so tenants can be onboarded or revoked without a
redeploy. Both satisfy the same ``resolve(credential) -> scope_key | None`` contract, so
the static resolver continues to back the unit tests unchanged. Privilege (010) comes only
from the credential: the directory row for ``DbScopeResolver``, the ``operators`` set here.
"""
from __future__ import annotations

import time
from collections.abc import Iterable

from . import rbac
from .store import credentials_directory


class ScopeResolver:
    def __init__(self, credentials: dict[str, str], *, operators: Iterable[str] = ()) -> None:
        self._creds = dict(credentials)  # credential -> scope_key
        self._operators = frozenset(operators)  # credentials issued operator privilege

    def resolve(self, credential: str | None) -> str | None:
        return self._creds.get(credential or "")

    def privilege(self, credential: str | None) -> str:
        known = (credential or "") in self._creds
        return rbac.OPERATOR if known and credential in self._operators else rbac.TENANT


class DbScopeResolver:
    """Resolve a credential to its scope via the ``scope_credentials`` directory.

    Backs ``credentials_directory.resolve`` (an O(1) ``sha256`` lookup of the high-entropy
    credential) with a SHORT TTL in-process cache: hot credentials skip the round-trip, and
    because entries expire after ``ttl_s`` a revocation takes effect within that window. The
    cache is positive-only (unknown credentials are not cached) so a freshly provisioned
    credential resolves immediately. Owns its own psycopg connection pool because the
    resolver interface takes no connection; each lookup checks out its own connection, so it
    is concurrency-safe.

    The directory ``resolve`` returns ``(scope_id, scope_key)`` in ONE lookup, so
    :meth:`resolve_full` exposes both: the auth path resolves the scope id and key in a single
    round-trip (009 R5), removing the second scope-id ``SELECT`` and the TOCTOU window that
    raised a ``KeyError`` (500) when a tenant was removed between two lookups. The legacy
    :meth:`resolve` (scope_key only) keeps the original contract for any caller that needs it.
    The cached record includes the privilege; admin routes read with ``fresh=True`` so a
    revoked operator loses admin rights at once (010), while chat keeps the TTL window.
    """

    def __init__(self, dsn: str, *, ttl_s: float = 5.0,
                 min_size: int = 1, max_size: int = 4) -> None:
        from psycopg_pool import ConnectionPool  # lazy: keep ScopeResolver pool-free
        self._ttl_s = ttl_s
        # credential -> (expires_at, record)
        self._cache: dict[str, tuple[float, credentials_directory.CredentialRecord]] = {}
        self._pool = ConnectionPool(dsn, min_size=min_size, max_size=max_size, open=True)

    def close(self) -> None:
        self._pool.close()

    def resolve_record(self, credential: str | None, *,
                       fresh: bool = False) -> credentials_directory.CredentialRecord | None:
        """Resolve a credential to its directory record in one lookup, else ``None``.

        Reads the directory once, caching the positive result for ``ttl_s``. ``fresh=True``
        skips the cache and drops any cached entry, so a revocation is seen immediately. A
        revoked/removed credential resolves to ``None`` so the auth path refuses cleanly.
        """
        if not credential:
            return None
        now = time.monotonic()
        cached = self._cache.get(credential)
        if cached is not None and cached[0] > now and not fresh:
            return cached[1]
        if cached is not None:  # expired or bypassed: drop before re-checking the directory
            self._cache.pop(credential, None)
        with self._pool.connection() as conn:
            record = credentials_directory.lookup(conn, credential)
        if record is None:
            return None
        self._cache[credential] = (now + self._ttl_s, record)
        return record

    def resolve_full(self, credential: str | None):
        """Resolve a credential to ``(scope_id, scope_key)`` in one lookup, else ``None``."""
        record = self.resolve_record(credential)
        return (record.scope_id, record.scope_key) if record is not None else None

    def resolve(self, credential: str | None) -> str | None:
        record = self.resolve_record(credential)
        return record.scope_key if record is not None else None
