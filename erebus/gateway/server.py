"""Configurable gateway entrypoint: assemble + launch the deployable service (008 R6/R7).

``build_app_from_config(config)`` is the single assembly path the deploy artifact and the
acceptance harness share: it builds the connection pool, the restart-safe key custody
(:class:`~erebus.gateway.crypto.keyprovider.MasterKeyKms`), the production detector, the
dynamic :class:`~erebus.gateway.tenancy.DbScopeResolver`, the httpx-backed egress, runs the
(idempotent) migrations, and returns a wired :class:`fastapi.FastAPI` app together with a
shutdown closure that drains the pool, the KMS pool, the resolver pool, and the httpx client.

``main()`` is the ``erebus-gateway`` console script: it loads ``GatewayConfig.from_env()``,
*probes* the critical dependencies (DB reachable, master key valid, detection reachable
unless explicitly disabled) and **exits non-zero before binding** on any failure so the
service never serves half-open (FR-009). Secret hygiene (FR-012): failure messages name the
faulty setting but never echo its value; the master key is never logged.

The scope directory is dynamic: ``DbScopeResolver`` resolves a credential to its
``(scope_id, scope_key)`` in ONE lookup (009 R5), so the auth path needs no separate
``scope_key -> scope_id`` directory -- a freshly onboarded tenant is still servable with no
restart. :class:`_ScopeIdDirectory` is retained as a standalone live ``scope_key -> scope_id``
view for callers/tests that want one, but the app no longer wires it.
"""
from __future__ import annotations

import sys
import uuid
from dataclasses import dataclass

from .app import create_app
from .config import ConfigError, GatewayConfig
from .crypto.keyprovider import MasterKeyKms
from .detection import build_detector
from .egress import build_egress, build_egress_stream
from .http_provider import build_http_post, close_client
from .observability import Metrics
from .overload import Limiter
from .store import db
from .tenancy import DbScopeResolver


class _ScopeIdDirectory:
    """A live ``scope_key -> scope_id`` view over the shared ``scopes`` table.

    Standalone dict-like helper: each lookup checks out a pooled connection and reads
    ``scopes`` for an ``active`` row, so a newly provisioned scope resolves immediately
    (FR-005/006); misses are not cached, so they never mask an onboarding. The auth path no
    longer wires this -- ``DbScopeResolver`` returns the scope id in one lookup (009 R5) -- but
    it remains available for callers/tests that want a live id directory.
    """

    def __init__(self, pool) -> None:
        self._pool = pool

    def _lookup(self, scope_key: str) -> uuid.UUID | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT id FROM scopes WHERE scope_key = %s AND status = 'active'",
                (scope_key,),
            ).fetchone()
        return row[0] if row else None

    def __contains__(self, scope_key: object) -> bool:
        return isinstance(scope_key, str) and self._lookup(scope_key) is not None

    def __getitem__(self, scope_key: str) -> uuid.UUID:
        sid = self._lookup(scope_key)
        if sid is None:
            raise KeyError(scope_key)
        return sid


def _kms_health_probe(kms: MasterKeyKms):
    """Return the no-secret custody probe for ``/readyz``: ``kms.health`` (008 T038/FR-012).

    Delegates to :meth:`MasterKeyKms.health`, which touches the custody store over the KMS's
    own pool without unwrapping any scope key, so a custody outage surfaces in ``/readyz``
    while never decrypting or logging key material.
    """
    return kms.health


@dataclass
class _Assembly:
    """A built app plus the resources to close on shutdown (FR-015)."""

    app: object
    pool: object
    kms: MasterKeyKms
    resolver: DbScopeResolver
    client: object

    async def aclose(self) -> None:
        """Drain in order: httpx client, then the three connection pools. Never raises."""
        import contextlib
        with contextlib.suppress(Exception):
            await close_client(self.client)
        for closer in (self.resolver.close, self.kms.close, self.pool.close):
            with contextlib.suppress(Exception):
                closer()


def build_app_from_config(config: GatewayConfig):
    """Assemble the wired gateway from ``config`` (R6); return ``(app, assembly)``.

    Builds the pool, ``MasterKeyKms``, detector, ``DbScopeResolver``, httpx ``http_post`` /
    ``http_stream``, and the scope-aware egress; runs migrations idempotently; and returns
    the FastAPI app plus an :class:`_Assembly` whose :meth:`_Assembly.aclose` releases every
    pool and the httpx client on shutdown.
    """
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(config.dsn, min_size=config.pool_min, max_size=config.pool_max, open=True)
    # Run migrations on a checked-out connection in autocommit so the KMS/resolver pools
    # (separate connections) see the schema (idempotent + recorded).
    with pool.connection() as conn:
        conn.autocommit = True
        db.run_migrations(conn)

    kms = MasterKeyKms(config.dsn, config.master_key_b64)
    detector = build_detector(config)
    resolver = DbScopeResolver(config.dsn)
    http_post, http_stream, client = build_http_post(config)
    egress = build_egress(pool, kms, config, http_post)
    egress_stream = build_egress_stream(pool, kms, config, http_stream)

    # Operability for the deployed service: masked telemetry is always on (FR-011); when
    # the operator sets a per-tenant concurrency cap, a burst is shed gracefully (503 +
    # Retry-After) by the Limiter instead of the _slot semaphore queueing (FR-010). With
    # no cap (0 = unlimited, the default) neither control is applied.
    metrics = Metrics()
    limiter = None
    slot_cap = config.concurrency_cap
    if config.concurrency_cap > 0:
        limiter = Limiter(max_concurrent=config.concurrency_cap, max_queue=0, retry_after_seconds=1)
        slot_cap = 0

    # Build the assembly first so its drain closure (FR-015) can be handed to the
    # FastAPI lifespan via create_app(on_shutdown=...); app is backfilled below.
    assembly = _Assembly(None, pool, kms, resolver, client)
    app = create_app(
        key_provider=kms,
        detector=detector,
        scopes=resolver,
        # The resolver yields the scope id alongside the key in one lookup (009 R5), so the
        # auth path no longer needs a separate scope_key -> scope_id directory: pass an empty
        # dict (the static fallback is unused on the dynamic path).
        scope_ids={},
        egress=egress,
        egress_stream=egress_stream,
        pool=pool,
        concurrency_cap=slot_cap,
        kms_health=_kms_health_probe(kms),
        detector_posture=getattr(detector, "posture", None),
        metrics=metrics,
        metrics_enabled=True,
        limiter=limiter,
        on_shutdown=assembly.aclose,  # lifespan drains pool + httpx on shutdown (FR-015)
    )
    assembly.app = app
    return app, assembly


def _probe_or_die(config: GatewayConfig) -> None:
    """Probe critical deps; on any failure print a precise message and exit non-zero.

    Runs BEFORE binding (FR-009): DB reachable, master key valid (a real KEK wrap round-trip),
    and detection reachable unless explicitly disabled. Messages name the faulty dependency
    but never echo a secret (FR-012).
    """
    import psycopg

    try:
        with psycopg.connect(config.dsn) as conn:
            conn.execute("SELECT 1")
    except Exception as exc:
        _die(f"database unreachable at EREBUS_PG_DSN: {type(exc).__name__}")

    # Master key well-formed AND usable: construct the KMS (validates base64 + 32 bytes) and
    # exercise a wrap/unwrap round-trip on an ephemeral key so a corrupt key fails fast.
    kms = None
    try:
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

        kms = MasterKeyKms(config.dsn, config.master_key_b64)
        import os
        probe_kek = os.urandom(32)
        wrapped, nonce = kms._wrapper.wrap(probe_kek)
        if kms._wrapper.unwrap(wrapped, nonce) != probe_kek:
            raise ValueError("master key wrap round-trip mismatch")
        dek = os.urandom(32)
        if aes_key_unwrap(probe_kek, aes_key_wrap(probe_kek, dek)) != dek:
            raise ValueError("DEK wrap round-trip mismatch")
    except Exception as exc:
        _die(f"key custody unavailable (check EREBUS_GATEWAY_MASTER_KEY): {type(exc).__name__}")
    finally:
        if kms is not None:
            kms.close()

    if not config.detection_disabled:
        try:
            detector = build_detector(config)
            posture = detector.posture()
        except Exception as exc:
            _die(f"detection unreachable (set EREBUS_DISABLE_GLINER to run without it): {type(exc).__name__}")
        if posture == "degraded":
            _die("detection unreachable (set EREBUS_DISABLE_GLINER to run without it): degraded")


def _die(message: str) -> None:
    """Print a precise startup failure to stderr and exit non-zero (never a secret)."""
    print(f"erebus-gateway: {message}", file=sys.stderr)
    raise SystemExit(2)


def main() -> None:
    """``erebus-gateway`` entrypoint: validate + probe, then serve (R6).

    Loads ``GatewayConfig.from_env()`` (format validation, fail-fast on malformed env),
    probes the critical dependencies and exits non-zero before binding on any failure, then
    runs uvicorn on the configured host/port. A FastAPI lifespan drains the pool + httpx
    client on SIGTERM/SIGINT for a graceful shutdown (FR-015).
    """
    try:
        config = GatewayConfig.from_env()
    except ConfigError as exc:
        _die(str(exc))

    _probe_or_die(config)

    import uvicorn

    # build_app_from_config wires assembly.aclose into the app's FastAPI lifespan via
    # create_app(on_shutdown=...), so SIGTERM/SIGINT drains the pool + httpx (FR-015).
    app, _assembly = build_app_from_config(config)
    uvicorn.run(app, host=config.host, port=config.port, timeout_graceful_shutdown=config.shutdown_timeout_s)


if __name__ == "__main__":
    main()
