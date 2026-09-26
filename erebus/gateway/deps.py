"""Request dependency container + handler type aliases for the gateway app.

Holds :class:`GatewayDeps` (everything a request handler needs, injected so tests can stub
each piece) and the callable type aliases for the egress / provider / probe seams. Kept out
of ``app.py`` so that module stays within the line budget; nothing here imports the handlers
or ``create_app``, so there is no import cycle.
"""
from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

import anyio

from .crypto.keyprovider import KeyProvider
from .modalities import Decision
from .observability import Metrics
from .overload import Limiter
from .tenancy import ScopeResolver
from .tokenizer import Detector

ProviderCall = Callable[[dict], Awaitable[dict]]
ProviderStream = Callable[[dict], AsyncIterator[str]]
# Scope-aware egress seams (008 R1): when wired they replace the scope-agnostic
# provider_call/provider_stream so the per-tenant central credential + approved route
# are injected. (scope_id, sanitized_payload) -> response.
Egress = Callable[[uuid.UUID, dict], Awaitable[dict]]
EgressStream = Callable[[uuid.UUID, dict], AsyncIterator[str]]
# Liveness probes for readyz (008 R7): a kms custody check and a detection posture.
KmsHealth = Callable[[], bool]
DetectorPosture = Callable[[], str]
# Graceful-shutdown hook (008 T041): the server passes _Assembly.aclose so the
# lifespan drains the pool + httpx client after new work stops being accepted.
ShutdownHook = Callable[[], Awaitable[None]]


@dataclass
class GatewayDeps:
    """Everything a request handler needs, injected so tests can stub them."""

    conn: object
    key_provider: KeyProvider
    detector: Detector
    provider_call: ProviderCall
    scopes: ScopeResolver
    scope_ids: dict[str, uuid.UUID]
    modes: dict[str, str] = field(default_factory=dict)
    provider_stream: ProviderStream | None = None
    concurrency_cap: int = 0  # 0 = unlimited
    pool: Any = None  # psycopg_pool.ConnectionPool; None => use the shared `conn`
    modality_policy: dict[str, Decision] = field(default_factory=dict)
    # Scope-aware egress (008): when set, the chat handler injects the per-tenant
    # central credential via these instead of the scope-agnostic provider_call.
    egress: Egress | None = None
    egress_stream: EgressStream | None = None
    # Readiness probes (008 R7): custody + detection health for /readyz.
    kms_health: KmsHealth | None = None
    detector_posture: DetectorPosture | None = None
    # Masked operational telemetry (008 T042/FR-011): a per-scope counter registry
    # recording served/quota/blocked events. None => telemetry is off (no overhead).
    metrics: Metrics | None = None
    # Config-gated GET /metrics exposure (008 T044): only mounted when True so a
    # deployment that does not opt in never exposes the telemetry surface.
    metrics_enabled: bool = False
    # Graceful overload admission control (008 T043/FR-047): a per-tenant Limiter
    # registry sheds saturated requests 503 + Retry-After. None => admission is off.
    limiter: Limiter | None = None
    _sems: dict[str, anyio.Semaphore] = field(default_factory=dict, repr=False)
    # Per-tenant overload limiters, lazily minted from ``limiter`` so one tenant's
    # burst is shed against its own bound and cannot starve another (FR-047/FR-010).
    _limiters: dict[str, Limiter] = field(default_factory=dict, repr=False)
