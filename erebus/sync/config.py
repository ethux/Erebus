"""Sync worker configuration (spec 015 "Config and deploy").

``SyncConfig.from_env()`` reads only what the worker needs: ``EREBUS_PG_DSN``,
``EREBUS_GATEWAY_MASTER_KEY``, ``EREBUS_DISABLE_GLINER`` and the ``EREBUS_SYNC_*``
settings. Gateway-only settings (``EREBUS_GATEWAY_PROVIDER`` and the rest) are never
required. Errors name the variable, never its value.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from ..gateway.config import ConfigError, master_key
from ..gateway.connectors.policy import JobTimings
from .netpolicy import HostList, NetworkPolicy, default_denied, parse_hosts


def _int(env: dict[str, str], name: str, default: int, *, minimum: int = 1) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be >= {minimum}")
    return value


def _backoff(env: dict[str, str]) -> tuple[int, ...]:
    raw = env.get("EREBUS_SYNC_BACKOFF_S", "").strip()
    if not raw:
        return JobTimings().backoff_s
    try:
        steps = tuple(int(p) for p in raw.split(","))
    except ValueError as exc:
        raise ConfigError("EREBUS_SYNC_BACKOFF_S must be comma-separated seconds") from exc
    if not steps or any(s <= 0 for s in steps):
        raise ConfigError("EREBUS_SYNC_BACKOFF_S must be comma-separated seconds")
    return steps


def _hosts(env: dict[str, str], name: str) -> HostList | None:
    raw = env.get(name, "").strip()
    if not raw:
        return None
    if raw.lower() == "none":
        return HostList()
    try:
        return parse_hosts(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} holds a malformed entry") from exc


def _sqlite_dir(env: dict[str, str]) -> Path | None:
    raw = env.get("EREBUS_SYNC_SQLITE_DIR", "").strip()
    if not raw:
        return None
    path = Path(raw)
    if not path.is_absolute() or not path.is_dir():
        raise ConfigError("EREBUS_SYNC_SQLITE_DIR must be an existing absolute directory")
    return path


@dataclass(frozen=True)
class SyncConfig:
    """Validated worker settings."""

    dsn: str
    master_key_b64: str
    policy: NetworkPolicy
    detection_disabled: bool = False
    poll_s: int = 5
    concurrency: int = 2
    tenant_max_values: int = 1_000_000
    timings: JobTimings = field(default_factory=JobTimings)

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> SyncConfig:
        """Parse and check the environment; raise ``ConfigError`` on anything bad."""
        env = dict(os.environ if env is None else env)
        dsn = env.get("EREBUS_PG_DSN", "").strip()
        if not dsn:
            raise ConfigError("EREBUS_PG_DSN is required")
        key = master_key(env)
        defaults = JobTimings()
        heartbeat_s = _int(env, "EREBUS_SYNC_HEARTBEAT_S", defaults.heartbeat_s)
        lease_s = _int(env, "EREBUS_SYNC_LEASE_S", defaults.lease_s)
        if heartbeat_s >= lease_s:
            raise ConfigError("EREBUS_SYNC_HEARTBEAT_S must be below EREBUS_SYNC_LEASE_S")
        timings = JobTimings(
            lease_s=lease_s,
            heartbeat_s=heartbeat_s,
            backoff_s=_backoff(env),
            limit_wait_s=_int(env, "EREBUS_SYNC_LIMIT_WAIT_S", defaults.limit_wait_s),
        )
        denied = _hosts(env, "EREBUS_SYNC_DENIED_HOSTS")
        policy = NetworkPolicy(
            denied=default_denied(dsn) if denied is None else denied,
            allowed=_hosts(env, "EREBUS_SYNC_ALLOWED_HOSTS"),
            sqlite_dir=_sqlite_dir(env),
        )
        return cls(
            dsn=dsn,
            master_key_b64=key,
            policy=policy,
            detection_disabled=env.get("EREBUS_DISABLE_GLINER", "").strip().lower() in {"1", "true", "yes", "on"},
            poll_s=_int(env, "EREBUS_SYNC_POLL_S", 5),
            concurrency=_int(env, "EREBUS_SYNC_CONCURRENCY", 2),
            tenant_max_values=_int(env, "EREBUS_SYNC_TENANT_MAX_VALUES", 1_000_000),
            timings=timings,
        )
