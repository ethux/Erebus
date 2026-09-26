"""Operator configuration for the deployable gateway (008 FR-001/009/012; R6).

``GatewayConfig.from_env()`` is the single deploy input: it parses and *format*-validates
the operator environment and raises ``ConfigError`` (fail-fast) on anything malformed, so
``server.main()`` can refuse to start rather than serve half-open. Reachability of the
database and detection daemon is probed later, at startup, where live connections exist.

Secret hygiene (FR-012): error messages name the offending environment variable but never
echo its value, so a malformed master key or provider credential cannot leak via a startup
error. The master key itself is carried as the raw base64 string and handed to the KMS;
nothing here logs it.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass, field


class ConfigError(ValueError):
    """A required setting is missing or malformed; the gateway must not start."""


def _require(env: dict[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _int(env: dict[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer") from exc


def _bool(env: dict[str, str], name: str) -> bool:
    return env.get(name, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class GatewayConfig:
    """Validated operator settings; the sole input needed to deploy (FR-001)."""

    dsn: str
    master_key_b64: str
    provider_default: str
    host: str = "0.0.0.0"  # a gateway binds all interfaces by design
    port: int = 8080
    provider_model_map: dict[str, str] = field(default_factory=dict)
    detection_disabled: bool = False
    pool_min: int = 2
    pool_max: int = 8
    http_timeout_s: int = 30
    concurrency_cap: int = 0  # 0 = unlimited
    shutdown_timeout_s: int = 30  # drain window before in-flight work aborts fail-closed

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> GatewayConfig:
        """Parse + format-validate the environment; raise ConfigError on anything bad."""
        env = dict(os.environ if env is None else env)

        master_key_b64 = _require(env, "EREBUS_GATEWAY_MASTER_KEY")
        try:  # validate shape now (never echo the value); the KMS holds the raw string
            if len(base64.b64decode(master_key_b64, validate=True)) != 32:
                raise ConfigError("EREBUS_GATEWAY_MASTER_KEY must decode to 32 bytes (AES-256)")
        except (binascii.Error, ValueError) as exc:
            raise ConfigError("EREBUS_GATEWAY_MASTER_KEY must be valid base64 of 32 bytes") from exc

        model_map: dict[str, str] = {}
        raw_map = env.get("EREBUS_GATEWAY_MODEL_MAP", "").strip()
        if raw_map:
            try:
                parsed = json.loads(raw_map)
            except json.JSONDecodeError as exc:
                raise ConfigError("EREBUS_GATEWAY_MODEL_MAP must be a JSON object") from exc
            if not isinstance(parsed, dict) or not all(isinstance(v, str) for v in parsed.values()):
                raise ConfigError("EREBUS_GATEWAY_MODEL_MAP must map model->provider strings")
            model_map = parsed

        pool_min = _int(env, "EREBUS_GATEWAY_POOL_MIN", 2)
        pool_max = _int(env, "EREBUS_GATEWAY_POOL_MAX", 8)
        port = _int(env, "EREBUS_GATEWAY_PORT", 8080)
        http_timeout_s = _int(env, "EREBUS_GATEWAY_HTTP_TIMEOUT", 30)
        concurrency_cap = _int(env, "EREBUS_GATEWAY_CONCURRENCY", 0)
        shutdown_timeout_s = _int(env, "EREBUS_GATEWAY_SHUTDOWN_TIMEOUT_S", 30)

        if not 1 <= port <= 65535:
            raise ConfigError("EREBUS_GATEWAY_PORT must be in 1..65535")
        if pool_min < 1 or pool_max < pool_min:
            raise ConfigError("EREBUS_GATEWAY_POOL_MIN/MAX must satisfy 1 <= MIN <= MAX")
        if http_timeout_s <= 0:
            raise ConfigError("EREBUS_GATEWAY_HTTP_TIMEOUT must be > 0")
        if concurrency_cap < 0:
            raise ConfigError("EREBUS_GATEWAY_CONCURRENCY must be >= 0")
        if shutdown_timeout_s <= 0:
            raise ConfigError("EREBUS_GATEWAY_SHUTDOWN_TIMEOUT_S must be > 0")

        return cls(
            dsn=_require(env, "EREBUS_PG_DSN"),
            master_key_b64=master_key_b64,
            provider_default=_require(env, "EREBUS_GATEWAY_PROVIDER"),
            host=env.get("EREBUS_GATEWAY_HOST", "0.0.0.0").strip() or "0.0.0.0",
            port=port,
            provider_model_map=model_map,
            detection_disabled=_bool(env, "EREBUS_DISABLE_GLINER"),
            pool_min=pool_min,
            pool_max=pool_max,
            http_timeout_s=http_timeout_s,
            concurrency_cap=concurrency_cap,
            shutdown_timeout_s=shutdown_timeout_s,
        )

    def provider_for(self, model: str | None) -> str:
        """Resolve a request's model to its upstream provider (default if unmapped)."""
        return self.provider_model_map.get(model or "", self.provider_default)
