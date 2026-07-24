"""GatewayConfig.from_env parsing + fail-fast validation (008 T005; FR-009/012).

Pure logic (no Postgres/network): drives from_env() with crafted environments and
asserts precise ConfigError on each malformed input, and that a bad master key is
never echoed in the error message (FR-012 secret hygiene).
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.config import ConfigError, GatewayConfig

_KEY = base64.b64encode(b"\x01" * 32).decode()
_BASE = {
    "EREBUS_PG_DSN": "postgresql:///erebus_gateway",
    "EREBUS_GATEWAY_MASTER_KEY": _KEY,
    "EREBUS_GATEWAY_PROVIDER": "openai",
}
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _raises(env, needle=None):
    try:
        GatewayConfig.from_env(env)
    except ConfigError as exc:
        return needle is None or needle in str(exc)
    return False


def main():
    print("\n=== Gateway config parsing + fail-fast (T005) ===\n")

    cfg = GatewayConfig.from_env(_BASE)
    check("valid env parses with defaults",
          cfg.dsn == "postgresql:///erebus_gateway" and cfg.provider_default == "openai"
          and cfg.host == "0.0.0.0" and cfg.port == 8080 and cfg.shutdown_timeout_s == 30)

    check("missing EREBUS_PG_DSN fails fast",
          _raises({k: v for k, v in _BASE.items() if k != "EREBUS_PG_DSN"}, "EREBUS_PG_DSN"))
    check("missing EREBUS_GATEWAY_PROVIDER fails fast",
          _raises({k: v for k, v in _BASE.items() if k != "EREBUS_GATEWAY_PROVIDER"}, "EREBUS_GATEWAY_PROVIDER"))

    # Master key: bad base64 and wrong length both fail fast.
    check("non-base64 master key fails fast", _raises({**_BASE, "EREBUS_GATEWAY_MASTER_KEY": "not base64 !!"}))
    short = base64.b64encode(b"\x02" * 16).decode()
    check("wrong-length master key fails fast", _raises({**_BASE, "EREBUS_GATEWAY_MASTER_KEY": short}, "32 bytes"))

    # FR-012: the bad master-key VALUE must never appear in the error message.
    err = ""
    try:
        GatewayConfig.from_env({**_BASE, "EREBUS_GATEWAY_MASTER_KEY": short})
    except ConfigError as exc:
        err = str(exc)
    check("master key value is never echoed in the error (FR-012)",
          short not in err and "EREBUS_GATEWAY_MASTER_KEY" in err)

    check("pool MIN>MAX fails fast",
          _raises({**_BASE, "EREBUS_GATEWAY_POOL_MIN": "5", "EREBUS_GATEWAY_POOL_MAX": "2"}, "MIN <= MAX"))
    check("non-integer port fails fast", _raises({**_BASE, "EREBUS_GATEWAY_PORT": "abc"}))
    check("out-of-range port fails fast", _raises({**_BASE, "EREBUS_GATEWAY_PORT": "70000"}, "1..65535"))
    check("zero http timeout fails fast", _raises({**_BASE, "EREBUS_GATEWAY_HTTP_TIMEOUT": "0"}))
    check("negative concurrency fails fast", _raises({**_BASE, "EREBUS_GATEWAY_CONCURRENCY": "-1"}))
    check("zero shutdown timeout fails fast", _raises({**_BASE, "EREBUS_GATEWAY_SHUTDOWN_TIMEOUT_S": "0"}))

    dis = GatewayConfig.from_env({**_BASE, "EREBUS_DISABLE_GLINER": "1"})
    check("EREBUS_DISABLE_GLINER sets detection_disabled", dis.detection_disabled is True)
    check("detection enabled by default", cfg.detection_disabled is False)

    _map_json = '{"gpt-4o": "openai", "claude-3": "anthropic"}'
    mapped = GatewayConfig.from_env({**_BASE, "EREBUS_GATEWAY_MODEL_MAP": _map_json})
    check("model->provider map routes a mapped model", mapped.provider_for("claude-3") == "anthropic")
    check("unmapped model falls back to default provider", mapped.provider_for("mystery") == "openai")
    check("malformed model map fails fast", _raises({**_BASE, "EREBUS_GATEWAY_MODEL_MAP": "{not json"}))

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
