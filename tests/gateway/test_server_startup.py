"""Config-driven server assembly + readiness (008 T017; R6/R7, FR-001/008/009).

Proves the deployable entrypoint: ``build_app_from_config`` boots a serving app from a
``GatewayConfig`` (detection disabled so no GLiNER daemon is needed), migrations run
idempotently on its own pool, ``/healthz`` is always up and ``/readyz`` reflects live
dependency health (state + custody up, detection 'disabled' is healthy), a freshly
provisioned tenant resolves with no restart, and ``GatewayConfig.from_env`` fails fast with
``ConfigError`` on malformed env. Live Postgres; self-skips without it.
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.config import ConfigError, GatewayConfig
from erebus.gateway.server import build_app_from_config

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_us1_server")
_KEY = base64.b64encode(os.urandom(32)).decode()
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _config() -> GatewayConfig:
    return GatewayConfig.from_env({
        "EREBUS_PG_DSN": _DSN,
        "EREBUS_GATEWAY_MASTER_KEY": _KEY,
        "EREBUS_GATEWAY_PROVIDER": "openai",
        "EREBUS_DISABLE_GLINER": "1",  # no GLiNER daemon needed for a boot/readiness test
        "EREBUS_GATEWAY_POOL_MIN": "1",
        "EREBUS_GATEWAY_POOL_MAX": "3",
    })


def _config_checks():
    """Format validation fails fast (no DB needed); runs even when Postgres is absent."""
    bad = False
    try:
        GatewayConfig.from_env({"EREBUS_GATEWAY_MASTER_KEY": _KEY, "EREBUS_GATEWAY_PROVIDER": "openai"})
    except ConfigError:
        bad = True
    check("from_env without EREBUS_PG_DSN raises ConfigError (fail-fast, FR-009)", bad)

    bad = False
    try:
        GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN,
            "EREBUS_GATEWAY_MASTER_KEY": "not-valid-base64!!",
            "EREBUS_GATEWAY_PROVIDER": "openai",
        })
    except ConfigError as exc:
        # The error names the variable but must never echo the (would-be) secret value.
        bad = "EREBUS_GATEWAY_MASTER_KEY" in str(exc) and "not-valid-base64" not in str(exc)
    check("from_env with a malformed master key raises ConfigError, no secret echoed (FR-012)", bad)

    bad = False
    try:
        GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN,
            "EREBUS_GATEWAY_MASTER_KEY": _KEY,
            "EREBUS_GATEWAY_PROVIDER": "openai",
            "EREBUS_GATEWAY_PORT": "0",
        })
    except ConfigError:
        bad = True
    check("from_env with an out-of-range port raises ConfigError", bad)

    cfg = _config()
    check("valid env parses to a GatewayConfig with detection disabled", cfg.detection_disabled is True)


def main():
    print("\n=== Config-driven server assembly + readiness (T017; R6/R7) ===\n")

    # Config format validation needs no database, so it always runs.
    _config_checks()

    try:
        os.system(f"createdb {_DSN.rsplit('/', 1)[-1]} 2>/dev/null")  # best-effort
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (DB-backed checks skipped: no Postgres: {exc})")
        print(f"\n{_passed}/{_passed} passed\n")
        return

    assembly = None
    try:
        conn.autocommit = True
        # Pre-create _migrations so the app's run_migrations is provably idempotent across
        # this connection and the app's own pool.
        from erebus.gateway.store import db
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")

        config = _config()
        app, assembly = build_app_from_config(config)
        client = TestClient(app)

        # Migrations are idempotent: a second pass over the same DSN applies nothing new.
        applied_again = db.run_migrations(conn)
        check("migrations are idempotent (second pass applies nothing)", applied_again == [])

        check("healthz is up once the app is built", client.get("/healthz").json()["status"] == "ok")

        r = client.get("/readyz")
        check("readyz is 200 when state + custody are up", r.status_code == 200)
        check("readyz reports detection posture 'disabled' (recorded, not an outage)",
              r.json().get("detection") == "disabled")

        # An unknown credential is rejected (the dynamic resolver returns no scope -> 401).
        unknown = client.post("/v1/chat/completions",
                              json={"messages": [{"role": "user", "content": "hi"}]},
                              headers={"Authorization": "Bearer egw_not-real"})
        check("an unknown credential is rejected 401 (dynamic resolver)", unknown.status_code == 401)

        # A freshly provisioned tenant resolves through the live scope-id directory with no
        # restart: provision a scope + credential, then the directory must see it.
        from erebus.gateway.crypto.keyprovider import MasterKeyKms
        from erebus.gateway.server import _ScopeIdDirectory
        from erebus.gateway.store import credentials_directory
        from erebus.gateway.store.known_value_store import provision_scope

        kms = MasterKeyKms(_DSN, _KEY)
        try:
            sid = provision_scope(conn, kms, "org/new-tenant")
            credentials_directory.provision(conn, sid, "org/new-tenant", label="ci")
            directory = _ScopeIdDirectory(assembly.pool)
            check("a freshly provisioned scope_key is in the live directory (no restart, FR-005)",
                  "org/new-tenant" in directory)
            check("the live directory resolves scope_key -> the provisioned scope_id",
                  directory["org/new-tenant"] == sid)
        finally:
            kms.close()

        # readyz fails closed when the custody probe reports unhealthy.
        import anyio

        from erebus.gateway.app import _readyz  # exercise the probe path directly

        class _Deps:
            pool = assembly.pool
            conn = None
            kms_health = staticmethod(lambda: False)
            detector_posture = None

        denied = False
        try:
            anyio.run(_readyz, _Deps())
        except Exception as exc:  # HTTPException(503)
            denied = getattr(exc, "status_code", None) == 503
        check("readyz returns 503 fail-closed when key custody is unhealthy (FR-008)", denied)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if assembly is not None:
            anyio_run_close(assembly)
        conn.close()


def anyio_run_close(assembly):
    """Drain the assembly (close pools + httpx) outside the event loop, tolerating errors."""
    import anyio
    try:
        anyio.run(assembly.aclose)
    except Exception:
        pass


if __name__ == "__main__":
    main()
