"""Fail-closed egress on a revoke/crypto-erase race (009 R1/R3; FR-001/FR-003).

Regression for the TOCTOU window between the egress pre-check and the upstream send.
``select_route``/``get_credential`` are typed ``... | None``; a concurrent
revoke/crypto-erase between the ``egress_allowed`` pre-check and the send makes them
return ``None``. Before the fix the non-streaming path then built ``Bearer None`` (a
malformed credential upstream) and the streaming path dereferenced ``route`` (a 500);
the fix turns both into the clean fail-closed refusal that already exists for the
no-route case.

For BOTH the non-streaming and the streaming egress paths this provisions a tenant +
central credential + approved route with a fake RECORDING upstream, then forces the race
by making the SEND-site resolution return ``None`` (revoke/erase between the pre-check
and the send), and asserts:

* a clean fail-closed refusal (``EgressDenied`` -> the handler's 502),
* the upstream received NOTHING (no call at all),
* the literal string ``Bearer None`` never appears in any captured upstream header.

It also asserts (009 R3/FR-003) that the non-streaming egress runs its
allow/route/credential checks OFF the event-loop thread, so the synchronous DB work no
longer blocks the loop. Live Postgres; self-skips without it.
"""
import base64
import os
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway.config import GatewayConfig
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.egress import build_egress, build_egress_stream
from erebus.gateway.providers import credentials
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.transport import EgressDenied

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_egress_failclosed")
_KEY = base64.b64encode(os.urandom(32)).decode()
# Built at runtime; never written as a literal credential string in source.
_BEARER_NONE = "Bearer " + str(None)
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
    })


def _no_bearer_none(captured) -> bool:
    """True iff no captured upstream header carries the literal 'Bearer None'."""
    for rec in captured:
        for value in rec.get("headers", {}).values():
            if _BEARER_NONE in str(value):
                return False
    return True


def main():
    print("\n=== Fail-closed egress on a revoke/crypto-erase race (R1/R3; FR-001/003) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    conn.autocommit = True  # so the KMS + egress pools see migrations + the provisioned scope
    kms = None
    pool = None
    try:
        import anyio
        from psycopg_pool import ConnectionPool

        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")

        kms = MasterKeyKms(_DSN, _KEY)
        scope_id = provision_scope(conn, kms, "tenA")
        crypto = open_store(conn, kms, scope_id)._crypto

        central_secret = "CENTRAL-EGRESS-SECRET-" + "654321"
        credentials.store_credential(conn, crypto, scope_id, "openai", central_secret)
        rid = credentials.add_route(conn, scope_id, "openai", "https://api.openai.com")
        credentials.approve_route(conn, scope_id, rid)

        captured = []  # one record per upstream send; MUST stay empty in every race below

        async def fake_post(url, headers, payload):
            captured.append({"url": url, "headers": dict(headers), "payload": payload})
            return {"choices": [{"message": {"content": "ok"}}]}

        async def fake_stream(url, headers, payload):
            captured.append({"url": url, "headers": dict(headers), "payload": payload})
            yield "data: hello\n\n"

        pool = ConnectionPool(_DSN, min_size=1, max_size=3, open=True)
        try:
            _run_non_streaming(anyio, pool, kms, fake_post, scope_id, captured)
            _run_streaming(anyio, pool, kms, fake_stream, scope_id, captured)
            _run_offloop(anyio, pool, kms, fake_post, scope_id)

        finally:
            pool.close()

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if pool is not None and not pool.closed:
            pool.close()
        if kms is not None:
            kms.close()
        conn.close()


def _race_route_revoke():
    """Patch so the route is live for the ``egress_allowed`` pre-check then vanishes.

    The first ``select_route`` (the ``egress_allowed`` pre-check) returns the real route;
    every subsequent ``select_route`` returns ``None`` — the route revoked/unapproved in
    the TOCTOU window after the pre-check passed. The guard under test must turn that
    ``None`` into a clean fail-closed refusal (FR-001). Structure-agnostic: it keys off
    call order, not a fixed count. Returns a ``restore`` callable.
    """
    real_route = credentials.select_route
    seen = {"n": 0}

    def patched_route(*args, **kwargs):
        seen["n"] += 1
        if seen["n"] > 1:
            return None  # route gone after the egress_allowed pre-check saw it live
        return real_route(*args, **kwargs)

    def restore():
        credentials.select_route = real_route

    credentials.select_route = patched_route
    return restore


def _race_credential_erase():
    """Patch so the credential reads valid until the route is resolved, then erased.

    Models the central credential being crypto-erased/deleted in the window between
    approving egress (route resolved) and reading the secret: ``get_credential`` returns
    the real value only while no ``select_route`` has run yet (any pre-send pre-check), and
    ``None`` once the route has been resolved (the load-bearing send-site read). This makes
    the race fire identically whether the resolution happens once or twice, so it FAILS on
    the pre-fix code (which built ``Bearer None`` and posted it) and the guard under test
    turns it into a clean refusal (FR-001). Returns a ``restore`` callable.
    """
    real_route = credentials.select_route
    real_secret = credentials.get_credential
    route_resolved = {"yes": False}

    def patched_route(*args, **kwargs):
        route_resolved["yes"] = True
        return real_route(*args, **kwargs)

    def patched_secret(*args, **kwargs):
        if route_resolved["yes"]:
            return None  # credential erased at the send-site read (route already resolved)
        return real_secret(*args, **kwargs)

    def restore():
        credentials.select_route = real_route
        credentials.get_credential = real_secret

    credentials.select_route = patched_route
    credentials.get_credential = patched_secret
    return restore


def _run_non_streaming(anyio, pool, kms, fake_post, scope_id, captured):
    """Non-streaming egress: a send-site None must fail closed, never 'Bearer None'."""
    captured.clear()
    egress = build_egress(pool, kms, _config(), fake_post)

    # Race the route revoke: the send-site select_route returns None (the egress_allowed
    # pre-check inside the send still saw it live). The first select_route call is the
    # pre-check; the second is the load-bearing one whose None must fail closed cleanly.
    restore = _race_route_revoke()
    denied = False
    try:
        anyio.run(egress, scope_id, {"model": "gpt-4o", "messages": []})
    except EgressDenied:
        denied = True
    finally:
        restore()
    check("non-streaming: route revoked in the race fails closed (FR-001)", denied)
    check("non-streaming: nothing egressed when the route vanished mid-flight", captured == [])
    check("non-streaming: no 'Bearer None' header ever sent (route race)", _no_bearer_none(captured))

    # Race the credential erase: the route stays live (egress_allowed + select_route both
    # pass), but the central credential is gone when read. Pre-fix this built 'Bearer None'
    # and posted it upstream; the fix must refuse before any header is built (FR-001).
    captured.clear()
    restore = _race_credential_erase()
    denied = False
    try:
        anyio.run(egress, scope_id, {"model": "gpt-4o", "messages": []})
    except EgressDenied:
        denied = True
    finally:
        restore()
    check("non-streaming: credential erased in the race fails closed (FR-001)", denied)
    check("non-streaming: nothing egressed when the credential vanished mid-flight", captured == [])
    check("non-streaming: no 'Bearer None' header ever sent (credential race)",
          _no_bearer_none(captured))


def _run_streaming(anyio, pool, kms, fake_stream, scope_id, captured):
    """Streaming egress: the same race must fail closed before any fragment is yielded."""
    captured.clear()
    egress_stream = build_egress_stream(pool, kms, _config(), fake_stream)

    async def drain():
        frags = []
        async for frag in egress_stream(scope_id, {"model": "gpt-4o", "messages": []}):
            frags.append(frag)
        return frags

    # Race the route revoke on the streaming path: the load-bearing select_route (after the
    # egress_allowed pre-check) returns None. Pre-fix this dereferenced route; the fix must
    # refuse cleanly before any header is built or fragment yielded.
    restore = _race_route_revoke()
    denied = False
    frags = None
    try:
        frags = anyio.run(drain)
    except EgressDenied:
        denied = True
    finally:
        restore()
    check("streaming: route revoked in the race fails closed (FR-001)", denied)
    check("streaming: nothing egressed when the route vanished mid-flight", captured == [])
    check("streaming: no fragment leaked before the refusal", not frags)
    check("streaming: no 'Bearer None' header ever sent (route race)", _no_bearer_none(captured))

    # Race the credential erase on the streaming path: the credential is gone at the read.
    captured.clear()
    restore = _race_credential_erase()
    denied = False
    frags = None
    try:
        frags = anyio.run(drain)
    except EgressDenied:
        denied = True
    finally:
        restore()
    check("streaming: credential erased in the race fails closed (FR-001)", denied)
    check("streaming: nothing egressed when the credential vanished mid-flight", captured == [])
    check("streaming: no fragment leaked before the refusal", not frags)
    check("streaming: no 'Bearer None' header ever sent (credential race)", _no_bearer_none(captured))


def _run_offloop(anyio, pool, kms, fake_post, scope_id):
    """The non-streaming allow/route/credential checks must run OFF the event-loop thread (R3)."""
    egress = build_egress(pool, kms, _config(), fake_post)
    real_route = credentials.select_route
    seen = {}
    loop_thread = {}

    def recording_route(*args, **kwargs):
        seen["route_thread"] = threading.current_thread()
        return real_route(*args, **kwargs)

    async def served():
        loop_thread["loop"] = threading.current_thread()
        return await egress(scope_id, {"model": "gpt-4o", "messages": []})

    credentials.select_route = recording_route
    try:
        anyio.run(served)
    finally:
        credentials.select_route = real_route
    check("non-streaming: route lookup ran off the event-loop thread (R3/FR-003)",
          seen.get("route_thread") is not None
          and seen["route_thread"] is not loop_thread["loop"])


if __name__ == "__main__":
    main()
