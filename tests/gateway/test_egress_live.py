"""Live scope-aware egress on the chat path (008 T016/T028; R1, FR-001/003/020/021).

Drives ``/v1/chat/completions`` THROUGH the app with a real scope-aware egress wired in (a
real ``MasterKeyKms`` + token store + central credential + approved route, and a fake
``http_post`` that records what the upstream actually received). Asserts the invariants the
e2e gate verifies in miniature:

* the upstream received ONLY tokens for a request carrying PII (no raw name leaves; SC-002),
* the client receives the RESTORED completion,
* the request to the provider carried the tenant CENTRAL credential, never the client's,
  whether the client smuggled it in the request BODY or in a request HEADER (FR-003),
* under interleaved two-tenant traffic each tenant's upstream request carries ITS OWN
  central credential (per-tenant distinctness; FR-003/020),
* an unapproved route or a model absent from the allowlist is refused FAIL-CLOSED with 502,
  nothing egresses, and the refusal is audited (FR-021).

Live Postgres; self-skips without it.
"""
import base64
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.config import GatewayConfig
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.egress import build_egress
from erebus.gateway.governance import audit
from erebus.gateway.providers import credentials, quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_us1_live")
_KEY = base64.b64encode(os.urandom(32)).decode()
_PERSON = re.compile(r"\[PERSON_\d+_[0-9a-f]+\]")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def fake_detector(text):
    """A deterministic detector that finds the seeded name (no real model needed)."""
    out = []
    needle = "John Smith"
    i = text.find(needle)
    if i != -1:
        out.append((i, i + len(needle), "PERSON"))
    return out


def main():
    print("\n=== Live scope-aware egress on the chat path (T016/T028; FR-001/003/020/021) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    conn.autocommit = True  # so the KMS + egress pools see migrations + the provisioned scope
    kms = None
    pool = None
    try:
        from psycopg_pool import ConnectionPool

        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")

        kms = MasterKeyKms(_DSN, _KEY)

        # --- Two tenants, each with its OWN distinct central credential + approved route. ---
        scope_a = provision_scope(conn, kms, "tenA")
        scope_b = provision_scope(conn, kms, "tenB")
        quota.set_quota(conn, scope_a, 1000, 1000, 60)
        quota.set_quota(conn, scope_b, 1000, 1000, 60)
        crypto_a = open_store(conn, kms, scope_a)._crypto
        crypto_b = open_store(conn, kms, scope_b)._crypto

        client_secret = "USER-KEY-SHOULD-NOT-LEAK-" + "123"
        central_a = "CENTRAL-EGRESS-SECRET-A-" + "456"
        central_b = "CENTRAL-EGRESS-SECRET-B-" + "789"
        credentials.store_credential(conn, crypto_a, scope_a, "openai", central_a)
        credentials.store_credential(conn, crypto_b, scope_b, "openai", central_b)
        rid_a = credentials.add_route(conn, scope_a, "openai", "https://api.openai.com",
                                      model_allowlist=["gpt-4o"])
        rid_b = credentials.add_route(conn, scope_b, "openai", "https://api.openai.com",
                                      model_allowlist=["gpt-4o"])
        credentials.approve_route(conn, scope_a, rid_a)
        credentials.approve_route(conn, scope_b, rid_b)

        calls = []  # one record per upstream call, in arrival order (for interleaving)

        async def fake_post(url, headers, payload):
            rec = {"url": url, "headers": dict(headers), "payload": payload}
            calls.append(rec)
            # Echo the (tokenized) last message back so the restore path has tokens to rehydrate.
            content = payload["messages"][-1]["content"]
            return {"choices": [{"message": {"role": "assistant", "content": "Re: " + content}}]}

        config = GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN,
            "EREBUS_GATEWAY_MASTER_KEY": _KEY,
            "EREBUS_GATEWAY_PROVIDER": "openai",
        })
        pool = ConnectionPool(_DSN, min_size=1, max_size=3, open=True)
        egress = build_egress(pool, kms, config, fake_post)

        app = create_app(
            conn=conn, key_provider=kms, detector=fake_detector,
            scopes=ScopeResolver({"cA": "tenA", "cB": "tenB"}),
            scope_ids={"tenA": scope_a, "tenB": scope_b},
            egress=egress, pool=pool,
        )
        client = TestClient(app)

        # --- A request carrying PII egresses token-only and is restored on the way back. ---
        # The client smuggles its own credential in BOTH the body and a header; neither must leave.
        calls.clear()
        resp = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o", "authorization": "Bearer " + client_secret,
                  "api_key": client_secret,
                  "messages": [{"role": "user", "content": "Contact John Smith now"}]},
            headers={"Authorization": "Bearer cA", "X-Api-Key": client_secret},
        )
        check("chat request succeeds 200", resp.status_code == 200)

        egressed = calls[-1]["payload"]["messages"][-1]["content"]
        check("the upstream received ONLY tokens, no raw PII (SC-002)",
              "John Smith" not in egressed and bool(_PERSON.search(egressed)))

        restored = resp.json()["choices"][0]["message"]["content"]
        check("the client receives the RESTORED value", "John Smith" in restored)
        check("the restored response carries no leftover token", not _PERSON.search(restored))

        # --- The tenant CENTRAL credential was injected, never the client's (FR-003). ---
        check("egress reached the approved route", calls[-1]["url"] == "https://api.openai.com")
        check("CENTRAL credential injected in Authorization (FR-020)",
              calls[-1]["headers"]["Authorization"] == "Bearer " + central_a)
        check("client-supplied credential (header OR body) is NEVER forwarded (FR-003)",
              "USER-KEY-SHOULD-NOT-LEAK" not in str(calls[-1]))
        check("the client api_key body field never egresses (FR-003)",
              "api_key" not in calls[-1]["payload"] and "authorization" not in calls[-1]["payload"])

        # --- Interleaved two-tenant traffic: each upstream call carries ITS OWN central key. ---
        calls.clear()
        order = ["cA", "cB", "cA", "cB", "cB", "cA"]
        expect = {"cA": "Bearer " + central_a, "cB": "Bearer " + central_b}
        for ck in order:
            r = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-4o", "authorization": "Bearer " + client_secret,
                      "messages": [{"role": "user", "content": "Contact John Smith now"}]},
                headers={"Authorization": "Bearer " + ck},
            )
            check(f"interleaved request for {ck} succeeds 200", r.status_code == 200)
        check("every interleaved request reached the upstream", len(calls) == len(order))
        got = [c["headers"]["Authorization"] for c in calls]
        check("each tenant's upstream request carried ITS OWN central credential (FR-003/020)",
              got == [expect[ck] for ck in order])
        check("tenant A's central credential never appeared on a tenant B request",
              all(("Bearer " + central_a) != c["headers"]["Authorization"]
                  for c, ck in zip(calls, order, strict=True) if ck == "cB"))
        check("no client credential leaked across the interleaved traffic (FR-003)",
              all("USER-KEY-SHOULD-NOT-LEAK" not in str(c) for c in calls))

        # --- An unapproved model is refused FAIL-CLOSED (502), nothing egresses, audited. ---
        calls.clear()
        bad = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-not-allowed",
                  "messages": [{"role": "user", "content": "Contact John Smith now"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("a model absent from the allowlist is refused fail-closed 502 (FR-021)",
              bad.status_code == 502)
        check("nothing egressed for the refused model (no raw to the provider)", calls == [])
        check("the 502 body carries no raw PII", "John Smith" not in bad.text)
        events_a = audit.query(conn, scope_a, event_type="chat")
        check("the refused model is audited as egress_refused (FR-021)",
              any(e["outcome"] == "egress_refused" for e in events_a))

        # --- A provider with no approved route at all is refused fail-closed too, and audited. ---
        calls.clear()
        config_unrouted = GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN,
            "EREBUS_GATEWAY_MASTER_KEY": _KEY,
            "EREBUS_GATEWAY_PROVIDER": "openai",
            "EREBUS_GATEWAY_MODEL_MAP": '{"claude-3": "anthropic"}',
        })
        egress_unrouted = build_egress(pool, kms, config_unrouted, fake_post)
        app2 = create_app(
            conn=conn, key_provider=kms, detector=fake_detector,
            scopes=ScopeResolver({"cA": "tenA"}), scope_ids={"tenA": scope_a},
            egress=egress_unrouted, pool=pool,
        )
        unrouted = TestClient(app2).post(
            "/v1/chat/completions",
            json={"model": "claude-3", "messages": [{"role": "user", "content": "John Smith"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("a provider with no approved route is refused fail-closed 502 (FR-021)",
              unrouted.status_code == 502)
        check("nothing egressed for the unrouted provider", calls == [])

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        if pool is not None:
            pool.close()
        if kms is not None:
            kms.close()
        conn.close()


if __name__ == "__main__":
    main()
