"""Known values on the live chat path (spec 015 "Request path", "Fail closed").

Live Postgres on its own database. A value that exists only in a tenant's catalog, and
that the detector does not find, reaches the provider as a token and comes back to the
client as the value; a known value inside a detected email does not split it. Readiness
is 503 until the builder's first pass, then 200 ``ready``, and 200 ``degraded`` when a
rebuild fails (the old matcher keeps serving). A tenant with no matcher gets 503 before
any quota is reserved: crypto-erased (evicted at once on this replica), inactive, or not
built yet. A tenant onboarded since the last pass with an empty catalog is served at once.
Edge mode refuses a known-value hit.
"""
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import psycopg
from fastapi.testclient import TestClient
from helpers import fresh_db
from psycopg_pool import ConnectionPool

from erebus.core.patterns import TOKEN_RE
from erebus.gateway import catalog
from erebus.gateway.app import create_app
from erebus.gateway.connectors import sources
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.detection import build_detector
from erebus.gateway.known_value_registry import MatcherBuilder, MatcherRegistry
from erebus.gateway.observability import Metric, Metrics
from erebus.gateway.providers import quota
from erebus.gateway.store import catalog_versions
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DB = "erebus_gw_known_values_chat"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _Config:
    detection_disabled = True  # regex only: it finds emails, never names


class Provider:
    def __init__(self):
        self.sent = []

    async def __call__(self, payload):
        text = payload["messages"][-1]["content"]
        self.sent.append(text)
        return {"choices": [{"message": {"role": "assistant", "content": "Re: " + text}}]}

    async def stream(self, payload):
        yield payload["messages"][-1]["content"]


def _sync(conn, kms, scope_id, values):
    """What a finished sync leaves behind: the values linked to a source, the version bumped."""
    crypto = open_scope_crypto(conn, kms, scope_id)
    src = sources.create_source(conn, crypto, scope_id, name=f"crm-{uuid.uuid4().hex[:6]}",
                                connector_type="postgres", settings={}, secrets={"password": "x"})
    catalog.upsert_values(conn, crypto, scope_id, src, uuid.uuid4(), values)
    catalog_versions.bump(conn, scope_id)
    conn.commit()


def _chat(client, cred, text, stream=False):
    body = {"messages": [{"role": "user", "content": text}]}
    if stream:
        body["stream"] = True
    return client.post("/v1/chat/completions", json=body, headers={"Authorization": f"Bearer {cred}"})


def _used(conn, scope_id):
    with conn.transaction():
        row = conn.execute("SELECT coalesce(sum(requests), 0) FROM usage_counters WHERE scope_id = %s",
                           (scope_id,)).fetchone()
    return row[0]


def _fail_closed_audits(conn, scope_id):
    with conn.transaction():
        conn.execute("SELECT set_config('erebus.scope_id', %s, true)", (str(scope_id),))
        row = conn.execute("SELECT count(*) FROM audit_events WHERE scope_id = %s AND outcome = 'fail_closed'",
                           (scope_id,)).fetchone()
    return row[0]


class World:
    def __init__(self, conn, kms):
        self.conn, self.kms = conn, kms
        self.a = provision_scope(conn, kms, "tenA")
        self.b = provision_scope(conn, kms, "tenB")
        self.e = provision_scope(conn, kms, "tenE")
        self.ops = provision_scope(conn, kms, "ops")
        for sid in (self.a, self.b, self.e):
            quota.set_quota(conn, sid, 1000, 100000, 60)
        conn.commit()
        _sync(conn, kms, self.a, [("Zyx Qorbel", "PERSON"), ("Qorbel", "ORGANIZATION")])
        _sync(conn, kms, self.e, [("Zyx Qorbel", "PERSON")])
        self.fail_load = False
        self.metrics = Metrics()
        self.registry = MatcherRegistry()
        self.provider = Provider()

    def load(self, conn, kp, sid):
        if self.fail_load:
            raise RuntimeError("decrypt failed")
        return catalog.load_matcher(conn, kp, sid)


def _check_before_first_pass(world, client):
    r = client.get("/readyz")
    check("readyz is 503 before the first build pass", r.status_code == 503 and "known values" in r.text)
    r = _chat(client, "cA", "Hi Zyx Qorbel")
    check("a tenant with values but no matcher yet gets 503",
          r.status_code == 503 and r.json()["detail"] == "known values unavailable")
    check("the 503 names no value", "Qorbel" not in r.text)
    check("no quota is spent on it", _used(world.conn, world.a) == 0)
    check("the refusal is audited fail_closed", _fail_closed_audits(world.conn, world.a) == 1)
    check("nothing reached the provider", world.provider.sent == [])
    r = _chat(client, "cB", "Hi there")
    check("a tenant with an empty catalog is served before any pass", r.status_code == 200)


def _check_served(world, client, builder):
    builder.run_pass()
    r = client.get("/readyz")
    check("readyz is 200 ready after the first pass",
          r.status_code == 200 and r.json().get("known_values") == "ready")
    world.provider.sent.clear()
    r = _chat(client, "cA", "Please call Zyx Qorbel today")
    sent = world.provider.sent[-1]
    check("a synced value the detector does not find is tokenized",
          r.status_code == 200 and "Zyx Qorbel" not in sent and sent.startswith("Please call [PERSON_"))
    check("the client gets the value back", r.json()["choices"][0]["message"]["content"]
          == "Re: Please call Zyx Qorbel today")
    check("known-value matches are counted",
          world.metrics.snapshot(str(world.a))[Metric.KNOWN_VALUE_MATCHES] == 1)
    r = _chat(client, "cA", "Write to info@qorbel.nl about Qorbel")
    sent = world.provider.sent[-1]
    check("an email holding a known value stays one token, the value alone is another",
          r.status_code == 200 and len(TOKEN_RE.findall(sent)) == 2 and "[EMAIL_ADDRESS_" in sent
          and "[ORGANIZATION_" in sent and "qorbel" not in TOKEN_RE.sub("", sent).casefold())
    r = _chat(client, "cA", "Zyx Qorbel", stream=True)
    check("the stream path tokenizes known values too", r.status_code == 200 and "Zyx Qorbel" in r.text)
    r = _chat(client, "cE", "Hi Zyx Qorbel")
    check("edge mode refuses a known-value hit", r.status_code == 400)
    check("edge mode passes a clean payload", _chat(client, "cE", "Hi there").status_code == 200)


def _check_rebuild_and_degraded(world, client, builder):
    _sync(world.conn, world.kms, world.a, [("Mira Vantol", "PERSON")])
    builder.run_pass()
    world.provider.sent.clear()
    _chat(client, "cA", "Mira Vantol called")
    check("a value synced later is tokenized after the next pass", "Mira Vantol" not in world.provider.sent[-1])
    world.fail_load = True
    _sync(world.conn, world.kms, world.a, [("Oren Talbek", "PERSON")])
    builder.run_pass()
    r = client.get("/readyz")
    check("a failed rebuild keeps readyz 200 with known_values degraded",
          r.status_code == 200 and r.json().get("known_values") == "degraded")
    _chat(client, "cA", "Mira Vantol called")
    check("the previous matcher keeps serving", "Mira Vantol" not in world.provider.sent[-1])
    check("rebuild failures are counted",
          world.metrics.snapshot(str(world.a))[Metric.KNOWN_VALUE_REBUILD_FAILURES] == 1)
    world.fail_load = False


def _check_eviction(world, client, builder):
    version = catalog_versions.read(world.conn, world.a)
    r = client.post("/v1/admin/keys", json={"op": "crypto_erase", "scope_key": "tenA"},
                    headers={"Authorization": "Bearer cOp"})
    check("crypto-erase succeeds", r.status_code == 200)
    check("crypto-erase evicts the tenant's matcher on this replica at once", world.registry.get(world.a) is None)
    check("crypto-erase bumps the catalog version for the other replicas",
          catalog_versions.read(world.conn, world.a) == version + 1)
    used = _used(world.conn, world.a)
    r = _chat(client, "cA", "Hi Zyx Qorbel")
    check("an evicted tenant gets 503 before quota", r.status_code == 503 and _used(world.conn, world.a) == used)
    check("the stream path refuses it too", _chat(client, "cA", "Hi", stream=True).status_code == 503)
    builder.run_pass()
    check("the next pass keeps it evicted and is not degraded",
          world.registry.get(world.a) is None and client.get("/readyz").json().get("known_values") == "ready")
    with world.conn.transaction():
        world.conn.execute("UPDATE scopes SET status = 'suspended' WHERE id = %s", (world.b,))
    builder.run_pass()
    check("a scope that is no longer active is evicted", _chat(client, "cB", "Hi").status_code == 503)
    late = provision_scope(world.conn, world.kms, "tenLate")
    quota.set_quota(world.conn, late, 1000, 100000, 60)
    world.conn.commit()
    return late


def main():
    print("\n=== Gateway known values on the live chat path ===\n")
    try:
        conn = fresh_db(_DB)
    except psycopg.OperationalError as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    dsn = conn.info.dsn
    kms = LocalKms()
    pool = ConnectionPool(dsn, min_size=1, max_size=4, open=True)
    world = World(conn, kms)
    builder = MatcherBuilder(world.registry, ConnectionPool(dsn, min_size=1, max_size=1, open=True), kms,
                             metrics=world.metrics, load=world.load)
    creds = {"cA": "tenA", "cB": "tenB", "cE": "tenE", "cOp": "ops", "cLate": "tenLate"}
    ids = {"tenA": world.a, "tenB": world.b, "tenE": world.e, "ops": world.ops}
    try:
        app = create_app(pool=pool, key_provider=kms, detector=build_detector(_Config()),
                         provider_call=world.provider, provider_stream=world.provider.stream,
                         scopes=ScopeResolver(creds, operators={"cOp"}), scope_ids=ids,
                         modes={"tenE": "edge"}, metrics=world.metrics, known_values=world.registry)
        client = TestClient(app)
        _check_before_first_pass(world, client)
        _check_served(world, client, builder)
        _check_rebuild_and_degraded(world, client, builder)
        late = _check_eviction(world, client, builder)
        ids["tenLate"] = late
        check("a tenant onboarded since the last pass with no values is served at once",
              _chat(client, "cLate", "Hi Zyx Qorbel").status_code == 200)
    finally:
        builder.close()
        pool.close()
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
