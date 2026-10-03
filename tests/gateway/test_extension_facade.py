"""The gateway facade extensions use (spec 015 D6: ``app.state.erebus``).

Live Postgres. An extension route built only on the facade authenticates, admits only an
operator (a tenant gets 403 and the denial is audited), runs DB work on a pooled
connection, audits with ids-only metadata, resolves a tenant scope (a reserved or unknown
scope is ``None``), looks up a tenant's source with its family (another scope's source is
``None``) and seals source credentials that only the worker's key path opens.
"""
import base64
import os
import sys
import uuid

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

from fastapi import Header
from fastapi.testclient import TestClient
from helpers import fake_detector, fresh_db, operator_bearer

from erebus.gateway.app import create_app
from erebus.gateway.connectors import sources
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.governance import audit
from erebus.gateway.store import credentials_directory
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope
from erebus.gateway.tenancy import DbScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_extension_facade")
_KEY = base64.b64encode(os.urandom(32)).decode()
_SECRET = "Zq-facade-secret-81"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _extension(app):
    """A stand-in Pro route that uses nothing but the facade."""
    erebus = app.state.erebus

    @app.get("/ext/{scope_id}/{source_id}")
    async def route(scope_id: str, source_id: str, authorization: str | None = Header(default=None)) -> dict:
        ident = await erebus.require_operator(authorization, event="ext_probe")
        target = await erebus.target_scope(scope_id)
        ref = await erebus.source(target, source_id) if target is not None else None
        one = await erebus.db(lambda c: c.execute("SELECT 1").fetchone()[0])
        if target is not None:
            await erebus.audit(target, "ext_probe", "ok", ident, {"source_id": source_id})
        return {"target": str(target) if target else None, "one": one,
                "source": None if ref is None else {"id": str(ref.id), "type": ref.connector_type,
                                                    "family": ref.family, "status": ref.status}}

    @app.get("/ext-whoami")
    async def whoami(authorization: str | None = Header(default=None)) -> dict:
        ident = await erebus.authenticate(authorization)
        return {"scope_id": str(ident.scope_id), "privilege": ident.privilege}


def main():
    print("\n=== Gateway facade for extensions (spec 015 D6) ===\n")
    conn = fresh_db("erebus_gw_extension_facade")
    conn.autocommit = True
    kms = MasterKeyKms(_DSN, _KEY)
    resolver = DbScopeResolver(_DSN)
    try:
        a = provision_scope(conn, kms, "org/a")
        b = provision_scope(conn, kms, "org/b")
        tenant = credentials_directory.provision(conn, a, "org/a", label="a")
        op = operator_bearer(conn)
        home = conn.execute("SELECT id FROM scopes WHERE scope_key = %s",
                            (credentials_directory.OPERATOR_SCOPE_KEY,)).fetchone()[0]
        crypto_a = open_scope_crypto(conn, kms, a)
        src_a = sources.create_source(conn, crypto_a, a, name="crm", connector_type="mysql",
                                      settings={"host": "db.example", "dbname": "crm", "user": "r"},
                                      secrets={"password": _SECRET})
        src_b = sources.create_source(conn, open_scope_crypto(conn, kms, b), b, name="crm",
                                      connector_type="postgres", settings={"host": "db.example"},
                                      secrets={"password": _SECRET})

        app = create_app(conn=conn, key_provider=kms, detector=fake_detector([]), scopes=resolver, scope_ids={})
        erebus = app.state.erebus
        for name in ("authenticate", "require_operator", "db", "audit", "encrypt_source_secrets",
                     "target_scope", "source", "scoped"):
            check(f"the facade exposes {name}", callable(getattr(erebus, name, None)))
        _extension(app)
        client = TestClient(app)

        def get(path, cred=None):
            return client.get(path, headers={"Authorization": f"Bearer {cred}"} if cred else {})

        who = get("/ext-whoami", tenant)
        check("authenticate resolves a tenant credential",
              who.status_code == 200 and who.json() == {"scope_id": str(a), "privilege": "tenant"})
        check("authenticate refuses a missing credential with 401", get("/ext-whoami").status_code == 401)

        denied = get(f"/ext/{a}/{src_a}", tenant)
        check("require_operator refuses a tenant with 403 and no data",
              denied.status_code == 403 and str(src_a) not in denied.text)
        check("the refusal is audited on the tenant's chain",
              any(e["event_type"] == "ext_probe" and e["outcome"] == "forbidden" for e in audit.query(conn, a)))

        ok = get(f"/ext/{a}/{src_a}", op)
        body = ok.json()
        check("an operator passes and db() runs on a connection", ok.status_code == 200 and body["one"] == 1)
        check("source() returns the tenant's source with its family and no secret",
              body["source"] == {"id": str(src_a), "type": "mysql", "family": "database", "status": "active"}
              and _SECRET not in ok.text)
        events = [e for e in audit.query(conn, a) if e["event_type"] == "ext_probe" and e["outcome"] == "ok"]
        check("audit() appends an ids-only event on the target tenant's chain",
              len(events) == 1 and events[0]["metadata"] == {"source_id": str(src_a)})
        check("the audit chain still verifies", audit.verify_chain(conn, a))

        other = get(f"/ext/{a}/{src_b}", op).json()
        check("another scope's source is None", other["source"] is None and other["target"] == str(a))
        check("the operator home scope is not a target", get(f"/ext/{home}/{src_a}", op).json()["target"] is None)
        check("an unknown scope is not a target", get(f"/ext/{uuid.uuid4()}/{src_a}", op).json()["target"] is None)
        check("a malformed scope id is not a target", get(f"/ext/not-a-uuid/{src_a}", op).json()["target"] is None)
        check("a malformed source id is None", get(f"/ext/{a}/nope", op).json()["source"] is None)

        sealed = erebus.encrypt_source_secrets(conn, a, src_a, {"refresh_token": "Zq-rt-1"})
        plain = sources.open_secrets(crypto_a, src_a, sealed.nonce, sealed.ciphertext)
        check("encrypt_source_secrets seals under the tenant key, bound to the source id",
              b"Zq-rt-1" in plain and sealed.key_version == crypto_a.key_version
              and b"Zq-rt-1" not in sealed.ciphertext)
        try:
            sources.open_secrets(crypto_a, src_b, sealed.nonce, sealed.ciphertext)
            moved = True
        except Exception:
            moved = False
        check("the sealed blob does not open for another source", not moved)
        with erebus.scoped(conn, a):
            n = conn.execute("SELECT count(*) FROM sources").fetchone()[0]
        check("scoped() opens a tenant-bound transaction", n >= 1)
    finally:
        resolver.close()
        kms.close()
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
