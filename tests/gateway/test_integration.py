"""End-to-end integration of the wired gateway services on the request path.

Exercises the stories that only exist once the services are wired into the routes:
US10 quota fail-closed, US8 audit recorded + chain intact, US4 hybrid edge-mode
verify, US6 governed reveal (RBAC + grant), US5 fail-closed on crypto-erase.
Live Postgres; self-skips without it.
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway import rbac
from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.governance import audit, reveal
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_PERSON = re.compile(r"\[PERSON_\d+_[0-9a-f]+\]")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def detector(text):
    out = []
    for needle, label in (("John Smith", "PERSON"), ("john@corp.com", "EMAIL")):
        i = text.find(needle)
        if i != -1:
            out.append((i, i + len(needle), label))
    return out


def main():
    print("\n=== Gateway wired-services integration (US4/US5/US6/US8/US10) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        a = provision_scope(conn, kms, "tenA")    # gateway mode
        e = provision_scope(conn, kms, "tenE")    # edge mode
        q = provision_scope(conn, kms, "tenQ")    # tight quota
        f = provision_scope(conn, kms, "tenF")    # crypto-erased
        for sid in (a, e, f):
            quota.set_quota(conn, sid, 100, 1000, 60)
        quota.set_quota(conn, q, 2, 1000, 60)     # rate limit = 2

        captured = []

        async def provider_call(payload):
            captured.append(payload)
            return {"choices": [{"message": {"role": "assistant",
                    "content": "Re: " + payload["messages"][-1]["content"]}}]}

        app = create_app(
            conn=conn, key_provider=kms, detector=detector, provider_call=provider_call,
            scopes=ScopeResolver({"cA": "tenA", "cE": "tenE", "cQ": "tenQ", "cF": "tenF"}),
            scope_ids={"tenA": a, "tenE": e, "tenQ": q, "tenF": f},
            modes={"tenE": "edge"},
        )
        client = TestClient(app)

        def post(cred, content):
            return client.post("/v1/chat/completions",
                               json={"messages": [{"role": "user", "content": content}]},
                               headers={"Authorization": f"Bearer {cred}"})

        # --- US10: quota fail-closed ---
        check("quota: 1st request OK", post("cQ", "hi").status_code == 200)
        check("quota: 2nd request OK", post("cQ", "hi").status_code == 200)
        r3 = post("cQ", "hi")
        check("quota: 3rd request rejected fail-closed 429 (US10)", r3.status_code == 429)
        check("quota: rejection is retryable", "retry-after" in {k.lower() for k in r3.headers})

        # --- US8: audit recorded + chain intact ---
        post("cA", "Email John Smith at john@corp.com")
        rows = audit.query(conn, a)
        check("audit: events recorded for the request (US8)", len(rows) >= 1)
        check("audit: chain verifies intact (US8)", audit.verify_chain(conn, a) is True)
        check("audit: no raw value in audit rows (FR-030)",
              all("John Smith" not in str(r.get("masked_value")) for r in rows))

        # --- US4: hybrid edge mode ---
        check("edge: already-clean payload passes (US4)", post("cE", "no pii here").status_code == 200)
        check("edge: raw PII in an edge payload is blocked 400 (FR-011)",
              post("cE", "John Smith").status_code == 400)

        # --- US6: governed reveal ---
        post("cA", "John Smith")  # mint a token for John Smith in scope A
        token = _PERSON.findall(captured[-1]["messages"][-1]["content"])[0]
        reveal.grant(conn, a, "alice", reveal.REVEAL_ROLE, "support case 42", [token], ttl_seconds=300)

        def reveal_post(cred, grantee, role, tokens):
            return client.post("/v1/reveal",
                               json={"grantee": grantee, "role": role, "tokens": tokens},
                               headers={"Authorization": f"Bearer {cred}"})

        ok = reveal_post("cA", "alice", str(rbac.Role.REVEAL_REVIEWER), [token])
        check("reveal: authorized + granted returns the real value (US6)",
              ok.status_code == 200 and ok.json()["values"][token] == "John Smith")
        denied_role = reveal_post("cA", "alice", str(rbac.Role.GATEWAY_OPERATOR), [token])
        check("reveal: wrong RBAC role denied 403 (FR-016)", denied_role.status_code == 403)
        denied_grant = reveal_post("cA", "bob", str(rbac.Role.REVEAL_REVIEWER), [token])
        check("reveal: no grant for this grantee denied 403 (FR-015)", denied_grant.status_code == 403)

        # --- US5: fail-closed on crypto-erase ---
        before = len(captured)
        kms.destroy_kek(str(f))
        rf = post("cF", "John Smith")
        check("fail-closed: crypto-erased scope returns 503 (US5/FR-024)", rf.status_code == 503)
        check("fail-closed: no egress occurred (no raw to the provider)", len(captured) == before)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
