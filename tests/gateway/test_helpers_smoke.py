"""Smoke test for the shared gateway test harness (T003, tests/gateway/helpers.py).

Proves the harness actually works by driving a real ``create_app`` round-trip with
nothing but the harness primitives: ``fresh_db`` (createdb + all gateway migrations
+ truncate), ``provision`` (scope + wrapped DEK), ``fake_detector`` (deterministic
PII fixture), and ``StubProvider`` (capturing async upstream). A quota is set via
``erebus.gateway.providers.quota.set_quota`` because the chat route is fail-closed
on quota (an unconfigured scope is denied). The test asserts token-only egress
(FR-001) and that the restored response rehydrates the original value.

Creates its own database ``erebus_gw_helpers``; self-skips without Postgres.
Prints ``N/N passed``.
"""
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", ".."))  # repo root -> erebus.*
sys.path.insert(0, _HERE)                              # this dir   -> helpers

from fastapi.testclient import TestClient  # noqa: E402
from helpers import StubProvider, fake_detector, fresh_db, provision  # noqa: E402

from erebus.gateway.app import create_app  # noqa: E402
from erebus.gateway.crypto.keyprovider import LocalKms  # noqa: E402
from erebus.gateway.providers.quota import set_quota  # noqa: E402
from erebus.gateway.tenancy import ScopeResolver  # noqa: E402

_DBNAME = "erebus_gw_helpers"
_DSN = os.environ.get("EREBUS_PG_DSN", f"postgresql:///{_DBNAME}")
_PERSON = re.compile(r"\[PERSON_\d+_[0-9a-f]+\]")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def main():
    print("\n=== Gateway test harness smoke (T003) ===\n")
    try:
        conn = fresh_db(_DBNAME)
    except Exception as exc:  # no Postgres -> self-skip (suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    try:
        check("fresh_db applied gateway migrations (scopes table queryable)",
              conn.execute("SELECT count(*) FROM scopes").fetchone()[0] == 0)

        kms = LocalKms()
        scope_id = provision(conn, kms, "org1/helpers/a")
        check("provision returned a scope id", scope_id is not None)

        # Route is fail-closed on quota: configure one so the request can proceed.
        set_quota(conn, scope_id, rate_limit=10, spend_budget="100.00", window_seconds=3600)

        detector = fake_detector([("John Smith", "PERSON"), ("john@corp.com", "EMAIL")])
        provider = StubProvider()

        app = create_app(
            conn=conn,
            key_provider=kms,
            detector=detector,
            provider_call=provider,
            scopes=ScopeResolver({"cred-a": "org1/helpers/a"}),
            scope_ids={"org1/helpers/a": scope_id},
        )
        client = TestClient(app)

        resp = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": "Email John Smith at john@corp.com"}]},
            headers={"Authorization": "Bearer cred-a"},
        )
        check("create_app round-trip returns 200", resp.status_code == 200)

        # Egress was captured by the StubProvider and carried tokens, not raw PII.
        check("StubProvider captured exactly one egress payload", len(provider.egress) == 1)
        sent = provider.egress[0]["messages"][-1]["content"]
        check("egress is token-only: no raw 'John Smith' (FR-001)", "John Smith" not in sent)
        check("egress is token-only: no raw email (FR-001)", "john@corp.com" not in sent)
        check("egress carried a PERSON placeholder", bool(_PERSON.search(sent)))

        # The response was restored back to the world: placeholders rehydrated.
        restored = resp.json()["choices"][0]["message"]["content"]
        check("restore rehydrated the real value in the response",
              "John Smith" in restored and "john@corp.com" in restored)
        check("restore left no placeholders behind", not _PERSON.search(restored))

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
