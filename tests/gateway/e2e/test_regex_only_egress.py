"""Regex-only egress over real HTTP (EREBUS_DISABLE_GLINER=1).

Assembles the gateway via ``build_app_from_config`` with GLiNER disabled, serves it with
uvicorn, and points a tenant at the recording mock provider from ``test_end_to_end``. An
email, an international phone number and an IBAN in the prompt must reach the provider only
as tokens and come back restored; GLiNER is never called. Self-skips only without Postgres.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

import httpx
import psycopg
import test_end_to_end as e2e

from erebus.core import detect as core_detect
from erebus.gateway.config import GatewayConfig
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.store import db

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_e2e_regex")
_RAW = {
    "EMAIL_ADDRESS": "jan.jansen@voorbeeld-bv.test",
    "PHONE_NUMBER": "+31 6 12345678",
    "IBAN": "NL91ABNA0417164300",
}
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def main():
    print("\n=== Regex-only egress over real HTTP (EREBUS_DISABLE_GLINER=1) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = True
    provider = gateway = kms = None
    ner_calls: list[str] = []
    original_predict = core_detect._predict_entities
    core_detect._predict_entities = lambda text: ner_calls.append(text) or []
    try:
        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")
        provider = e2e._MockProvider()
        provider.start()
        kms = MasterKeyKms(_DSN, e2e._KEY)
        _sid, credential = e2e._provision_tenant(
            conn, kms, "e2e/regex", "openai", provider.base_url, ["gpt-4o"])
        gateway = e2e._GatewayServer(GatewayConfig.from_env({
            "EREBUS_PG_DSN": _DSN,
            "EREBUS_GATEWAY_MASTER_KEY": e2e._KEY,
            "EREBUS_GATEWAY_PROVIDER": "openai",
            "EREBUS_DISABLE_GLINER": "1",
        }))
        gateway.start()
        base = gateway.base_url
        prompt = (f"Mail {_RAW['EMAIL_ADDRESS']}, bel {_RAW['PHONE_NUMBER']}, "
                  f"IBAN {_RAW['IBAN']}.")
        with httpx.Client(timeout=30.0) as client:
            ready = client.get(f"{base}/readyz")
            check("readyz is 200 and reports detection 'regex-only'",
                  ready.status_code == 200 and ready.json().get("detection") == "regex-only")
            resp = client.post(
                f"{base}/v1/chat/completions",
                headers={"Authorization": f"Bearer {credential}"},
                json={"model": "gpt-4o", "messages": [{"role": "user", "content": prompt}]},
            )
        check("chat is 200 with GLiNER disabled", resp.status_code == 200)
        check("exactly one upstream call", len(provider.requests) == 1)
        recorded = json.dumps(provider.requests[-1])
        for label, raw in _RAW.items():
            check(f"{label}: the raw value never reached the provider", raw not in recorded)
            check(f"{label}: the provider saw a [{label}_..] token", f"[{label}_" in recorded)
        check("the client gets the original prompt back, fully restored",
              resp.json()["choices"][0]["message"]["content"] == prompt)
        check("GLiNER was never called in the regex-only posture", ner_calls == [])
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        core_detect._predict_entities = original_predict
        if gateway is not None:
            gateway.stop()
        if provider is not None:
            provider.stop()
        if kms is not None:
            kms.close()
        conn.close()


if __name__ == "__main__":
    main()
