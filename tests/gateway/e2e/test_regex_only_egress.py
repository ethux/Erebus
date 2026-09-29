"""Regex-only egress over real HTTP (EREBUS_DISABLE_GLINER=1).

Assembles the gateway via ``build_app_from_config`` with GLiNER disabled, serves it with
uvicorn, and points a tenant at the recording mock provider from ``test_end_to_end``. An
email, an international phone number, an IBAN and a PKCS#8 private key in the prompt must
reach the provider only as tokens and come back restored. A token the client already sent
must reach the provider verbatim, never wrapped in a new token, even when a regex hit
touches it. GLiNER is never called. Self-skips only without Postgres.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

import httpx
import psycopg
import test_end_to_end as e2e
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

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
# A token the client sent. PERSON is NER-only, so the regex-only gateway can never mint
# it, and restore leaves an unknown token as-is.
_FOREIGN = "[PERSON_1_abcdef]"
_TOKEN = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6,}\]")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _pkcs8_pem() -> str:
    """A real PKCS#8 block ("BEGIN PRIVATE KEY"), generated so none is committed."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def _chat(client, base, credential, content):
    return client.post(
        f"{base}/v1/chat/completions",
        headers={"Authorization": f"Bearer {credential}"},
        json={"model": "gpt-4o", "messages": [{"role": "user", "content": content}]},
    )


def _check_structured_pii(client, base, credential, provider):
    pem = _pkcs8_pem()
    prompt = (f"Mail {_RAW['EMAIL_ADDRESS']}, bel {_RAW['PHONE_NUMBER']}, "
              f"IBAN {_RAW['IBAN']}. Key:\n{pem}")
    resp = _chat(client, base, credential, prompt)
    check("chat is 200 with GLiNER disabled", resp.status_code == 200)
    check("exactly one upstream call", len(provider.requests) == 1)
    recorded = json.dumps(provider.requests[-1])
    sent = provider.requests[-1]["body"]["messages"][-1]["content"]
    for label, raw in _RAW.items():
        check(f"{label}: the raw value never reached the provider",
              raw not in recorded and raw not in sent)
        check(f"{label}: the provider saw a [{label}_..] token", f"[{label}_" in sent)
    check("PRIVATE_KEY: no line of the PEM block reached the provider",
          not any(line in sent for line in pem.splitlines() if line))
    check("PRIVATE_KEY: the whole block became exactly one token",
          sent.count("[PRIVATE_KEY_") == 1 and sent.endswith("]\n"))
    check("the provider saw exactly four tokens", len(_TOKEN.findall(sent)) == 4)
    check("the client gets the original prompt back, key included",
          resp.json()["choices"][0]["message"]["content"] == prompt)


def _check_existing_token(client, base, credential, provider):
    email = "piet@voorbeeld-bv.test"
    prompt = f"Ask {_FOREIGN}{email} or password: {_FOREIGN} today."
    resp = _chat(client, base, credential, prompt)
    check("chat with an existing token is 200", resp.status_code == 200)
    sent = provider.requests[-1]["body"]["messages"][-1]["content"]
    check("the existing token reached the provider verbatim, both times",
          sent.count(_FOREIGN) == 2)
    check("the email glued to the token is tokenized on its own",
          email not in sent and f"{_FOREIGN}[EMAIL_ADDRESS_" in sent)
    check("no token was minted around the existing token (no PASSWORD token)",
          "[PASSWORD_" not in sent and f"password: {_FOREIGN} today." in sent)
    check("the provider saw one new token plus the two existing ones",
          len(_TOKEN.findall(sent)) == 3)
    check("the prompt round-trips exactly",
          resp.json()["choices"][0]["message"]["content"] == prompt)


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
        with httpx.Client(timeout=30.0) as client:
            ready = client.get(f"{base}/readyz")
            check("readyz is 200 and reports detection 'regex-only'",
                  ready.status_code == 200 and ready.json().get("detection") == "regex-only")
            _check_structured_pii(client, base, credential, provider)
            _check_existing_token(client, base, credential, provider)
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
