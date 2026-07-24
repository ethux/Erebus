"""The chat route actually applies the modality gate (T023/FR-004) end to end.

The pure classifier is covered by test_modalities; this proves /v1/chat/completions
WIRES it: text parts inside a content array are tokenized, tool-call arguments are
tokenized (no raw value rides inside a JSON arguments blob), images are blocked
fail-closed by default, and an operator policy can opt a modality past the gate.
Live Postgres for the route; self-skips without it.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gateway_test")
_NAME = "Alice Adams"
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def detector(text):
    """Detect the one fixture name wherever it appears (incl. inside JSON args)."""
    i = text.find(_NAME)
    return [(i, i + len(_NAME), "PERSON")] if i != -1 else []


def main():
    print("\n=== Gateway modality gate wired into the route (FR-004) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres: {exc})")
        return
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        m = provision_scope(conn, kms, "tenM")
        quota.set_quota(conn, m, 1000, 100000, 60)
        ids = {"tenM": m}
        hdr = {"Authorization": "Bearer cM"}

        captured = []

        async def prov(payload):
            captured.append(json.loads(json.dumps(payload)))  # snapshot the egress payload
            return {"choices": [{"message": {"content": "ok"}}]}

        app = create_app(conn=conn, key_provider=kms, detector=detector, provider_call=prov,
                         scopes=ScopeResolver({"cM": "tenM"}), scope_ids=ids)
        client = TestClient(app)

        # 1) A text part inside a structured content array is tokenized, not sent raw.
        client.post("/v1/chat/completions", headers=hdr, json={"messages": [
            {"role": "user", "content": [{"type": "text", "text": f"Contact {_NAME} today"}]}]})
        part_text = captured[-1]["messages"][0]["content"][0]["text"]
        check("text part in a content array is tokenized (FR-004)",
              _NAME not in part_text and "[PERSON_" in part_text)

        # 2) PII hidden inside tool-call JSON arguments is tokenized (no bypass).
        client.post("/v1/chat/completions", headers=hdr, json={"messages": [
            {"role": "assistant", "content": None, "tool_calls": [
                {"id": "c1", "type": "function",
                 "function": {"name": "send_email", "arguments": json.dumps({"to": _NAME})}}]}]})
        args = captured[-1]["messages"][0]["tool_calls"][0]["function"]["arguments"]
        check("tool-call arguments are routed through the gate and tokenized (FR-004)",
              _NAME not in args and "[PERSON_" in args)

        # 3) An image part is blocked by default, fail-closed (415) - nothing egresses.
        before = len(captured)
        r_img = client.post("/v1/chat/completions", headers=hdr, json={"messages": [
            {"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]}]})
        check("an image modality is blocked by default (FR-004)", r_img.status_code == 415)
        check("a blocked request never reaches the provider", len(captured) == before)

        # 4) An operator policy can opt a modality past the gate (ack-required).
        app_ok = create_app(conn=conn, key_provider=kms, detector=detector, provider_call=prov,
                            scopes=ScopeResolver({"cM": "tenM"}), scope_ids=ids,
                            modality_policy={"image_url": "ack-required"})
        r_ok = TestClient(app_ok).post("/v1/chat/completions", headers=hdr, json={"messages": [
            {"role": "user", "content": [
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}}]}]})
        check("operator policy can permit a modality past the gate (FR-004)", r_ok.status_code == 200)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
