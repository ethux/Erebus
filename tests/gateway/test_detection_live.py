"""Route-level detection fail-closed on the live path (008 US5; T046/T045, FR-007).

Drives a real ``/v1/chat/completions`` request THROUGH the app with the PRODUCTION
detection adapter (``build_detector`` over ``erebus.core.detect``), not a fake
detector, so the actual fail-closed wiring in ``app._sanitize_or_fail`` is exercised:

* available  -> PII is tokenized and the (capturing) upstream receives only tokens,
  no raw PII (the baseline guarantee still holds with the real adapter).
* degraded   -> the GLiNER daemon is forced to mark the per-call signal degraded
  (exactly as a real outage would). The chat request MUST fail closed with 503 and
  the upstream MUST have received NOTHING -- no raw PII, no partial-token egress,
  even when the regex layer found PII in the same request.
* regex-only -> ``EREBUS_DISABLE_GLINER``: email, phone and IBAN reach the upstream only
  as tokens, come back restored, and GLiNER is never called.

We do not run a real daemon: ``erebus.core.detect._predict_entities`` is monkeypatched
(the same seam ``test_detection_adapter`` uses) and the degraded signal is driven via
``erebus.core.state``, the way a daemon outage surfaces it. Live Postgres; self-skips
without it. Owns its own database (does not reuse another test's DSN).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg
from fastapi.testclient import TestClient

from erebus.core import detect as core_detect
from erebus.core import state as core_state
from erebus.gateway.app import create_app
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.detection import build_detector
from erebus.gateway.providers import quota
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import provision_scope
from erebus.gateway.tenancy import ScopeResolver

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_us5_detection")
_passed = 0
_SECRET = "John Smith"


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _Cfg:
    """Production-detection config stand-in: ``detection_disabled`` False, so
    ``build_detector`` returns regex + the fail-closed GLiNER adapter (not regex-only)."""

    detection_disabled = False


_EMAIL = "jan@voorbeeld-bv.test"
_PHONE = "+31 6 12345678"
_IBAN = "NL91ABNA0417164300"


class _CfgRegexOnly:
    """``EREBUS_DISABLE_GLINER`` stand-in: ``build_detector`` returns the regex-only detector."""

    detection_disabled = True


def _must_not_run(text):
    raise AssertionError("GLiNER must not run in the regex-only posture")


def _healthy_with_pii(text):
    """A daemon that finds the secret as a PERSON span and leaves the signal clear."""
    core_state._reset_detector_state()
    i = text.find(_SECRET)
    if i == -1:
        return []
    return [{"start": i, "end": i + len(_SECRET), "label": "person", "text": _SECRET}]


def _degraded(text):
    """A daemon that marks the per-call signal degraded (a real outage), returns no spans."""
    core_state._reset_detector_state()
    core_state._mark_detector_degraded("daemon_unavailable")
    return []


def main():
    print("\n=== Route-level detection fail-closed on the live path (T046/T045) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return

    original = core_detect._predict_entities
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")
        kms = LocalKms()
        a = provision_scope(conn, kms, "tenA")
        quota.set_quota(conn, a, 1000, 100000, 60)  # generous; the route is fail-closed on quota

        # The PRODUCTION adapter, not a fake -- this is what makes the test exercise the
        # real DetectionUnavailable -> 503 wiring in app._sanitize_or_fail.
        detector = build_detector(_Cfg())

        captured = []

        async def provider_call(payload):
            captured.append(payload)  # records EVERYTHING that reached the upstream
            user = payload["messages"][-1]["content"]
            return {"choices": [{"message": {"role": "assistant", "content": "Re: " + user}}]}

        app = create_app(
            conn=conn, key_provider=kms, detector=detector, provider_call=provider_call,
            scopes=ScopeResolver({"cA": "tenA"}), scope_ids={"tenA": a},
        )
        client = TestClient(app)

        # --- baseline: detection available -> PII tokenized, upstream gets only tokens. ---
        core_detect._predict_entities = _healthy_with_pii
        ok = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": f"Email {_SECRET} today"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("available: chat 200 with the production adapter", ok.status_code == 200)
        check("available: exactly one upstream call captured", len(captured) == 1)
        egress = captured[-1]["messages"][-1]["content"]
        check("available: no raw PII reached the upstream (tokenized)", _SECRET not in egress)
        check("available: egress carries a PERSON token", "[PERSON_" in egress)
        check("available: response restored the real value for the client", _SECRET in ok.text)

        captured.clear()

        # --- detection degraded mid-request -> fail closed 503, NOTHING egressed. ---
        core_detect._predict_entities = _degraded
        down = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": f"Email {_SECRET} today"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("degraded: chat fails closed with 503 (FR-007)", down.status_code == 503)
        check("degraded: the upstream received NOTHING (no raw PII egress, T046)",
              len(captured) == 0)
        check("degraded: no raw PII leaked to the client response", _SECRET not in down.text)

        # --- a streaming request during the outage also fails closed before any egress. ---
        captured.clear()
        stream_calls = []

        async def provider_stream(payload):  # must never be reached on a degraded request
            stream_calls.append(payload)
            yield "unreached"

        app_stream = create_app(
            conn=conn, key_provider=kms, detector=detector, provider_call=provider_call,
            provider_stream=provider_stream,
            scopes=ScopeResolver({"cA": "tenA"}), scope_ids={"tenA": a},
        )
        sc = TestClient(app_stream)
        core_detect._predict_entities = _degraded
        sresp = sc.post(
            "/v1/chat/completions",
            json={"stream": True, "messages": [{"role": "user", "content": f"Email {_SECRET} now"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("degraded stream: fails closed 503 before opening the stream", sresp.status_code == 503)
        check("degraded stream: the upstream stream was never invoked (no egress)",
              len(stream_calls) == 0)
        check("degraded stream: no raw PII in the response body", _SECRET not in sresp.text)

        # --- recovery: detection healthy again -> serves once more, no restart (SC-005). ---
        core_detect._predict_entities = _healthy_with_pii
        again = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": f"Email {_SECRET} today"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("recovery: chat serves again after detection recovers (no restart)",
              again.status_code == 200 and _SECRET in again.text)

        # --- GLiNER down + a regex hit in the same request: still 503, nothing egressed. ---
        captured.clear()
        core_detect._predict_entities = _degraded
        mixed = client.post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": f"Email {_SECRET} at {_EMAIL}"}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("degraded + regex hit: still fails closed with 503", mixed.status_code == 503)
        check("degraded + regex hit: the upstream received NOTHING", len(captured) == 0)
        check("degraded + regex hit: no raw PII in the response",
              _SECRET not in mixed.text and _EMAIL not in mixed.text)

        # --- regex-only (EREBUS_DISABLE_GLINER): structured PII tokenized, GLiNER never runs. ---
        core_detect._predict_entities = _must_not_run
        app_regex = create_app(
            conn=conn, key_provider=kms, detector=build_detector(_CfgRegexOnly()),
            provider_call=provider_call,
            scopes=ScopeResolver({"cA": "tenA"}), scope_ids={"tenA": a},
        )
        prompt = f"Mail {_EMAIL}, bel {_PHONE}, IBAN {_IBAN}"
        ro = TestClient(app_regex).post(
            "/v1/chat/completions",
            json={"messages": [{"role": "user", "content": prompt}]},
            headers={"Authorization": "Bearer cA"},
        )
        check("regex-only: chat 200 without GLiNER", ro.status_code == 200)
        egress = captured[-1]["messages"][-1]["content"]
        check("regex-only: no raw email, phone or IBAN reached the upstream",
              all(raw not in egress for raw in (_EMAIL, _PHONE, _IBAN)))
        check("regex-only: the upstream saw EMAIL_ADDRESS, PHONE_NUMBER and IBAN tokens",
              all(tok in egress for tok in ("[EMAIL_ADDRESS_", "[PHONE_NUMBER_", "[IBAN_")))
        check("regex-only: the response is restored for the client",
              ro.json()["choices"][0]["message"]["content"] == "Re: " + prompt)

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        core_detect._predict_entities = original
        conn.close()


if __name__ == "__main__":
    main()
