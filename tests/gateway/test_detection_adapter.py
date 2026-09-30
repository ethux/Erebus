"""Production detection adapter unit tests (008 T021/T015; research R4, FR-007).

No database, no real GLiNER daemon: we monkeypatch
``erebus.core.detect._predict_entities`` (the daemon client that
``predict_entities`` resolves at call time) and drive the degraded signal through
``erebus.core.state`` directly, exactly the way a real daemon outage would surface
it. Verifies the four postures the spec requires:

  * available   -> regex + GLiNER spans returned and tokenizable (labels normalized)
  * unavailable -> the adapter raises (fail closed; no raw egress), regex hits or not
  * degraded    -> the adapter raises (fail closed)
  * regex-only  -> EREBUS_DISABLE_GLINER posture: core regex spans, never raises

and the readiness surface ``health()`` derived from that posture (008 R7/FR-008):

  * available -> health True   · degraded -> health False (drain the replica)
  * regex-only -> health True (deliberate, surfaced operator choice, never an outage)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.core import detect as core_detect
from erebus.core import state as core_state
from erebus.gateway.detection import (
    AVAILABLE,
    DEGRADED,
    REGEX_ONLY,
    DetectionUnavailable,
    build_detector,
)

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _Config:
    def __init__(self, detection_disabled=False):
        self.detection_disabled = detection_disabled


def _set_predict(fn):
    """Swap the daemon client that ``predict_entities`` resolves at call time."""
    core_detect._predict_entities = fn  # test seam, mirrors core's own patch surface


def _healthy(entities):
    """A daemon that returns ``entities`` and leaves the degraded signal clear."""
    def predict(text):
        core_state._reset_detector_state()
        return list(entities)
    return predict


def _degraded(reason):
    """A daemon that marks the per-call signal degraded and returns no spans,
    exactly as ``erebus.core.detect`` does when the daemon is unreachable."""
    def predict(text):
        core_state._reset_detector_state()
        core_state._mark_detector_degraded(reason)
        return []
    return predict


def _must_not_run(calls):
    def predict(text):
        calls.append(text)
        raise AssertionError("GLiNER must not run in the regex-only posture")
    return predict


def _ner(start, end, label, text):
    return _healthy([{"start": start, "end": end, "label": label, "text": text[start:end]}])


def _check_regex_only():
    """Regex-only finds structured PII and secrets without ever calling GLiNER."""
    calls = []
    _set_predict(_must_not_run(calls))
    det = build_detector(_Config(detection_disabled=True))
    text = ("Mail jan@corp.example, bel +31 6 12345678, IBAN NL91 ABNA 0417 1643 00, "
            "key sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456")
    check("regex-only -> email, international phone, grouped IBAN and API key",
          {text[s:e]: label for s, e, label in det(text)} == {
              "jan@corp.example": "EMAIL_ADDRESS", "+31 6 12345678": "PHONE_NUMBER",
              "NL91 ABNA 0417 1643 00": "IBAN",
              "sk-ant-api03-abcdefghijklmnopqrstuvwxyz123456": "API_KEY"})
    check("regex-only -> names are NER-only (the documented limit)", det("Ask Jan de Vries") == [])
    check("regex-only -> a bad IBAN checksum is not tokenized", det("NL00ABNA0417164300") == [])
    for text, iban in (("BETAAL AAN BE68 5390 0754 7034 VOOR DE HUUR", "BE68 5390 0754 7034"),
                       ("Pay ES91 2100 0418 4502 0005 1332 ASAP OK", "ES91 2100 0418 4502 0005 1332"),
                       ("BE68 5390 0754 7034 TEST DATA", "BE68 5390 0754 7034")):
        check(f"regex-only -> IBAN before two caps words is tokenized: {text!r}",
              [(text[s:e], label) for s, e, label in det(text)] == [(iban, "IBAN")])
    pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----"
    check("regex-only -> the whole PEM block is one PRIVATE_KEY span",
          det(f"k:\n{pem}\n") == [(3, 3 + len(pem), "PRIVATE_KEY")])
    head = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
    check("regex-only -> a header with no footer takes its base64 body in one span",
          det(f"key:\n{head}\n") == [(5, 5 + len(head), "PRIVATE_KEY")])
    check("regex-only -> GLiNER was never called", calls == [])


def _check_composite():
    """GLiNER enabled: regex and NER spans merge; a down daemon still fails closed."""
    _set_predict(_degraded("daemon_unavailable"))
    raised = False
    try:
        build_detector(_Config())("mail jan@corp.example")
    except DetectionUnavailable:
        raised = True
    check("composite -> GLiNER down raises even with a regex hit (fail closed)", raised)

    text = "Jan jan@corp.example"
    _set_predict(_ner(0, 3, "person", text))
    det = build_detector(_Config())
    check("composite -> NER and regex spans both returned, sorted",
          det(text) == [(0, 3, "PERSON"), (4, 20, "EMAIL_ADDRESS")])
    check("composite posture reports 'available'", det.posture() == AVAILABLE)

    text = "Mail jan@corp.example"
    _set_predict(_ner(5, 21, "person", text))
    check("composite -> a tie goes to regex", det(text) == [(5, 21, "EMAIL_ADDRESS")])
    text = "Mail jan@corp.example, Street 1"
    _set_predict(_ner(0, 30, "address", text))
    check("composite -> the longest span wins (NER)", det(text) == [(0, 30, "ADDRESS")])
    text = "password: hunter22x now"
    _set_predict(_ner(10, 18, "password", text))
    check("composite -> the longest span wins (regex)", det(text) == [(0, 19, "PASSWORD")])
    text = "see [PERSON_1_abcdef] token: [EMAIL_ADDRESS_2_abcdef]"
    _set_predict(_ner(4, 10, "person", text))
    check("composite -> nothing is minted over an existing token", det(text) == [])
    text = "IBAN NL91ABNA0417164300"
    _set_predict(_healthy([]))
    check("composite -> regex runs even when NER finds nothing",
          det(text) == [(5, 23, "IBAN")])


def main():
    print("\n=== Production detection adapter (T021/T015, FR-007) ===\n")
    original = core_detect._predict_entities
    try:
        # --- available: real spans returned, labels normalized, tokenizable ---
        _set_predict(_healthy([
            {"start": 0, "end": 10, "label": "person", "text": "John Smith"},
            {"start": 14, "end": 24, "label": "email address", "text": "j@corp.com"},
        ]))
        det = build_detector(_Config())
        spans = det("John Smith at j@corp.com")
        check("available -> spans returned", len(spans) == 2)
        check("available -> spans are (start,end,label) tuples",
              spans[0] == (0, 10, "PERSON"))
        check("available -> spaced GLiNER label normalized to token shape",
              spans[1] == (14, 24, "EMAIL_ADDRESS"))
        check("available -> normalized labels match the [A-Z_]+ token shape",
              all(s[2].replace("_", "").isalpha() and s[2].isupper() for s in spans))
        check("available posture reports 'available'",
              det.posture() == AVAILABLE)
        check("available -> health() True (ready)", det.health() is True)

        # A clean text on a healthy daemon returns [] WITHOUT raising (empty != degraded).
        _set_predict(_healthy([]))
        check("available + no PII -> empty spans, no raise",
              build_detector(_Config())("nothing sensitive here") == [])

        # --- unavailable: daemon down -> fail closed (raises) ---
        _set_predict(_degraded("daemon_unavailable"))
        det = build_detector(_Config())
        raised = False
        try:
            det("John Smith leaked here")
        except DetectionUnavailable as exc:
            raised = True
            check("unavailable -> raise carries the reason",
                  "daemon_unavailable" in str(exc))
        check("unavailable (daemon down) -> raises, fail closed (no raw egress)", raised)
        check("unavailable posture reports 'degraded'", det.posture() == DEGRADED)
        check("degraded -> health() False (drain the replica)", det.health() is False)

        # --- degraded: model loading / partial -> fail closed (raises) ---
        _set_predict(_degraded("model_loading"))
        raised = False
        try:
            build_detector(_Config())("Jane Doe")
        except DetectionUnavailable:
            raised = True
        check("degraded -> raises, fail closed", raised)

        # --- regex-only: EREBUS_DISABLE_GLINER posture -> regex spans, never raises ---
        # Even if the (irrelevant) underlying daemon would mark degraded, the
        # regex-only detector must not touch it and must not raise.
        _set_predict(_degraded("gliner_disabled"))
        det = build_detector(_Config(detection_disabled=True))
        check("regex-only -> only the regex (email) span, never raises",
              det("John Smith email j@x.com") == [(17, 24, "EMAIL_ADDRESS")])
        check("regex-only posture reports 'regex-only'", det.posture() == REGEX_ONLY)
        check("regex-only -> health() True (deliberate, ready; not an outage)",
              det.health() is True)

        # Regex-only is independent of the underlying signal: a 'healthy' daemon's PERSON
        # span is never used.
        _set_predict(_healthy([{"start": 0, "end": 4, "label": "person", "text": "Jane"}]))
        check("regex-only ignores underlying NER entirely",
              build_detector(_Config(detection_disabled=True))("Jane") == [])

        # --- fidelity: posture()/health() probe on a healthy daemon never raises and
        #     reports 'available' even though it probes with an empty string. ---
        _set_predict(_healthy([]))
        det = build_detector(_Config())
        check("posture() probe on a healthy daemon -> 'available' (no raise)",
              det.posture() == AVAILABLE)
        check("health() on a healthy daemon -> True", det.health() is True)

        # --- fidelity: posture()/health() never raise even when the daemon raises
        #     during the probe; they report 'degraded' / False so a probe never takes
        #     the service down. ---
        def _boom(_text):
            raise RuntimeError("daemon socket refused")

        _set_predict(_boom)
        det = build_detector(_Config())
        check("posture() swallows a probe exception and reports 'degraded'",
              det.posture() == DEGRADED)
        check("health() on a raising daemon -> False (never raises)", det.health() is False)

        # --- fidelity: every distinct GLiNER label is normalized to the [A-Z_]+ token
        #     shape so each minted token is restorable (mixed case + spaces). ---
        _set_predict(_healthy([
            {"start": 0, "end": 3, "label": "Person", "text": "Ann"},
            {"start": 4, "end": 9, "label": "us ssn", "text": "12345"},
            {"start": 10, "end": 14, "label": "phone_number", "text": "0000"},
        ]))
        spans = build_detector(_Config())("Ann 12345 0000 here")
        labels = [s[2] for s in spans]
        check("mixed-case/spaced labels all normalize to [A-Z_]+",
              labels == ["PERSON", "US_SSN", "PHONE_NUMBER"])
        check("every normalized label is upper-snake (restorable token shape)",
              all(label.replace("_", "").isalpha() and label.isupper() for label in labels))

        # --- fidelity: a degraded signal raises EVEN WHEN the daemon returned spans.
        #     A partial/degraded answer must fail closed, never tokenize-and-forward a
        #     truncated detection (the daemon could have missed PII). ---
        def _degraded_with_spans(text):
            core_state._reset_detector_state()
            core_state._mark_detector_degraded("partial_result")
            return [{"start": 0, "end": 3, "label": "person", "text": "Ann"}]

        _set_predict(_degraded_with_spans)
        raised = False
        try:
            build_detector(_Config())("Ann leaked")
        except DetectionUnavailable as exc:
            raised = True
            check("degraded-with-spans raise carries the reason", "partial_result" in str(exc))
        check("degraded signal raises even when spans were returned (fail closed)", raised)

        _check_regex_only()
        _check_composite()
    finally:
        core_detect._predict_entities = original

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
