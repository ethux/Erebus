"""Production detection adapter unit tests (008 T021/T015; research R4, FR-007).

No database, no real GLiNER daemon: we monkeypatch
``erebus.core.detect._predict_entities`` (the daemon client that
``predict_entities`` resolves at call time) and drive the degraded signal through
``erebus.core.state`` directly, exactly the way a real daemon outage would surface
it. Verifies the four postures the spec requires:

  * available   -> real PII spans returned and tokenizable (labels normalized)
  * unavailable -> the adapter raises (fail closed; no raw egress)
  * degraded    -> the adapter raises (fail closed)
  * disabled    -> EREBUS_DISABLE_GLINER posture: returns [] and never raises

and the readiness surface ``health()`` derived from that posture (008 R7/FR-008):

  * available -> health True   · degraded -> health False (drain the replica)
  * disabled  -> health True (deliberate, surfaced operator choice, never an outage)
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.core import detect as core_detect
from erebus.core import state as core_state
from erebus.gateway.detection import (
    AVAILABLE,
    DEGRADED,
    DISABLED,
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


def main():
    print("\n=== Production detection adapter (T021/T015, FR-007) ===\n")
    original = core_detect._predict_entities
    try:
        # --- available: real spans returned, labels normalized, tokenizable ---
        _set_predict(_healthy([
            {"start": 0, "end": 10, "label": "person", "text": "John Smith"},
            {"start": 15, "end": 28, "label": "email address", "text": "j@corp.com"},
        ]))
        det = build_detector(_Config())
        spans = det("John Smith at j@corp.com")
        check("available -> spans returned", len(spans) == 2)
        check("available -> spans are (start,end,label) tuples",
              spans[0] == (0, 10, "PERSON"))
        check("available -> spaced GLiNER label normalized to token shape",
              spans[1] == (15, 28, "EMAIL_ADDRESS"))
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

        # --- disabled: EREBUS_DISABLE_GLINER posture -> [] and never raises ---
        # Even if the (irrelevant) underlying daemon would mark degraded, the
        # recorded-disabled detector must not touch it and must not raise.
        _set_predict(_degraded("gliner_disabled"))
        det = build_detector(_Config(detection_disabled=True))
        check("disabled -> returns [] (never raises)", det("John Smith email j@x.com") == [])
        check("disabled posture reports 'disabled'", det.posture() == DISABLED)
        check("disabled -> health() True (deliberate, ready; not an outage)",
              det.health() is True)

        # Disabled is independent of the underlying signal: still [] with a 'healthy'
        # daemon, and still never raises.
        _set_predict(_healthy([{"start": 0, "end": 4, "label": "person", "text": "Jane"}]))
        check("disabled ignores underlying detection entirely",
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
    finally:
        core_detect._predict_entities = original

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
