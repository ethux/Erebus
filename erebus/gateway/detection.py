"""Production detection adapter (008 T021/T015; research R4, FR-007).

The gateway tokenizer takes an injectable ``Detector`` (``text -> [(start, end,
label)]``). This module adapts ``erebus.core.detect`` (the GLiNER daemon client)
into that shape, with the fail-closed posture a deployable privacy gateway needs:

* **available** -- detection ran at full strength; PII spans are returned and the
  tokenizer can replace them before egress.
* **degraded / unavailable** -- the GLiNER daemon was unreachable or the model was
  still loading, so NER did not actually run. ``erebus.core.detect`` returns ``[]``
  in this case (and marks the per-call signal degraded). Returning those empty
  spans would forward NER-class PII (names/addresses/phones) raw to the provider,
  so in gateway mode the adapter **raises** ``DetectionUnavailable`` and the chat
  handler fails closed rather than leaking.
* **disabled** -- the operator explicitly set ``EREBUS_DISABLE_GLINER`` (recorded
  in ``GatewayConfig.detection_disabled``). This is a deliberate, surfaced config
  choice, not an outage: the detector returns ``[]`` and never raises, and the
  posture reports ``"disabled"`` so readiness/telemetry can show it.

The degraded signal is read from ``erebus.core.state`` (the same per-call flag the
core tokenizer honors) rather than inferred from the empty result, so a genuinely
clean text is never mistaken for a degraded one.
"""
from __future__ import annotations

from collections.abc import Callable

from erebus.core import detect as core_detect
from erebus.core import state as core_state

Detector = Callable[[str], "list[tuple[int, int, str]]"]  # (start, end, label)

# Posture values surfaced in readiness/telemetry (FR-007).
AVAILABLE = "available"
DEGRADED = "degraded"
DISABLED = "disabled"


def _posture_is_healthy(posture: str) -> bool:
    """Map a posture string to a readiness boolean (008 R7/FR-008).

    Detection is ready unless it is actively ``degraded``: ``available`` is healthy
    and ``disabled`` is a deliberate, surfaced operator choice that must NOT drain a
    replica. Any unrecognized posture is treated as not-healthy (fail closed), so a
    new outage shape never silently reads as ready.
    """
    return posture != DEGRADED


class DetectionUnavailable(RuntimeError):
    """Detection could not run at full strength; the gateway must fail closed.

    Raised by the production detector when the GLiNER daemon is unreachable or the
    model is still loading, so the chat handler refuses the request rather than
    forwarding raw PII it could not tokenize.
    """


def _normalize_label(label: str) -> str:
    """Map a GLiNER label (``email address``) to the token-label shape (``EMAIL_ADDRESS``).

    The gateway store mints ``[{label}_{n}_{hex}]`` verbatim and the restore regex
    only matches ``[A-Z_]+``; a raw lowercase/spaced GLiNER label would mint a token
    that can never be restored, so it is normalized here to match core's convention.
    """
    return (label or "").upper().replace(" ", "_")


class _RecordedDisabledDetector:
    """Detector for the explicit ``EREBUS_DISABLE_GLINER`` posture.

    Always returns no spans and never raises: detection is off by deliberate
    operator choice, and the posture records that choice as ``"disabled"`` so it is
    visible in readiness/telemetry rather than masquerading as an outage.
    """

    def __call__(self, text: str) -> list[tuple[int, int, str]]:
        return []

    def posture(self) -> str:
        return DISABLED

    def health(self) -> bool:
        """Disabled detection is a deliberate, healthy posture: always ready.

        Never raises -- a readiness probe must not take the service down.
        """
        return True


class _CoreDetector:
    """Fail-closed adapter over ``erebus.core.detect`` for gateway mode.

    Calls core detection, maps each ``{start, end, label}`` entity to a
    ``(start, end, label)`` span, and raises :class:`DetectionUnavailable` whenever
    the per-call degraded signal fired (daemon down / model loading), so the
    gateway refuses the request instead of leaking raw PII.
    """

    def __call__(self, text: str) -> list[tuple[int, int, str]]:
        core_state._reset_detector_state()
        entities = core_detect.predict_entities(text)
        if core_state.detector_degraded():
            reason = core_state.turn_degraded_reason() or "detector_degraded"
            raise DetectionUnavailable(reason)
        return [
            (int(e["start"]), int(e["end"]), _normalize_label(e["label"]))
            for e in entities
        ]

    def posture(self) -> str:
        """Best-effort live posture for readiness/telemetry.

        Probes detection with an empty string (no PII, never raises on a healthy
        daemon) and reports ``"degraded"`` if the daemon is unreachable, else
        ``"available"``. Never raises -- a posture probe must not take the service
        down.
        """
        try:
            core_state._reset_detector_state()
            core_detect.predict_entities("")
        except Exception:
            return DEGRADED
        return DEGRADED if core_state.detector_degraded() else AVAILABLE

    def health(self) -> bool:
        """Readiness boolean for ``/readyz`` derived from the masked posture (FR-008).

        ``True`` while detection is ``available`` (the daemon answered the probe),
        ``False`` once it is ``degraded`` (daemon down / model loading) so a load
        balancer drains the replica. Built on :meth:`posture`, which masks all raw
        daemon internals and never raises, so this never raises either.
        """
        return _posture_is_healthy(self.posture())


def build_detector(config) -> Detector:
    """Return the gateway ``Detector`` for the given config (FR-007).

    When ``config.detection_disabled`` is set (``EREBUS_DISABLE_GLINER``), returns a
    recorded-disabled detector that always yields no spans and never raises. Otherwise
    returns the fail-closed adapter over ``erebus.core.detect`` that raises
    :class:`DetectionUnavailable` when detection is degraded/unavailable. Both expose a
    ``posture()`` reporting ``available`` | ``degraded`` | ``disabled`` and a
    ``health() -> bool`` for ``/readyz`` (``True`` unless ``degraded``; ``disabled`` is
    healthy). Neither surface raises -- a readiness probe must not take the service down.
    """
    if getattr(config, "detection_disabled", False):
        return _RecordedDisabledDetector()
    return _CoreDetector()
