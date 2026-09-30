"""Production detection adapter (008 T021/T015; research R4, FR-007).

The gateway tokenizer takes an injectable ``Detector`` (``text -> [(start, end,
label)]``). This module builds it from two layers:

* **regex** -- the ``erebus.core.patterns`` structured-PII and secret patterns (email,
  international phone, IBAN, API keys, private keys, ``key=value`` secrets). No daemon;
  always runs.
* **NER** -- ``erebus.core.detect`` (the GLiNER daemon client), unless the operator set
  ``EREBUS_DISABLE_GLINER`` (``GatewayConfig.detection_disabled``).

Postures surfaced in readiness/telemetry:

* **available** -- regex + GLiNER ran at full strength.
* **degraded** -- GLiNER is enabled but the daemon was unreachable or still loading.
  The detector **raises** ``DetectionUnavailable`` and the chat handler fails closed
  (503). Regex never stands in for a down GLiNER: names and addresses would ride to
  the provider raw.
* **regex-only** -- ``EREBUS_DISABLE_GLINER`` is set. Regex still runs; NER-only
  classes (names, addresses, national phone formats) are not detected. A deliberate,
  recorded choice: ready, never raises.

The degraded signal is read from ``erebus.core.state`` (the same per-call flag the
core tokenizer honors) rather than inferred from the empty result, so a genuinely
clean text is never mistaken for a degraded one.
"""
from __future__ import annotations

import re
from collections.abc import Callable

from erebus.core import detect as core_detect
from erebus.core import patterns as core_patterns
from erebus.core import state as core_state

from .spans import Span, merge_spans

Detector = Callable[[str], "list[tuple[int, int, str]]"]  # (start, end, label)

# Posture values surfaced in readiness/telemetry (FR-007).
AVAILABLE = "available"
DEGRADED = "degraded"
REGEX_ONLY = "regex-only"

# Compiled once; the patterns themselves live only in erebus.core.patterns.
_REGEX = tuple((re.compile(pattern), label) for pattern, label in core_patterns.SECRET_PATTERNS)


def _posture_is_healthy(posture: str) -> bool:
    """Map a posture string to a readiness boolean (008 R7/FR-008).

    Detection is ready unless it is actively ``degraded``: ``available`` is healthy
    and ``regex-only`` is a deliberate, surfaced operator choice that must NOT drain a
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


def _merge(regex: list[Span], ner: list[Span], text: str) -> list[Span]:
    """Resolve overlaps once: longest span first, ties to regex, never over an existing token.

    Every span comes from the original text, unlike core's sequential ``re.sub``, so no
    token is ever minted around another token: the gateway's single-pass restore could not
    unwrap it. Returns disjoint spans by start.
    """
    return merge_spans(regex, ner, text)


def _regex_spans(text: str) -> list[Span]:
    """Every core ``SECRET_PATTERNS`` hit plus checksum-valid IBANs, on the original text."""
    spans = [(m.start(), m.end(), label) for rx, label in _REGEX for m in rx.finditer(text)]
    spans.extend(core_patterns.iban_spans(text))
    return spans


class _RegexOnlyDetector:
    """Detector for the explicit ``EREBUS_DISABLE_GLINER`` posture: core regex, no NER.

    Never touches the daemon and never raises; the posture records the choice as
    ``"regex-only"`` so it is visible in readiness/telemetry, not mistaken for an outage.
    """

    def __call__(self, text: str) -> list[Span]:
        return _merge(_regex_spans(text), [], text)

    def posture(self) -> str:
        return REGEX_ONLY

    def health(self) -> bool:
        """Regex-only is a deliberate, healthy posture: always ready. Never raises."""
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


class _CompositeDetector:
    """Regex + fail-closed GLiNER: the production detector when GLiNER is enabled.

    NER runs first, so a down daemon raises :class:`DetectionUnavailable` before any
    span is returned; regex hits never let a degraded request through.
    """

    def __init__(self) -> None:
        self._ner = _CoreDetector()

    def __call__(self, text: str) -> list[Span]:
        ner = self._ner(text)  # raises DetectionUnavailable when GLiNER is degraded
        return _merge(_regex_spans(text), ner, text)

    def posture(self) -> str:
        return self._ner.posture()

    def health(self) -> bool:
        return self._ner.health()


def build_detector(config) -> Detector:
    """Return the gateway ``Detector`` for the given config (FR-007).

    ``config.detection_disabled`` (``EREBUS_DISABLE_GLINER``) -> the regex-only detector:
    core regex spans, never raises. Otherwise -> regex + GLiNER, which raises
    :class:`DetectionUnavailable` when GLiNER is degraded/unavailable. Both expose a
    ``posture()`` reporting ``available`` | ``degraded`` | ``regex-only`` and a
    ``health() -> bool`` for ``/readyz`` (``True`` unless ``degraded``). Neither surface
    raises -- a readiness probe must not take the service down.
    """
    if getattr(config, "detection_disabled", False):
        return _RegexOnlyDetector()
    return _CompositeDetector()
