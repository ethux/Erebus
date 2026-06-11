"""Detection-completeness signals (per-call + per-turn) and the degraded warner.

Leaf module. Per-thread detection-completeness signal
(specs/003-proxy-tokenize-latency): when NER could not run at full strength
(daemon unreachable, model still loading, or text skipped above the ceiling),
the detector marks the current tokenize call "degraded". A degraded result
MUST NOT be recorded as a durable "clean" fingerprint — otherwise a transient
daemon outage would permanently forward NER-class PII (names/addresses/phones)
as clean on every resent turn.
"""
from __future__ import annotations

import sys
import threading
import time

_DETECTOR_STATE = threading.local()


def _reset_detector_state() -> None:
    # Per-call flag only — the turn-scoped flag survives so a degraded signal
    # from an earlier cached_tokenize call in the same request isn't lost.
    _DETECTOR_STATE.degraded = False
    _DETECTOR_STATE.reason = ""


def _mark_detector_degraded(reason: str) -> None:
    _DETECTOR_STATE.degraded = True
    _DETECTOR_STATE.reason = reason
    _DETECTOR_STATE.turn_degraded = True
    _DETECTOR_STATE.turn_reason = reason


def detector_degraded() -> bool:
    return bool(getattr(_DETECTOR_STATE, "degraded", False))


def begin_detection_turn() -> None:
    """Reset the turn-scoped degraded signal. Call once per request/turn,
    before any tokenization for that turn runs."""
    _DETECTOR_STATE.turn_degraded = False
    _DETECTOR_STATE.turn_reason = ""


def turn_degraded() -> bool:
    """True if any detection call since begin_detection_turn() was degraded."""
    return bool(getattr(_DETECTOR_STATE, "turn_degraded", False))


def turn_degraded_reason() -> str:
    return getattr(_DETECTOR_STATE, "turn_reason", "")


_DEGRADED_WARN_INTERVAL_SECS = 300.0
_DEGRADED_WARN_LOCK = threading.Lock()
_last_degraded_warn = 0.0


def warn_detection_degraded(reason: str) -> bool:
    """Loudly signal that PII detection ran degraded (stderr + macOS
    notification), debounced so a long outage doesn't spam every message.
    Returns True if a warning was emitted this call."""
    global _last_degraded_warn
    with _DEGRADED_WARN_LOCK:
        now = time.monotonic()
        if now - _last_degraded_warn < _DEGRADED_WARN_INTERVAL_SECS:
            return False
        _last_degraded_warn = now
    print(
        f"[erebus] WARNING: PII detection degraded ({reason}) — "
        "NER did not run; only regex/blacklist passes applied.",
        file=sys.stderr, flush=True,
    )
    try:
        from ..ui.popup import notify
        # Fixed strings only: notify() interpolates into AppleScript source.
        notify("Erebus", "PII detection degraded - GLiNER daemon unreachable")
    except Exception:
        pass
    return True
