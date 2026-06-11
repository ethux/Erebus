"""GLiNER detection client: daemon calls, window chunking, and the NER ceiling.

Two-layer approach (with erebus.core.patterns):
  1. GLiNER (urchade/gliner_multi_pii-v1) — fast local NER, multilingual
     Detects: names, emails, phones, addresses, orgs, IBANs, SSNs, IPs, etc.
  2. Regex — instant, zero deps, catches secrets/credentials (patterns.py)

The daemon import stays lazy and runtime/daemon keeps its own GLINER_LABELS
copy — importing this module from the daemon would create a cycle.
"""
from __future__ import annotations

import os
from functools import lru_cache

from . import modes
from .state import _mark_detector_degraded

GLINER_LABELS = [
    "person", "email address", "phone number", "address",
    "organization", "credit card number", "social security number",
    "iban", "passport number", "ip address", "username",
    "password", "api key", "date of birth", "bank account number",
]

# GLiNER window chunking (specs/003-proxy-tokenize-latency). The detector's
# effective context window is small (~384 tokens), so feeding it one giant
# block (e.g. a Codex tool output of a whole file) is both slow and inaccurate.
# Long text is split into overlapping windows, predicted as a batch, and the
# entity offsets are remapped to the original text. Above the hard ceiling NER
# is skipped entirely; the cheap structured/secret/blacklist/catalog passes in
# tokenize() still run, so oversized content stays bounded AND protected.
NER_WINDOW_CHARS = 1500       # ~384 tokens
NER_WINDOW_OVERLAP = 150      # catch entities straddling a window boundary
NER_CEILING_CHARS = 32_768    # above this, skip NER (cheap passes only)


@lru_cache(maxsize=1)
def _get_gliner():
    """Lazy-load GLiNER model — cached after first call."""
    from gliner import GLiNER
    return GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")


def _allow_in_process_gliner() -> bool:
    """Emergency escape hatch for debugging; normal clients must use the daemon."""
    return os.environ.get("EREBUS_ALLOW_IN_PROCESS_GLINER", "").lower() in {"1", "true", "yes"}


def preload_gliner():
    """Ensure GLiNER daemon is running (starts it if needed)."""
    from ..runtime.daemon import ensure_daemon
    ensure_daemon()


def _gliner_disabled() -> bool:
    """Hard off-switch for NER. Used by hermetic tests and regex-only setups so
    no daemon is started and detection relies on the cheap passes alone."""
    return os.environ.get("EREBUS_DISABLE_GLINER", "").lower() in {"1", "true", "yes"}


def _predict_entities(text: str) -> list[dict]:
    """Get GLiNER entities from the daemon without loading the model in clients."""
    if _gliner_disabled():
        _mark_detector_degraded("gliner_disabled")
        return []
    from ..runtime.daemon import ensure_daemon, predict_via_daemon

    result = predict_via_daemon(text, threshold=0.85)
    if result is not None:
        return modes._filter_entities(result)

    try:
        ensure_daemon()
    except Exception:
        pass

    # Retry the daemon after starting it — otherwise the first request that
    # boots the daemon would skip detection entirely and leak PII.
    result = predict_via_daemon(text, threshold=0.85)
    if result is not None:
        return modes._filter_entities(result)

    if not _allow_in_process_gliner():
        _mark_detector_degraded("daemon_unavailable")
        return []

    model = _get_gliner()
    entities = model.predict_entities(text, GLINER_LABELS, threshold=0.85)
    raw = [{"start": e["start"], "end": e["end"], "label": e["label"],
            "text": e["text"]} for e in entities]
    return modes._filter_entities(raw)


def _predict_entities_many(texts: list[str]) -> list[list[dict]]:
    """Get GLiNER entities for many texts without concatenating them."""
    if not texts:
        return []
    if _gliner_disabled():
        _mark_detector_degraded("gliner_disabled")
        return [[] for _ in texts]

    from ..runtime.daemon import ensure_daemon, predict_many_via_daemon, predict_via_daemon

    result = predict_many_via_daemon(texts, threshold=0.85)
    if result is not None:
        return [modes._filter_entities(entities) for entities in result]

    try:
        ensure_daemon()
    except Exception:
        pass

    # Retry the daemon after starting it (see _predict_entities) before any
    # in-process fallback.
    result = predict_many_via_daemon(texts, threshold=0.85)
    if result is not None:
        return [modes._filter_entities(entities) for entities in result]

    # Older already-running daemons only understand single-text requests.
    single_results = []
    daemon_available = True
    for text in texts:
        entities = predict_via_daemon(text, threshold=0.85)
        if entities is None:
            daemon_available = False
            break
        single_results.append(modes._filter_entities(entities))
    if daemon_available:
        return single_results

    if not _allow_in_process_gliner():
        _mark_detector_degraded("daemon_unavailable")
        return [[] for _ in texts]

    model = _get_gliner()
    batches: list[list[dict]]  # type: ignore[assignment]
    if hasattr(model, "inference"):
        batches = model.inference(texts, GLINER_LABELS, threshold=0.85, batch_size=8)  # type: ignore[assignment]
    else:
        batches = [
            model.predict_entities(text, GLINER_LABELS, threshold=0.85)
            for text in texts
        ]
    return [
        modes._filter_entities([
            {"start": e["start"], "end": e["end"], "label": e["label"],
             "text": e["text"]}
            for e in entities
        ])
        for entities in batches
    ]


def predict_entities(text: str) -> list[dict]:
    """Public single-text detection entry point (FR-008).

    Thin alias of ``_predict_entities`` so callers outside erebus/core/ never
    bind the private name; resolved at call time so test patches of
    ``detect._predict_entities`` stay effective.
    """
    return _predict_entities(text)


def predict_entities_many(texts: list[str]) -> list[list[dict]]:
    """Public batch detection entry point (FR-008); see ``predict_entities``."""
    return _predict_entities_many(texts)


def _window_slices(text: str) -> list[tuple[int, str]]:
    """Split text into overlapping windows. Returns (abs_start, window_text)."""
    step = max(1, NER_WINDOW_CHARS - NER_WINDOW_OVERLAP)
    slices: list[tuple[int, str]] = []
    start = 0
    n = len(text)
    while start < n:
        end = min(start + NER_WINDOW_CHARS, n)
        slices.append((start, text[start:end]))
        if end >= n:
            break
        start += step
    return slices


def _remap_windowed_entities(slices: list[tuple[int, str]],
                             per_window: list[list[dict]]) -> list[dict]:
    """Remap per-window entity offsets to the original text and dedupe overlaps."""
    seen: set[tuple[int, int, str]] = set()
    merged: list[dict] = []
    for (abs_start, _window), entities in zip(slices, per_window):  # noqa: B905
        for e in entities:
            s = e["start"] + abs_start
            en = e["end"] + abs_start
            ident = (s, en, e["label"])
            if ident in seen:
                continue
            seen.add(ident)
            merged.append({"start": s, "end": en, "label": e["label"], "text": e["text"]})
    merged.sort(key=lambda e: e["start"])
    return merged


def _predict_entities_windowed(text: str) -> list[dict]:
    """Detect entities with bounded cost.

    Short text: one prediction (current behaviour). Medium text: window-chunk and
    batch-predict, remapping offsets to the original. Oversized text (> ceiling):
    skip NER entirely — the caller's cheap passes still protect it.
    """
    n = len(text)
    if n <= NER_WINDOW_CHARS:
        return _predict_entities(text)
    if n > NER_CEILING_CHARS:
        # Intentional, documented policy (not an outage): NER's effective window
        # is ~384 tokens, so above the ceiling we rely on the whole-text cheap
        # passes. This is NOT marked degraded — large clean histories remain
        # fingerprint-cacheable, matching pre-existing behaviour.
        return []
    slices = _window_slices(text)
    per_window = _predict_entities_many([window for _start, window in slices])
    return _remap_windowed_entities(slices, per_window)


def _predict_entities_many_windowed(texts: list[str]) -> list[list[dict]]:
    """Batch variant of _predict_entities_windowed.

    When every text fits a single window, defers to the existing single-batch
    path. Oversized texts are window-chunked individually so one giant item in a
    batch can never trigger an unbounded forward pass.
    """
    if all(len(t) <= NER_WINDOW_CHARS for t in texts):
        return _predict_entities_many(texts)
    results: list[list[dict] | None] = [None] * len(texts)
    small_idx: list[int] = []
    small_texts: list[str] = []
    for i, text in enumerate(texts):
        if len(text) <= NER_WINDOW_CHARS:
            small_idx.append(i)
            small_texts.append(text)
        else:
            results[i] = _predict_entities_windowed(text)
    if small_texts:
        for idx, entities in zip(small_idx, _predict_entities_many(small_texts)):  # noqa: B905
            results[idx] = entities
    return [r if r is not None else [] for r in results]
