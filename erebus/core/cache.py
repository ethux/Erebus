"""Two-tier tokenize cache (memory + disk) and batch tokenization.

Chat clients commonly resend the same history on every turn; cache hits reuse
the sanitized text and token map instead of re-running GLiNER/verifiers and
minting duplicate tokens.

Cross-module rules:
  * tokenize is invoked as ``tokenizer.tokenize(...)`` and batch prediction as
    ``detect._predict_entities_many_windowed(...)`` (module attributes), so
    patching the owning module intercepts these calls.
  * All ``_DISK_*`` state lives in cache_disk and is REBOUND by
    _save_disk_cache(); it is only ever accessed here as ``cache_disk.<attr>``.
"""
from __future__ import annotations

import hashlib
import threading
from collections import OrderedDict

from ..perf import PerfTimer, log_perf_event
from . import cache_disk, detect, tokenizer
from .escapes import _parse_escapes
from .modes import DEFAULT_MODE
from .state import (
    _mark_detector_degraded,
    _reset_detector_state,
    begin_detection_turn,
    detector_degraded,
)

_TOKENIZE_CACHE_MAX_ENTRIES = 1024
_TOKENIZE_CACHE_MAX_TEXT_CHARS = 32_768
_TOKENIZE_BATCH_MAX_TEXT_CHARS = 200_000

_TOKENIZE_CACHE: OrderedDict[tuple, tuple[str, dict]] = OrderedDict()
_TOKENIZE_CLEAN_CACHE: OrderedDict[tuple, None] = OrderedDict()
_TOKENIZE_CACHE_LOCK = threading.Lock()


def _short_cache_key(key: tuple) -> str:
    return cache_disk._disk_cache_key(key)[:12]


def _cache_text_identity(text: str) -> str | tuple[str, int, str]:
    if len(text) <= _TOKENIZE_CACHE_MAX_TEXT_CHARS:
        return text
    return ("sha256", len(text), hashlib.sha256(text.encode("utf-8")).hexdigest())


def _cache_tuple(values: list[str] | None) -> tuple[str, ...]:
    return tuple(values or ())


def _tokenize_cache_key(text: str, extra_entities: list[str] | None,
                        allowed_names: list[str] | None, mode: str,
                        blacklist: list[str] | None,
                        verifiers: list[str] | None,
                        verifier_llm_model: str,
                        verifier_openai_pf_url: str) -> tuple:
    return (
        _cache_text_identity(text),
        _cache_tuple(extra_entities),
        _cache_tuple(allowed_names),
        mode,
        _cache_tuple(blacklist),
        _cache_tuple(verifiers),
        verifier_llm_model,
        verifier_openai_pf_url,
    )


def _get_cached_tokenize_result_detail(key: tuple, original_text: str | None = None) -> tuple[tuple[str, dict] | None, str]:  # noqa: E501
    with _TOKENIZE_CACHE_LOCK:
        cached = _TOKENIZE_CACHE.get(key)
        if cached is not None:
            _TOKENIZE_CACHE.move_to_end(key)
            sanitized, tokens = cached
            return (sanitized, dict(tokens)), "memory"
        if key in _TOKENIZE_CLEAN_CACHE and original_text is not None:
            _TOKENIZE_CLEAN_CACHE.move_to_end(key)
            return (original_text, {}), "memory_clean"

    cache_disk._load_disk_cache()
    dk = cache_disk._disk_cache_key(key)
    if dk in cache_disk._DISK_CLEAN_CACHE and original_text is not None:
        with _TOKENIZE_CACHE_LOCK:
            _TOKENIZE_CLEAN_CACHE[key] = None
            _TOKENIZE_CLEAN_CACHE.move_to_end(key)
            while len(_TOKENIZE_CLEAN_CACHE) > _TOKENIZE_CACHE_MAX_ENTRIES:
                _TOKENIZE_CLEAN_CACHE.popitem(last=False)
        return (original_text, {}), "disk_clean"
    disk_hit = cache_disk._DISK_CACHE.get(dk)
    if disk_hit is None:
        return None, "miss"

    sanitized, tokens = disk_hit[0], dict(disk_hit[1])
    with _TOKENIZE_CACHE_LOCK:
        _TOKENIZE_CACHE[key] = (sanitized, dict(tokens))
        _TOKENIZE_CACHE.move_to_end(key)
        while len(_TOKENIZE_CACHE) > _TOKENIZE_CACHE_MAX_ENTRIES:
            _TOKENIZE_CACHE.popitem(last=False)
    return (sanitized, tokens), "disk"


def _store_tokenize_result(key: tuple, sanitized: str, tokens: dict,
                           save: bool = True, original_text: str | None = None,
                           degraded: bool | None = None) -> str:
    if degraded is None:
        degraded = detector_degraded()
    if degraded:
        # Never cache a degraded result — not just clean fingerprints. A
        # token-bearing result from a degraded pass (regex caught an email,
        # NER missed a name) would otherwise replay the under-filtered text
        # from memory/disk even after the daemon recovers. Re-run detection
        # next time instead.
        return "degraded_skip"
    if original_text is not None and not tokens and sanitized == original_text:
        with _TOKENIZE_CACHE_LOCK:
            _TOKENIZE_CLEAN_CACHE[key] = None
            _TOKENIZE_CLEAN_CACHE.move_to_end(key)
            while len(_TOKENIZE_CLEAN_CACHE) > _TOKENIZE_CACHE_MAX_ENTRIES:
                _TOKENIZE_CLEAN_CACHE.popitem(last=False)
        dk = cache_disk._disk_cache_key(key)
        cache_disk._DISK_CLEAN_CACHE.add(dk)
        cache_disk._DISK_CLEAN_CACHE_DIRTY_KEYS.add(dk)
        cache_disk.mark_dirty()
        if save:
            cache_disk._save_disk_cache()
        return "clean_fingerprint"

    if len(sanitized) > _TOKENIZE_CACHE_MAX_TEXT_CHARS:
        return "too_large"

    with _TOKENIZE_CACHE_LOCK:
        _TOKENIZE_CACHE[key] = (sanitized, dict(tokens))
        _TOKENIZE_CACHE.move_to_end(key)
        while len(_TOKENIZE_CACHE) > _TOKENIZE_CACHE_MAX_ENTRIES:
            _TOKENIZE_CACHE.popitem(last=False)

    if not cache_disk._can_persist_tokenize_result(sanitized, tokens):
        return "memory_only"

    dk = cache_disk._disk_cache_key(key)
    cache_disk._DISK_CACHE[dk] = (sanitized, dict(tokens))
    cache_disk._DISK_CACHE_DIRTY_KEYS.add(dk)
    cache_disk.mark_dirty()
    if save:
        cache_disk._save_disk_cache()
        return "disk"
    return "disk_pending"


def clear_tokenize_cache() -> None:
    """Clear both in-memory and disk tokenization caches."""
    # Full reset includes the degraded-detection signals, so a stale flag from
    # earlier activity on this thread can't suppress caching of fresh results.
    _reset_detector_state()
    begin_detection_turn()
    with _TOKENIZE_CACHE_LOCK:
        _TOKENIZE_CACHE.clear()
        _TOKENIZE_CLEAN_CACHE.clear()
    cache_disk.reset()


def cached_tokenize(text: str, extra_entities: list[str] | None = None,
                    allowed_names: list[str] | None = None,
                    mode: str = DEFAULT_MODE,
                    blacklist: list[str] | None = None,
                    verifiers: list[str] | None = None,
                    verifier_llm_model: str = "gemma3:1b",
                    verifier_openai_pf_url: str = "") -> tuple[str, dict]:
    """Tokenize with a two-tier cache (memory + disk).

    Chat clients commonly resend the same history on every turn. The first
    pass still runs the full detector pipeline; later identical strings reuse
    the same sanitized text and token map instead of running GLiNER/verifiers
    again and minting duplicate tokens.

    The disk cache survives process restarts so the proxy doesn't re-tokenize
    the entire conversation on every Codex turn after a restart.
    """
    timer = PerfTimer()
    key = _tokenize_cache_key(
        text, extra_entities, allowed_names, mode, blacklist, verifiers,
        verifier_llm_model, verifier_openai_pf_url,
    )

    cached, cache_result = _get_cached_tokenize_result_detail(key, text)
    if cached is not None:
        log_perf_event(
            "tokenize_cache",
            **timer.finish(),
            cache_result=cache_result,
            cache_key=_short_cache_key(key),
            text_count=1,
            text_chars=len(text),
            token_count=len(cached[1]),
            mode=mode,
            verifier_count=len(verifiers or []),
        )
        return cached

    # Cache miss: run full pipeline. Reset the degraded signal here as well so
    # a stale flag from an earlier call can never block clean-fingerprinting
    # (tokenize() also resets, but callers may stub it in tests).
    _reset_detector_state()
    sanitized, tokens = tokenizer.tokenize(
        text, extra_entities, allowed_names, mode=mode,
        blacklist=blacklist, verifiers=verifiers,
        verifier_llm_model=verifier_llm_model,
        verifier_openai_pf_url=verifier_openai_pf_url,
    )

    stored = _store_tokenize_result(key, sanitized, tokens, original_text=text)
    log_perf_event(
        "tokenize_cache",
        **timer.finish(),
        cache_result=cache_result,
        cache_key=_short_cache_key(key),
        stored=stored,
        text_count=1,
        text_chars=len(text),
        token_count=len(tokens),
        mode=mode,
        verifier_count=len(verifiers or []),
    )
    return sanitized, tokens


def _batch_chunks(items: list[tuple[int, str, tuple]]) -> list[list[tuple[int, str, tuple]]]:
    chunks = []
    current = []
    current_chars = 0
    for item in items:
        text_len = len(item[1])
        if current and current_chars + text_len > _TOKENIZE_BATCH_MAX_TEXT_CHARS:
            chunks.append(current)
            current = []
            current_chars = 0
        current.append(item)
        current_chars += text_len
    if current:
        chunks.append(current)
    return chunks


def _tokenize_batch_misses(items: list[tuple[int, str, tuple]],
                           extra_entities: list[str] | None,
                           allowed_names: list[str] | None,
                           mode: str,
                           blacklist: list[str] | None,
                           verifiers: list[str] | None,
                           verifier_llm_model: str,
                           verifier_openai_pf_url: str) -> list[tuple[int, str, dict]]:
    timer = PerfTimer()
    results = []
    cleaned_texts = [_parse_escapes(text)[1] for _idx, text, _key in items]
    _reset_detector_state()
    try:
        predicted_batches = detect._predict_entities_many_windowed(cleaned_texts)
    except Exception:
        _mark_detector_degraded("daemon_unavailable")
        predicted_batches = [[] for _ in items]
    # Batch-level detection state applies to every item produced from this call.
    degraded_batch = detector_degraded()
    for (idx, text, key), predicted_entities in zip(items, predicted_batches):  # noqa: B905
        sanitized, tokens = tokenizer.tokenize(
            text, extra_entities, allowed_names, mode=mode,
            blacklist=blacklist, verifiers=verifiers,
            verifier_llm_model=verifier_llm_model,
            verifier_openai_pf_url=verifier_openai_pf_url,
            _predicted_entities=predicted_entities,
        )
        _store_tokenize_result(key, sanitized, tokens, save=False, original_text=text,
                               degraded=degraded_batch)
        results.append((idx, sanitized, tokens))
    cache_disk._save_disk_cache()
    log_perf_event(
        "tokenize_batch_miss",
        **timer.finish(),
        text_count=len(items),
        text_chars=sum(len(text) for _idx, text, _key in items),
        token_count=sum(len(tokens) for _idx, _sanitized, tokens in results),
        mode=mode,
        verifier_count=len(verifiers or []),
    )
    return results


def cached_tokenize_many(texts: list[str], extra_entities: list[str] | None = None,
                         allowed_names: list[str] | None = None,
                         mode: str = DEFAULT_MODE,
                         blacklist: list[str] | None = None,
                         verifiers: list[str] | None = None,
                         verifier_llm_model: str = "gemma3:1b",
                         verifier_openai_pf_url: str = "") -> list[tuple[str, dict]]:
    """Tokenize many strings while preserving the per-string cache contract.

    Chat/Responses payloads often contain many fresh text fragments. Cache hits
    still return per string, while cache misses use GLiNER's batch inference
    and are stored as individual long-lived cache entries.
    """
    timer = PerfTimer()
    results: list[tuple[str, dict] | None] = [None] * len(texts)
    misses: list[tuple[int, str, tuple]] = []
    cache_counts: dict[str, int] = {}

    for i, text in enumerate(texts):
        key = _tokenize_cache_key(
            text, extra_entities, allowed_names, mode, blacklist, verifiers,
            verifier_llm_model, verifier_openai_pf_url,
        )
        cached, cache_result = _get_cached_tokenize_result_detail(key, text)
        cache_counts[cache_result] = cache_counts.get(cache_result, 0) + 1
        if cached is not None:
            results[i] = cached
        else:
            misses.append((i, text, key))

    for chunk in _batch_chunks(misses):
        for idx, sanitized, tokens in _tokenize_batch_misses(
            chunk, extra_entities, allowed_names, mode, blacklist, verifiers,
            verifier_llm_model, verifier_openai_pf_url,
        ):
            results[idx] = (sanitized, tokens)

    if any(result is None for result in results):
        raise RuntimeError("cached_tokenize_many left an unprocessed text")
    final = [(sanitized, dict(tokens)) for sanitized, tokens in results]  # type: ignore[misc]
    log_perf_event(
        "tokenize_many_cache",
        **timer.finish(),
        cache_result="mixed",
        cache_counts=cache_counts,
        text_count=len(texts),
        text_chars=sum(len(text) for text in texts),
        miss_count=len(misses),
        token_count=sum(len(tokens) for _sanitized, tokens in final),
        mode=mode,
        verifier_count=len(verifiers or []),
    )
    return final
