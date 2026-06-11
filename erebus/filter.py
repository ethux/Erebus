"""PII detection and tokenization — compatibility facade.

The implementation lives in erebus/core/ (specs/004-core-pii-boundary, P2):

  patterns.py   token shapes + secret/structured-PII regexes
  detect.py     GLiNER daemon client, window chunking, NER ceiling
  state.py      degraded/turn signals + degraded warner
  escapes.py    ``~`` escape-marker parsing
  modes.py      filter modes, policy data, blacklist classification
  tokenizer.py  tokenize()/detokenize() composition
  verify.py     verifier dispatch
  cache.py      two-tier tokenize cache + batching
  cache_disk.py disk-backed cache (v5 format)

This module only re-exports that surface for existing importers. Mutable
cache/state attributes are forwarded live via ``__getattr__`` (PEP 562) so
module-level reads such as ``erebus.filter._DISK_CACHE`` keep observing the
owning module's current binding. Patching/assigning attributes must target
the owning core module, not this facade.
"""
from __future__ import annotations

from .core import cache as _cache_mod
from .core import cache_disk as _cache_disk_mod
from .core import state as _state_mod
from .core.cache import (
    _TOKENIZE_CACHE_LOCK,
    _TOKENIZE_CACHE_MAX_TEXT_CHARS,
    _get_cached_tokenize_result_detail,
    _store_tokenize_result,
    _tokenize_cache_key,
    cached_tokenize,
    cached_tokenize_many,
    clear_tokenize_cache,
)
from .core.cache_disk import (
    _DISK_CACHE_VERSION,
    _disk_cache_key,
    _load_disk_cache,
    _save_disk_cache,
)
from .core.detect import (
    GLINER_LABELS,
    NER_CEILING_CHARS,
    NER_WINDOW_CHARS,
    NER_WINDOW_OVERLAP,
    _get_gliner,
    _predict_entities,
    _predict_entities_many,
    preload_gliner,
)
from .core.escapes import _parse_escapes
from .core.modes import DEFAULT_MODE, MODES
from .core.patterns import SECRET_PATTERNS, TOKEN_RE
from .core.state import (
    _mark_detector_degraded,
    begin_detection_turn,
    detector_degraded,
    turn_degraded,
    turn_degraded_reason,
    warn_detection_degraded,
)
from .core.tokenizer import detokenize, tokenize

__all__ = [
    "DEFAULT_MODE",
    "GLINER_LABELS",
    "MODES",
    "NER_CEILING_CHARS",
    "NER_WINDOW_CHARS",
    "NER_WINDOW_OVERLAP",
    "SECRET_PATTERNS",
    "TOKEN_RE",
    "_DISK_CACHE_VERSION",
    "_TOKENIZE_CACHE_LOCK",
    "_TOKENIZE_CACHE_MAX_TEXT_CHARS",
    "_disk_cache_key",
    "_get_cached_tokenize_result_detail",
    "_get_gliner",
    "_load_disk_cache",
    "_mark_detector_degraded",
    "_parse_escapes",
    "_predict_entities",
    "_predict_entities_many",
    "_save_disk_cache",
    "_store_tokenize_result",
    "_tokenize_cache_key",
    "begin_detection_turn",
    "cached_tokenize",
    "cached_tokenize_many",
    "clear_tokenize_cache",
    "detector_degraded",
    "detokenize",
    "preload_gliner",
    "tokenize",
    "turn_degraded",
    "turn_degraded_reason",
    "warn_detection_degraded",
]

# Dead code kept as a facade-only compat shim (carve-map risk 4): no callers
# remain anywhere; intentionally NOT carved into erebus/core/.
def _get_cached_tokenize_result(key: tuple, original_text: str | None = None) -> tuple[str, dict] | None:
    return _get_cached_tokenize_result_detail(key, original_text)[0]


# Mutable module state owned (and sometimes REBOUND) by the core modules.
# Resolved on every attribute read so facade-level reads stay live.
_LIVE_STATE_OWNERS = {
    "_TOKENIZE_CACHE": _cache_mod,
    "_TOKENIZE_CLEAN_CACHE": _cache_mod,
    "_DISK_CACHE": _cache_disk_mod,
    "_DISK_CLEAN_CACHE": _cache_disk_mod,
    "_DISK_CACHE_LOADED": _cache_disk_mod,
    "_DISK_CACHE_PATH": _cache_disk_mod,
    "_DISK_CACHE_DIRTY": _cache_disk_mod,
    "_DISK_CACHE_DIRTY_KEYS": _cache_disk_mod,
    "_DISK_CLEAN_CACHE_DIRTY_KEYS": _cache_disk_mod,
    "_last_degraded_warn": _state_mod,
}


def __getattr__(name: str):
    owner = _LIVE_STATE_OWNERS.get(name)
    if owner is not None:
        return getattr(owner, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
