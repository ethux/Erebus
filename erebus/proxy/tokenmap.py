"""Boundary wiring + the proxy's TOKEN_MAP compatibility mirror.

The proxy routes all tokenization through ONE app-level Boundary
(specs/004-core-pii-boundary T030). ``TOKEN_MAP`` stays the passive in-memory
mirror of the Known-Value view + legacy JSON so the existing detokenize paths
(which also resolve process-local entries seeded by tests) keep working during
the migration. Every store touch goes through public Boundary methods
(sync_view_into / persist_mirror / recover_tokens / the legacy-export
helpers), so this package never opens the Known-Value DB itself.
"""
from __future__ import annotations

import os
import re
import time

from ..config import load_repo_config
from ..core import Boundary
from ..core import _set_path_value as _core_set_path_value
from ..core import message_cache as _message_cache
from .payload import collect_text_paths as _collect_text_paths

# Deliberate read-only copy of the canonical token shape (kept local so the
# adapter does not reach into core submodules for a regex).
_TOKEN_RE = re.compile(r"\[(?:[A-Z_]+_\d+_[0-9a-f]{6,}|CATALOG_[A-Z0-9_]+_[0-9a-f]{6,})\]")

TOKEN_MAP: dict = {}

_BOUNDARY: Boundary | None = None

# A streamed token that resolves nowhere stays in the buffer for the rest of
# the response; without this, every later SSE delta re-ran the store/JSON
# sync and the recovery lookup for it. Misses are retried after the window.
_RESPONSE_MISS_RETRY_S = 60.0
_RESPONSE_MISSES: dict[str, float] = {}  # token -> time.monotonic() deadline


def get_boundary(repo_config=None) -> Boundary | None:
    """One Boundary per proxy process; module-level fallback for tests.

    The aiohttp app constructs it once from its repo_config; helper calls with
    a different config object (tests) rebuild it so detector/catalog settings
    always match the caller's config.
    """
    global _BOUNDARY
    if repo_config is None:
        if _BOUNDARY is not None:
            return _BOUNDARY
        try:
            repo_config = load_repo_config()
        except Exception:
            return None
    if _BOUNDARY is None or _BOUNDARY.repo_config is not repo_config:
        _BOUNDARY = Boundary.from_config(repo_config, os.getcwd(), source="proxy")
    return _BOUNDARY


def reload_token_map() -> None:
    """(Re)load the persisted map in place; the package __init__ calls this on
    every (re)import, mirroring the old module-level load semantics."""
    fresh = Boundary.load_legacy_export()
    TOKEN_MAP.clear()
    TOKEN_MAP.update(fresh)


def _sync_mirror() -> set:
    """Merge the known-value view + legacy JSON into TOKEN_MAP (memory wins).

    Returns the view tokens the legacy JSON file does not hold, so callers
    can tell whether a persist pass is needed to re-sync the exported file.
    """
    if (boundary := get_boundary()) is not None:
        return boundary.sync_view_into(TOKEN_MAP)
    merged = Boundary.load_legacy_export()
    merged.update(TOKEN_MAP)
    TOKEN_MAP.clear()
    TOKEN_MAP.update(merged)
    return set()


def _persist_mirror() -> None:
    """Ingest new pairs into the known-value store, then write the legacy JSON.

    The JSON write keeps 0600 perms + age-based rotation (Boundary.export_mirror
    -> config.save_token_map) and covers degraded-DB sessions, where ingest
    only buffers transient pairs.
    """
    if (boundary := get_boundary()) is not None:
        boundary.persist_mirror(TOKEN_MAP)
        return
    _sync_mirror()
    Boundary.export_mirror(TOKEN_MAP)


def _resolve_missing_tokens(unresolved: set) -> dict:
    """Resolve unknown tokens via the Boundary (includes audit-log recovery)."""
    if not unresolved:
        return {}
    if (boundary := get_boundary()) is None:
        return Boundary.audit_lookup(unresolved)
    return boundary.recover_tokens(unresolved)


def record_cached_token_keys(token_keys: list[str], collected: dict) -> bool:
    """Resolve a cached entry's token keys into `collected`.

    Returns False (and records nothing) when a key resolves nowhere: the
    message cache then evicts the entry and re-tokenizes the item instead of
    replaying a token whose value is lost."""
    if not token_keys:
        return True
    unresolved = {token for token in token_keys if token not in TOKEN_MAP}
    if unresolved:
        _sync_mirror()
        unresolved = {token for token in unresolved if token not in TOKEN_MAP}
    recovered = _resolve_missing_tokens(unresolved)
    if recovered:
        TOKEN_MAP.update(recovered)
        _persist_mirror()
    if any(not TOKEN_MAP.get(token) for token in token_keys):
        return False
    for token in token_keys:
        collected[token] = TOKEN_MAP[token]
    return True


def _retokenize_cached_item(boundary, item) -> dict:
    """Re-run the known-value pre-scan over EVERY model-bound text field of a
    cache-applied item. Walks the whole item (not just patched fields) so a
    zero-patch entry — a message the detector first MISSED — cannot replay a
    now-known value raw. Returns the tokens it inserted."""
    inserted: dict = {}
    for path, text in _collect_text_paths(item):
        new_text, toks = boundary.retokenize_known(text)
        if new_text != text:
            _core_set_path_value(item, path, new_text)
        if toks:
            TOKEN_MAP.update(toks)  # keep the mirror able to detokenize them
            inserted.update(toks)
    return inserted


def apply_message_cache_entry(key: str | None, item, collected: dict, kind: str = "message") -> bool:
    """Compat wrapper: core mechanics + the proxy's TOKEN_MAP token recovery.

    Passes the live Boundary's item-level retokenizer so a cached entry can
    never replay a value that has since become known (it would otherwise reach
    the model raw — the cache key carries no known-value generation)."""
    boundary = get_boundary()
    return _message_cache.apply_message_cache_entry(
        key, item, collected, kind, record_tokens=record_cached_token_keys,
        retokenize_item=(lambda it: _retokenize_cached_item(boundary, it))
        if boundary is not None else None)


def patch_tokens_for(item, item_tokens: dict) -> dict:
    """``item_tokens`` plus the mirror's value for every OTHER token in the
    sanitized item's text, so the message cache can express a large item as
    exact spans. Pre-scan replacements and result-cache hits reuse tokens
    minted earlier, which are not in the item's NEW tokens; without their
    values a >16 KB tool output could never be cached and went back through
    the detector on every turn (1981 of 2466 misses live, 2026-09-06)."""
    present: set[str] = set()
    for _path, text in _collect_text_paths(item):
        present.update(_TOKEN_RE.findall(text))
    resolved = dict(item_tokens)
    for token in present - resolved.keys():
        if (value := TOKEN_MAP.get(token)):
            resolved[token] = value
    return resolved


def _record_new_tokens(tokens: dict, collected: dict) -> None:
    if not tokens:
        return
    TOKEN_MAP.update(tokens)
    collected.update(tokens)


def _ensure_response_tokens_loaded(text: str) -> bool:
    """Load or recover token mappings needed to detokenize a response fragment.

    Only a token the mirror does not hold triggers the store/JSON sync and the
    recovery path; this runs per SSE delta over the whole buffer, so a
    resolvable stream must stay a pure in-memory check."""
    needed = {match.group(0) for match in _TOKEN_RE.finditer(text)}
    missing = needed - TOKEN_MAP.keys()
    now = time.monotonic()
    retry = {token for token in missing if _RESPONSE_MISSES.get(token, 0.0) <= now}
    if not retry:
        return bool(TOKEN_MAP)
    json_stale = _sync_mirror()
    recovered = _resolve_missing_tokens(retry - TOKEN_MAP.keys())
    if recovered:
        TOKEN_MAP.update(recovered)
    if recovered or json_stale & needed:
        # Persist on recovery, and re-export when the legacy JSON is missing
        # tokens this response needs (e.g. it was age-rotated; the DB has them).
        _persist_mirror()
    for token in retry:
        if token not in TOKEN_MAP:
            _RESPONSE_MISSES[token] = now + _RESPONSE_MISS_RETRY_S
    return bool(TOKEN_MAP)


_DETOKENIZE_MAX_ROUNDS = 10  # a value may itself hold a token (chain); bounded like core detokenize


def _detokenize_text(text: str) -> str:
    """Replace tokens with real values in response text.

    Scans the TEXT for token shapes and resolves only those, so the cost
    follows the text length rather than the size of the token store (13k
    live entries; the previous store-wide probe cost ~45 ms per 10 KB of
    streamed buffer on every SSE delta)."""
    for _ in range(_DETOKENIZE_MAX_ROUNDS):
        needed = {match.group(0) for match in _TOKEN_RE.finditer(text)}
        if not needed:
            return text
        _ensure_response_tokens_loaded(text)
        present = [token for token in needed if TOKEN_MAP.get(token)]
        if not present:
            return text
        for token in sorted(present, key=len, reverse=True):
            text = text.replace(token, TOKEN_MAP[token])
    return text


def _detokenize_payload(value):
    """Recursively detokenize strings in a decoded JSON payload."""
    if isinstance(value, str):
        return _detokenize_text(value)
    if isinstance(value, list):
        return [_detokenize_payload(item) for item in value]
    if isinstance(value, dict):
        return {k: _detokenize_payload(v) for k, v in value.items()}
    return value
