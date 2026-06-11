"""Proxy message cache (v3 format) — text patches keyed by content+config hash.

Moved from erebus/proxy.py (specs/004-core-pii-boundary T028). Values are text
patches, not full chat items, so very large Codex histories can be skipped
without storing the whole history. Entries are never stored for a degraded
detection turn. Mutable module state (_MSG_CACHE, _MSG_CACHE_PATH, flags) is
owned HERE; erebus.proxy forwards reads/writes of every ``_MSG_CACHE*`` name to
this module during the migration — access the state via module attributes.
"""
from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..config import ensure_erebus_dir, secure_path
from ..perf import PerfTimer, log_perf_event
from .patterns import TOKEN_RE
from .state import turn_degraded

_MSG_CACHE_VERSION = 3  # bumped: invalidate entries that may have been stored during a degraded detection pass
_MSG_CACHE_MAX = 16_384
_MSG_CACHE_MAX_BYTES = 8 * 1024 * 1024
_MSG_CACHE_MAX_PATCH_CHARS = 16_384
_MSG_CACHE_MAX_PATCHES = 128
_MSG_CACHE_MAX_SPANS = 512
_MSG_CACHE_PATH = Path.home() / ".erebus" / "message_cache.json"
_MSG_CACHE: OrderedDict[str, dict[str, Any]] = OrderedDict()
_MSG_CACHE_LOADED = False
_MSG_CACHE_DIRTY = False
_MSG_CACHE_DIRTY_KEYS: set[str] = set()


def stable_json_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def stable_json_size(value: Any) -> int:
    try:
        return len(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    except (TypeError, ValueError):
        return 0


# (name, default, as_list) triples; hashing sorts keys, so build order is free.
_CATALOG_SIG_FIELDS = (
    ("enabled", False, False), ("enforce_known_values", True, False),
    ("source_names", [], True), ("connector_ids", [], True),
    ("name_mode", "balanced", False), ("allow_first_name", True, False),
    ("strict_near_identifiers", True, False), ("review_threshold", "medium", False))
_CONFIG_SIG_FIELDS = (
    ("sensitive_entities", [], True), ("allowed_names", [], True),
    ("mode", "balanced", False), ("blacklist", [], True), ("verifier", "", False),
    ("verifier_llm_model", "gemma3:1b", False), ("verifier_openai_pf_url", "", False))


def _signature_fields(obj, fields) -> dict[str, Any]:
    return {name: (list(getattr(obj, name, default) or []) if as_list else getattr(obj, name, default))
            for name, default, as_list in fields}

def repo_config_cache_signature(repo_config) -> dict[str, Any]:
    catalog_config = getattr(repo_config, "pii_catalog", None)
    signature = _signature_fields(repo_config, _CONFIG_SIG_FIELDS)
    signature["catalog"] = (None if catalog_config is None
                            else _signature_fields(catalog_config, _CATALOG_SIG_FIELDS))
    return signature


def message_cache_key(kind: str, item: Any, repo_config) -> str | None:
    try:
        return stable_json_hash({
            "version": _MSG_CACHE_VERSION,
            "kind": kind,
            "config": repo_config_cache_signature(repo_config),
            "item": item,
        })
    except (TypeError, ValueError):
        return None


def message_cache_file_is_too_large() -> bool:
    try:
        return _MSG_CACHE_PATH.stat().st_size > _MSG_CACHE_MAX_BYTES
    except OSError:
        return False


def drop_message_cache_file() -> None:
    try:
        _MSG_CACHE_PATH.unlink(missing_ok=True)
    except Exception:
        pass


def normalize_message_cache_patch(patch: Any) -> dict[str, Any] | None:
    if not isinstance(patch, dict):
        return None
    path = patch.get("path")
    if not isinstance(path, list) or not all(isinstance(part, (str, int)) for part in path):
        return None

    if "value" in patch:
        value = patch.get("value")
        if not isinstance(value, str) or len(value) > _MSG_CACHE_MAX_PATCH_CHARS:
            return None
        return {"path": list(path), "value": value}

    raw_spans = patch.get("spans")
    if not isinstance(raw_spans, list) or len(raw_spans) > _MSG_CACHE_MAX_SPANS:
        return None

    spans = []
    previous_end = 0
    for span in raw_spans:
        if not isinstance(span, list) or len(span) != 3:
            return None
        start, end, replacement = span
        if not isinstance(start, int) or not isinstance(end, int) or not isinstance(replacement, str):
            return None
        if start < previous_end or end <= start or not TOKEN_RE.fullmatch(replacement):
            return None
        spans.append([start, end, replacement])
        previous_end = end
    return {"path": list(path), "spans": spans}


def normalize_message_cache_entry(entry: Any) -> dict[str, Any] | None:
    if not isinstance(entry, dict):
        return None
    raw_patches = entry.get("patches", [])
    raw_tokens = entry.get("tokens", [])
    if (not isinstance(raw_patches, list) or not isinstance(raw_tokens, list)
            or len(raw_patches) > _MSG_CACHE_MAX_PATCHES):
        return None

    patches = []
    for patch in raw_patches:
        if (normalized_patch := normalize_message_cache_patch(patch)) is None:
            return None
        patches.append(normalized_patch)

    tokens = []
    for token in raw_tokens:
        if not isinstance(token, str) or not TOKEN_RE.fullmatch(token):
            return None
        tokens.append(token)

    normalized = {"patches": patches, "tokens": sorted(set(tokens))}
    try:
        if len(json.dumps(normalized).encode("utf-8")) > 128 * 1024:
            return None
    except Exception:
        return None
    return normalized


def load_message_cache() -> None:
    global _MSG_CACHE_LOADED
    if _MSG_CACHE_LOADED:
        return
    _MSG_CACHE_LOADED = True
    try:
        if not _MSG_CACHE_PATH.exists():
            return
        if message_cache_file_is_too_large():
            drop_message_cache_file()
            return
        data = json.loads(_MSG_CACHE_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("version") != _MSG_CACHE_VERSION:
            drop_message_cache_file()
            return
        entries = data.get("entries")
        if not isinstance(entries, dict):
            return
        for key, entry in list(entries.items())[-_MSG_CACHE_MAX:]:
            if isinstance(key, str) and (normalized := normalize_message_cache_entry(entry)) is not None:
                _MSG_CACHE[key] = normalized
    except Exception:
        pass


def save_message_cache() -> None:
    global _MSG_CACHE_DIRTY
    if not _MSG_CACHE_DIRTY:
        return
    try:
        ensure_erebus_dir()
        existing = {}
        if _MSG_CACHE_PATH.exists() and not message_cache_file_is_too_large():
            try:
                data = json.loads(_MSG_CACHE_PATH.read_text(encoding="utf-8"))
                if isinstance(data, dict) and data.get("version") == _MSG_CACHE_VERSION and isinstance(data.get("entries"), dict):  # noqa: E501
                    for key, entry in data["entries"].items():
                        if isinstance(key, str) and (normalized := normalize_message_cache_entry(entry)) is not None:
                            existing[key] = normalized
            except Exception:
                existing = {}
        elif _MSG_CACHE_PATH.exists():
            drop_message_cache_file()

        merged = dict(existing)
        for key in _MSG_CACHE_DIRTY_KEYS:
            if key in _MSG_CACHE:
                merged.pop(key, None)
                merged[key] = _MSG_CACHE[key]
        entries = dict(list(merged.items())[-_MSG_CACHE_MAX:])
        payload = {"version": _MSG_CACHE_VERSION, "entries": entries}
        while entries and len(json.dumps(payload).encode("utf-8")) > _MSG_CACHE_MAX_BYTES:
            entries.pop(next(iter(entries)))
            payload = {"version": _MSG_CACHE_VERSION, "entries": entries}

        tmp_path = _MSG_CACHE_PATH.with_suffix(_MSG_CACHE_PATH.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload), encoding="utf-8")
        tmp_path.replace(_MSG_CACHE_PATH)
        secure_path(_MSG_CACHE_PATH, 0o600)
        _MSG_CACHE_DIRTY_KEYS.clear()
        _MSG_CACHE_DIRTY = False
    except Exception:
        pass


def apply_text_span_patches(text: str, spans: list[list[Any]]) -> str:
    if not spans:
        return text
    chunks = []
    cursor = 0
    for start, end, replacement in spans:
        chunks.append(text[cursor:start])
        chunks.append(replacement)
        cursor = end
    chunks.append(text[cursor:])
    return "".join(chunks)


def collect_token_span_patch(original: str, sanitized: str, tokens: dict) -> dict[str, Any] | None:
    candidates = []
    for token, value in tokens.items():
        if (not isinstance(token, str) or not TOKEN_RE.fullmatch(token)
                or not isinstance(value, str) or not value or value == token):
            continue
        start = 0
        while (idx := original.find(value, start)) >= 0:
            candidates.append((idx, idx + len(value), token))
            start = idx + len(value)
    if not candidates:
        return None

    candidates.sort(key=lambda item: (item[0], -(item[1] - item[0])))
    spans = []
    cursor = 0
    for start, end, token in candidates:
        if start < cursor:
            continue
        spans.append([start, end, token])
        cursor = end
        if len(spans) > _MSG_CACHE_MAX_SPANS:
            return None
    if apply_text_span_patches(original, spans) != sanitized:
        return None
    return {"spans": spans}


def collect_text_patches(original: Any, sanitized: Any, tokens: dict, path: tuple = ()) -> list[dict[str, Any]] | None:
    if isinstance(original, str) and isinstance(sanitized, str):
        if original == sanitized:
            return []
        if len(sanitized) <= _MSG_CACHE_MAX_PATCH_CHARS:
            return [{"path": list(path), "value": sanitized}]
        span_patch = collect_token_span_patch(original, sanitized, tokens)
        return None if span_patch is None else [{"path": list(path), **span_patch}]

    if isinstance(original, list) and isinstance(sanitized, list) and len(original) == len(sanitized):
        pairs = list(enumerate(zip(original, sanitized)))  # noqa: B905
    elif isinstance(original, dict) and isinstance(sanitized, dict):
        pairs = [(key, (before, sanitized[key])) for key, before in original.items() if key in sanitized]
    else:
        return []
    patches = []
    for key, (before, after) in pairs:
        nested = collect_text_patches(before, after, tokens, path + (key,))  # noqa: RUF005
        if nested is None:
            return None
        patches.extend(nested)
    return patches


def token_keys_from_patches(patches: list[dict[str, Any]], tokens: dict) -> list[str]:
    keys = set(tokens.keys())
    for patch in patches:
        replacement = patch.get("value")
        if isinstance(replacement, str):
            keys.update(match.group(0) for match in TOKEN_RE.finditer(replacement))
        for span in patch.get("spans", []):
            if isinstance(span, list) and len(span) == 3 and isinstance(span[2], str):
                keys.add(span[2])
    return sorted(keys)


def _log_store(timer: PerfTimer, text_chars: int, token_count: int, **fields: Any) -> None:
    log_perf_event("message_cache_store", **timer.finish(), text_count=1,
                   text_chars=text_chars, token_count=token_count, **fields)


def store_message_cache_entry(key: str | None, original: Any, sanitized: Any, tokens: dict, save: bool = False) -> None:
    timer = PerfTimer()
    text_chars = stable_json_size(original)
    if turn_degraded():
        # A degraded pass may have missed NER-class PII; caching its patches (or a
        # "no changes" entry) would replay the under-filtered result on every later turn.
        _log_store(timer, text_chars, len(tokens), cache_result="skip",
                   reason="degraded", cache_key=(key or "")[:12])
        return
    if not key:
        _log_store(timer, text_chars, len(tokens), cache_result="skip", reason="no_key")
        return
    patches = collect_text_patches(original, sanitized, tokens)
    if patches is None:
        _log_store(timer, text_chars, len(tokens), cache_result="skip",
                   reason="uncacheable_patch", cache_key=key[:12])
        return
    entry = normalize_message_cache_entry(
        {"patches": patches, "tokens": token_keys_from_patches(patches, tokens)})
    if entry is None:
        _log_store(timer, text_chars, len(tokens), cache_result="skip",
                   reason="normalize_failed", cache_key=key[:12])
        return

    global _MSG_CACHE_DIRTY
    _MSG_CACHE[key] = entry
    _MSG_CACHE.move_to_end(key)
    while len(_MSG_CACHE) > _MSG_CACHE_MAX:
        _MSG_CACHE.popitem(last=False)
    _MSG_CACHE_DIRTY_KEYS.add(key)
    _MSG_CACHE_DIRTY = True
    if save:
        save_message_cache()
    _log_store(timer, text_chars, len(tokens), cache_result="stored", cache_key=key[:12],
               patch_count=len(entry.get("patches", [])),
               cached_token_count=len(entry.get("tokens", [])))


def get_path_value(root, path: tuple):
    target = root
    for key in path:
        target = target[key]
    return target


def _set_path_value(root, path: tuple, replacement):
    if not path:
        return replacement
    target = root
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return root


def _log_apply(timer: PerfTimer, kind: str, text_chars: int, **fields: Any) -> None:
    log_perf_event("message_cache", **timer.finish(), kind=kind, text_count=1,
                   text_chars=text_chars, **fields)


def apply_message_cache_entry(key: str | None, item: Any, collected: dict, kind: str = "message",
                              record_tokens: Callable[[list[str], dict], None] | None = None,
                              retokenize_item: Callable[[Any], dict] | None = None) -> bool:
    """Reapply a cached entry's patches to `item`; True on a hit. The caller's
    `record_tokens(token_keys, collected)` resolves the entry's token keys into
    `collected` (proxy wires TOKEN_MAP recovery; Boundary wires the DB later).

    `retokenize_item(item) -> inserted_tokens` re-runs the known-value pre-scan
    over EVERY model-bound text field of the applied item. This must run on the
    whole item, not per-patch: a message first seen on a non-degraded turn that
    the detector simply MISSED is stored as a ZERO-patch entry (original ==
    sanitized), so a per-patch hook would never visit any field and the raw
    value would replay forever once it became known. The cache key carries no
    known-value generation, so retokenizing on the way out is what keeps a
    replay from leaking a now-known value (the Boundary result cache does the
    same on its hits)."""
    timer = PerfTimer()
    text_chars = stable_json_size(item)
    if not key:
        _log_apply(timer, kind, text_chars, cache_result="skip", reason="no_key")
        return False
    load_message_cache()
    entry = _MSG_CACHE.get(key)
    if entry is None:
        _log_apply(timer, kind, text_chars, cache_result="miss", reason="not_found", cache_key=key[:12])
        return False
    _MSG_CACHE.move_to_end(key)
    for patch in entry.get("patches", []):
        path = tuple(patch["path"])
        if "value" in patch:
            _set_path_value(item, path, patch["value"])
            continue
        current = get_path_value(item, path)
        if not isinstance(current, str):
            _log_apply(timer, kind, text_chars, cache_result="miss", reason="patch_type_mismatch",
                       cache_key=key[:12], patch_count=len(entry.get("patches", [])))
            return False
        _set_path_value(item, path, apply_text_span_patches(current, patch.get("spans", [])))
    if retokenize_item is not None:
        inserted = retokenize_item(item)
        if inserted:
            collected.update(inserted)
    if record_tokens is not None:
        record_tokens(entry.get("tokens", []), collected)
    _log_apply(timer, kind, text_chars, cache_result="hit", cache_key=key[:12],
               patch_count=len(entry.get("patches", [])),
               cached_token_count=len(entry.get("tokens", [])))
    return True
