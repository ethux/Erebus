"""Disk-backed tokenize cache (v5 format) — entries + clean fingerprints.

Leaf module. Small token-bearing results survive process restarts; large clean
contexts persist as fingerprints only, keeping old-chat cache hits cheap
without holding or writing giant prompt strings.

Mutable module state (_DISK_CACHE, _DISK_CLEAN_CACHE, dirty flags) is REBOUND
by _save_disk_cache(), so sibling modules must always access it as
``cache_disk.<attr>`` module attributes — never via ``from`` imports — and use
mark_dirty()/reset() for the flag rebinding sites.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

_DISK_CACHE_PATH = Path.home() / ".erebus" / "tokenize_cache.json"
_DISK_CACHE_VERSION = 5  # bumped: invalidate token-bearing entries that may have been stored during a degraded pass
_DISK_CACHE_MAX_ENTRIES = 1024
_DISK_CLEAN_CACHE_MAX_ENTRIES = 4096
_DISK_CACHE_MAX_BYTES = 2 * 1024 * 1024
_DISK_CACHE_MAX_TEXT_CHARS = 16_384
_DISK_CACHE_MAX_TOKENS = 128
_DISK_CACHE_MAX_ENTRY_BYTES = 64 * 1024
_DISK_CACHE: dict[str, tuple[str, dict]] = {}
_DISK_CLEAN_CACHE: set[str] = set()
_DISK_CACHE_DIRTY = False
_DISK_CACHE_DIRTY_KEYS: set[str] = set()
_DISK_CLEAN_CACHE_DIRTY_KEYS: set[str] = set()
_DISK_CACHE_LOADED = False


def mark_dirty() -> None:
    """Flag the disk cache for persistence (rebinding site for cache.py)."""
    global _DISK_CACHE_DIRTY
    _DISK_CACHE_DIRTY = True


def reset() -> None:
    """Clear all disk-cache state and drop the cache file (rebinding site)."""
    global _DISK_CACHE_DIRTY, _DISK_CACHE_LOADED
    _DISK_CACHE.clear()
    _DISK_CLEAN_CACHE.clear()
    _DISK_CACHE_DIRTY_KEYS.clear()
    _DISK_CLEAN_CACHE_DIRTY_KEYS.clear()
    _DISK_CACHE_DIRTY = False
    _DISK_CACHE_LOADED = False
    try:
        _DISK_CACHE_PATH.unlink(missing_ok=True)
    except Exception:
        pass


def _disk_cache_key(key: tuple) -> str:
    return hashlib.sha256(repr(key).encode()).hexdigest()


def _disk_cache_file_is_too_large() -> bool:
    try:
        return _DISK_CACHE_PATH.stat().st_size > _DISK_CACHE_MAX_BYTES
    except OSError:
        return False


def _drop_disk_cache_file() -> None:
    try:
        _DISK_CACHE_PATH.unlink(missing_ok=True)
    except Exception:
        pass


def _can_persist_tokenize_result(sanitized: str, tokens: dict) -> bool:
    if not tokens:
        return False
    if len(sanitized) > _DISK_CACHE_MAX_TEXT_CHARS:
        return False
    if len(tokens) > _DISK_CACHE_MAX_TOKENS:
        return False
    try:
        size = len(json.dumps([sanitized, tokens]).encode("utf-8"))
    except Exception:
        return False
    return size <= _DISK_CACHE_MAX_ENTRY_BYTES


def _load_disk_cache():
    global _DISK_CACHE, _DISK_CLEAN_CACHE, _DISK_CACHE_LOADED
    if _DISK_CACHE_LOADED:
        return
    _DISK_CACHE_LOADED = True
    try:
        if _DISK_CACHE_PATH.exists():
            if _disk_cache_file_is_too_large():
                _drop_disk_cache_file()
                return
            data = json.loads(_DISK_CACHE_PATH.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or data.get("version") != _DISK_CACHE_VERSION:
                _drop_disk_cache_file()
                return
            if isinstance(data.get("entries"), dict):
                for k, v in data["entries"].items():
                    if isinstance(v, list) and len(v) == 2:
                        sanitized, tokens = v[0], v[1]
                        if isinstance(sanitized, str) and isinstance(tokens, dict):  # noqa: SIM102
                            if _can_persist_tokenize_result(sanitized, tokens):
                                _DISK_CACHE[k] = (sanitized, tokens)
            if isinstance(data.get("clean"), list):
                for k in data["clean"]:
                    if isinstance(k, str):
                        _DISK_CLEAN_CACHE.add(k)
    except Exception:
        pass


def _save_disk_cache():
    global _DISK_CACHE, _DISK_CLEAN_CACHE, _DISK_CACHE_DIRTY, _DISK_CACHE_DIRTY_KEYS
    if not _DISK_CACHE_DIRTY:
        return
    try:
        os.makedirs(_DISK_CACHE_PATH.parent, exist_ok=True)
        existing = {}
        existing_clean: list[str] = []
        if _DISK_CACHE_PATH.exists() and not _disk_cache_file_is_too_large():
            try:
                data = json.loads(_DISK_CACHE_PATH.read_text(encoding="utf-8"))
                if (
                    isinstance(data, dict)
                    and data.get("version") == _DISK_CACHE_VERSION
                    and isinstance(data.get("entries"), dict)
                ):
                    for key, value in data["entries"].items():
                        if isinstance(value, list) and len(value) == 2:
                            sanitized, tokens = value[0], value[1]
                            if isinstance(sanitized, str) and isinstance(tokens, dict):  # noqa: SIM102
                                if _can_persist_tokenize_result(sanitized, tokens):
                                    existing[key] = value
                    if isinstance(data.get("clean"), list):
                        existing_clean = [key for key in data["clean"] if isinstance(key, str)]
            except Exception:
                existing = {}
                existing_clean = []
        elif _DISK_CACHE_PATH.exists():
            _drop_disk_cache_file()

        merged = dict(existing)
        for key in _DISK_CACHE_DIRTY_KEYS:
            if key in _DISK_CACHE:
                merged.pop(key, None)
                merged[key] = _DISK_CACHE[key]

        entries = dict(list(merged.items())[-_DISK_CACHE_MAX_ENTRIES:])
        clean = list(dict.fromkeys(existing_clean + list(_DISK_CLEAN_CACHE)))[-_DISK_CLEAN_CACHE_MAX_ENTRIES:]
        payload = {"version": _DISK_CACHE_VERSION, "entries": entries, "clean": clean}
        while entries and len(json.dumps(payload).encode("utf-8")) > _DISK_CACHE_MAX_BYTES:
            entries.pop(next(iter(entries)))
            payload = {"version": _DISK_CACHE_VERSION, "entries": entries, "clean": clean}
        tmp_path = _DISK_CACHE_PATH.with_suffix(_DISK_CACHE_PATH.suffix + ".tmp")
        tmp_path.write_text(json.dumps(payload), encoding="utf-8")
        tmp_path.replace(_DISK_CACHE_PATH)
        from ..config import secure_path
        secure_path(_DISK_CACHE_PATH.parent, 0o700)
        secure_path(_DISK_CACHE_PATH, 0o600)
        _DISK_CACHE = entries
        _DISK_CLEAN_CACHE = set(clean)
        _DISK_CACHE_DIRTY_KEYS.clear()
        _DISK_CLEAN_CACHE_DIRTY_KEYS.clear()
        _DISK_CACHE_DIRTY = False
    except Exception:
        pass
