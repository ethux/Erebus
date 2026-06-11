"""Shared per-process session state for the Claude shim.

One lazy module-level :class:`~erebus.core.Boundary` is the shim's PII gate
(``source='claude-shim'``). ``TOKEN_MAP`` is a compatibility mirror of the
boundary's known-value view, kept only because tests and the interactive PTY
path still read/set it (specs/004-core-pii-boundary/contracts/compat-surface.md);
the mirror wrappers below honor entries placed in it from outside through the
Boundary's public compat methods and are slated for removal with TOKEN_MAP.
"""
from __future__ import annotations

import os
import threading
import time
import uuid

from ..audit.logger import log_event
from ..config import load_repo_config
from ..core import Boundary

# Session state
SESSION_ID = str(uuid.uuid4())[:8]
CWD = os.getcwd()
REPO_CONFIG = load_repo_config(CWD)

# In-memory mirror of the known-value store, seeded from its legacy JSON
# export (no DB open at import).
TOKEN_MAP: dict = Boundary.load_legacy_export()

# Known-value plumbing: one lazy module-level Boundary shared by both pipe
# threads. sqlite3 here reports threadsafety=1 (connections must not cross
# threads without external locking), so every boundary/DB-touching operation
# serializes on _KV_LOCK. Reentrant: recovery persists internally.
_BOUNDARY: Boundary | None = None  # lazy facade, created on first tokenize/detokenize
_KV_LOCK = threading.RLock()


def get_boundary() -> Boundary:
    """Lazy module-level Boundary: the shim's only PII tokenize/detokenize gate."""
    global _BOUNDARY
    with _KV_LOCK:
        if _BOUNDARY is None:
            _BOUNDARY = Boundary.from_config(REPO_CONFIG, CWD, source="claude-shim")
        return _BOUNDARY


def _persist_mirror():
    """Ingest TOKEN_MAP into the known-value store, then export the legacy JSON
    with 0600 perms + age-based rotation (Boundary.persist_mirror)."""
    with _KV_LOCK:
        get_boundary().persist_mirror(TOKEN_MAP)


def _sync_mirror():
    """Merge persisted tokens (legacy JSON + DB view) so old context tokens resolve."""
    with _KV_LOCK:
        before = set(TOKEN_MAP)
        stale = get_boundary().sync_view_into(TOKEN_MAP)
        if stale - before:
            try:  # the store is ahead of its legacy JSON export — re-sync it
                Boundary.export_mirror(TOKEN_MAP)
            except Exception:
                pass


def _safe_log_event(*args, **kwargs) -> None:
    try:
        log_event(*args, **kwargs)
    except Exception:
        pass


# Turn timing: track when the last outgoing message was sent so we can
# compute the full round-trip time when the response arrives.
_last_outgoing_ts: float = 0.0
_last_turn_type: str = "chat"  # "chat" or "tool"


def mark_outgoing_sent(turn_type: str) -> None:
    """Record the send time + turn type of the outgoing message just piped."""
    global _last_outgoing_ts, _last_turn_type
    _last_outgoing_ts = time.perf_counter()
    _last_turn_type = turn_type


def take_turn_timing() -> tuple[float, str] | None:
    """(turn_latency_ms, turn_type) for the pending turn, consumed once; else None."""
    global _last_outgoing_ts
    if _last_outgoing_ts <= 0:
        return None
    turn_ms = round((time.perf_counter() - _last_outgoing_ts) * 1000, 1)
    _last_outgoing_ts = 0.0
    return turn_ms, _last_turn_type
