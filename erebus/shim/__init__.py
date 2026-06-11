"""
Claude Code binary shim — main entry point.

Sits between the Claude Code VSCode extension and the real Claude binary.
Configure in VSCode settings:
  "claudeCode.claudeProcessWrapper": "/path/to/erebus"

Flow:
  VSCode → shim (stdin) → [Boundary.to_model] → Claude binary (stdin)
  Claude binary (stdout) → [Boundary.from_model] → shim (stdout) → VSCode

Kill switch:
  EREBUS_BYPASS=1  — disable ALL filtering, pass through directly

Package layout (specs/004-core-pii-boundary):
  _state.py    session state, the module-level Boundary, TOKEN_MAP compat mirror
  outgoing.py  process_outgoing (world → model)
  incoming.py  process_incoming (model → world), usage/LOC logging
  launcher.py  main(), run modes, passthrough exec, child lifecycle

This __init__ re-exports every name the entry point and tests use
(contracts/compat-surface.md); the implementation lives in the submodules.
"""
import os  # noqa: F401  — re-exported: tests patch shim.os.execv

from ..audit.logger import init_db
from ._state import (
    CWD,
    REPO_CONFIG,
    SESSION_ID,
    TOKEN_MAP,
    _persist_mirror,
    _sync_mirror,
    get_boundary,
)
from .incoming import (
    _PENDING_WRITE_PATHS,
    _detokenize_completed_writes,
    _detokenize_file,
    _log_usage_if_present,
    _track_pending_writes,
    process_incoming,
)
from .launcher import (
    _kill_child,
    _run_interactive,
    _run_piped,
    _watch_parent,
    main,
    pipe_stream,
    should_passthrough_claude_command,
)
from .outgoing import process_outgoing

__all__ = [
    "CWD",
    "REPO_CONFIG",
    "SESSION_ID",
    "TOKEN_MAP",
    "_PENDING_WRITE_PATHS",
    "_detokenize_completed_writes",
    "_detokenize_file",
    "_kill_child",
    "_log_usage_if_present",
    "_persist_mirror",
    "_run_interactive",
    "_run_piped",
    "_sync_mirror",
    "_track_pending_writes",
    "_watch_parent",
    "get_boundary",
    "init_db",
    "main",
    "pipe_stream",
    "process_incoming",
    "process_outgoing",
    "should_passthrough_claude_command",
]
