"""Daemon self-supervision: the watchdogs that keep exactly one healthy
GLiNER daemon alive, and the memory hygiene that keeps it small.

Split out of ``daemon.py`` (module line cap); the daemon starts these as
threads and passes its own paths/identity in, so this module stays free of
daemon state. Each guard exists because its failure mode happened live:

  * parent-death watchdog — redeploy cycles orphaned model-loaded daemons
    (~1 GB each) that accumulated for days (2026-06-11).
  * socket-path watchdog — a stop_daemon bug unlinked a live daemon's socket,
    leaving an unreachable zombie that blocked spawns via the lock
    (2026-06-10).
  * memory ceiling + accelerator-cache release — the torch MPS allocator
    retained every peak allocation; varied-shape inference grew one daemon to
    30 GB in a day (2026-06-12).
"""
from __future__ import annotations

import os
import sys
import time

PARENT_PID_ENV = "EREBUS_DAEMON_PARENT_PID"
MEMORY_CEILING_ENV = "EREBUS_DAEMON_MAX_FOOTPRINT_MB"
_DEFAULT_MEMORY_CEILING_MB = 8192


# ── parent-death guard ─────────────────────────────────────────────────────────

def daemon_child_env() -> dict[str, str]:
    """Environment for a daemon spawned by ensure_daemon()."""
    env = os.environ.copy()
    env[PARENT_PID_ENV] = str(os.getpid())
    return env


def expected_parent_pid() -> int | None:
    raw = os.environ.get(PARENT_PID_ENV)
    try:
        pid = int(raw) if raw else os.getppid()
    except ValueError:
        pid = os.getppid()
    return pid if pid > 1 else None


def parent_process_gone(expected: int) -> bool:
    """True once a spawned daemon is no longer owned by its launcher."""
    if expected <= 1:
        return False
    if os.getppid() != expected:
        return True
    try:
        os.kill(expected, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False


def parent_process_watchdog() -> None:
    """Exit once a daemon spawned by ensure_daemon() becomes orphaned.

    Spawned daemons inherit the launcher's PID; direct shell launches use their
    initial PPID. If a redeploy/restart kills that parent, this process is
    reparented while keeping the model, socket, and lock alive. Exiting here
    releases that memory and lets the replacement service generation own a
    fresh daemon. Daemons launched directly by launchd/systemd start with
    PPID=1 and are left alone.
    """
    parent_pid = expected_parent_pid()
    if parent_pid is None:
        return
    while True:
        time.sleep(15)
        if parent_process_gone(parent_pid):
            print("GLiNER daemon parent exited; releasing model and singleton lock.",
                  file=sys.stderr, flush=True)
            os._exit(0)


# ── socket-path guard ──────────────────────────────────────────────────────────

def socket_path_watchdog(socket_path: str) -> None:
    """Exit if our socket path vanishes from disk.

    Clients find the daemon by socket path; if something deletes it, this
    process is unreachable forever yet still blocks fresh daemons via the
    singleton lock — every request then burns the full spawn wait and
    degrades. Exiting releases the lock so the next ensure_daemon() can start
    a healthy instance.
    """
    misses = 0
    while True:
        time.sleep(15)
        misses = misses + 1 if not os.path.exists(socket_path) else 0
        if misses >= 2:
            print("GLiNER daemon socket path vanished; exiting so a fresh "
                  "daemon can bind.", file=sys.stderr, flush=True)
            os._exit(1)


# ── memory hygiene ─────────────────────────────────────────────────────────────

def release_accelerator_cache() -> None:
    """Return cached accelerator memory to the OS after each request.

    The torch MPS caching allocator retains every peak allocation for reuse,
    but varied input shapes mean blocks are rarely reused — the footprint only
    grows (observed live: 30 GB after ~20h / 256 requests of mixed traffic;
    measured: 5 varied calls grew the allocator 1.1->2.7 GB, empty_cache
    released it and steady state stayed flat at ~1.5 GB). Costs ~1ms per
    request, which is noise next to inference itself."""
    try:
        import torch
        if torch.backends.mps.is_available():
            torch.mps.empty_cache()
        elif torch.cuda.is_available():
            torch.cuda.empty_cache()
    except Exception:
        pass


def memory_ceiling_mb() -> int:
    """Self-recycle threshold; override via EREBUS_DAEMON_MAX_FOOTPRINT_MB."""
    raw = os.environ.get(MEMORY_CEILING_ENV)
    try:
        return max(1024, int(raw)) if raw else _DEFAULT_MEMORY_CEILING_MB
    except ValueError:
        return _DEFAULT_MEMORY_CEILING_MB


def process_peak_footprint_mb() -> float:
    """Peak resident size of this process in MB (ru_maxrss: bytes on macOS,
    KB on Linux). Peak is the right trigger: page compression shrinks current
    RSS while the process still owns the memory."""
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def memory_ceiling_watchdog() -> None:
    """Self-recycle when this daemon's peak footprint crosses the ceiling.

    Backstop for any allocator or library leak the per-request cache release
    misses: exiting releases everything and the next ensure_daemon() spawns a
    fresh daemon — one ~15s model reload, paid rarely, instead of the machine
    sliding into compression/swap pressure."""
    ceiling = memory_ceiling_mb()
    while True:
        time.sleep(60)
        used = process_peak_footprint_mb()
        if used > ceiling:
            print(f"GLiNER daemon peak footprint {used:.0f}MB exceeds ceiling "
                  f"{ceiling}MB; exiting so a fresh daemon replaces it.",
                  file=sys.stderr, flush=True)
            os._exit(0)
