"""Process plumbing for the Claude shim: argv handling, passthrough exec,
piped/interactive run modes, child lifecycle (signals, atexit, watchdog).

No PII logic lives here — outgoing/incoming piping delegates to
shim.outgoing.process_outgoing / shim.incoming.process_incoming, which cross
the Boundary facade.
"""
from __future__ import annotations

import atexit
import os
import signal
import subprocess
import sys
import threading
import time

from ..audit.logger import init_db
from ..config import get_real_claude_binary
from ..filter import detokenize
from ._state import CWD, REPO_CONFIG, SESSION_ID, TOKEN_MAP, _safe_log_event
from .incoming import process_incoming
from .outgoing import process_outgoing

_PASSTHROUGH_CLAUDE_COMMANDS = {
    "auth",
    "config",
    "doctor",
    "help",
    "login",
    "logout",
    "mcp",
    "update",
    "version",
}
_PASSTHROUGH_CLAUDE_FLAGS = {"--help", "-h", "--version", "-v", "-V"}
_CHAT_CLAUDE_FLAGS = {
    "--continue",
    "--print",
    "--resume",
    "--replay-user-messages",
    "-c",
    "-p",
}


def should_passthrough_claude_command(claude_args: list[str]) -> bool:
    """Return True for Claude utility commands that do not carry chat content."""
    args = list(claude_args[1:])
    if not args:
        return False

    if any(arg in _CHAT_CLAUDE_FLAGS for arg in args):
        return False

    if all(arg in _PASSTHROUGH_CLAUDE_FLAGS for arg in args):
        return True

    for arg in args:
        if arg == "--":
            return False
        if arg.startswith("-"):
            continue
        return arg in _PASSTHROUGH_CLAUDE_COMMANDS

    return False


def pipe_stream(source, dest, processor, close_dest_on_eof=False):
    """Read lines from source, process, write to dest.

    When close_dest_on_eof is set, dest is closed once source reaches EOF —
    this is how we propagate VSCode closing our stdin to the claude child,
    so it can shut down cleanly instead of hanging on a read.
    """
    try:
        for line in source:
            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="replace")
            processed = processor(line)
            if isinstance(processed, str):
                processed = processed.encode("utf-8")
            # Handle both text streams (sys.stdout has .buffer) and
            # binary streams (proc.stdin is already a BufferedWriter)
            if hasattr(dest, 'buffer'):
                dest.buffer.write(processed)
                dest.buffer.flush()
            else:
                dest.write(processed)
                dest.flush()
    except (BrokenPipeError, OSError):
        pass  # destination closed — nothing we can do, just stop piping
    except Exception as e:
        try:
            _safe_log_event(SESSION_ID, event_type="pipe_error",
                            metadata={"error": str(e)})
        except Exception:
            pass
    finally:
        if close_dest_on_eof:
            try:
                dest.close()
            except Exception:
                pass


def main():
    # When called via claudeProcessWrapper, VSCode passes the original binary
    # as argv[1]: wrapper <original-binary> <args...>
    # Detect this and use argv[1] as the real binary.
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]) and os.access(sys.argv[1], os.X_OK):
        real_binary = sys.argv[1]
        claude_args = [real_binary] + sys.argv[2:]  # noqa: RUF005
    else:
        real_binary = get_real_claude_binary()
        claude_args = [real_binary] + sys.argv[1:]  # noqa: RUF005

    # Kill-switch: EREBUS_BYPASS=1 skips ALL filtering
    if os.environ.get("EREBUS_BYPASS", "").strip() in ("1", "true", "yes"):
        os.execv(claude_args[0], claude_args)

    # Lightweight Claude utility commands never contain chat payloads. Exec the
    # real binary directly so VSCode/background probes don't keep an Erebus
    # Python wrapper, token map, or detector stack resident in memory.
    if should_passthrough_claude_command(claude_args):
        os.execv(claude_args[0], claude_args)

    try:
        init_db()
        _safe_log_event(SESSION_ID, event_type="session_start",
                        metadata={"cwd": CWD, "args": sys.argv[1:],
                                  "mode": REPO_CONFIG.mode,
                                  "repo_config": REPO_CONFIG.__dict__})
    except Exception:
        pass

    if sys.stdin.isatty():
        _run_interactive(claude_args)
    else:
        # Warm the GLiNER daemon before the first prompt so detection does not
        # fail open while the model is still loading (specs/003-proxy-tokenize-latency).
        try:
            from ..filter import preload_gliner
            preload_gliner()
        except Exception:
            pass
        _run_piped(claude_args)


def _run_interactive(claude_args):
    """Run with a PTY so the TUI works. Detokenizes output; input is passed through."""
    import pty

    def master_read(fd):
        try:
            data = os.read(fd, 1024)
        except OSError:
            return b""
        if TOKEN_MAP:
            text = data.decode("utf-8", errors="replace")
            text = detokenize(text, TOKEN_MAP)
            data = text.encode("utf-8")
        return data

    try:
        pty.spawn(claude_args, master_read)
    except Exception:
        os.execv(claude_args[0], claude_args)


def _kill_child(proc: subprocess.Popen):
    """Terminate the claude child if still running. Idempotent."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
    except Exception:
        pass


def _watch_parent(proc: subprocess.Popen, original_ppid: int):
    """Detect parent death on macOS (no PR_SET_PDEATHSIG) by polling getppid().

    If our parent (VSCode extension host) dies without closing stdin cleanly,
    we get reparented to launchd (ppid=1). Kill the child and exit.
    """
    while True:
        time.sleep(2)
        try:
            current_ppid = os.getppid()
        except Exception:
            return
        if current_ppid != original_ppid or current_ppid == 1:
            _kill_child(proc)
            os._exit(0)


def _run_piped(claude_args):
    """VSCode mode: pipe JSON, tokenize outgoing, detokenize incoming."""
    proc = subprocess.Popen(
        claude_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
    )

    # Ensure the child dies with us, no matter how we exit.
    atexit.register(_kill_child, proc)

    def _on_signal(signum, _frame):
        _kill_child(proc)
        os._exit(128 + signum)

    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        try:
            signal.signal(sig, _on_signal)
        except (ValueError, OSError):
            pass

    # Watchdog: exit if parent (VSCode) dies without closing stdin cleanly.
    threading.Thread(
        target=_watch_parent,
        args=(proc, os.getppid()),
        daemon=True,
    ).start()

    # Input thread closes proc.stdin on EOF so claude can shut down.
    t_in = threading.Thread(
        target=pipe_stream,
        args=(sys.stdin, proc.stdin, process_outgoing),
        kwargs={"close_dest_on_eof": True},
        daemon=True,
    )

    t_out = threading.Thread(
        target=pipe_stream,
        args=(proc.stdout, sys.stdout, process_incoming),
        daemon=True,
    )

    t_in.start()
    t_out.start()

    try:
        proc.wait()
    except KeyboardInterrupt:
        _kill_child(proc)
        sys.exit(130)
    # The child has exited, so proc.stdout is at EOF and t_out's read loop will
    # finish on its own. Join it before exiting so the final detokenized bytes
    # are flushed to our stdout — otherwise this (daemon) thread can be killed
    # mid-write and the last response is silently dropped.
    t_out.join(timeout=5)
    sys.exit(proc.returncode)
