"""
Persistent GLiNER daemon — loads the model once, serves predictions via Unix socket.
Stays alive across Claude sessions. Auto-started by the wrapper if not running.
"""

import fcntl
import json
import os
import signal
import socket
import sys
import threading
import time

try:
    from ..perf import PerfTimer, log_perf_event
except Exception:
    class PerfTimer:
        def __init__(self):
            self.wall_start = time.perf_counter()
            self.cpu_start = time.process_time()

        def finish(self):
            wall = max(time.perf_counter() - self.wall_start, 0.0)
            cpu = max(time.process_time() - self.cpu_start, 0.0)
            return {
                "wall_ms": round(wall * 1000, 3),
                "cpu_ms": round(cpu * 1000, 3),
                "cpu_pct": round((cpu / wall) * 100, 1) if wall else 0.0,
            }

    def log_perf_event(event, **metadata):
        return None

from .lifecycle import (
    daemon_child_env as _daemon_child_env,
)
from .lifecycle import (
    memory_ceiling_watchdog as _memory_ceiling_watchdog,
)
from .lifecycle import (
    parent_process_watchdog as _parent_process_watchdog,
)
from .lifecycle import (
    release_accelerator_cache as _release_accelerator_cache,
)
from .lifecycle import (
    socket_path_watchdog as _socket_path_watchdog,
)

SOCKET_PATH = os.path.expanduser("~/.erebus/gliner.sock")
PID_PATH = os.path.expanduser("~/.erebus/gliner.pid")
# Exclusive, held for the daemon's whole life: makes "exactly one daemon loads
# the model" a hard guarantee even when several are spawned at once (e.g. many
# editor windows starting together). Without it, each racer loaded its own
# ~2 GB model copy and could exhaust memory.
LOCK_PATH = os.path.expanduser("~/.erebus/gliner.lock")
MODEL_LOCK = threading.Lock()
# Module-global so the fd (and thus the lock) lives as long as the process.
_singleton_lock_fd: int | None = None


def _acquire_singleton_lock() -> int | None:
    """Take the exclusive daemon lock without blocking. Returns the held fd on
    success, or None if another live daemon already holds it. The fd is kept
    open for the process lifetime; closing it (or exiting) releases the lock."""
    os.makedirs(os.path.dirname(LOCK_PATH), exist_ok=True)
    fd = os.open(LOCK_PATH, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd

GLINER_LABELS = [
    "person", "email address", "phone number", "address",
    "organization", "credit card number", "social security number",
    "iban", "passport number", "ip address", "username",
    "password", "api key", "date of birth", "bank account number",
]


def _default_threads() -> int:
    """Detector thread count. Defaults to most of the box so batched windows
    (specs/003-proxy-tokenize-latency) parallelise; override via env."""
    env = os.environ.get("EREBUS_GLINER_THREADS")
    if env:
        try:
            return max(1, int(env))
        except ValueError:
            pass
    cpu = os.cpu_count() or 4
    return max(1, min(8, cpu - 2))


def _detector_device() -> str:
    """Inference device: EREBUS_GLINER_DEVICE overrides, else MPS when present.

    Measured on M-series: MPS runs GLiNER ~3x faster than CPU with identical
    outputs, which is the difference between sub-second and multi-second
    tokenization on novel interactive turns.
    """
    env = os.environ.get("EREBUS_GLINER_DEVICE")
    if env:
        return env
    try:
        import torch
        if torch.backends.mps.is_available():
            return "mps"
    except Exception:
        pass
    return "cpu"


def _load_model():
    import torch
    torch.set_num_threads(_default_threads())
    from gliner import GLiNER
    model = GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")
    device = _detector_device()
    if device != "cpu":
        try:
            model = model.to(device)
            print(f"GLiNER running on {device}.", file=sys.stderr, flush=True)
        except Exception as exc:
            print(f"GLiNER {device} unavailable ({exc}); staying on CPU.",
                  file=sys.stderr, flush=True)
    return model


def handle_client(conn, model):
    """Handle a single client connection: receive text, return entities."""
    try:
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
            # Protocol: newline-terminated JSON
            if b"\n" in data:
                break

        line = data.split(b"\n", 1)[0]
        if not line:
            return

        req = json.loads(line)
        text = req.get("text", "")
        texts = req.get("texts")
        threshold = req.get("threshold", 0.7)
        labels = req.get("labels", GLINER_LABELS)
        batch_size = int(req.get("batch_size", 8) or 8)

        with MODEL_LOCK:
            timer = PerfTimer()
            text_count = 0
            text_chars = 0
            entity_count = 0
            threads = _default_threads()
            if isinstance(texts, list):
                clean_texts = [t if isinstance(t, str) else "" for t in texts]
                text_count = len(clean_texts)
                text_chars = sum(len(t) for t in clean_texts)
                if hasattr(model, "inference"):
                    raw_batches = model.inference(
                        clean_texts,
                        labels,
                        threshold=threshold,
                        batch_size=batch_size,
                    )
                else:
                    raw_batches = [
                        model.predict_entities(t, labels, threshold=threshold)
                        for t in clean_texts
                    ]
                result = [
                    [{"start": e["start"], "end": e["end"], "label": e["label"],
                      "text": e["text"]} for e in entities]
                    for entities in raw_batches
                ]
                entity_count = sum(len(entities) for entities in result)
            elif text:
                text_count = 1
                text_chars = len(text)
                entities = model.predict_entities(text, labels, threshold=threshold)
                result = [{"start": e["start"], "end": e["end"], "label": e["label"],
                           "text": e["text"]} for e in entities]
                entity_count = len(result)
            else:
                result = []
            _release_accelerator_cache()
            log_perf_event(
                "gliner_inference",
                **timer.finish(),
                text_count=text_count,
                text_chars=text_chars,
                batch_size=batch_size if isinstance(texts, list) else 1,
                entity_count=entity_count,
                label_count=len(labels) if isinstance(labels, list) else 0,
                threads=max(1, threads),
            )

        conn.sendall(json.dumps(result).encode() + b"\n")
    except Exception as e:
        try:
            conn.sendall(json.dumps({"error": str(e)}).encode() + b"\n")
        except Exception:
            pass
    finally:
        conn.close()




def run_daemon():
    """Main daemon loop."""
    global _singleton_lock_fd
    # Singleton guard FIRST, before any expensive work: if another daemon is
    # already alive it holds this lock, so we exit immediately — crucially
    # before loading the ~2 GB model. This is the hard stop on the spawn race
    # that could otherwise load one model copy per concurrent starter.
    _singleton_lock_fd = _acquire_singleton_lock()
    if _singleton_lock_fd is None:
        print("GLiNER daemon already running; exiting.", file=sys.stderr, flush=True)
        return

    # Publish our pid in the lock file: with the flock held, its content is
    # the authoritative "who is the daemon" answer (the pid *file* can go
    # stale, but only the lock holder can have written this).
    os.ftruncate(_singleton_lock_fd, 0)
    os.write(_singleton_lock_fd, str(os.getpid()).encode())

    # We hold the exclusive lock, so reclaiming the socket can't disturb a live
    # daemon — any socket on disk is stale.
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)

    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)

    # Write PID
    with open(PID_PATH, "w") as f:
        f.write(str(os.getpid()))

    threading.Thread(target=_parent_process_watchdog, daemon=True).start()

    # Bind socket before loading the model so ensure_daemon() detects us
    # quickly.  Connections that arrive during model loading queue in the
    # kernel backlog (listen 8) and are served once the model is ready.
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(8)

    # Load model (this is the slow part — only happens once)
    print("Loading GLiNER model...", file=sys.stderr, flush=True)
    model = _load_model()
    print("GLiNER model ready.", file=sys.stderr, flush=True)

    threading.Thread(target=_socket_path_watchdog, args=(SOCKET_PATH,), daemon=True).start()
    threading.Thread(target=_memory_ceiling_watchdog, daemon=True).start()

    while True:
        conn, _ = server.accept()
        threading.Thread(target=handle_client, args=(conn, model), daemon=True).start()


def is_daemon_running() -> bool:
    """Check if the daemon is alive."""
    if not os.path.exists(PID_PATH) or not os.path.exists(SOCKET_PATH):
        return False
    try:
        with open(PID_PATH) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)  # signal 0 = check if alive
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(0.25)
        try:
            sock.connect(SOCKET_PATH)
        finally:
            sock.close()
        return True
    except (OSError, ValueError, ProcessLookupError, PermissionError):
        return False


def _singleton_lock_state() -> tuple[bool, int | None]:
    """(lock_held_by_someone, holder_pid_if_known)."""
    probe = _acquire_singleton_lock()
    if probe is not None:
        os.close(probe)
        return False, None
    for path in (LOCK_PATH, PID_PATH):
        try:
            with open(path) as f:
                return True, int(f.read().strip())
        except (OSError, ValueError):
            continue
    return True, None


def _remove_runtime_files():
    for path in (SOCKET_PATH, PID_PATH):
        try:
            os.unlink(path)
        except OSError:
            pass


def stop_daemon(timeout: float = 3.0) -> bool:
    """Stop the GLiNER daemon if it is running, and remove stale runtime files.

    The singleton lock is the source of truth: socket/pid files are removed
    only once no process holds the lock. The old behaviour (unlink always)
    could delete the socket out from under a live daemon it failed to
    identify, leaving an unreachable model-holding zombie that blocked every
    future spawn via the lock while requests burned timeouts and degraded.
    """
    held, pid = _singleton_lock_state()
    if not held:
        _remove_runtime_files()
        return True
    if pid is None:
        return False  # daemon alive but unidentifiable; leave its files alone

    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        return False
    deadline = time.time() + timeout
    while time.time() < deadline:
        held, _ = _singleton_lock_state()  # flock releases when the holder dies
        if not held:
            _remove_runtime_files()
            return True
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    for _ in range(20):
        held, _ = _singleton_lock_state()
        if not held:
            _remove_runtime_files()
            return True
        time.sleep(0.1)
    return False


def _process_command(pid: int) -> str:
    import subprocess
    try:
        out = subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return out.stdout.strip()


def _recover_wedged_daemon() -> bool:
    """Kill a daemon that holds the singleton lock but has no socket on disk.

    Clients find the daemon by socket path, so that state never heals by
    itself: the holder is unreachable forever while blocking every spawn
    attempt, and each request burns the full socket wait before degrading.
    Only kills a pid whose command line is verifiably the erebus daemon.
    Returns True when the holder was killed and the lock is free again.
    """
    held, pid = _singleton_lock_state()
    if not held or pid is None or os.path.exists(SOCKET_PATH):
        return False
    if "erebus.runtime.daemon" not in _process_command(pid):
        return False
    log_perf_event("daemon_wedged_killed", pid=pid)
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        return False
    for _ in range(20):
        held, _ = _singleton_lock_state()
        if not held:
            return True
        time.sleep(0.1)
    return False


def ensure_daemon():
    """Start the daemon if not already running.

    Spawns a fresh interpreter (fork+exec) instead of a bare os.fork(). On
    macOS, forking a process with Objective-C frameworks initialised (e.g. the
    aiohttp proxy with torch loaded) crashes the child outright, and a forked
    child also inherits the parent's listening sockets — which made a
    launchd-restarted proxy crash-loop on "address already in use" while a
    daemon child silently held port 4748. exec'ing a new process avoids both.
    """
    if is_daemon_running():
        return

    # Cheap pre-check that avoids the thundering herd: if a daemon already holds
    # the singleton lock (alive but perhaps still loading the model, so its
    # socket isn't up yet), don't spawn another — just wait for the socket. The
    # daemon-side guard is still the authoritative stop; this only trims wasted
    # spawns. We immediately release on success so the real daemon can take it.
    probe_fd = _acquire_singleton_lock()
    if probe_fd is None:
        for _ in range(30):  # up to 3s
            if os.path.exists(SOCKET_PATH):
                return
            time.sleep(0.1)
        if _recover_wedged_daemon():
            ensure_daemon()  # lock is free now; take the spawn path
        return
    os.close(probe_fd)  # release; the spawned daemon re-acquires and holds it

    import subprocess

    log_path = os.path.expanduser("~/.erebus/daemon.log")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    try:
        stderr_target = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    except OSError:
        stderr_target = subprocess.DEVNULL
    try:
        subprocess.Popen(
            [sys.executable, "-m", "erebus.runtime.daemon"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=stderr_target,
            close_fds=True,
            start_new_session=True,
            env=_daemon_child_env(),
        )
    except Exception:
        return
    finally:
        if isinstance(stderr_target, int) and stderr_target >= 0:
            try:
                os.close(stderr_target)
            except OSError:
                pass

    # Wait for the socket to appear. The daemon binds it before loading the
    # model, so this should return within ~1 second.
    for _ in range(30):  # up to 3s
        if os.path.exists(SOCKET_PATH):
            return
        time.sleep(0.1)


def predict_via_daemon(text: str, threshold: float = 0.5) -> list[dict] | None:
    """Send text to the daemon, get back entities. Returns None if daemon unavailable."""
    if not os.path.exists(SOCKET_PATH):
        return None

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(30.0)
        sock.connect(SOCKET_PATH)

        req = json.dumps({"text": text, "threshold": threshold}) + "\n"
        sock.sendall(req.encode())
        sock.shutdown(socket.SHUT_WR)

        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk

        sock.close()
        result = json.loads(data)
        if isinstance(result, dict) and "error" in result:
            return None
        if not isinstance(result, list):
            return None
        return result
    except Exception:
        return None


def predict_many_via_daemon(texts: list[str], threshold: float = 0.5,
                            batch_size: int = 8) -> list[list[dict]] | None:
    """Send multiple texts to the daemon, preserving one entity list per text."""
    if not os.path.exists(SOCKET_PATH):
        return None

    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(30.0)
        sock.connect(SOCKET_PATH)

        req = json.dumps({
            "texts": texts,
            "threshold": threshold,
            "batch_size": batch_size,
        }) + "\n"
        sock.sendall(req.encode())
        sock.shutdown(socket.SHUT_WR)

        data = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk

        sock.close()
        result = json.loads(data)
        if isinstance(result, dict) and "error" in result:
            return None
        if not isinstance(result, list) or len(result) != len(texts):
            return None
        if not all(isinstance(item, list) for item in result):
            return None
        return result
    except Exception:
        return None


if __name__ == "__main__":
    run_daemon()
