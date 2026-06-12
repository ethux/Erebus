"""Tests for GLiNER daemon lifecycle: the singleton lock is the source of truth.

Regression guard for the 2026-06-10 incident: stop_daemon unlinked the socket
of a live daemon it failed to identify, leaving an unreachable model-holding
zombie that blocked every spawn via the lock while requests burned timeouts.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.runtime import daemon, lifecycle

CHILD_SRC = """
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDWR | os.O_CREAT, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
if len(sys.argv) > 2 and sys.argv[2] == "write-pid":
    os.ftruncate(fd, 0)
    os.write(fd, str(os.getpid()).encode())
print("READY", flush=True)
time.sleep(60)
"""


def _hold_lock_in_child(lock_path: Path, write_pid: bool) -> subprocess.Popen:
    args = [sys.executable, "-c", CHILD_SRC, str(lock_path)]
    if write_pid:
        args.append("write-pid")
    child = subprocess.Popen(args, stdout=subprocess.PIPE, text=True)
    assert child.stdout.readline().strip() == "READY"
    return child


def _patched_paths(tmp: Path):
    return (
        patch.object(daemon, "LOCK_PATH", str(tmp / "gliner.lock")),
        patch.object(daemon, "SOCKET_PATH", str(tmp / "gliner.sock")),
        patch.object(daemon, "PID_PATH", str(tmp / "gliner.pid")),
    )


def test_stop_cleans_files_when_no_daemon():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "gliner.sock").write_text("")
        (tmp / "gliner.pid").write_text("99999")
        lock_p, sock_p, pid_p = _patched_paths(tmp)

        with lock_p, sock_p, pid_p:
            assert daemon.stop_daemon(timeout=1.0)

        assert not (tmp / "gliner.sock").exists()
        assert not (tmp / "gliner.pid").exists()
    print("  ok stop_daemon cleans runtime files when no daemon holds the lock")


def test_stop_never_unlinks_socket_of_unidentified_live_daemon():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "gliner.sock").write_text("")
        lock_p, sock_p, pid_p = _patched_paths(tmp)
        child = _hold_lock_in_child(tmp / "gliner.lock", write_pid=False)
        try:
            with lock_p, sock_p, pid_p:
                assert daemon.stop_daemon(timeout=1.0) is False
            assert (tmp / "gliner.sock").exists(), \
                "socket of a live-but-unidentified daemon must never be unlinked"
            assert child.poll() is None, "unidentified holder must not be killed"
        finally:
            child.kill()
            child.wait()
    print("  ok stop_daemon leaves a live unidentified daemon's socket alone")


def test_stop_kills_identified_holder_and_cleans():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        (tmp / "gliner.sock").write_text("")
        lock_p, sock_p, pid_p = _patched_paths(tmp)
        child = _hold_lock_in_child(tmp / "gliner.lock", write_pid=True)
        try:
            with lock_p, sock_p, pid_p:
                assert daemon.stop_daemon(timeout=3.0)
            assert child.wait(timeout=5) is not None
            assert not (tmp / "gliner.sock").exists()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    print("  ok stop_daemon kills the lock holder and cleans up afterwards")


def test_wedged_recovery_refuses_non_daemon_processes():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)  # no socket file: the wedged-daemon signature
        lock_p, sock_p, pid_p = _patched_paths(tmp)
        child = _hold_lock_in_child(tmp / "gliner.lock", write_pid=True)
        try:
            with lock_p, sock_p, pid_p:
                assert daemon._recover_wedged_daemon() is False
            assert child.poll() is None, \
                "recovery must only kill verified erebus.runtime.daemon processes"
        finally:
            child.kill()
            child.wait()
    print("  ok wedge recovery only kills verified erebus daemons")


def test_parent_watchdog_marks_reparented_daemon_orphaned():
    with patch.object(lifecycle.os, "getppid", return_value=1), \
         patch.object(lifecycle.os, "kill") as kill:
        assert lifecycle.parent_process_gone(4242) is True
        kill.assert_not_called()

    with patch.object(lifecycle.os, "getppid", return_value=4242), \
         patch.object(lifecycle.os, "kill") as kill:
        assert lifecycle.parent_process_gone(4242) is False
        kill.assert_called_once_with(4242, 0)
    print("  ok parent watchdog treats ppid changes as orphaned")


def test_spawn_env_records_expected_parent_pid():
    with patch.object(lifecycle.os, "getpid", return_value=4242):
        env = lifecycle.daemon_child_env()
    assert env[lifecycle.PARENT_PID_ENV] == "4242"
    print("  ok spawned daemon records its expected parent pid")


def test_expected_parent_pid_uses_env_or_initial_ppid():
    with patch.dict(lifecycle.os.environ, {lifecycle.PARENT_PID_ENV: "4242"}), \
         patch.object(lifecycle.os, "getppid", return_value=9999):
        assert lifecycle.expected_parent_pid() == 4242

    with patch.dict(lifecycle.os.environ, {}, clear=True), \
         patch.object(lifecycle.os, "getppid", return_value=4343):
        assert lifecycle.expected_parent_pid() == 4343

    with patch.dict(lifecycle.os.environ, {}, clear=True), \
         patch.object(lifecycle.os, "getppid", return_value=1):
        assert lifecycle.expected_parent_pid() is None
    print("  ok parent watchdog covers spawned and direct non-launchd daemons")


def test_ensure_daemon_passes_parent_pid_to_spawned_daemon():
    with patch.object(daemon, "is_daemon_running", return_value=False), \
         patch.object(daemon, "_acquire_singleton_lock", return_value=123), \
         patch.object(daemon.os, "close"), \
         patch.object(daemon.os, "makedirs"), \
         patch.object(daemon.os, "open", return_value=456), \
         patch.object(daemon.os.path, "exists", return_value=False), \
         patch.object(daemon.time, "sleep"), \
         patch.object(daemon, "_recover_wedged_daemon", return_value=False), \
         patch("subprocess.Popen") as popen:
        daemon.ensure_daemon()

    kwargs = popen.call_args.kwargs
    assert kwargs["env"][lifecycle.PARENT_PID_ENV] == str(os.getpid())
    print("  ok ensure_daemon passes parent pid to spawned daemon")


def test_memory_ceiling_parses_env_override():
    """Regression for the 2026-06-12 incident: the daemon's MPS allocator
    retained 30 GB after a day of varied-shape inference."""
    with patch.dict(lifecycle.os.environ, {lifecycle.MEMORY_CEILING_ENV: "2048"}):
        assert lifecycle.memory_ceiling_mb() == 2048
    with patch.dict(lifecycle.os.environ, {lifecycle.MEMORY_CEILING_ENV: "64"}):
        assert lifecycle.memory_ceiling_mb() == 1024, "floor must be 1 GB"
    with patch.dict(lifecycle.os.environ, {lifecycle.MEMORY_CEILING_ENV: "not-a-number"}):
        assert lifecycle.memory_ceiling_mb() == lifecycle._DEFAULT_MEMORY_CEILING_MB
    with patch.dict(lifecycle.os.environ, {}, clear=True):
        assert lifecycle.memory_ceiling_mb() == lifecycle._DEFAULT_MEMORY_CEILING_MB
    print("  ok memory ceiling honors env override, floor, and garbage input")


def test_peak_footprint_reports_sane_value():
    mb = lifecycle.process_peak_footprint_mb()
    assert 1 < mb < 1_000_000, f"implausible footprint: {mb}MB"
    print(f"  ok peak footprint reports a sane value ({mb:.0f}MB)")


def test_release_accelerator_cache_never_raises():
    # Must be safe with or without torch/accelerators present.
    lifecycle.release_accelerator_cache()
    with patch.dict(sys.modules, {"torch": None}):
        lifecycle.release_accelerator_cache()
    print("  ok accelerator cache release is unconditionally safe")


if __name__ == "__main__":
    tests = [
        test_stop_cleans_files_when_no_daemon,
        test_stop_never_unlinks_socket_of_unidentified_live_daemon,
        test_stop_kills_identified_holder_and_cleans,
        test_wedged_recovery_refuses_non_daemon_processes,
        test_parent_watchdog_marks_reparented_daemon_orphaned,
        test_spawn_env_records_expected_parent_pid,
        test_expected_parent_pid_uses_env_or_initial_ppid,
        test_ensure_daemon_passes_parent_pid_to_spawned_daemon,
        test_memory_ceiling_parses_env_override,
        test_peak_footprint_reports_sane_value,
        test_release_accelerator_cache_never_raises,
    ]
    print("\n=== Daemon Lifecycle Tests ===\n")
    passed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as exc:
            print(f"  FAIL {test.__name__}: {exc}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
