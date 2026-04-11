"""
E2E tests for the orphan-process fix in erebus/shim.py.

These spawn the real shim as a subprocess against a fake `claude` binary that
blocks forever. We then verify:

  1. stdin EOF propagates to the child so everything exits cleanly.
  2. A SIGTERM to the shim kills the child too (no half-leaks).
  3. When the shim's parent dies (simulating VSCode crash), the watchdog
     detects ppid==1 and takes down both the shim and its child.

All tests pass the fake claude via argv[1], which shim.py picks up as the real
binary when it's executable — no real claude install needed.
"""
import sys
import os
import signal
import stat
import subprocess
import tempfile
import time
from pathlib import Path

SHIM_PATH = Path(__file__).parent.parent / "erebus" / "shim.py"
REPO_ROOT = SHIM_PATH.parent.parent

# Fake claude: reads stdin line-by-line and exits on EOF. Used for the
# "EOF propagation" test — it's a cooperative child that *will* exit
# if (and only if) the shim closes its stdin.
FAKE_CLAUDE_COOPERATIVE = """#!/usr/bin/env python3
import sys
for _ in sys.stdin:
    pass
sys.exit(0)
"""

# Fake claude: blocks forever on read. Used for the SIGTERM / parent-death
# tests — proves we actively kill the child, not just wait for it.
FAKE_CLAUDE_BLOCKING = """#!/usr/bin/env python3
import sys, time
# Write a byte so the parent knows we're alive, then block forever.
sys.stdout.write("ready\\n")
sys.stdout.flush()
while True:
    time.sleep(3600)
"""


def _write_fake(src: str) -> Path:
    tmp = Path(tempfile.mktemp(suffix="-fake-claude.py"))
    tmp.write_text(src)
    tmp.chmod(tmp.stat().st_mode | stat.S_IEXEC | stat.S_IRUSR)
    return tmp


def _shim_env() -> dict:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return env


def _spawn_shim(fake_claude: Path, stdin=subprocess.PIPE) -> subprocess.Popen:
    return subprocess.Popen(
        [sys.executable, "-m", "erebus.shim", str(fake_claude)],
        stdin=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=_shim_env(),
        cwd=str(REPO_ROOT),
    )


def _child_pids(parent_pid: int) -> list[int]:
    """Return direct children of a pid via `ps`."""
    out = subprocess.run(
        ["ps", "-eo", "pid,ppid"],
        capture_output=True, text=True,
    ).stdout
    kids = []
    for line in out.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == str(parent_pid):
            kids.append(int(parts[0]))
    return kids


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def test_shim_exits_on_stdin_eof():
    """Closing stdin should propagate EOF to claude; shim exits cleanly."""
    fake = _write_fake(FAKE_CLAUDE_COOPERATIVE)
    try:
        proc = _spawn_shim(fake)
        # Close stdin immediately — shim should propagate to child.
        proc.stdin.close()
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise AssertionError("shim hung after stdin EOF — fix regressed")
        assert proc.returncode == 0, f"unexpected exit code {proc.returncode}"
        print("  ✓ shim exits cleanly on stdin EOF")
    finally:
        fake.unlink(missing_ok=True)


def test_shim_kills_child_on_sigterm():
    """SIGTERM to the shim must take down the (otherwise-blocking) claude child."""
    fake = _write_fake(FAKE_CLAUDE_BLOCKING)
    try:
        proc = _spawn_shim(fake)
        # Wait for fake claude to be up.
        deadline = time.time() + 5
        child_pids: list[int] = []
        while time.time() < deadline:
            child_pids = _child_pids(proc.pid)
            if child_pids:
                break
            time.sleep(0.1)
        assert child_pids, "fake claude never started under shim"
        claude_pid = child_pids[0]

        proc.send_signal(signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            raise AssertionError("shim ignored SIGTERM")

        # Give reaper a beat to clean up the child.
        for _ in range(20):
            if not _pid_alive(claude_pid):
                break
            time.sleep(0.1)
        assert not _pid_alive(claude_pid), (
            f"claude child {claude_pid} survived shim SIGTERM — leak regressed"
        )
        print("  ✓ SIGTERM to shim kills the claude child")
    finally:
        fake.unlink(missing_ok=True)


def test_shim_exits_when_parent_dies():
    """
    Simulate VSCode crashing: a grandparent python spawns the shim, then the
    grandparent is SIGKILLed. The shim's ppid becomes 1; the watchdog should
    detect this within ~3s and take itself (and the claude child) down.
    """
    fake = _write_fake(FAKE_CLAUDE_BLOCKING)
    try:
        # Grandparent: spawns shim detached from us, prints shim pid, then sleeps.
        grandparent_src = f"""
import subprocess, sys, time
p = subprocess.Popen(
    [{sys.executable!r}, "-m", "erebus.shim", {str(fake)!r}],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
print(p.pid, flush=True)
time.sleep(300)
"""
        grandparent = subprocess.Popen(
            [sys.executable, "-c", grandparent_src],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_shim_env(),
            cwd=str(REPO_ROOT),
        )
        shim_pid_line = grandparent.stdout.readline().decode().strip()
        assert shim_pid_line.isdigit(), f"didn't get shim pid: {shim_pid_line!r}"
        shim_pid = int(shim_pid_line)

        # Wait for the claude grandchild to appear.
        deadline = time.time() + 5
        claude_pids: list[int] = []
        while time.time() < deadline:
            claude_pids = _child_pids(shim_pid)
            if claude_pids:
                break
            time.sleep(0.1)
        assert claude_pids, "fake claude never started under shim"
        claude_pid = claude_pids[0]

        # SIGKILL the grandparent — no cleanup, no clean stdin close.
        grandparent.kill()
        grandparent.wait(timeout=2)

        # Watchdog polls every 2s; give it up to 8s to react.
        deadline = time.time() + 8
        while time.time() < deadline:
            if not _pid_alive(shim_pid) and not _pid_alive(claude_pid):
                break
            time.sleep(0.2)

        shim_alive = _pid_alive(shim_pid)
        claude_alive = _pid_alive(claude_pid)

        # Cleanup stragglers before asserting so we don't leak from the test itself.
        for pid in (claude_pid, shim_pid):
            if _pid_alive(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

        assert not shim_alive, f"shim {shim_pid} survived parent death — watchdog regressed"
        assert not claude_alive, f"claude {claude_pid} orphaned after shim died"
        print("  ✓ shim + child exit when parent (VSCode) dies")
    finally:
        fake.unlink(missing_ok=True)


if __name__ == "__main__":
    tests = [
        test_shim_exits_on_stdin_eof,
        test_shim_kills_child_on_sigterm,
        test_shim_exits_when_parent_dies,
    ]
    print("\n=== Orphan Cleanup E2E Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
