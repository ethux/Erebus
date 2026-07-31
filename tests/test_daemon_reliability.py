"""Regression tests for the four GLiNER daemon crash causes (spec 011, FR-008).

Each reproduced crash trigger gets a guard so the daemon survives it:
  (a) fork-after-initialize abort — the daemon's spawn/service env carries the
      macOS fork-safety mitigation, so a fork in the model path cannot abort it.
  (b) a client that hangs up mid-request does not propagate into the accept loop.
  (c) a model-hub name-resolution failure falls back to the local cache instead
      of crashing the load.
  (d) two near-simultaneous starts bind exactly one socket, zero "address
      already in use".

Availability-only: nothing here touches detection logic or the redaction guarantee.
"""

import os
import sys
import tempfile
import types
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.runtime import daemon, lifecycle, model_loading

# ── (a) fork-after-initialize abort ────────────────────────────────────────────

def test_fork_safety_env_is_set_for_spawned_daemon():
    """The dominant crash: a fork after Metal/ObjC init aborts the child unless
    OBJC_DISABLE_INITIALIZE_FORK_SAFETY is set and tokenizers forking is off."""
    env = lifecycle.daemon_child_env()
    assert env["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] == "YES"
    assert env["TOKENIZERS_PARALLELISM"] == "false"
    # The standalone helper the service plist also uses returns the same pair.
    assert lifecycle.fork_safety_env() == {
        "OBJC_DISABLE_INITIALIZE_FORK_SAFETY": "YES",
        "TOKENIZERS_PARALLELISM": "false",
    }
    print("  ok spawned-daemon env carries the fork-safety mitigation")


# ── (b) client disconnect mid-request ──────────────────────────────────────────

class _HangupConn:
    """A client that connects then immediately hangs up (recv -> b'')."""

    def __init__(self):
        self.closed = False

    def recv(self, _n):
        return b""

    def sendall(self, _data):
        raise BrokenPipeError("client gone")

    def close(self):
        self.closed = True


class _ResetConn:
    """A client whose socket resets mid-request."""

    def recv(self, _n):
        raise ConnectionResetError("reset by peer")

    def sendall(self, _data):
        raise BrokenPipeError("client gone")

    def close(self):
        self.closed = True


def test_handle_client_survives_disconnect():
    """A client that hangs up or resets must never propagate out of
    handle_client; the connection is always closed."""
    for conn in (_HangupConn(), _ResetConn()):
        # model is never reached for a hung-up client; a sentinel proves it.
        daemon.handle_client(conn, model=object())
        assert conn.closed, "connection must be closed in finally"
    print("  ok handle_client tears down a disconnecting client cleanly")


# ── (c) hub name-resolution failure -> local cache ─────────────────────────────

def _fake_gliner_module(record: list):
    """A stand-in gliner module: the first (online) load raises a DNS error,
    the forced-offline retry succeeds. Records the call kwargs."""
    mod = types.ModuleType("gliner")

    class GLiNER:
        @staticmethod
        def from_pretrained(model_id, **kwargs):
            record.append(kwargs)
            if not kwargs.get("local_files_only"):
                raise OSError("nodename nor servname provided, or not known")
            return f"cached-model:{model_id}"

    mod.GLiNER = GLiNER
    return mod


def test_load_falls_back_to_local_cache_on_dns_failure():
    record: list = []
    fake = _fake_gliner_module(record)
    with patch.dict(sys.modules, {"gliner": fake}):
        model = model_loading._load_gliner_weights()
    assert model == "cached-model:urchade/gliner_multi_pii-v1"
    assert record[0] == {}  # first attempt: normal online load
    assert record[1] == {"local_files_only": True}  # fell back offline
    print("  ok a DNS failure falls back to the local model cache")


def test_non_network_error_is_not_swallowed():
    """A genuine load bug (not a network failure) must still surface."""
    mod = types.ModuleType("gliner")

    class GLiNER:
        @staticmethod
        def from_pretrained(model_id, **kwargs):
            raise ValueError("corrupt weights")

    mod.GLiNER = GLiNER
    with patch.dict(sys.modules, {"gliner": mod}):
        try:
            model_loading._load_gliner_weights()
        except ValueError:
            print("  ok a non-network load error is not masked as offline")
            return
    raise AssertionError("non-network error should have propagated")


def test_network_error_classifier():
    assert model_loading._is_network_error(OSError("nodename nor servname provided"))
    assert model_loading._is_network_error(Exception("Max retries exceeded with url"))
    assert not model_loading._is_network_error(ValueError("corrupt weights"))
    print("  ok network-error classifier distinguishes DNS/connect from real bugs")


# ── (d) concurrent start binds exactly once ────────────────────────────────────

def test_bind_reclaims_stale_socket():
    """A stale socket file left by a dead daemon must be reclaimed under the
    lock, so a start never hits 'address already in use'."""
    with tempfile.TemporaryDirectory() as tmpdir:
        sock_path = str(Path(tmpdir) / "gliner.sock")
        # Simulate a stale socket file left behind by a crashed daemon.
        Path(sock_path).write_bytes(b"")
        with patch.object(daemon, "SOCKET_PATH", sock_path):
            server = daemon._bind_reclaiming_socket()
            try:
                assert server.fileno() != -1
                assert os.path.exists(sock_path)
            finally:
                server.close()
        print("  ok bind reclaims a stale socket instead of failing")


def test_singleton_lock_admits_exactly_one():
    """Two starters racing the lock: exactly one wins; the loser gets None and
    never touches the socket."""
    with tempfile.TemporaryDirectory() as tmpdir:
        lock_path = str(Path(tmpdir) / "gliner.lock")
        with patch.object(daemon, "LOCK_PATH", lock_path):
            first = daemon._acquire_singleton_lock()
            second = daemon._acquire_singleton_lock()
        try:
            assert first is not None, "first starter must win the lock"
            assert second is None, "second starter must lose and not bind"
        finally:
            if first is not None:
                os.close(first)
        print("  ok singleton lock admits exactly one daemon")


if __name__ == "__main__":
    tests = [
        test_fork_safety_env_is_set_for_spawned_daemon,
        test_handle_client_survives_disconnect,
        test_load_falls_back_to_local_cache_on_dns_failure,
        test_non_network_error_is_not_swallowed,
        test_network_error_classifier,
        test_bind_reclaims_stale_socket,
        test_singleton_lock_admits_exactly_one,
    ]
    print("\n=== Daemon reliability tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  x {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    if passed != len(tests):
        sys.exit(1)
