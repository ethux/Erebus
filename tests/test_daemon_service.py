"""Tests for the GLiNER daemon KeepAlive service plist (spec 011, US4).

Unit-tests the launchd plist construction only — no real launchctl. The daemon
must be installed as an always-warm supervised service carrying the fork-safety
environment, so there is no cold-start degraded window.
"""

import os
import sys
from xml.etree import ElementTree

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.setup import services


def _plist_dict(xml: str) -> dict:
    """Parse the top-level <dict> of a plist into a Python dict (bools/strings,
    and a nested dict for EnvironmentVariables)."""
    root = ElementTree.fromstring(xml)
    top = root.find("dict")
    return _parse_dict(top)


def _parse_dict(dict_el) -> dict:
    out: dict = {}
    children = list(dict_el)
    for i in range(0, len(children), 2):
        key = children[i].text
        val_el = children[i + 1]
        if val_el.tag == "true":
            out[key] = True
        elif val_el.tag == "false":
            out[key] = False
        elif val_el.tag == "dict":
            out[key] = _parse_dict(val_el)
        elif val_el.tag == "array":
            out[key] = [c.text for c in val_el]
        else:
            out[key] = val_el.text
    return out


def test_daemon_plist_is_well_formed_keepalive_service():
    xml = services.build_gliner_daemon_plist("/opt/erebus/bin/erebus-daemon")
    plist = _plist_dict(xml)
    assert plist["Label"] == services.GLINER_DAEMON_LABEL == "com.ethux.erebus-gliner-daemon"
    assert plist["RunAtLoad"] is True
    assert plist["KeepAlive"] is True
    assert plist["ProgramArguments"] == ["/opt/erebus/bin/erebus-daemon"]
    print("  ok daemon plist is a well-formed RunAtLoad+KeepAlive service")


def test_daemon_plist_carries_fork_safety_env():
    xml = services.build_gliner_daemon_plist("/opt/erebus/bin/erebus-daemon")
    env = _plist_dict(xml)["EnvironmentVariables"]
    assert env["OBJC_DISABLE_INITIALIZE_FORK_SAFETY"] == "YES"
    assert env["TOKENIZERS_PARALLELISM"] == "false"
    print("  ok daemon plist bakes in the fork-safety environment")


def test_daemon_plist_logs_to_daemon_log():
    """StandardErrorPath is the daemon.log the soak greps for 'GLiNER model ready'."""
    xml = services.build_gliner_daemon_plist("/opt/erebus/bin/erebus-daemon")
    plist = _plist_dict(xml)
    assert plist["StandardErrorPath"].endswith("/.erebus/daemon.log")
    print("  ok daemon stderr is routed to ~/.erebus/daemon.log")


if __name__ == "__main__":
    tests = [
        test_daemon_plist_is_well_formed_keepalive_service,
        test_daemon_plist_carries_fork_safety_env,
        test_daemon_plist_logs_to_daemon_log,
    ]
    print("\n=== Daemon service tests ===\n")
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
