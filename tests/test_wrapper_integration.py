"""
Integration test — verifies the wrapper correctly intercepts Claude's stdin/stdout.
Uses a fake `claude-real` binary (a Python script) so no real Claude needed.
"""
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

FAKE_CLAUDE = """#!/usr/bin/env python3
# Fake claude binary — echoes stdin back as assistant messages.
# If FAKE_CLAUDE_CAPTURE is set, also append every received user text to that
# file. That file is the model-side artifact: it is exactly what crossed the
# boundary toward "Claude", so it is the only honest place to assert that PII
# was tokenized on the way out (the shim detokenizes the response on the way
# back, so the final stdout legitimately shows real values again).
import sys, json, os
_cap = os.environ.get("FAKE_CLAUDE_CAPTURE")
for line in sys.stdin:
    try:
        msg = json.loads(line)
        if msg.get("type") == "user":
            for block in msg.get("message", {}).get("content", []):
                if block.get("type") == "text":
                    if _cap:
                        with open(_cap, "a") as fh:
                            fh.write(block["text"] + "\\n")
                    reply = {"type": "assistant", "message": {"role": "assistant",
                        "content": [{"type": "text", "text": f"Echo: {block['text']}"}]}}
                    print(json.dumps(reply), flush=True)
    except Exception:
        pass
"""

# The shim is a package (erebus/shim/); run it the same way VSCode's wrapper
# entry point does, via the module entry.
REPO_ROOT = Path(__file__).parent.parent
WRAPPER_CMD = [sys.executable, "-m", "erebus.shim"]


def _make_fake_claude() -> Path:
    tmp = Path(tempfile.mktemp(suffix="-fake-claude"))
    tmp.write_text(FAKE_CLAUDE)
    tmp.chmod(tmp.stat().st_mode | stat.S_IEXEC)
    return tmp


def _send_prompt(text: str, fake_claude: Path, capture: Path | None = None) -> str:
    """Run wrapper with a fake claude binary, send one prompt, return response.

    Hermetic: HOME is redirected to a throwaway dir (no real ~/.erebus is read
    or written) and the GLiNER daemon is disabled, so tokenization relies only
    on the deterministic regex pass. That makes the test fast and removes the
    daemon-startup race that used to flake this suite.

    If `capture` is given, the fake claude records everything it receives there
    (the model-side artifact)."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    env["EREBUS_DISABLE_GLINER"] = "1"
    env["HOME"] = tempfile.mkdtemp(prefix="erebus-wrapper-home-")
    if capture is not None:
        env["FAKE_CLAUDE_CAPTURE"] = str(capture)

    msg = json.dumps({
        "type": "user",
        "message": {"role": "user", "content": [{"type": "text", "text": text}]}
    }) + "\n"

    proc = subprocess.run(
        WRAPPER_CMD,
        input=msg, capture_output=True, text=True,
        env={**env, "REAL_CLAUDE_BINARY": str(fake_claude)},
        timeout=10,
    )
    return proc.stdout


def test_clean_prompt_passes_through():
    fake = _make_fake_claude()
    try:
        response = _send_prompt("Write a fibonacci function", fake)
        assert "Echo:" in response or len(response) > 0
        print("  ✓ Clean prompt passed through to Claude")
    finally:
        fake.unlink(missing_ok=True)


def test_email_tokenized_before_reaching_claude():
    fake = _make_fake_claude()
    capture = Path(tempfile.mktemp(suffix="-claude-received"))
    try:
        # Assert on what Claude RECEIVED (the model-side artifact), not on the
        # shim's stdout: the shim detokenizes the response on the way back, so
        # the real email correctly reappears in stdout. The only honest check
        # of "tokenized before reaching Claude" is the capture file.
        _send_prompt("Send results to test@secretcorp.com", fake, capture=capture)
        assert capture.exists(), "fake claude never received input (shim produced no output)"
        received = capture.read_text()
        assert "test@secretcorp.com" not in received, \
            f"real email reached Claude untokenized: {received!r}"
        assert "[EMAIL" in received, \
            f"email was not replaced by a token before reaching Claude: {received!r}"
        print("  ✓ Email was tokenized before reaching Claude")
    finally:
        fake.unlink(missing_ok=True)
        capture.unlink(missing_ok=True)


def test_wrapper_exits_with_claude_exitcode():
    fake = _make_fake_claude()
    try:
        proc = subprocess.run(
            WRAPPER_CMD,
            input="", capture_output=True, text=True,
            env={**os.environ.copy(), "PYTHONPATH": str(REPO_ROOT),
                 "REAL_CLAUDE_BINARY": str(fake)},
            timeout=5,
        )
        # Should not crash
        assert proc.returncode in (0, 1)
        print(f"  ✓ Wrapper exits cleanly (code {proc.returncode})")
    finally:
        fake.unlink(missing_ok=True)


def test_detokenize_completed_writes():
    """After a Write tool executes, tokens in the file should be replaced."""
    import tempfile

    from erebus.shim import (
        _PENDING_WRITE_PATHS,
        TOKEN_MAP,
        _detokenize_completed_writes,
        _track_pending_writes,
    )

    # Set up a token mapping
    TOKEN_MAP["[PERSON_1_" "aabb01]"] = "Jansen"

    # Create a temp file simulating what the Claude binary wrote
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)  # noqa: SIM115
    tmp.write("Contact: Jan [PERSON_1_" "aabb01]\n")
    tmp.close()

    try:
        # Step 1: assistant message announces a Write tool_use
        assistant_msg = {
            "type": "assistant",
            "message": {"role": "assistant", "content": [
                {"type": "tool_use", "id": "toolu_test1", "name": "Write",
                 "input": {"file_path": tmp.name}},
            ]},
        }
        _track_pending_writes(assistant_msg)
        assert "toolu_test1" in _PENDING_WRITE_PATHS

        # Step 2: user message carries the tool_result (tool has executed)
        user_msg = {
            "type": "user",
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "toolu_test1",
                 "content": "File written successfully"},
            ]},
        }
        _detokenize_completed_writes(user_msg)

        # Verify: file should now have real name, not token
        result = Path(tmp.name).read_text()
        assert "Jansen" in result, f"Expected real name in file, got: {result}"
        assert "[PERSON_1_" "aabb01]" not in result, f"Token still in file: {result}"
    finally:
        Path(tmp.name).unlink(missing_ok=True)
        TOKEN_MAP.pop("[PERSON_1_" "aabb01]", None)
        _PENDING_WRITE_PATHS.clear()


if __name__ == "__main__":
    tests = [
        test_clean_prompt_passes_through,
        test_email_tokenized_before_reaching_claude,
        test_wrapper_exits_with_claude_exitcode,
    ]
    print("\n=== Wrapper Integration Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
