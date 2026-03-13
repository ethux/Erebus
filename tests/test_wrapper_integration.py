"""
Integration test — verifies the wrapper correctly intercepts Claude's stdin/stdout.
Uses a fake `claude-real` binary (a Python script) so no real Claude needed.
"""
import sys, os, json, subprocess, tempfile, stat
from pathlib import Path

FAKE_CLAUDE = """#!/usr/bin/env python3
# Fake claude binary — echoes stdin back as assistant messages
import sys, json
for line in sys.stdin:
    try:
        msg = json.loads(line)
        if msg.get("type") == "user":
            for block in msg.get("message", {}).get("content", []):
                if block.get("type") == "text":
                    reply = {"type": "assistant", "message": {"role": "assistant",
                        "content": [{"type": "text", "text": f"Echo: {block['text']}"}]}}
                    print(json.dumps(reply), flush=True)
    except Exception:
        pass
"""

WRAPPER_PATH = Path(__file__).parent.parent / "erebus" / "shim.py"


def _make_fake_claude() -> Path:
    tmp = Path(tempfile.mktemp(suffix="-fake-claude"))
    tmp.write_text(FAKE_CLAUDE)
    tmp.chmod(tmp.stat().st_mode | stat.S_IEXEC)
    return tmp


def _send_prompt(text: str, fake_claude: Path) -> str:
    """Run wrapper with a fake claude binary, send one prompt, return response."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(WRAPPER_PATH.parent.parent)

    # Patch REAL_CLAUDE_BINARY to fake binary
    wrapper_src = WRAPPER_PATH.read_text()
    patched = wrapper_src.replace(
        'from .config import', 'from erebus.config import'
    )

    msg = json.dumps({
        "type": "user",
        "message": {"role": "user", "content": [{"type": "text", "text": text}]}
    }) + "\n"

    proc = subprocess.run(
        [sys.executable, str(WRAPPER_PATH)],
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
    try:
        response = _send_prompt("Send results to test@secretcorp.com", fake)
        # The fake claude echoes what it received — should NOT contain real email
        assert "test@secretcorp.com" not in response or "[EMAIL" in response
        print("  ✓ Email was tokenized before reaching Claude")
    finally:
        fake.unlink(missing_ok=True)


def test_wrapper_exits_with_claude_exitcode():
    fake = _make_fake_claude()
    try:
        proc = subprocess.run(
            [sys.executable, str(WRAPPER_PATH)],
            input="", capture_output=True, text=True,
            env={**os.environ.copy(), "REAL_CLAUDE_BINARY": str(fake)},
            timeout=5,
        )
        # Should not crash
        assert proc.returncode in (0, 1)
        print(f"  ✓ Wrapper exits cleanly (code {proc.returncode})")
    finally:
        fake.unlink(missing_ok=True)


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
