"""Tests for erebus-check-file (erebus/commands/check_file.py).

The checker reports what is physically on disk — token-shaped strings, their
liveness against the current token map, and a count of real map values —
without ever printing file content or real values.
"""
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.commands import check_file as cf

# Split-literal tokens: built by concatenation so detokenize-on-write (which
# matches contiguous TOKEN_RE only) can never rewrite these into their values
# inside this source file.
PERSON_TOKEN = "[PERSON_1_" + "abc123]"
ORG_TOKEN = "[ORGANIZATION_9_" + "0ff1ce]"


def _tmp_file(content: str) -> Path:
    path = Path(tempfile.mktemp(suffix="-check-file.txt"))
    path.write_text(content, encoding="utf-8")
    return path


def test_clean_file_reports_no_tokens():
    path = _tmp_file("nothing token-shaped in here at all")
    try:
        report = cf.check_file(path, {PERSON_TOKEN: "Alice"})
        assert report["token_count"] == 0
        assert report["live_tokens"] == []
        assert report["unknown_tokens"] == []
        assert report["real_values_from_map"] == 0
        assert report["sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
        print("  ✓ clean file reports no tokens")
    finally:
        path.unlink(missing_ok=True)


def test_live_and_unknown_tokens_are_separated():
    path = _tmp_file(f"live {PERSON_TOKEN} and synthetic {ORG_TOKEN} here")
    try:
        report = cf.check_file(path, {PERSON_TOKEN: "Alice"})
        assert report["token_count"] == 2
        assert report["live_tokens"] == [PERSON_TOKEN]
        assert report["unknown_tokens"] == [ORG_TOKEN]
        print("  ✓ live and unknown tokens are separated")
    finally:
        path.unlink(missing_ok=True)


def test_real_values_counted_but_never_printed():
    path = _tmp_file("the file holds Alice in plain text")
    try:
        report = cf.check_file(path, {PERSON_TOKEN: "Alice"})
        assert report["real_values_from_map"] == 1
        serialized = json.dumps(report)
        assert "Alice" not in serialized, "report leaked a real value"
        print("  ✓ real values are counted but never included in the report")
    finally:
        path.unlink(missing_ok=True)


def test_cli_exit_codes_and_json():
    import subprocess
    clean = _tmp_file("no tokens")
    tokened = _tmp_file(f"contains {PERSON_TOKEN}")
    env = dict(os.environ)
    try:
        # No live map in a fresh HOME -> token is "unknown", exit 0.
        with tempfile.TemporaryDirectory() as fake_home:
            env["HOME"] = fake_home
            result = subprocess.run(
                [sys.executable, "-m", "erebus.commands.check_file", "--json",
                 str(clean), str(tokened)],
                capture_output=True, text=True, env=env,
                cwd=os.path.join(os.path.dirname(__file__), ".."),
            )
            assert result.returncode == 0, result.stderr
            reports = [json.loads(line) for line in result.stdout.splitlines()]
            assert reports[0]["token_count"] == 0
            assert reports[1]["unknown_tokens"] == [PERSON_TOKEN]

            # With a live map containing the token -> exit 2.
            erebus_dir = Path(fake_home) / ".erebus"
            erebus_dir.mkdir()
            (erebus_dir / "token_map.json").write_text(json.dumps({
                "version": 2, "created_at": "2999-01-01T00:00:00+00:00",
                "entries": {PERSON_TOKEN: "Alice"},
            }))
            result = subprocess.run(
                [sys.executable, "-m", "erebus.commands.check_file", str(tokened)],
                capture_output=True, text=True, env=env,
                cwd=os.path.join(os.path.dirname(__file__), ".."),
            )
            assert result.returncode == 2, (result.stdout, result.stderr)
            assert PERSON_TOKEN in result.stdout
            assert "Alice" not in result.stdout, "CLI output leaked a real value"

        # Unreadable file -> exit 1.
        result = subprocess.run(
            [sys.executable, "-m", "erebus.commands.check_file", "/nonexistent/x"],
            capture_output=True, text=True, env=env,
            cwd=os.path.join(os.path.dirname(__file__), ".."),
        )
        assert result.returncode == 1
        print("  ✓ CLI exit codes and JSON output behave")
    finally:
        clean.unlink(missing_ok=True)
        tokened.unlink(missing_ok=True)


if __name__ == "__main__":
    print("\n=== Check File Tests ===\n")
    tests = [
        test_clean_file_reports_no_tokens,
        test_live_and_unknown_tokens_are_separated,
        test_real_values_counted_but_never_printed,
        test_cli_exit_codes_and_json,
    ]
    passed = 0
    for test in tests:
        test()
        passed += 1
    print(f"\n{passed}/{len(tests)} passed")
