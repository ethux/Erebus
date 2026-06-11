"""Tests for the erebus-loc source line counter."""

import io
import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from erebus.audit.loc import ai_write_events_from_payload, ai_written_loc_summary, count_loc, total_stats


def _tmpdir() -> Path:
    return Path(tempfile.mkdtemp(prefix="erebus-loc-test-"))


def test_count_loc_by_language():
    tmp = _tmpdir()
    (tmp / "app.py").write_text("# comment\n\nprint('hello')\n", encoding="utf-8")
    (tmp / "web.js").write_text("// comment\nconst answer = 42;\n\n", encoding="utf-8")

    by_language = count_loc(tmp, use_git=False)

    assert by_language["Python"].files == 1
    assert by_language["Python"].code == 1
    assert by_language["Python"].comment == 1
    assert by_language["Python"].blank == 1
    assert by_language["JavaScript"].code == 1
    assert total_stats(by_language).as_dict() == {
        "files": 2,
        "code": 2,
        "comment": 2,
        "blank": 2,
        "total": 6,
    }
    print("  ✓ counts code/comment/blank lines by language")


def test_count_loc_skips_dependency_and_build_dirs():
    tmp = _tmpdir()
    (tmp / "src").mkdir()
    (tmp / "node_modules").mkdir()
    (tmp / "dist").mkdir()
    (tmp / "src" / "app.py").write_text("print('count me')\n", encoding="utf-8")
    (tmp / "node_modules" / "skip.py").write_text("print('skip me')\n", encoding="utf-8")
    (tmp / "dist" / "skip.py").write_text("print('skip me too')\n", encoding="utf-8")

    by_language = count_loc(tmp, use_git=False)

    assert by_language["Python"].files == 1
    assert by_language["Python"].code == 1
    print("  ✓ skips dependency and build directories")


def test_count_loc_unknown_files_are_opt_in():
    tmp = _tmpdir()
    (tmp / "notes.custom").write_text("first\nsecond\n", encoding="utf-8")

    assert count_loc(tmp, use_git=False) == {}

    by_language = count_loc(tmp, include_unknown=True, use_git=False)
    assert by_language["Text"].files == 1
    assert by_language["Text"].code == 2
    print("  ✓ unknown text files are opt-in")


def test_loc_cli_json_output():
    from erebus.audit import loc

    tmp = _tmpdir()
    (tmp / "pyproject.toml").write_text("# package\n[project]\n", encoding="utf-8")
    buf = io.StringIO()

    with patch("sys.argv", ["erebus-loc", str(tmp), "--repo", "--json", "--no-git"]), patch("sys.stdout", buf):
        rc = loc.main()

    payload = json.loads(buf.getvalue())
    assert rc == 0
    assert payload["languages"]["TOML"]["files"] == 1
    assert payload["languages"]["TOML"]["code"] == 1
    assert payload["languages"]["TOML"]["comment"] == 1
    print("  ✓ CLI prints JSON output")


def test_loc_cli_total_output():
    from erebus.audit import loc

    tmp = _tmpdir()
    (tmp / "one.py").write_text("# comment\nprint('one')\n", encoding="utf-8")
    (tmp / "two.py").write_text("\nprint('two')\n", encoding="utf-8")
    buf = io.StringIO()

    with patch("sys.argv", ["erebus-loc", str(tmp), "--repo", "--total", "--no-git"]), patch("sys.stdout", buf):
        rc = loc.main()

    assert rc == 0
    assert buf.getvalue() == "2\n"
    print("  ✓ CLI prints total code LOC only")


def test_ai_write_events_from_claude_write_tool():
    payload = {
        "type": "assistant",
        "message": {
            "content": [{
                "type": "tool_use",
                "name": "Write",
                "input": {
                    "file_path": "app.py",
                    "content": "# generated\n\nprint('hello')\n",
                },
            }]
        },
    }

    events = ai_write_events_from_payload(payload, source="shim")

    assert len(events) == 1
    assert events[0]["source"] == "shim"
    assert events[0]["tool"] == "Write"
    assert events[0]["file_path"] == "app.py"
    assert events[0]["code_lines"] == 1
    assert events[0]["comment_lines"] == 1
    assert events[0]["blank_lines"] == 1
    assert "content" not in events[0]
    print("  ✓ extracts AI-written LOC without storing generated content")


def test_ai_write_events_from_multiedit_tool():
    payload = {
        "name": "MultiEdit",
        "input": {
            "file_path": "app.py",
            "edits": [
                {"old_string": "old = 1\n", "new_string": "new = 1\n"},
                {"old_string": "", "new_string": "# note\nprint(new)\n"},
            ],
        },
    }

    events = ai_write_events_from_payload(payload, source="shim")

    assert len(events) == 1
    assert events[0]["operation_count"] == 2
    assert events[0]["code_lines"] == 2
    assert events[0]["comment_lines"] == 1
    assert events[0]["removed_code_lines"] == 1
    print("  ✓ aggregates AI-written LOC from MultiEdit")


def test_ai_written_loc_summary_and_default_cli():
    from erebus import config
    from erebus.audit import loc, logger

    db = Path(tempfile.mktemp(suffix="-erebus-loc-test.db"))
    original_config_db = config.DB_PATH
    original_logger_db = logger.DB_PATH
    config.DB_PATH = db
    logger.DB_PATH = db
    logger.init_db()
    try:
        logger.log_event(
            "s1",
            "ai_written_loc",
            metadata={
                "file_path": "app.py",
                "code_lines": 3,
                "comment_lines": 1,
                "blank_lines": 1,
                "total_lines": 5,
                "removed_code_lines": 1,
                "net_code_lines": 2,
            },
        )
        logger.log_event(
            "s1",
            "ai_written_loc",
            metadata={
                "file_path": "app.py",
                "code_lines": 2,
                "total_lines": 2,
                "net_code_lines": 2,
            },
        )

        summary = ai_written_loc_summary()
        assert summary["events"] == 2
        assert summary["files"] == 1
        assert summary["code_lines"] == 5
        assert summary["total_lines"] == 7
        assert summary["net_code_lines"] == 4

        buf = io.StringIO()
        with patch("sys.argv", ["erebus-loc"]), patch("sys.stdout", buf):
            rc = loc.main()
        assert rc == 0
        assert buf.getvalue() == "5\n"
        print("  ✓ default CLI prints total AI-written code LOC")
    finally:
        config.DB_PATH = original_config_db
        logger.DB_PATH = original_logger_db
        db.unlink(missing_ok=True)


if __name__ == "__main__":
    tests = [
        test_count_loc_by_language,
        test_count_loc_skips_dependency_and_build_dirs,
        test_count_loc_unknown_files_are_opt_in,
        test_loc_cli_json_output,
        test_loc_cli_total_output,
        test_ai_write_events_from_claude_write_tool,
        test_ai_write_events_from_multiedit_tool,
        test_ai_written_loc_summary_and_default_cli,
    ]
    print("\n=== LOC Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
