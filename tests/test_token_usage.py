"""
Tests for token usage logging (shim.py and proxy.py helpers).

Verifies that `usage` blocks in API responses are correctly extracted and
normalized across Anthropic and OpenAI shapes, and that cumulative streaming
deltas are NOT double-counted — only the final message per turn is logged.
"""
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _fresh_db() -> Path:
    """Create a temporary DB and monkeypatch DB_PATH for the duration of a test."""
    return Path(tempfile.mktemp(suffix="-erebus-test.db"))


def _logged_events(db: Path) -> list[dict]:
    if not db.exists():
        return []
    conn = sqlite3.connect(db)
    rows = conn.execute(
        "SELECT event_type, metadata FROM events ORDER BY id"
    ).fetchall()
    conn.close()
    return [{"type": t, "meta": json.loads(m) if m else {}} for t, m in rows]


def _with_temp_db(fn):
    """Decorator: run `fn` with a fresh DB and patched DB_PATH everywhere it's used."""
    def wrapper():
        db = _fresh_db()
        from erebus import config, logger
        original = config.DB_PATH
        config.DB_PATH = db
        logger.DB_PATH = db
        logger.init_db()
        try:
            fn(db)
        finally:
            config.DB_PATH = original
            logger.DB_PATH = original
            db.unlink(missing_ok=True)
    wrapper.__name__ = fn.__name__
    return wrapper


# ── shim.py: _log_usage_if_present ───────────────────────────────────────────

@_with_temp_db
def test_shim_logs_final_anthropic_message(db: Path):
    """Claude Code wraps the final message — we should log its usage."""
    from erebus import shim
    shim._log_usage_if_present({
        "type": "assistant",
        "message": {
            "model": "claude-opus-4",
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 20,
                "cache_creation_input_tokens": 100,
                "cache_read_input_tokens": 5000,
            },
        },
    })
    events = _logged_events(db)
    assert len(events) == 1
    assert events[0]["type"] == "token_usage"
    assert events[0]["meta"]["input_tokens"] == 10
    assert events[0]["meta"]["output_tokens"] == 20
    assert events[0]["meta"]["cache_read_input_tokens"] == 5000
    assert events[0]["meta"]["model"] == "claude-opus-4"
    print("  ✓ shim logs final wrapped message")


@_with_temp_db
def test_shim_skips_non_final_delta(db: Path):
    """Intermediate message_delta without stop_reason should NOT be logged."""
    from erebus import shim
    shim._log_usage_if_present({
        "type": "message_delta",
        "delta": {},  # no stop_reason yet
        "usage": {"output_tokens": 5},
    })
    assert _logged_events(db) == []
    print("  ✓ shim skips non-final delta")


@_with_temp_db
def test_shim_logs_message_start(db: Path):
    """message_start carries initial input tokens and should be logged."""
    from erebus import shim
    shim._log_usage_if_present({
        "type": "message_start",
        "message": {"id": "msg_1", "model": "claude-opus-4"},
        "usage": {"input_tokens": 500, "cache_read_input_tokens": 1000},
    })
    events = _logged_events(db)
    assert len(events) == 1
    assert events[0]["meta"]["input_tokens"] == 500
    assert events[0]["meta"]["cache_read_input_tokens"] == 1000
    print("  ✓ shim logs message_start")


@_with_temp_db
def test_shim_skips_all_zero_usage(db: Path):
    """A final message with all-zero counts is noise and should not be stored."""
    from erebus import shim
    shim._log_usage_if_present({
        "type": "assistant",
        "message": {
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 0, "output_tokens": 0,
                "cache_creation_input_tokens": 0, "cache_read_input_tokens": 0,
            },
        },
    })
    assert _logged_events(db) == []
    print("  ✓ shim skips all-zero usage")


@_with_temp_db
def test_shim_ignores_non_dict(db: Path):
    from erebus import shim
    shim._log_usage_if_present(None)  # type: ignore[arg-type]
    shim._log_usage_if_present("a string")  # type: ignore[arg-type]
    shim._log_usage_if_present(42)  # type: ignore[arg-type]
    assert _logged_events(db) == []
    print("  ✓ shim tolerates non-dict input")


# ── proxy.py: _log_usage_from_response ───────────────────────────────────────

@_with_temp_db
def test_proxy_logs_anthropic_format(db: Path):
    from erebus import proxy
    proxy._log_usage_from_response({
        "model": "claude-opus-4",
        "usage": {
            "input_tokens": 50,
            "output_tokens": 100,
            "cache_creation_input_tokens": 200,
            "cache_read_input_tokens": 3000,
        },
    })
    events = _logged_events(db)
    assert len(events) == 1
    assert events[0]["meta"]["input_tokens"] == 50
    assert events[0]["meta"]["cache_read_input_tokens"] == 3000
    assert events[0]["meta"]["source"] == "proxy"
    print("  ✓ proxy logs Anthropic-format response")


@_with_temp_db
def test_proxy_logs_openai_format(db: Path):
    """OpenAI uses prompt_tokens/completion_tokens — normalize to our schema."""
    from erebus import proxy
    proxy._log_usage_from_response({
        "model": "gpt-4",
        "usage": {
            "prompt_tokens": 123,
            "completion_tokens": 456,
            "total_tokens": 579,
        },
    })
    events = _logged_events(db)
    assert len(events) == 1
    assert events[0]["meta"]["input_tokens"] == 123
    assert events[0]["meta"]["output_tokens"] == 456
    assert events[0]["meta"]["cache_creation_input_tokens"] == 0
    assert events[0]["meta"]["cache_read_input_tokens"] == 0
    print("  ✓ proxy logs OpenAI-format response")


@_with_temp_db
def test_proxy_skips_missing_usage(db: Path):
    from erebus import proxy
    proxy._log_usage_from_response({"model": "x", "choices": []})
    proxy._log_usage_from_response({})
    proxy._log_usage_from_response({"usage": None})
    assert _logged_events(db) == []
    print("  ✓ proxy skips responses without usage")


# ── logger.usage_summary ──────────────────────────────────────────────────────

@_with_temp_db
def test_usage_summary_aggregates(db: Path):
    """Multiple token_usage events should sum correctly in the summary."""
    from erebus import shim
    from erebus.logger import usage_summary
    for _ in range(3):
        shim._log_usage_if_present({
            "type": "assistant",
            "message": {
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 10, "output_tokens": 20,
                          "cache_creation_input_tokens": 0,
                          "cache_read_input_tokens": 1000},
            },
        })
    # Capture stdout
    import io
    buf = io.StringIO()
    with patch("sys.stdout", buf):
        usage_summary()
    out = buf.getvalue()
    import re
    # Whitespace between label and count is format-dependent; just match digits.
    assert re.search(r"turns logged:\s+3\b", out), f"didn't find 'turns logged: 3' in:\n{out}"
    assert "30" in out   # input_tokens total
    assert "60" in out   # output_tokens total
    assert "3,000" in out   # cache_read total
    print("  ✓ usage_summary aggregates across events")


if __name__ == "__main__":
    tests = [
        test_shim_logs_final_anthropic_message,
        test_shim_skips_non_final_delta,
        test_shim_logs_message_start,
        test_shim_skips_all_zero_usage,
        test_shim_ignores_non_dict,
        test_proxy_logs_anthropic_format,
        test_proxy_logs_openai_format,
        test_proxy_skips_missing_usage,
        test_usage_summary_aggregates,
    ]
    print("\n=== Token Usage Tests ===\n")
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            print(f"  ✗ {t.__name__}: {e}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
