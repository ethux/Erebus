# pylint: disable=too-many-lines  # legacy size, slated to shrink in 004 restructure
"""
Tests for token usage logging (shim.py and proxy.py helpers).

Verifies that `usage` blocks in API responses are correctly extracted and
normalized across Anthropic and OpenAI shapes, and that cumulative streaming
deltas are NOT double-counted — only the final message per turn is logged.
"""
import importlib
import json
import os
import sqlite3
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
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
        from erebus import config
        from erebus.audit import logger
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


def test_shim_detokenizes_write_tool_use_from_persisted_map():
    """Claude file-write payloads may contain tokens from before a wrapper restart."""
    from erebus import config

    # Split-literal token: immune to detokenize-on-write rewriting this source.
    org_token = "[ORGANIZATION_9_" + "0ff1ce]"
    token_path = Path(tempfile.mktemp(suffix="-token-map.json"))
    token_path.write_text(json.dumps({
        org_token: "Example Org",
    }), encoding="utf-8")

    original_token_path = config.TOKEN_MAP_PATH
    config.TOKEN_MAP_PATH = token_path
    try:
        from erebus import shim
        importlib.reload(shim)
        shim.REPO_CONFIG.log_enabled = False
        shim.TOKEN_MAP.clear()

        msg = {
            "type": "assistant",
            "message": {
                "content": [{
                    "type": "tool_use",
                    "name": "Write",
                    "input": {
                        "file_path": "/tmp/handover.md",
                        "content": f"as with {org_token}.",
                    },
                }]
            },
        }
        restored = shim.process_incoming(json.dumps(msg))
        assert org_token not in restored
        assert "as with Example Org." in restored
        print("  ✓ shim restores persisted tokens in Write tool payloads")
    finally:
        config.TOKEN_MAP_PATH = original_token_path
        token_path.unlink(missing_ok=True)
        if "erebus.shim" in sys.modules:
            importlib.reload(sys.modules["erebus.shim"])


def test_shim_persist_token_map_preserves_disk_entries():
    from erebus import config, shim

    # Split-literal tokens: immune to detokenize-on-write rewriting this source.
    ip_token = "[IP_ADDRESS_1_" + "ab8a22]"
    person_token = "[PERSON_1_" + "abcdef]"
    token_path = Path(tempfile.mktemp(suffix="-token-map.json"))
    original_token_path = config.TOKEN_MAP_PATH
    config.TOKEN_MAP_PATH = token_path
    try:
        config.save_token_map({ip_token: "100.64.0.1"})
        shim.TOKEN_MAP.clear()
        shim.TOKEN_MAP[person_token] = "Alice"

        shim._persist_mirror()

        loaded = config.load_token_map()
        assert loaded[ip_token] == "100.64.0.1"
        assert loaded[person_token] == "Alice"
        print("  ✓ shim preserves existing token_map entries when saving")
    finally:
        config.TOKEN_MAP_PATH = original_token_path
        shim.TOKEN_MAP.clear()
        token_path.unlink(missing_ok=True)


@_with_temp_db
def test_shim_recovers_unresolved_token_from_audit_log(db: Path):
    from erebus import config, shim
    from erebus.audit import logger

    token_path = Path(tempfile.mktemp(suffix="-token-map.json"))
    original_token_path = config.TOKEN_MAP_PATH
    config.TOKEN_MAP_PATH = token_path
    shim.TOKEN_MAP.clear()
    try:
        # Split-literal token: immune to detokenize-on-write rewriting this
        # source file (TOKEN_RE matches contiguous tokens only).
        ip_token = "[IP_ADDRESS_1_" + "ab8a22]"
        logger.log_event(
            "s",
            "pii_detected",
            tokens_map={ip_token: "100.64.0.1"},
        )
        msg = {
            "type": "assistant",
            "message": {
                "content": [{
                    "type": "text",
                    "text": f"CAPI serves {ip_token}.",
                }],
            },
        }

        restored = shim.process_incoming(json.dumps(msg))

        assert ip_token not in restored
        assert "100.64.0.1" in restored
        assert config.load_token_map()[ip_token] == "100.64.0.1"
        print("  ✓ shim recovers unresolved response tokens from audit log")
    finally:
        config.TOKEN_MAP_PATH = original_token_path
        shim.TOKEN_MAP.clear()
        token_path.unlink(missing_ok=True)


@_with_temp_db
def test_shim_logs_ai_written_loc_from_write_tool(db: Path):
    from erebus import shim

    shim.REPO_CONFIG.log_enabled = True
    msg = {
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

    shim.process_incoming(json.dumps(msg))

    events = _logged_events(db)
    loc_events = [event for event in events if event["type"] == "ai_written_loc"]
    assert len(loc_events) == 1
    assert loc_events[0]["meta"]["file_path"] == "app.py"
    assert loc_events[0]["meta"]["code_lines"] == 1
    assert loc_events[0]["meta"]["comment_lines"] == 1
    assert "content" not in loc_events[0]["meta"]
    print("  ✓ shim logs AI-written LOC metadata for Write tools")


def test_shim_passthroughs_lightweight_claude_commands():
    from erebus import shim

    assert shim.should_passthrough_claude_command(["/bin/claude", "auth", "status", "--json"])
    assert shim.should_passthrough_claude_command(["/bin/claude", "mcp", "list"])
    assert shim.should_passthrough_claude_command(["/bin/claude", "--version"])
    assert not shim.should_passthrough_claude_command([
        "/bin/claude",
        "--output-format",
        "stream-json",
        "--replay-user-messages",
    ])
    assert not shim.should_passthrough_claude_command(["/bin/claude", "--print", "hello"])
    print("  ✓ shim identifies lightweight Claude commands")


def test_shim_execs_passthrough_before_logging():
    from erebus import shim

    fake = Path(tempfile.mktemp(suffix="-fake-claude"))
    fake.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake.chmod(0o755)
    original_argv = sys.argv[:]
    sys.argv = ["erebus", str(fake), "auth", "status", "--json"]
    try:
        with patch.object(shim, "init_db", side_effect=AssertionError("init_db should be bypassed")):
            with patch.object(shim, "_run_piped", side_effect=AssertionError("_run_piped should be bypassed")):
                with patch.object(shim.os, "execv", side_effect=SystemExit(0)) as execv:
                    try:
                        shim.main()
                    except SystemExit as exc:
                        assert exc.code == 0
                    else:
                        raise AssertionError("passthrough command did not exec")
        execv.assert_called_once_with(str(fake), [str(fake), "auth", "status", "--json"])
        print("  ✓ shim execs Claude utility commands before Erebus logging")
    finally:
        sys.argv = original_argv
        fake.unlink(missing_ok=True)


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


@_with_temp_db
def test_proxy_logs_ai_written_loc_from_function_call(db: Path):
    from erebus import proxy

    proxy._log_ai_written_loc_from_response({
        "output": [{
            "type": "function_call",
            "name": "Write",
            "arguments": json.dumps({
                "file_path": "app.py",
                "content": "print('from proxy')\n",
            }),
        }]
    })

    events = _logged_events(db)
    assert len(events) == 1
    assert events[0]["type"] == "ai_written_loc"
    assert events[0]["meta"]["source"] == "proxy"
    assert events[0]["meta"]["code_lines"] == 1
    assert "content" not in events[0]["meta"]
    print("  ✓ proxy logs AI-written LOC metadata for function calls")


def test_proxy_streaming_tool_call_arguments_detokenized_across_chunks():
    from erebus import proxy

    proxy.TOKEN_MAP.clear()
    proxy.TOKEN_MAP["[PERSON_1_" + "abc123]"] = "Jansen"
    buffers = {}
    emitted = {}

    first = {
        "choices": [{
            "delta": {
                "tool_calls": [{
                    "index": 0,
                    "function": {"arguments": "{\"body\":\"Hi [PERSON_"},
                }]
            }
        }]
    }
    second = {
        "choices": [{
            "delta": {
                "tool_calls": [{
                    "index": 0,
                    "function": {"arguments": "1_abc123]\"}"},
                }]
            }
        }]
    }

    proxy._detokenize_streaming_tool_calls(first, buffers, emitted)
    proxy._detokenize_streaming_tool_calls(second, buffers, emitted)

    streamed_arguments = (
        first["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
        + second["choices"][0]["delta"]["tool_calls"][0]["function"]["arguments"]
    )
    assert streamed_arguments == "{\"body\":\"Hi Jansen\"}"
    assert "[PERSON_" not in streamed_arguments
    proxy.TOKEN_MAP.clear()
    print("  ✓ proxy detokenizes streamed tool-call arguments")


def _repo_config():
    return SimpleNamespace(
        sensitive_entities=[],
        allowed_names=[],
        mode="balanced",
        blacklist=[],
        verifier="",
        verifier_llm_model="gemma3:1b",
        verifier_openai_pf_url="",
    )


def test_proxy_tokenizes_responses_payload():
    from test_catalog_helpers import IsolatedCatalogHome

    from erebus import proxy

    # Isolated home: the Boundary persists minted tokens to the Known-Value DB
    # before returning (specs/004), so the test must not write the real one.
    with IsolatedCatalogHome():
        proxy.TOKEN_MAP.clear()
        payload = {
            "model": "gpt-5.5",
            "instructions": "Keep john@example.com private",
            "input": [{
                "role": "user",
                "content": [{"type": "input_text", "text": "Email jane@example.com"}],
            }],
        }

        sanitized, tokens = proxy._tokenize_responses_payload(payload, _repo_config())
        raw = json.dumps(sanitized)
        assert "john@example.com" not in raw
        assert "jane@example.com" not in raw
        assert len(tokens) == 2
        assert proxy._detokenize_payload(sanitized)["instructions"] == "Keep john@example.com private"
        proxy.TOKEN_MAP.clear()
    print("  ✓ proxy tokenizes Responses API payloads")


def test_proxy_responses_streaming_output_delta_detokenized_across_chunks():
    from erebus import proxy

    proxy.TOKEN_MAP.clear()
    proxy.TOKEN_MAP["[PERSON_1_" + "abc123]"] = "Jansen"
    buffers = {}
    emitted = {}
    first = {
        "type": "response.output_text.delta",
        "item_id": "msg_1",
        "output_index": 0,
        "content_index": 0,
        "delta": "Hi [PERSON_",
    }
    second = {
        "type": "response.output_text.delta",
        "item_id": "msg_1",
        "output_index": 0,
        "content_index": 0,
        "delta": "1_abc123]",
    }

    assert proxy._detokenize_responses_streaming_chunk(first, buffers, emitted)
    assert proxy._detokenize_responses_streaming_chunk(second, buffers, emitted)
    assert first["delta"] + second["delta"] == "Hi Jansen"
    assert "[PERSON_" not in first["delta"] + second["delta"]
    proxy.TOKEN_MAP.clear()
    print("  ✓ proxy detokenizes Responses output deltas")


@_with_temp_db
def test_proxy_responses_streaming_recovers_unresolved_token_from_audit(db: Path):
    from erebus import config, proxy
    from erebus.audit import logger

    token_path = Path(tempfile.mktemp(suffix="-token-map.json"))
    original_token_path = config.TOKEN_MAP_PATH
    config.TOKEN_MAP_PATH = token_path
    proxy.TOKEN_MAP.clear()
    try:
        # Split-literal token: immune to detokenize-on-write rewriting this source.
        ip_token = "[IP_ADDRESS_1_" + "ab8a22]"
        logger.log_event(
            "s",
            "pii_detected",
            tokens_map={ip_token: "100.64.0.1"},
        )
        chunk = {
            "type": "response.output_text.delta",
            "item_id": "msg_1",
            "output_index": 0,
            "content_index": 0,
            "delta": f"CAPI serves {ip_token}.",
        }

        assert proxy._ensure_response_tokens_loaded(json.dumps(chunk))
        assert proxy._detokenize_responses_streaming_chunk(chunk, {}, {})
        assert chunk["delta"] == "CAPI serves 100.64.0.1."
        assert config.load_token_map()[ip_token] == "100.64.0.1"
        print("  ✓ proxy recovers unresolved Codex stream tokens from audit log")
    finally:
        config.TOKEN_MAP_PATH = original_token_path
        proxy.TOKEN_MAP.clear()
        token_path.unlink(missing_ok=True)


def test_proxy_responses_streaming_function_arguments_detokenized():
    from erebus import proxy

    proxy.TOKEN_MAP.clear()
    proxy.TOKEN_MAP["[EMAIL_ADDRESS_1_" + "abc123]"] = "jansen@example.com"
    buffers = {}
    emitted = {}
    first = {
        "type": "response.function_call_arguments.delta",
        "item_id": "call_1",
        "output_index": 1,
        "delta": "{\"email\":\"[EMAIL_ADDRESS_",
    }
    second = {
        "type": "response.function_call_arguments.delta",
        "item_id": "call_1",
        "output_index": 1,
        "delta": "1_abc123]\"}",
    }

    proxy._detokenize_responses_streaming_chunk(first, buffers, emitted)
    proxy._detokenize_responses_streaming_chunk(second, buffers, emitted)
    assert first["delta"] + second["delta"] == "{\"email\":\"jansen@example.com\"}"
    proxy.TOKEN_MAP.clear()
    print("  ✓ proxy detokenizes Responses function arguments")


# ── tokenization cache ───────────────────────────────────────────────────────

def test_cached_tokenize_reuses_identical_text():
    from erebus import filter as erebus_filter
    from erebus.core import tokenizer

    calls = {"count": 0}

    def fake_tokenize(text, *args, **kwargs):
        calls["count"] += 1
        return text.replace("secret", "[SENSITIVE_1_" "abc123]"), {
            "[SENSITIVE_1_" "abc123]": "secret",
        }

    erebus_filter.clear_tokenize_cache()
    try:
        with patch.object(tokenizer, "tokenize", side_effect=fake_tokenize):
            first = erebus_filter.cached_tokenize("repeatable secret")
            second = erebus_filter.cached_tokenize("repeatable secret")
            second[1]["[SENSITIVE_2_" "def456]"] = "mutated"
            third = erebus_filter.cached_tokenize("repeatable secret")

        assert calls["count"] == 1
        assert first[0] == second[0] == third[0]
        assert "[SENSITIVE_2_" "def456]" not in third[1]
        print("  ✓ cached_tokenize reuses exact text safely")
    finally:
        erebus_filter.clear_tokenize_cache()


def test_proxy_tokenize_text_uses_cache_for_repeated_history():
    from erebus import filter as erebus_filter
    from erebus import proxy
    from erebus.core import tokenizer

    calls = {"count": 0}

    def fake_tokenize(text, *args, **kwargs):
        calls["count"] += 1
        return text, {}

    erebus_filter.clear_tokenize_cache()
    try:
        with patch.object(tokenizer, "tokenize", side_effect=fake_tokenize):
            proxy._tokenize_proxy_text("history line repeated by the client", _repo_config())
            proxy._tokenize_proxy_text("history line repeated by the client", _repo_config())

        assert calls["count"] == 1
        print("  ✓ proxy skips re-tokenizing repeated history text")
    finally:
        erebus_filter.clear_tokenize_cache()


def test_proxy_allows_16mb_request_bodies():
    from erebus import proxy

    if proxy.web is None or proxy.httpx is None:
        assert proxy.PROXY_CLIENT_MAX_SIZE == 16 * 1024 * 1024
        print("  ✓ proxy config allows request bodies up to 16MB")
        return

    app = proxy.create_app()

    assert app._client_max_size == 16 * 1024 * 1024
    print("  ✓ proxy allows request bodies up to 16MB")


# ── logger.usage_summary ──────────────────────────────────────────────────────

@_with_temp_db
def test_usage_summary_aggregates(db: Path):
    """Multiple token_usage events should sum correctly in the summary."""
    from erebus import shim
    from erebus.audit.logger import usage_summary
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
        test_shim_detokenizes_write_tool_use_from_persisted_map,
        test_shim_persist_token_map_preserves_disk_entries,
        test_shim_recovers_unresolved_token_from_audit_log,
        test_shim_logs_ai_written_loc_from_write_tool,
        test_shim_passthroughs_lightweight_claude_commands,
        test_shim_execs_passthrough_before_logging,
        test_proxy_logs_anthropic_format,
        test_proxy_logs_openai_format,
        test_proxy_skips_missing_usage,
        test_proxy_logs_ai_written_loc_from_function_call,
        test_proxy_streaming_tool_call_arguments_detokenized_across_chunks,
        test_proxy_tokenizes_responses_payload,
        test_proxy_responses_streaming_output_delta_detokenized_across_chunks,
        test_proxy_responses_streaming_recovers_unresolved_token_from_audit,
        test_proxy_responses_streaming_function_arguments_detokenized,
        test_cached_tokenize_reuses_identical_text,
        test_proxy_tokenize_text_uses_cache_for_repeated_history,
        test_proxy_allows_16mb_request_bodies,
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
