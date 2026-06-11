# pylint: disable=too-many-lines  # legacy size, slated to shrink in 004 restructure
"""
Tests for batched proxy tokenization.

These stay fully mocked so they exercise cache/batching behavior without
loading the GLiNER model or touching the daemon.
"""
import importlib
import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


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


def _reset_proxy_message_cache(proxy, cache_path: Path):
    from erebus import filter as erebus_filter

    original_path = proxy._MSG_CACHE_PATH
    proxy._MSG_CACHE_PATH = cache_path
    proxy._MSG_CACHE.clear()
    proxy._MSG_CACHE_DIRTY = False
    proxy._MSG_CACHE_DIRTY_KEYS.clear()
    proxy._MSG_CACHE_LOADED = False
    # Stores are skipped on degraded turns; start a fresh turn the way
    # handle_proxy does so flags from earlier tests can't leak in.
    erebus_filter.begin_detection_turn()
    return original_path


def _reset_perf_log(perf, perf_path: Path):
    original_path = perf.PERF_LOG_PATH
    original_env = os.environ.get("EREBUS_PERF_LOG")
    perf.PERF_LOG_PATH = perf_path
    os.environ["EREBUS_PERF_LOG"] = "1"
    perf_path.unlink(missing_ok=True)
    return original_path, original_env


def _restore_perf_log(perf, original_path: Path, original_env: str | None, perf_path: Path):
    perf.PERF_LOG_PATH = original_path
    if original_env is None:
        os.environ.pop("EREBUS_PERF_LOG", None)
    else:
        os.environ["EREBUS_PERF_LOG"] = original_env
    perf_path.unlink(missing_ok=True)


def test_cached_tokenize_many_batches_uncached_texts():
    from erebus import filter as erebus_filter
    from erebus.core import cache_disk, detect

    calls = []
    cache_path = Path(tempfile.mktemp(suffix="-tokenize-cache.json"))
    original_cache_path = cache_disk._DISK_CACHE_PATH

    def fake_predict_many(texts):
        calls.append(list(texts))
        batches = []
        for text in texts:
            start = text.find("alpha beta")
            batches.append([{
                "start": start,
                "end": start + len("alpha beta"),
                "text": "alpha beta",
                "label": "organization",
            }])
        return batches

    texts = ["first alpha beta", "second alpha beta", "third alpha beta"]
    cache_disk._DISK_CACHE_PATH = cache_path
    erebus_filter.clear_tokenize_cache()
    try:
        with patch.object(detect, "_predict_entities_many", side_effect=fake_predict_many):
            first = erebus_filter.cached_tokenize_many(texts)
            second = erebus_filter.cached_tokenize_many(texts)

        assert len(calls) == 1
        assert calls[0] == texts
        assert all("<EREBUS_BATCH_" not in text for text in calls[0])
        assert all("alpha beta" not in item[0] for item in first)
        assert all("[ORGANIZATION_" in item[0] for item in first)
        assert second == first
        print("  ✓ cached_tokenize_many batches misses and reuses cache hits")
    finally:
        erebus_filter.clear_tokenize_cache()
        cache_disk._DISK_CACHE_PATH = original_cache_path
        cache_path.unlink(missing_ok=True)


def test_cached_tokenize_writes_privacy_safe_perf_events():
    from erebus import filter as erebus_filter
    from erebus import perf
    from erebus.core import cache_disk, tokenizer

    calls = {"count": 0}
    cache_path = Path(tempfile.mktemp(suffix="-tokenize-cache.json"))
    perf_path = Path(tempfile.mktemp(suffix="-perf.jsonl"))
    original_cache_path = cache_disk._DISK_CACHE_PATH
    original_perf_path, original_perf_env = _reset_perf_log(perf, perf_path)

    def fake_tokenize(text, *args, **kwargs):
        calls["count"] += 1
        return text.replace("telemetry secret customer", "[SENSITIVE_1_" "abc123]"), {
            "[SENSITIVE_1_" "abc123]": "telemetry secret customer",
        }

    cache_disk._DISK_CACHE_PATH = cache_path
    erebus_filter.clear_tokenize_cache()
    try:
        with patch.object(tokenizer, "tokenize", side_effect=fake_tokenize):
            first = erebus_filter.cached_tokenize("ask about telemetry secret customer")
            second = erebus_filter.cached_tokenize("ask about telemetry secret customer")

        assert calls["count"] == 1
        assert first == second
        events = perf.read_perf_events(path=perf_path)
        cache_events = [event for event in events if event.get("event") == "tokenize_cache"]
        assert len(cache_events) >= 2
        assert cache_events[0]["cache_result"] == "miss"
        assert cache_events[-1]["cache_result"] == "memory"
        assert cache_events[0]["stored"] in {"disk", "memory_only", "disk_pending"}
        raw = perf_path.read_text(encoding="utf-8")
        assert "telemetry secret customer" not in raw
        assert "ask about" not in raw
        print("  ✓ cached_tokenize writes privacy-safe perf telemetry")
    finally:
        erebus_filter.clear_tokenize_cache()
        cache_disk._DISK_CACHE_PATH = original_cache_path
        cache_path.unlink(missing_ok=True)
        _restore_perf_log(perf, original_perf_path, original_perf_env, perf_path)


def test_cached_tokenize_fingerprints_large_clean_texts_in_memory():
    from erebus import filter as erebus_filter
    from erebus.core import cache, cache_disk, tokenizer

    calls = {"count": 0}
    cache_path = Path(tempfile.mktemp(suffix="-tokenize-cache.json"))
    cache_path_attr = next(
        name for name, value in vars(cache_disk).items()
        if isinstance(value, Path) and value.name == "tokenize_cache.json"
    )
    original_cache_path = getattr(cache_disk, cache_path_attr)
    long_text = "safe history line " * 3000
    assert len(long_text) > cache._TOKENIZE_CACHE_MAX_TEXT_CHARS

    def fake_tokenize(text, *args, **kwargs):
        calls["count"] += 1
        return text, {}

    setattr(cache_disk, cache_path_attr, cache_path)
    erebus_filter.clear_tokenize_cache()
    try:
        with patch.object(tokenizer, "tokenize", side_effect=fake_tokenize):
            first = erebus_filter.cached_tokenize(long_text)
            second = erebus_filter.cached_tokenize(long_text)

        assert calls["count"] == 1
        assert first == (long_text, {})
        assert second == first
        clean_keys = list(cache._TOKENIZE_CLEAN_CACHE.keys())
        assert clean_keys
        assert all(long_text not in repr(key) for key in clean_keys)
        assert isinstance(clean_keys[-1][0], tuple)
        print("  ✓ large clean tokenize cache entries use fingerprints, not resident text")
    finally:
        erebus_filter.clear_tokenize_cache()
        setattr(cache_disk, cache_path_attr, original_cache_path)
        cache_path.unlink(missing_ok=True)


def test_predict_entities_does_not_load_gliner_in_client_process():
    from erebus.core import detect
    from erebus.runtime import daemon

    predict_attr = next(
        name for name in dir(daemon)
        if "predict" in name and "via" in name and "daemon" in name and "many" not in name
    )
    ensure_attr = next(name for name in dir(daemon) if "ensure" in name and "daemon" in name)
    gliner_attr = next(name for name in dir(detect) if "get" in name and "gliner" in name)

    with patch.object(daemon, predict_attr, return_value=None) as predict:
        with patch.object(daemon, ensure_attr) as ensure:
            with patch.object(detect, gliner_attr, side_effect=AssertionError("local GLiNER should not load")):
                assert detect._predict_entities("Alice") == []

    assert predict.call_count == 2
    ensure.assert_called_once()
    print("  ✓ single-text GLiNER misses do not load a client-local model")


def test_predict_entities_many_does_not_load_gliner_in_client_process():
    from erebus.core import detect
    from erebus.runtime import daemon

    batch_attr = next(
        name for name in dir(daemon)
        if "predict" in name and "via" in name and "daemon" in name and ("many" in name or "batch" in name)
    )
    single_attr = next(
        name for name in dir(daemon)
        if "predict" in name and "via" in name and "daemon" in name and "many" not in name
    )
    ensure_attr = next(name for name in dir(daemon) if "ensure" in name and "daemon" in name)
    gliner_attr = next(name for name in dir(detect) if "get" in name and "gliner" in name)

    with patch.object(daemon, batch_attr, return_value=None) as batch:
        with patch.object(daemon, single_attr, return_value=None) as single:
            with patch.object(daemon, ensure_attr) as ensure:
                with patch.object(detect, gliner_attr, side_effect=AssertionError("local GLiNER should not load")):
                    assert detect._predict_entities_many(["Alice", "Bob"]) == [[], []]

    assert batch.call_count == 2
    assert single.call_count == 1
    ensure.assert_called_once()
    print("  ✓ batch GLiNER misses do not load a client-local model")


def test_perf_summary_reports_cache_and_cpu_without_raw_values():
    import io

    from erebus import perf

    perf_path = Path(tempfile.mktemp(suffix="-perf.jsonl"))
    original_perf_path, original_perf_env = _reset_perf_log(perf, perf_path)
    try:
        perf.log_perf_event(
            "tokenize_cache",
            wall_ms=25.0,
            cpu_ms=20.0,
            cpu_pct=80.0,
            cache_result="miss",
            text_count=1,
            text_chars=len("sensitive customer text"),
            token_count=2,
        )
        buf = io.StringIO()
        with patch("sys.stdout", buf):
            perf.perf_summary(limit=20)
        out = buf.getvalue()
        assert "tokenize_cache" in out
        assert "miss=1" in out
        assert "CPU avg/max" in out
        assert "sensitive customer text" not in out
        print("  ✓ perf summary reports cache/CPU without raw values")
    finally:
        _restore_perf_log(perf, original_perf_path, original_perf_env, perf_path)


def test_proxy_responses_payload_tokenizes_texts_in_one_batch():
    from test_catalog_helpers import IsolatedCatalogHome

    from erebus import proxy

    calls = []

    def fake_cached_tokenize_many(texts, *args, **kwargs):
        calls.append(list(texts))
        results = []
        for i, text in enumerate(texts, start=1):
            tok = f"[PERSON_{i}_abc123]"
            results.append((text.replace("sample customer", tok), {tok: "sample customer"}))
        return results

    payload = {
        "instructions": "first sample customer",
        "input": [{
            "role": "user",
            "content": [{"type": "input_text", "text": "second sample customer"}],
        }],
    }

    # Isolated home: the Boundary persists minted tokens to the Known-Value DB
    # before returning (specs/004), so the test must not write the real one.
    with IsolatedCatalogHome():
        with patch("erebus.proxy.cached_tokenize_many", side_effect=fake_cached_tokenize_many):
            sanitized, tokens = proxy._tokenize_responses_payload(payload, _repo_config())

    assert len(calls) == 1
    assert calls[0] == ["first sample customer", "second sample customer"]
    assert sanitized["instructions"] == "first [PERSON_1_" "abc123]"
    assert sanitized["input"][0]["content"][0]["text"] == "second [PERSON_2_" "abc123]"
    assert sorted(tokens) == ["[PERSON_1_" "abc123]", "[PERSON_2_" "abc123]"]
    print("  ✓ Responses payload strings are tokenized in one batch")


def test_disk_cache_save_merges_external_entries():
    from erebus import filter as erebus_filter
    from erebus.core import cache_disk

    cache_path = Path(tempfile.mktemp(suffix="-tokenize-cache.json"))
    original_cache_path = cache_disk._DISK_CACHE_PATH
    cache_disk._DISK_CACHE_PATH = cache_path
    erebus_filter.clear_tokenize_cache()
    try:
        cache_path.write_text(
            json.dumps({"version": cache_disk._DISK_CACHE_VERSION, "entries": {
                "external": ["external [PERSON_1_" "abcdef]", {"[PERSON_1_" "abcdef]": "external"}],
            }}),
            encoding="utf-8",
        )
        key = erebus_filter._tokenize_cache_key(
            "local text", None, None, "balanced", None, None, "gemma3:1b", "",
        )

        erebus_filter._store_tokenize_result(key, "local [PERSON_2_" "abcdef]", {"[PERSON_2_" "abcdef]": "local"})

        entries = json.loads(cache_path.read_text(encoding="utf-8"))["entries"]
        assert "external" in entries
        assert erebus_filter._disk_cache_key(key) in entries
        print("  ✓ disk cache saves merge sibling-process entries")
    finally:
        erebus_filter.clear_tokenize_cache()
        cache_disk._DISK_CACHE_PATH = original_cache_path
        cache_path.unlink(missing_ok=True)


def test_large_clean_history_uses_fingerprint_cache_after_restart():
    from erebus import filter as erebus_filter
    from erebus.core import cache, cache_disk, tokenizer

    calls = []
    cache_path = Path(tempfile.mktemp(suffix="-tokenize-cache.json"))
    original_cache_path = cache_disk._DISK_CACHE_PATH
    long_text = "safe old Codex history line " * 10_000

    def fake_tokenize(text, *args, **kwargs):
        calls.append(text)
        return text, {}

    cache_disk._DISK_CACHE_PATH = cache_path
    erebus_filter.clear_tokenize_cache()
    try:
        with patch.object(tokenizer, "tokenize", side_effect=fake_tokenize):
            first = erebus_filter.cached_tokenize(long_text)

        assert first == (long_text, {})
        assert calls == [long_text]
        raw = cache_path.read_text(encoding="utf-8")
        assert long_text[:80] not in raw
        assert "\"clean\"" in raw

        with cache._TOKENIZE_CACHE_LOCK:
            cache._TOKENIZE_CACHE.clear()
            cache._TOKENIZE_CLEAN_CACHE.clear()
        cache_disk._DISK_CACHE.clear()
        cache_disk._DISK_CLEAN_CACHE.clear()
        cache_disk._DISK_CACHE_LOADED = False

        with patch.object(tokenizer, "tokenize", side_effect=AssertionError("model should stay cached")):
            second = erebus_filter.cached_tokenize(long_text)

        assert second == (long_text, {})
        print("  ✓ large clean history uses fingerprint cache after restart")
    finally:
        erebus_filter.clear_tokenize_cache()
        cache_disk._DISK_CACHE_PATH = original_cache_path
        cache_path.unlink(missing_ok=True)


def test_message_cache_stores_clean_large_history_as_fingerprint():
    from erebus import proxy

    cache_path = Path(tempfile.mktemp(suffix="-message-cache.json"))
    original_path = _reset_proxy_message_cache(proxy, cache_path)
    long_text = "safe history line " * 20_000
    item = {"role": "user", "content": [{"type": "input_text", "text": long_text}]}

    try:
        key = proxy.message_cache_key("responses-input", item, _repo_config())
        proxy.store_message_cache_entry(key, item, item, {})
        proxy.save_message_cache()

        raw = cache_path.read_text(encoding="utf-8")
        assert long_text[:80] not in raw
        assert len(raw) < 2000

        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_LOADED = False
        replay = json.loads(json.dumps(item))
        assert proxy.apply_message_cache_entry(key, replay, {})
        assert replay == item
        print("  ✓ message cache fingerprints clean large Codex history")
    finally:
        proxy._MSG_CACHE_PATH = original_path
        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_DIRTY_KEYS.clear()
        proxy._MSG_CACHE_DIRTY = False
        proxy._MSG_CACHE_LOADED = False
        cache_path.unlink(missing_ok=True)


def test_message_cache_writes_privacy_safe_perf_events():
    from erebus import perf, proxy

    cache_path = Path(tempfile.mktemp(suffix="-message-cache.json"))
    perf_path = Path(tempfile.mktemp(suffix="-perf.jsonl"))
    original_path = _reset_proxy_message_cache(proxy, cache_path)
    original_perf_path, original_perf_env = _reset_perf_log(perf, perf_path)
    original = {"role": "user", "content": [{"type": "input_text", "text": "Call Alice"}]}
    sanitized = {"role": "user", "content": [{"type": "input_text", "text": "Call [PERSON_1_" "abcdef]"}]}
    tokens = {"[PERSON_1_" "abcdef]": "Alice"}

    try:
        key = proxy.message_cache_key("responses-input", original, _repo_config())
        proxy.store_message_cache_entry(key, original, sanitized, tokens)
        proxy.save_message_cache()

        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_LOADED = False
        proxy.TOKEN_MAP["[PERSON_1_" "abcdef]"] = "Alice"
        replay = json.loads(json.dumps(original))
        collected = {}
        assert proxy.apply_message_cache_entry(key, replay, collected, "responses_input")
        assert replay == sanitized
        assert collected == tokens

        events = perf.read_perf_events(path=perf_path)
        store_events = [event for event in events if event.get("event") == "message_cache_store"]
        hit_events = [event for event in events if event.get("event") == "message_cache"]
        assert store_events[-1]["cache_result"] == "stored"
        assert hit_events[-1]["cache_result"] == "hit"
        raw = perf_path.read_text(encoding="utf-8")
        assert "Alice" not in raw
        assert "Call Alice" not in raw
        print("  ✓ message cache writes privacy-safe perf telemetry")
    finally:
        proxy.TOKEN_MAP.pop("[PERSON_1_" "abcdef]", None)
        proxy._MSG_CACHE_PATH = original_path
        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_DIRTY_KEYS.clear()
        proxy._MSG_CACHE_DIRTY = False
        proxy._MSG_CACHE_LOADED = False
        cache_path.unlink(missing_ok=True)
        _restore_perf_log(perf, original_perf_path, original_perf_env, perf_path)


def test_message_cache_replays_large_pii_history_with_compact_spans():
    from erebus import proxy

    cache_path = Path(tempfile.mktemp(suffix="-message-cache.json"))
    original_path = _reset_proxy_message_cache(proxy, cache_path)
    long_prefix = "safe history line " * 20_000
    long_suffix = " more safe history " * 20_000
    original_text = f"{long_prefix}Call Alice{long_suffix}"
    sanitized_text = f"{long_prefix}Call [PERSON_1_" f"abcdef]{long_suffix}"
    original = {"role": "user", "content": [{"type": "input_text", "text": original_text}]}
    sanitized = {"role": "user", "content": [{"type": "input_text", "text": sanitized_text}]}
    tokens = {"[PERSON_1_" "abcdef]": "Alice"}

    try:
        key = proxy.message_cache_key("responses-input", original, _repo_config())
        proxy.store_message_cache_entry(key, original, sanitized, tokens)
        proxy.save_message_cache()

        raw = cache_path.read_text(encoding="utf-8")
        assert original_text[:80] not in raw
        assert sanitized_text[:80] not in raw
        assert "Alice" not in raw
        assert "[PERSON_1_" "abcdef]" in raw
        assert len(raw) < 3000

        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_LOADED = False
        proxy.TOKEN_MAP["[PERSON_1_" "abcdef]"] = "Alice"
        replay = json.loads(json.dumps(original))
        collected = {}

        assert proxy.apply_message_cache_entry(key, replay, collected)
        assert replay == sanitized
        assert collected == tokens
        print("  ✓ message cache replays large PII history with compact spans")
    finally:
        proxy.TOKEN_MAP.pop("[PERSON_1_" "abcdef]", None)
        proxy._MSG_CACHE_PATH = original_path
        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_DIRTY_KEYS.clear()
        proxy._MSG_CACHE_DIRTY = False
        proxy._MSG_CACHE_LOADED = False
        cache_path.unlink(missing_ok=True)


def test_message_cache_skips_uncacheable_large_changes():
    from erebus import proxy

    cache_path = Path(tempfile.mktemp(suffix="-message-cache.json"))
    original_path = _reset_proxy_message_cache(proxy, cache_path)
    original_text = ("safe history line " * 20_000) + "Call Alice"
    sanitized_text = ("different safe history line " * 20_000) + "Call [PERSON_1_" "abcdef]"
    original = {"role": "user", "content": [{"type": "input_text", "text": original_text}]}
    sanitized = {"role": "user", "content": [{"type": "input_text", "text": sanitized_text}]}
    tokens = {"[PERSON_1_" "abcdef]": "Alice"}

    try:
        key = proxy.message_cache_key("responses-input", original, _repo_config())
        proxy.store_message_cache_entry(key, original, sanitized, tokens)

        assert key not in proxy._MSG_CACHE
        assert not cache_path.exists()
        print("  ✓ message cache skips uncacheable large changes")
    finally:
        proxy._MSG_CACHE_PATH = original_path
        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_DIRTY_KEYS.clear()
        proxy._MSG_CACHE_DIRTY = False
        proxy._MSG_CACHE_LOADED = False
        cache_path.unlink(missing_ok=True)


def test_message_cache_replays_pii_patches_without_raw_values_on_disk():
    from erebus import proxy

    cache_path = Path(tempfile.mktemp(suffix="-message-cache.json"))
    original_path = _reset_proxy_message_cache(proxy, cache_path)
    original = {"role": "user", "content": [{"type": "input_text", "text": "Call Alice"}]}
    sanitized = {"role": "user", "content": [{"type": "input_text", "text": "Call [PERSON_1_" "abcdef]"}]}
    tokens = {"[PERSON_1_" "abcdef]": "Alice"}

    try:
        key = proxy.message_cache_key("responses-input", original, _repo_config())
        proxy.store_message_cache_entry(key, original, sanitized, tokens)
        proxy.save_message_cache()

        raw = cache_path.read_text(encoding="utf-8")
        assert "Alice" not in raw
        assert "[PERSON_1_" "abcdef]" in raw

        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_LOADED = False
        proxy.TOKEN_MAP["[PERSON_1_" "abcdef]"] = "Alice"
        replay = json.loads(json.dumps(original))
        collected = {}

        assert proxy.apply_message_cache_entry(key, replay, collected)
        assert replay == sanitized
        assert collected == tokens
        print("  ✓ message cache replays PII patches without raw disk values")
    finally:
        proxy.TOKEN_MAP.pop("[PERSON_1_" "abcdef]", None)
        proxy._MSG_CACHE_PATH = original_path
        proxy._MSG_CACHE.clear()
        proxy._MSG_CACHE_DIRTY_KEYS.clear()
        proxy._MSG_CACHE_DIRTY = False
        proxy._MSG_CACHE_LOADED = False
        cache_path.unlink(missing_ok=True)


def test_existing_placeholder_is_not_retokenized():
    from erebus import filter as erebus_filter
    from erebus.core import detect

    text = "Alice [PERSON_1_" "abcdef]"
    entity = [{
        "start": 0,
        "end": len(text),
        "text": text,
        "label": "person",
    }]

    with patch.object(detect, "_predict_entities", return_value=entity):
        sanitized, tokens = erebus_filter.tokenize(text, mode="balanced")

    assert sanitized == text
    assert tokens == {}
    print("  ✓ existing token placeholders are not re-tokenized")


def test_detokenize_resolves_token_chains():
    from erebus.filter import detokenize

    token_map = {
        "[PERSON_1_" "abcdef]": "[PERSON_2_" "123456]",
        "[PERSON_2_" "123456]": "Restored Value",
    }

    assert detokenize("Hello [PERSON_1_" "abcdef]", token_map) == "Hello Restored Value"
    print("  ✓ detokenize resolves nested token chains")


def test_proxy_loads_and_refreshes_persisted_token_map():
    from erebus import config

    token_path = Path(tempfile.mktemp(suffix="-token-map.json"))
    original_token_path = config.TOKEN_MAP_PATH
    config.TOKEN_MAP_PATH = token_path
    try:
        config.save_token_map({
            "[PERSON_1_" "abcdef]": "[PERSON_2_" "123456]",
            "[PERSON_2_" "123456]": "Persisted Value",
        })

        from erebus import proxy
        proxy = importlib.reload(proxy)
        assert proxy.TOKEN_MAP.get("[PERSON_1_" "abcdef]") == "[PERSON_2_" "123456]"

        proxy.TOKEN_MAP.clear()
        restored = proxy._detokenize_text("Hello [PERSON_1_" "abcdef]")

        assert restored == "Hello Persisted Value"
        assert proxy.TOKEN_MAP["[PERSON_2_" "123456]"] == "Persisted Value"
        print("  ✓ proxy loads and refreshes persisted token maps")
    finally:
        config.TOKEN_MAP_PATH = original_token_path
        token_path.unlink(missing_ok=True)
        if "erebus.proxy" in sys.modules:
            importlib.reload(sys.modules["erebus.proxy"])


def test_gliner_daemon_inference_writes_privacy_safe_perf_event():
    import socket

    from erebus import perf
    from erebus.runtime import daemon

    class FakeModel:
        def inference(self, texts, labels, threshold=0.7, batch_size=8):
            return [
                [{"start": 0, "end": 5, "label": "person", "text": "Alice"}]
                if text == "Alice" else []
                for text in texts
            ]

    perf_path = Path(tempfile.mktemp(suffix="-perf.jsonl"))
    original_perf_path, original_perf_env = _reset_perf_log(perf, perf_path)
    server_sock, client_sock = socket.socketpair()
    try:
        client_sock.sendall(json.dumps({
            "texts": ["Alice", "clean text"],
            "threshold": 0.5,
            "batch_size": 2,
        }).encode() + b"\n")
        client_sock.shutdown(socket.SHUT_WR)

        daemon.handle_client(server_sock, FakeModel())
        data = b""
        while True:
            chunk = client_sock.recv(65536)
            if not chunk:
                break
            data += chunk

        assert json.loads(data) == [[{"start": 0, "end": 5, "label": "person", "text": "Alice"}], []]
        events = perf.read_perf_events(path=perf_path)
        gliner_events = [event for event in events if event.get("event") == "gliner_inference"]
        assert gliner_events
        assert gliner_events[-1]["text_count"] == 2
        assert gliner_events[-1]["text_chars"] == len("Alice") + len("clean text")
        assert gliner_events[-1]["batch_size"] == 2
        assert gliner_events[-1]["entity_count"] == 1
        raw = perf_path.read_text(encoding="utf-8")
        assert "Alice" not in raw
        assert "clean text" not in raw
        print("  ✓ GLiNER daemon writes privacy-safe inference perf telemetry")
    finally:
        client_sock.close()
        _restore_perf_log(perf, original_perf_path, original_perf_env, perf_path)


def test_gliner_daemon_liveness_rejects_stale_pid_without_socket():
    from erebus.runtime import daemon

    pid_path = Path(tempfile.mktemp(suffix="-gliner.pid"))
    socket_path = Path(tempfile.mktemp(suffix="-gliner.sock"))
    original_pid_path = daemon.PID_PATH
    original_socket_path = daemon.SOCKET_PATH
    daemon.PID_PATH = str(pid_path)
    daemon.SOCKET_PATH = str(socket_path)
    try:
        pid_path.write_text(str(os.getpid()), encoding="utf-8")

        assert not daemon.is_daemon_running()
        print("  ✓ GLiNER daemon liveness rejects stale pid without socket")
    finally:
        daemon.PID_PATH = original_pid_path
        daemon.SOCKET_PATH = original_socket_path
        pid_path.unlink(missing_ok=True)
        socket_path.unlink(missing_ok=True)


def test_gliner_daemon_singleton_lock_admits_one():
    """The singleton lock guarantees only one daemon can hold it at a time, so
    only one process ever loads the model (the spawn-race memory fix)."""
    from erebus.runtime import daemon

    lock_path = Path(tempfile.mktemp(suffix="-gliner.lock"))
    original = daemon.LOCK_PATH
    daemon.LOCK_PATH = str(lock_path)
    first = second = None
    try:
        first = daemon._acquire_singleton_lock()
        assert first is not None, "first daemon should acquire the lock"
        second = daemon._acquire_singleton_lock()
        assert second is None, "a second daemon must be refused while one holds it"

        os.close(first)
        first = None
        third = daemon._acquire_singleton_lock()
        assert third is not None, "lock should be free again after the holder exits"
        os.close(third)
        print("  \u2713 GLiNER daemon singleton lock admits exactly one")
    finally:
        for fd in (first, second):
            if fd is not None:
                os.close(fd)
        daemon.LOCK_PATH = original
        lock_path.unlink(missing_ok=True)


if __name__ == "__main__":
    tests = [
        test_cached_tokenize_many_batches_uncached_texts,
        test_cached_tokenize_writes_privacy_safe_perf_events,
        test_cached_tokenize_fingerprints_large_clean_texts_in_memory,
        test_predict_entities_does_not_load_gliner_in_client_process,
        test_predict_entities_many_does_not_load_gliner_in_client_process,
        test_perf_summary_reports_cache_and_cpu_without_raw_values,
        test_proxy_responses_payload_tokenizes_texts_in_one_batch,
        test_disk_cache_save_merges_external_entries,
        test_large_clean_history_uses_fingerprint_cache_after_restart,
        test_message_cache_stores_clean_large_history_as_fingerprint,
        test_message_cache_writes_privacy_safe_perf_events,
        test_message_cache_replays_large_pii_history_with_compact_spans,
        test_message_cache_skips_uncacheable_large_changes,
        test_message_cache_replays_pii_patches_without_raw_values_on_disk,
        test_existing_placeholder_is_not_retokenized,
        test_detokenize_resolves_token_chains,
        test_proxy_loads_and_refreshes_persisted_token_map,
        test_gliner_daemon_inference_writes_privacy_safe_perf_event,
        test_gliner_daemon_liveness_rejects_stale_pid_without_socket,
        test_gliner_daemon_singleton_lock_admits_one,
    ]
    print("\n=== Batch Tokenize Tests ===\n")
    passed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as exc:
            print(f"  ✗ {test.__name__}: {exc}")
    print(f"\n{passed}/{len(tests)} passed\n")
    sys.exit(0 if passed == len(tests) else 1)
