"""Regression tests for proxy tokenization latency (specs/003-proxy-tokenize-latency).

The GLiNER detector is mocked throughout, so these tests are hermetic (no model
download, no daemon) and assert the *code paths* that bound detector cost:
window-chunking, the NER ceiling, the cached instructions block, and daemon
telemetry.
"""
from __future__ import annotations

import json
import os
import socket
import sys
import time
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_catalog_helpers import IsolatedCatalogHome

from erebus import config, proxy
from erebus import filter as ef
from erebus.core import cache_disk, detect

# ── US1: large tool output is bounded; cheap passes still protect it ──────────

def test_above_ceiling_skips_ner_but_keeps_regex():
    """Text above NER_CEILING_CHARS must not call the detector, yet email/secret
    regex must still tokenize."""
    ef.clear_tokenize_cache()
    email = "alice" + "@" + "example.test"
    aws = "AKIA" + "A" * 16
    filler = "lorem ipsum dolor sit amet " * 5000  # ~135 KB, well over the ceiling
    text = filler + f" reach {email} key {aws} " + filler
    assert len(text) > ef.NER_CEILING_CHARS

    with patch.object(detect, "_predict_entities", return_value=[]) as predict:
        sanitized, tokens = ef.cached_tokenize(text, mode="strict")

    assert predict.call_count == 0, "detector was invoked on an oversized block"
    values = set(tokens.values())
    assert email in values, "email not tokenized by the cheap pass above the ceiling"
    assert aws in values, "AWS key not tokenized by the cheap pass above the ceiling"
    assert email not in sanitized and aws not in sanitized


def test_large_tool_turn_is_fast():
    """A ~100 KB payload is sanitized well under one second (SC-004)."""
    ef.clear_tokenize_cache()
    email = "bob" + "@" + "example.test"
    text = ("x" * 100_000) + f" mail {email}"

    with patch.object(detect, "_predict_entities", return_value=[]):
        start = time.perf_counter()
        _sanitized, tokens = ef.cached_tokenize(text, mode="strict")
        elapsed = time.perf_counter() - start

    assert elapsed < 1.0, f"sanitization took {elapsed:.3f}s"
    assert email in set(tokens.values())


def test_windowed_offsets_roundtrip_and_dedupe():
    """A PERSON entity straddling a window boundary is detected once (overlap
    deduped) and the result round-trips losslessly."""
    ef.clear_tokenize_cache()
    sentinel = "Zaphodbeeblebrox"
    # Length between one window and the ceiling, sentinel inside the overlap
    # region [step, window) = [1350, 1500) so it appears in two windows.
    head = "lorem ipsum " * 116  # 1392 chars, pushes sentinel start to ~1392
    text = head + sentinel + (" dolor sit amet" * 250)
    assert ef.NER_WINDOW_CHARS < len(text) <= ef.NER_CEILING_CHARS
    s_start = text.index(sentinel)
    assert ef.NER_WINDOW_CHARS - ef.NER_WINDOW_OVERLAP <= s_start < ef.NER_WINDOW_CHARS

    def fake_many(texts):
        out = []
        for t in texts:
            spans = []
            i = t.find(sentinel)
            while i != -1:
                spans.append({"start": i, "end": i + len(sentinel),
                              "label": "person", "text": sentinel})
                i = t.find(sentinel, i + 1)
            out.append(spans)
        return out

    with patch.object(detect, "_predict_entities_many", side_effect=fake_many):
        sanitized, tokens = ef.cached_tokenize(text, mode="strict")

    person_tokens = [tok for tok, val in tokens.items() if val == sentinel]
    assert len(person_tokens) == 1, f"expected one token, got {person_tokens}"
    assert sentinel not in sanitized

    restored = sanitized
    for tok, val in tokens.items():
        restored = restored.replace(tok, val)
    assert restored == text, "windowed tokenization did not round-trip"


# ── US2: the stable instructions block is detected once and reused ────────────

def test_instructions_block_cached_across_turns():
    """The Responses non-input block is stored on the first turn and reapplied
    from cache on an identical second turn (the wiring handle_proxy uses)."""
    with IsolatedCatalogHome():
        proxy._MSG_CACHE.clear()
        cfg = config.RepoConfig()
        email = "carol" + "@" + "example.test"
        instructions = f"You are a helpful agent. Operator contact is {email} for support"

        with patch.object(detect, "_predict_entities", return_value=[]), \
             patch.object(detect, "_predict_entities_many", side_effect=lambda texts: [[] for _ in texts]):
            # Turn 1 — miss: tokenize + store.
            item1 = {"instructions": instructions}
            key = proxy.message_cache_key("responses-non-input", item1, cfg)
            assert key is not None
            original = json.loads(json.dumps(item1))
            sanitized_item, tokens = proxy._tokenize_responses_payload(item1, cfg)
            assert email not in sanitized_item["instructions"]
            assert email in set(tokens.values())
            proxy.store_message_cache_entry(key, original, sanitized_item, tokens, save=True)

            # Turn 2 — identical block: must hit cache and reapply the same tokens
            # WITHOUT re-running detection.
            item2 = {"instructions": instructions}
            collected: dict = {}
            with patch.object(proxy, "_tokenize_responses_payload",
                              side_effect=AssertionError("re-tokenized cached block")):
                hit = proxy.apply_message_cache_entry(key, item2, collected, "responses_non_input")

        assert hit is True, "identical instructions block missed the cache"
        assert email not in item2["instructions"]
        assert item2["instructions"] == sanitized_item["instructions"]
        assert collected, "cached tokens were not recorded on the hit"


# ── Security: degraded detection must not poison the clean-fingerprint cache ──

def test_degraded_detection_is_not_cached_as_clean():
    """If NER could not run (daemon down), a no-token result must NOT be stored
    as a durable 'clean' fingerprint — otherwise a transient outage would forward
    NER-class PII verbatim on every resent turn."""
    text = "Please call Jan de Vries about the contract today"  # NER-only PII, no regex hits
    key = ef._tokenize_cache_key(text, None, None, "strict", None, None, "gemma3:1b", "")

    # Degraded run: detector unavailable -> marks degraded, finds nothing.
    ef.clear_tokenize_cache()

    def degraded_predict(_t):
        ef._mark_detector_degraded("daemon_unavailable")
        return []

    with patch.object(detect, "_predict_entities", side_effect=degraded_predict):
        _s, tokens = ef.cached_tokenize(text, mode="strict")
    assert tokens == {}
    assert key not in ef._TOKENIZE_CLEAN_CACHE, "degraded result was cached as clean"

    # Healthy run: detector ran and genuinely found nothing -> clean cache is OK.
    ef.clear_tokenize_cache()
    with patch.object(detect, "_predict_entities", return_value=[]):
        ef.cached_tokenize(text, mode="strict")
    assert key in ef._TOKENIZE_CLEAN_CACHE, "healthy clean result was not cached"


def test_degraded_token_bearing_result_not_cached():
    """A degraded pass that still minted tokens (regex caught the email, NER
    missed the name) must not be stored in the memory or disk caches — it would
    replay the under-filtered text even after the daemon recovers."""
    email = "dave" + "@" + "example.test"
    text = f"Ask Jan de Vries to mail {email} about the contract"
    key = ef._tokenize_cache_key(text, None, None, "strict", None, None, "gemma3:1b", "")

    ef.clear_tokenize_cache()

    def degraded_predict(_t):
        ef._mark_detector_degraded("daemon_unavailable")
        return []

    with patch.object(detect, "_predict_entities", side_effect=degraded_predict) as predict:
        _s, tokens = ef.cached_tokenize(text, mode="strict")
        assert email in set(tokens.values()), "regex pass should still tokenize the email"
        assert key not in ef._TOKENIZE_CACHE, "degraded token-bearing result was memory-cached"
        assert ef._disk_cache_key(key) not in ef._DISK_CACHE, "degraded token-bearing result was disk-cached"

        # An identical resent turn must re-run detection, not replay the cache.
        ef.cached_tokenize(text, mode="strict")
        assert predict.call_count == 2, "degraded result was replayed from cache"

    # Healthy run afterwards: the full result is cached again.
    ef.clear_tokenize_cache()
    with patch.object(detect, "_predict_entities", return_value=[]):
        ef.cached_tokenize(text, mode="strict")
    assert key in ef._TOKENIZE_CACHE, "healthy token-bearing result was not cached"
    ef.clear_tokenize_cache()


def test_turn_degraded_flag_is_sticky_across_calls():
    """turn_degraded() aggregates across all detection calls in a request:
    the per-call reset inside cached_tokenize must not clear it, and
    begin_detection_turn() must."""
    ef.clear_tokenize_cache()
    ef.begin_detection_turn()
    assert not ef.turn_degraded()

    name_text = "Contact Jan de Vries please"
    plain_text = "nothing sensitive in this one"

    def degraded_predict(_t):
        ef._mark_detector_degraded("daemon_unavailable")
        return []

    with patch.object(detect, "_predict_entities", side_effect=degraded_predict):
        ef.cached_tokenize(name_text, mode="strict")
    assert ef.turn_degraded(), "degraded call did not set the turn flag"
    assert ef.turn_degraded_reason() == "daemon_unavailable"

    # A later healthy call in the same turn resets only the per-call flag.
    with patch.object(detect, "_predict_entities", return_value=[]):
        ef.cached_tokenize(plain_text, mode="strict")
    assert ef.turn_degraded(), "healthy call cleared the turn-scoped flag"

    ef.begin_detection_turn()
    assert not ef.turn_degraded()
    ef.clear_tokenize_cache()


def test_message_cache_store_skipped_when_turn_degraded():
    """The proxy message cache must not record entries for a degraded turn —
    a cached 'no changes' patch would bypass detection on every later turn."""
    with IsolatedCatalogHome():
        proxy._MSG_CACHE.clear()
        cfg = config.RepoConfig()
        msg = {"role": "user", "content": "Contact Jan de Vries please"}
        key = proxy.message_cache_key("chat", msg, cfg)
        assert key is not None

        ef.begin_detection_turn()
        ef._mark_detector_degraded("daemon_unavailable")
        proxy.store_message_cache_entry(key, msg, msg, {})
        assert key not in proxy._MSG_CACHE, "degraded turn was stored in the message cache"

        ef.begin_detection_turn()
        proxy.store_message_cache_entry(key, msg, msg, {})
        assert key in proxy._MSG_CACHE, "healthy turn was not stored in the message cache"
        proxy._MSG_CACHE.clear()


def test_degraded_header_on_regular_response():
    """A degraded turn is signalled to the client via X-Erebus-Degraded."""
    import asyncio

    class FakeResp:
        status_code = 200
        content = b"{}"
        headers: dict = {}  # noqa: RUF012

    class FakeClient:
        async def request(self, *args, **kwargs):
            return FakeResp()

    cfg = config.RepoConfig()
    resp = asyncio.run(proxy._handle_regular(
        FakeClient(), "POST", "http://upstream.test/v1/chat/completions",
        {}, b"{}", False, cfg, degraded_reason="daemon_unavailable"))
    assert resp.headers["X-Erebus-Degraded"] == "daemon_unavailable"

    resp = asyncio.run(proxy._handle_regular(
        FakeClient(), "POST", "http://upstream.test/v1/chat/completions",
        {}, b"{}", False, cfg))
    assert "X-Erebus-Degraded" not in resp.headers


def test_old_disk_cache_version_is_dropped():
    """Cache files written before the degraded-guard fix (version < 5) are
    invalidated wholesale on load."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp:
        cache_path = Path(tmp) / "tokenize_cache.json"
        with patch.object(cache_disk, "_DISK_CACHE_PATH", cache_path):
            ef.clear_tokenize_cache()
            cache_path.write_text(json.dumps({
                "version": 4,
                "entries": {"deadbeef": ["sanitized [EMAIL_1_x]", {"[EMAIL_1_x]": "a@b.test"}]},
                "clean": ["cafebabe"],
            }))
            ef._load_disk_cache()
            assert ef._DISK_CACHE == {}, "stale-version entries survived the load"
            assert set() == ef._DISK_CLEAN_CACHE, "stale-version clean fingerprints survived"
            assert not cache_path.exists(), "stale-version cache file was not dropped"
            ef.clear_tokenize_cache()


# ── US3: detector telemetry is real and emitted ──────────────────────────────

def test_daemon_emits_gliner_inference_telemetry():
    """handle_client emits a gliner_inference perf event via the real perf
    module (not the fallback no-op)."""
    from erebus.runtime import daemon

    assert daemon.log_perf_event.__module__ == "erebus.perf", \
        "daemon is using the fallback no-op perf logger (perf module not importable)"

    class FakeModel:
        def predict_entities(self, text, labels, threshold):
            return []

    a, b = socket.socketpair()
    try:
        a.sendall(json.dumps({"text": "nothing sensitive here"}).encode() + b"\n")
        with patch.object(daemon, "log_perf_event") as logged:
            daemon.handle_client(b, FakeModel())
        events = [c.args[0] for c in logged.call_args_list if c.args]
        assert "gliner_inference" in events, f"no gliner_inference event: {events}"
        resp = a.recv(65536)
        assert json.loads(resp.split(b"\n", 1)[0]) == []
    finally:
        a.close()


if __name__ == "__main__":
    tests = [
        test_above_ceiling_skips_ner_but_keeps_regex,
        test_large_tool_turn_is_fast,
        test_windowed_offsets_roundtrip_and_dedupe,
        test_instructions_block_cached_across_turns,
        test_degraded_detection_is_not_cached_as_clean,
        test_degraded_token_bearing_result_not_cached,
        test_turn_degraded_flag_is_sticky_across_calls,
        test_message_cache_store_skipped_when_turn_degraded,
        test_degraded_header_on_regular_response,
        test_old_disk_cache_version_is_dropped,
        test_daemon_emits_gliner_inference_telemetry,
    ]
    for test in tests:
        test()
        print(f"  ✓ {test.__name__}")
    print("All proxy tokenize latency tests passed.")
