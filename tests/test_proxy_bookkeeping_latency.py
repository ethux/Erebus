"""Regression tests for the proxy's per-request bookkeeping cost (2026-09-05).

Codex turns through the proxy added 3-25 s before the upstream call, and long
streams stalled until Codex hit its SSE idle timeout. GLiNER was not the cause;
the proxy's own bookkeeping was:

  * a message-cache hit whose token keys no longer resolve fell into a full
    scan of the audit log (3.4 GB live) on EVERY turn, because nothing
    remembered the miss and the poisoned entry was never evicted;
  * expired escape allowances were never swept (174k rows live) and were
    re-scanned on every store generation bump;
  * ``word~`` escapes matched code (``~/path``, ``~~strike~~``) and each match
    was a store write, which bumped the generation and rewrote the legacy map;
  * the known-value pre-scan probed every stored value against every cached
    item's text;
  * the whole tokenize pass ran synchronously on the aiohttp event loop, and
    the streaming detokenizer probed every stored token against the whole
    growing buffer on every SSE delta.

Detector calls are stubbed; assertions are on artifacts (sqlite rows, the
model-bound text, the emitted stream text, call counts).
"""
from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.dirname(__file__))

from boundary.helpers import IsolatedBoundaryHome, daemon_stub, fake_clock, person_entity, run

NAME = "Jan Modaal"  # synthetic fixture
ORPHAN = "[PERSON_9_" "deadbe]"


def _rows(db_path, sql: str, params=()):
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute(sql, params).fetchall()
    finally:
        conn.close()


# ── 1. audit-log token recovery is bounded and never repeated per token ──────

def test_audit_recovery_not_repeated_for_unresolvable_token():
    """One audit scan per unresolvable token per retry window, not one per turn."""
    with IsolatedBoundaryHome() as env, fake_clock() as clk:
        from erebus.audit import logger
        from erebus.core import knownvalues
        logger.init_db()
        knownvalues._UNRESOLVABLE.clear()
        db = env.open_db()
        try:
            with patch.object(logger, "lookup_token_values", wraps=logger.lookup_token_values) as scan:
                assert db.resolve_missing({ORPHAN}) == {}
                assert db.resolve_missing({ORPHAN}) == {}
                assert scan.call_count == 1, f"audit log rescanned for a known-unresolvable token ({scan.call_count}x)"
                clk.advance(seconds=knownvalues._AUDIT_RETRY_SECONDS + 1)
                assert db.resolve_missing({ORPHAN}) == {}
                assert scan.call_count == 2, "retry window did not reopen the audit lookup"
        finally:
            db.close()
            knownvalues._UNRESOLVABLE.clear()


def test_audit_recovery_scans_only_recent_rows():
    """The recovery query is bounded to the most recent rows; it never walks
    the whole events table."""
    with IsolatedBoundaryHome():
        from erebus.audit import logger
        logger.init_db()
        old = "[PERSON_1_" "aaaaaa]"
        recent = "[PERSON_2_" "bbbbbb]"
        insert = "INSERT INTO events (session_id, event_type, tokens_map) VALUES (?, ?, ?)"
        conn = sqlite3.connect(str(logger.DB_PATH))
        try:
            conn.execute(insert, ("s", "pii_detected", json.dumps({old: "Old Value"})))
            conn.executemany(insert, [
                ("s", "pii_detected", json.dumps({f"[PERSON_9_{i:06x}]": "filler"}))
                for i in range(logger.AUDIT_RECOVERY_MAX_ROWS)])
            conn.execute(insert, ("s", "pii_detected", json.dumps({recent: "Recent Value"})))
            conn.commit()
        finally:
            conn.close()
        assert logger.lookup_token_values({old, recent}) == {recent: "Recent Value"}


# ── 2. a cached item whose tokens are gone is re-tokenized, not replayed ──────

def test_message_cache_hit_with_unresolvable_tokens_becomes_a_miss():
    from erebus.core import message_cache as mc
    mc._MSG_CACHE.clear()
    mc._MSG_CACHE_LOADED = True
    key = "entry-with-ghost-token"
    mc._MSG_CACHE[key] = {"patches": [{"path": ["content"], "value": f"hi {ORPHAN}"}], "tokens": [ORPHAN]}
    item = {"content": f"hi {NAME}"}
    collected: dict = {}
    try:
        hit = mc.apply_message_cache_entry(key, item, collected, "responses_input",
                                           record_tokens=lambda _keys, _out: False)
        assert hit is False, "entry with unresolvable tokens was replayed as a hit"
        assert item == {"content": f"hi {NAME}"}, f"item was patched before its tokens resolved: {item!r}"
        assert key not in mc._MSG_CACHE, "poisoned entry was not evicted"
        assert collected == {}
    finally:
        mc._MSG_CACHE.clear()


def test_proxy_retokenizes_item_whose_cached_tokens_are_gone():
    """End-to-end through the Responses adapter: the ghost token never reaches
    the model, the value is tokenized afresh, and the cache holds the new entry."""
    with IsolatedBoundaryHome() as env, fake_clock():
        from erebus import proxy
        from erebus.core import knownvalues
        from erebus.core import message_cache as mc
        from erebus.proxy import tokenmap
        mc._MSG_CACHE.clear()
        mc._MSG_CACHE_LOADED = True
        proxy.TOKEN_MAP.clear()
        knownvalues._UNRESOLVABLE.clear()
        tokenmap._BOUNDARY = None
        cfg = env.repo_config(mode="strict")
        item = {"type": "message", "role": "user",
                "content": [{"type": "input_text", "text": f"Bel {NAME} morgen."}]}
        key = mc.message_cache_key("responses-input", item, cfg)
        mc._MSG_CACHE[key] = {
            "patches": [{"path": ["content", 0, "text"], "value": f"Bel {ORPHAN} morgen."}],
            "tokens": [ORPHAN]}
        body = {"model": "m", "input": [json.loads(json.dumps(item))]}
        try:
            with daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
                out, new_tokens, _turn = proxy.tokenize_responses_request(body, cfg)
            text = out["input"][0]["content"][0]["text"]
            assert ORPHAN not in text, f"ghost token replayed to the model: {text!r}"
            assert NAME not in text, f"value leaked raw after eviction: {text!r}"
            assert new_tokens and set(new_tokens.values()) == {NAME}, new_tokens
            fresh = mc._MSG_CACHE.get(key)
            assert fresh is not None and ORPHAN not in fresh["tokens"], fresh
        finally:
            mc._MSG_CACHE.clear()
            proxy.TOKEN_MAP.clear()
            knownvalues._UNRESOLVABLE.clear()
            tokenmap._BOUNDARY = None


# ── 3. escape allowances: swept, deduplicated, and cheap to read ─────────────

def test_expired_allowances_are_swept_on_open():
    with IsolatedBoundaryHome() as env, fake_clock() as clk:
        db = env.open_db()
        try:
            for i in range(3):
                db.grant_allowance(f"value {i}", window_min=5)
            assert len(_rows(env.global_db_path(), "SELECT value FROM escape_allowances")) == 3
        finally:
            db.close()
        clk.advance(minutes=10)
        db = env.open_db()
        try:
            assert _rows(env.global_db_path(), "SELECT value FROM escape_allowances") == [], \
                "expired allowances survived a store open"
            assert db.active_allowances() == {}
        finally:
            db.close()


def test_repeated_escape_grant_is_not_a_store_write():
    """Replaying the same escape (every turn resends the history) must not
    bump the generation or add rows; it only extends the window when the
    existing allowance is past its half-life."""
    with IsolatedBoundaryHome() as env, fake_clock() as clk:
        path = env.global_db_path()
        db = env.open_db()
        try:
            db.grant_allowance(NAME, window_min=10)
            gen = _rows(path, "SELECT generation FROM meta")[0][0]
            first_expiry = _rows(path, "SELECT expires_at FROM escape_allowances")[0][0]
            clk.advance(minutes=1)
            db.grant_allowance(NAME, window_min=10)
            assert _rows(path, "SELECT generation FROM meta")[0][0] == gen, "re-grant bumped the generation"
            assert len(_rows(path, "SELECT value FROM escape_allowances")) == 1
            clk.advance(minutes=6)  # past the half-life: extend, still one row
            db.grant_allowance(NAME, window_min=10)
            rows = _rows(path, "SELECT expires_at FROM escape_allowances")
            assert len(rows) == 1 and rows[0][0] > first_expiry, rows
        finally:
            db.close()


def test_active_allowances_does_not_parse_expired_rows():
    with IsolatedBoundaryHome() as env, fake_clock():
        from erebus.core import knownvalues
        db = env.open_db()
        try:
            db.grant_allowance(NAME, window_min=10)
            insert = ("INSERT INTO escape_allowances (value, granted_at, expires_at, source)"
                      " VALUES (?, '2026-01-01T00:00:00+00:00', '2026-01-01T00:05:00+00:00', 'test')")
            conn = sqlite3.connect(str(env.global_db_path()))
            try:
                conn.executemany(insert, [(f"stale {i}",) for i in range(1000)])
                conn.commit()
            finally:
                conn.close()
            with patch.object(knownvalues, "_parse_iso", wraps=knownvalues._parse_iso) as parse:
                active = db.active_allowances()
            assert set(active) == {NAME}
            assert parse.call_count <= 1, f"expired rows were fetched and parsed ({parse.call_count})"
        finally:
            db.close()


# ── 4. ``~`` escapes: words only, never code ────────────────────────────────

def test_parse_escapes_ignores_code_tildes():
    from erebus.core.escapes import _parse_escapes
    for sample in ("see ~/.erebus/config now", "x ~~strike~~ y", "a~b c", "$x =~ /re/ ok",
                   "path/~user ok", "lone ~ tilde", "-~ dash"):
        escaped, cleaned = _parse_escapes(sample)
        assert escaped == set(), f"{sample!r} produced escapes {escaped}"
        assert cleaned == sample, f"{sample!r} was rewritten to {cleaned!r}"
    escaped, cleaned = _parse_escapes('Ask Jan de Vries~ ("Smith~") now')
    assert {"jan", "de", "vries", "jan de vries", "smith"} <= escaped, escaped
    assert "~" not in cleaned


# ── 5. known-value pre-scan probes only candidate values ─────────────────────

class _CountingStr(str):
    checks = 0

    def __contains__(self, item):
        type(self).checks += 1
        return str.__contains__(self, item)


def test_prescan_probes_only_candidate_values():
    from erebus.core.knownvalues import KnownValueView
    from erebus.core.prescan import KnownValuePrescan
    tokens = {f"[PERSON_{i}_{i:06x}]": f"Value Number {i}" for i in range(5000)}
    tokens["[PERSON_9_" "ffffff]"] = "Li"  # short: word-bounded path
    view = KnownValueView(tokens, {v: k for k, v in tokens.items()}, 1)
    prescan = KnownValuePrescan()

    text = _CountingStr("plain prose without any stored value in it " * 40)
    _CountingStr.checks = 0
    assert prescan.apply(text, view) == str(text)
    assert _CountingStr.checks < 50, f"{_CountingStr.checks} substring probes for {len(tokens)} values"

    out = prescan.apply("call Value Number 42 or Li about Value Number 4999, not Lithium", view)
    assert "[PERSON_42_" in out and "[PERSON_4999_" in out and "[PERSON_9_" in out, out
    assert "Value Number" not in out and "Lithium" in out and " Li " not in f" {out} ", out


# ── 6. the event loop keeps serving while a request tokenizes ────────────────

def test_tokenize_pass_runs_off_the_event_loop():
    with IsolatedBoundaryHome() as env, fake_clock():
        from erebus.proxy import app as proxy_app
        from erebus.proxy import tokenmap
        tokenmap._BOUNDARY = None
        seen: dict = {}

        def slow_turn(*_args, **_kwargs):
            seen["thread"] = threading.current_thread().name
            time.sleep(0.3)
            return b"{}", "chat", "", False

        class FakeResp:
            status_code = 200
            content = b"{}"
            headers: dict = {}  # noqa: RUF012

        class FakeClient:
            async def request(self, *_a, **_k):
                return FakeResp()

        class FakeRequest:
            method = "POST"
            path = "/responses"
            query_string = ""
            headers = {"content-type": "application/json"}  # noqa: RUF012

            def __init__(self, app):
                self.app = app

            async def read(self):
                return b'{"input": []}'

        executor = ThreadPoolExecutor(max_workers=1)
        app = {"repo_config": env.repo_config(), "http_client": FakeClient(),
               "target_url": "http://upstream.test", "tokenize_executor": executor}
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.02)
                ticks += 1

        async def main():
            task = asyncio.ensure_future(ticker())
            try:
                with patch.object(proxy_app, "_tokenize_turn", slow_turn):
                    return await proxy_app.handle_proxy(FakeRequest(app))
            finally:
                task.cancel()

        try:
            resp = asyncio.run(main())
            assert resp.status == 200
            assert seen["thread"] != threading.current_thread().name, "tokenize ran on the loop thread"
            assert ticks >= 5, f"event loop was blocked during tokenization ({ticks} ticks)"
        finally:
            executor.shutdown(wait=True)
            tokenmap._BOUNDARY = None


# ── 7. streaming detokenization scales with the text, not the token store ────

def test_stream_detokenize_scales_with_text_not_map_size():
    with IsolatedBoundaryHome(), fake_clock():
        from erebus import proxy
        from erebus.proxy import tokenmap
        tokenmap._BOUNDARY = None
        proxy.TOKEN_MAP.clear()
        proxy.TOKEN_MAP.update({f"[PERSON_{i}_{i:06x}]": f"Value {i}" for i in range(20000)})
        proxy.TOKEN_MAP["[PERSON_1_" "aaaaaa]"] = "see [PERSON_2_" "bbbbbb]"
        proxy.TOKEN_MAP["[PERSON_2_" "bbbbbb]"] = "Bob"
        token = "[PERSON_5_" "000005]"
        text = ("lorem ipsum dolor " * 1700) + token + " end"  # ~30 KB, like a long streamed reply
        try:
            with patch.object(tokenmap, "_sync_mirror", wraps=tokenmap._sync_mirror) as sync:
                start = time.perf_counter()
                for _ in range(20):
                    out = tokenmap._detokenize_text(text)
                elapsed = time.perf_counter() - start
            assert out.endswith("Value 5 end") and token not in out
            assert sync.call_count == 0, "resolvable tokens triggered a store/JSON sync"
            assert elapsed < 0.4, f"20 detokenize passes over 30 KB took {elapsed:.2f}s"
            assert tokenmap._detokenize_text("hi [PERSON_1_" "aaaaaa]") == "hi see Bob", "token chain broken"
        finally:
            proxy.TOKEN_MAP.clear()
            tokenmap._BOUNDARY = None


# ── 8. large tool outputs are cacheable: exact spans by alignment ─────────────

def test_span_patch_aligns_known_values_and_preexisting_tokens():
    """A >16 KB sanitized text must be expressible as spans whenever every token
    in it resolves: derive the spans by aligning the two texts, not by replacing
    every occurrence of a value. Balanced mode keeps a lone surname raw while
    tokenizing it inside the full name, so "replace all occurrences" could never
    reproduce the sanitized text and the item was rejected as uncacheable."""
    from erebus.core import message_cache as mc
    surname = NAME.split()[-1]
    known = "[PERSON_1_" "abc001]"
    older = "[EMAIL_ADDRESS_1_" "abc002]"
    filler = "lorem ipsum dolor sit amet " * 700  # ~19 KB: past the value-patch limit
    original = f"{filler}owner: {NAME}; cc {older}; note {surname} alone\n{filler}"
    sanitized = f"{filler}owner: {NAME.split()[0]} {known}; cc {older}; note {surname} alone\n{filler}"
    assert len(sanitized) > mc._MSG_CACHE_MAX_PATCH_CHARS
    patch = mc.collect_token_span_patch(original, sanitized, {known: surname})
    assert patch is not None, "balanced-mode replacement in a large text was not cacheable"
    assert mc.apply_text_span_patches(original, patch["spans"]) == sanitized
    assert mc.collect_token_span_patch(original, sanitized, {}) is None, "a token with no value must not be guessed"


def test_large_tool_output_with_known_value_is_cached_and_not_redetected():
    """Live: 1981 of 2466 message-cache misses were 74 large tool outputs
    whose entry was rejected every turn (uncacheable_patch), so GLiNER re-ran
    over the same 20-45 KB on every request. After the first turn the item
    must replay from the message cache with zero detector calls."""
    with IsolatedBoundaryHome() as env, fake_clock():
        from erebus import filter as ef
        from erebus import proxy
        from erebus.core import detect
        from erebus.core import message_cache as mc
        from erebus.proxy import tokenmap
        tokenmap._BOUNDARY = None
        proxy.TOKEN_MAP.clear()
        mc._MSG_CACHE.clear()
        mc._MSG_CACHE_LOADED = True
        cfg = env.repo_config(mode="strict")
        try:
            small = {"model": "m", "input": [{"type": "message", "role": "user",
                     "content": [{"type": "input_text", "text": f"Bel {NAME}."}]}]}
            with daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
                proxy.tokenize_responses_request(json.loads(json.dumps(small)), cfg)
            big_text = ("lorem ipsum dolor sit amet " * 750) + f"\nowner: {NAME}\n" + ("consectetur " * 100)
            big = {"model": "m", "input": [{"type": "function_call_output", "call_id": "c1", "output": big_text}]}
            with daemon_stub("up"):
                out, _tokens, _turn = proxy.tokenize_responses_request(json.loads(json.dumps(big)), cfg)
            assert NAME not in json.dumps(out), "known value reached the model raw"
            stored = [e for e in mc._MSG_CACHE.values() if any(p.get("spans") for p in e["patches"])]
            assert stored, "large tool output with a known value was not stored in the message cache"

            ef.clear_tokenize_cache()  # a restart or LRU churn: only the message cache can save the turn
            calls: list = []
            with patch.object(detect, "_predict_entities_many",
                              side_effect=lambda texts: (calls.append(len(texts)), [[] for _ in texts])[1]), \
                 patch.object(detect, "_predict_entities", side_effect=lambda _t: (calls.append(1), [])[1]):
                out2, _tokens2, _turn2 = proxy.tokenize_responses_request(json.loads(json.dumps(big)), cfg)
            assert calls == [], f"identical large tool output went back through the detector: {calls}"
            assert out2["input"][0]["output"] == out["input"][0]["output"]
        finally:
            mc._MSG_CACHE.clear()
            proxy.TOKEN_MAP.clear()
            tokenmap._BOUNDARY = None


if __name__ == "__main__":
    run([
        test_audit_recovery_not_repeated_for_unresolvable_token,
        test_audit_recovery_scans_only_recent_rows,
        test_message_cache_hit_with_unresolvable_tokens_becomes_a_miss,
        test_proxy_retokenizes_item_whose_cached_tokens_are_gone,
        test_expired_allowances_are_swept_on_open,
        test_repeated_escape_grant_is_not_a_store_write,
        test_active_allowances_does_not_parse_expired_rows,
        test_parse_escapes_ignores_code_tildes,
        test_prescan_probes_only_candidate_values,
        test_tokenize_pass_runs_off_the_event_loop,
        test_stream_detokenize_scales_with_text_not_map_size,
        test_span_patch_aligns_known_values_and_preexisting_tokens,
        test_large_tool_output_with_known_value_is_cached_and_not_redetected,
    ], "Proxy bookkeeping latency (Codex, 2026-09-05)")
