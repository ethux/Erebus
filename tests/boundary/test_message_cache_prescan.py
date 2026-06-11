"""A message-cache replay must never send a now-known value to the model raw.

Regression for the 2026-06-11 review:
  * (first hole) message_cache_key carries no known-value generation, so an
    entry cached when value V was unknown replayed V on every later turn.
  * (zero-patch hole) the dominant case: a message first seen on a NON-degraded
    turn that the detector simply MISSED is stored with ZERO patches
    (original == sanitized). A per-patch retokenize hook never visited any
    field, so the raw value replayed forever once V became known. The fix
    retokenizes the whole applied item, not just patched fields.

apply_message_cache_entry now takes `retokenize_item(item) -> inserted`, run
over every model-bound text field. Asserts on real artifacts: the model-bound
string after a cache hit. Fixture value is synthetic ('Jan Modaal').
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers
from helpers import IsolatedBoundaryHome, assert_value_absent, daemon_stub, fake_clock, person_entity

from erebus.core import _set_path_value
from erebus.core import message_cache as mc
from erebus.proxy.payload import collect_text_paths

NAME = "Jan Modaal"  # synthetic fixture, never a real name


def _make_boundary(h: IsolatedBoundaryHome):
    from erebus.core import Boundary
    return Boundary.from_config(h.repo_config(mode="strict"), str(h.project), source="test")


def _item_retokenizer(boundary):
    """Mirror the proxy's _retokenize_cached_item: pre-scan every text field."""
    def _retok(item) -> dict:
        inserted: dict = {}
        for path, text in collect_text_paths(item):
            new_text, toks = boundary.retokenize_known(text)
            if new_text != text:
                _set_path_value(item, path, new_text)
            inserted.update(toks)
        return inserted
    return _retok


def _msg(text: str) -> dict:
    return {"role": "user", "content": [{"type": "input_text", "text": text}]}


def _seed_known(boundary):
    """Make NAME a known value via a channel the detector catches."""
    with daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        _, minted = boundary.to_model(f"Bel {NAME} morgen.")
    return {v: k for k, v in minted.items()}[NAME]


def test_zero_patch_resend_retokenizes_value_learned_later():
    """The dominant leak: a byte-identical resend cached with NO patches (the
    detector missed NAME on first sight) must still get retokenized once NAME
    becomes known. This is the path the per-patch hook missed."""
    with IsolatedBoundaryHome() as h, fake_clock():
        boundary = _make_boundary(h)
        mc._MSG_CACHE.clear()
        mc._MSG_CACHE_LOADED = True

        key = "history-zero-patch"
        raw_text = f"Eerder: {NAME} stuurde het rapport."
        # Store via the REAL path with original == sanitized == raw (detector
        # miss, no tokens) -> a valid zero-patch, zero-token entry.
        with daemon_stub("down"):
            mc.store_message_cache_entry(key, _msg(raw_text), _msg(raw_text), tokens={})
        assert mc._MSG_CACHE[key]["patches"] == [], "precondition: entry must be zero-patch"

        token = _seed_known(boundary)

        item = _msg(raw_text)  # byte-identical resend carrying the raw value
        collected: dict = {}
        assert mc.apply_message_cache_entry(key, item, collected, "responses_input",
                                            retokenize_item=_item_retokenizer(boundary))
        out = item["content"][0]["text"]
        assert_value_absent(out, NAME)
        assert token in out, f"zero-patch replay leaked the raw value: {out!r}"
        assert collected.get(token) == NAME
    print("  ✓ zero-patch resend retokenizes a value learned after caching")


def test_patched_entry_retokenizes_value_learned_later():
    with IsolatedBoundaryHome() as h, fake_clock():
        boundary = _make_boundary(h)
        mc._MSG_CACHE.clear()
        mc._MSG_CACHE_LOADED = True

        # A patched entry (original PLACEHOLDER != sanitized raw text).
        key = "history-patched"
        raw_text = f"Notitie: {NAME} belt terug."
        with daemon_stub("down"):
            mc.store_message_cache_entry(key, _msg("PLACEHOLDER"), _msg(raw_text), tokens={})

        token = _seed_known(boundary)

        item = _msg("PLACEHOLDER")
        collected: dict = {}
        assert mc.apply_message_cache_entry(key, item, collected, "responses_input",
                                            retokenize_item=_item_retokenizer(boundary))
        out = item["content"][0]["text"]
        assert_value_absent(out, NAME)
        assert token in out, f"patched replay leaked the raw value: {out!r}"
    print("  ✓ patched entry replay retokenizes a value learned after caching")


def test_without_hook_zero_patch_leaks_raw():
    """Pin the regression: the SAME zero-patch replay with no retokenizer (old
    behavior) leaks raw — proving the item-level hook is what closes it."""
    with IsolatedBoundaryHome() as h, fake_clock():
        boundary = _make_boundary(h)
        mc._MSG_CACHE.clear()
        mc._MSG_CACHE_LOADED = True

        key = "history-zero-patch-2"
        raw_text = f"Eerder: {NAME} stuurde het rapport."
        with daemon_stub("down"):
            mc.store_message_cache_entry(key, _msg(raw_text), _msg(raw_text), tokens={})
        _seed_known(boundary)

        item = _msg(raw_text)
        mc.apply_message_cache_entry(key, item, {}, "responses_input")  # no hook
        assert NAME in item["content"][0]["text"], "expected the old behavior to leak raw"
    print("  ✓ confirmed the zero-patch hole exists without the hook (regression is real)")


if __name__ == "__main__":
    helpers.run([
        test_zero_patch_resend_retokenizes_value_learned_later,
        test_patched_entry_retokenizes_value_learned_later,
        test_without_hook_zero_patch_leaks_raw,
    ], "Message-cache replay pre-scan (FR-011 cache-hit, zero-patch)")
