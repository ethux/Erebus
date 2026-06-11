"""Boundary tests for FR-006: degraded-detector behavior at the model boundary.

When the GLiNER daemon is unreachable, Boundary.to_model must still tokenize
everything the regex pass can catch (emails), and the surrounding turn must be
flagged degraded with reason 'daemon_unavailable'. Degraded results must never
enter the result cache: a repeat call for the same text must hit the detector
path again. Once the daemon recovers, the same text caches normally: one
detector invocation populates the cache and the next identical call is served
without touching the detector.

Detector traffic is observed via a counting side_effect layered on top of the
daemon stub; sanitized output is checked only for ABSENCE of real values
(helpers.assert_value_absent), never for token equality on the model side.
All fixture values are synthetic ('Jan Modaal', 'fake@example.test').
"""
import os
import sys
from contextlib import contextmanager
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers

TEXT = "Reach fake@example.test about Jan Modaal"
EMAIL = "fake@example.test"
NAME = "Jan Modaal"


def _detector_module():
    try:
        from erebus.core import detect as det
    except ImportError:  # pre-P2: detection still lives in erebus.filter
        from erebus import filter as det
    return det


def _make_boundary(env):
    from erebus.core import Boundary
    cfg = env.repo_config(mode="strict")
    return Boundary.from_config(cfg, str(env.project), source="test")


@contextmanager
def _counting_daemon(mode, entities_for=None):
    """daemon_stub wrapped so every detector invocation increments a counter.

    Counts both the single and the batched entry point: a cache hit is exactly
    a to_model call that increments nothing.
    """
    det = _detector_module()
    counter = {"count": 0}
    with helpers.daemon_stub(mode, entities_for=entities_for):
        stubbed_single = det._predict_entities
        stubbed_many = det._predict_entities_many

        def counted_single(text):
            counter["count"] += 1
            return stubbed_single(text)

        def counted_many(texts):
            counter["count"] += 1
            return stubbed_many(texts)

        with patch.object(det, "_predict_entities", side_effect=counted_single), \
             patch.object(det, "_predict_entities_many", side_effect=counted_many):
            yield counter


def test_down_daemon_still_tokenizes_email_and_flags_turn_degraded():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        boundary = _make_boundary(env)
        with helpers.daemon_stub("down"):
            with boundary.turn() as t:
                assert t.degraded is False, "turn entered already degraded"
                out, new_tokens = boundary.to_model(TEXT)

                # Regex pass must survive daemon loss: the email is tokenized.
                helpers.assert_value_absent(out, EMAIL)
                assert helpers.TOKEN_RE.search(out), (
                    "no token in model-bound output under degraded detector"
                )
                assert EMAIL in new_tokens.values(), (
                    "email was not the value behind a freshly minted token"
                )

                assert t.degraded is True, (
                    "turn not flagged degraded while daemon is down"
                )
                assert t.degraded_reason == "daemon_unavailable", (
                    f"wrong degraded reason: {t.degraded_reason!r}"
                )


def test_degraded_results_are_not_served_from_cache():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        boundary = _make_boundary(env)
        with _counting_daemon("down") as calls:
            with boundary.turn() as t1:
                out1, _ = boundary.to_model(TEXT)
                assert t1.degraded is True
            first = calls["count"]
            assert first >= 1, "first to_model never reached the detector path"

            # Same text again: a degraded result must NOT have been cached,
            # so the detector path must be invoked again.
            with boundary.turn() as t2:
                out2, _ = boundary.to_model(TEXT)
                assert t2.degraded is True, (
                    "repeat call not degraded: degraded result was cached"
                )
            assert calls["count"] > first, (
                "second degraded to_model did not hit the detector: "
                "degraded result was served from cache"
            )

            # Both passes still keep the regex-caught value out of the output.
            helpers.assert_value_absent(out1, EMAIL)
            helpers.assert_value_absent(out2, EMAIL)


def test_recovered_daemon_caches_same_text_normally():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        boundary = _make_boundary(env)

        # Calls 1 and 2: daemon down, both degraded, nothing cached.
        with helpers.daemon_stub("down"):
            for _ in range(2):
                with boundary.turn() as t:
                    boundary.to_model(TEXT)
                    assert t.degraded is True

        # Daemon recovers: call 3 must run the detector and cache the clean
        # result; call 4 must be served from that cache. Exactly one detector
        # invocation across the two calls.
        finder = lambda text: helpers.person_entity(text, NAME)
        with _counting_daemon("up", entities_for=finder) as calls:
            with boundary.turn() as t3:
                out3, _ = boundary.to_model(TEXT)
                assert t3.degraded is False, (
                    "turn degraded although daemon is back up"
                )
            with boundary.turn() as t4:
                out4, _ = boundary.to_model(TEXT)
                assert t4.degraded is False
            assert calls["count"] == 1, (
                f"detector invoked {calls['count']} times across the two "
                "post-recovery calls; expected exactly 1 (miss then cache hit)"
            )

        # Clean (non-degraded) output hides BOTH values: email via regex,
        # name via the recovered detector.
        for out in (out3, out4):
            helpers.assert_value_absent(out, EMAIL)
            helpers.assert_value_absent(out, NAME)
            assert helpers.TOKEN_RE.search(out)


if __name__ == "__main__":
    from helpers import run
    run([
        test_down_daemon_still_tokenizes_email_and_flags_turn_degraded,
        test_degraded_results_are_not_served_from_cache,
        test_recovered_daemon_caches_same_text_normally,
    ], "Boundary degraded-detector behavior (FR-006)")
