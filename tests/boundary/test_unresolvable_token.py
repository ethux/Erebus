"""Boundary tests: unresolvable outbound tokens (spec FR-018 / FR-010b).

A token in model output whose mapping is gone (rotated, erased, other machine)
must NEVER be silently dropped: after view revalidation and audit recovery fail,
`from_model` leaves the token literal in the detokenized text and reports it in
`unresolved_tokens`. The configured action ('warn' default, 'block') is applied
by the ADAPTER; core stays mechanics-only and always returns the report.
A token that IS recoverable from the audit log resolves normally.

All assertions run against real-world artifacts: the returned real-world-side
strings and sqlite-backed audit rows. All fixture values are synthetic.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import TOKEN_RE, IsolatedBoundaryHome, daemon_stub, fake_clock

from erebus.core import Boundary

# Synthetic fixture tokens (canonical shape, never live-map values).
ORPHAN_TOKEN = "[PERSON_9_" "deadbe]"   # no DB row, no audit trail -> unresolvable
RECOVERABLE_TOKEN = "[PERSON_3_" "abc123]"
RECOVERABLE_VALUE = "Jan Modaal"     # synthetic Dutch-sounding fake

assert TOKEN_RE.fullmatch(ORPHAN_TOKEN)
assert TOKEN_RE.fullmatch(RECOVERABLE_TOKEN)


def _boundary(h, **config_overrides):
    cfg = h.repo_config(mode="strict", **config_overrides)
    return cfg, Boundary.from_config(cfg, str(h.project), source="test")


# -- tests ---------------------------------------------------------------------


def test_unresolvable_token_stays_literal_and_is_reported():
    """Empty home (no DB entries, no audit log): the orphan token survives
    literally in the detokenized text AND is reported -- never silently
    dropped, never silently swallowed (FR-018)."""
    with IsolatedBoundaryHome() as h, fake_clock(), daemon_stub("up"):
        cfg, boundary = _boundary(h)
        # default policy is 'warn' (FR-018: proceed with the literal token)
        assert cfg.unresolved_token_action == "warn"

        resolved, unresolved = boundary.from_model(f"ship {ORPHAN_TOKEN} now")

        assert resolved == f"ship {ORPHAN_TOKEN} now", (
            f"literal token must remain in output under 'warn': {resolved!r}")
        assert resolved.count(ORPHAN_TOKEN) == 1, "token silently dropped/duplicated"
        assert unresolved == [ORPHAN_TOKEN], (
            f"unresolvable token not reported: {unresolved}")


def test_block_action_core_still_returns_report():
    """unresolved_token_action='block' does not change core mechanics:
    from_model RETURNS the same (text, unresolved) report -- blocking the
    side effect is the adapter's job (contracts/boundary-api.md). Unresolved
    tokens are a separate signal from turn degradation."""
    with IsolatedBoundaryHome() as h, fake_clock(), daemon_stub("up"):
        _, boundary = _boundary(h, unresolved_token_action="block")

        with boundary.turn() as t:
            resolved, unresolved = boundary.from_model(f"ship {ORPHAN_TOKEN} now")

            # identical return to the 'warn' case: no exception, full report
            assert resolved == f"ship {ORPHAN_TOKEN} now"
            assert unresolved == [ORPHAN_TOKEN]

            # separate signals: an unresolvable token must NOT degrade the turn
            assert not getattr(t, "degraded", False), (
                f"unresolved token wrongly set turn-degraded "
                f"({getattr(t, 'degraded_reason', '')!r})")


def test_audit_recoverable_token_resolves():
    """A token whose mapping survives only in the audit log (pii_detected
    event with tokens_map) is recovered by from_model: real value emitted,
    token absent from both the output and the unresolved report."""
    with IsolatedBoundaryHome() as h, fake_clock(), daemon_stub("up"):
        from erebus.audit import logger
        logger.init_db()
        logger.log_event(
            "boundary-test-session", "pii_detected",
            sanitized=f"met {RECOVERABLE_TOKEN} earlier",
            tokens_map={RECOVERABLE_TOKEN: RECOVERABLE_VALUE})

        _, boundary = _boundary(h)
        resolved, unresolved = boundary.from_model(
            f"contact {RECOVERABLE_TOKEN} today")

        assert resolved == f"contact {RECOVERABLE_VALUE} today", (
            f"audit-recoverable token not resolved: {resolved!r}")
        assert RECOVERABLE_TOKEN not in resolved
        assert unresolved == [], (
            f"recovered token wrongly reported unresolved: {unresolved}")


def test_partial_resolution_reports_only_the_orphan():
    """Mixed output: the audit-recoverable token resolves, the orphan stays
    literal, and ONLY the orphan lands in unresolved_tokens."""
    with IsolatedBoundaryHome() as h, fake_clock(), daemon_stub("up"):
        from erebus.audit import logger
        logger.init_db()
        logger.log_event(
            "boundary-test-session", "pii_detected",
            sanitized=f"met {RECOVERABLE_TOKEN} earlier",
            tokens_map={RECOVERABLE_TOKEN: RECOVERABLE_VALUE})

        _, boundary = _boundary(h)
        resolved, unresolved = boundary.from_model(
            f"ask {RECOVERABLE_TOKEN} to ship {ORPHAN_TOKEN} now")

        assert resolved == f"ask {RECOVERABLE_VALUE} to ship {ORPHAN_TOKEN} now"
        assert unresolved == [ORPHAN_TOKEN], (
            f"expected only the orphan token reported: {unresolved}")


if __name__ == "__main__":
    from helpers import run
    run([
        test_unresolvable_token_stays_literal_and_is_reported,
        test_block_action_core_still_returns_report,
        test_audit_recoverable_token_resolves,
        test_partial_resolution_reports_only_the_orphan,
    ], "Unresolvable outbound tokens (FR-018 / FR-010b)")
