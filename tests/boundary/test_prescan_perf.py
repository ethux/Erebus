"""Boundary perf test: known-value pre-scan scales (plan T041, SC-010b).

The unconditional known-value pre-scan (FR-011) runs on every model-bound
string before the detector. This test proves it stays fast as the Known-Value
DB grows: with 10,000 distinct value->token pairs in the store and the GLiNER
detector stubbed OFF, tokenizing a ~16 KB message that embeds a handful of
those known values completes well under a second.

What is measured: ONLY ``Boundary.to_model`` on a fresh (uncached) 16 KB
message, with the daemon down (``daemon_stub("down")``) so the timed work is
the pre-scan + the regex pass, NOT GLiNER. The 10,000-entry store is built
before the timed region via the public legacy-seed path (one bulk transaction
on DB open), so the seed cost never enters the measurement.

Timing uses ``time.perf_counter`` (real wall time) on purpose: this asserts a
real-world latency budget, so the injected fake clock is NOT used for it. The
fake clock is still installed only to keep created_at/last_seen_at timestamps
deterministic during the seed.

Budget (SC-010b): pre-scan <= ~0.5 s on CI-class hardware for a 16 KB message
against a 10k-entry DB. The hard assert is a generous < 1.0 s to stay
non-flaky; the measured millisecond figure is printed so the real number is
visible. Correctness is asserted alongside latency: every embedded known value
is absent from the model-bound output and replaced by its exact stored token.

All fixture values are synthetic ("User Number <i>"); token shapes are seeded,
never live-map values. Assertions run against real-world artifacts (sqlite rows
for the seeded pairs) and against the ABSENCE of real values in model-bound
output.
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import (
    TOKEN_RE,
    IsolatedBoundaryHome,
    assert_value_absent,
    daemon_stub,
    fake_clock,
)

KNOWN_COUNT = 10_000          # distinct value->token pairs seeded into the store
TARGET_BYTES = 16_000         # model-bound message size (~16 KB)
EMBEDDED_IDS = (123, 17, 4242, 8000, 9999)  # known values that appear in the message
BUDGET_SECONDS = 1.0          # non-flaky hard cap; documented budget is ~0.5 s
DOCUMENTED_BUDGET_MS = 500.0  # SC-010b target on CI-class hardware (printed only)

FILLER = "lorem ipsum dolor sit amet consectetur adipiscing elit " * 400


def _value(i: int) -> str:
    return f"User Number {i}"


def _seed_entries() -> dict[str, str]:
    """token -> value for KNOWN_COUNT synthetic pairs, canonical token shape."""
    return {
        f"[PERSON_{i + 1}_{secrets.token_hex(3)}]": _value(i)
        for i in range(KNOWN_COUNT)
    }


def _seed_store(env: IsolatedBoundaryHome, entries: dict[str, str]):
    """Bulk-load the 10k pairs via the public legacy-seed path: writing the
    legacy token_map.json and opening the DB imports them in ONE transaction,
    so the (one-time) setup cost stays out of the timed region."""
    env.write_legacy_map(entries)
    return env.open_db()


def _build_message(values: list[str]) -> str:
    """A ~16 KB message: filler text with the embedded known values spread
    through it, padded/truncated to exactly TARGET_BYTES while keeping every
    embedded value intact."""
    parts = [FILLER[:7000]]
    for value in values:
        parts.append(f" please contact {value} regarding the matter. ")
        parts.append(FILLER[:1500])
    message = "".join(parts)
    if len(message) < TARGET_BYTES:
        message += FILLER * ((TARGET_BYTES - len(message)) // len(FILLER) + 1)
    message = message[:TARGET_BYTES]
    # Truncation must not have clipped any embedded value.
    for value in values:
        if value not in message:
            message = message[:TARGET_BYTES - 40] + f" contact {value} now "
    return message


def _stored_tokens(db_path, entries: dict[str, str]) -> dict[str, str]:
    """value -> token straight from sqlite, for the embedded values only."""
    wanted = set(entries.values())
    con = sqlite3.connect(db_path)
    try:
        rows = con.execute("SELECT token, value FROM known_values").fetchall()
    finally:
        con.close()
    return {value: token for token, value in rows if value in wanted}


def test_prescan_scales_on_16kb_message_with_10k_known_values():
    """ONLY ``to_model`` is timed, on a 16 KB message, with 10k known values
    in the store and the detector down. The call must finish well under a
    second AND retokenize every embedded known value to its exact stored
    token."""
    with IsolatedBoundaryHome() as env, fake_clock():
        entries = _seed_entries()
        _seed_store(env, entries)  # one-time bulk seed, OUTSIDE the timed region

        # Real-world artifact: the 10k pairs are actually rows in the DB.
        row_count = sqlite3.connect(env.global_db_path()).execute(
            "SELECT COUNT(*) FROM known_values").fetchone()[0]
        assert row_count == KNOWN_COUNT, (
            f"expected {KNOWN_COUNT} seeded rows, found {row_count}")

        from erebus.core import Boundary
        cfg = env.repo_config(mode="strict")
        boundary = Boundary.from_config(cfg, str(env.project), source="perf")

        embedded_values = [_value(i) for i in EMBEDDED_IDS]
        message = _build_message(embedded_values)
        assert len(message.encode("utf-8")) >= TARGET_BYTES - 64, (
            f"message too small to exercise the pre-scan: "
            f"{len(message.encode('utf-8'))} bytes")

        # Token the embedded values were seeded with, read from sqlite.
        token_for = _stored_tokens(env.global_db_path(), {
            tok: val for tok, val in entries.items() if val in embedded_values})
        assert set(token_for) == set(embedded_values), (
            "seeded tokens missing for embedded values")

        # -- timed region: detector OFF, fresh (uncached) message ------------
        # perf_counter (real wall time), NOT the fake clock: this is a latency
        # budget, not logical-time logic.
        with daemon_stub("down"):
            with boundary.turn():
                start = time.perf_counter()
                tokenized, _new_tokens = boundary.to_model(message)
                elapsed = time.perf_counter() - start

        elapsed_ms = elapsed * 1000.0
        print(f"\n  pre-scan: 10k-entry DB, {len(message.encode('utf-8'))}-byte "
              f"message -> {elapsed_ms:.1f} ms "
              f"(budget ~{DOCUMENTED_BUDGET_MS:.0f} ms, hard cap "
              f"{BUDGET_SECONDS * 1000:.0f} ms)")

        # -- latency assertion (generous to avoid CI flakiness) --------------
        assert elapsed < BUDGET_SECONDS, (
            f"pre-scan over 10k known values took {elapsed_ms:.1f} ms, "
            f"over the {BUDGET_SECONDS * 1000:.0f} ms hard cap (SC-010b)")

        # -- correctness: every embedded known value is retokenized ----------
        for value in embedded_values:
            assert_value_absent(tokenized, value)
            token = token_for[value]
            assert token in tokenized, (
                f"embedded known value {value!r} was not retokenized to its "
                f"stored token {token!r}")
            assert TOKEN_RE.fullmatch(token), f"bad seeded token shape: {token!r}"


if __name__ == "__main__":
    from helpers import run
    run([
        test_prescan_scales_on_16kb_message_with_10k_known_values,
    ], "Known-value pre-scan performance (T041 / SC-010b)")
