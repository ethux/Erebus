"""Boundary tests for FR-010d: two KnownValueDB handles on the same home.

Simulates the proxy and shim processes sharing one known_values.db:
  * a stale bulk_view() misses a remotely minted token until revalidate()
  * meta.generation strictly increases across mint / grant_allowance / erase
  * resolve_missing() recovers token->value pairs from the audit log and
    persists them so the other handle sees them after revalidation
All assertions land on real-world artifacts (sqlite rows in the shared DB
file) or on views reloaded from that file; no sleeps, fake clock only.
"""
from __future__ import annotations

import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import TOKEN_RE, IsolatedBoundaryHome, fake_clock


def _db_generation(db_path) -> int:
    """Read meta.generation straight from the shared DB file."""
    conn = sqlite3.connect(db_path)
    try:
        (gen,) = conn.execute("SELECT generation FROM meta").fetchone()
    finally:
        conn.close()
    return gen


def test_stale_view_misses_remote_mint_until_revalidate():
    with IsolatedBoundaryHome() as env, fake_clock():
        handle_a = env.open_db()  # "proxy" process
        handle_b = env.open_db()  # "shim" process
        try:
            stale = handle_b.bulk_view()

            token = handle_a.mint("203.0.113.7", "ip_address")
            assert TOKEN_RE.fullmatch(token), f"bad token shape: {token!r}"
            assert token.startswith("[IP_ADDRESS_"), token

            # B's stale view predates the mint and must not contain it.
            assert token not in stale.token_view
            assert "203.0.113.7" not in stale.value_view

            # Revalidation notices the generation bump and reloads.
            fresh = handle_b.revalidate(stale)
            assert fresh.generation != stale.generation
            assert fresh.token_view[token] == "203.0.113.7"
            assert fresh.value_view["203.0.113.7"] == token

            # Real-world artifact: the row is in the shared global DB file.
            conn = sqlite3.connect(env.global_db_path())
            try:
                row = conn.execute(
                    "SELECT value, label FROM known_values WHERE token = ?",
                    (token,),
                ).fetchone()
            finally:
                conn.close()
            assert row == ("203.0.113.7", "ip_address")
        finally:
            handle_a.close()
            handle_b.close()


def test_generation_strictly_increases_across_writes():
    with IsolatedBoundaryHome() as env, fake_clock():
        handle_a = env.open_db()
        handle_b = env.open_db()
        try:
            db_path = env.global_db_path()
            gen_open = _db_generation(db_path)

            handle_a.mint("198.51.100.9", "ip_address")
            gen_mint = _db_generation(db_path)
            assert gen_mint > gen_open, (gen_open, gen_mint)

            # Write from the OTHER handle: generation lives in the file,
            # not in any single process.
            handle_b.grant_allowance("198.51.100.9", window_min=30)
            gen_grant = _db_generation(db_path)
            assert gen_grant > gen_mint, (gen_mint, gen_grant)

            assert handle_a.erase("198.51.100.9") is True
            gen_erase = _db_generation(db_path)
            assert gen_erase > gen_grant, (gen_grant, gen_erase)

            # erase() removed both the value row and its allowances.
            conn = sqlite3.connect(db_path)
            try:
                (kv_left,) = conn.execute(
                    "SELECT COUNT(*) FROM known_values WHERE value = ?",
                    ("198.51.100.9",),
                ).fetchone()
                (allow_left,) = conn.execute(
                    "SELECT COUNT(*) FROM escape_allowances WHERE value = ?",
                    ("198.51.100.9",),
                ).fetchone()
            finally:
                conn.close()
            assert kv_left == 0 and allow_left == 0, (kv_left, allow_left)

            # A revalidated view converges on the file's latest generation.
            view = handle_b.revalidate(handle_b.bulk_view())
            assert view.generation == gen_erase, (view.generation, gen_erase)
        finally:
            handle_a.close()
            handle_b.close()


def test_resolve_missing_recovers_from_audit_log_and_persists():
    with IsolatedBoundaryHome() as env, fake_clock():
        # Audit DB_PATH is already redirected by IsolatedBoundaryHome.
        from erebus.audit import logger as audit_logger

        token = "100.64.0.1"
        audit_logger.init_db()
        audit_logger.log_event(
            "boundary-session",
            "pii_detected",
            sanitized=f"ping {token}",
            tokens_map={token: "100.64.0.1"},
        )

        handle_a = env.open_db()
        handle_b = env.open_db()
        try:
            stale = handle_b.bulk_view()
            assert token not in stale.token_view

            recovered = handle_a.resolve_missing({token})
            assert recovered == {token: "100.64.0.1"}

            # Recovery INSERTs the pair into the shared DB (real artifact).
            conn = sqlite3.connect(env.global_db_path())
            try:
                row = conn.execute(
                    "SELECT value FROM known_values WHERE token = ?",
                    (token,),
                ).fetchone()
            finally:
                conn.close()
            assert row == ("100.64.0.1",)

            # The other handle sees it once its stale view is revalidated.
            fresh = handle_b.revalidate(stale)
            assert fresh.generation != stale.generation
            assert fresh.token_view[token] == "100.64.0.1"
            assert fresh.value_view["100.64.0.1"] == token
        finally:
            handle_a.close()
            handle_b.close()


if __name__ == "__main__":
    from helpers import run

    run(
        [
            test_stale_view_misses_remote_mint_until_revalidate,
            test_generation_strictly_increases_across_writes,
            test_resolve_missing_recovers_from_audit_log_and_persists,
        ],
        "Multi-process KnownValueDB sync (FR-010d)",
    )
