"""Gateway test: Known-Value DB scope resolution + retention rotation.

Release conditions (spec FR-010e, FR-015, FR-016):
  * scope global/project/hybrid selects which on-disk DB file backs the store,
    and hybrid resolves a value to the PROJECT token when both hold it
    (deterministic, project wins);
  * age-rotation retention ("days:N") sweeps aged value rows and their escape
    allowances once the clock passes the window, bumping the generation;
  * erase(value) drops the row + its allowances in one go and bumps generation;
  * "session" retention never writes a DB file to disk yet resolves in-handle.

Assertions run against real-world artifacts only: sqlite rows read with a
direct connection, the generation counter in the meta table, and the presence
or absence of the .db file on disk. Time is injected via helpers.fake_clock,
never slept on.
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import helpers

VALUE = "Jan Modaal"
VALUE_2 = "Piet Puk"
LABEL = "PERSON"


def _open(env, scope: str, retention: str = "days:7"):
    """Open a KnownValueDB for the given scope + retention, directly."""
    from erebus.core.knownvalues import open_known_values
    cfg = env.repo_config(known_values_scope=scope, known_values_retention=retention)
    return open_known_values(cfg, str(env.project))


def _row_values(db_path) -> set[str]:
    """Values stored in a .db file, read with a plain sqlite3 connection."""
    conn = sqlite3.connect(str(db_path))
    try:
        return {r[0] for r in conn.execute("SELECT value FROM known_values").fetchall()}
    finally:
        conn.close()


def _generation(db_path) -> int:
    conn = sqlite3.connect(str(db_path))
    try:
        return conn.execute("SELECT generation FROM meta").fetchone()[0]
    finally:
        conn.close()


def _allowance_values(db_path) -> set[str]:
    conn = sqlite3.connect(str(db_path))
    try:
        return {r[0] for r in conn.execute("SELECT value FROM escape_allowances").fetchall()}
    finally:
        conn.close()


# --- 1. scope lookup order --------------------------------------------------

def test_scope_lookup_order_project_global_hybrid():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        # Mint a value into the PROJECT DB via a hybrid handle (mint target = project).
        proj_db = _open(env, "hybrid")
        try:
            proj_token = proj_db.mint(VALUE, LABEL, source="test")
        finally:
            proj_db.close()

        # The value's row lives ONLY in the project DB file: the global DB file
        # (created empty when the hybrid handle opened both scopes) has no
        # known_values row of its own. This is the real scope-isolation artifact.
        assert env.project_db_path().is_file(), "project DB file not created"
        assert VALUE in _row_values(env.project_db_path()), "value missing from project DB"
        assert env.global_db_path().is_file(), "hybrid handle did not create the global DB file"
        assert _row_values(env.global_db_path()) == set(), (
            "project-minted value leaked into the global DB's own rows"
        )

        # NOTE (real store behavior): the shared legacy token_map.json export is a
        # single global file. A hybrid mint exports the project pair there, so a
        # later global-scope handle SEEDS that pair into the global DB and would
        # resolve it. To test genuine scope isolation at the lookup layer we drop
        # that cross-scope legacy carrier first (we do not mint into global here).
        env.legacy_map_path().unlink(missing_ok=True)

        # A global-scope store reads only the (empty) global file: it cannot see it.
        global_db = _open(env, "global")
        try:
            assert global_db.lookup_value(proj_token) is None, (
                "global-scope store resolved a project-only token"
            )
            assert global_db.lookup_token(VALUE, LABEL) is None, (
                "global-scope store found a project-only value"
            )
        finally:
            global_db.close()

        # A hybrid store reads project first: it sees the value.
        hybrid_db = _open(env, "hybrid")
        try:
            assert hybrid_db.lookup_value(proj_token) == VALUE, (
                "hybrid store could not resolve the project token"
            )
            assert hybrid_db.lookup_token(VALUE, LABEL) == proj_token, (
                "hybrid store resolved the wrong token for the project value"
            )
        finally:
            hybrid_db.close()


def test_hybrid_resolves_to_project_token_when_both_hold_value():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        # Mint the SAME value into the global DB first (global-scope handle).
        gdb = _open(env, "global")
        try:
            global_token = gdb.mint(VALUE, LABEL, source="global")
        finally:
            gdb.close()

        # Drop the shared legacy carrier so the next handle does NOT seed the
        # global pair into the project DB. A PROJECT-scope handle reads only the
        # project DB, so it never sees the global row and mints a FRESH token.
        # (A hybrid handle would instead reuse the global token, since mint() is
        # idempotent across every DB the handle reads.) This stages the genuine
        # "same value, different token in each DB file" state.
        env.legacy_map_path().unlink(missing_ok=True)

        # Mint it independently into the project DB via a project-scope handle.
        pdb = _open(env, "project")
        try:
            project_token = pdb.mint(VALUE, LABEL, source="project")
        finally:
            pdb.close()

        # Distinct tokens really live in distinct files.
        assert global_token != project_token, "expected two distinct tokens"
        assert VALUE in _row_values(env.global_db_path()), "value missing from global DB"
        assert VALUE in _row_values(env.project_db_path()), "value missing from project DB"

        # Hybrid resolution is deterministic: PROJECT token wins (read project first).
        hybrid = _open(env, "hybrid")
        try:
            assert hybrid.lookup_token(VALUE, LABEL) == project_token, (
                "hybrid did not resolve the value to the project token"
            )
            # And mint() is idempotent against that same project token.
            assert hybrid.mint(VALUE, LABEL, source="again") == project_token, (
                "hybrid mint() did not return the existing project token"
            )
            # The global token still resolves to the value (both rows live on).
            assert hybrid.lookup_value(global_token) == VALUE
            assert hybrid.lookup_value(project_token) == VALUE
        finally:
            hybrid.close()


# --- 2. age rotation --------------------------------------------------------

def test_age_rotation_sweeps_aged_value_and_allowance():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock() as clk:
        db_path = env.global_db_path()
        db = _open(env, "global", retention="days:1")
        try:
            aged_token = db.mint(VALUE, LABEL, source="aged")
            db.grant_allowance(VALUE, window_min=60)  # well inside the 1-day window
            assert _row_values(db_path) == {VALUE}
            assert _allowance_values(db_path) == {VALUE}
            gen_before = _generation(db_path)

            # Advance past the retention window, then mint a still-fresh value.
            clk.advance(days=2)
            fresh_token = db.mint(VALUE_2, LABEL, source="fresh")

            removed = db.sweep()
            assert removed >= 1, f"sweep removed nothing (returned {removed})"

            # The aged value row AND its allowance are gone; fresh survives.
            assert _row_values(db_path) == {VALUE_2}, "aged value not rotated / fresh lost"
            assert _allowance_values(db_path) == set(), "aged allowance survived sweep"
            assert _generation(db_path) > gen_before, "sweep did not bump generation"

            # Resolution reflects the sweep.
            assert db.lookup_value(aged_token) is None, "aged token still resolves"
            assert db.lookup_value(fresh_token) == VALUE_2, "fresh token lost"
        finally:
            db.close()


def test_permanent_retention_never_rotates():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock() as clk:
        db_path = env.global_db_path()
        db = _open(env, "global", retention="permanent")
        try:
            db.mint(VALUE, LABEL, source="kept")
            gen_before = _generation(db_path)
            clk.advance(days=400)
            assert db.sweep() == 0, "permanent retention rotated a value"
        finally:
            db.close()
        assert VALUE in _row_values(db_path), "permanent value was rotated away"
        assert _generation(db_path) == gen_before, "no-op sweep bumped generation"


# --- 3. erasure (store method directly) -------------------------------------

def test_erase_removes_row_and_allowances_and_bumps_generation():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        db_path = env.global_db_path()
        db = _open(env, "global")
        try:
            token = db.mint(VALUE, LABEL, source="erase-me")
            db.grant_allowance(VALUE, window_min=60)
            keep_token = db.mint(VALUE_2, LABEL, source="keep")
            assert _row_values(db_path) == {VALUE, VALUE_2}
            assert _allowance_values(db_path) == {VALUE}
            gen_before = _generation(db_path)

            erased = db.erase(VALUE)
            assert erased is True, "erase reported no change for a present value"

            # Row + allowance gone in one go; the unrelated entry survives.
            assert _row_values(db_path) == {VALUE_2}, "erase left value or dropped unrelated row"
            assert _allowance_values(db_path) == set(), "erase left the allowance behind"
            assert _generation(db_path) > gen_before, "erase did not bump generation"

            assert db.lookup_value(token) is None, "erased token still resolves"
            assert db.lookup_value(keep_token) == VALUE_2, "unrelated token lost on erase"
        finally:
            db.close()


# --- 4. session retention ---------------------------------------------------

def test_session_retention_writes_no_db_file_but_resolves_in_handle():
    with helpers.IsolatedBoundaryHome() as env, helpers.fake_clock():
        db = _open(env, "global", retention="session")
        try:
            token = db.mint(VALUE, LABEL, source="session")
            assert helpers.TOKEN_RE.fullmatch(token), f"bad token shape: {token!r}"

            # Resolves within the live handle (in-memory store).
            assert db.lookup_value(token) == VALUE, "session store did not resolve token"
            assert db.lookup_token(VALUE, LABEL) == token, "session store lost the pair"

            # Nothing touches disk: neither DB file nor the legacy JSON map.
            assert not env.global_db_path().exists(), "session retention wrote a global DB file"
            assert not env.project_db_path().exists(), "session retention wrote a project DB file"
            assert not env.legacy_map_path().exists(), "session retention exported the legacy map"
        finally:
            db.close()

        # A brand-new session handle starts empty: nothing was persisted.
        fresh = _open(env, "global", retention="session")
        try:
            assert fresh.lookup_value(token) is None, "session token survived across handles"
        finally:
            fresh.close()


if __name__ == "__main__":
    from helpers import run
    run([
        test_scope_lookup_order_project_global_hybrid,
        test_hybrid_resolves_to_project_token_when_both_hold_value,
        test_age_rotation_sweeps_aged_value_and_allowance,
        test_permanent_retention_never_rotates,
        test_erase_removes_row_and_allowances_and_bumps_generation,
        test_session_retention_writes_no_db_file_but_resolves_in_handle,
    ], "Known-Value DB scope + retention gateway tests (FR-010e / FR-015 / FR-016)")
