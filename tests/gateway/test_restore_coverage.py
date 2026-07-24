"""Token-restore coverage tests (T014/T015; FR-006) against a live Postgres.

Set EREBUS_PG_DSN (defaults to postgresql:///erebus_gw_restore). Mints tokens via
the detector label path AND via a catalog-style label, then round-trips every
minted token form through whole-response restore (Tokenizer.restore) and streamed
restore (StreamRestorer), asserting ZERO leftover tokens remain. This proves the
gateway's restore regex covers every token shape the store's mint can produce:
mint normalizes the label into the restore pattern's character class, so a label
carrying a digit, lowercase, or punctuation can never yield an unrestorable token.

Self-skips if no Postgres is reachable (matches the suite convention).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

os.environ.setdefault("EREBUS_DISABLE_GLINER", "1")

import psycopg

from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.store import db
from erebus.gateway.store.known_value_store import open_store, provision_scope
from erebus.gateway.streaming_restore import _TOKEN_RE as _STREAM_TOKEN_RE
from erebus.gateway.streaming_restore import StreamRestorer
from erebus.gateway.tokenizer import _TOKEN_RE as _TOK_TOKEN_RE
from erebus.gateway.tokenizer import Tokenizer

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_restore")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _stream_restore(restorer_factory, text):
    """Feed ``text`` one character at a time through a fresh StreamRestorer."""
    r = restorer_factory()
    out = []
    for ch in text:
        out.append(r.feed(ch))
    out.append(r.flush())
    return "".join(out)


def main():
    print("\n=== Gateway token-restore coverage (T014/T015; FR-006) ===\n")
    try:
        conn = psycopg.connect(_DSN)
    except Exception as exc:  # no Postgres available -> self-skip (matches suite convention)
        print(f"  (skipped: no Postgres at {_DSN}: {exc})")
        return
    conn.autocommit = False
    try:
        db.run_migrations(conn)
        with conn.transaction():
            conn.execute("TRUNCATE scopes CASCADE")  # clean slate for re-runs

        kms = LocalKms()
        scope_id = provision_scope(conn, kms, "org1/restore/coverage")
        store = open_store(conn, kms, scope_id)

        # Labels exercising every shape mint can be handed:
        #  - a plain detector label (PERSON)
        #  - a multi-word detector label with an underscore (INTERNAL_ID)
        #  - catalog-style labels carrying a digit, lowercase, hyphen, and space,
        #    which the restore regex's [A-Z_]+ class would NOT match if mint left
        #    them verbatim. mint must normalize them so restore still covers them.
        cases = [
            ("Jan Modaal", "PERSON"),
            ("ACME-1234", "INTERNAL_ID"),
            ("Project Erebus", "project2"),
            ("Stichting Zonnebloem", "Org-Name"),
            ("widget-9", "sku 42"),
        ]

        tokens = []
        for value, label in cases:
            tok = store.mint(value, label)
            tokens.append((tok, value))

        # Every minted token must match BOTH restore regexes (whole + streamed),
        # otherwise the round-trips below could never restore it.
        for tok, _ in tokens:
            check(
                f"minted token {tok!r} matches the whole-response restore pattern",
                _TOK_TOKEN_RE.fullmatch(tok) is not None,
            )
            check(
                f"minted token {tok!r} matches the streamed restore pattern",
                _STREAM_TOKEN_RE.fullmatch(tok) is not None,
            )

        # Build a response embedding every minted token in prose.
        response = "Report: " + ", ".join(
            f"{tok} stands for a value" for tok, _ in tokens
        ) + ". End."

        # Whole-response restore via Tokenizer.restore: every token resolves to its
        # value and ZERO tokens remain.
        tokenizer = Tokenizer(store, detector=lambda _t: [])
        restored_whole = tokenizer.restore(response)
        for tok, value in tokens:
            check(
                f"whole-response restore replaces {tok!r} with its value",
                tok not in restored_whole and value in restored_whole,
            )
        check(
            "whole-response restore leaves zero leftover tokens",
            _TOK_TOKEN_RE.search(restored_whole) is None,
        )

        # Streamed restore via StreamRestorer (fed char-by-char to force split
        # tokens across chunk boundaries): same result, zero leftover tokens.
        restored_stream = _stream_restore(
            lambda: StreamRestorer(store.lookup), response
        )
        for tok, value in tokens:
            check(
                f"streamed restore replaces {tok!r} with its value",
                tok not in restored_stream and value in restored_stream,
            )
        check(
            "streamed restore leaves zero leftover tokens",
            _STREAM_TOKEN_RE.search(restored_stream) is None,
        )
        check(
            "streamed restore matches whole-response restore exactly",
            restored_stream == restored_whole,
        )

        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        conn.close()


if __name__ == "__main__":
    main()
