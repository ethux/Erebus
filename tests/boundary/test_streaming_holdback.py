"""Boundary tests for US1 (streaming): StreamDetokenizer holdback.

A model response streams back in fragments that split a token mid-string.
The StreamDetokenizer must hold back any increment that could be a partial
token, and only ever emit token-safe text: at no point may the real-world
stream contain a partial token (an unclosed '[') and no full token may
survive into the final concatenation. The final assembled output must be
the detokenized real value plus the surrounding plain text.

Assertions run only on the real-world side: the strings actually emitted
to the consumer (concatenated feed/flush return values) inside an isolated
temp HOME, with the daemon stubbed up and mode='strict' so names always
tokenize. All fixture values are synthetic.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from helpers import (
    TOKEN_RE,
    IsolatedBoundaryHome,
    assert_value_absent,
    daemon_stub,
    fake_clock,
    person_entity,
)

NAME = "Jan Modaal"
NAME_2 = "Mies Modaal"


def _seed_token(boundary, value):
    """Tokenize `value` through the boundary and return its minted token."""
    tokenized, new_tokens = boundary.to_model(value)
    assert_value_absent(tokenized, value)
    match = TOKEN_RE.search(tokenized)
    assert match, f"strict mode did not tokenize {value!r}: {tokenized!r}"
    token = match.group(0)
    assert new_tokens.get(token) == value, (
        f"new_tokens does not map {token!r} -> {value!r}: {new_tokens!r}"
    )
    return token


def _mid_token_chunks(token, tail):
    """Split token+tail into 3 fragments with both cuts strictly mid-token,
    e.g. '[PERS' / 'ON_1_ab' / 'cd12] done'."""
    assert len(token) >= 6, f"token too short to split mid-token: {token!r}"
    cut1 = max(1, len(token) // 3)
    cut2 = min(len(token) - 1, max(cut1 + 1, (2 * len(token)) // 3))
    full = token + tail
    chunks = [full[:cut1], full[cut1:cut2], full[cut2:]]
    assert "".join(chunks) == full
    # Both boundaries land inside the token: every fragment is token-partial.
    assert "]" not in chunks[0] and "]" not in chunks[1]
    return chunks


def _assert_token_safe(emitted_so_far):
    """The concatenated emitted output never contains a partial or full token."""
    open_idx = emitted_so_far.rfind("[")
    if open_idx != -1:
        assert "]" in emitted_so_far[open_idx:], (
            f"partial token emitted (unclosed '['): {emitted_so_far!r}"
        )
    assert TOKEN_RE.search(emitted_so_far) is None, (
        f"full token leaked into emitted stream: {emitted_so_far!r}"
    )


def test_holdback_single_stream_mid_token_fragments():
    with IsolatedBoundaryHome() as env, fake_clock(), \
            daemon_stub("up", entities_for=lambda t: person_entity(t, NAME)):
        from erebus.core import Boundary, StreamDetokenizer

        boundary = Boundary.from_config(
            env.repo_config(mode="strict"), str(env.project), source="test")
        token = _seed_token(boundary, NAME)

        chunks = _mid_token_chunks(token, " done")
        sd = StreamDetokenizer(boundary)

        emitted = ""
        for chunk in chunks:
            out = sd.feed("key-a", chunk)
            assert isinstance(out, str), f"feed returned {type(out).__name__}"
            emitted += out
            _assert_token_safe(emitted)

        emitted += sd.flush("key-a")
        _assert_token_safe(emitted)

        assert token not in emitted, "full token survived into final output"
        assert emitted == NAME + " done", (
            f"final stream output wrong: {emitted!r} != {NAME + ' done'!r}"
        )


def test_two_keys_stream_concurrently_without_cross_talk():
    finder = lambda t: person_entity(t, NAME) + person_entity(t, NAME_2)
    with IsolatedBoundaryHome() as env, fake_clock(), \
            daemon_stub("up", entities_for=finder):
        from erebus.core import Boundary, StreamDetokenizer

        boundary = Boundary.from_config(
            env.repo_config(mode="strict"), str(env.project), source="test")
        token_a = _seed_token(boundary, NAME)
        token_b = _seed_token(boundary, NAME_2)
        assert token_a != token_b, "distinct values minted the same token"

        chunks_a = _mid_token_chunks(token_a, " done")
        chunks_b = _mid_token_chunks(token_b, " klaar")

        sd = StreamDetokenizer(boundary)
        out_a, out_b = "", ""
        # Interleave the two streams chunk by chunk under independent keys.
        for chunk_a, chunk_b in zip(chunks_a, chunks_b):  # noqa: B905
            out_a += sd.feed("key-a", chunk_a)
            out_b += sd.feed("key-b", chunk_b)
            _assert_token_safe(out_a)
            _assert_token_safe(out_b)

        out_a += sd.flush("key-a")
        out_b += sd.flush("key-b")
        _assert_token_safe(out_a)
        _assert_token_safe(out_b)

        assert out_a == NAME + " done", f"stream A corrupted: {out_a!r}"
        assert out_b == NAME_2 + " klaar", f"stream B corrupted: {out_b!r}"
        # No cross-talk: neither stream carries the other's value or token.
        assert NAME_2 not in out_a and token_b not in out_a, (
            f"stream B content leaked into stream A: {out_a!r}"
        )
        assert NAME not in out_b and token_a not in out_b, (
            f"stream A content leaked into stream B: {out_b!r}"
        )


if __name__ == "__main__":
    from helpers import run
    run([
        test_holdback_single_stream_mid_token_fragments,
        test_two_keys_stream_concurrently_without_cross_talk,
    ], "StreamDetokenizer holdback (US1 streaming)")
