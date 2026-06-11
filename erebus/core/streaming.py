"""Streaming hold-back detokenization (contracts/boundary-api.md).

Model responses stream back in fragments that can split a token mid-string
("[PERS" / "ON_1_ab" / "cd12]"). StreamDetokenizer accumulates the raw text
per stream key, detokenizes the whole buffer through the Boundary, and emits
only the increment that cannot be a partial token: no partial token text is
ever emitted (the proxy's _safe_detokenized_increment semantics, moved here).

Adapters keep their wire-format walking (SSE lines, tool-call deltas); this
class is the pure text-level hold-back they feed extracted text through.
"""
from __future__ import annotations

from collections.abc import Hashable


def safe_increment(detokenized: str, emitted_len: int) -> tuple[str, int]:
    """Next safe slice of `detokenized` after `emitted_len`, holding back any
    trailing partial token (an unclosed '[')."""
    safe_end = len(detokenized)
    bracket_pos = detokenized.rfind("[", emitted_len)
    if bracket_pos >= 0 and "]" not in detokenized[bracket_pos:]:
        safe_end = bracket_pos
    return detokenized[emitted_len:safe_end], safe_end


class StreamDetokenizer:
    """Per-key streaming detokenizer over a Boundary.

    feed(key, text) returns only the newly safe detokenized suffix for that
    key's stream; flush(key) returns the held-back remainder at stream end.
    Keys are independent: interleaved streams never cross-talk.
    """

    def __init__(self, boundary):
        self._boundary = boundary
        self._buffers: dict[Hashable, str] = {}
        self._emitted_lens: dict[Hashable, int] = {}

    def feed(self, key: Hashable, text: str) -> str:
        """Append a raw chunk to `key`'s stream; emit the next token-safe slice."""
        buffer = self._buffers.get(key, "") + text
        self._buffers[key] = buffer
        # Quiet resolve: mid-stream an unresolved token may still complete or
        # recover; the FR-018 warning fires once at flush() for what remains.
        detokenized, _unresolved = self._boundary._detokenize(buffer)
        increment, safe_end = safe_increment(detokenized, self._emitted_lens.get(key, 0))
        self._emitted_lens[key] = safe_end
        return increment

    def flush(self, key: Hashable) -> str:
        """End `key`'s stream: emit the held-back remainder (FR-018 applies to
        any token still unresolved) and drop the key's state."""
        buffer = self._buffers.pop(key, "")
        emitted_len = self._emitted_lens.pop(key, 0)
        if not buffer:
            return ""
        detokenized, _unresolved = self._boundary.from_model(buffer)
        return detokenized[emitted_len:]
