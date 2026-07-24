"""Streaming token restore with split-token hold-back (FR-002/FR-025; research R3).

A token split across streamed chunks (``[PERS`` / ``ON_1_abcdef]``) is never emitted
partially: the restorer holds back any trailing run starting at an unclosed ``[``
until it completes. A restore failure mid-stream is fatal: the caller stops the
stream fail-closed rather than emitting an unresolved token or partial raw value.
"""
from __future__ import annotations

import re
from collections.abc import Callable

_TOKEN_RE = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6,}\]")


class StreamRestorer:
    """Incremental restorer; feed() returns the safe-to-emit restored prefix."""

    def __init__(self, lookup: Callable[[str], str | None]) -> None:
        self._lookup = lookup
        self._buf = ""

    def feed(self, chunk: str) -> str:
        self._buf += chunk
        cut = self._hold_point(self._buf)
        emit, self._buf = self._buf[:cut], self._buf[cut:]
        return self._restore(emit)

    def flush(self) -> str:
        emit, self._buf = self._buf, ""
        return self._restore(emit)

    @staticmethod
    def _hold_point(text: str) -> int:
        """Index up to which it is safe to emit (hold back a trailing unclosed token)."""
        i = text.rfind("[")
        if i == -1 or "]" in text[i:]:
            return len(text)
        return i

    def _restore(self, text: str) -> str:
        return _TOKEN_RE.sub(lambda m: self._lookup(m.group(0)) or m.group(0), text)
