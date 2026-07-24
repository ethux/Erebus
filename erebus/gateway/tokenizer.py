"""Gateway tokenize/restore over a tenant-scoped store (research R1).

The gateway orchestrates detection + the per-scope store directly rather than
editing ``erebus.core.Boundary``. The detector is injectable (a callable
``text -> [(start, end, label)]``); the production detector wraps the
tenant-agnostic ``erebus.core`` detection, and tests inject a deterministic fake.
"""
from __future__ import annotations

import re
from collections.abc import Callable

from .store.known_value_store import KnownValueStore

# Matches the placeholder shape minted by the store / erebus.core tokenizer.
_TOKEN_RE = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6,}\]")

Detector = Callable[[str], "list[tuple[int, int, str]]"]  # (start, end, label)


class Tokenizer:
    """Per-scope tokenize (world -> model) and restore (model -> world)."""

    def __init__(self, store: KnownValueStore, detector: Detector) -> None:
        self._store = store
        self._detect = detector

    def tokenize(self, text: str) -> str:
        out: list[str] = []
        last = 0
        for start, end, label in sorted(self._detect(text), key=lambda s: s[0]):
            if start < last:
                continue  # drop overlapping spans
            out.append(text[last:start])
            out.append(self._store.mint(text[start:end], label))
            last = end
        out.append(text[last:])
        return "".join(out)

    def restore(self, text: str) -> str:
        return _TOKEN_RE.sub(lambda m: self._store.lookup(m.group(0)) or m.group(0), text)
