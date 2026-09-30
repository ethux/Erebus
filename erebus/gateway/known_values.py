"""Per-tenant known-value matcher (spec 015 D4, "Request path" step 1).

An Aho-Corasick automaton (``pyahocorasick``) over the folded known values of one
tenant. ``match(text)`` folds the request text with ``textfold.fold``, collects every
candidate, drops those that are not a whole word (a non-word character or the text edge
on both sides, and not splitting one character's expansion) or that touch an existing
token, then resolves overlaps longest-first (ties: the earlier start). Spans are on the
original text. One label per folded value: the first one ``build`` sees, so the caller
orders its pairs (the catalog loader puts manual entries first, then the oldest).

Pure: no database or config import. Built by ``catalog.load_matcher``; values live only
in memory (the automaton holds the folded keys, never a copy on disk).
"""
from __future__ import annotations

import bisect
import unicodedata
from collections.abc import Iterable

import ahocorasick

from ..cataloging.field_rules import MIN_VALUE_CHARS, clean_value
from ..core.patterns import TOKEN_RE
from .textfold import fold

Span = tuple[int, int, str]

# An automaton value packs the key length and the label index into one int (cheaper than a tuple).
_LABEL_BITS = 16
_LABEL_MASK = (1 << _LABEL_BITS) - 1


def _word(ch: str) -> bool:
    """A character that continues a word: letters, digits and combining marks."""
    return ch.isalnum() or unicodedata.category(ch)[0] == "M"


class KnownValueMatcher:
    """Immutable matcher over one tenant's known values."""

    def __init__(self, automaton: ahocorasick.Automaton, labels: list[str], size: int) -> None:
        self._auto = automaton
        self._labels = labels
        self._size = size

    @classmethod
    def build(cls, pairs: Iterable[tuple[str, str]]) -> KnownValueMatcher:
        """Build from ``(value, label)`` pairs; values under 3 characters are skipped.

        A value folding to a key already added keeps the earlier label.
        """
        auto = ahocorasick.Automaton()
        labels: list[str] = []
        index: dict[str, int] = {}
        size = 0
        for value, label in pairs:
            cleaned = clean_value(value)
            if len(cleaned) < MIN_VALUE_CHARS:
                continue
            key = fold(cleaned)[0]
            if len(key) < MIN_VALUE_CHARS or auto.exists(key):
                continue
            idx = index.get(label)
            if idx is None:
                if len(labels) > _LABEL_MASK:
                    raise ValueError("too many known-value labels")
                idx = index[label] = len(labels)
                labels.append(label)
            auto.add_word(key, (len(key) << _LABEL_BITS) | idx)
            size += 1
        if size:
            auto.make_automaton()
        return cls(auto, labels, size)

    def __len__(self) -> int:
        return self._size

    def match(self, text: str) -> list[Span]:
        """Disjoint ``(start, end, label)`` spans of known values in ``text``, by start."""
        if not self._size or not text:
            return []
        folded, offsets = fold(text)
        n = len(folded)
        tokens = [(t.start(), t.end()) for t in TOKEN_RE.finditer(text)]
        token_starts = [s for s, _e in tokens]
        candidates: list[tuple[int, int, int, int]] = []
        for last, packed in self._auto.iter(folded):
            b = last + 1
            a = b - (packed >> _LABEL_BITS)
            if a and (_word(folded[a - 1]) or offsets[a] == offsets[a - 1]):
                continue
            if b < n and (_word(folded[b]) or offsets[b] == offsets[b - 1]):
                continue
            start, end = offsets[a], offsets[b]
            i = bisect.bisect_right(token_starts, start)
            if (i and tokens[i - 1][1] > start) or (i < len(tokens) and tokens[i][0] < end):
                continue
            candidates.append((start - end, start, end, packed & _LABEL_MASK))
        candidates.sort()
        kept: list[Span] = []
        starts: list[int] = []
        for _neg, start, end, idx in candidates:
            i = bisect.bisect_left(starts, start)
            if (i and kept[i - 1][1] > start) or (i < len(kept) and kept[i][0] < end):
                continue
            starts.insert(i, start)
            kept.insert(i, (start, end, self._labels[idx]))
        return kept
