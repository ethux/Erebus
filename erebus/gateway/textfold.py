"""Offset-preserving text fold for known values (spec 015 "Request path").

``fold(text)`` returns the NFC, per-code-point casefolded, whitespace-collapsed and
trimmed form of ``text`` plus ``offsets``: ``offsets[i]`` is the index in ``text`` of
the character folded character ``i`` came from, and ``offsets[-1]`` is the end of the
last kept character. A folded span ``[a, b)`` is therefore ``text[offsets[a]:offsets[b]]``,
and ``offsets[a] == offsets[a - 1]`` means ``a`` falls inside one character's expansion
("ß" folds to "ss"). The blind index uses the same fold (``normalize_value``), so a
matched span mints the token of the catalog value it matched.

Pure and stdlib only. Text that is NFC already and folds one character per character
(nearly every request) takes a path that does no per-character Python work.
"""
from __future__ import annotations

import re
import unicodedata

# A run the collapse changes: two or more whitespace characters, or one that is not a space.
_RUN = re.compile(r"\s{2,}|[^\S ]")


def fold(text: str) -> tuple[str, list[int]]:
    """Return ``(folded, offsets)`` for ``text``; see the module docstring."""
    if unicodedata.is_normalized("NFC", text):
        low = text.casefold()
        if len(low) == len(text):  # casefold never shrinks a character, so this is 1:1
            return _collapse(low)
    return _fold_slow(text)


def _collapse(low: str) -> tuple[str, list[int]]:
    """Collapse and trim whitespace in a 1:1 casefolded string."""
    start = len(low) - len(low.lstrip())
    stop = len(low.rstrip())
    if start >= stop:
        return "", [0]
    parts: list[str] = []
    offsets: list[int] = []
    pos = start
    for run in _RUN.finditer(low, start, stop):
        parts.append(low[pos:run.start()])
        parts.append(" ")
        offsets.extend(range(pos, run.start() + 1))
        pos = run.end()
    parts.append(low[pos:stop])
    offsets.extend(range(pos, stop + 1))
    return "".join(parts), offsets


def _segments(text: str) -> list[tuple[int, int]]:
    """Split ``text`` where NFC cannot join the characters on either side."""
    bounds: list[tuple[int, int]] = []
    seg = 0
    for i in range(1, len(text)):
        ch = text[i]
        if unicodedata.combining(ch):
            continue
        head = unicodedata.normalize("NFC", text[seg:i])
        if unicodedata.normalize("NFC", text[seg:i + 1]) == head + unicodedata.normalize("NFC", ch):
            bounds.append((seg, i))
            seg = i
    if text:
        bounds.append((seg, len(text)))
    return bounds


def _fold_slow(text: str) -> tuple[str, list[int]]:
    """General path: NFC per segment, casefold per code point, collapse whitespace."""
    out: list[str] = []
    offsets: list[int] = []
    end = 0
    pending_space = -1  # source index of a whitespace run not yet emitted
    for seg_start, seg_end in _segments(text):
        for ch in unicodedata.normalize("NFC", text[seg_start:seg_end]):
            if ch.isspace():
                if pending_space < 0:
                    pending_space = seg_start
                continue
            if pending_space >= 0 and out:
                out.append(" ")
                offsets.append(pending_space)
            pending_space = -1
            for piece in ch.casefold():
                out.append(piece)
                offsets.append(seg_start)
            end = seg_end
    offsets.append(end)
    return "".join(out), offsets
