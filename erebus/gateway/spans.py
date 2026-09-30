"""One-pass overlap resolution for spans found on the same original text.

Shared by the detector (regex before GLiNER) and the tokenizer (known values before the
detector): longest span first, ties to the preferred list, then the earlier start. Existing
tokens are pre-placed as blockers, so nothing is minted inside or around one.
"""
from __future__ import annotations

import bisect

from erebus.core.patterns import TOKEN_RE

Span = tuple[int, int, str]


def merge_spans(preferred: list[Span], other: list[Span], text: str) -> list[Span]:
    """Disjoint spans by start: longest first, ties to ``preferred``, none touching a token."""
    kept: list[tuple[int, int, str | None]] = [(m.start(), m.end(), None) for m in TOKEN_RE.finditer(text)]
    starts = [start for start, _end, _label in kept]
    ranked = sorted([(span, 0) for span in preferred] + [(span, 1) for span in other],
                    key=lambda item: (item[0][0] - item[0][1], item[1], item[0][0]))
    for (start, end, label), _source in ranked:
        i = bisect.bisect_left(starts, start)
        if end <= start or (i and kept[i - 1][1] > start) or (i < len(kept) and kept[i][0] < end):
            continue
        starts.insert(i, start)
        kept.insert(i, (start, end, label))
    return [(start, end, label) for start, end, label in kept if label is not None]
