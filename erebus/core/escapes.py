"""``~`` escape-marker parsing — words the user explicitly opted out of tokenizing.

Leaf module (stdlib ``re`` only).
"""
from __future__ import annotations

import re

# Bound the word run (\S{1,128}) so this never backtracks quadratically on long
# whitespace-free blobs (base64, minified JS, long log lines). Escape targets are
# short words; nothing longer than 128 chars is a name to escape.
# (specs/003-proxy-tokenize-latency)
_ESCAPE_RE = re.compile(r'(\S{1,128})~([)\]}"\'`.,:;!?]*)(?=\s|$)')
_PUNCTUATION_LEFT = "\"'`([{"
_PUNCTUATION_RIGHT = "\"'`)]}.,:;!?"
_MULTIWORD_ESCAPE_LOOKBACK = 4


def _strip_punctuation(word: str) -> str:
    """Strip surrounding quotes, parens, brackets, and trailing punctuation."""
    return word.lstrip(_PUNCTUATION_LEFT).rstrip(_PUNCTUATION_RIGHT)


def _parse_escapes(text: str) -> tuple[set[str], str]:
    """
    Parse ~ escape markers from text.

    Returns (escaped_words, cleaned_text). The cleaned text has all ~ markers
    stripped while preserving surrounding punctuation.

    Handles:
      - Trailing punctuation: "Smith~." "Smith~," "Smith~)"
      - Multi-word names: walks back up to _MULTIWORD_ESCAPE_LOOKBACK words
        so "Jan Willem de Vries~" escapes each part and all combined phrases
      - Surrounding quotes: ("Smith~") escapes "smith", not '"smith'
    """
    escaped: set[str] = set()

    # Fast path: the overwhelming majority of text has no escape markers, so
    # skip all scanning (and the quadratic-prone word walk) entirely.
    if '~' not in text:
        return escaped, text

    for m in _ESCAPE_RE.finditer(text):
        clean = _strip_punctuation(m.group(1)).lower()
        if clean:
            escaped.add(clean)

    # Multi-word escape: walk back through preceding words and register both
    # individual words and the combined phrases (so GLiNER's multi-word span
    # match is also caught).
    words = text.split()
    for i, w in enumerate(words):
        if '~' not in w:
            continue
        clean_current = _strip_punctuation(w.replace('~', '')).lower()
        if not clean_current:
            continue
        phrase = [clean_current]
        for j in range(1, min(_MULTIWORD_ESCAPE_LOOKBACK + 1, i + 1)):
            prev = _strip_punctuation(words[i - j].replace('~', '')).lower()
            if not prev:
                break
            phrase.insert(0, prev)
            escaped.add(prev)
            escaped.add(' '.join(phrase))

    cleaned = _ESCAPE_RE.sub(r'\1\2', text)
    return escaped, cleaned
