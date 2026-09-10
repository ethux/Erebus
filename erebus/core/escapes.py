"""``~`` escape-marker parsing — words the user explicitly opted out of tokenizing.

Leaf module (stdlib ``re`` only).
"""
from __future__ import annotations

import re

# Bound the word run (\S{1,128}) so this never backtracks quadratically on long
# whitespace-free blobs (base64, minified JS, long log lines). Escape targets are
# short words; nothing longer than 128 chars is a name to escape.
# (specs/003-proxy-tokenize-latency)
# The run itself may not contain ``~``: ``~~strike~~``, ``a~b`` and ``~/path``
# are code/markdown, not escapes. Every false match used to grant a store
# allowance (a DB write, a generation bump, a legacy-map rewrite); 167k such
# rows had accumulated from proxied tool output by 2026-09-05.
_ESCAPE_RE = re.compile(r'([^\s~]{1,128})~([)\]}"\'`.,:;!?]*)(?=\s|$)')
_PUNCTUATION_LEFT = "\"'`([{"
_PUNCTUATION_RIGHT = "\"'`)]}.,:;!?"
_MULTIWORD_ESCAPE_LOOKBACK = 4


def _strip_punctuation(word: str) -> str:
    """Strip surrounding quotes, parens, brackets, and trailing punctuation."""
    return word.lstrip(_PUNCTUATION_LEFT).rstrip(_PUNCTUATION_RIGHT)


def _escape_target(word: str) -> str:
    """The lowercased escape target in ``word`` (the text before the marker),
    or '' when it is not a word a user would escape: at least two characters
    with something alphanumeric in them (``=~``, ``-~`` are operators)."""
    clean = _strip_punctuation(word).lower()
    if len(clean) < 2 or not any(ch.isalnum() for ch in clean):
        return ""
    return clean


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

    # Multi-word escape: walk back through preceding words and register both
    # individual words and the combined phrases (so GLiNER's multi-word span
    # match is also caught). Only a word that IS an escape (trailing marker,
    # word-like target) anchors a walk-back.
    words = text.split()
    for i, w in enumerate(words):
        match = _ESCAPE_RE.fullmatch(w)
        if match is None:
            continue
        clean_current = _escape_target(match.group(1))
        if not clean_current:
            continue
        escaped.add(clean_current)
        phrase = [clean_current]
        for j in range(1, min(_MULTIWORD_ESCAPE_LOOKBACK + 1, i + 1)):
            prev = _strip_punctuation(words[i - j].replace('~', '')).lower()
            if not prev:
                break
            phrase.insert(0, prev)
            escaped.add(prev)
            escaped.add(' '.join(phrase))

    def _strip_marker(match: re.Match) -> str:
        if not _escape_target(match.group(1)):
            return match.group(0)  # not an escape: leave the text untouched
        return match.group(1) + match.group(2)

    cleaned = _ESCAPE_RE.sub(_strip_marker, text)
    return escaped, cleaned
