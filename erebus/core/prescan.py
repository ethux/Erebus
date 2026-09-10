"""Generation-cached known-value pre-scan (FR-011 efficiency, T039).

The boundary unconditionally retokenizes already-known values before the
detector runs and on the cache-hit path: every stored value that still appears
literally in the text is replaced by its existing token (longest value first,
never inside an existing token). Done naively that re-sorts the whole store and
scans the text once per pair on EVERY call, which does not scale (SC-010b: a
10,000-entry store must add <=100ms on a 16KB message).

``KnownValuePrescan`` amortizes the cost by building the scan index ONCE per
view generation and reusing it until the store mutates (the view generation
strictly increases on any committed write, so a generation match means the
known values are unchanged). The index is ``_pairs`` — (value, token,
word_bounded) sorted longest-value-first, the exact order
``_retokenize_known_values`` used, so the replacement semantics are identical.
Each call still skips a pair whose value is not a substring of the text before
doing the (more expensive) outside-token replacement.

Replacement rules per stored value:
  * degenerate (stripped length < 2): never scanned — a legacy-imported
    1-char "value" would rewrite that character everywhere in prose. The
    token stays resolvable on the from_model path.
  * short (below the label's detection minimum, e.g. a balanced-mode 2-char
    surname): scanned with whole-word boundaries so 'Li' tokenizes "ask Li"
    but never mangles "Lithium". The pre-scan is the ONLY layer protecting
    these standalone short values, so they must stay in the index.
  * everything else: the historical bare-substring replace.

The replacement itself reuses ``patterns._replace_outside_tokens`` (and its
word-bounded sibling), the canonical helpers that skip existing token regions;
this module never re-implements token-shape handling.
"""
from __future__ import annotations

import re
import sys
from collections import Counter

from .knownvalues import KnownValueView
from .modes import _MIN_LENGTHS
from .patterns import _replace_outside_tokens, _replace_outside_tokens_word

_TOKEN_LABEL_RE = re.compile(r"^\[([A-Z_]+)_\d+_[0-9a-f]+\]$")
_GRAM = 3  # gram length of the candidate index (values shorter than this are probed always)


def _grams(text: str) -> set[str]:
    return {text[i:i + _GRAM] for i in range(len(text) - _GRAM + 1)}


def _label_min(token: str) -> int:
    match = _TOKEN_LABEL_RE.match(token)
    return _MIN_LENGTHS.get(match.group(1) if match else "", 2)


class KnownValuePrescan:
    """Per-Boundary cached index for the FR-011 known-value pre-scan.

    ``apply`` rebuilds the index only when the supplied view's generation
    differs from the one the cached index was built for; otherwise it reuses
    the already-sorted pairs. The instance holds one index at a time (the
    latest generation seen), so memory stays bounded by the store size.
    """

    __slots__ = ("_by_gram", "_generation", "_gram_freq", "_key_of", "_pairs", "_seq", "_short", "_skipped")

    def __init__(self) -> None:
        self._generation: int = -1  # -1 != any real generation -> first build
        # token -> (value, token, word_bounded, seq); seq keeps the historical
        # tie order (view order on first build, arrival order after).
        self._pairs: dict[str, tuple[str, str, bool, int]] = {}
        self._by_gram: dict[str, set[str]] = {}   # index gram -> tokens keyed under it
        self._key_of: dict[str, str] = {}         # token -> its index gram
        self._gram_freq: Counter[str] = Counter()  # gram -> stored values containing it
        self._short: set[str] = set()             # values shorter than _GRAM: always probed
        self._seq = 0
        self._skipped: tuple[str, ...] = ()

    def _rebuild(self, view: KnownValueView) -> None:
        """Bring the index to ``view``: add pairs the store gained, drop the
        ones it lost. Incremental, so a generation bump (one per turn that
        mints tokens) costs O(changed pairs), not a re-index of the store."""
        token_view = view.token_view
        for token in [t for t, pair in self._pairs.items() if token_view.get(t) != pair[0]]:
            self._remove(token)
        skipped = []
        for token, value in token_view.items():
            if token in self._pairs or not value:
                continue
            stripped = value.strip()
            if len(stripped) < 2:
                skipped.append(token)
                continue
            self._add(token, value, len(stripped) < _label_min(token))
        new_skipped = tuple(sorted(skipped))
        if new_skipped and new_skipped != self._skipped:
            # Throttled: only when the degenerate set changes, not per rebuild.
            print(f"erebus: known-value pre-scan ignoring {len(new_skipped)} degenerate "
                  f"stored value(s) ({', '.join(new_skipped[:5])}); they stay resolvable "
                  f"but never drive replacements", file=sys.stderr)
        self._skipped = new_skipped
        self._generation = view.generation

    def _add(self, token: str, value: str, word_bounded: bool) -> None:
        self._seq += 1
        self._pairs[token] = (value, token, word_bounded, self._seq)
        grams = _grams(value)
        if not grams:
            self._short.add(token)
            return
        self._gram_freq.update(grams)
        # Key each value under its rarest gram: names cluster on a shared first
        # word ("Jan ..."), so a fixed prefix would make them all candidates.
        key = min(grams, key=lambda g: (self._gram_freq[g], g))
        self._key_of[token] = key
        self._by_gram.setdefault(key, set()).add(token)

    def _remove(self, token: str) -> None:
        value = self._pairs.pop(token)[0]
        if token in self._short:
            self._short.discard(token)
            return
        key = self._key_of.pop(token)
        bucket = self._by_gram[key]
        bucket.discard(token)
        if not bucket:
            del self._by_gram[key]
        for gram in _grams(value):
            if self._gram_freq[gram] <= 1:
                del self._gram_freq[gram]
            else:
                self._gram_freq[gram] -= 1

    def apply(self, text: str, view: KnownValueView,
              excluded: frozenset[str] = frozenset()) -> str:
        """Replace every known value in ``text`` with its existing token.

        Longest value first, never inside an existing token. Values in
        ``excluded`` (lowercased: ``~`` escapes, active allowances,
        allowed_names) are skipped — the user opted those out. The index is
        updated only when ``view.generation`` changed since the last build, so
        steady-state calls pay only for the scan, not for re-sorting the store.
        """
        if not text:
            return text
        if view.generation != self._generation:
            self._rebuild(view)
        if not self._pairs:
            return text
        for value, token, word_bounded, _seq in self._candidates(text):
            if excluded and value.lower() in excluded:
                continue
            if value in text:
                replace = _replace_outside_tokens_word if word_bounded else _replace_outside_tokens
                text = replace(text, value, token)
        return text

    def _candidates(self, text: str) -> list[tuple[str, str, bool, int]]:
        """The pairs (longest value first) that can occur in ``text``.

        A value can only match if its index gram occurs in the text, so one
        pass over the text's grams narrows ~13k stored values to the handful
        worth a substring probe. Replacements only ever remove text outside
        existing tokens, so a value absent from the original text stays absent
        after earlier replacements: filtering on the original is exact.
        """
        tokens = set(self._short)
        for gram in _grams(text).intersection(self._by_gram):
            tokens.update(self._by_gram[gram])
        return sorted((self._pairs[token] for token in tokens), key=lambda pair: (-len(pair[0]), pair[3]))
