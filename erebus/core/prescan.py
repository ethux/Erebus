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

from .knownvalues import KnownValueView
from .modes import _MIN_LENGTHS
from .patterns import _replace_outside_tokens, _replace_outside_tokens_word

_TOKEN_LABEL_RE = re.compile(r"^\[([A-Z_]+)_\d+_[0-9a-f]+\]$")


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

    __slots__ = ("_generation", "_pairs", "_skipped")

    def __init__(self) -> None:
        self._generation: int = -1  # -1 != any real generation -> first build
        self._pairs: list[tuple[str, str, bool]] = []
        self._skipped: tuple[str, ...] = ()

    def _rebuild(self, view: KnownValueView) -> None:
        """Build the longest-value-first index for ``view`` and cache it keyed
        on its generation."""
        eligible, skipped = [], []
        for token, value in view.token_view.items():
            if not value:
                continue
            stripped = value.strip()
            if len(stripped) < 2:
                skipped.append(token)
                continue
            eligible.append((value, token, len(stripped) < _label_min(token)))
        self._pairs = sorted(eligible, key=lambda pair: len(pair[0]), reverse=True)
        new_skipped = tuple(sorted(skipped))
        if new_skipped and new_skipped != self._skipped:
            # Throttled: only when the degenerate set changes, not per rebuild.
            print(f"erebus: known-value pre-scan ignoring {len(new_skipped)} degenerate "
                  f"stored value(s) ({', '.join(new_skipped[:5])}); they stay resolvable "
                  f"but never drive replacements", file=sys.stderr)
        self._skipped = new_skipped
        self._generation = view.generation

    def apply(self, text: str, view: KnownValueView,
              excluded: frozenset[str] = frozenset()) -> str:
        """Replace every known value in ``text`` with its existing token.

        Longest value first, never inside an existing token. Values in
        ``excluded`` (lowercased: ``~`` escapes, active allowances,
        allowed_names) are skipped — the user opted those out. The index is
        rebuilt only when ``view.generation`` changed since the last build, so
        steady-state calls pay only for the scan, not for re-sorting the store.
        """
        if not text:
            return text
        if view.generation != self._generation:
            self._rebuild(view)
        if not self._pairs:
            return text
        for value, token, word_bounded in self._pairs:
            if excluded and value.lower() in excluded:
                continue
            if value in text:
                replace = _replace_outside_tokens_word if word_bounded else _replace_outside_tokens
                text = replace(text, value, token)
        return text
