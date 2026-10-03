"""Gateway tokenize/restore over a tenant-scoped store (research R1).

The gateway orchestrates detection + the per-scope store directly rather than
editing ``erebus.core.Boundary``. The detector is injectable (a callable
``text -> [(start, end, label)]``); the production detector wraps the
tenant-agnostic ``erebus.core`` detection, and tests inject a deterministic fake.

Known values (spec 015 D3): the tenant's matcher and the detector both run on the
original text; their spans merge once, longest first, ties to the known value, so an
entity is never split or tokenized twice. A request plans every text first
(:meth:`Tokenizer.collect`) and then mints all its spans in one ``mint_many`` call.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Protocol

from .spans import Span, merge_spans
from .store.known_value_store import KnownValueStore

# Matches the placeholder shape minted by the store / erebus.core tokenizer.
_TOKEN_RE = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6,}\]")

Detector = Callable[[str], "list[tuple[int, int, str]]"]  # (start, end, label)


class Matcher(Protocol):
    """A tenant's known-value matcher (``known_values.KnownValueMatcher``)."""

    def match(self, text: str) -> list[Span]: ...


class Tokenizer:
    """Per-scope tokenize (world -> model) and restore (model -> world)."""

    def __init__(self, store: KnownValueStore, detector: Detector, matcher: Matcher | None = None) -> None:
        self._store = store
        self._detect = detector
        self._matcher = matcher
        # (text, known values on?) -> (merged spans, how many of them are known values)
        self._plans: dict[tuple[str, bool], tuple[list[Span], int]] = {}
        self._tokens: dict[tuple[str, str], str] = {}
        self._collecting = False
        self.known_hits = 0

    def spans(self, text: str, known: bool = True) -> list[Span]:
        """The merged spans of ``text`` (cached per request, so each text is detected once)."""
        key = (text, known)
        plan = self._plans.get(key)
        if plan is None:
            found = self._matcher.match(text) if known and self._matcher is not None else []
            merged = merge_spans(found, self._detect(text), text)
            plan = self._plans[key] = (merged, len(set(merged) & set(found)))
        return plan[0]

    def collect(self) -> None:
        """Plan only: :meth:`tokenize` records spans and returns the text unchanged."""
        self._collecting = True

    def mint_collected(self) -> None:
        """Mint every planned span in one batch, then let :meth:`tokenize` substitute."""
        self._collecting = False
        self._mint([(text[s:e], label) for (text, _k), (spans, _n) in self._plans.items() for s, e, label in spans])

    def _mint(self, pairs: list[tuple[str, str]]) -> None:
        missing = list(dict.fromkeys(p for p in pairs if p not in self._tokens))
        if missing:
            self._tokens.update(self._store.mint_many(missing))

    def tokenize(self, text: str, known: bool = True) -> str:
        spans = self.spans(text, known)
        if self._collecting or not spans:
            return text
        self._mint([(text[s:e], label) for s, e, label in spans])
        self.known_hits += self._plans[(text, known)][1]
        out: list[str] = []
        last = 0
        for start, end, label in spans:
            out.append(text[last:start])
            out.append(self._tokens[(text[start:end], label)])
            last = end
        out.append(text[last:])
        return "".join(out)

    def restore(self, text: str) -> str:
        return _TOKEN_RE.sub(lambda m: self._store.lookup(m.group(0)) or m.group(0), text)
