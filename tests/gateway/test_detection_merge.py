"""One-pass span merge for the gateway detector (regex + GLiNER).

Pure. ``_merge(regex, ner, text)`` must keep existing tokens untouched, take the longest
span first, give ties to regex, and return disjoint spans sorted by start. A brute-force
property test compares it with a naive reference over thousands of random cases.
"""
import os
import random
import sys
from itertools import pairwise

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.core.patterns import TOKEN_RE
from erebus.gateway.detection import _merge

_passed = 0
_CASES = 5000
_TOKENS = ("[PERSON_1_abcdef]", "[EMAIL_ADDRESS_12_0a1b2c3d]", "[CATALOG_ACME_X_abcdef12]")
_LABELS = ("PERSON", "EMAIL_ADDRESS", "IBAN", "API_KEY")


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _overlaps(a_start, a_end, b_start, b_end):
    return a_start < b_end and a_end > b_start


def _naive(regex, ner, text):
    """Reference: try every candidate in priority order against everything placed so far."""
    placed = [(m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
    ranked = sorted([(s, 0) for s in regex] + [(s, 1) for s in ner],
                    key=lambda c: (-(c[0][1] - c[0][0]), c[1], c[0][0]))
    kept = []
    for (start, end, label), _source in ranked:
        if end <= start or any(_overlaps(start, end, s, e) for s, e in placed):
            continue
        placed.append((start, end))
        kept.append((start, end, label))
    return sorted(kept, key=lambda s: s[0])


def _random_case(rng):
    parts = []
    for _ in range(rng.randint(0, 6)):
        if rng.random() < 0.3:
            parts.append(rng.choice(_TOKENS))
        else:
            parts.append("".join(rng.choice("ab @.1") for _ in range(rng.randint(0, 12))))
    text = "".join(parts)
    n = len(text)

    def spans(count):
        out = []
        for _ in range(count):
            start = rng.randint(0, max(n, 1))
            end = start + rng.randint(-2, 15) if rng.random() < 0.9 else start
            out.append((start, min(end, n), rng.choice(_LABELS)))
        return out

    return spans(rng.randint(0, 8)), spans(rng.randint(0, 8)), text


def _invariants_hold(out, text):
    tokens = [(m.start(), m.end()) for m in TOKEN_RE.finditer(text)]
    starts_sorted = all(a[0] <= b[0] for a, b in pairwise(out))
    disjoint = all(a[1] <= b[0] for a, b in pairwise(out))
    clear_of_tokens = not any(_overlaps(s, e, ts, te) for s, e, _l in out for ts, te in tokens)
    return starts_sorted and disjoint and clear_of_tokens and all(s < e for s, e, _l in out)


def test_rules():
    text = "Mail jan@corp.example, Street 1"
    check("tie goes to regex",
          _merge([(5, 21, "EMAIL_ADDRESS")], [(5, 21, "PERSON")], text) == [(5, 21, "EMAIL_ADDRESS")])
    check("the longest span wins, whichever layer found it",
          _merge([(5, 21, "EMAIL_ADDRESS")], [(0, 30, "ADDRESS")], text) == [(0, 30, "ADDRESS")])
    check("a longer regex span beats a shorter NER span inside it",
          _merge([(0, 19, "PASSWORD")], [(10, 18, "PASSWORD")], "password: hunter22x now")
          == [(0, 19, "PASSWORD")])
    check("disjoint spans from both layers are all kept, sorted by start",
          _merge([(4, 20, "EMAIL_ADDRESS")], [(0, 3, "PERSON")], "Jan jan@corp.example")
          == [(0, 3, "PERSON"), (4, 20, "EMAIL_ADDRESS")])
    tok = "see [PERSON_1_abcdef] and [CATALOG_ACME_abcdef12] ok"
    check("a span inside or across an existing token is dropped",
          _merge([(4, 25, "TOKEN")], [(5, 10, "PERSON"), (30, 40, "PERSON")], tok) == [])
    check("a span next to (not over) a token is kept",
          _merge([], [(0, 4, "PERSON")], tok) == [(0, 4, "PERSON")])
    check("empty and inverted spans are dropped", _merge([(3, 3, "X"), (5, 2, "Y")], [], text) == [])
    check("no spans in, no spans out", _merge([], [], text) == [])


def test_matches_reference():
    rng = random.Random(1609)
    mismatches = broken = 0
    for _ in range(_CASES):
        regex, ner, text = _random_case(rng)
        out = _merge(list(regex), list(ner), text)
        mismatches += out != _naive(regex, ner, text)
        broken += not _invariants_hold(out, text)
    check(f"_merge equals the naive reference on {_CASES} random cases", mismatches == 0)
    check(f"_merge output is sorted, disjoint and clear of tokens on {_CASES} random cases",
          broken == 0)


def main():
    print("\n=== Gateway detection: one-pass span merge ===\n")
    test_rules()
    test_matches_reference()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
