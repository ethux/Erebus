"""Known-value matcher and the offset-preserving fold (spec 015 "Request path", D4).

Pure. ``fold`` must NFC-normalize, casefold per code point and collapse whitespace
while mapping every folded character back to the original text, so a match on the
folded text lands on the right original characters ("Straße" vs "STRASSE", NFD input,
whitespace runs). ``normalize_value`` is ``fold(v)[0]`` and keeps every blind index of
NFC input. The matcher keeps whole words only, drops candidates inside existing
tokens before resolving overlaps longest-first, picks one label per folded value
(the first added) and skips values under 3 characters.
"""
import os
import random
import sys
import unicodedata

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.core.patterns import TOKEN_RE
from erebus.gateway.crypto.envelope import ScopeCrypto
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.crypto.purposekeys import normalize_value
from erebus.gateway.known_values import KnownValueMatcher
from erebus.gateway.textfold import fold

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _matched(matcher, text):
    return [(text[s:e], label) for s, e, label in matcher.match(text)]


def test_fold():
    folded, offsets = fold("Straße")
    check("fold expands ß to ss", folded == "strasse")
    check("both s of ß map to the ß", offsets == [0, 1, 2, 3, 4, 4, 5, 6])
    folded, offsets = fold("STRASSE")
    check("fold casefolds per code point", folded == "strasse" and offsets == list(range(8)))
    nfd = "Jose\u0301 Garci\u0301a"
    folded, offsets = fold(nfd)
    check("fold composes NFD input", folded == "josé garcía")
    check("a composed character maps to its base", offsets[3] == 3 and offsets[4] == 5 and offsets[-1] == len(nfd))
    folded, offsets = fold("  Jan\n\t de   Vries \n")
    check("fold collapses whitespace runs and trims the ends", folded == "jan de vries")
    check("a collapsed run maps to its first character", offsets[3] == 5 and offsets[4] == 8)
    check("the end offset is the end of the last kept character", offsets[-1] == 18)
    check("the empty string folds to nothing", fold("") == ("", [0]))
    check("whitespace only folds to nothing", fold(" \n ")[0] == "")
    for text in ("Straße", "İstanbul", "ﬁne", "Jose\u0301", "Ǆemal", "Σίσυφος", "a \u00a0 b", "x\u2028y"):
        folded, offsets = fold(text)
        check(f"offsets are monotone and one longer than the fold for {text!r}",
              len(offsets) == len(folded) + 1 and offsets == sorted(offsets) and offsets[-1] <= len(text))


def test_normalize_value():
    for value in ("Jan de Vries", "  acme   BV ", "ZYX.QORBEL@ACME.COM", "Straße", "İstanbul", "a\u00a0b", "x\ty"):
        legacy = " ".join(value.split()).casefold()
        check(f"normalize_value keeps the legacy form of NFC input {value!r}", normalize_value(value) == legacy)
    check("normalize_value equals fold()[0]", normalize_value("  Jan\nDE Vries") == fold("  Jan\nDE Vries")[0])
    nfd, nfc = "Jose\u0301", "José"
    check("NFD and NFC input normalize alike", normalize_value(nfd) == normalize_value(nfc))
    crypto, _ = ScopeCrypto.create(LocalKms(), "scope-fold")
    check("NFD and NFC input share a blind index",
          crypto.blind_index(nfd, "PERSON") == crypto.blind_index(nfc, "PERSON"))
    check("Straße and STRASSE share a blind index",
          crypto.blind_index("Straße", "ADDRESS") == crypto.blind_index("STRASSE", "ADDRESS"))


def test_offsets():
    m = KnownValueMatcher.build([("STRASSE 5", "ADDRESS")])
    check("an ASCII value matches ß text on the original characters",
          _matched(m, "Ga naar Straße 5, links") == [("Straße 5", "ADDRESS")])
    m = KnownValueMatcher.build([("Straße 5", "ADDRESS")])
    check("a ß value matches ASCII text", _matched(m, "Ga naar STRASSE 5.") == [("STRASSE 5", "ADDRESS")])
    check("text after an expansion keeps its offsets",
          _matched(m, "Weiße Straße 5 en Straße 5") == [("Straße 5", "ADDRESS"), ("Straße 5", "ADDRESS")])
    m = KnownValueMatcher.build([("José García", "PERSON")])
    nfd = "Mail Jose\u0301 Garci\u0301a vandaag"
    check("NFD text matches and the span covers the combining marks",
          _matched(m, nfd) == [("Jose\u0301 Garci\u0301a", "PERSON")])
    m = KnownValueMatcher.build([("Jan de Vries", "PERSON")])
    check("a whitespace run in the text still matches", _matched(m, "Bel Jan\n  de\tVries.") ==
          [("Jan\n  de\tVries", "PERSON")])
    check("leading whitespace keeps the offsets", _matched(m, "\n\n  jan DE vries") == [("jan DE vries", "PERSON")])


def test_whole_word():
    m = KnownValueMatcher.build([("acme", "ORGANIZATION"), ("12345678", "IDENTIFIER")])
    check("no match inside a longer word", m.match("acmetools and xacme") == [])
    check("punctuation and text edges are boundaries",
          [t for t, _ in _matched(m, "acme, (acme) acme")] == ["acme", "acme", "acme"])
    check("no match inside a longer number", m.match("ref a123456789 or 123456789") == [])
    check("an underscore is a boundary", _matched(m, "x_acme_y") == [("acme", "ORGANIZATION")])
    m = KnownValueMatcher.build([("Qorbel Zyx", "PERSON")])
    check("a trailing combining mark is part of the word", m.match("Qorbel Zyx\u0303") == [])
    check("case-insensitive", _matched(m, "QORBEL ZYX?") == [("QORBEL ZYX", "PERSON")])
    m = KnownValueMatcher.build([("zyx.qorbel@acme.com", "EMAIL_ADDRESS")])
    check("a value with punctuation matches whole",
          _matched(m, "mail zyx.qorbel@acme.com.") == [("zyx.qorbel@acme.com", "EMAIL_ADDRESS")])


def test_resolution():
    m = KnownValueMatcher.build([("Anna Smit", "PERSON"), ("Smit Holdingsx", "ORGANIZATION")])
    check("the boundary filter runs before longest-first",
          _matched(m, "Anna Smit Holdingsxyz") == [("Anna Smit", "PERSON")])
    m = KnownValueMatcher.build([("Acme", "ORGANIZATION"), ("Acme Holding BV", "ORGANIZATION")])
    check("the longest match wins and later ones still match",
          _matched(m, "Acme Holding BV and Acme") == [("Acme Holding BV", "ORGANIZATION"), ("Acme", "ORGANIZATION")])
    m = KnownValueMatcher.build([("Smit Jan", "PERSON"), ("Jan Smit", "PERSON")])
    check("equal lengths go to the earlier start", _matched(m, "Jan Smit Jan") == [("Jan Smit", "PERSON")])
    m = KnownValueMatcher.build([("Acme BV", "ORGANIZATION"), ("ACME  bv", "PERSON"), ("acme bv", "IDENTIFIER")])
    check("one label per folded value: the first added", _matched(m, "acme bv") == [("acme bv", "ORGANIZATION")])
    check("a folded value counts once", len(m) == 1)


def test_tokens():
    m = KnownValueMatcher.build([("person", "ORGANIZATION"), ("abcdef", "IDENTIFIER"), ("acme corp", "ORGANIZATION")])
    text = "[PERSON_1_abcdef] and person, [CATALOG_ACME_X_abcdef12] [EMAIL_ADDRESS_2_0a1b2c3d]"
    spans = m.match(text)
    check("nothing inside an existing token matches", _matched(m, text) == [("person", "ORGANIZATION")])
    tokens = [(t.start(), t.end()) for t in TOKEN_RE.finditer(text)]
    check("no span overlaps a token", all(e <= ts or s >= te for s, e, _ in spans for ts, te in tokens))


def test_short_and_empty():
    m = KnownValueMatcher.build([("ab", "PERSON"), ("ß", "PERSON"), ("e\u0301x", "PERSON"), ("  a ", "PERSON"),
                                 ("", "PERSON"), ("abc", "IDENTIFIER")])
    check("values under 3 characters are skipped", len(m) == 1)
    check("a 3-character value matches", _matched(m, "ab abc ß") == [("abc", "IDENTIFIER")])
    empty = KnownValueMatcher.build([])
    check("an empty matcher matches nothing", empty.match("Jan de Vries") == [] and len(empty) == 0)
    check("empty text matches nothing", m.match("") == [])


_WORDS = ("Straße", "STRASSE", "Jose\u0301", "José", "acme", "Acme BV", "Jan", "de", "Vries", "Zyx", "Qorbel",
          "İstanbul", "ﬁne", "[PERSON_1_abcdef]", "x@y.nl", "123456", "Σίσυφος")
_SEPS = (" ", "  ", "\n", ", ", ".", "-", "", "\t ")


def _word_char(ch):
    return ch.isalnum() or unicodedata.category(ch).startswith("M")


def test_properties():
    rng = random.Random(15)
    values = ["Straße", "josé", "Acme BV", "Jan de Vries", "Zyx Qorbel", "istanbul", "fine", "x@y.nl", "123456",
              "Qorbel Jan", "de Vries Acme"]
    m = KnownValueMatcher.build([(v, "L") for v in values])
    keys = {normalize_value(v) for v in values}
    bad = 0
    for _ in range(3000):
        text = "".join(rng.choice(_WORDS) + rng.choice(_SEPS) for _ in range(rng.randint(0, 12)))
        spans = m.match(text)
        last = 0
        for s, e, _label in spans:
            ok = s >= last and normalize_value(text[s:e]) in keys
            ok = ok and (s == 0 or not _word_char(text[s - 1])) and (e == len(text) or not _word_char(text[e]))
            bad += not ok
            last = e
    check("3000 random texts: every span is a whole known value, disjoint and in order", bad == 0)


def main():
    print("\n=== Gateway known values: fold and matcher ===\n")
    test_fold()
    test_normalize_value()
    test_offsets()
    test_whole_word()
    test_resolution()
    test_tokens()
    test_short_and_empty()
    test_properties()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
