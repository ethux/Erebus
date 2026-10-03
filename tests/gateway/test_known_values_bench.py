"""Known-value matcher benchmark (spec 015 SC-2, D4).

Pure. Builds a matcher over 100,000 synthetic values (names, emails, company names)
and asserts the median time to match one 5 KB request is under 1 ms. It also prints
the build time, the bulk decrypt time for the same number of ciphertexts (what a
replica spends before the build) and the peak RSS.

Manual 1M run (SC-2 at 1,000,000 values per tenant; takes about a minute and some GB):

    EREBUS_BENCH_VALUES=1000000 .venv/bin/python tests/gateway/test_known_values_bench.py

``EREBUS_BENCH_MAX_MS`` overrides the 1 ms budget (default 1.0).
"""
import os
import random
import resource
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.crypto.envelope import ScopeCrypto
from erebus.gateway.crypto.keyprovider import LocalKms
from erebus.gateway.known_values import KnownValueMatcher

_VALUES = int(os.environ.get("EREBUS_BENCH_VALUES", "100000"))
_MAX_MS = float(os.environ.get("EREBUS_BENCH_MAX_MS", "1.0"))
_RUNS = 101
_TEXT_BYTES = 5 * 1024
_SYLLABLES = ("an", "bel", "cor", "dra", "el", "fin", "gor", "hal", "is", "jan", "kor", "lin", "mar", "nor",
              "ol", "pet", "qor", "ros", "sen", "tal", "ul", "van", "wil", "xan", "yor", "zyx")
_PROSE = ("Hi team, please follow up with the customer about the open invoice and the delivery date. "
          "The contract was renewed last week; the address on file is outdated.\n"
          "Kun je dit morgen oppakken en de klant terugbellen over de bestelling?\n\n")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _word(rng):
    return "".join(rng.choice(_SYLLABLES) for _ in range(rng.randint(2, 3))).capitalize()


def _values(rng, count):
    seen = set()
    out = []
    kinds = ("PERSON", "EMAIL_ADDRESS", "ORGANIZATION")
    while len(out) < count:
        first, last = _word(rng), _word(rng)
        kind = kinds[len(out) % 3]
        if kind == "PERSON":
            value = f"{first} {last}"
        elif kind == "EMAIL_ADDRESS":
            value = f"{first.lower()}.{last.lower()}@example.com"
        else:
            value = f"{first} {last} BV"
        if value.casefold() not in seen:
            seen.add(value.casefold())
            out.append((value, kind))
    return out


def _text(rng, values):
    parts = []
    size = 0
    while size < _TEXT_BYTES:
        chunk = _PROSE if rng.random() < 0.7 else f"Contact: {rng.choice(values)[0]}, cc {_word(rng)}. "
        parts.append(chunk)
        size += len(chunk.encode("utf-8"))
    return "".join(parts)[:_TEXT_BYTES]


def _median_ms(fn, runs):
    fn()
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return statistics.median(times)


def main():
    print(f"\n=== Gateway known values: benchmark at {_VALUES:,} values ===\n")
    rng = random.Random(2026)
    values = _values(rng, _VALUES)

    crypto, _ = ScopeCrypto.create(LocalKms(), "scope-bench")
    sealed = [crypto.encrypt(v.encode("utf-8")) for v, _l in values]
    t0 = time.perf_counter()
    dec = crypto.decryptor()
    plain = [(dec(n, c).decode("utf-8"), label) for (n, c), (_v, label) in zip(sealed, values, strict=True)]
    decrypt_s = time.perf_counter() - t0
    del sealed
    check("the bulk decrypt returns every value", plain == values)
    del plain

    t0 = time.perf_counter()
    matcher = KnownValueMatcher.build(values)
    build_s = time.perf_counter() - t0
    check("every synthetic value is in the matcher", len(matcher) == _VALUES)

    text = _text(rng, values)
    spans = matcher.match(text)
    check(f"the {len(text.encode())}-byte request has known-value hits", len(spans) >= 5)
    median = _median_ms(lambda: matcher.match(text), _RUNS)
    rss_mb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)
    print(f"  decrypt {decrypt_s:.2f} s, build {build_s:.2f} s, match median {median:.3f} ms, "
          f"peak RSS {rss_mb:.0f} MB")
    check(f"median match of 5 KB under {_MAX_MS} ms at {_VALUES:,} values", median < _MAX_MS)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
