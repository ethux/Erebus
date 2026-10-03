"""Known values on the chat gate (spec 015 "Request path", D3).

Pure. Known-value spans and detector spans are found on the ORIGINAL text and merged
once: longest first, ties to the known value, nothing inside an existing token, so no
value is tokenized twice. A request's spans are minted in one ``mint_many`` call. Edge
mode refuses a known-value hit. Tool-call ``id``, ``type`` and ``function.name`` are
not matched against known values.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.core.patterns import TOKEN_RE
from erebus.gateway import gating
from erebus.gateway.crypto.purposekeys import normalize_value
from erebus.gateway.gating import BlockedModality, EdgeRawError, tokenize_payload
from erebus.gateway.known_values import KnownValueMatcher
from erebus.gateway.tokenizer import Tokenizer

_passed = 0

MATCHER = KnownValueMatcher.build([
    ("Zyx Qorbel", "PERSON"),
    ("Qorbel", "IDENTIFIER"),
    ("Acme Corp", "ORGANIZATION"),
    ("Search", "ORGANIZATION"),
])


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class FakeStore:
    """Deterministic token per (normalized value, label); records every mint_many call."""

    def __init__(self):
        self.calls = []
        self._tokens = {}

    def mint_many(self, items):
        items = list(items)
        self.calls.append(items)
        out = {}
        for value, label in items:
            key = (normalize_value(value), label)
            if key not in self._tokens:
                self._tokens[key] = f"[{label}_{len(self._tokens) + 1}_abcdef]"
            out[(value, label)] = self._tokens[key]
        return out

    def minted(self):
        return [pair for call in self.calls for pair in call]


def _finder(*pairs):
    """A detector returning ``label`` for every occurrence of each ``needle``."""
    def detect(text):
        spans = []
        for needle, label in pairs:
            start = text.find(needle)
            while start != -1:
                spans.append((start, start + len(needle), label))
                start = text.find(needle, start + 1)
        return spans
    return detect


def _none(_text):
    return []


def test_tokenizer():
    store = FakeStore()
    out = Tokenizer(store, _none, MATCHER).tokenize("Call Zyx Qorbel today")
    check("a synced value the detector does not find is tokenized", out == "Call [PERSON_1_abcdef] today")
    check("it is minted as the known value's label", store.minted() == [("Zyx Qorbel", "PERSON")])

    store = FakeStore()
    out = Tokenizer(store, _finder(("Qorbel", "PERSON")), MATCHER).tokenize("Call Zyx Qorbel today")
    check("a longer known value beats a shorter detector span inside it",
          out == "Call [PERSON_1_abcdef] today" and store.minted() == [("Zyx Qorbel", "PERSON")])

    store = FakeStore()
    out = Tokenizer(store, _finder(("Acme Corp", "PERSON")), MATCHER).tokenize("Ask Acme Corp.")
    check("a tie goes to the known value's label",
          out == "Ask [ORGANIZATION_1_abcdef]." and store.minted() == [("Acme Corp", "ORGANIZATION")])

    store = FakeStore()
    text = "mail zyx.qorbel@acme.com now"
    out = Tokenizer(store, _finder(("zyx.qorbel@acme.com", "EMAIL_ADDRESS")), MATCHER).tokenize(text)
    check("a longer detector span keeps the whole entity (no split email)",
          out == "mail [EMAIL_ADDRESS_1_abcdef] now" and len(store.minted()) == 1)

    store = FakeStore()
    out = Tokenizer(store, _finder(("Zyx", "PERSON")), MATCHER).tokenize("Zyx Qorbel")
    check("a partial detector overlap loses to the longer known value", out == "[PERSON_1_abcdef]")

    store = FakeStore()
    token = "[PERSON_9_fedcba]"
    text = f"{token} and Zyx Qorbel"
    out = Tokenizer(store, _finder((token, "PERSON"), ("PERSON_9", "PERSON")), MATCHER).tokenize(text)
    check("an existing token is never re-tokenized",
          out.startswith(token + " and [PERSON_") and len(TOKEN_RE.findall(out)) == 2
          and store.minted() == [("Zyx Qorbel", "PERSON")])

    store = FakeStore()
    out = Tokenizer(store, _finder(("John Smith", "PERSON"))).tokenize("Zyx Qorbel met John Smith")
    check("without a matcher only detector spans are tokenized",
          out == "Zyx Qorbel met [PERSON_1_abcdef]")

    store = FakeStore()
    tok = Tokenizer(store, _none, MATCHER)
    once = tok.tokenize("Zyx Qorbel")
    check("tokenizing a token-only text again changes nothing", tok.tokenize(once) == once)


def _payload():
    arguments = json.dumps({"q": "Search Zyx Qorbel", "who": "Acme Corp"})
    return {"messages": [
        {"role": "user", "content": "Hi Zyx Qorbel from Acme Corp"},
        {"role": "user", "content": [{"type": "text", "text": "zyx  qorbel again"}]},
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "Search", "type": "function",
            "function": {"name": "Search", "arguments": arguments}}]},
    ]}


def _with_store(store, fn):
    original = gating.open_store
    gating.open_store = lambda _conn, _kp, _sid: store
    try:
        return fn()
    finally:
        gating.open_store = original


def test_payload():
    store = FakeStore()
    hits = []
    out = _with_store(store, lambda: tokenize_payload(
        None, _none, {}, None, None, "gateway", _payload(), matcher=MATCHER, on_known=hits.append))
    first = out["messages"][0]["content"]
    check("string content is tokenized", first == "Hi [PERSON_1_abcdef] from [ORGANIZATION_2_abcdef]")
    check("text parts get the same token for the same value",
          out["messages"][1]["content"][0]["text"] == "[PERSON_1_abcdef] again")
    call = out["messages"][2]["tool_calls"][0]
    args = json.loads(call["function"]["arguments"])
    check("tool-call arguments are matched", args == {
        "q": "[ORGANIZATION_3_abcdef] [PERSON_1_abcdef]", "who": "[ORGANIZATION_2_abcdef]"})
    check("tool-call id, type and function.name are not matched",
          call["id"] == "Search" and call["type"] == "function" and call["function"]["name"] == "Search")
    check("the whole request mints in one batch", len(store.calls) == 1)
    check("known-value hits are reported once per request", hits == [6])

    store = FakeStore()
    out = _with_store(store, lambda: tokenize_payload(
        None, _none, {}, None, None, "gateway", {"messages": [{"role": "user", "content": "nothing here"}]},
        matcher=MATCHER))
    check("a clean request mints nothing", store.calls == [] and out["messages"][0]["content"] == "nothing here")

    store = FakeStore()
    blocked = {"messages": [{"role": "user", "content": "Zyx Qorbel"},
                            {"role": "user", "content": [{"type": "image_url", "image_url": {"url": "x"}}]}]}
    try:
        _with_store(store, lambda: tokenize_payload(None, _none, {}, None, None, "gateway", blocked, matcher=MATCHER))
        refused = False
    except BlockedModality:
        refused = True
    check("a blocked part refuses the request before anything is minted", refused and store.calls == [])


def test_edge():
    store = FakeStore()
    try:
        _with_store(store, lambda: tokenize_payload(
            None, _none, {}, None, None, "edge", {"messages": [{"role": "user", "content": "Hi Zyx Qorbel"}]},
            matcher=MATCHER))
        raised = False
    except EdgeRawError:
        raised = True
    check("edge mode refuses a known-value hit", raised and store.calls == [])
    payload = {"messages": [{"role": "user", "content": "Hi [PERSON_1_abcdef]"}]}
    out = _with_store(store, lambda: tokenize_payload(None, _none, {}, None, None, "edge", payload, matcher=MATCHER))
    check("edge mode passes a clean payload through unchanged",
          out["messages"][0]["content"] == "Hi [PERSON_1_abcdef]" and store.calls == [])


def main():
    print("\n=== Gateway known values on the chat gate ===\n")
    test_tokenizer()
    test_payload()
    test_edge()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
