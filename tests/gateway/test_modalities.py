"""Non-text / structured-content gate unit tests (FR-004).

Pure logic, no database. Verifies that text parts tokenize, that known non-text
modalities (image/file/audio) block by default, that tool-call/function argument
string fields are routed to tokenization (never bypassing the gate), that unknown
modalities block, and that no part ever yields an empty decision -- the structural
guarantee that no modality silently passes the privacy gate.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.modalities import (
    classify_part,
    classify_parts,
)

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def main():
    print("\n=== Non-text / structured-content gate (FR-004) ===\n")

    # Text tokenizes.
    check("text part tokenizes", classify_part({"type": "text", "text": "hi"}) == ["tokenize"])
    check("input_text tokenizes", classify_part({"type": "input_text", "text": "x"}) == ["tokenize"])
    check("text type is case/space-insensitive",
          classify_part({"type": " TEXT "}) == ["tokenize"])

    # Known non-text modalities block by default.
    check("image blocks by default", classify_part({"type": "image"}) == ["block"])
    check("file blocks by default", classify_part({"type": "file"}) == ["block"])
    check("audio blocks by default", classify_part({"type": "audio"}) == ["block"])
    check("video blocks by default", classify_part({"type": "video"}) == ["block"])
    check("image_url blocks by default", classify_part({"type": "image_url"}) == ["block"])

    # Unknown / missing modality blocks (block-by-default, no silent pass).
    check("unknown modality blocks", classify_part({"type": "hologram"}) == ["block"])
    check("missing type blocks", classify_part({}) == ["block"])
    check("non-string type blocks", classify_part({"type": 7}) == ["block"])

    # Tool-call / function arguments recurse into string fields for tokenization.
    tc = {
        "type": "tool_call",
        "arguments": {"city": "Amsterdam", "ssn": "111-22-3333", "count": 3},
    }
    check("tool_call routes each string arg to tokenize",
          classify_part(tc) == ["tokenize", "tokenize"])
    check("function_call args string tokenizes",
          classify_part({"type": "function_call", "arguments": {"q": "secret"}}) == ["tokenize"])
    check("tool_use input string tokenizes",
          classify_part({"type": "tool_use", "input": {"a": "v1", "b": "v2"}})
          == ["tokenize", "tokenize"])
    check("nested list of strings in args all tokenize",
          classify_part({"type": "tool_call", "arguments": {"xs": ["a", "b"]}})
          == ["tokenize", "tokenize"])
    check("tool_call with no string content still does not bypass (tokenize container)",
          classify_part({"type": "tool_call", "arguments": {"n": 1}}) == ["tokenize"])
    check("tool_call with no arguments key still does not bypass",
          classify_part({"type": "tool_call"}) == ["tokenize"])

    # A non-text modality hidden inside structured args cannot bypass the gate.
    smuggled = {
        "type": "tool_call",
        "arguments": {"attachment": {"type": "image", "url": "http://x/y.png"}},
    }
    check("image smuggled inside tool args is blocked, not passed",
          classify_part(smuggled) == ["block"])

    # Configurable: an operator policy may permit a modality via acknowledgement.
    check("policy can route image to ack-required",
          classify_part({"type": "image"}, {"image": "ack-required"}) == ["ack-required"])
    check("policy can route file to tokenize",
          classify_part({"type": "file"}, {"file": "tokenize"}) == ["tokenize"])
    check("default policy still blocks unconfigured modality",
          classify_part({"type": "audio"}, {"image": "ack-required"}) == ["block"])

    # Batch classification preserves order and flattens decisions.
    parts = [
        {"type": "text", "text": "hello"},
        {"type": "image"},
        {"type": "tool_call", "arguments": {"a": "x", "b": "y"}},
        {"type": "weird"},
    ]
    check("classify_parts flattens decisions in order",
          classify_parts(parts) == ["tokenize", "block", "tokenize", "tokenize", "block"])
    check("classify_parts on empty input is empty", classify_parts([]) == [])

    # No-bypass invariant: every part yields at least one decision.
    check("every classify_part result is non-empty (no silent pass)",
          all(len(classify_part(p)) >= 1 for p in [
              {"type": "text"}, {"type": "image"}, {"type": "tool_call"},
              {"type": "unknown"}, {},
          ]))

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
