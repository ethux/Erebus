"""Non-text / structured-content gate, pure logic (FR-004).

Every cloud-bound message part must receive a protective decision before egress,
and no modality may silently bypass the privacy gate (FR-004). This module is the
pure decision core: it inspects message-part dicts and routes each one, holding no
database connection and no mutable process-global state (FR-041..043).

Three decisions are possible per part:

* ``"tokenize"`` -- text content (and the string fields inside structured
  tool-call/function arguments) flows through the tokenization gate.
* ``"block"`` -- unsupported or unhandled modalities (image, file, audio, video,
  or any unknown ``type``) are blocked by default. Blocking-by-default is what
  guarantees no modality escapes the gate: a part the gate does not understand is
  refused rather than forwarded raw.
* ``"ack-required"`` -- a configurable middle ground for modalities the operator
  has explicitly opted to permit behind a recorded acknowledgement. Nothing is
  ack-required unless a modality is named in the supplied policy; the default
  policy permits nothing, so unhandled modalities still block.

Structured tool-call / function arguments are never trusted to be plain text: the
gate recurses into their string fields and routes each to tokenization, so a raw
value cannot ride into the provider hidden inside a JSON arguments blob. Nested
non-text parts found while recursing are themselves classified, never passed
through. :func:`classify_parts` is the batch entry point and asserts, as a
structural invariant, that every part produced at least one decision.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any, Literal

Decision = Literal["tokenize", "block", "ack-required"]

# Part types whose payload is natural-language text and goes to the text gate.
_TEXT_TYPES: frozenset[str] = frozenset({"text", "input_text", "output_text"})

# Structured types that carry JSON arguments. Their string fields are recursed
# into for tokenization; the structured wrapper itself never bypasses the gate.
_STRUCTURED_TYPES: frozenset[str] = frozenset(
    {"tool_call", "tool_use", "function", "function_call"}
)

# Known non-text modalities that are blocked by default unless policy opts in.
_NON_TEXT_TYPES: frozenset[str] = frozenset(
    {"image", "image_url", "file", "audio", "video", "input_audio", "document"}
)

# Keys that may hold the structured arguments payload on a structured part.
_ARG_KEYS: tuple[str, ...] = ("arguments", "args", "input", "parameters")


def _part_type(part: Mapping[str, Any]) -> str | None:
    """Return the normalized ``type`` of a part, or None if absent/blank."""
    raw = part.get("type")
    if not isinstance(raw, str):
        return None
    norm = raw.strip().casefold()
    return norm or None


def _decide_modality(
    part_type: str | None, policy: Mapping[str, Decision]
) -> Decision:
    """Decide a known non-text / unknown modality (block by default; FR-004).

    A modality blocks unless the operator policy explicitly maps it to another
    decision; an unknown ``type`` (None or unrecognized) always blocks, so no
    modality can silently pass.
    """
    if part_type is not None:
        configured = policy.get(part_type)
        if configured in ("tokenize", "block", "ack-required"):
            return configured
    return "block"


def _classify_value(value: Any, policy: Mapping[str, Decision]) -> list[Decision]:
    """Route an arbitrary structured-arguments value, recursing into it.

    String leaves go to tokenization. Nested dicts that look like message parts
    are classified as parts; other dicts/lists are walked so a non-text part
    hidden inside the structure cannot escape the gate (FR-004).
    """
    decisions: list[Decision] = []
    if isinstance(value, str):
        decisions.append("tokenize")
    elif isinstance(value, Mapping):
        if isinstance(value.get("type"), str):
            decisions.extend(classify_part(value, policy))
        else:
            for nested in value.values():
                decisions.extend(_classify_value(nested, policy))
    elif isinstance(value, Iterable) and not isinstance(value, (bytes, bytearray)):
        for item in value:
            decisions.extend(_classify_value(item, policy))
    # Non-string scalars (numbers, bools, None) carry no PII text to tokenize.
    return decisions


def classify_part(
    part: Mapping[str, Any], policy: Mapping[str, Decision] | None = None
) -> list[Decision]:
    """Classify one message part into one or more protective decisions (FR-004).

    Returns a non-empty list: text tokenizes; known non-text modalities block by
    default (or follow ``policy``); structured tool-call/function arguments recurse
    so their string fields tokenize; unknown types block. The list is never empty,
    which is the guarantee that no modality bypasses the gate.
    """
    pol = policy or {}
    part_type = _part_type(part)

    if part_type in _TEXT_TYPES:
        return ["tokenize"]

    if part_type in _STRUCTURED_TYPES:
        decisions: list[Decision] = []
        for key in _ARG_KEYS:
            if key in part:
                decisions.extend(_classify_value(part[key], pol))
        # A structured part with no recursable string content still must not
        # bypass the gate: route it to tokenization as a handled text container.
        return decisions or ["tokenize"]

    # Known non-text modality or unknown type: block by default (configurable).
    return [_decide_modality(part_type, pol)]


def classify_parts(
    parts: Iterable[Mapping[str, Any]],
    policy: Mapping[str, Decision] | None = None,
) -> list[Decision]:
    """Classify a sequence of message parts, asserting none bypasses the gate.

    Flattens the per-part decisions in order. Raises ``AssertionError`` if any
    part yields no decision, enforcing FR-004's no-bypass invariant structurally
    rather than by convention.
    """
    pol = policy or {}
    out: list[Decision] = []
    for part in parts:
        decisions = classify_part(part, pol)
        if not decisions:
            raise AssertionError(
                f"modality bypassed the privacy gate: {part!r}"
            )
        out.extend(decisions)
    return out
