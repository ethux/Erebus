"""JSON-aware gate and restore for tool-call ``arguments`` strings (FR-004).

OpenAI tool calls carry ``function.arguments`` as one JSON string. Gated as plain text,
a ``key=value`` pattern's ``\\S{n,}`` tail swallows the closing quote and brace, and a
restored value with a quote or backslash breaks the JSON. So literals are gated one JSON
string at a time, and a token restored inside JSON is written back JSON-escaped.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any

from .tokenizer import _TOKEN_RE

Lookup = Callable[[str], "str | None"]

# One JSON string literal. Only applied to text json.loads accepted, where every '"'
# outside a literal opens one.
_STRING_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.S)


def _parses(text: str) -> bool:
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return False
    return True


def map_json_strings(raw: str, fn: Callable[[str], str]) -> str | None:
    """Apply ``fn`` to every string literal in the JSON text ``raw``; None if it is not JSON.

    Keys are data too (a map of email to role), so they go through ``fn`` as well; a
    plain parameter name matches no pattern and is left as it is. Numbers and layout
    keep their exact bytes; only a literal ``fn`` changed is re-encoded, ASCII-escaped
    when the client's literal was.
    """
    if not _parses(raw):
        return None

    def one(m: re.Match) -> str:
        old = json.loads(m.group(0))
        new = fn(old)
        return m.group(0) if new == old else json.dumps(new, ensure_ascii=m.group(0).isascii())

    return _STRING_RE.sub(one, raw)


def restore_plain(text: str, lookup: Lookup) -> str:
    return _TOKEN_RE.sub(lambda m: lookup(m.group(0)) or m.group(0), text)


def restore_escaped(text: str, lookup: Lookup) -> str:
    """Restore tokens that sit inside JSON strings (valid JSON has them nowhere else)."""
    def one(m: re.Match) -> str:
        value = lookup(m.group(0))
        return json.dumps(value, ensure_ascii=False)[1:-1] if value else m.group(0)

    return _TOKEN_RE.sub(one, text)


def restore_arguments(raw: str, lookup: Lookup) -> str:
    """Whole ``arguments`` from a response: escaped when JSON, plain text otherwise."""
    return restore_escaped(raw, lookup) if _parses(raw) else restore_plain(raw, lookup)


def _restore_tree(value: Any, lookup: Lookup, key: str | None = None) -> Any:
    if isinstance(value, dict):
        return {k: _restore_tree(v, lookup, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_restore_tree(v, lookup) for v in value]
    if isinstance(value, str):
        # A streamed arguments delta is a slice of JSON text, so it cannot be parsed.
        return restore_escaped(value, lookup) if key == "arguments" else restore_plain(value, lookup)
    return value


def restore_frame(chunk: str, lookup: Lookup) -> str | None:
    """Restore one streamed JSON chunk; None when ``chunk`` is not a JSON object.

    Restoring into the parsed chunk and re-encoding it keeps the frame valid JSON
    whatever the restored value contains.
    """
    if not chunk.lstrip().startswith("{"):
        return None
    try:
        frame = json.loads(chunk)
    except (ValueError, RecursionError):
        return None
    if not _TOKEN_RE.search(chunk):
        return chunk
    return json.dumps(_restore_tree(frame, lookup), ensure_ascii=False, separators=(",", ":"))
