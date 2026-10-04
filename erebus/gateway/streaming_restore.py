"""Streaming token restore with split-token hold-back (FR-002/FR-025; research R3).

A token split across streamed chunks (``[PERS`` / ``ON_1_abcdef]``) is never emitted
partially: the restorer holds back a trailing run that could still grow into a token
until it completes. A restore failure mid-stream is fatal: the caller stops the
stream fail-closed rather than emitting an unresolved token or partial raw value.

A fragment that is a whole JSON chunk (an OpenAI SSE ``data:`` frame) is restored
inside the parsed chunk, so a restored quote or backslash cannot break its JSON. A
token split across frames is split inside one field, so the hold-back is kept per
choice and field (``content``, each tool call's ``arguments``, any other string such
as ``reasoning_content``) and flushed into the frame that carries the choice's
``finish_reason``, or into a last frame at stream end. Reasoning models may stream
``content`` as a list of parts (Mistral): a text part continues ``content``, and the
text inside ``thinking`` parts is held as one more field.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator
from typing import Any

from .toolargs import parse_frame, restore_frame

_TOKEN_RE = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6,}\]")
# A run that could still grow into a token: "[", "[PASS", "[PASSWORD_1_ab".
_PARTIAL_RE = re.compile(r"\[[A-Z_]*(?:\d+(?:_[0-9a-f]*)?)?")
# Frame fields copied onto the last frame that flushes held text at stream end.
_META = ("id", "object", "created", "model")

Key = tuple[Any, ...]  # (choice index, field name) or (choice index, "tool_calls", call index)
# The text inside a delta's ``thinking`` content parts, held apart from the answer text.
_THINKING: Key = ("content", "thinking")


def _hold_point(text: str) -> int:
    """Index up to which it is safe to emit (hold back a trailing partial token)."""
    i = text.rfind("[")
    return i if i != -1 and _PARTIAL_RE.fullmatch(text, i) else len(text)


def _fields(delta: dict) -> Iterator[tuple[Key, Any, Any]]:
    """``(key, holder, name)`` for every streamed string field of one choice's delta."""
    for name, value in list(delta.items()):
        if isinstance(value, str):
            yield (name,), delta, name
    content = delta.get("content")
    for part in content if isinstance(content, list) else ():
        if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
            yield ("content",), part, "text"
        elif isinstance(part, dict) and part.get("type") == "thinking" and "thinking" in part:
            yield from _thinking_fields(part["thinking"], part, "thinking")
    for call in delta.get("tool_calls") or []:
        fn = call.get("function") if isinstance(call, dict) else None
        if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
            yield ("tool_calls", call.get("index", 0)), fn, "arguments"
    fn = delta.get("function_call")
    if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
        yield ("function_call",), fn, "arguments"


def _thinking_fields(value: Any, holder: Any, name: Any) -> Iterator[tuple[Key, Any, Any]]:
    """The strings of a thinking payload: a string, a list of them, or text parts."""
    if isinstance(value, str):
        yield _THINKING, holder, name
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _thinking_fields(item, value, i)
    elif isinstance(value, dict) and isinstance(value.get("text"), str):
        yield _THINKING, value, "text"


def _parts(content: Any) -> list:
    """``content`` as a list of parts, so a thinking part can go in front of it."""
    if isinstance(content, list):
        return content
    return [{"type": "text", "text": content}] if isinstance(content, str) and content else []


def _put(delta: dict, key: tuple[Any, ...], text: str) -> None:
    """Add held ``text`` for ``key`` to a delta that does not carry that field."""
    if key == _THINKING:
        thinking = {"type": "thinking", "thinking": [{"type": "text", "text": text}]}
        delta["content"] = [thinking, *_parts(delta.get("content"))]
    elif key == ("content",) and isinstance(delta.get("content"), list):
        delta["content"].append({"type": "text", "text": text})
    elif key[0] == "tool_calls":
        calls = delta.get("tool_calls") if isinstance(delta.get("tool_calls"), list) else []
        delta["tool_calls"] = [*calls, {"index": key[1], "function": {"arguments": text}}]
    elif key[0] == "function_call":
        fn = delta.get("function_call") if isinstance(delta.get("function_call"), dict) else {}
        delta["function_call"] = {**fn, "arguments": text}
    else:
        delta[key[0]] = text


class StreamRestorer:
    """Incremental restorer; feed() returns the safe-to-emit restored prefix."""

    def __init__(self, lookup: Callable[[str], str | None]) -> None:
        self._lookup = lookup
        self._buf = ""
        self._held: dict[Key, str] = {}
        self._meta: dict = {}

    def feed(self, chunk: str) -> str:
        if not self._buf and (frame := parse_frame(chunk)) is not None:
            return self._feed_frame(chunk, frame)
        self._buf += chunk
        cut = _hold_point(self._buf)
        emit, self._buf = self._buf[:cut], self._buf[cut:]
        return self._restore(emit)

    def flush(self) -> str:
        emit, self._buf = self._buf, ""
        return self._restore(emit) + self._held_frame()

    def _feed_frame(self, chunk: str, frame: dict) -> str:
        self._meta = {k: frame[k] for k in _META if k in frame}
        changed = False
        for choice in frame.get("choices") or []:
            if isinstance(choice, dict):
                changed |= self._hold(choice)
        if not changed and not _TOKEN_RE.search(chunk):
            return chunk
        return restore_frame(frame, self._lookup)

    def _hold(self, choice: dict) -> bool:
        """Splice held text into this choice's fields and hold back new partial tokens."""
        index, done = choice.get("index", 0), choice.get("finish_reason") is not None
        delta = choice.get("delta")
        changed = False
        for key, holder, name in _fields(delta) if isinstance(delta, dict) else ():
            text = self._held.pop((index, *key), "") + holder[name]
            cut = len(text) if done else _hold_point(text)
            changed |= text != holder[name] or cut < len(text)
            holder[name] = text[:cut]
            if text[cut:]:
                self._held[(index, *key)] = text[cut:]
        if done:
            for key in [k for k in self._held if k[0] == index]:
                delta = choice["delta"] = delta if isinstance(delta, dict) else {}
                _put(delta, key[1:], self._held.pop(key))
                changed = True
        return changed

    def _held_frame(self) -> str:
        """A last frame carrying text still held when the stream ends; "" if none."""
        if not self._held:
            return ""
        choices: dict[Any, dict] = {}
        for (index, *key), text in self._held.items():
            _put(choices.setdefault(index, {"index": index, "delta": {}})["delta"], tuple(key), text)
        self._held.clear()
        return json.dumps({**self._meta, "choices": list(choices.values())},
                          ensure_ascii=False, separators=(",", ":"))

    def _restore(self, text: str) -> str:
        return _TOKEN_RE.sub(lambda m: self._lookup(m.group(0)) or m.group(0), text)
