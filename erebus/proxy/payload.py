"""Generic recursive text-path walk for API request payloads.

Pure module: imports nothing else in ``erebus.proxy``, so chat, responses, and
tokenmap can all share one definition of *which* strings are model-bound text
(the key set) and *where* they live (paths) without import cycles.

A string is model-bound text iff its immediate parent key is in
``PAYLOAD_TEXT_KEYS``. That covers chat ``content``/``text``, Anthropic
``system`` blocks, Responses ``instructions``/``input``/``output``/``summary``,
tool/function ``description``, and tool-call ``arguments`` — every field a
model actually reads. Structural strings (ids, roles, tool names, enum keys)
are intentionally excluded so tokenizing them can't break routing.
"""
from __future__ import annotations

PAYLOAD_TEXT_KEYS = {
    "arguments",
    "content",
    "description",
    "input",
    "instructions",
    "output",
    "summary",
    "text",
}


def collect_text_paths(value, parent_key: str | None = None,
                       path: tuple = ()) -> list[tuple[tuple, str]]:
    """Return [(path, text), ...] for every model-bound text string in ``value``.

    ``path`` is a tuple of dict keys / list indices usable with
    ``core._set_path_value`` / ``get_path_value``.
    """
    if isinstance(value, str):
        if value and parent_key in PAYLOAD_TEXT_KEYS:
            return [(path, value)]
        return []
    if isinstance(value, list):
        found: list[tuple[tuple, str]] = []
        for i, item in enumerate(value):
            found.extend(collect_text_paths(item, parent_key, path + (i,)))  # noqa: RUF005
        return found
    if isinstance(value, dict):
        found = []
        for key, item in value.items():
            found.extend(collect_text_paths(item, key, path + (key,)))  # noqa: RUF005
        return found
    return []
