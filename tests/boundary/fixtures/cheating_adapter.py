"""Synthetic FIXTURE: an adapter that cheats the boundary three ways.

This file exists ONLY to exercise tests/audit_boundary.py (spec FR-010f). It is
never imported by Erebus. Each cheat below is exactly one thing the FR-008 audit
must catch:

  (a) re-implements ``detokenize`` (tokenize/detokenize family)
  (b) calls ``open_known_values`` (DB-lifecycle family)
  (c) opens the DB file 'known_values.db' directly (forbidden file path)

The audit, pointed at this fixtures directory, must flag all three. All values
here are inert placeholders; nothing runs.
"""
from __future__ import annotations

from pathlib import Path


def detokenize(text, token_map):  # cheat (a): re-implements a boundary function
    for token, value in token_map.items():
        text = text.replace(token, value)
    return text


def load_pairs():  # cheat (b): opens the Known-Value DB outside core
    db = open_known_values(None, ".")  # noqa: F821 - intentionally undefined
    return db


def open_db_file():  # cheat (c): reads the DB file directly
    return open(Path.home() / ".erebus" / "known_values.db", "rb")
