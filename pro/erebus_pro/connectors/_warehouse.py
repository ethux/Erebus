# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Shared pieces of the Pro warehouse connectors (and Oracle's).

Collections are named ``schema.table`` (a BigQuery dataset is its schema). A connector
reads the columns of every table it may see from the catalog once, and only ever
queries a table and columns that listing named, so every identifier it quotes came from
the warehouse's own catalog. Settings that are identifiers are checked against a plain
pattern before they reach the driver; nothing a setting holds is put into SQL.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from erebus.cataloging.connector_errors import ConnectorError
from erebus.cataloging.sources import FieldInfo

# Upper bound for one statement; the job's lease is heartbeated separately.
STATEMENT_TIMEOUT_S = 600
LOGIN_TIMEOUT_S = 10
QUERY_TAG = "erebus-sync"
MAX_SETTING = 256


def setting(settings: Mapping[str, Any], key: str, pattern: re.Pattern | None = None, *,
            required: bool = False) -> str | None:
    """The text setting ``key``; ``settings`` error when missing (if required) or malformed."""
    value = settings.get(key)
    if value is None:
        if required:
            raise ConnectorError("settings") from None
        return None
    if not isinstance(value, str) or not 0 < len(value) <= MAX_SETTING or not value.isprintable() \
            or (pattern is not None and not pattern.fullmatch(value)):
        raise ConnectorError("settings") from None
    return value


def schema_filter(settings: Mapping[str, Any]) -> list[str] | None:
    schemas = settings.get("schemas")
    return [str(s) for s in schemas] if schemas else None


class Columns:
    """What INFORMATION_SCHEMA listed: ``schema.table`` -> (schema, table, fields in order)."""

    def __init__(self) -> None:
        self._tables: dict[str, tuple[str, str, list[FieldInfo]]] | None = None

    def fill(self, rows: Iterable[tuple[str, str, FieldInfo]]) -> list[str]:
        self._tables = {}
        for schema, table, info in rows:
            self._tables.setdefault(f"{schema}.{table}", (schema, table, []))[2].append(info)
        return list(self._tables)

    def known(self) -> bool:
        return self._tables is not None

    def get(self, collection: str) -> tuple[str, str, list[FieldInfo]]:
        if self._tables is None or collection not in self._tables:
            raise ConnectorError("query") from None
        return self._tables[collection]


def check_fields(fields: list[FieldInfo], wanted: list[str] | None) -> list[str]:
    """The selected column names; an unknown or missing name is a ``query`` error."""
    names = [f.name for f in fields]
    selected = list(wanted) if wanted else names
    if not selected or any(n not in names for n in selected):
        raise ConnectorError("query") from None
    return selected


def check_groups(fields: list[FieldInfo], groups: list[list[str]]) -> list[list[str]]:
    """Every group checked as by ``check_fields``; no group may be empty."""
    if not groups:
        raise ConnectorError("query") from None
    return [check_fields(fields, group) for group in groups]
