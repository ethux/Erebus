"""Shared pieces of the SQL database connectors (Postgres, MySQL).

Collections are named ``schema.table``. A connector only ever queries a collection it
listed itself, so every identifier it quotes came from the server's own catalog. The
worker hands a checked ``hostaddr``; without one a connector refuses to dial.
"""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..connector_errors import ConnectorError
from ..sources import FieldInfo

# Upper bound for one statement and for an idle transaction on the source; the job's
# lease is heartbeated separately, so a long DISTINCT is fine up to this.
STATEMENT_TIMEOUT_S = 600
CONNECT_TIMEOUT_S = 10
SYSTEM_SCHEMAS = {
    "postgres": frozenset({"pg_catalog", "information_schema", "pg_toast"}),
    "mysql": frozenset({"mysql", "information_schema", "performance_schema", "sys"}),
}


def hostaddr(settings: Mapping[str, Any]) -> str:
    """The address the worker checked; a connector must dial exactly this."""
    addr = settings.get("hostaddr")
    if not isinstance(addr, str) or not addr:
        raise ValueError("the sync worker must supply a checked hostaddr")
    return addr


def schema_filter(settings: Mapping[str, Any]) -> list[str] | None:
    schemas = settings.get("schemas")
    return list(schemas) if schemas else None


class Catalog:
    """The collections a source listed: ``schema.table`` -> (schema, table)."""

    def __init__(self) -> None:
        self._tables: dict[str, tuple[str, str]] | None = None

    def fill(self, rows: list[tuple[str, str]]) -> list[str]:
        self._tables = {}
        for schema, table in rows:
            self._tables.setdefault(f"{schema}.{table}", (schema, table))
        return list(self._tables)

    def known(self) -> bool:
        return self._tables is not None

    def get(self, collection: str) -> tuple[str, str]:
        if self._tables is None or collection not in self._tables:
            raise ConnectorError("query")
        return self._tables[collection]


def check_fields(fields: list[FieldInfo], wanted: list[str] | None) -> tuple[list[str], str | None]:
    """(selected column names, the single primary-key column or None); unknown names: ``query``."""
    names = [f.name for f in fields]
    selected = list(wanted) if wanted else names
    if not selected or any(n not in names for n in selected):
        raise ConnectorError("query")
    pks = [f.name for f in fields if f.primary_key]
    return selected, (pks[0] if len(pks) == 1 else None)
