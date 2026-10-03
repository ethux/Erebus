"""In-memory source connectors for the sync worker tests (not a test module itself).

``FakeConnector`` opens ``FakeSource``, a table set described as data. Tests change the
tables between syncs and set ``fail`` to make one call raise, so a sync can fail in the
middle. Every ``connect`` is recorded (with the settings the worker handed over).
"""
from __future__ import annotations

import base64
import os
import sys
from dataclasses import dataclass, field

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.cataloging.sources import CollectionInfo, SourceRecord
from erebus.sync.config import SyncConfig

KEY = base64.b64encode(b"k" * 32).decode()


@dataclass
class Field:
    """A column as a database connector reports it."""

    name: str
    db_type: str = "varchar"
    primary_key: bool = False
    pii_hint: str = ""
    label: str = ""
    kind_hint: str = ""


@dataclass
class Table:
    fields: list[Field]
    rows: list[dict] = field(default_factory=list)


def customers(rows=None):
    """A people table: an integer PK, an email, a full name, a name tuple and a product name."""
    return Table(
        [Field("id", "integer", True), Field("email"), Field("full_name"), Field("first_name"),
         Field("tussenvoegsel"), Field("last_name"), Field("product_name")],
        rows if rows is not None else [
            {"id": 1, "email": "zyx.qorbel@acme.example", "full_name": "Zyx Qorbel", "first_name": "Jan",
             "tussenvoegsel": "de", "last_name": "Vries", "product_name": "Widget"},
            {"id": 2, "email": "mila.brandt@acme.example", "full_name": "Mila Brandt", "first_name": "Mila",
             "tussenvoegsel": "", "last_name": "Brandt", "product_name": "Gadget"},
        ],
    )


class FakeSource:
    """A read-only RowSource over ``tables``; ``fail`` maps a call name to an exception."""

    def __init__(self, owner: FakeConnector) -> None:
        self.owner = owner

    def _raise(self, call: str, collection: str) -> None:
        exc = self.owner.fail.get((call, collection)) or self.owner.fail.get((call, "*"))
        if exc is not None:
            raise exc

    def list_collections(self):
        self._raise("collections", "*")
        return [CollectionInfo(name) for name in self.owner.tables]

    def list_fields(self, collection):
        self._raise("fields", collection)
        return list(self.owner.tables[collection].fields)

    def iter_records(self, collection, fields=None, limit=None, page_size=500):
        self._raise("records", collection)
        self.owner.calls.append(("records", collection, limit))
        rows = self.owner.tables[collection].rows
        for i, row in enumerate(rows[:limit] if limit is not None else rows):
            yield SourceRecord(f"{collection}:{i}", {k: row.get(k) for k in (fields or row)})

    def iter_distinct_values(self, collection, fields, limit):
        self._raise("distinct", collection)
        self.owner.calls.append(("distinct", collection, tuple(fields), limit))
        seen = []
        for row in self.owner.tables[collection].rows:
            key = tuple(row.get(f) for f in fields)
            if key not in seen:
                seen.append(key)
        if self.owner.on_distinct is not None:
            self.owner.on_distinct(collection)
        yield from seen[:limit]

    def close(self):
        self.owner.closed += 1


class FakeConnector:
    """A connector for ``type_id`` whose sources read ``tables``."""

    def __init__(self, type_id: str, tables: dict[str, Table]) -> None:
        self.type_id = type_id
        self.tables = tables
        self.fail: dict[tuple[str, str], BaseException] = {}
        self.connects: list[tuple[dict, dict]] = []
        self.calls: list[tuple] = []
        self.closed = 0
        self.on_distinct = None

    def connector_id(self):
        return self.type_id

    def connect(self, settings, secrets):
        self.connects.append((dict(settings), dict(secrets)))
        exc = self.fail.get(("connect", "*"))
        if exc is not None:
            raise exc
        return FakeSource(self)


def lookup(*connectors: FakeConnector):
    """A ``connectors`` callable for the worker: type id -> connector or None."""
    table = {c.type_id: c for c in connectors}
    return table.get


def config(dsn: str, **env) -> SyncConfig:
    """A worker config for ``dsn``; loopback is allowed unless ``EREBUS_SYNC_DENIED_HOSTS`` is given."""
    base = {"EREBUS_PG_DSN": dsn, "EREBUS_GATEWAY_MASTER_KEY": KEY, "EREBUS_SYNC_DENIED_HOSTS": "none",
            "EREBUS_SYNC_BACKOFF_S": "60,300,900", "EREBUS_DISABLE_GLINER": "1"}
    base.update({k: str(v) for k, v in env.items()})
    if base["EREBUS_SYNC_DENIED_HOSTS"] == "":
        del base["EREBUS_SYNC_DENIED_HOSTS"]
    return SyncConfig.from_env(base)
