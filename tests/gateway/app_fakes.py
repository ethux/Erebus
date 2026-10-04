"""An in-memory app connector for the record-sync tests (not a test module itself).

``FakeApp`` holds records per collection, each stamped with the tick of its last change,
as an app's modified-since field would. Its cursor is the tick a read started at;
``iter_changes`` returns the records changed after the cursor plus, when ``feed`` is set,
the deletions since then.
``expired`` makes every cursor unusable; ``fail_after`` raises after that many records.
Values are made up.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from sync_fakes import Field

from erebus.cataloging import connector_types
from erebus.cataloging.connector_errors import ConnectorError, CursorExpired
from erebus.cataloging.connector_types import ConnectorType
from erebus.cataloging.sources import CollectionInfo, SourceRecord

APP_TYPE = ConnectorType("zq-app", "app", "pro", frozenset({"url", "collections"}))


def install_app_type() -> None:
    """Make ``zq-app`` an installed app type for this process (core ships no app type)."""
    types = dict(connector_types._installed())  # test seam
    types[APP_TYPE.id] = APP_TYPE
    connector_types._installed = lambda: types


CONTACT_FIELDS = [Field("id", "integer", True), Field("name", "char", pii_hint="person"),
                  Field("email", "char", pii_hint="email"), Field("company", "char", pii_hint="organization")]


class FakeApp:
    """A connector for ``zq-app`` over ``records``: collection -> {record id: values}."""

    def __init__(self, records: dict[str, dict[str, dict]], fields: dict[str, list[Field]] | None = None) -> None:
        self.fields = fields or {c: CONTACT_FIELDS for c in records}
        self.records = {c: dict(rows) for c, rows in records.items()}
        self.tick = 1
        self.stamp = {(c, r): 1 for c, rows in records.items() for r in rows}
        self.deleted: list[tuple[str, str, int]] = []
        self.feed = False
        self.expired = False
        self.fail_after: int | None = None
        self.expiry = None
        self.calls: list[tuple] = []

    def connector_id(self):
        return APP_TYPE.id

    def connect(self, settings, secrets):
        self.calls.append(("connect",))
        return _Source(self)

    def change(self, collection: str, record_id: str, **values) -> None:
        self.tick += 1
        self.records[collection].setdefault(record_id, {}).update(values)
        self.stamp[(collection, record_id)] = self.tick

    def delete(self, collection: str, record_id: str) -> None:
        self.tick += 1
        del self.records[collection][record_id]
        self.deleted.append((collection, record_id, self.tick))


class _Source:
    def __init__(self, app: FakeApp) -> None:
        self.app = app
        self.positions: dict[str, str] = {}
        self.read = 0

    def list_collections(self):
        return [CollectionInfo(c) for c in self.app.records]

    def list_fields(self, collection):
        return list(self.app.fields[collection])

    def _record(self, collection, record_id, fields):
        self.read += 1
        if self.app.fail_after is not None and self.read > self.app.fail_after:
            raise ConnectorError("unreachable")
        values = self.app.records[collection][record_id]
        return SourceRecord(record_id, {f: values.get(f) for f in (fields or values)})

    def iter_records(self, collection, fields=None, limit=None, page_size=500):
        self.app.calls.append(("records", collection, limit))
        self.positions[collection] = str(self.app.tick)
        for record_id in list(self.app.records[collection])[:limit]:
            yield self._record(collection, record_id, fields)

    def iter_changes(self, collection, fields, cursor):
        self.app.calls.append(("changes", collection, cursor))
        if self.app.expired or not cursor.isdigit():
            raise CursorExpired()
        since = int(cursor)
        self.positions[collection] = str(self.app.tick)
        for record_id in list(self.app.records[collection]):
            if self.app.stamp[(collection, record_id)] > since:
                yield self._record(collection, record_id, fields)
        if self.app.feed:
            for c, record_id, tick in self.app.deleted:
                if c == collection and tick > since:
                    yield SourceRecord(record_id, {}, {"deleted": True})

    def cursor(self, collection):
        return self.positions.get(collection)

    def credentials_expire_at(self):
        return self.app.expiry

    def close(self):
        pass
