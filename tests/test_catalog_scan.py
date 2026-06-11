"""Tests for catalog scanning over normalized source connectors."""
from __future__ import annotations

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_catalog_helpers import IsolatedCatalogHome, create_customer_db

from erebus import catalog, catalog_scan, source_plugins
from erebus.source_plugins import CollectionInfo, ConnectorMetadata, FieldInfo, SourceRecord


class FakeApiSource:
    def list_collections(self):
        return [CollectionInfo("contacts")]

    def list_fields(self, collection):
        assert collection == "contacts"
        return [
            FieldInfo("name", pii_hint="person"),
            FieldInfo("email", pii_hint="email"),
            FieldInfo("external_id", pii_hint="identifier"),
        ]

    def iter_records(self, collection, fields=None, limit=None, page_size=500):
        email = "api.customer" + "@" + "example.test"
        rows = [
            SourceRecord(
                "contacts:9",
                {"name": "Ada Lovelace", "email": email, "external_id": "ODOO-9"},
                {"page": 1},
            )
        ]
        yield from rows[:limit]

    def close(self):
        pass


class FakeApiConnector:
    def connector_id(self):
        return "fake-api"

    def connector_metadata(self):
        return ConnectorMetadata("fake-api", "Fake API", "1.0", ["page_records"])

    def connect(self, settings, secrets):
        return FakeApiSource()


def test_scan_sqlite_source_creates_accepted_findings():
    with IsolatedCatalogHome() as home:
        db_path = create_customer_db(home.home / "customers.db")
        source = catalog.add_source("customers", "sqlite", str(db_path))
        catalog.add_scope(source.id, "customers", ["first_name", "last_name", "email", "phone", "account_id"])

        result = catalog_scan.scan_source("customers")

        assert result.rows_seen == 2
        assert result.accepted_total >= 4
        findings = catalog.list_findings(source_id=source.id)
        assert any(f.category == "EMAIL_ADDRESS" for f in findings)
        assert any(f.category == "PERSON" for f in findings)
        assert all("@" not in f.detection_reason for f in findings)


def test_scan_fake_api_connector_uses_normalized_records():
    with IsolatedCatalogHome():
        source_plugins.register_connector(FakeApiConnector())
        source = catalog.add_source("api", "fake-api", connector_config={"base_url": "https://api.example.test"})
        catalog.add_scope(source.id, "contacts", ["name", "email", "external_id"])

        result = catalog_scan.scan_source("api")

        assert result.rows_seen == 1
        findings = catalog.list_findings(source_id=source.id)
        assert any(f.source_ref["row_ref"] == "contacts:9" for f in findings)
        assert any(f.category == "EMAIL_ADDRESS" for f in findings)


def test_refresh_marks_changed_missing_and_rediscovered_entries():
    with IsolatedCatalogHome() as home:
        db_path = create_customer_db(home.home / "customers.db")
        source = catalog.add_source("customers", "sqlite", str(db_path))
        catalog.add_scope(source.id, "customers", ["email"])

        catalog_scan.scan_source("customers")
        old_email = "jan.jansen" + "@" + "example.test"
        new_email = "jan.changed" + "@" + "example.test"
        added_email = "new.customer" + "@" + "example.test"
        old_entry = next(
            entry for entry in catalog.list_catalog_entries()
            if entry.value == old_email
        )

        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE customers SET email=? WHERE id=1", (new_email,))
        conn.execute(
            """
            INSERT INTO customers
                (id, first_name, last_name, email, phone, account_id, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (3, "New", "Customer", added_email, "", "CUST-003", ""),
        )
        conn.commit()
        conn.close()

        refreshed = catalog_scan.refresh_source("customers")
        entries = catalog.list_catalog_entries()
        old_after_change = next(entry for entry in entries if entry.id == old_entry.id)

        assert refreshed.rows_seen == 3
        assert old_after_change.status == catalog.ENTRY_STALE
        assert any(entry.value == new_email and entry.status == catalog.ENTRY_ACTIVE for entry in entries)
        assert any(entry.value == added_email and entry.status == catalog.ENTRY_ACTIVE for entry in entries)

        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE customers SET email=? WHERE id=1", (old_email,))
        conn.commit()
        conn.close()

        catalog_scan.refresh_source("customers")
        rediscovered = next(
            entry for entry in catalog.list_catalog_entries()
            if entry.id == old_entry.id
        )
        assert rediscovered.status == catalog.ENTRY_ACTIVE


def test_scan_representative_dataset_performance_and_safe_summary():
    with IsolatedCatalogHome() as home:
        db_path = home.home / "many_customers.db"
        import sqlite3
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE customers (
                id INTEGER PRIMARY KEY,
                name TEXT,
                email TEXT,
                phone TEXT,
                account_id TEXT
            )
            """
        )
        rows = []
        for idx in range(1, 81):
            email = f"customer{idx}" + "@" + "example.test"
            phone = "+31" + f"6000{idx:05d}"
            rows.append((idx, f"Customer {idx}", email, phone, f"CUST-{idx:04d}"))
        conn.executemany(
            "INSERT INTO customers (id, name, email, phone, account_id) VALUES (?, ?, ?, ?, ?)",
            rows,
        )
        conn.commit()
        conn.close()

        source = catalog.add_source("many", "sqlite", str(db_path))
        catalog.add_scope(source.id, "customers", ["name", "email", "phone", "account_id"])

        started = time.perf_counter()
        result = catalog_scan.scan_source("many")
        elapsed = time.perf_counter() - started

        assert result.rows_seen == 80
        assert result.findings_total >= 80
        assert elapsed < 10
        assert "@" not in result.error_summary
        assert "customer1" not in result.error_summary.lower()


if __name__ == "__main__":
    tests = [
        test_scan_sqlite_source_creates_accepted_findings,
        test_scan_fake_api_connector_uses_normalized_records,
        test_refresh_marks_changed_missing_and_rediscovered_entries,
        test_scan_representative_dataset_performance_and_safe_summary,
    ]
    for test in tests:
        test()
        print(f"  ✓ {test.__name__}")
