"""Tests for catalog persistence and domain helpers."""
from __future__ import annotations

import os
import stat
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_catalog_helpers import IsolatedCatalogHome

from erebus import catalog


def test_catalog_source_scope_scan_finding_entry_lifecycle():
    with IsolatedCatalogHome():
        catalog.init_catalog_db()
        source = catalog.add_source(
            "customers",
            "sqlite",
            "/tmp/customers.db",
            connector_config={"mode": "readonly"},
            secret_refs={"credential": "CUSTOMERS_DB_URL"},
        )
        scope = catalog.add_scope(source.id, "customers", ["first_name", "email"])
        scan = catalog.create_scan_run(source.id, [{"dataset": "customers"}])
        email = "jan.jansen" + "@" + "example.test"
        finding = catalog.create_finding(
            scan.id,
            source.id,
            {"dataset": "customers", "column": "email", "row_ref": "1"},
            "EMAIL_ADDRESS",
            email,
            "deterministic",
            "email column",
        )
        entry = catalog.accept_finding(finding.id)
        catalog.finish_scan_run(scan.id, rows_seen=1)

        assert source.id > 0
        assert scope.columns == ["first_name", "email"]
        assert entry.status == catalog.ENTRY_ACTIVE
        assert entry.token.startswith("[CATALOG_EMAIL_ADDRESS_")
        assert catalog.list_findings(status=catalog.FINDING_ACCEPTED)[0].catalog_entry_id == entry.id
        assert catalog.list_catalog_entries(active_only=True)[0].value == email


def test_catalog_db_permissions_and_helpers():
    with IsolatedCatalogHome():
        catalog.init_catalog_db()
        mode = stat.S_IMODE(os.stat(catalog.CATALOG_DB_PATH).st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"
        assert catalog.normalize_value("  Jan   Jansen ") == "jan jansen"
        assert catalog.mask_value("abcdef").startswith("ab")
        err = catalog.sanitize_error("password=super-secret for jan@example.test")
        assert "super-secret" not in err
        assert "jan@" not in err


def test_catalog_forget_removes_entries_from_enforcement():
    with IsolatedCatalogHome():
        source = catalog.add_source("customers", "sqlite", "/tmp/customers.db")
        scan = catalog.create_scan_run(source.id)
        value = "Bietje Bakker"
        finding = catalog.create_finding(
            scan.id,
            source.id,
            {"dataset": "customers", "column": "name", "row_ref": "2"},
            "PERSON",
            value,
            "deterministic",
        )
        entry = catalog.accept_finding(finding.id)
        removed = catalog.forget_catalog_value("Bietje")
        entries = catalog.list_catalog_entries(active_only=True)
        assert removed == 1
        assert all(e.id != entry.id for e in entries)


def test_catalog_forget_cleans_references_findings_and_audit_search_text():
    with IsolatedCatalogHome():
        source = catalog.add_source("customers", "sqlite", "/tmp/customers.db")
        scan = catalog.create_scan_run(source.id)
        value = "Bietje Bakker"
        finding = catalog.create_finding(
            scan.id,
            source.id,
            {"dataset": "customers", "column": "name", "row_ref": "2"},
            "PERSON",
            value,
            "deterministic",
        )
        entry = catalog.accept_finding(finding.id)
        catalog.log_audit_event("catalog_review", value, {"value": value})

        removed = catalog.forget_catalog_value("Bietje")
        audit_text = " ".join(
            event.summary + " " + str(event.metadata)
            for event in catalog.list_audit_events()
        )

        assert removed == 1
        assert catalog.list_source_references(entry.id) == []
        assert catalog.list_findings(status=catalog.FINDING_REMOVED)[0].catalog_entry_id == entry.id
        assert "Bietje" not in audit_text
        assert any(event.event_type == "catalog_forget" for event in catalog.list_audit_events())


if __name__ == "__main__":
    tests = [
        test_catalog_source_scope_scan_finding_entry_lifecycle,
        test_catalog_db_permissions_and_helpers,
        test_catalog_forget_removes_entries_from_enforcement,
        test_catalog_forget_cleans_references_findings_and_audit_search_text,
    ]
    for test in tests:
        test()
        print(f"  ✓ {test.__name__}")
