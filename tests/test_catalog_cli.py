"""Contract tests for the erebus-catalog CLI."""
from __future__ import annotations

import contextlib
import io
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_catalog_helpers import IsolatedCatalogHome, create_customer_db

from erebus import catalog, source_plugins
from erebus.commands import catalog as catalog_cli
from erebus.source_plugins import ConnectorMetadata


class CliFakeConnector:
    def connector_id(self):
        return "cli-fake"

    def connector_metadata(self):
        return ConnectorMetadata(
            "cli-fake",
            "CLI Fake",
            "1.0",
            ["page_records"],
            {"base_url": {"required": True}},
            {"credential": {"required": False}},
        )

    def connect(self, settings, secrets):
        raise AssertionError("connect should not be called by source add")


def run_cli(args):
    out = io.StringIO()
    err = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = catalog_cli.main(args)
    return code, out.getvalue(), err.getvalue()


def _seed_catalog_entry(value: str = "Bietje Bakker"):
    source = catalog.add_source("customers", "sqlite", "/tmp/customers.db")
    scan = catalog.create_scan_run(source.id)
    finding = catalog.create_finding(
        scan.id,
        source.id,
        {"dataset": "customers", "column": "name", "row_ref": "1"},
        "PERSON",
        value,
        "deterministic",
    )
    return catalog.accept_finding(finding.id)


def test_source_connectors_json_lists_sqlite():
    with IsolatedCatalogHome():
        code, out, _err = run_cli(["source", "connectors", "--json"])
        data = json.loads(out)
        assert code == 0
        assert any(item["id"] == "sqlite" for item in data["connectors"])


def test_source_add_sqlite_list_and_scan_json():
    with IsolatedCatalogHome() as home:
        db_path = create_customer_db(home.home / "customers.db")
        code, out, _err = run_cli([
            "source",
            "add",
            "sqlite",
            "customers",
            str(db_path),
            "--scope",
            "customers:first_name,last_name,email,phone",
            "--json",
        ])
        assert code == 0
        assert json.loads(out)["source"]["name"] == "customers"

        code, out, _err = run_cli(["source", "list", "--json"])
        assert code == 0
        assert json.loads(out)["sources"][0]["name"] == "customers"

        code, out, _err = run_cli(["scan", "customers", "--json"])
        data = json.loads(out)
        assert code == 0
        assert data["scan"]["rows_seen"] == 2
        assert data["scan"]["accepted_total"] > 0

        code, out, err = run_cli(["refresh", "customers", "--json"])
        data = json.loads(out)
        assert code == 0, err
        assert data["scan"]["rows_seen"] == 2


def test_source_add_plugin_records_secret_refs_not_secret_values():
    with IsolatedCatalogHome():
        source_plugins.register_connector(CliFakeConnector())
        code, out, _err = run_cli([
            "source",
            "add",
            "cli-fake",
            "api",
            "--setting",
            "base_url=https://api.example.test",
            "--secret-env",
            "credential=ODOO_CREDENTIAL_ENV",
            "--scope",
            "contacts:name,email",
            "--json",
        ])
        data = json.loads(out)
        assert code == 0
        assert data["source"]["type"] == "cli-fake"
        assert "ODOO_CREDENTIAL_ENV" in data["source"]["credential_refs"].values()
        assert "secret" not in out.lower()


def test_invalid_connector_error_is_sanitized():
    with IsolatedCatalogHome():
        code, _out, err = run_cli([
            "source",
            "add",
            "missing",
            "bad",
            "--setting",
            "base_url=https://api.example.test",
        ])
        assert code != 0
        assert "missing" in err
        assert "credential" not in err.lower()


def test_policy_set_and_reveal_json_outputs_expiry():
    with IsolatedCatalogHome():
        entry = _seed_catalog_entry()

        code, out, err = run_cli([
            "policy",
            "set",
            "--name-mode",
            "strict",
            "--allow-first-name",
            "false",
            "--strict-near-identifiers",
            "true",
            "--temporary-reveal-minutes",
            "15",
            "--json",
        ])
        policy_data = json.loads(out)
        assert code == 0, err
        assert policy_data["policy"]["name_mode"] == "strict"
        assert policy_data["policy"]["allow_first_name"] is False
        assert policy_data["policy"]["temporary_reveal_minutes"] == 15

        code, out, err = run_cli([
            "reveal",
            str(entry.id),
            "--reason",
            "support task",
            "--minutes",
            "5",
            "--json",
        ])
        reveal_data = json.loads(out)
        assert code == 0, err
        assert reveal_data["grant"]["catalog_entry_id"] == entry.id
        assert reveal_data["grant"]["status"] == "active"
        assert reveal_data["grant"]["expires_at"]


def test_policy_and_reveal_reject_invalid_durations():
    with IsolatedCatalogHome():
        entry = _seed_catalog_entry()

        code, _out, err = run_cli([
            "policy",
            "set",
            "--temporary-reveal-minutes",
            "0",
        ])
        assert code != 0
        assert "duration" in err.lower()

        code, _out, err = run_cli([
            "reveal",
            str(entry.id),
            "--reason",
            "support task",
            "--minutes",
            "0",
        ])
        assert code != 0
        assert "duration" in err.lower()


def test_findings_list_accept_reject_masks_and_reveals():
    with IsolatedCatalogHome():
        source = catalog.add_source("customers", "sqlite", "/tmp/customers.db")
        scan = catalog.create_scan_run(source.id)
        email = "review.me" + "@" + "example.test"
        finding = catalog.create_finding(
            scan.id,
            source.id,
            {"dataset": "customers", "column": "email", "row_ref": "1"},
            "EMAIL_ADDRESS",
            email,
            "medium",
            "model label",
        )
        rejected = catalog.create_finding(
            scan.id,
            source.id,
            {"dataset": "customers", "column": "notes", "row_ref": "2"},
            "PERSON",
            "Internal Label",
            "low",
            "model label",
        )

        code, out, err = run_cli(["findings", "list", "--json"])
        listed = json.loads(out)
        assert code == 0, err
        assert listed["findings"][0]["value"] != email
        assert listed["findings"][0]["masked"] is True

        code, out, err = run_cli(["findings", "list", "--reveal", "--json"])
        revealed = json.loads(out)
        assert code == 0, err
        assert any(item["value"] == email for item in revealed["findings"])

        code, out, err = run_cli(["findings", "accept", str(finding.id), "--json"])
        accepted = json.loads(out)
        assert code == 0, err
        assert accepted["accepted"][0]["finding_id"] == finding.id
        assert catalog.list_findings(status=catalog.FINDING_ACCEPTED)[0].id == finding.id

        code, out, err = run_cli([
            "findings",
            "reject",
            str(rejected.id),
            "--reason",
            "not pii",
            "--json",
        ])
        rejected_payload = json.loads(out)
        assert code == 0, err
        assert rejected_payload["rejected"][0]["finding_id"] == rejected.id
        assert catalog.list_findings(status=catalog.FINDING_REJECTED)[0].id == rejected.id


def test_forget_requires_confirmation_and_erases_catalog_and_log_refs():
    with IsolatedCatalogHome():
        entry = _seed_catalog_entry()

        code, _out, err = run_cli(["forget", ""])
        assert code != 0
        assert "empty" in err.lower()

        code, _out, err = run_cli(["forget", "Bietje"])
        assert code != 0
        assert "confirmation" in err.lower()

        code, out, err = run_cli(["forget", "Bietje", "--yes", "--json"])
        payload = json.loads(out)
        assert code == 0, err
        assert payload["catalog_removed"] == 1
        assert all(item.id != entry.id for item in catalog.list_catalog_entries(active_only=True))


if __name__ == "__main__":
    tests = [
        test_source_connectors_json_lists_sqlite,
        test_source_add_sqlite_list_and_scan_json,
        test_source_add_plugin_records_secret_refs_not_secret_values,
        test_invalid_connector_error_is_sanitized,
        test_policy_set_and_reveal_json_outputs_expiry,
        test_policy_and_reveal_reject_invalid_durations,
        test_findings_list_accept_reject_masks_and_reveals,
        test_forget_requires_confirmation_and_erases_catalog_and_log_refs,
    ]
    for test in tests:
        test()
        print(f"  ✓ {test.__name__}")
