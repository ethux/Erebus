"""End-to-end catalog API tests over a real local fake HTTP API."""
from __future__ import annotations

import http.server
import json
import os
import sys
import threading
import urllib.parse
import urllib.request
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_catalog_helpers import IsolatedCatalogHome

from erebus import catalog, catalog_scan, config, proxy, source_plugins

CREDENTIAL_ENV = "EREBUS_FAKE_API_CREDENTIAL"
CONTACT_COLUMNS = ["name", "email", "phone", "external_id"]


def fake_email(local_part: str) -> str:
    return local_part + "@" + "example.test"


FAKE_CONTACTS = [
    {
        "id": 1,
        "name": "Avery Example",
        "email": fake_email("avery.example"),
        "phone": "+31" + "612340001",
        "external_id": "ODOO-9001",
    },
    {
        "id": 2,
        "name": "Blair Sample",
        "email": fake_email("blair.sample"),
        "phone": "+31" + "612340002",
        "external_id": "ODOO-9002",
    },
    {
        "id": 3,
        "name": "Casey Fixture",
        "email": fake_email("casey.fixture"),
        "phone": "+31" + "612340003",
        "external_id": "ODOO-9003",
    },
    {
        "id": 4,
        "name": "Devon Synthetic",
        "email": fake_email("devon.synthetic"),
        "phone": "+31" + "612340004",
        "external_id": "ODOO-9004",
    },
    {
        "id": 5,
        "name": "Emery Placeholder",
        "email": fake_email("emery.placeholder"),
        "phone": "+31" + "612340005",
        "external_id": "ODOO-9005",
    },
]


class FakeApiServer:
    """Threaded localhost API serving paginated synthetic contact records."""

    def __init__(self, fault: bool = False, expected_credential: str = "Z9Y8X7"):
        self.fault = fault
        self.expected_credential = expected_credential
        self.records = [dict(record) for record in FAKE_CONTACTS]
        self.request_methods: list[str] = []
        self.request_paths: list[str] = []
        self.base_url = ""
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> FakeApiServer:
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        host, port = self._server.server_address
        self.base_url = f"http://{host}:{port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)

    def _handler(self):
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, format, *args) -> None:
                return

            def json_response(self, status: int, payload: dict) -> None:
                body = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def reject_non_get(self) -> None:
                owner.request_methods.append(self.command)
                owner.request_paths.append(self.path)
                self.json_response(405, {"error": "method not allowed"})

            def do_POST(self) -> None:
                self.reject_non_get()

            def do_PUT(self) -> None:
                self.reject_non_get()

            def do_PATCH(self) -> None:
                self.reject_non_get()

            def do_DELETE(self) -> None:
                self.reject_non_get()

            def do_GET(self) -> None:
                owner.request_methods.append("GET")
                owner.request_paths.append(self.path)

                auth = self.headers.get("Authorization", "")
                if auth != f"Bearer {owner.expected_credential}":
                    self.json_response(401, {"error": "unauthorized"})
                    return

                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != "/contacts":
                    self.json_response(404, {"error": "not found"})
                    return

                if owner.fault:
                    self.json_response(500, {"error": "internal"})
                    return

                query = urllib.parse.parse_qs(parsed.query)
                page = max(1, int(query.get("page", ["1"])[0]))
                page_size = max(1, int(query.get("page_size", ["2"])[0]))
                start = (page - 1) * page_size
                end = start + page_size
                self.json_response(
                    200,
                    {
                        "records": owner.records[start:end],
                        "page": page,
                        "has_more": end < len(owner.records),
                    },
                )

        return Handler


class HttpApiRowSource:
    """Test connector row source that pages through the fake API over HTTP."""

    def __init__(self, base_url: str, credential: str, page_size: int = 2):
        self.base_url = base_url.rstrip("/")
        self.credential = credential
        self.page_size = page_size

    def list_collections(self):
        return [source_plugins.CollectionInfo("contacts")]

    def list_fields(self, collection: str):
        if collection != "contacts":
            raise ValueError(f"Unknown collection: {collection}")
        return [
            source_plugins.FieldInfo("name", "Name", "text", "person"),
            source_plugins.FieldInfo("email", "Email", "email", "email"),
            source_plugins.FieldInfo("phone", "Phone", "phone", "phone"),
            source_plugins.FieldInfo("external_id", "External ID", "identifier", "identifier"),
        ]

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 2,
    ):
        if collection != "contacts":
            raise ValueError(f"Unknown collection: {collection}")
        selected = fields or CONTACT_COLUMNS
        emitted = 0
        page = 1
        effective_page_size = min(page_size, self.page_size)

        while True:
            query = urllib.parse.urlencode({"page": page, "page_size": effective_page_size})
            request = urllib.request.Request(
                f"{self.base_url}/{collection}?{query}",
                headers={"Authorization": f"Bearer {self.credential}"},
                method="GET",
            )
            with urllib.request.urlopen(request, timeout=5) as response:
                payload = json.loads(response.read().decode("utf-8"))

            for record in payload["records"]:
                values = {field: record[field] for field in selected}
                yield source_plugins.SourceRecord(
                    f"{collection}:{record['id']}",
                    values,
                    {"page": payload["page"]},
                )
                emitted += 1
                if limit is not None and emitted >= limit:
                    return

            if not payload.get("has_more"):
                return
            page += 1

    def close(self) -> None:
        return


class HttpApiConnector:
    def connector_id(self) -> str:
        return "fake-http-api"

    def connector_metadata(self):
        return source_plugins.ConnectorMetadata(
            "fake-http-api",
            "Fake HTTP API",
            "1.0",
            ["page_records"],
            {"base_url": {"required": True}},
            {"token": {"required": True}},
        )

    def connect(self, settings: dict, secrets: dict):
        return HttpApiRowSource(settings["base_url"], secrets["token"])


def register_connector() -> None:
    source_plugins.register_connector(HttpApiConnector())


def add_api_source(base_url: str) -> catalog.ExternalDataSource:
    source = catalog.add_source(
        "api",
        "fake-http-api",
        connector_config={"base_url": base_url},
        secret_refs={"token": CREDENTIAL_ENV},
    )
    catalog.add_scope(source.id, "contacts", CONTACT_COLUMNS)
    return source


def scan_fake_api(server: FakeApiServer):
    os.environ[CREDENTIAL_ENV] = server.expected_credential
    register_connector()
    source = add_api_source(server.base_url)
    result = catalog_scan.scan_source("api")
    return source, result


def api_repo_config() -> config.RepoConfig:
    cfg = config.RepoConfig()
    cfg.pii_catalog.enabled = True
    cfg.pii_catalog.source_names = ["api"]
    return cfg


def assert_no_seeded_data(text: str, include_names: bool = True) -> None:
    assert "@" not in text
    for record in FAKE_CONTACTS:
        assert record["email"] not in text
        assert record["phone"] not in text
        assert record["external_id"] not in text
        if include_names:
            assert record["name"] not in text


def test_api_values_scrubbed_and_restored_through_proxy():
    with IsolatedCatalogHome():
        with FakeApiServer() as server:
            source, result = scan_fake_api(server)
            assert source.name == "api"
            assert result.status == catalog.SCAN_COMPLETED

            contact = server.records[0]
            first_name, hidden_name = contact["name"].split(maxsplit=1)
            prompt = (
                f"Send status to {contact['email']} and call {contact['phone']} "
                f"for account {contact['external_id']}. "
                f"{'context ' * 30}"
                f"Visible-name policy check: {contact['name']}."
            )

            proxy.TOKEN_MAP.clear()
            with patch("erebus.proxy.cached_tokenize", side_effect=lambda text, *a, **k: (text, {})):
                sanitized, tokens = proxy._tokenize_proxy_text(prompt, api_repo_config())

            assert contact["email"] not in sanitized
            assert contact["phone"] not in sanitized
            assert contact["external_id"] not in sanitized
            assert contact["name"] not in sanitized
            assert first_name in sanitized
            assert hidden_name not in sanitized
            assert any(token.startswith("[CATALOG_") for token in tokens)
            assert {contact["email"], contact["phone"], contact["external_id"], hidden_name} <= set(tokens.values())

            proxy.TOKEN_MAP.update(tokens)
            assert proxy._detokenize_text(sanitized) == prompt


def test_api_scan_paginates_and_accepts_findings():
    with IsolatedCatalogHome():
        with FakeApiServer() as server:
            source, result = scan_fake_api(server)

            assert result.status == catalog.SCAN_COMPLETED
            assert result.rows_seen == len(server.records)
            fetched_pages = [path for path in server.request_paths if path.startswith("/contacts?")]
            assert len(fetched_pages) > 1

            findings = catalog.list_findings(source_id=source.id)
            categories = {finding.category for finding in findings}
            assert {"EMAIL_ADDRESS", "PHONE_NUMBER", "PERSON", "IDENTIFIER"} <= categories
            assert all("@" not in finding.detection_reason for finding in findings)


def test_api_source_is_read_only():
    with IsolatedCatalogHome():
        with FakeApiServer() as server:
            source, result = scan_fake_api(server)

            assert source.type == "fake-http-api"
            assert result.status == catalog.SCAN_COMPLETED
            assert server.request_methods
            assert all(method == "GET" for method in server.request_methods)


def test_api_rejects_missing_or_wrong_credential():
    cases = [
        ("missing", None),
        ("wrong", "not-the-credential"),
    ]
    for label, credential in cases:
        with IsolatedCatalogHome():
            with FakeApiServer() as server:
                register_connector()
                if credential is None:
                    os.environ.pop(CREDENTIAL_ENV, None)
                else:
                    os.environ[CREDENTIAL_ENV] = credential
                add_api_source(server.base_url)

                result = catalog_scan.scan_source("api")

                assert result.status == catalog.SCAN_FAILED, label
                assert "401" in result.error_summary or "Unauthorized" in result.error_summary
                assert server.expected_credential not in result.error_summary


def test_api_scan_error_summary_is_sanitized():
    with IsolatedCatalogHome():
        with FakeApiServer(fault=True, expected_credential="Q7W6E5") as server:
            source, result = scan_fake_api(server)

            assert source.name == "api"
            assert result.status == catalog.SCAN_FAILED
            assert result.error_summary
            assert_no_seeded_data(result.error_summary)
            assert server.expected_credential not in result.error_summary


if __name__ == "__main__":
    tests = [
        test_api_values_scrubbed_and_restored_through_proxy,
        test_api_scan_paginates_and_accepts_findings,
        test_api_source_is_read_only,
        test_api_rejects_missing_or_wrong_credential,
        test_api_scan_error_summary_is_sanitized,
    ]
    for test in tests:
        test()
        print(f"  ✓ {test.__name__}")
