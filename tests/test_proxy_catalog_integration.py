"""Proxy integration tests for catalog known-value enforcement."""
from __future__ import annotations

import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_catalog_helpers import IsolatedCatalogHome

from erebus import catalog, config, proxy


def _seed_email_entry():
    source = catalog.add_source("customers", "sqlite", "/tmp/customers.db")
    scan = catalog.create_scan_run(source.id)
    value = "jan.jansen" + "@" + "example.test"
    finding = catalog.create_finding(
        scan.id,
        source.id,
        {"dataset": "customers", "column": "email", "row_ref": "1"},
        "EMAIL_ADDRESS",
        value,
        "deterministic",
    )
    return value, catalog.accept_finding(finding.id)


def test_proxy_tokenize_text_applies_catalog_before_detector():
    with IsolatedCatalogHome():
        value, entry = _seed_email_entry()
        cfg = config.RepoConfig()
        cfg.pii_catalog.enabled = True

        with patch("erebus.proxy.cached_tokenize", return_value=("already clean", {})) as cached:
            sanitized, tokens = proxy._tokenize_proxy_text(f"Ask {value} for status", cfg)

        assert value not in cached.call_args.args[0]
        assert entry.token in cached.call_args.args[0]
        assert entry.token in sanitized
        assert tokens[entry.token] == value


def test_proxy_catalog_tokens_detokenize_from_runtime_map():
    with IsolatedCatalogHome():
        value, _entry = _seed_email_entry()
        cfg = config.RepoConfig()
        cfg.pii_catalog.enabled = True
        proxy.TOKEN_MAP.clear()

        sanitized, tokens = proxy._tokenize_proxy_text(f"Ask {value}", cfg)
        proxy.TOKEN_MAP.update(tokens)

        assert proxy._detokenize_text(sanitized) == f"Ask {value}"


if __name__ == "__main__":
    tests = [
        test_proxy_tokenize_text_applies_catalog_before_detector,
        test_proxy_catalog_tokens_detokenize_from_runtime_map,
    ]
    for test in tests:
        test()
        print(f"  ✓ {test.__name__}")
