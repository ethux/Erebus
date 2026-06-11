"""Tests for catalog known-value matching."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from test_catalog_helpers import IsolatedCatalogHome

from erebus import catalog, catalog_matcher, config


def _seed_entry(value: str, category: str = "PERSON"):
    source = catalog.add_source("customers", "sqlite", "/tmp/customers.db")
    scan = catalog.create_scan_run(source.id)
    finding = catalog.create_finding(
        scan.id,
        source.id,
        {"dataset": "customers", "column": "name", "row_ref": "1"},
        category,
        value,
        "deterministic",
    )
    return catalog.accept_finding(finding.id)


def test_catalog_matcher_loads_active_entries_and_filters_sources():
    with IsolatedCatalogHome():
        entry = _seed_entry("Jan Jansen")
        cfg = config.RepoConfig()
        cfg.pii_catalog.enabled = True
        cfg.pii_catalog.source_names = ["customers"]

        entries = catalog_matcher.load_active_entries(cfg)

        assert [e.id for e in entries] == [entry.id]


def test_catalog_matcher_replaces_longest_overlapping_value_first():
    with IsolatedCatalogHome():
        full = _seed_entry("Jan Jansen")
        _seed_entry("Jan")
        cfg = config.RepoConfig()
        cfg.pii_catalog.enabled = True
        cfg.pii_catalog.name_mode = "strict"

        sanitized, tokens, matches = catalog_matcher.apply_catalog_matches(
            "Ask Jan Jansen about Jan Jansen today",
            cfg,
        )

        assert "Jan Jansen" not in sanitized
        assert sanitized.count(full.token) == 2
        assert tokens[full.token] == "Jan Jansen"
        assert len(matches) == 2


def test_catalog_matcher_skips_removed_entries():
    with IsolatedCatalogHome():
        entry = _seed_entry("Bietje Bakker")
        catalog.forget_catalog_value("Bietje")
        cfg = config.RepoConfig()
        cfg.pii_catalog.enabled = True

        sanitized, tokens, matches = catalog_matcher.apply_catalog_matches(
            "Bietje Bakker should stay because entry is removed",
            cfg,
        )

        assert entry.token not in sanitized
        assert tokens == {}
        assert matches == []


def test_catalog_matcher_applies_strict_balanced_and_relaxed_name_policies():
    with IsolatedCatalogHome():
        entry = _seed_entry("Bietje Bakker")
        cfg = config.RepoConfig()
        cfg.pii_catalog.enabled = True

        cfg.pii_catalog.name_mode = "strict"
        strict_text, strict_tokens, strict_matches = catalog_matcher.apply_catalog_matches(
            "Ask Bietje Bakker for an update",
            cfg,
        )
        assert strict_text == f"Ask {entry.token} for an update"
        assert strict_tokens[entry.token] == "Bietje Bakker"
        assert strict_matches[0].policy_decision == "tokenized"

        cfg.pii_catalog.name_mode = "balanced"
        balanced_text, balanced_tokens, balanced_matches = catalog_matcher.apply_catalog_matches(
            "Ask Bietje Bakker for an update",
            cfg,
        )
        assert balanced_text == f"Ask Bietje {entry.token} for an update"
        assert balanced_tokens[entry.token] == "Bakker"
        assert balanced_matches[0].policy_decision == "first_name_visible"

        cfg.pii_catalog.name_mode = "relaxed"
        relaxed_text, relaxed_tokens, relaxed_matches = catalog_matcher.apply_catalog_matches(
            "Ask Bietje Bakker for an update",
            cfg,
        )
        assert relaxed_text == "Ask Bietje Bakker for an update"
        assert relaxed_tokens == {}
        assert relaxed_matches[0].policy_decision == "visible"


def test_catalog_matcher_strict_near_identifier_overrides_visible_names():
    with IsolatedCatalogHome():
        entry = _seed_entry("Bietje Bakker")
        email = "bietje.bakker" + "@" + "example.test"
        cfg = config.RepoConfig()
        cfg.pii_catalog.enabled = True
        cfg.pii_catalog.name_mode = "relaxed"
        cfg.pii_catalog.strict_near_identifiers = True

        sanitized, tokens, matches = catalog_matcher.apply_catalog_matches(
            f"Bietje Bakker uses {email}",
            cfg,
        )

        assert sanitized == f"{entry.token} uses {email}"
        assert tokens[entry.token] == "Bietje Bakker"
        assert matches[0].policy_decision == "strict_override"


def test_catalog_matcher_temporary_reveal_keeps_value_visible():
    with IsolatedCatalogHome():
        entry = _seed_entry("Bietje Bakker")
        catalog.create_reveal_grant(entry.id, "support task", minutes=5)
        cfg = config.RepoConfig()
        cfg.pii_catalog.enabled = True
        cfg.pii_catalog.name_mode = "strict"

        sanitized, tokens, matches = catalog_matcher.apply_catalog_matches(
            "Ask Bietje Bakker for an update",
            cfg,
        )

        assert sanitized == "Ask Bietje Bakker for an update"
        assert tokens == {}
        assert matches[0].policy_decision == "temporarily_revealed"


if __name__ == "__main__":
    tests = [
        test_catalog_matcher_loads_active_entries_and_filters_sources,
        test_catalog_matcher_replaces_longest_overlapping_value_first,
        test_catalog_matcher_skips_removed_entries,
        test_catalog_matcher_applies_strict_balanced_and_relaxed_name_policies,
        test_catalog_matcher_strict_near_identifier_overrides_visible_names,
        test_catalog_matcher_temporary_reveal_keeps_value_visible,
    ]
    for test in tests:
        test()
        print(f"  ✓ {test.__name__}")
