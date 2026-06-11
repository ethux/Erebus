"""Shared helpers for catalog feature tests."""
from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path
from unittest.mock import patch

from erebus import catalog, config
from erebus.audit import logger
from erebus.core import cache_disk


class IsolatedCatalogHome:
    """Context manager that redirects Erebus sensitive paths to a temp home."""

    def __enter__(self):
        self.home = Path(tempfile.mkdtemp(prefix="erebus-catalog-test-"))
        self.erebus_dir = self.home / ".erebus"
        self.orig_db = config.DB_PATH
        self.orig_token_map = config.TOKEN_MAP_PATH
        self.orig_catalog_db = getattr(catalog, "CATALOG_DB_PATH", config.DB_PATH)
        config.DB_PATH = self.erebus_dir / "log.db"
        config.TOKEN_MAP_PATH = self.erebus_dir / "token_map.json"
        logger.DB_PATH = config.DB_PATH
        catalog.CATALOG_DB_PATH = config.DB_PATH
        # The tokenize disk cache resolves its path at import time, so redirect
        # it explicitly (repoint BEFORE reset: reset() unlinks the current file)
        # or results leak into the real ~/.erebus across test runs.
        self.orig_disk_cache = cache_disk._DISK_CACHE_PATH
        cache_disk._DISK_CACHE_PATH = self.erebus_dir / "tokenize_cache.json"
        cache_disk.reset()
        self.home_patch = patch.object(Path, "home", return_value=self.home)
        self.home_patch.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.home_patch.stop()
        config.DB_PATH = self.orig_db
        config.TOKEN_MAP_PATH = self.orig_token_map
        logger.DB_PATH = self.orig_db
        catalog.CATALOG_DB_PATH = self.orig_catalog_db
        cache_disk.reset()  # still pointing at the temp file; real cache untouched
        cache_disk._DISK_CACHE_PATH = self.orig_disk_cache


def create_customer_db(path: Path) -> Path:
    """Create a small SQLite customer database for catalog scans."""
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE customers (
            id INTEGER PRIMARY KEY,
            first_name TEXT,
            last_name TEXT,
            email TEXT,
            phone TEXT,
            account_id TEXT,
            notes TEXT
        )
        """
    )
    email1 = "jan.jansen" + "@" + "example.test"
    email2 = "bietje.bakker" + "@" + "example.test"
    phone1 = "+31" + "612345678"
    phone2 = "+31" + "687654321"
    conn.executemany(
        """
        INSERT INTO customers
            (first_name, last_name, email, phone, account_id, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        [
            ("Jan", "Jansen", email1, phone1, "CUST-001", "VIP contact"),
            ("Bietje", "Bakker", email2, phone2, "CUST-002", "Odoo partner"),
        ],
    )
    conn.commit()
    conn.close()
    return path
