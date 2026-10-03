# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Erebus Pro connector types as data (the ``erebus.source_types`` entry point).

The gateway loads this to accept a Pro type and its setting keys, so it imports nothing
but core's ``ConnectorType``: no connector module, no driver. SaaS warehouses take an
account or project id and the connector derives the vendor host; no Pro type takes a
host, DSN or endpoint. Without erebus-pro installed these types are unknown.
"""
from __future__ import annotations

from erebus.cataloging.connector_types import ConnectorType

TYPES = (
    ConnectorType("snowflake", "warehouse", "pro",
                  frozenset({"account", "user", "database", "warehouse", "role", "schemas", "collections"})),
    # ``schemas`` are BigQuery datasets; ``auth`` is "key" (a service-account key) or "attached" (ADC).
    ConnectorType("bigquery", "warehouse", "pro",
                  frozenset({"project", "location", "max_bytes_billed", "auth", "schemas", "collections"})),
)
