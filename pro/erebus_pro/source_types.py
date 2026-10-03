# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Erebus Pro connector types as data (the ``erebus.source_types`` entry point).

The gateway loads this to accept a Pro type and its setting keys, so it imports nothing
but core's ``ConnectorType``: no connector module, no driver. SaaS warehouses take an
account or project id and the connector derives the vendor host; Databricks takes the
workspace host itself, accepted only on Databricks' own domains. A self-hosted database
(Oracle) takes a host and port like Postgres: its ``default_port`` makes the worker
resolve the host, apply its host lists and hand the connector the checked ``hostaddr``.
No Pro type takes a DSN, connect descriptor or endpoint. Without erebus-pro installed
these types are unknown.
"""
from __future__ import annotations

from erebus.cataloging.connector_types import ConnectorType

TYPES = (
    ConnectorType("snowflake", "warehouse", "pro",
                  frozenset({"account", "user", "database", "warehouse", "role", "schemas", "collections"})),
    # ``schemas`` are BigQuery datasets; ``auth`` is "key" (a service-account key) or "attached" (ADC).
    ConnectorType("bigquery", "warehouse", "pro",
                  frozenset({"project", "location", "max_bytes_billed", "auth", "schemas", "collections"})),
    # ``server_hostname`` is the workspace host, which the connector checks against Databricks'
    # own domains; ``client_id`` is the service principal's (its secret is a credential).
    ConnectorType("databricks", "warehouse", "pro",
                  frozenset({"server_hostname", "http_path", "catalog", "client_id", "schemas", "collections"})),
    # ``auth`` is "password" (the default) or "wallet" (an mTLS wallet's certificate signs in).
    ConnectorType("oracle", "database", "pro",
                  frozenset({"host", "port", "service_name", "user", "sslmode", "auth", "schemas", "collections"}),
                  1521),
)
