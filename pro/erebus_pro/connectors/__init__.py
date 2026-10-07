# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Erebus Pro source connectors (``erebus.sources`` entry points).

Only the sync worker loads these; the gateway never does. Each one checks its license
feature ``connectors.<type>`` before it reads a credential or imports its driver, and
wraps every driver failure in core's fixed-text ``ConnectorError``.
"""
