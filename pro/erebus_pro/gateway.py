# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Registers Erebus Pro with the gateway (``erebus.gateway.extensions`` entry point)."""
from __future__ import annotations

from .license import from_env


def register(app, _config) -> None:
    """Attach entitlements to ``app.state`` and expose ``GET /v1/license``. Never raises on key problems."""
    entitlements = from_env()
    app.state.erebus_entitlements = entitlements
    _ = entitlements.status  # first read logs a startup warning for grace/expired/invalid keys

    @app.get("/v1/license")
    async def license_status() -> dict:
        return entitlements.public_view()
