# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Registers Erebus Pro with the gateway (``erebus.gateway.extensions`` entry point)."""
from __future__ import annotations

import logging

from .license import Status, from_env

log = logging.getLogger(__name__)


def register(app, _config) -> None:
    """Attach entitlements to ``app.state`` and expose ``GET /v1/license``. Never raises on key problems."""
    entitlements = from_env()
    app.state.erebus_entitlements = entitlements
    status = entitlements.status
    if status in (Status.INVALID, Status.EXPIRED):
        log.warning("Erebus Pro license is %s: Pro features are off, core gateway unaffected", status.value)
    elif status is Status.GRACE:
        log.warning("Erebus Pro license expired: grace period active, renew within 14 days")

    @app.get("/v1/license")
    async def license_status() -> dict:
        return entitlements.public_view()
