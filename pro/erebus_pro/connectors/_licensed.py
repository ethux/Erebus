# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""The license gate every Pro connector passes first.

Core never checks a license: a Pro connector raises ``LicenseRequired`` itself when the
license lacks ``connectors.<type>`` (no key, another feature, expired past grace). The
worker stores that message as is and syncs nothing more for the source; values already
synced keep matching.
"""
from __future__ import annotations

from functools import cache

from erebus.cataloging.connector_errors import LicenseRequired

from ..license import Entitlements, from_env


@cache
def default_entitlements() -> Entitlements:
    """The worker's license (``EREBUS_LICENSE_KEY`` or ``_FILE``), read once; expiry is live."""
    return from_env()


class LicensedConnector:
    """Base of a Pro connector for ``type_id``; ``entitlements`` defaults to the worker's."""

    type_id = ""

    def __init__(self, entitlements: Entitlements | None = None) -> None:
        self._entitlements = entitlements

    def connector_id(self) -> str:
        return self.type_id

    def require_license(self) -> None:
        """Raise ``LicenseRequired`` unless the license carries ``connectors.<type_id>``."""
        entitlements = self._entitlements if self._entitlements is not None else default_entitlements()
        feature = f"connectors.{self.type_id}"
        if not entitlements.has(feature):
            raise LicenseRequired(feature)
