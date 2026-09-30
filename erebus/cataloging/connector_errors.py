"""Errors a source connector may raise (spec 015 "Sync behaviour": failure).

A connector wraps every driver or HTTP failure in ``ConnectorError(kind)``, raised
``from None``: its message is the class's fixed text, never a host, DSN, credential or
value. ``LicenseRequired`` is raised by Pro connectors without their license feature.
Pure: no store, config or gateway import.
"""
from __future__ import annotations

import re

CONNECTOR_TEXT = {
    "auth": "authentication failed",
    "unreachable": "source unreachable",
    "permission": "permission denied",
    "query": "query failed",
    "limit": "source rate limit reached",
    "incomplete": "sync incomplete",
}
_FEATURE = re.compile(r"[a-z0-9_.-]{1,64}")


class ConnectorError(Exception):
    """A connector failure of class ``kind``; ``str()`` is the fixed text.

    ``reset_at`` (``limit`` only) is when the source's limit resets, if it said so: a
    ``datetime`` or an ISO-8601 string. Use ``incomplete`` when a query was capped or
    values were skipped, so the sync retires nothing.
    """

    def __init__(self, kind: str, *, reset_at=None) -> None:
        if kind not in CONNECTOR_TEXT:
            raise ValueError("unknown connector error class")
        super().__init__(CONNECTOR_TEXT[kind])
        self.kind = kind
        self.reset_at = reset_at


class LicenseRequired(PermissionError):
    """The Erebus Pro license lacks ``feature``; the message is stored as is."""

    def __init__(self, feature: str) -> None:
        if not _FEATURE.fullmatch(feature):
            raise ValueError("malformed license feature")
        super().__init__(f"requires Erebus Pro (feature {feature})")
        self.feature = feature
