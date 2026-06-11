"""Patchable time source for everything time-dependent in the boundary.

Escape-allowance expiry, retention rotation, and warn debouncing all read the
clock through here so tests can inject time instead of sleeping. Production
code must not call datetime.now()/time.monotonic() directly for boundary
decisions; it calls clock.now() / clock.monotonic().
"""
from __future__ import annotations

import time as _time
from datetime import UTC, datetime


def now() -> datetime:
    """Current UTC time. Patch this in tests to control allowance/rotation math."""
    return datetime.now(UTC)


def monotonic() -> float:
    """Monotonic seconds. Patch this in tests to control debounce windows."""
    return _time.monotonic()
