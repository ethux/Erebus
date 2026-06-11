"""Compatibility alias for catalog storage/domain operations."""
from __future__ import annotations

import sys

from .cataloging import store as _store

sys.modules[__name__] = _store
