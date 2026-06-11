"""Compatibility alias for catalog scanning operations."""
from __future__ import annotations

import sys

from .cataloging import scan as _scan

sys.modules[__name__] = _scan
