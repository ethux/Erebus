"""Compatibility alias for trusted source connector plugins."""
from __future__ import annotations

import sys

from .cataloging import sources as _sources

sys.modules[__name__] = _sources
