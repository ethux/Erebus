"""Compatibility alias for catalog known-value matching."""
from __future__ import annotations

import sys

from .cataloging import matcher as _matcher

sys.modules[__name__] = _matcher
