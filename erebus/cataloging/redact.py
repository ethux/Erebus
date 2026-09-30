"""Mask what an error message may carry before it reaches a log or the laptop CLI.

Pure (no store or config import), so it serves the laptop catalog and any other process.
``sanitize_error`` masks emails, phone numbers, secret assignments, DSNs, conninfo
values, host names, IP addresses and Postgres ``DETAIL`` lines. It is no licence to
store or log a source's error: a free-form message can still carry a value, so the sync
worker keeps fixed text in job rows and logs only exception types.
"""
from __future__ import annotations

import ipaddress
import re

_MAX = 500
_EMAIL_RE = re.compile(r"(?i)[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}")
_PHONE_RE = re.compile(r"\+?[\d\s().-]{7,}")
_SECRET_ASSIGNMENT_RE = re.compile(r"(?i)(password|secret|token|api[_-]?key)\s*[:=]\s*\S+")
_DETAIL_RE = re.compile(r"(?m)^\s*DETAIL:.*$")
_DSN_RE = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://\S+")
_CONNINFO_RE = re.compile(
    r"(?i)\b(host|hostaddr|port|dbname|database|db|user|username|passfile|service|sslkey|sslcert|"
    r"sslrootcert|options)\s*=\s*('[^']*'|\S+)"
)
# Candidates only; each is checked with ipaddress so times and ratios stay readable.
_IP_RE = re.compile(r"(?i)(?<![\w:.])(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?![\w:])|\b\d{1,3}(?:\.\d{1,3}){3}\b")
_HOST_RE = re.compile(r"(?i)(?<![/\w.\-@])(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+[a-z]{2,24}\b(?![/\w\-])")


def _ip(match: re.Match) -> str:
    try:
        ipaddress.ip_address(match.group(0))
    except ValueError:
        return match.group(0)
    return "[HOST]"


def sanitize_error(exc: BaseException | str) -> str:
    """``exc`` as text with secrets, contact details, hosts and DSNs masked (500 chars max)."""
    text = str(exc)
    text = _DETAIL_RE.sub("DETAIL: [REDACTED]", text)
    text = _DSN_RE.sub("[DSN]", text)
    text = _CONNINFO_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _EMAIL_RE.sub("[EMAIL]", text)
    text = _SECRET_ASSIGNMENT_RE.sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    text = _IP_RE.sub(_ip, text)
    text = _HOST_RE.sub("[HOST]", text)
    text = _PHONE_RE.sub("[PHONE]", text)
    return text[:_MAX]
