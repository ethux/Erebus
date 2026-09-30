"""Pure rules for sync jobs and known values (spec 015 "Sync behaviour", "Failure").

No database, config or connector import: the job store and the worker apply these, and
the pure tests check them directly. Every error a job row can carry is a fixed text
from ``ERROR_TEXT`` (SC-4); only a well-formed LicenseRequired message is kept as is.
"""
from __future__ import annotations

import re
from collections.abc import Collection
from dataclasses import dataclass
from datetime import datetime, timedelta

ERROR_TEXT = {
    "auth": "authentication failed",
    "unreachable": "source unreachable",
    "permission": "permission denied",
    "query": "query failed",
    "limit": "source rate limit reached",
    "incomplete": "sync incomplete",
    "license": "requires Erebus Pro",
    "crypto_erased": "tenant keys erased",
    "lease": "worker lease expired",
    "internal": "internal error",
}

# Unretried, and the source is marked needs_attention: a person must act.
_FATAL = frozenset({"auth", "permission", "incomplete", "license", "crypto_erased"})
_LICENSE_TEXT = re.compile(r"requires Erebus Pro \(feature [a-z0-9_.-]{1,64}\)")

MIN_VALUE_CHARS = 3
_MIN_NUMERIC_DIGITS = 6
_NUMERIC = re.compile(r"[0-9]+")


@dataclass(frozen=True)
class JobTimings:
    """Worker timings; defaults are the spec's (EREBUS_SYNC_* overrides them)."""

    lease_s: int = 600
    heartbeat_s: int = 30
    backoff_s: tuple[int, ...] = (60, 300, 900)
    limit_wait_s: int = 172800
    lease_attempts: int = 3


@dataclass(frozen=True)
class Outcome:
    """What a failed or expired job becomes."""

    status: str  # 'queued' (retry or wait) or 'failed'
    error: str
    attempts: int
    not_before: datetime | None = None
    limited_since: datetime | None = None
    needs_attention: bool = False


def error_text(error_class: str, license_message: str | None = None) -> str:
    """Fixed text for ``error_class``; unknown classes read as internal."""
    if error_class == "license" and license_message and _LICENSE_TEXT.fullmatch(license_message):
        return license_message
    return ERROR_TEXT.get(error_class, ERROR_TEXT["internal"])


def failure_outcome(
    error_class: str,
    *,
    attempts: int,
    limited_since: datetime | None,
    now: datetime,
    timings: JobTimings,
    reset_at: datetime | None = None,
    license_message: str | None = None,
) -> Outcome:
    """Decide retry, wait or failure for a job that raised ``error_class``.

    ``attempts`` counts earlier failed attempts. A limit wait is no attempt and fails
    once the job has waited ``limit_wait_s`` since its first limit.
    """
    if error_class not in ERROR_TEXT or error_class == "lease":
        error_class = "internal"
    text = error_text(error_class, license_message)
    if error_class in _FATAL:
        return Outcome("failed", text, attempts + 1, needs_attention=True)
    if error_class == "limit":
        since = limited_since or now
        deadline = since + timedelta(seconds=timings.limit_wait_s)
        wake = reset_at if reset_at is not None and reset_at > now else now + timedelta(seconds=timings.backoff_s[0])
        if now >= deadline or wake > deadline:
            return Outcome("failed", text, attempts, limited_since=since)
        return Outcome("queued", text, attempts, not_before=wake, limited_since=since)
    tried = attempts + 1
    if tried > len(timings.backoff_s):
        return Outcome("failed", text, tried)
    return Outcome("queued", text, tried, not_before=now + timedelta(seconds=timings.backoff_s[tried - 1]))


def lease_outcome(*, attempts: int, timings: JobTimings) -> Outcome:
    """A running job whose lease expired: re-queue as an attempt; the last one fails."""
    tried = attempts + 1
    if tried >= timings.lease_attempts:
        return Outcome("failed", ERROR_TEXT["lease"], tried, needs_attention=True)
    return Outcome("queued", ERROR_TEXT["lease"], tried)


def clean_value(value: str) -> str:
    """The stored form of a known value: whitespace runs collapsed, ends trimmed."""
    return " ".join(value.split())


def reject_reason(value: str, label: str, *, stop_words: Collection[str] = ()) -> str | None:
    """Why a synced value never becomes a known value, or ``None`` to keep it.

    ``label`` is compared case-insensitively. ``stop_words`` are casefolded single words.
    """
    cleaned = clean_value(value)
    if len(cleaned) < MIN_VALUE_CHARS:
        return "short"
    if _NUMERIC.fullmatch(cleaned) and len(cleaned) < _MIN_NUMERIC_DIGITS:
        return "numeric"
    single = " " not in cleaned
    if single and label.upper() == "PERSON":
        return "single_word"
    if single and cleaned.casefold() in stop_words:
        return "stop_word"
    return None
