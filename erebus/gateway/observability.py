"""Per-tenant and privacy-quality metrics with masked telemetry (FR-046).

Pure logic: an in-memory, per-instance metrics registry keyed by ``scope_id``.
This module holds no database and no process-global mutable state -- callers own
a :class:`Metrics` instance and its lifetime (FR-041..043). Telemetry is masked by
construction: the registry only ever stores integer counters, never raw values,
identifiers, prompts, or any other PII (FR-046). The recordable metrics are a
fixed, closed vocabulary covering per-tenant traffic and privacy quality:

* ``requests`` -- requests handled for the scope.
* ``tokenized_count`` -- values tokenized before egress.
* ``restored_count`` -- values de-tokenized (restored) on the return path.
* ``reveals`` -- approved reveal operations.
* ``blocked_egress`` -- egress attempts blocked by policy.
* ``over_tokenizations`` -- spans tokenized that need not have been (quality).
* ``escapes`` -- raw values that escaped tokenization (quality, should stay 0).
* ``quota_rejections`` -- requests rejected for exceeding quota.

Unknown metric names and unknown scopes are rejected/empty rather than silently
coerced, so the stored telemetry stays a numeric-only, fixed-shape surface.
"""
from __future__ import annotations

from enum import StrEnum
from threading import Lock


class Metric(StrEnum):
    """Closed vocabulary of recordable per-scope counters (FR-046)."""

    REQUESTS = "requests"
    TOKENIZED_COUNT = "tokenized_count"
    RESTORED_COUNT = "restored_count"
    REVEALS = "reveals"
    BLOCKED_EGRESS = "blocked_egress"
    OVER_TOKENIZATIONS = "over_tokenizations"
    ESCAPES = "escapes"
    QUOTA_REJECTIONS = "quota_rejections"


# Fixed order used for every snapshot so each scope's telemetry has a stable,
# fully-populated numeric shape (missing counters read as zero).
_METRIC_ORDER: tuple[Metric, ...] = tuple(Metric)


def _coerce_metric(metric: Metric | str) -> Metric | None:
    """Resolve a metric name to a :class:`Metric`; ``None`` if unknown."""
    if isinstance(metric, Metric):
        return metric
    try:
        return Metric(metric)
    except ValueError:
        return None


class Metrics:
    """In-memory per-tenant metrics registry keyed by ``scope_id`` (FR-046).

    Each instance owns its own state (no process-global mutable state, FR-043) and
    is safe to share across threads. Only integer counters are ever stored; no raw
    value, identifier, or other PII is accepted or retained -- telemetry is masked
    to counts by construction.
    """

    __slots__ = ("_counters", "_lock")

    def __init__(self) -> None:
        # scope_id -> {Metric -> count}. Counts only; never any raw payload.
        self._counters: dict[str, dict[Metric, int]] = {}
        self._lock = Lock()

    def record(self, scope_id: str, metric: Metric | str, n: int = 1) -> None:
        """Add ``n`` to ``metric`` for ``scope_id`` (FR-046).

        ``metric`` must be a member of the closed :class:`Metric` vocabulary
        (string or enum); unknown names raise :class:`KeyError`. ``n`` must be an
        integer (``bool`` is rejected) so only numeric telemetry is stored; a
        non-int ``n`` raises :class:`TypeError`. Negative ``n`` is permitted for
        corrections. Raw values are never accepted: the API surface stores counts
        only.
        """
        resolved = _coerce_metric(metric)
        if resolved is None:
            raise KeyError(f"unknown metric: {metric!r}")
        if isinstance(n, bool) or not isinstance(n, int):
            raise TypeError(f"metric increment must be int, got {type(n).__name__}")
        with self._lock:
            scope = self._counters.get(scope_id)
            if scope is None:
                scope = {}
                self._counters[scope_id] = scope
            scope[resolved] = scope.get(resolved, 0) + n

    def snapshot(self, scope_id: str) -> dict[str, int]:
        """Return a fixed-shape ``{metric_name: count}`` for ``scope_id`` (FR-046).

        Every metric in the vocabulary is present; counters never recorded read as
        ``0``. An unseen scope yields an all-zero snapshot. The returned dict is a
        copy of integers only -- it carries no raw values or PII.
        """
        with self._lock:
            scope = self._counters.get(scope_id, {})
            return {m.value: int(scope.get(m, 0)) for m in _METRIC_ORDER}

    def snapshot_all(self) -> dict[str, dict[str, int]]:
        """Return ``{scope_id: snapshot}`` for every known scope (FR-046).

        Each per-scope value is a fixed-shape, numeric-only snapshot. Scopes that
        have never been recorded against are absent from the mapping.
        """
        with self._lock:
            scope_ids = list(self._counters)
        return {scope_id: self.snapshot(scope_id) for scope_id in scope_ids}
