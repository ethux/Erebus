"""Per-tenant masked-telemetry metrics unit tests (FR-046).

Pure logic, no database. Verifies per-scope isolation of counters, fixed-shape
all-numeric snapshots, that only members of the closed metric vocabulary are
recordable, and that the registry stores integer counts only -- never strings,
raw values, or any other PII (telemetry is masked to counts).
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway.observability import Metric, Metrics

_passed = 0

SCOPE_A = "11111111-1111-1111-1111-111111111111"
SCOPE_B = "22222222-2222-2222-2222-222222222222"

_ALL_METRICS = {m.value for m in Metric}


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def main():
    print("\n=== Gateway observability masked telemetry (FR-046) ===\n")

    m = Metrics()

    # Unseen scope yields an all-zero, fixed-shape snapshot.
    snap_empty = m.snapshot(SCOPE_A)
    check("unseen scope snapshot has the full metric vocabulary",
          set(snap_empty) == _ALL_METRICS)
    check("unseen scope snapshot is all zeros", set(snap_empty.values()) == {0})
    check("snapshot_all empty before any record", m.snapshot_all() == {})

    # Record across two scopes with distinct values per metric.
    m.record(SCOPE_A, Metric.REQUESTS, 3)
    m.record(SCOPE_A, "tokenized_count", 5)  # string-keyed API works like enum
    m.record(SCOPE_A, Metric.REQUESTS)  # default n=1 accumulates -> 4
    m.record(SCOPE_A, Metric.ESCAPES, 0)  # quality counter, stays observable
    m.record(SCOPE_B, Metric.REVEALS, 2)
    m.record(SCOPE_B, Metric.QUOTA_REJECTIONS, 7)

    snap_a = m.snapshot(SCOPE_A)
    snap_b = m.snapshot(SCOPE_B)

    # Per-scope counter isolation: A's writes never leak into B and vice versa.
    check("scope A requests accumulated to 4", snap_a["requests"] == 4)
    check("scope A tokenized_count is 5", snap_a["tokenized_count"] == 5)
    check("scope B reveals is 2", snap_b["reveals"] == 2)
    check("scope B quota_rejections is 7", snap_b["quota_rejections"] == 7)
    check("scope A did not see scope B reveals", snap_a["reveals"] == 0)
    check("scope A did not see scope B quota_rejections", snap_a["quota_rejections"] == 0)
    check("scope B did not see scope A requests", snap_b["requests"] == 0)
    check("scope B did not see scope A tokenized_count", snap_b["tokenized_count"] == 0)

    # Snapshot shape is fixed and complete for every scope.
    check("scope A snapshot has full vocabulary", set(snap_a) == _ALL_METRICS)
    check("scope B snapshot has full vocabulary", set(snap_b) == _ALL_METRICS)

    # Only numeric counters are stored -- no strings/PII anywhere in telemetry.
    for scope_id, snap in m.snapshot_all().items():
        check(f"{scope_id[:8]} keys are all known metric names",
              set(snap) <= _ALL_METRICS)
        check(f"{scope_id[:8]} every value is a non-bool int",
              all(type(v) is int for v in snap.values()))
    check("snapshot_all lists exactly the recorded scopes",
          set(m.snapshot_all()) == {SCOPE_A, SCOPE_B})

    # Negative increments allowed for corrections; result stays an int.
    m.record(SCOPE_A, Metric.REQUESTS, -1)
    check("negative increment corrects the counter", m.snapshot(SCOPE_A)["requests"] == 3)

    # Closed vocabulary: unknown metric names are rejected, never stored.
    rejected = False
    try:
        m.record(SCOPE_A, "secret_user_email")
    except KeyError:
        rejected = True
    check("unknown metric name rejected (KeyError)", rejected)
    check("rejected metric did not appear in snapshot",
          "secret_user_email" not in m.snapshot(SCOPE_A))

    # Only integer increments accepted -- a raw string value can never be stored.
    type_rejected = False
    try:
        m.record(SCOPE_A, Metric.REQUESTS, "alice@example.com")  # type: ignore[arg-type]
    except TypeError:
        type_rejected = True
    check("non-int increment rejected (TypeError)", type_rejected)

    bool_rejected = False
    try:
        m.record(SCOPE_A, Metric.REQUESTS, True)  # type: ignore[arg-type]
    except TypeError:
        bool_rejected = True
    check("bool increment rejected (not a count)", bool_rejected)

    # Snapshots are copies: mutating a snapshot cannot corrupt the registry.
    snap_a2 = m.snapshot(SCOPE_A)
    snap_a2["requests"] = 9999
    check("snapshot is a defensive copy", m.snapshot(SCOPE_A)["requests"] == 3)

    # Independent registries do not share state (no process-global mutable state).
    other = Metrics()
    check("fresh registry sees no prior scopes", other.snapshot_all() == {})

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
