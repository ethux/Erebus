from __future__ import annotations

import json
import os
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .config import ensure_erebus_dir, secure_path

PERF_LOG_PATH = Path.home() / ".erebus" / "perf.jsonl"
PERF_LOG_MAX_BYTES = 8 * 1024 * 1024


class PerfTimer:
    """Measure wall time and process CPU time for a small operation."""

    def __init__(self):
        self.wall_start = time.perf_counter()
        self.cpu_start = time.process_time()

    def finish(self) -> dict[str, float]:
        wall = max(time.perf_counter() - self.wall_start, 0.0)
        cpu = max(time.process_time() - self.cpu_start, 0.0)
        return {
            "wall_ms": round(wall * 1000, 3),
            "cpu_ms": round(cpu * 1000, 3),
            "cpu_pct": round((cpu / wall) * 100, 1) if wall else 0.0,
        }


def perf_enabled() -> bool:
    return os.environ.get("EREBUS_PERF_LOG", "1").lower() not in {"0", "false", "no", "off"}


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def rotate_perf_log_if_needed(path: Path | None = None) -> None:
    if path is None:
        path = PERF_LOG_PATH
    try:
        if path.exists() and path.stat().st_size > PERF_LOG_MAX_BYTES:
            path.replace(path.with_suffix(path.suffix + ".1"))
    except OSError:
        pass


def log_perf_event(event: str, **metadata: Any) -> None:
    """Append a privacy-safe performance event.

    Never pass raw prompts, model responses, or token maps here. Only record
    counts, durations, cache status, process IDs, and short cache-key hashes.
    """
    if not perf_enabled():
        return
    try:
        ensure_erebus_dir()
        rotate_perf_log_if_needed(PERF_LOG_PATH)
        payload = {
            "ts": time.time(),
            "event": event,
            "pid": os.getpid(),
            **metadata,
        }
        with PERF_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
        secure_path(PERF_LOG_PATH, 0o600)
    except Exception:
        pass


def read_perf_events(limit: int | None = None, path: Path | None = None) -> list[dict[str, Any]]:
    if path is None:
        path = PERF_LOG_PATH
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    if limit is not None:
        lines = lines[-limit:]
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(event, dict):
            events.append(event)
    return events


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    idx = min(len(values) - 1, int(len(values) * q))
    return values[idx]


def perf_summary(limit: int = 2000) -> None:  # noqa: C901
    events = read_perf_events(limit=limit)
    if not events:
        print("No performance events recorded yet.")
        return

    by_event: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        by_event[str(event.get("event", "unknown"))].append(event)

    print(f"\n{'=' * 70}")
    print(f"  erebus -- performance telemetry (last {len(events):,} events)")
    print(f"{'=' * 70}\n")

    for event_name in sorted(by_event):
        rows = by_event[event_name]
        walls = [float(row.get("wall_ms", 0) or 0) for row in rows if row.get("wall_ms") is not None]
        cpus = [float(row.get("cpu_pct", 0) or 0) for row in rows if row.get("cpu_pct") is not None]
        print(f"  {event_name}")
        print(f"    events:       {len(rows):>8,}")
        if walls:
            print(f"    wall avg/p95: {sum(walls) / len(walls):>8.1f} / {percentile(walls, 0.95):>8.1f} ms")
        if cpus:
            print(f"    CPU avg/max:  {sum(cpus) / len(cpus):>8.1f}% / {max(cpus):>8.1f}%")

        cache_counts = Counter()
        for row in rows:
            if row.get("cache_result"):
                cache_counts[str(row.get("cache_result"))] += 1
            nested_counts = row.get("cache_counts")
            if isinstance(nested_counts, dict):
                for key, value in nested_counts.items():
                    cache_counts[str(key)] += safe_int(value)
        if cache_counts:
            print("    cache:        " + "  ".join(f"{k}={v:,}" for k, v in cache_counts.most_common()))

        stored_counts = Counter(str(row.get("stored")) for row in rows if row.get("stored"))
        if stored_counts:
            print("    stored:       " + "  ".join(f"{k}={v:,}" for k, v in stored_counts.most_common()))

        reason_counts = Counter(str(row.get("reason")) for row in rows if row.get("reason"))
        if reason_counts:
            print("    reasons:      " + "  ".join(f"{k}={v:,}" for k, v in reason_counts.most_common()))

        text_count = sum(safe_int(row.get("text_count")) for row in rows)
        text_chars = sum(safe_int(row.get("text_chars")) for row in rows)
        if text_count or text_chars:
            print(f"    text:         count={text_count:,}  chars={text_chars:,}")
        print()

    top = sorted(
        [row for row in events if row.get("cpu_pct") is not None],
        key=lambda row: float(row.get("cpu_pct", 0) or 0),
        reverse=True,
    )[:10]
    if top:
        print("  Top CPU samples:")
        for row in top:
            print(
                "    "
                f"{row.get('event')} "
                f"cpu={float(row.get('cpu_pct', 0) or 0):.1f}% "
                f"wall={float(row.get('wall_ms', 0) or 0):.1f}ms "
                f"cache={row.get('cache_result', '-')}"
            )
        print()
