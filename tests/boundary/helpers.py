"""Shared fixtures for the boundary gateway tests.

Rules these helpers enforce by construction (see README.md):
  * assertions run against real-world artifacts (disk bytes, executed args, DB rows)
  * all state is isolated in a temp HOME + temp project dir
  * time is injected, never slept on
"""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import tempfile
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

# Deliberate read-only copy of the canonical token shape (tests are audit-allowlisted).
TOKEN_RE = re.compile(r"\[(?:[A-Z_]+_\d+_[0-9a-f]{6,}|CATALOG_[A-Z0-9_]+_[0-9a-f]{6,})\]")


class IsolatedBoundaryHome:
    """Redirect every Erebus path to a temp home + temp project dir."""

    def __enter__(self):
        self.home = Path(tempfile.mkdtemp(prefix="erebus-boundary-home-"))
        self.project = Path(tempfile.mkdtemp(prefix="erebus-boundary-proj-"))
        (self.home / ".erebus").mkdir(parents=True, exist_ok=True)

        from erebus import config
        self._config = config
        self._orig = {
            "DB_PATH": config.DB_PATH,
            "TOKEN_MAP_PATH": config.TOKEN_MAP_PATH,
            "GLOBAL_CONFIG_PATH": config.GLOBAL_CONFIG_PATH,
            "GLOBAL_BLACKLIST_PATH": config.GLOBAL_BLACKLIST_PATH,
        }
        config.DB_PATH = self.home / ".erebus" / "log.db"
        config.TOKEN_MAP_PATH = self.home / ".erebus" / "token_map.json"
        config.GLOBAL_CONFIG_PATH = self.home / ".erebus" / "config.json"
        config.GLOBAL_BLACKLIST_PATH = self.home / ".erebus" / "blacklist.txt"

        from erebus.audit import logger
        self._logger = logger
        self._orig_logger_db = logger.DB_PATH
        logger.DB_PATH = config.DB_PATH

        self._home_patch = patch.object(Path, "home", return_value=self.home)
        self._home_patch.start()
        return self

    def __exit__(self, exc_type, exc, tb):
        self._home_patch.stop()
        for name, value in self._orig.items():
            setattr(self._config, name, value)
        self._logger.DB_PATH = self._orig_logger_db
        shutil.rmtree(self.home, ignore_errors=True)
        shutil.rmtree(self.project, ignore_errors=True)

    # -- factories -----------------------------------------------------------

    def global_db_path(self) -> Path:
        return self.home / ".erebus" / "known_values.db"

    def project_db_path(self) -> Path:
        return self.project / ".erebus" / "known_values.db"

    def legacy_map_path(self) -> Path:
        return self.home / ".erebus" / "token_map.json"

    def write_legacy_map(self, entries: dict, created_at: datetime | None = None) -> Path:
        created = (created_at or datetime.now(UTC)).isoformat()
        self.legacy_map_path().write_text(json.dumps(
            {"version": 2, "created_at": created, "entries": entries}))
        return self.legacy_map_path()

    def repo_config(self, **overrides):
        from erebus.config import RepoConfig
        cfg = RepoConfig()
        for key, value in overrides.items():
            setattr(cfg, key, value)
        return cfg

    def open_db(self, scope: str = "global"):
        from erebus.core.knownvalues import open_known_values
        cfg = self.repo_config(known_values_scope=scope)
        return open_known_values(cfg, str(self.project))


@contextmanager
def daemon_stub(mode: str = "up", entities_for=None):
    """Patch the GLiNER daemon client. Modes: 'up' (returns entities_for(text) or []),
    'down' (daemon unreachable -> degraded)."""
    try:
        from erebus.core import detect as det
    except ImportError:  # pre-P2: detection still lives in erebus.filter
        from erebus import filter as det

    if mode == "down":
        def single(_text):
            det._mark_detector_degraded("daemon_unavailable")
            return []

        def many(texts):
            det._mark_detector_degraded("daemon_unavailable")
            return [[] for _ in texts]
    else:
        finder = entities_for or (lambda _t: [])

        def single(text):
            return finder(text)

        def many(texts):
            return [finder(t) for t in texts]

    with patch.object(det, "_predict_entities", side_effect=single), \
         patch.object(det, "_predict_entities_many", side_effect=many):
        yield


@contextmanager
def fake_clock(start: datetime | None = None):
    """Inject a controllable clock into erebus.core.clock."""
    from erebus.core import clock

    class _Clock:
        def __init__(self, t0):
            self.current = t0
            self.mono = 1000.0

        def advance(self, **kw):
            delta = timedelta(**kw)
            self.current += delta
            self.mono += delta.total_seconds()

    ctl = _Clock(start or datetime(2026, 6, 10, 12, 0, 0, tzinfo=UTC))
    with patch.object(clock, "now", side_effect=lambda: ctl.current), \
         patch.object(clock, "monotonic", side_effect=lambda: ctl.mono):
        yield ctl


def person_entity(text: str, name: str) -> list[dict]:
    """Entity list marking every occurrence of `name` in `text` as a person."""
    spans = []
    start = 0
    while True:
        idx = text.find(name, start)
        if idx < 0:
            break
        spans.append({"start": idx, "end": idx + len(name), "label": "person", "text": name})
        start = idx + len(name)
    return spans


# -- artifact assertions (real-world side ONLY) ------------------------------

def assert_no_tokens_in_file(path: Path | str):
    raw = Path(path).read_text(encoding="utf-8")
    found = TOKEN_RE.findall(raw)
    assert not found, f"token(s) {found} present in real-world artifact {path}"


def assert_value_absent(payload, value: str):
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    assert value not in raw, "real value leaked into model-bound payload"


def assert_tokens_match(path: Path | str, expected: set[str]):
    raw = Path(path).read_text(encoding="utf-8")
    assert set(TOKEN_RE.findall(raw)) == expected


def run(tests, title: str):
    """Uniform __main__ runner matching the repo's test style."""
    print(f"\n=== {title} ===\n")
    for test in tests:
        test()
        print(f"  ✓ {test.__name__}")
    print(f"\n{len(tests)}/{len(tests)} passed")
