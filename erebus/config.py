import json
import os
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

GLOBAL_CONFIG_PATH = Path.home() / ".erebus" / "config.json"
REPO_CONFIG_FILENAME = ".erebus/pii-filter.json"
LEGACY_REPO_CONFIG_FILENAME = ".claude/pii-filter.json"
GLOBAL_BLACKLIST_PATH = Path.home() / ".erebus" / "blacklist.txt"
REPO_BLACKLIST_FILENAME = ".erebus/blacklist.txt"
DB_PATH = Path.home() / ".erebus" / "log.db"
TOKEN_MAP_PATH = Path.home() / ".erebus" / "token_map.json"
OLLAMA_MODEL = "ministral-3:3b"

# How long entries in the persisted token map survive before being rotated out.
# The file is the reverse map from tokens back to real values — the single most
# sensitive artifact Erebus writes to disk, so we cap its age.
TOKEN_MAP_MAX_AGE_DAYS = 7


def secure_path(path: Path, mode: int = 0o600) -> None:
    """Restrict permissions on a sensitive file or directory.

    Silent no-op on Windows or if the path is gone — hardening is best-effort.
    Applied to the log DB, token map, blacklist files, and ~/.erebus/ itself so
    other local users on a shared machine can't read tokenized data at rest.
    """
    try:
        path.chmod(mode)
    except (FileNotFoundError, OSError, NotImplementedError):
        pass


def ensure_erebus_dir() -> Path:
    """Create ~/.erebus/ with 0700 perms and return its path."""
    d = Path.home() / ".erebus"
    d.mkdir(parents=True, exist_ok=True)
    secure_path(d, 0o700)
    return d


def load_token_map(max_age_days: int = TOKEN_MAP_MAX_AGE_DAYS) -> dict:
    """Read the persisted token map, dropping it if it's past its age limit.

    File format is versioned — v2 wraps the flat map with a created_at timestamp
    so we can age-rotate it. v1 (legacy flat dict) is tolerated on read and
    upgraded on the next write.

    Returns a flat {token: value} dict. If the file is expired, wipes it and
    returns {} — any in-flight tokens in memory continue to work for the
    current session; they just no longer leak to disk for future sessions.
    """
    if not TOKEN_MAP_PATH.exists():
        return {}
    try:
        data = json.loads(TOKEN_MAP_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}

    # v2 format
    if isinstance(data, dict) and "entries" in data and "created_at" in data:
        try:
            created = datetime.fromisoformat(data["created_at"])
        except ValueError:
            created = datetime.now(timezone.utc)
        if datetime.now(timezone.utc) - created > timedelta(days=max_age_days):
            TOKEN_MAP_PATH.unlink(missing_ok=True)
            return {}
        entries = data.get("entries") or {}
        return entries if isinstance(entries, dict) else {}

    # v1 format (legacy flat dict) — treat as expired if file is old enough on
    # disk, otherwise pass through and let the next write upgrade it.
    if isinstance(data, dict):
        try:
            mtime = datetime.fromtimestamp(TOKEN_MAP_PATH.stat().st_mtime, tz=timezone.utc)
            if datetime.now(timezone.utc) - mtime > timedelta(days=max_age_days):
                TOKEN_MAP_PATH.unlink(missing_ok=True)
                return {}
        except OSError:
            pass
        return data
    return {}


def save_token_map(tokens: dict, max_age_days: int = TOKEN_MAP_MAX_AGE_DAYS) -> None:
    """Write the token map in v2 format with age rotation.

    If the existing file is past its age limit, the created_at timestamp resets
    so the fresh entries start a new window. Otherwise the original window is
    preserved — that prevents writers from "renewing" an old file forever and
    keeps the max-age guarantee honest.
    """
    ensure_erebus_dir()
    created_at = datetime.now(timezone.utc).isoformat()
    if TOKEN_MAP_PATH.exists():
        try:
            existing = json.loads(TOKEN_MAP_PATH.read_text(encoding="utf-8"))
            if isinstance(existing, dict) and "created_at" in existing:
                prev = datetime.fromisoformat(existing["created_at"])
                if datetime.now(timezone.utc) - prev <= timedelta(days=max_age_days):
                    created_at = existing["created_at"]
        except (json.JSONDecodeError, OSError, ValueError):
            pass
    payload = {"version": 2, "created_at": created_at, "entries": tokens}
    TOKEN_MAP_PATH.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    secure_path(TOKEN_MAP_PATH, 0o600)


def _load_blacklist_file(path: Path) -> list[str]:
    """Read a blacklist file — one term per line, '#' comments and blank lines skipped."""
    if not path.exists():
        return []
    terms = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            terms.append(line)
    return terms


def _find_real_claude() -> str:
    """Find the real Claude binary (claude-real), not the shim."""
    # 1. Check saved config from install step
    if GLOBAL_CONFIG_PATH.exists():
        try:
            with open(GLOBAL_CONFIG_PATH) as f:
                cfg = json.load(f)
            if cfg.get("real_binary") and Path(cfg["real_binary"]).exists():
                return cfg["real_binary"]
        except (json.JSONDecodeError, KeyError):
            pass
    # 2. Look for claude-real next to the symlink target
    homebrew_bin = Path("/opt/homebrew/bin/claude")
    if homebrew_bin.exists():
        resolved = homebrew_bin.resolve().parent
        real = resolved / "claude-real"
        if real.exists():
            return str(real)
    # 3. Search PATH for claude-real
    found = shutil.which("claude-real")
    if found:
        return found
    return None


def get_real_claude_binary() -> str:
    """Get the real Claude binary path, raising if not found."""
    result = _find_real_claude()
    if result is None:
        raise FileNotFoundError("Could not find claude-real binary. Run erebus-setup first.")
    return result


# Lazy — only crashes when actually needed (shim), not on import (logger, proxy, etc.)
REAL_CLAUDE_BINARY = _find_real_claude()

@dataclass
class RepoConfig:
    sensitive_entities: list[str] = field(default_factory=list)
    allowed_names: list[str] = field(default_factory=list)  # never tokenize these values
    context: str = ""
    block_file_patterns: list[str] = field(default_factory=list)  # e.g. ["**/contracts/**", "**/.env*"]
    log_enabled: bool = True
    mode: str = "balanced"  # strict | balanced | relaxed
    blacklist: list[str] = field(default_factory=list)  # hard-blocked terms (merged global + repo)


# Patterns forced into block_file_patterns so the blacklist files themselves
# can never be surfaced to the AI via a file-read tool.
_BLACKLIST_BLOCK_PATTERNS = [
    "**/.erebus/blacklist.txt",
    ".erebus/blacklist.txt",
    "blacklist.txt",
    str(GLOBAL_BLACKLIST_PATH),
]


def load_repo_config(cwd: Optional[str] = None) -> RepoConfig:
    """Load per-repo config from .erebus/pii-filter.json (falls back to .claude/pii-filter.json).

    Also merges the global blacklist (~/.erebus/blacklist.txt) with the repo-level
    one (.erebus/blacklist.txt) and adds both files to block_file_patterns so they
    cannot be read by the AI.
    """
    search_dir = Path(cwd) if cwd else Path.cwd()
    config_path = search_dir / REPO_CONFIG_FILENAME
    if not config_path.exists():
        config_path = search_dir / LEGACY_REPO_CONFIG_FILENAME
    if config_path.exists():
        with open(config_path) as f:
            data = json.load(f)
        cfg = RepoConfig(**{k: v for k, v in data.items() if k in RepoConfig.__dataclass_fields__})
    else:
        cfg = RepoConfig()

    blacklist_terms = _load_blacklist_file(GLOBAL_BLACKLIST_PATH)
    blacklist_terms += _load_blacklist_file(search_dir / REPO_BLACKLIST_FILENAME)
    # De-duplicate while preserving order
    seen = set()
    cfg.blacklist = [t for t in blacklist_terms if not (t in seen or seen.add(t))]

    for pat in _BLACKLIST_BLOCK_PATTERNS:
        if pat not in cfg.block_file_patterns:
            cfg.block_file_patterns.append(pat)

    return cfg
