import json
import os
import shutil
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

GLOBAL_CONFIG_PATH = Path.home() / ".erebus" / "config.json"
REPO_CONFIG_FILENAME = ".erebus/pii-filter.json"
LEGACY_REPO_CONFIG_FILENAME = ".claude/pii-filter.json"
DB_PATH = Path.home() / ".erebus" / "log.db"
OLLAMA_MODEL = "ministral-3:3b"


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

def load_repo_config(cwd: Optional[str] = None) -> RepoConfig:
    """Load per-repo config from .erebus/pii-filter.json (falls back to .claude/pii-filter.json)."""
    search_dir = Path(cwd) if cwd else Path.cwd()
    config_path = search_dir / REPO_CONFIG_FILENAME
    if not config_path.exists():
        config_path = search_dir / LEGACY_REPO_CONFIG_FILENAME
    if config_path.exists():
        with open(config_path) as f:
            data = json.load(f)
        return RepoConfig(**{k: v for k, v in data.items() if k in RepoConfig.__dataclass_fields__})
    return RepoConfig()
