"""
Editor-specific installation and configuration.
"""

import shutil
import os
import stat
import json
from pathlib import Path
from ..ui.colors import ok, fail, warn, info, dl, bold


PROXY_PORT = 4747
PROXY_NOTICE = f"http://localhost:{PROXY_PORT}"

SHIM = """#!/bin/bash
# erebus shim — auto-generated, do not edit
# Real binary: {real_binary}
exec {wrapper_binary} "$@"
"""


# ── Claude Code ──────────────────────────────────────────────────────────────

def install_claude():
    claude = shutil.which("claude")
    if not claude:
        print(fail("`claude` not found in PATH — skipping"))
        return

    claude_path = Path(claude).resolve()
    if "erebus" in str(claude_path):
        print(ok("Claude Code already wrapped"))
        return

    real_path = claude_path.parent / "claude-real"
    if real_path.exists():
        print(ok(f"Claude Code already wrapped (real binary: {real_path})"))
        return

    # Prefer the uv tools path (has correct Python env); fall back to PATH lookup
    uv_tools_path = Path.home() / ".local" / "share" / "uv" / "tools" / "erebus" / "bin" / "erebus"
    if uv_tools_path.exists():
        wrapper_binary = str(uv_tools_path)
    else:
        wrapper_binary = shutil.which("erebus") or "erebus"
    claude_path.rename(real_path)
    shim = SHIM.format(real_binary=real_path, wrapper_binary=wrapper_binary)
    claude_path.write_text(shim)
    claude_path.chmod(claude_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    _update_config(str(real_path))
    print(ok(f"Claude Code wrapped — shim at {claude_path}"))


def uninstall_claude():
    claude = shutil.which("claude")
    if not claude:
        return
    claude_path = Path(claude).resolve()
    real_path = claude_path.parent / "claude-real"
    if real_path.exists():
        claude_path.unlink()
        real_path.rename(claude_path)
        print(ok("Claude Code restored"))


# ── Proxy-based editors (Cursor, Windsurf, Vibe, Codex) ──────────────────────

EDITOR_CONFIGS = {
    "cursor": {
        "name": "Cursor",
        "settings_paths": [
            Path.home() / ".cursor" / "settings.json",
            Path.home() / "Library" / "Application Support" / "Cursor" / "User" / "settings.json",
        ],
        "key": "cursor.anthropicBaseUrl",
        "env_var": "ANTHROPIC_BASE_URL",
    },
    "windsurf": {
        "name": "Windsurf",
        "settings_paths": [
            Path.home() / ".codeium" / "windsurf" / "settings.json",
            Path.home() / "Library" / "Application Support" / "Windsurf" / "User" / "settings.json",
        ],
        "key": "windsurf.anthropicBaseUrl",
        "env_var": "ANTHROPIC_BASE_URL",
    },
    # Vibe is handled separately (TOML config, not JSON)
    # "vibe" is NOT in EDITOR_CONFIGS — see install_vibe() / uninstall_vibe()
    "codex": {
        "name": "OpenAI Codex",
        "settings_paths": [
            Path.home() / ".codex" / "config.json",
        ],
        "key": "apiBaseUrl",
        "env_var": "OPENAI_BASE_URL",
    },
}


def install_editor(editor_key: str):
    cfg = EDITOR_CONFIGS[editor_key]
    name = cfg["name"]

    settings_path = None
    for p in cfg["settings_paths"]:
        if p.exists():
            settings_path = p
            break

    if not settings_path:
        settings_path = cfg["settings_paths"][0]
        settings_path.parent.mkdir(parents=True, exist_ok=True)
        settings_path.write_text("{}\n")

    try:
        data = json.loads(settings_path.read_text())
    except Exception:
        data = {}

    data[cfg["key"]] = PROXY_NOTICE
    settings_path.write_text(json.dumps(data, indent=2) + "\n")
    print(ok(f"{name} -> set {cfg['key']} = {PROXY_NOTICE}"))
    print(f"         add to shell profile: export {cfg['env_var']}={PROXY_NOTICE}")


def uninstall_editor(editor_key: str):
    cfg = EDITOR_CONFIGS[editor_key]
    for p in cfg["settings_paths"]:
        if p.exists():
            try:
                data = json.loads(p.read_text())
                data.pop(cfg["key"], None)
                p.write_text(json.dumps(data, indent=2) + "\n")
                print(ok(f"{cfg['name']} proxy removed from {p}"))
            except Exception as e:
                print(fail(f"Could not update {p}: {e}"))


# ── Mistral Vibe (TOML config) ───────────────────────────────────────────────

VIBE_CONFIG = Path.home() / ".vibe" / "config.toml"
VIBE_ORIGINAL_API_BASE = "https://api.mistral.ai/v1"


EREBUS_PROVIDER_BLOCK = f"""
# ── Erebus PII proxy ──────────────────────────────────────────────────────────
# Added by `erebus-setup --editor vibe`. Remove with `erebus-uninstall --editor vibe`.
[[providers]]
name = "erebus"
api_base = "{PROXY_NOTICE}/v1"
api_key_env_var = "MISTRAL_API_KEY"
backend = "mistral"
"""

EREBUS_MODELS_BLOCK = """
# Erebus-proxied models — same as direct Mistral but routed through PII filter.
# Switch with: active_model = "devstral-2-safe"
[[models]]
name = "devstral-2512"
provider = "erebus"
alias = "devstral-2-safe"
temperature = 0.1
input_price = 0.4
output_price = 2.0
"""

EREBUS_MARKER = "# ── Erebus PII proxy"


def install_vibe():
    """Add an Erebus proxy provider + models to Vibe config (keeps original intact)."""
    if not VIBE_CONFIG.exists():
        print(warn("Mistral Vibe config not found (~/.vibe/config.toml) — skipping"))
        print(f"         Install Vibe first, then run `erebus-setup --editor vibe`")
        return

    content = VIBE_CONFIG.read_text()

    if EREBUS_MARKER in content or 'name = "erebus"' in content:
        print(ok("Mistral Vibe already has Erebus provider"))
        return

    # Append provider and models at the end
    new_content = content.rstrip() + "\n" + EREBUS_PROVIDER_BLOCK + EREBUS_MODELS_BLOCK
    VIBE_CONFIG.write_text(new_content)
    print(ok(f"Mistral Vibe -> added 'erebus' provider ({PROXY_NOTICE})"))
    print(f"         Switch to filtered mode: active_model = \"devstral-2-safe\"")
    print(f"         Switch to direct mode:   active_model = \"devstral-2\"")


def uninstall_vibe():
    """Remove the Erebus provider and models from Vibe config."""
    if not VIBE_CONFIG.exists():
        return

    content = VIBE_CONFIG.read_text()
    if EREBUS_MARKER not in content:
        return

    # Remove everything from the marker to the end of the Erebus blocks
    import re
    new_content = re.sub(
        r'\n*# ── Erebus PII proxy.*?(?=\n# ──|\n\[(?!tools\.|models\b|\[providers\]\]|\[models\]\])|\Z)',
        '',
        content,
        flags=re.DOTALL,
    )
    # Also remove the erebus model blocks
    new_content = re.sub(
        r'\n*# Erebus-proxied models.*?(?=\n# |\n\[(?!\[)|\Z)',
        '',
        new_content,
        flags=re.DOTALL,
    )
    VIBE_CONFIG.write_text(new_content.rstrip() + "\n")
    print(ok("Mistral Vibe -> removed Erebus provider and models"))


# ── Dependencies ─────────────────────────────────────────────────────────────

def install_dependencies():
    """Pre-warm GLiNER model and verify Ollama is running."""
    print(bold("\nInstalling dependencies...\n"))

    # GLiNER model warm-up (downloads from HuggingFace on first use)
    try:
        from gliner import GLiNER
        print(dl("Loading GLiNER model urchade/gliner_multi_pii-v1 (downloads on first run)..."))
        GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")
        print(ok("GLiNER model ready"))
    except ImportError:
        print(warn("gliner not installed — PII detection will use regex-only mode"))
        print(f"    Install manually: uv tool install --reinstall .")
    except Exception as e:
        print(warn(f"GLiNER model load failed: {e}"))

    # Ollama check
    try:
        import ollama
        from ..config import OLLAMA_MODEL
        models = [m.model for m in ollama.list().models]
        if OLLAMA_MODEL in models:
            print(ok(f"Ollama model {OLLAMA_MODEL} ready"))
        else:
            print(dl(f"Pulling Ollama model {OLLAMA_MODEL}..."))
            import subprocess
            subprocess.run(["ollama", "pull", OLLAMA_MODEL], check=True)
            print(ok(f"{OLLAMA_MODEL} pulled"))
    except Exception as e:
        print(warn(f"Ollama check failed (is Ollama running?): {e}"))
        print(f"    Run manually: ollama pull ministral-3:3b")


def _update_config(real_binary_path: str):
    """Save the real binary path to ~/.erebus/config.json."""
    from ..config import GLOBAL_CONFIG_PATH
    GLOBAL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    cfg = {}
    if GLOBAL_CONFIG_PATH.exists():
        try:
            cfg = json.loads(GLOBAL_CONFIG_PATH.read_text())
        except Exception:
            pass
    cfg["real_binary"] = real_binary_path
    GLOBAL_CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")
    print(ok(f"Saved real binary path -> {real_binary_path}"))
