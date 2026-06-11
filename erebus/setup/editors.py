"""
Editor-specific installation and configuration.
"""

import json
import re
import shutil
import stat
import tomllib
from pathlib import Path

from ..ui.colors import bold, dl, fail, info, ok, warn

PROXY_PORT = 4747
PROXY_NOTICE = f"http://localhost:{PROXY_PORT}"
CODEX_PROXY_PORT = 4748
CODEX_PROXY_NOTICE = f"http://127.0.0.1:{CODEX_PROXY_PORT}"
CODEX_CONFIG = Path.home() / ".codex" / "config.toml"
CODEX_PROVIDER_ID = "erebus-openai"
CODEX_MARKER_START = "# ── Erebus Codex PII proxy"
CODEX_MARKER_END = "# ── End Erebus Codex PII proxy"

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
    if uv_tools_path.exists():  # noqa: SIM108
        wrapper_binary = str(uv_tools_path)
    else:
        wrapper_binary = shutil.which("erebus") or "erebus"
    claude_path.rename(real_path)
    shim = SHIM.format(real_binary=real_path, wrapper_binary=wrapper_binary)
    claude_path.write_text(shim)
    claude_path.chmod(claude_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    _update_binary_config("real_binary", str(real_path))
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


# ── Codex ────────────────────────────────────────────────────────────────────

def _find_codex_wrapper_binary() -> str:
    uv_path = Path.home() / ".local" / "share" / "uv" / "tools" / "erebus" / "bin" / "erebus-codex"
    if uv_path.exists():
        return str(uv_path)
    return shutil.which("erebus-codex") or "erebus-codex"


def _install_binary_wrapper(binary_name: str, wrapper_binary: str) -> Path | None:
    binary = shutil.which(binary_name)
    if not binary:
        print(fail(f"`{binary_name}` not found in PATH — skipping"))
        return None

    binary_path = Path(binary).resolve()
    real_path = binary_path.parent / f"{binary_name}-real"
    if real_path.exists():
        print(ok(f"{binary_name} already wrapped (real binary: {real_path})"))
        return real_path

    binary_path.rename(real_path)
    shim = SHIM.format(real_binary=real_path, wrapper_binary=wrapper_binary)
    binary_path.write_text(shim)
    binary_path.chmod(binary_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    print(ok(f"{binary_name} wrapped — shim at {binary_path}"))
    return real_path


def _uninstall_binary_wrapper(binary_name: str):
    binary = shutil.which(binary_name)
    if not binary:
        return
    binary_path = Path(binary).resolve()
    real_path = binary_path.parent / f"{binary_name}-real"
    if real_path.exists():
        binary_path.unlink()
        real_path.rename(binary_path)
        print(ok(f"{binary_name} restored"))


def _root_table_end(lines: list[str]) -> int:
    for i, line in enumerate(lines):
        if re.match(r"\s*\[", line):
            return i
    return len(lines)


def _find_root_key(lines: list[str], key: str) -> int | None:
    for i in range(_root_table_end(lines)):
        if re.match(rf"\s*{re.escape(key)}\s*=", lines[i]):
            return i
    return None


def _remove_codex_provider_block(content: str) -> str:
    pattern = rf"\n?{re.escape(CODEX_MARKER_START)}.*?{re.escape(CODEX_MARKER_END)}[^\n]*\n?"
    return re.sub(pattern, "\n", content, flags=re.DOTALL).strip() + "\n"


def _set_codex_model_provider(content: str) -> tuple[str, dict]:
    lines = content.splitlines()
    idx = _find_root_key(lines, "model_provider")
    state = {"had_model_provider": idx is not None, "model_provider_line": lines[idx] if idx is not None else None}
    new_line = f'model_provider = "{CODEX_PROVIDER_ID}"'
    if idx is not None:
        lines[idx] = new_line
    else:
        lines.insert(_root_table_end(lines), new_line)
    return "\n".join(lines).rstrip() + "\n", state


def _restore_codex_model_provider(content: str, state: dict | None) -> str:
    lines = content.splitlines()
    idx = _find_root_key(lines, "model_provider")
    previous = (state or {}).get("model_provider_line")
    had_previous = bool((state or {}).get("had_model_provider"))
    if idx is None:
        if had_previous and previous:
            lines.insert(_root_table_end(lines), previous)
    elif had_previous and previous:
        lines[idx] = previous
    elif re.match(rf'\s*model_provider\s*=\s*"{re.escape(CODEX_PROVIDER_ID)}"\s*$', lines[idx]):
        lines.pop(idx)
    return "\n".join(lines).rstrip() + "\n"


def _codex_provider_block() -> str:
    return f"""
{CODEX_MARKER_START} ─────────────────────────────────────────────────────────
# Added by `erebus-setup --editor codex`. Remove with `erebus-uninstall --editor codex`.
[model_providers.{CODEX_PROVIDER_ID}]
name = "OpenAI via Erebus"
base_url = "{CODEX_PROXY_NOTICE}"
requires_openai_auth = true
supports_websockets = false
wire_api = "responses"
{CODEX_MARKER_END} ─────────────────────────────────────────────────────
"""


def _apply_codex_config(content: str) -> tuple[str, dict]:
    content = _remove_codex_provider_block(content)
    content, state = _set_codex_model_provider(content)
    content = content.rstrip() + "\n" + _codex_provider_block()
    tomllib.loads(content)
    return content, state


def _remove_codex_config(content: str, state: dict | None = None) -> str:
    content = _remove_codex_provider_block(content)
    content = _restore_codex_model_provider(content, state)
    tomllib.loads(content)
    return content


def _load_setup_config() -> dict:
    from ..config import GLOBAL_CONFIG_PATH
    if not GLOBAL_CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(GLOBAL_CONFIG_PATH.read_text())
    except Exception:
        return {}


def install_codex():
    wrapper_binary = _find_codex_wrapper_binary()
    real_path = _install_binary_wrapper("codex", wrapper_binary)
    if real_path:
        _update_binary_config("real_codex_binary", str(real_path))

    CODEX_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    content = CODEX_CONFIG.read_text() if CODEX_CONFIG.exists() else ""
    try:
        new_content, state = _apply_codex_config(content)
    except tomllib.TOMLDecodeError as e:
        print(fail(f"Could not update Codex config.toml: {e}"))
        return

    cfg = _load_setup_config()
    cfg["codex_config_state"] = state
    _write_setup_config(cfg)
    CODEX_CONFIG.write_text(new_content)
    print(ok(f"Codex -> added {CODEX_PROVIDER_ID} provider ({CODEX_PROXY_NOTICE})"))
    print(info("Codex keeps using ~/.codex/auth.json via requires_openai_auth = true"))


def uninstall_codex():
    _uninstall_binary_wrapper("codex")
    if CODEX_CONFIG.exists():
        cfg = _load_setup_config()
        try:
            content = _remove_codex_config(
                CODEX_CONFIG.read_text(),
                cfg.get("codex_config_state"),
            )
            CODEX_CONFIG.write_text(content)
            print(ok(f"Codex proxy config removed from {CODEX_CONFIG}"))
        except tomllib.TOMLDecodeError as e:
            print(fail(f"Could not update Codex config.toml: {e}"))


# ── Proxy-based editors (Cursor, Windsurf) ───────────────────────────────────

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
    # Vibe and Codex are handled separately (TOML config, not JSON).
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
        print("         Install Vibe first, then run `erebus-setup --editor vibe`")
        return

    content = VIBE_CONFIG.read_text()

    if EREBUS_MARKER in content or 'name = "erebus"' in content:
        print(ok("Mistral Vibe already has Erebus provider"))
        return

    # Append provider and models at the end
    new_content = content.rstrip() + "\n" + EREBUS_PROVIDER_BLOCK + EREBUS_MODELS_BLOCK
    VIBE_CONFIG.write_text(new_content)
    print(ok(f"Mistral Vibe -> added 'erebus' provider ({PROXY_NOTICE})"))
    print("         Switch to filtered mode: active_model = \"devstral-2-safe\"")
    print("         Switch to direct mode:   active_model = \"devstral-2\"")


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
        print("    Install manually: uv tool install . --force")
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
        print("    Run manually: ollama pull ministral-3:3b")


def _write_setup_config(cfg: dict):
    from ..config import GLOBAL_CONFIG_PATH
    GLOBAL_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    GLOBAL_CONFIG_PATH.write_text(json.dumps(cfg, indent=2) + "\n")


def _update_binary_config(key: str, real_binary_path: str):
    """Save a wrapped real binary path to ~/.erebus/config.json."""
    from ..config import GLOBAL_CONFIG_PATH
    cfg = {}
    if GLOBAL_CONFIG_PATH.exists():
        try:
            cfg = json.loads(GLOBAL_CONFIG_PATH.read_text())
        except Exception:
            pass
    cfg[key] = real_binary_path
    _write_setup_config(cfg)
    print(ok(f"Saved real binary path -> {real_binary_path}"))
