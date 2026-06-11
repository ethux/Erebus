"""
erebus setup

Wraps AI coding editor binaries/configs with the PII filter.
Supported editors:
  - Mistral Vibe (proxy provider in ~/.vibe/config.toml)
  - Cursor       (ANTHROPIC_BASE_URL proxy via ~/.cursor/settings.json)
  - Windsurf     (proxy via ~/.codeium/windsurf/settings.json)
  - Codex        (binary launcher + Responses API proxy via ~/.codex/config.toml)
  - Claude Code  (claude binary shim)

Run:    erebus-setup [--editor vibe|claude|cursor|windsurf|codex|all]
Undo:   erebus-uninstall [--editor ...]
"""

import argparse
import shutil
import subprocess as sp
import sys
from pathlib import Path

from ..runtime.daemon import stop_daemon
from ..ui.colors import bold, fail, info, ok, warn
from .editors import (
    EDITOR_CONFIGS,
    install_claude,
    install_codex,
    install_dependencies,
    install_editor,
    install_vibe,
    uninstall_claude,
    uninstall_codex,
    uninstall_editor,
    uninstall_vibe,
)
from .services import (
    install_openai_proxy_service,
    install_proxy_service,
    restart_proxy_services,
    uninstall_openai_proxy_service,
    uninstall_proxy_service,
)


def _parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--editor",
        nargs="+",
        choices=["claude", "cursor", "windsurf", "vibe", "codex", "all"],
        default=["claude"],
        help="Which editors to wrap (default: claude)",
    )
    return parser.parse_args()


def main_install():
    args = _parse_args()
    editors = list(EDITOR_CONFIGS.keys()) + ["claude", "vibe", "codex"] if "all" in args.editor else args.editor  # noqa: RUF005
    print(bold("\nerebus setup\n"))
    install_dependencies()
    print(bold("\nConfiguring editors...\n"))
    for editor in editors:
        if editor == "claude":
            install_claude()
        elif editor == "codex":
            install_codex()
        elif editor == "vibe":
            install_vibe()
        elif editor in EDITOR_CONFIGS:
            install_editor(editor)
    install_proxy_service()
    if "codex" in editors:
        install_openai_proxy_service()
    print(ok("\nDone. Run `erebus-uninstall` to remove."))
    print(info("Try it: erebus-log  (view activity log after first use)\n"))


def main_uninstall():
    args = _parse_args()
    editors = list(EDITOR_CONFIGS.keys()) + ["claude", "vibe", "codex"] if "all" in args.editor else args.editor  # noqa: RUF005
    print(bold("\nerebus uninstall\n"))
    for editor in editors:
        if editor == "claude":
            uninstall_claude()
        elif editor == "codex":
            uninstall_codex()
        elif editor == "vibe":
            uninstall_vibe()
        elif editor in EDITOR_CONFIGS:
            uninstall_editor(editor)
    if "codex" in editors:
        uninstall_openai_proxy_service()
    uninstall_proxy_service()
    print(ok("\nUninstalled.\n"))


def update_install_command(source: str | None, has_uv: bool) -> list[str]:
    """Return the package update command for the current installer."""
    if has_uv:
        if source:
            return ["uv", "tool", "install", "--force", source]
        return ["uv", "tool", "upgrade", "erebus", "--reinstall"]
    python = shutil.which("python3") or sys.executable
    package = source or "erebus"
    return [python, "-m", "pip", "install", "--upgrade", package]


def local_update_source_path(source: str | None) -> Path | None:
    """Return a local project directory for path-like update sources."""
    if not source:
        return None
    path = Path(source).expanduser()
    if not path.exists():
        return None
    path = path.resolve()
    if path.is_file():
        return None
    if not (path / "pyproject.toml").exists():
        return None
    return path


def clean_local_build_artifacts(source: str | None) -> list[Path]:
    """Remove setuptools artifacts that can make local tool installs stale."""
    project = local_update_source_path(source)
    if project is None:
        return []

    removed: list[Path] = []
    artifacts = [project / "build", *project.glob("*.egg-info")]
    for artifact in artifacts:
        if not artifact.exists():
            continue
        shutil.rmtree(artifact, ignore_errors=True)
        removed.append(artifact)
    return removed


def parse_update_args():
    parser = argparse.ArgumentParser(
        prog="erebus-update",
        description="Update Erebus and restart its local proxy services.",
    )
    parser.add_argument(
        "--from",
        dest="source",
        help="Install from a package spec or local path instead of upgrading the installed tool, e.g. `--from .`.",
    )
    parser.add_argument(
        "--restart-only",
        action="store_true",
        help="Skip package installation and only restart Erebus services.",
    )
    parser.add_argument(
        "--no-restart",
        action="store_true",
        help="Update the package but leave running services untouched.",
    )
    return parser.parse_args()


def main_update():
    args = parse_update_args()
    print(bold("\nerebus update\n"))

    if args.restart_only and args.no_restart:
        print(fail("Choose either --restart-only or --no-restart, not both."))
        raise SystemExit(2)

    if not args.restart_only:
        has_uv = shutil.which("uv") is not None
        cmd = update_install_command(args.source, has_uv)
        cleaned = clean_local_build_artifacts(args.source)
        if cleaned:
            labels = ", ".join(path.name for path in cleaned)
            print(info(f"Cleaned local build artifacts: {labels}"))
        print(info("Updating package: " + " ".join(cmd)))
        result = sp.run(cmd)
        if result.returncode != 0:
            print(fail("Package update failed."))
            raise SystemExit(result.returncode)
        print(ok("Package updated."))

    if args.no_restart:
        print(warn("Services were not restarted. Running proxies may still use the previous code."))
        return

    if stop_daemon():
        print(ok("Stopped GLiNER daemon; it will restart on demand."))
    restarted = restart_proxy_services()
    if restarted:
        print(ok("\nErebus is updated and active.\n"))
    else:
        print(warn("\nNo proxy services were restarted. Run `erebus-setup --editor ...` if services are not installed.\n"))  # noqa: E501
