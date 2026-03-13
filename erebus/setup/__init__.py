"""
erebus setup

Wraps AI coding editor binaries/configs with the PII filter.
Supported editors:
  - Mistral Vibe (proxy provider in ~/.vibe/config.toml)
  - Cursor       (ANTHROPIC_BASE_URL proxy via ~/.cursor/settings.json)
  - Windsurf     (proxy via ~/.codeium/windsurf/settings.json)
  - Codex        (OPENAI_BASE_URL proxy via environment)
  - Claude Code  (claude binary shim)

Run:    erebus-setup [--editor vibe|claude|cursor|windsurf|codex|all]
Undo:   erebus-uninstall [--editor ...]
"""

import argparse
from ..ui.colors import ok, bold, info
from .editors import install_claude, uninstall_claude, install_editor, uninstall_editor, install_vibe, uninstall_vibe, install_dependencies, EDITOR_CONFIGS
from .services import install_proxy_service, uninstall_proxy_service


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
    editors = list(EDITOR_CONFIGS.keys()) + ["claude", "vibe"] if "all" in args.editor else args.editor
    print(bold("\nerebus setup\n"))
    install_dependencies()
    print(bold("\nConfiguring editors...\n"))
    for editor in editors:
        if editor == "claude":
            install_claude()
        elif editor == "vibe":
            install_vibe()
        elif editor in EDITOR_CONFIGS:
            install_editor(editor)
    install_proxy_service()
    print(ok("\nDone. Run `erebus-uninstall` to remove."))
    print(info("Try it: erebus-log  (view activity log after first use)\n"))


def main_uninstall():
    args = _parse_args()
    editors = list(EDITOR_CONFIGS.keys()) + ["claude", "vibe"] if "all" in args.editor else args.editor
    print(bold("\nerebus uninstall\n"))
    for editor in editors:
        if editor == "claude":
            uninstall_claude()
        elif editor == "vibe":
            uninstall_vibe()
        elif editor in EDITOR_CONFIGS:
            uninstall_editor(editor)
    uninstall_proxy_service()
    print(ok("\nUninstalled.\n"))
