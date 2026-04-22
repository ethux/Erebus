"""
Manage hard blacklists — plaintext terms that are always tokenized before any
content reaches the AI, regardless of filter mode or NER detection.

Two scopes:
  * Global: ~/.erebus/blacklist.txt         — applies to all projects
  * Repo:   <repo>/.erebus/blacklist.txt    — scoped to one repo

Both files are automatically added to block_file_patterns so the AI can never
read them back via a file-read tool.

Usage:
    erebus-blacklist add "Jan Jansen"           # global
    erebus-blacklist add "Acme BV" --repo       # current repo only
    erebus-blacklist list                       # global + current repo
    erebus-blacklist remove "Jan Jansen"        # global
    erebus-blacklist path                       # print the blacklist file paths
"""

import argparse
import sys
from pathlib import Path

from . import config
from .config import REPO_BLACKLIST_FILENAME, _load_blacklist_file, secure_path
from .ui.colors import bold, dim, info, ok, warn


_HEADER = (
    "# erebus blacklist — one term per line\n"
    "# blank lines and '#' comments are ignored\n"
    "# matches are case-insensitive and word-bounded\n"
)


def _resolve_path(use_repo: bool) -> Path:
    if use_repo:
        return Path.cwd() / REPO_BLACKLIST_FILENAME
    return config.GLOBAL_BLACKLIST_PATH


def _ensure_file(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(_HEADER, encoding="utf-8")
    secure_path(path, 0o600)


def cmd_add(args) -> int:
    path = _resolve_path(args.repo)
    _ensure_file(path)
    existing = {t.lower() for t in _load_blacklist_file(path)}
    term = args.term.strip()
    if not term:
        print(warn("empty term — nothing added"))
        return 1
    if term.lower() in existing:
        print(info(f"already in {path}: {term}"))
        return 0
    with path.open("a", encoding="utf-8") as f:
        f.write(term + "\n")
    print(ok(f"added to {path}: {term}"))
    return 0


def cmd_remove(args) -> int:
    path = _resolve_path(args.repo)
    if not path.exists():
        print(warn(f"no blacklist at {path}"))
        return 1
    target = args.term.strip().lower()
    kept = []
    removed = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        stripped = raw.split("#", 1)[0].strip()
        if stripped and stripped.lower() == target:
            removed = True
            continue
        kept.append(raw)
    if not removed:
        print(warn(f"not found in {path}: {args.term}"))
        return 1
    path.write_text("\n".join(kept) + "\n", encoding="utf-8")
    print(ok(f"removed from {path}: {args.term}"))
    return 0


def cmd_list(_args) -> int:
    repo_path = Path.cwd() / REPO_BLACKLIST_FILENAME
    global_terms = _load_blacklist_file(config.GLOBAL_BLACKLIST_PATH)
    repo_terms = _load_blacklist_file(repo_path)

    print(bold(f"\n  global ({config.GLOBAL_BLACKLIST_PATH})"))
    if global_terms:
        for t in global_terms:
            print(f"    {t}")
    else:
        print(dim("    (empty)"))

    print(bold(f"\n  repo   ({repo_path})"))
    if repo_terms:
        for t in repo_terms:
            print(f"    {t}")
    else:
        print(dim("    (empty)"))
    print()
    return 0


def cmd_path(_args) -> int:
    print(f"global: {config.GLOBAL_BLACKLIST_PATH}")
    print(f"repo:   {Path.cwd() / REPO_BLACKLIST_FILENAME}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="erebus-blacklist",
        description="Manage hard-blocked terms that are always tokenized.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_add = sub.add_parser("add", help="Add a term to the blacklist")
    p_add.add_argument("term", help="term to block (quote if it has spaces)")
    p_add.add_argument("--repo", action="store_true",
                       help="write to the current repo's blacklist instead of global")
    p_add.set_defaults(func=cmd_add)

    p_rm = sub.add_parser("remove", help="Remove a term from the blacklist")
    p_rm.add_argument("term", help="term to remove")
    p_rm.add_argument("--repo", action="store_true",
                      help="remove from repo blacklist instead of global")
    p_rm.set_defaults(func=cmd_remove)

    p_ls = sub.add_parser("list", help="List global + repo blacklists")
    p_ls.set_defaults(func=cmd_list)

    p_path = sub.add_parser("path", help="Print the blacklist file paths")
    p_path.set_defaults(func=cmd_path)

    args = parser.parse_args()
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
