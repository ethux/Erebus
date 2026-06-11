# pylint: disable=too-many-lines  # legacy size, slated to shrink in 004 restructure
from __future__ import annotations

import argparse
import json
import os
import sqlite3
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from .. import config

AI_LOC_EVENT = "ai_written_loc"
AI_WRITE_TOOL_NAMES = {
    "edit",
    "multiedit",
    "str_replace_editor",
    "write",
    "write_file",
}
PATCH_TOOL_NAMES = {
    "apply_patch",
}


LANGUAGE_BY_EXTENSION = {
    ".bash": "Shell",
    ".c": "C",
    ".cfg": "Config",
    ".conf": "Config",
    ".cpp": "C++",
    ".cs": "C#",
    ".css": "CSS",
    ".go": "Go",
    ".h": "C/C++ Header",
    ".hpp": "C/C++ Header",
    ".html": "HTML",
    ".ini": "Config",
    ".java": "Java",
    ".js": "JavaScript",
    ".json": "JSON",
    ".jsx": "JavaScript",
    ".kt": "Kotlin",
    ".kts": "Kotlin",
    ".less": "CSS",
    ".lua": "Lua",
    ".md": "Markdown",
    ".php": "PHP",
    ".ps1": "PowerShell",
    ".py": "Python",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".sass": "CSS",
    ".scala": "Scala",
    ".scss": "CSS",
    ".sh": "Shell",
    ".sql": "SQL",
    ".swift": "Swift",
    ".toml": "TOML",
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".vue": "Vue",
    ".yaml": "YAML",
    ".yml": "YAML",
    ".zsh": "Shell",
}

LANGUAGE_BY_FILENAME = {
    ".dockerignore": "Docker",
    ".env.example": "Config",
    ".gitignore": "Config",
    "Dockerfile": "Docker",
    "Makefile": "Make",
}

COMMENT_PREFIXES = {
    "C": ("//", "/*", "*"),
    "C#": ("//", "/*", "*"),
    "C++": ("//", "/*", "*"),
    "C/C++ Header": ("//", "/*", "*"),
    "CSS": ("/*", "*"),
    "Config": ("#", ";"),
    "Docker": ("#",),
    "Go": ("//", "/*", "*"),
    "HTML": ("<!--",),
    "Java": ("//", "/*", "*"),
    "JavaScript": ("//", "/*", "*"),
    "Kotlin": ("//", "/*", "*"),
    "Lua": ("--",),
    "Make": ("#",),
    "Markdown": ("<!--",),
    "PHP": ("//", "#", "/*", "*"),
    "PowerShell": ("#",),
    "Python": ("#",),
    "Ruby": ("#",),
    "Rust": ("//", "/*", "*"),
    "Scala": ("//", "/*", "*"),
    "Shell": ("#",),
    "SQL": ("--",),
    "Swift": ("//", "/*", "*"),
    "TOML": ("#",),
    "TypeScript": ("//", "/*", "*"),
    "Vue": ("<!--", "//", "/*", "*"),
    "YAML": ("#",),
}

SKIP_DIRS = {
    ".eggs",
    ".git",
    ".hg",
    ".mypy_cache",
    ".nox",
    ".pytest_cache",
    ".ruff_cache",
    ".svn",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "env",
    "node_modules",
    "site-packages",
    "venv",
}

SKIP_SUFFIXES = {
    ".lock",
    ".map",
    ".min.css",
    ".min.js",
    ".pyc",
    ".pyo",
}


@dataclass
class LocStats:
    files: int = 0
    total: int = 0
    blank: int = 0
    comment: int = 0

    @property
    def code(self) -> int:
        return self.total - self.blank - self.comment

    def add_file(self, total: int, blank: int, comment: int) -> None:
        self.files += 1
        self.total += total
        self.blank += blank
        self.comment += comment

    def add(self, other: LocStats) -> None:
        self.files += other.files
        self.total += other.total
        self.blank += other.blank
        self.comment += other.comment

    def as_dict(self) -> dict[str, int]:
        return {
            "files": self.files,
            "code": self.code,
            "comment": self.comment,
            "blank": self.blank,
            "total": self.total,
        }


def _language_for(path: Path, include_unknown: bool = False) -> str | None:
    if path.name in LANGUAGE_BY_FILENAME:
        return LANGUAGE_BY_FILENAME[path.name]
    language = LANGUAGE_BY_EXTENSION.get(path.suffix.lower())
    if language:
        return language
    return "Text" if include_unknown else None


def _is_skipped(path: Path) -> bool:
    if any(part in SKIP_DIRS for part in path.parts):
        return True
    name = path.name.lower()
    return any(name.endswith(suffix) for suffix in SKIP_SUFFIXES)


def _git_files(root: Path) -> list[Path] | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard"],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    return [root / line for line in result.stdout.splitlines() if line]


def _walk_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in SKIP_DIRS]
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            if _is_skipped(path.relative_to(root)):
                continue
            files.append(path)
    return files


def _read_text(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\0" in raw:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def _line_counts(text: str, language: str) -> tuple[int, int, int]:
    lines = text.splitlines()
    prefixes = COMMENT_PREFIXES.get(language, ())
    total = len(lines)
    blank = 0
    comment = 0
    for line in lines:
        stripped = line.strip()
        if not stripped:
            blank += 1
        elif prefixes and stripped.startswith(prefixes):
            comment += 1
    return total, blank, comment


def _count_text(text: str, file_path: str | None = None) -> dict[str, int]:
    language = _language_for(Path(file_path or ""), include_unknown=True)
    total, blank, comment = _line_counts(text, language or "Text")
    return {
        "code_lines": total - blank - comment,
        "comment_lines": comment,
        "blank_lines": blank,
        "total_lines": total,
    }


def _json_args(value) -> dict:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _line_delta(old_text: str = "", new_text: str = "",
                file_path: str | None = None) -> dict[str, int]:
    new_counts = _count_text(new_text or "", file_path)
    old_counts = _count_text(old_text or "", file_path)
    return {
        **new_counts,
        "removed_code_lines": old_counts["code_lines"],
        "removed_total_lines": old_counts["total_lines"],
        "net_code_lines": new_counts["code_lines"] - old_counts["code_lines"],
        "net_total_lines": new_counts["total_lines"] - old_counts["total_lines"],
    }


def _metadata(tool: str, file_path: str | None, source: str,
              counts: dict[str, int], operation_count: int = 1) -> dict:
    return {
        "source": source,
        "tool": tool,
        "file_path": file_path,
        "operation_count": operation_count,
        **counts,
    }


def _event_from_named_tool(tool: str, args: dict, source: str) -> dict | None:
    normalized = tool.lower()
    file_path = args.get("file_path") or args.get("path")
    if normalized in ("write", "write_file"):
        content = args.get("content")
        if not isinstance(content, str):
            content = args.get("file_text")
        if not isinstance(content, str):
            return None
        return _metadata(tool, file_path, source, _line_delta(new_text=content, file_path=file_path))

    if normalized in ("edit", "str_replace_editor"):
        new_text = args.get("new_string")
        old_text = args.get("old_string")
        if not isinstance(new_text, str):
            new_text = args.get("new_str") or args.get("file_text")
        if not isinstance(old_text, str):
            old_text = args.get("old_str", "")
        if not isinstance(new_text, str):
            return None
        return _metadata(
            tool,
            file_path,
            source,
            _line_delta(old_text=old_text or "", new_text=new_text, file_path=file_path),
        )

    if normalized == "multiedit":
        edits = args.get("edits")
        if not isinstance(edits, list):
            return None
        totals = {
            "code_lines": 0,
            "comment_lines": 0,
            "blank_lines": 0,
            "total_lines": 0,
            "removed_code_lines": 0,
            "removed_total_lines": 0,
            "net_code_lines": 0,
            "net_total_lines": 0,
        }
        operations = 0
        for edit in edits:
            if not isinstance(edit, dict):
                continue
            new_text = edit.get("new_string")
            old_text = edit.get("old_string", "")
            if not isinstance(new_text, str):
                continue
            counts = _line_delta(
                old_text=old_text if isinstance(old_text, str) else "",
                new_text=new_text,
                file_path=file_path,
            )
            for key in totals:
                totals[key] += counts[key]
            operations += 1
        if not operations:
            return None
        return _metadata(tool, file_path, source, totals, operation_count=operations)

    return None


def _events_from_patch(tool: str, patch: str, source: str) -> list[dict]:
    events = []
    current_file = None
    added: list[str] = []
    removed: list[str] = []

    def flush() -> None:
        nonlocal added, removed
        if not current_file or not added:
            added = []
            removed = []
            return
        events.append(_metadata(
            tool,
            current_file,
            source,
            _line_delta(
                old_text="\n".join(removed),
                new_text="\n".join(added),
                file_path=current_file,
            ),
        ))
        added = []
        removed = []

    for line in patch.splitlines():
        if line.startswith("*** Update File: ") or line.startswith("*** Add File: "):
            flush()
            current_file = line.split(": ", 1)[1]
        elif line.startswith("*** Delete File: "):
            flush()
            current_file = None
        elif current_file and line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:])
        elif current_file and line.startswith("-") and not line.startswith("---"):
            removed.append(line[1:])
    flush()
    return events


def _tool_name_and_args(value: dict) -> tuple[str | None, dict]:
    name = value.get("name")
    args = value.get("input")
    if isinstance(name, str) and isinstance(args, dict):
        return name, args

    function = value.get("function")
    if isinstance(function, dict):
        fn_name = function.get("name")
        if isinstance(fn_name, str):
            return fn_name, _json_args(function.get("arguments"))

    if isinstance(name, str) and ("arguments" in value or "args" in value):
        return name, _json_args(value.get("arguments", value.get("args")))

    return None, {}


def ai_write_events_from_payload(payload, source: str = "unknown") -> list[dict]:
    """Extract privacy-safe AI-written LOC metadata from model tool calls."""
    events: list[dict] = []

    def visit(value) -> None:
        if isinstance(value, list):
            for item in value:
                visit(item)
            return
        if not isinstance(value, dict):
            return

        name, args = _tool_name_and_args(value)
        if isinstance(name, str):
            normalized = name.lower()
            if normalized in AI_WRITE_TOOL_NAMES:
                event = _event_from_named_tool(name, args, source)
                if event:
                    events.append(event)
            elif normalized in PATCH_TOOL_NAMES:
                patch = args.get("patch")
                if isinstance(patch, str):
                    events.extend(_events_from_patch(name, patch, source))

        for item in value.values():
            visit(item)

    visit(payload)
    return events


def ai_written_loc_summary(days: int | None = None, session: str | None = None) -> dict:
    if not config.DB_PATH.exists():
        return {
            "events": 0,
            "files": 0,
            "code_lines": 0,
            "comment_lines": 0,
            "blank_lines": 0,
            "total_lines": 0,
            "removed_code_lines": 0,
            "net_code_lines": 0,
            "by_file": {},
        }

    clauses = [f"event_type = '{AI_LOC_EVENT}'"]
    params: list = []
    if days is not None:
        clauses.append("timestamp >= datetime('now', ?)")
        params.append(f"-{days} days")
    if session:
        clauses.append("session_id = ?")
        params.append(session)
    where = " AND ".join(clauses)

    conn = sqlite3.connect(config.DB_PATH)
    rows = conn.execute(
        f"SELECT metadata FROM events WHERE {where}",
        params,
    ).fetchall()
    conn.close()

    totals = {
        "events": 0,
        "files": 0,
        "code_lines": 0,
        "comment_lines": 0,
        "blank_lines": 0,
        "total_lines": 0,
        "removed_code_lines": 0,
        "net_code_lines": 0,
        "by_file": {},
    }
    files_seen = set()
    for (metadata,) in rows:
        try:
            meta = json.loads(metadata) if metadata else {}
        except (TypeError, ValueError):
            continue
        totals["events"] += 1
        file_path = meta.get("file_path") or "(unknown)"
        files_seen.add(file_path)
        bucket = totals["by_file"].setdefault(file_path, {
            "code_lines": 0,
            "comment_lines": 0,
            "blank_lines": 0,
            "total_lines": 0,
            "removed_code_lines": 0,
            "net_code_lines": 0,
        })
        for key in ("code_lines", "comment_lines", "blank_lines",
                    "total_lines", "removed_code_lines", "net_code_lines"):
            value = int(meta.get(key, 0) or 0)
            totals[key] += value
            bucket[key] += value
    totals["files"] = len(files_seen)
    return totals


def print_ai_written_loc(days: int | None = None, session: str | None = None,
                         details: bool = False) -> None:
    summary = ai_written_loc_summary(days=days, session=session)
    if not details:
        print(summary["code_lines"])
        return

    print("\nerebus-loc - AI-written code\n")
    print(f"  code lines written: {summary['code_lines']:,}")
    print(f"  total lines written: {summary['total_lines']:,}")
    print(f"  files touched: {summary['files']:,}")
    print(f"  write events: {summary['events']:,}")
    if summary["removed_code_lines"]:
        print(f"  code lines removed: {summary['removed_code_lines']:,}")
        print(f"  net code lines: {summary['net_code_lines']:,}")

    by_file = summary["by_file"]
    if by_file:
        print("\n  Top files:")
        for file_path, counts in sorted(
            by_file.items(),
            key=lambda item: item[1]["code_lines"],
            reverse=True,
        )[:10]:
            print(f"    {counts['code_lines']:>8,}  {file_path}")
    print()


def count_loc(root: Path | str = ".", include_unknown: bool = False,
              use_git: bool = True) -> dict[str, LocStats]:
    root = Path(root).expanduser().resolve()
    candidates = _git_files(root) if use_git else None
    if candidates is None:
        candidates = _walk_files(root)

    by_language: dict[str, LocStats] = defaultdict(LocStats)
    for path in candidates:
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if _is_skipped(rel):
            continue
        language = _language_for(path, include_unknown=include_unknown)
        if language is None:
            continue
        text = _read_text(path)
        if text is None:
            continue
        by_language[language].add_file(*_line_counts(text, language))
    return dict(by_language)


def total_stats(by_language: dict[str, LocStats]) -> LocStats:
    total = LocStats()
    for stats in by_language.values():
        total.add(stats)
    return total


def _print_table(root: Path, by_language: dict[str, LocStats]) -> None:
    if not by_language:
        print(f"No source files found under {root}")
        return

    rows = sorted(by_language.items(), key=lambda item: item[1].code, reverse=True)
    width = max(8, max(len(language) for language, _stats in rows))
    print(f"\nerebus-loc - {root}\n")
    print(f"{'Language':<{width}}  {'Files':>7}  {'Code':>10}  {'Comment':>10}  {'Blank':>10}  {'Total':>10}")
    print(f"{'-' * width}  {'-' * 7}  {'-' * 10}  {'-' * 10}  {'-' * 10}  {'-' * 10}")
    for language, stats in rows:
        print(
            f"{language:<{width}}  {stats.files:>7,}  {stats.code:>10,}  "
            f"{stats.comment:>10,}  {stats.blank:>10,}  {stats.total:>10,}"
        )
    total = total_stats(by_language)
    print(f"{'-' * width}  {'-' * 7}  {'-' * 10}  {'-' * 10}  {'-' * 10}  {'-' * 10}")
    print(
        f"{'TOTAL':<{width}}  {total.files:>7,}  {total.code:>10,}  "
        f"{total.comment:>10,}  {total.blank:>10,}  {total.total:>10,}"
    )
    print()


def _json_payload(root: Path, by_language: dict[str, LocStats]) -> dict:
    return {
        "root": str(root),
        "total": total_stats(by_language).as_dict(),
        "languages": {
            language: stats.as_dict()
            for language, stats in sorted(by_language.items())
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="erebus-loc",
        description="Count AI-written LOC from Erebus logs.",
    )
    parser.add_argument("path", nargs="?", default=".", help="directory to count with --repo")
    parser.add_argument("--all", action="store_true", help="include unknown text files as Text")
    parser.add_argument("--details", action="store_true", help="show AI-written LOC details instead of one number")
    parser.add_argument("--days", type=int, default=None, help="limit AI-written LOC to the last N days")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--repo", action="store_true", help="count source LOC in a directory instead of AI-written LOC")
    parser.add_argument("--session", default=None, help="limit AI-written LOC to one session id")
    parser.add_argument("--total", action="store_true", help="with --repo, print only total source code LOC")
    parser.add_argument("--no-git", action="store_true", help="walk files directly instead of using git ignore rules")
    args = parser.parse_args()

    if not args.repo:
        summary = ai_written_loc_summary(days=args.days, session=args.session)
        if args.json:
            print(json.dumps(summary, indent=2, sort_keys=True))
        else:
            print_ai_written_loc(days=args.days, session=args.session, details=args.details)
        return 0

    root = Path(args.path).expanduser().resolve()
    by_language = count_loc(root, include_unknown=args.all, use_git=not args.no_git)
    if args.total:
        print(total_stats(by_language).code)
    elif args.json:
        print(json.dumps(_json_payload(root, by_language), indent=2, sort_keys=True))
    else:
        _print_table(root, by_language)
    return 0


if __name__ == "__main__":
    sys.exit(main())
