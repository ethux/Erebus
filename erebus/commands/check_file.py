"""
CLI tool to check whether a file on disk contains PII filter tokens.

Why this exists: an AI session behind the Erebus filter can never verify file
contents itself — its reads are tokenized on the way in, so it would "see"
tokens whether or not they are physically in the file. This tool gives the
human ground truth by scanning the raw bytes on disk and reporting ONLY:

  * token-shaped strings found (the redacted form — safe to print),
  * whether each is "live" (resolvable via the current token map) or unknown
    (e.g. a synthetic test fixture),
  * a count of real token-map values present in the content (count only —
    the values themselves are never printed),
  * the content's SHA-256 and size, so the scanned bytes can be pinned.

A live token in a written file usually means detokenize-on-write failed and
the file should have contained the real value instead.

Usage:
    erebus-check-file <path> [path ...] [--json]

Exit codes: 0 = no live tokens found, 1 = error (e.g. unreadable file),
2 = at least one live token found.
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

# Same shape as the canonical token regex in proxy.py / shim.py.
TOKEN_RE = re.compile(r"\[(?:[A-Z_]+_\d+_[0-9a-f]{6,}|CATALOG_[A-Z0-9_]+_[0-9a-f]{6,})\]")


def _load_live_token_map() -> dict:
    try:
        from ..config import load_token_map
        tokens = load_token_map()
        return tokens if isinstance(tokens, dict) else {}
    except Exception:
        return {}


def check_file(path: Path, token_map: dict) -> dict:
    """Scan one file. Returns a report dict; never includes file content."""
    raw = path.read_bytes()
    text = raw.decode("utf-8", errors="replace")

    found = sorted(set(TOKEN_RE.findall(text)))
    live = [tok for tok in found if tok in token_map]
    unknown = [tok for tok in found if tok not in token_map]
    # Real PII from the live map present on disk — count only, never values.
    real_value_hits = sum(1 for value in set(token_map.values())
                          if isinstance(value, str) and value and value in text)

    return {
        "path": str(path),
        "size_bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "token_count": len(found),
        "live_tokens": live,
        "unknown_tokens": unknown,
        "real_values_from_map": real_value_hits,
    }


def _print_report(report: dict) -> None:
    print(f"{report['path']}")
    print(f"  size:    {report['size_bytes']} bytes")
    print(f"  sha256:  {report['sha256']}")
    if not report["token_count"]:
        print("  tokens:  none")
    else:
        if report["live_tokens"]:
            print(f"  LIVE tokens ({len(report['live_tokens'])}) — resolvable via the "
                  f"current token map; a written file should contain real values instead:")
            for tok in report["live_tokens"]:
                print(f"    {tok}")
        if report["unknown_tokens"]:
            print(f"  unknown tokens ({len(report['unknown_tokens'])}) — token-shaped but "
                  f"not in the current map (synthetic fixtures or expired sessions):")
            for tok in report["unknown_tokens"]:
                print(f"    {tok}")
    if report["real_values_from_map"]:
        print(f"  real values from the live map present on disk: "
              f"{report['real_values_from_map']} (values not shown)")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check whether files on disk contain PII filter tokens.")
    parser.add_argument("paths", nargs="+", help="Files to scan")
    parser.add_argument("--json", action="store_true",
                        help="Emit one JSON report per line instead of text")
    args = parser.parse_args()

    token_map = _load_live_token_map()
    any_live = False
    failed = False

    for raw_path in args.paths:
        path = Path(raw_path)
        try:
            report = check_file(path, token_map)
        except OSError as e:
            print(f"error: cannot read {path}: {e}", file=sys.stderr)
            failed = True
            continue
        any_live = any_live or bool(report["live_tokens"])
        if args.json:
            print(json.dumps(report))
        else:
            _print_report(report)

    if failed:
        sys.exit(1)
    sys.exit(2 if any_live else 0)


if __name__ == "__main__":
    main()
