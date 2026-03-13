"""
CLI tool to reveal hidden PII token values.

Usage:
    erebus-reveal                    # show all active tokens
    erebus-reveal [PERSON_1_abc123]  # reveal specific token
"""

import argparse
import json
from pathlib import Path


TOKEN_MAP_PATH = Path.home() / ".claude" / "pii-wrapper" / "token_map.json"


def main():
    parser = argparse.ArgumentParser(description="Reveal hidden PII token values")
    parser.add_argument("token", nargs="?", help="Specific token to reveal (e.g. [PERSON_1_abc123])")
    args = parser.parse_args()

    if not TOKEN_MAP_PATH.exists():
        print("No active tokens — the PII filter hasn't caught anything yet.")
        return

    try:
        token_map = json.loads(TOKEN_MAP_PATH.read_text())
    except (json.JSONDecodeError, OSError) as e:
        print(f"Error reading token map: {e}")
        return

    if not token_map:
        print("Token map is empty — no PII has been filtered in this session.")
        return

    if args.token:
        real = token_map.get(args.token)
        if real:
            print(f"{args.token} → {real}")
        else:
            print(f"Token {args.token} not found.")
            print(f"Active tokens: {', '.join(token_map.keys())}")
    else:
        print(f"\nActive tokens ({len(token_map)}):\n")
        for tok, real in token_map.items():
            print(f"  {tok} → {real}")
        print()
