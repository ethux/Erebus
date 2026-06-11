"""
MCP server for Erebus PII filter.

Exposes tools to inspect the current token map — lets the AI (or user)
check WHICH tokens are active, as masked previews only. Real PII values
never enter the model context here (spec FR-019, edge case h): full
values stay behind the local erebus-reveal CLI / UI.

Run: erebus-mcp
Configure in Claude Code: claude mcp add erebus -- erebus-mcp
"""

import json
import os
import re
import sys
from pathlib import Path

# MCP protocol over stdio — minimal implementation (no deps)

# Token shape: [KIND_<n>_<hex>]; group 1 is the entity KIND we surface.
_TOKEN_RE = re.compile(r"\[([A-Z_]+)_\d+_[0-9a-f]{6,}\]")

# Fixed pointer: full values live only behind the real-world-sink CLI.
_CLI_POINTER = "For full values, run the erebus-reveal CLI in your terminal."


def mask_value(value: str) -> str:
    """Deterministic masked preview: first char + asterisks + length hint.

    'Jan Modaal' -> 'J********* (10)'; a <=1 char value -> '* (n)'.
    Never reveals the real value (FR-019).
    """
    text = value if isinstance(value, str) else str(value)
    length = len(text)
    if length <= 1:
        return f"* ({length})"
    return f"{text[0]}{'*' * (length - 1)} ({length})"


def _kind_of(token: str) -> str:
    """Entity KIND parsed from a token label, or UNKNOWN."""
    match = _TOKEN_RE.fullmatch(token)
    return match.group(1) if match else "UNKNOWN"


def _read_message():
    """Read a JSON-RPC message from stdin (Content-Length framed)."""
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line or line == b"\r\n":
            break
        if b":" in line:
            key, val = line.decode().split(":", 1)
            headers[key.strip().lower()] = val.strip()

    length = int(headers.get("content-length", 0))
    if length == 0:
        return None
    body = sys.stdin.buffer.read(length)
    return json.loads(body)


def _send_message(msg):
    """Write a JSON-RPC message to stdout (Content-Length framed)."""
    body = json.dumps(msg).encode()
    sys.stdout.buffer.write(f"Content-Length: {len(body)}\r\n\r\n".encode())
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.flush()


def _get_token_map() -> dict:
    """Read the current session's token map from the shared state file (legacy)."""
    state_path = Path.home() / ".claude" / "pii-wrapper" / "token_map.json"
    if state_path.exists():
        try:
            return json.loads(state_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _db_token_map() -> dict | None:
    """Token -> value from the Known-Value DB, or None if it is unavailable.

    Preferred source (single source of truth). The caller masks every value
    before it is emitted; the raw map never leaves this process.
    """
    try:
        from ..config import load_repo_config
        from ..core.knownvalues import open_known_values

        db = open_known_values(load_repo_config(), os.getcwd())
        try:
            return dict(db.bulk_view().token_view)
        finally:
            db.close()
    except Exception:
        return None


def _masked_entries() -> list[tuple[str, str, str]]:
    """(token, masked_value, KIND) for every active token, DB source preferred."""
    token_map = _db_token_map()
    if token_map is None:  # fall back to the legacy file read
        token_map = _get_token_map()
    return [(tok, mask_value(val), _kind_of(tok)) for tok, val in token_map.items()]


def _handle_request(msg):
    method = msg.get("method", "")
    msg_id = msg.get("id")
    params = msg.get("params", {})

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "erebus", "version": "1.0.0"},
            },
        }

    if method == "notifications/initialized":
        return None  # no response needed

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": [
                    {
                        "name": "erebus_reveal",
                        "description": "List active PII tokens as MASKED previews only (first character, length, entity kind). "  # noqa: E501
                                       "Real values never enter the model context; run the erebus-reveal CLI in your terminal for full values.",  # noqa: E501
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "token": {
                                    "type": "string",
                                    "description": "A specific token like Jansen to preview (masked). Omit to show all.",  # noqa: E501
                                },
                            },
                        },
                    },
                    {
                        "name": "erebus_status",
                        "description": "Show Erebus PII filter status — active token count, session info, and filter config.",  # noqa: E501
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ],
            },
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        if tool_name == "erebus_reveal":
            entries = _masked_entries()
            specific = args.get("token")

            if not entries:
                text = "No active tokens in this session — nothing has been filtered yet."
            elif specific:
                # Masked preview only, even for a single-token request (FR-019).
                match = next((e for e in entries if e[0] == specific), None)
                if match:
                    text = f"{match[0]} → {match[1]} ({match[2]})\n{_CLI_POINTER}"
                else:
                    tokens = ", ".join(tok for tok, _, _ in entries)
                    text = f"Token {specific} not found. Active tokens: {tokens}\n{_CLI_POINTER}"
            else:
                lines = [f"{tok} → {masked} ({kind})" for tok, masked, kind in entries]
                text = (f"Active tokens ({len(lines)}), masked previews:\n"
                        + "\n".join(lines) + f"\n{_CLI_POINTER}")

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": text}]},
            }

        if tool_name == "erebus_status":
            # Counts only — never emit a real (or masked) PII value here.
            entries = _masked_entries()
            config_path = Path.home() / ".claude" / "pii-wrapper" / "config.json"
            config = {}
            if config_path.exists():
                try:
                    config = json.loads(config_path.read_text())
                except Exception:
                    pass

            text = (
                f"Erebus PII Filter\n"
                f"Active tokens: {len(entries)}\n"
                f"Real binary: {config.get('real_binary', 'not configured')}\n"
                f"Token map file: ~/.erebus/token_map.json"
            )
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": text}]},
            }

        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Unknown tool: {tool_name}"},
        }

    # Unknown method
    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Unknown method: {method}"},
        }
    return None


def main():
    """Run the MCP server over stdio."""
    while True:
        msg = _read_message()
        if msg is None:
            break
        response = _handle_request(msg)
        if response is not None:
            _send_message(response)


if __name__ == "__main__":
    main()
