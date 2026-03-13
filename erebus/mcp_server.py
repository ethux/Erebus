"""
MCP server for Erebus PII filter.

Exposes tools to inspect the current token map — lets the AI (or user)
check what real values are hidden behind tokens.

Run: erebus-mcp
Configure in Claude Code: claude mcp add erebus -- erebus-mcp
"""

import json
import sys
from pathlib import Path

# MCP protocol over stdio — minimal implementation (no deps)


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
    """Read the current session's token map from the shared state file."""
    state_path = Path.home() / ".claude" / "pii-wrapper" / "token_map.json"
    if state_path.exists():
        try:
            return json.loads(state_path.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


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
                "serverInfo": {"name": "erebus", "version": "0.2.0"},
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
                        "description": "Show the real values behind PII tokens in the current session. "
                                       "Call with no arguments to see all active tokens, or pass a specific token to reveal its value.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "token": {
                                    "type": "string",
                                    "description": "A specific token like [PERSON_1_abc123] to reveal. Omit to show all.",
                                },
                            },
                        },
                    },
                    {
                        "name": "erebus_status",
                        "description": "Show Erebus PII filter status — active token count, session info, and filter config.",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ],
            },
        }

    if method == "tools/call":
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        if tool_name == "erebus_reveal":
            token_map = _get_token_map()
            specific = args.get("token")

            if not token_map:
                text = "No active tokens in this session — nothing has been filtered yet."
            elif specific:
                real = token_map.get(specific)
                if real:
                    text = f"{specific} → {real}"
                else:
                    text = f"Token {specific} not found. Active tokens: {', '.join(token_map.keys())}"
            else:
                lines = [f"{tok} → {real}" for tok, real in token_map.items()]
                text = f"Active tokens ({len(lines)}):\n" + "\n".join(lines)

            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {"content": [{"type": "text", "text": text}]},
            }

        if tool_name == "erebus_status":
            token_map = _get_token_map()
            config_path = Path.home() / ".claude" / "pii-wrapper" / "config.json"
            config = {}
            if config_path.exists():
                try:
                    config = json.loads(config_path.read_text())
                except Exception:
                    pass

            text = (
                f"Erebus PII Filter\n"
                f"Active tokens: {len(token_map)}\n"
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
