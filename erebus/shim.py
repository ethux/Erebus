#!/usr/bin/env python3
"""
Claude Code binary shim — main entry point.

Sits between the Claude Code VSCode extension and the real Claude binary.
Configure in VSCode settings:
  "claudeCode.claudeProcessWrapper": "/path/to/erebus"

Flow:
  VSCode → shim (stdin) → [PII filter] → Claude binary (stdin)
  Claude binary (stdout) → [de-tokenize] → shim (stdout) → VSCode

Kill switch:
  EREBUS_BYPASS=1  — disable ALL filtering, pass through directly
"""

import sys
import os
import json
import subprocess
import threading
import uuid
from pathlib import Path

from .config import get_real_claude_binary, load_repo_config
from .filter import tokenize, detokenize, preload_gliner
from .logger import init_db, log_event

# Session state
SESSION_ID = str(uuid.uuid4())[:8]
TOKEN_MAP: dict = {}  # accumulated across session
CWD = os.getcwd()
REPO_CONFIG = load_repo_config(CWD)
_TOKEN_MAP_PATH = Path.home() / ".erebus" / "token_map.json"


def _persist_token_map():
    """Write token map to shared file so MCP server and CLI can read it."""
    import json as _json
    _TOKEN_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
    _TOKEN_MAP_PATH.write_text(_json.dumps(TOKEN_MAP, indent=2))


def _tokenize_text(text: str, source: str = "user") -> str:
    """Tokenize a string, update TOKEN_MAP, log if needed. Returns sanitized text."""
    sanitized, new_tokens = tokenize(text, REPO_CONFIG.sensitive_entities)
    if new_tokens:
        TOKEN_MAP.update(new_tokens)
        _persist_token_map()
        if REPO_CONFIG.log_enabled:
            log_event(
                SESSION_ID,
                event_type="pii_detected",
                raw=text,
                sanitized=sanitized,
                tokens_map=new_tokens,
                metadata={"cwd": CWD, "source": source, "token_count": len(new_tokens)},
            )
    return sanitized if new_tokens else text


def process_outgoing(line: str) -> str:
    """
    Process a line going FROM VSCode TO Claude.
    Tokenizes PII in user prompts AND tool results.
    """
    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return line  # not JSON, pass through

    if msg.get("type") != "user":
        return json.dumps(msg) + "\n"

    any_pii = False
    new_session_tokens = {}

    for block in msg.get("message", {}).get("content", []):
        if not isinstance(block, dict):
            continue

        # User-typed text
        if block.get("type") == "text":
            original = block["text"]
            sanitized, new_tokens = tokenize(original, REPO_CONFIG.sensitive_entities, REPO_CONFIG.allowed_names)
            if new_tokens:
                any_pii = True
                TOKEN_MAP.update(new_tokens)
                new_session_tokens.update(new_tokens)
                block["text"] = sanitized

                if REPO_CONFIG.log_enabled:
                    log_event(
                        SESSION_ID,
                        event_type="pii_detected",
                        raw=original,
                        sanitized=sanitized,
                        tokens_map=new_tokens,
                        metadata={"cwd": CWD, "source": "user_text", "token_count": len(new_tokens)},
                    )

        # Tool results (file reads, directory listings, command output)
        elif block.get("type") == "tool_result":
            content = block.get("content", "")
            if isinstance(content, str) and content:
                sanitized, new_tokens = tokenize(content, REPO_CONFIG.sensitive_entities, REPO_CONFIG.allowed_names)
                if new_tokens:
                    any_pii = True
                    TOKEN_MAP.update(new_tokens)
                    new_session_tokens.update(new_tokens)
                    block["content"] = sanitized

                    if REPO_CONFIG.log_enabled:
                        log_event(
                            SESSION_ID,
                            event_type="pii_detected",
                            raw=content[:500],
                            sanitized=sanitized[:500],
                            tokens_map=new_tokens,
                            metadata={"cwd": CWD, "source": "tool_result", "token_count": len(new_tokens)},
                        )
            elif isinstance(content, list):
                for sub in content:
                    if isinstance(sub, dict) and sub.get("type") == "text":
                        original = sub["text"]
                        sanitized, new_tokens = tokenize(original, REPO_CONFIG.sensitive_entities, REPO_CONFIG.allowed_names)
                        if new_tokens:
                            any_pii = True
                            TOKEN_MAP.update(new_tokens)
                            new_session_tokens.update(new_tokens)
                            sub["text"] = sanitized

    # Inject token hint into the first text block so Claude understands tokens
    if new_session_tokens:
        for block in msg.get("message", {}).get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                token_hint = (
                    "\n\n<pii-filter>"
                    "A privacy filter replaced sensitive values with tokens. "
                    "Use these tokens naturally as if they were the real values — "
                    "do NOT ask the user about them or mention they are redacted. "
                    "Do NOT save token values to memory or files. "
                    "They are automatically resolved to real values in tool calls. "
                    "Tokens: " + ", ".join(new_session_tokens.keys()) +
                    "</pii-filter>"
                )
                block["text"] += token_hint
                break

    if any_pii:
        _persist_token_map()

    if not any_pii and REPO_CONFIG.log_enabled:
        # Log first text block as prompt
        for block in msg.get("message", {}).get("content", []):
            if isinstance(block, dict) and block.get("type") == "text":
                log_event(SESSION_ID, event_type="prompt",
                          sanitized=block["text"], metadata={"cwd": CWD})
                break

    return json.dumps(msg) + "\n"


def process_incoming(line: str) -> str:
    """
    Process a line going FROM Claude TO VSCode.
    De-tokenizes any tokens back to real values.
    """
    if not TOKEN_MAP:
        return line

    try:
        msg = json.loads(line)
    except json.JSONDecodeError:
        return line

    raw = json.dumps(msg)
    restored = detokenize(raw, TOKEN_MAP)

    if raw != restored and REPO_CONFIG.log_enabled:
        log_event(SESSION_ID, event_type="response",
                  sanitized=raw, raw=restored,
                  tokens_map=TOKEN_MAP, metadata={"cwd": CWD})

    return restored + "\n"


def pipe_stream(source, dest, processor):
    """Read lines from source, process, write to dest."""
    try:
        for line in source:
            if isinstance(line, bytes):
                line = line.decode("utf-8", errors="replace")
            processed = processor(line)
            if isinstance(processed, str):
                processed = processed.encode("utf-8")
            # Handle both text streams (sys.stdout has .buffer) and
            # binary streams (proc.stdin is already a BufferedWriter)
            if hasattr(dest, 'buffer'):
                dest.buffer.write(processed)
                dest.buffer.flush()
            else:
                dest.write(processed)
                dest.flush()
    except Exception as e:
        log_event(SESSION_ID, event_type="pipe_error",
                  metadata={"error": str(e)})
        raise


def main():
    # When called via claudeProcessWrapper, VSCode passes the original binary
    # as argv[1]: wrapper <original-binary> <args...>
    # Detect this and use argv[1] as the real binary.
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]) and os.access(sys.argv[1], os.X_OK):
        real_binary = sys.argv[1]
        claude_args = [real_binary] + sys.argv[2:]
    else:
        real_binary = get_real_claude_binary()
        claude_args = [real_binary] + sys.argv[1:]

    # Kill-switch: EREBUS_BYPASS=1 skips ALL filtering
    if os.environ.get("EREBUS_BYPASS", "").strip() in ("1", "true", "yes"):
        os.execv(claude_args[0], claude_args)

    # Start loading GLiNER immediately in background
    preload_gliner()

    init_db()

    log_event(SESSION_ID, event_type="session_start",
              metadata={"cwd": CWD, "args": sys.argv[1:],
                        "repo_config": REPO_CONFIG.__dict__})

    if sys.stdin.isatty():
        _run_interactive(claude_args)
    else:
        _run_piped(claude_args)


def _run_interactive(claude_args):
    """Run with a PTY so the TUI works. Detokenizes output; input is passed through."""
    import pty

    def master_read(fd):
        try:
            data = os.read(fd, 1024)
        except OSError:
            return b""
        if TOKEN_MAP:
            text = data.decode("utf-8", errors="replace")
            text = detokenize(text, TOKEN_MAP)
            data = text.encode("utf-8")
        return data

    try:
        pty.spawn(claude_args, master_read)
    except Exception:
        os.execv(claude_args[0], claude_args)


def _run_piped(claude_args):
    """VSCode mode: pipe JSON, tokenize outgoing, detokenize incoming."""
    proc = subprocess.Popen(
        claude_args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=sys.stderr,
    )

    t_in = threading.Thread(
        target=pipe_stream,
        args=(sys.stdin, proc.stdin, process_outgoing),
        daemon=True,
    )

    t_out = threading.Thread(
        target=pipe_stream,
        args=(proc.stdout, sys.stdout, process_incoming),
        daemon=True,
    )

    t_in.start()
    t_out.start()

    proc.wait()
    sys.exit(proc.returncode)


if __name__ == "__main__":
    main()
