"""
User interaction for sensitive content decisions.

Two modes:
- VSCode inline: injects a decision request into the Claude stream as a
  formatted message — appears directly in the Claude Code chat UI.
- macOS fallback: native osascript dialog if running outside VSCode.
"""

import os
import subprocess
import sys
import json


def _in_vscode() -> bool:
    return "VSCODE_PID" in os.environ or os.environ.get("TERM_PROGRAM") == "vscode"


def _osascript(script: str) -> str:
    result = subprocess.run(["osascript", "-e", script], capture_output=True, text=True)
    return result.stdout.strip()


def _vscode_prompt(title: str, body: str, options: list[str]) -> str:
    """
    Inject a warning into the Claude Code chat UI as a formatted markdown block.
    Then wait for the user's reply on stdin.
    """
    options_str = " / ".join(f"**{o}**" for o in options)
    msg = {
        "type": "assistant",
        "message": {
            "role": "assistant",
            "content": [
                {
                    "type": "text",
                    "text": (
                        f"\n> **[!]{title}**\n>\n"
                        f"> {body}\n>\n"
                        f"> Reply with: {options_str}"
                    ),
                }
            ],
        },
    }
    sys.stdout.buffer.write((json.dumps(msg) + "\n").encode())
    sys.stdout.buffer.flush()

    # Read next user message as the decision
    for line in sys.stdin:
        try:
            data = json.loads(line)
            if data.get("type") == "user":
                for block in data.get("message", {}).get("content", []):
                    if block.get("type") == "text":
                        reply = block["text"].strip().lower()
                        for opt in options:
                            if opt.lower() in reply:
                                return opt.lower()
        except json.JSONDecodeError:
            pass
    return options[0].lower()  # default: most restrictive option


def ask_file_decision(filepath: str, reason: str) -> str:
    """Returns: 'block', 'sanitize', or 'allow'"""
    body = f"Claude wants to read: `{filepath}`  \nReason: _{reason}_"
    if _in_vscode():
        result = _vscode_prompt("PII Guard — File Access", body, ["Block", "Sanitize", "Allow"])
        if "sanitize" in result: return "sanitize"
        if "allow" in result: return "allow"
        return "block"

    script = f'''display dialog "Claude wants to read:\n\n{filepath}\n\nReason: {reason}" ¬
        buttons {{"Block", "Sanitize & Allow", "Allow Once"}} ¬
        default button "Block" with title "[!] Claude PII Guard" with icon caution'''
    output = _osascript(script)
    if "Sanitize" in output: return "sanitize"
    if "Allow" in output: return "allow"
    return "block"


def ask_pii_decision(detected_items: list[str], context_snippet: str) -> str:
    """Returns: 'block', 'tokenize', or 'allow'"""
    items_str = "  \n".join(f"• `{item}`" for item in detected_items[:6])
    body = f"Detected in prompt:  \n{items_str}"
    if _in_vscode():
        result = _vscode_prompt("PII Guard — Sensitive Prompt", body, ["Block", "Tokenize", "Allow"])
        if "block" in result: return "block"
        if "allow" in result: return "allow"
        return "tokenize"

    script = f'''display dialog "PII detected in prompt:\n\n{chr(10).join(detected_items[:6])}" ¬
        buttons {{"Block", "Tokenize & Send", "Send Anyway"}} ¬
        default button "Tokenize & Send" with title "[!] Claude PII Guard" with icon caution'''
    output = _osascript(script)
    if "Block" in output: return "block"
    if "Send Anyway" in output: return "allow"
    return "tokenize"


def ask_image_decision(filename: str, findings: str) -> str:
    """Returns: 'block' or 'allow'"""
    body = f"Image: `{filename}`  \nFindings: _{findings[:150]}_"
    if _in_vscode():
        result = _vscode_prompt("PII Guard — Sensitive Image", body, ["Block", "Allow"])
        return "allow" if "allow" in result else "block"

    script = f'''display dialog "Sensitive content in image:\n\n{filename}\n\n{findings[:150]}" ¬
        buttons {{"Block", "Allow Anyway"}} ¬
        default button "Block" with title "[!] Claude PII Guard" with icon caution'''
    output = _osascript(script)
    return "allow" if "Allow" in output else "block"


def notify(title: str, message: str):
    """Non-blocking macOS notification."""
    subprocess.Popen(["osascript", "-e", f'display notification "{message}" with title "{title}"'])
