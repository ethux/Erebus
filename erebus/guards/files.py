"""
File read guard using Ollama.
When Claude wants to read a file, we check the filename + context
with a small local model to decide: allow / sanitize / block.
"""

import fnmatch
import ollama
from pathlib import Path
from ..config import OLLAMA_MODEL, RepoConfig

SYSTEM_PROMPT = """You are a security guard for a developer's AI assistant.
Your job is to decide if a file is safe to read based on its path and purpose.
Respond with JSON only: {"decision": "allow"|"sanitize"|"block", "reason": "<short reason>"}

Block if: credentials, secrets, keys, tokens, sensitive partner data, financial records, contracts, PII
Sanitize if: config files that may contain some sensitive values mixed with safe content
Allow if: source code, documentation, general config without secrets"""


def check_file(filepath: str, purpose: str, repo_config: RepoConfig) -> dict:
    """
    Ask Ollama whether Claude should be allowed to read this file.
    Returns {"decision": "allow"|"sanitize"|"block", "reason": str}
    """
    path = Path(filepath)

    # Fast path: check block patterns from repo config
    for pattern in repo_config.block_file_patterns:
        if fnmatch.fnmatch(str(path), pattern) or fnmatch.fnmatch(path.name, pattern):
            return {"decision": "block", "reason": f"Matches block pattern: {pattern}"}

    # Fast path: obvious secret files
    blocked_names = {".env", ".env.local", ".env.production", "secrets.json",
                     "credentials.json", "id_rsa", "id_ed25519", ".netrc"}
    if path.name in blocked_names or path.suffix in {".pem", ".key", ".p12", ".pfx"}:
        return {"decision": "block", "reason": f"Sensitive file type: {path.name}"}

    # Ollama contextual check
    prompt = f"""File path: {filepath}
Purpose / why Claude wants to read it: {purpose}
Repo context: {repo_config.context or 'general development repo'}
Extra sensitive entities in this repo: {', '.join(repo_config.sensitive_entities) or 'none'}

Should this file be read?"""

    try:
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            format="json",
            options={"temperature": 0},
        )
        import json
        result = json.loads(response["message"]["content"])
        return result
    except Exception as e:
        # If Ollama is unavailable, fail open (allow) but log
        return {"decision": "allow", "reason": f"Ollama unavailable: {e}"}
