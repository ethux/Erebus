"""
PII detection and tokenization.

Two-layer approach:
  1. GLiNER (urchade/gliner_multi_pii-v1) — fast local NER, multilingual
     Detects: names, emails, phones, addresses, orgs, IBANs, SSNs, IPs, etc.
  2. Regex — instant, zero deps, catches secrets/credentials
     Detects: API keys, tokens, passwords, private keys

Story leak detection (contextual/narrative PII) is handled separately
by Ministral in guards/files.py — it's slower and only runs when needed.
"""

import fnmatch
import re
import uuid
from functools import lru_cache

# ── Regex: secrets and credentials ────────────────────────────────────────────

SECRET_PATTERNS = [
    # Specific token formats (high confidence)
    (r"sk-[a-zA-Z0-9\-_]{20,}",              "API_KEY"),
    (r"ghp_[a-zA-Z0-9]{36}",                  "GITHUB_TOKEN"),
    (r"glpat-[a-zA-Z0-9\-_]{20,}",            "GITLAB_TOKEN"),
    (r"xox[baprs]-[a-zA-Z0-9\-]+",            "SLACK_TOKEN"),
    (r"AKIA[0-9A-Z]{16}",                      "AWS_KEY"),
    (r"-----BEGIN [A-Z ]+PRIVATE KEY-----",    "PRIVATE_KEY"),
    # Key=value assignments (only match actual assignments, not mentions)
    (r"(?i)password\s*[:=]\s*['\"]?\S{6,}",   "PASSWORD"),
    (r"(?i)secret\s*[:=]\s*['\"]?\S{6,}",     "SECRET"),
    (r'(?i)api[_\-]?key\s*[:=]\s*[\'"]?\S{8,}', "API_KEY"),
    (r'(?i)token\s*[:=]\s*[\'"]?\S{8,}',      "TOKEN"),
]

# ── GLiNER: NER-based PII detection ───────────────────────────────────────────

GLINER_LABELS = [
    "person", "email address", "phone number", "address",
    "organization", "credit card number", "social security number",
    "iban", "passport number", "ip address", "username",
    "password", "api key", "date of birth", "bank account number",
]


@lru_cache(maxsize=1)
def _get_gliner():
    """Lazy-load GLiNER model — cached after first call."""
    from gliner import GLiNER
    return GLiNER.from_pretrained("urchade/gliner_multi_pii-v1")


def preload_gliner():
    """Ensure GLiNER daemon is running (starts it if needed)."""
    from .daemon import ensure_daemon
    ensure_daemon()


def _predict_entities(text: str) -> list[dict]:
    """Get GLiNER entities — tries daemon first, falls back to local model."""
    from .daemon import predict_via_daemon

    # Try daemon (fast — model already loaded)
    result = predict_via_daemon(text, threshold=0.85)
    if result is not None:
        return _filter_entities(result)

    # Fallback: load model in-process (slow first time)
    model = _get_gliner()
    entities = model.predict_entities(text, GLINER_LABELS, threshold=0.85)
    raw = [{"start": e["start"], "end": e["end"], "label": e["label"],
            "text": e["text"]} for e in entities]
    return _filter_entities(raw)


# Generic words that match entity labels but aren't actual PII
_FALSE_POSITIVES = {
    "iban", "ibans", "email", "emails", "email address", "phone", "phones",
    "phone number", "address", "addresses", "password", "passwords",
    "api key", "api keys", "token", "tokens", "secret", "secrets",
    "username", "usernames", "credit card", "credit cards", "ssn", "ssns",
    "social security number", "ip address", "passport", "name", "names",
    "person", "organization", "bank account", "date of birth",
}

# Built-in allowed names — public names, tools, and common words that should never
# be tokenized. Merged with per-repo allowed_names from .erebus/pii-filter.json.
DEFAULT_ALLOWED = {
    # AI editors & tools
    "Claude", "Claude Code", "Anthropic", "Mistral", "Mistral Vibe", "OpenAI",
    "Cursor", "Windsurf", "Codex", "Copilot", "ChatGPT", "Gemini", "Ollama",
    # Tech companies
    "Google", "Microsoft", "Apple", "Amazon", "Meta", "GitHub", "GitLab",
    "HuggingFace", "Hugging Face", "Docker", "Kubernetes", "Vercel", "Netlify",
    "Cloudflare", "Heroku", "DigitalOcean", "Supabase", "Firebase", "MongoDB",
    # Dev tools & languages
    "VSCode", "VS Code", "Python", "JavaScript", "TypeScript", "Node",
    "React", "Vue", "Angular", "Django", "Flask", "FastAPI", "Express",
    "PostgreSQL", "MySQL", "Redis", "SQLite", "Terraform", "Linux", "macOS",
    # This project
    "ETHUX", "ethux", "GLiNER", "Ministral", "Erebus",
    # Networking — local/dev addresses should never be tokenized
    "localhost", "127.0.0.1", "0.0.0.0", "::1",
    # Common words GLiNER may misclassify as entities
    "project", "project name", "project structure", "code", "wrapper",
    "filter", "config", "setup", "proxy", "daemon", "guard", "logger",
}

# Minimum length per entity type to reduce false positives
_MIN_LENGTHS = {
    "PERSON": 4, "ORGANIZATION": 4, "USERNAME": 4,
    "IBAN": 10, "CREDIT_CARD_NUMBER": 8, "SOCIAL_SECURITY_NUMBER": 6,
    "PHONE_NUMBER": 6, "IP_ADDRESS": 7, "BANK_ACCOUNT_NUMBER": 6,
    "PASSPORT_NUMBER": 5, "API_KEY": 8, "EMAIL_ADDRESS": 5,
}


def _filter_entities(entities: list[dict]) -> list[dict]:
    """Remove false positives — generic words and too-short matches."""
    filtered = []
    for e in entities:
        text = e["text"].strip()
        # Skip generic category words
        if text.lower() in _FALSE_POSITIVES:
            continue
        # Skip too-short matches for structured types
        label = e["label"].upper().replace(" ", "_")
        min_len = _MIN_LENGTHS.get(label, 2)
        if len(text) < min_len:
            continue
        filtered.append(e)
    return filtered


def tokenize(text: str, extra_entities: list[str] = None,
             allowed_names: list[str] = None) -> tuple[str, dict]:
    """
    Replace PII and secrets with reversible tokens.
    Returns (tokenized_text, token_map).
    Falls back to regex-only if GLiNER is not installed.
    Values in allowed_names are never tokenized.
    """
    token_map = {}
    counters = {}

    # Escape character: append ~ to a word to mark it as allowed
    # e.g. "Send this to Erebus~" — the ~ is stripped and "Erebus" passes through
    # For multi-word names: "John Smith~" escapes both "John" and "Smith" individually,
    # and also the combined phrase so GLiNER's span match is caught too.
    escaped = set()
    escape_re = re.findall(r'(\S+)~(?=\s|$)', text)
    for word in escape_re:
        escaped.add(word.lower())
    # Also escape the word before the escaped word (covers "FirstName LastName~")
    words = text.split()
    for i, w in enumerate(words):
        if w.endswith('~') and i > 0:
            prev = words[i - 1].rstrip('~').lower()
            combined = prev + ' ' + w.rstrip('~').lower()
            escaped.add(prev)
            escaped.add(combined)
    result = re.sub(r'(\S+)~(?=\s|$)', r'\1', text)  # strip the ~ markers

    all_allowed = [a.lower() for a in DEFAULT_ALLOWED] + [a.lower() for a in (allowed_names or [])]
    _exact = {a for a in all_allowed if "*" not in a and "?" not in a}
    _wild = [a for a in all_allowed if "*" in a or "?" in a]

    def _is_allowed(value: str) -> bool:
        v = value.lower()
        # Escaped with ~ by the user
        if v in escaped:
            return True
        # Exact: substring match in both directions
        if any(a in v or v in a for a in _exact):
            return True
        # Wildcard: fnmatch patterns like "Erebus*", "Project *"
        if any(fnmatch.fnmatch(v, w) for w in _wild):
            return True
        return False

    # Step 1: GLiNER NER (fast, multilingual)
    try:
        entities = _predict_entities(text)
        # Process right-to-left so replacements don't shift offsets
        for ent in sorted(entities, key=lambda e: e["start"], reverse=True):
            real_value = text[ent["start"]:ent["end"]]
            if _is_allowed(real_value):
                continue
            label = ent["label"].upper().replace(" ", "_")
            counters[label] = counters.get(label, 0) + 1
            uid = uuid.uuid4().hex[:6]
            token = f"[{label}_{counters[label]}_{uid}]"
            token_map[token] = real_value
            result = result[:ent["start"]] + token + result[ent["end"]:]
    except ImportError:
        pass  # gliner not installed — regex-only mode
    except Exception:
        pass  # model error — degrade gracefully

    # Step 2: Regex secrets (always runs, instant)
    for pattern, label in SECRET_PATTERNS:
        def _replace(m, lbl=label):
            counters[lbl] = counters.get(lbl, 0) + 1
            uid = uuid.uuid4().hex[:6]
            tok = f"[{lbl}_{counters[lbl]}_{uid}]"
            token_map[tok] = m.group(0)
            return tok
        result = re.sub(pattern, _replace, result)

    # Step 3: Custom entities from .erebus/pii-filter.json (exact match)
    if extra_entities:
        for entity in extra_entities:
            if entity in result:
                counters["SENSITIVE"] = counters.get("SENSITIVE", 0) + 1
                uid = uuid.uuid4().hex[:6]
                token = f"[SENSITIVE_{counters['SENSITIVE']}_{uid}]"
                token_map[token] = entity
                result = result.replace(entity, token)

    return result, token_map


def detokenize(text: str, token_map: dict) -> str:
    """Swap tokens back to real values in Claude's response."""
    for token, real_value in token_map.items():
        text = text.replace(token, real_value)
    return text
