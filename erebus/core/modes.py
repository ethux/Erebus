"""Filter modes, entity policy data, and blacklist term classification.

Leaf module (stdlib ``re``/``uuid``).

Filter modes:
  - strict:   tokenize everything — full names, orgs, all entity types
  - balanced: keep first names, tokenize last names and orgs with >1 word
  - relaxed:  only tokenize structured PII (emails, IBANs, keys, etc.) — skip names/orgs
"""
from __future__ import annotations

import re
import uuid

MODES = ("strict", "balanced", "relaxed")
DEFAULT_MODE = "balanced"

# Entity types that are always tokenized regardless of mode (structured PII / secrets)
_ALWAYS_TOKENIZE = {
    "EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD_NUMBER",
    "SOCIAL_SECURITY_NUMBER", "IBAN", "PASSPORT_NUMBER",
    "BANK_ACCOUNT_NUMBER", "DATE_OF_BIRTH", "IP_ADDRESS",
    # Regex-detected secrets
    "API_KEY", "GITHUB_TOKEN", "GITLAB_TOKEN", "SLACK_TOKEN",
    "AWS_KEY", "PRIVATE_KEY", "PASSWORD", "SECRET", "TOKEN",
    # Custom entities
    "SENSITIVE",
}

# Entity types affected by mode
_MODE_AFFECTED = {"PERSON", "ORGANIZATION", "USERNAME", "ADDRESS"}

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


def _should_tokenize_entity(label: str, text: str, mode: str) -> bool:
    """
    Decide whether to tokenize an entity based on the filter mode.

    strict:   tokenize everything GLiNER detects
    balanced: keep single-word person names and single-word orgs
    relaxed:  skip all names and orgs (secrets still caught by regex)

    Secrets and structured PII (emails, IBANs, etc.) are always tokenized
    regardless of mode — this is enforced by _ALWAYS_TOKENIZE.
    """
    norm_label = label.upper().replace(" ", "_")

    if norm_label in _ALWAYS_TOKENIZE:
        return True
    if norm_label not in _MODE_AFFECTED:
        return mode != "relaxed"
    if mode == "strict":
        return True
    if mode == "relaxed":
        return False

    # Balanced mode: keep single-word names/orgs, tokenize multi-word ones.
    # For PERSON specifically, tokenize() swaps in _balanced_name_replacement
    # which only replaces the last name.
    word_count = len(text.strip().split())
    if norm_label in ("PERSON", "ORGANIZATION"):
        return word_count > 1
    return True


def _balanced_name_replacement(real_value: str, counters: dict) -> tuple[str, str, str] | None:
    """
    In balanced mode, replace only the last name in a multi-word person name.
    Returns (replacement_text, token, token_map_entry) or None if no replacement needed.
    """
    parts = real_value.strip().split()
    if len(parts) <= 1:
        return None  # single name — don't tokenize

    first_parts = ' '.join(parts[:-1])
    last_name = parts[-1]
    if len(last_name) < 2:
        # A 1-char surname ('Malcolm X') would mint a degenerate stored value
        # that the durable store refuses; don't tokenize rather than orphan it.
        return None

    counters["PERSON"] = counters.get("PERSON", 0) + 1
    uid = uuid.uuid4().hex[:6]
    token = f"[PERSON_{counters['PERSON']}_{uid}]"

    replacement = f"{first_parts} {token}"
    return replacement, token, last_name


# ── Blacklist term classification ─────────────────────────────────────────────

_BLACKLIST_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_BLACKLIST_IBAN_RE = re.compile(r"^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$")
_BLACKLIST_CC_RE = re.compile(r"^\d{12,19}$")
_BLACKLIST_PHONE_RE = re.compile(r"^\+?[\d\s\-().]{7,}$")
_BLACKLIST_IP_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$"
)


def _classify_blacklist_term(term: str) -> str:
    """Infer the semantic kind of a blacklisted term for its token label.

    Heuristic only — we don't hit GLiNER here because blacklist terms are
    already known-sensitive by definition; the label is purely a hint for
    the AI about what shape of value to expect in the token's place.
    """
    s = term.strip()
    if not s:
        return "VALUE"
    if _BLACKLIST_EMAIL_RE.match(s):
        return "EMAIL"
    # IP must come before PHONE — "192.168.1.15" matches the permissive phone
    # regex otherwise.
    if _BLACKLIST_IP_RE.match(s):
        return "IP"
    compact = s.replace(" ", "").replace("-", "")
    if _BLACKLIST_IBAN_RE.match(compact.upper()):
        return "IBAN"
    digits_only = re.sub(r"\D", "", s)
    if _BLACKLIST_CC_RE.match(digits_only) and len(digits_only) in (13, 14, 15, 16, 19):
        return "CREDIT_CARD"
    if _BLACKLIST_PHONE_RE.match(s) and len(digits_only) >= 7:
        return "PHONE"
    # Default: names, company names, project codenames, free-form strings.
    return "PERSON"
