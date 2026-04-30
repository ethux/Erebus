"""
PII detection and tokenization.

Two-layer approach:
  1. GLiNER (urchade/gliner_multi_pii-v1) — fast local NER, multilingual
     Detects: names, emails, phones, addresses, orgs, IBANs, SSNs, IPs, etc.
  2. Regex — instant, zero deps, catches secrets/credentials
     Detects: API keys, tokens, passwords, private keys

Story leak detection (contextual/narrative PII) is handled separately
by Ministral in guards/files.py — it's slower and only runs when needed.

Filter modes:
  - strict:   tokenize everything — full names, orgs, all entity types
  - balanced: keep first names, tokenize last names and orgs with >1 word
  - relaxed:  only tokenize structured PII (emails, IBANs, keys, etc.) — skip names/orgs
"""

import fnmatch
import re
import uuid
from functools import lru_cache

# ── Filter modes ─────────────────────────────────────────────────────────────

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


# ── Escape handling ───────────────────────────────────────────────────────────

_ESCAPE_RE = re.compile(r'(\S+)~([)\]}"\'`.,:;!?]*)(?=\s|$)')
_PUNCTUATION_LEFT = "\"'`([{"
_PUNCTUATION_RIGHT = "\"'`)]}.,:;!?"
_MULTIWORD_ESCAPE_LOOKBACK = 4


def _strip_punctuation(word: str) -> str:
    """Strip surrounding quotes, parens, brackets, and trailing punctuation."""
    return word.lstrip(_PUNCTUATION_LEFT).rstrip(_PUNCTUATION_RIGHT)


def _parse_escapes(text: str) -> tuple[set[str], str]:
    """
    Parse ~ escape markers from text.

    Returns (escaped_words, cleaned_text). The cleaned text has all ~ markers
    stripped while preserving surrounding punctuation.

    Handles:
      - Trailing punctuation: "Smith~." "Smith~," "Smith~)"
      - Multi-word names: walks back up to _MULTIWORD_ESCAPE_LOOKBACK words
        so "Jan Willem de Vries~" escapes each part and all combined phrases
      - Surrounding quotes: ("Smith~") escapes "smith", not '"smith'
    """
    escaped: set[str] = set()

    for m in _ESCAPE_RE.finditer(text):
        clean = _strip_punctuation(m.group(1)).lower()
        if clean:
            escaped.add(clean)

    # Multi-word escape: walk back through preceding words and register both
    # individual words and the combined phrases (so GLiNER's multi-word span
    # match is also caught).
    words = text.split()
    for i, w in enumerate(words):
        if '~' not in w:
            continue
        clean_current = _strip_punctuation(w.replace('~', '')).lower()
        if not clean_current:
            continue
        phrase = [clean_current]
        for j in range(1, min(_MULTIWORD_ESCAPE_LOOKBACK + 1, i + 1)):
            prev = _strip_punctuation(words[i - j].replace('~', '')).lower()
            if not prev:
                break
            phrase.insert(0, prev)
            escaped.add(prev)
            escaped.add(' '.join(phrase))

    cleaned = _ESCAPE_RE.sub(r'\1\2', text)
    return escaped, cleaned


# ── Mode-aware entity filtering ──────────────────────────────────────────────

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


def _balanced_name_replacement(real_value: str, counters: dict) -> tuple[str, str, dict]:
    """
    In balanced mode, replace only the last name in a multi-word person name.
    Returns (replacement_text, token, token_map_entry) or None if no replacement needed.
    """
    parts = real_value.strip().split()
    if len(parts) <= 1:
        return None  # single name — don't tokenize

    first_parts = ' '.join(parts[:-1])
    last_name = parts[-1]

    counters["PERSON"] = counters.get("PERSON", 0) + 1
    uid = uuid.uuid4().hex[:6]
    token = f"[PERSON_{counters['PERSON']}_{uid}]"

    replacement = f"{first_parts} {token}"
    return replacement, token, last_name


# ── Main tokenize/detokenize ─────────────────────────────────────────────────

def tokenize(text: str, extra_entities: list[str] = None,
             allowed_names: list[str] = None,
             mode: str = DEFAULT_MODE,
             blacklist: list[str] = None,
             verifiers: list[str] = None,
             verifier_llm_model: str = "gemma3:1b",
             verifier_openai_pf_url: str = "") -> tuple[str, dict]:
    """
    Replace PII and secrets with reversible tokens.
    Returns (tokenized_text, token_map).
    Falls back to regex-only if GLiNER is not installed.
    Values in allowed_names are never tokenized.

    Modes:
      strict   - tokenize all detected PII
      balanced - keep first names, tokenize last names; keep single-word orgs
      relaxed  - only tokenize structured PII (emails, IBANs, keys, etc.)

    Verifiers:
      Optional second-pass checks run after GLiNER + regex + blacklist.
      Concrete verifier names are registered by their own modules. Each
      verifier only flags spans the earlier passes didn't touch.
    """
    if mode not in MODES:
        mode = DEFAULT_MODE

    token_map = {}
    counters = {}

    # ── Parse escape markers (~) ──────────────────────────────────────────────
    escaped, result = _parse_escapes(text)

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
    # Run GLiNER on the cleaned text (~ stripped) so offsets match `result`
    try:
        entities = _predict_entities(result)
        # Process right-to-left so replacements don't shift offsets
        for ent in sorted(entities, key=lambda e: e["start"], reverse=True):
            real_value = result[ent["start"]:ent["end"]]
            if _is_allowed(real_value):
                continue
            label = ent["label"].upper().replace(" ", "_")

            if not _should_tokenize_entity(label, real_value, mode):
                continue

            # Balanced mode: for person names, only replace the last name
            if mode == "balanced" and label == "PERSON":
                bal = _balanced_name_replacement(real_value, counters)
                if bal is None:
                    continue  # single name — skip
                replacement, token, last_name = bal
                token_map[token] = last_name
                result = result[:ent["start"]] + replacement + result[ent["end"]:]
            else:
                counters[label] = counters.get(label, 0) + 1
                uid = uuid.uuid4().hex[:6]
                token = f"[{label}_{counters[label]}_{uid}]"
                token_map[token] = real_value
                result = result[:ent["start"]] + token + result[ent["end"]:]
    except ImportError:
        pass  # gliner not installed — regex-only mode
    except Exception:
        pass  # model error — degrade gracefully

    # Step 2: Regex secrets (always runs regardless of mode — secrets are always sensitive)
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

    # Step 4: Hard blacklist — case-insensitive whole-word/phrase match, always
    # tokenized regardless of mode. This is the GDPR-safe layer: terms listed
    # in ~/.erebus/blacklist.txt or .erebus/blacklist.txt never reach the AI.
    # Token shape is [BLACKLIST_<KIND>_<N>_<uid>] so Claude has a hint about
    # the semantic type without seeing the value.
    if blacklist:
        for term in blacklist:
            term = term.strip()
            if not term:
                continue
            kind = _classify_blacklist_term(term)
            counter_key = f"BLACKLIST_{kind}"
            pattern = re.compile(
                rf"(?<!\w){re.escape(term)}(?!\w)",
                flags=re.IGNORECASE,
            )
            def _replace(m, k=kind, ck=counter_key):
                counters[ck] = counters.get(ck, 0) + 1
                uid = uuid.uuid4().hex[:6]
                tok = f"[BLACKLIST_{k}_{counters[ck]}_{uid}]"
                token_map[tok] = m.group(0)  # preserve original casing
                return tok
            result = pattern.sub(_replace, result)

    # Step 5: Optional verifiers - second-pass checks that run after
    # everything else and only flag spans not already covered by an
    # existing token or an allowlist entry. Concrete verifier modules
    # (e.g. piiranha, openai-pf, gemma) hook themselves into the
    # dispatcher in _run_verifiers.
    if verifiers:
        result, extra_tokens = _run_verifiers(
            result, verifiers, verifier_llm_model, verifier_openai_pf_url,
            _is_allowed, counters,
        )
        token_map.update(extra_tokens)

    return result, token_map


def _run_verifiers(text: str, verifiers: list[str], llm_model: str,
                   openai_pf_url: str, is_allowed, counters: dict) -> tuple[str, dict]:
    """Run each configured verifier and tokenize any spans it flags.

    Spans are ignored when they overlap an existing [TOKEN] in `text` or
    when `is_allowed` returns True for the span text. Returned (new_text,
    extra_token_map) — the caller merges extras into the main token map.
    """
    extra: dict = {}
    # Collect spans from every verifier in one go so we can de-duplicate and
    # process right-to-left without replacements shifting later offsets.
    collected = []
    for name in verifiers:
        n = name.strip().lower()
        if not n:
            continue
        spans: list = []
        if n == "piiranha":
            try:
                from .verifiers import piiranha
                spans = piiranha.predict(text)
            except Exception:
                spans = []
        elif n in ("openai-pf", "openai", "pf"):
            try:
                from .verifiers import openai_pf
                spans = openai_pf.predict(text, url=openai_pf_url)
            except Exception:
                spans = []
        # An unknown name is a silent no-op so the rest of the filter
        # keeps working when a verifier isn't installed.
        collected.extend(spans)

    if not collected:
        return text, extra

    # Drop spans inside existing [TOKEN_...] regions.
    token_regions = [(m.start(), m.end()) for m in re.finditer(r"\[[A-Z_]+_\d+_[0-9a-f]+\]", text)]
    def _in_token(start: int, end: int) -> bool:
        return any(ts <= start and end <= te for ts, te in token_regions)

    # Process right-to-left; drop duplicates and overlapping/allowed/in-token spans.
    seen: list[tuple[int, int]] = []
    result = text
    for sp in sorted(collected, key=lambda s: (s.start, -s.end), reverse=True):
        if sp.end <= sp.start:
            continue
        if _in_token(sp.start, sp.end):
            continue
        if any(max(sp.start, s) < min(sp.end, e) for s, e in seen):
            continue
        if is_allowed(sp.text):
            continue
        label = sp.label if sp.label else "SENSITIVE"
        counters[label] = counters.get(label, 0) + 1
        uid = uuid.uuid4().hex[:6]
        tok = f"[VERIFIED_{label}_{counters[label]}_{uid}]"
        extra[tok] = sp.text
        result = result[:sp.start] + tok + result[sp.end:]
        seen.append((sp.start, sp.end))
    return result, extra


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


def detokenize(text: str, token_map: dict) -> str:
    """Swap tokens back to real values in Claude's response."""
    for token, real_value in token_map.items():
        text = text.replace(token, real_value)
    return text
