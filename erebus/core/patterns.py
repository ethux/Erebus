"""Token-shape and secret/structured-PII regex patterns.

Leaf module (stdlib ``re`` only). TOKEN_RE is the ONE canonical token shape
shared by every adapter (specs/004-core-pii-boundary T020): it accepts six or
more hex chars and the CATALOG_* alternative so detokenization and identity
checks never diverge between the proxy, shim, and file checker.
"""
from __future__ import annotations

import re

# Canonical token shape: [LABEL_N_<hex6+>] or [CATALOG_<NAME>_<hex6+>].
TOKEN_RE = re.compile(r"\[(?:[A-Z_]+_\d+_[0-9a-f]{6,}|CATALOG_[A-Z0-9_]+_[0-9a-f]{6,})\]")

# Exact minting shape: tokenize() mints [LABEL_N_<exactly 6 hex>] placeholders.
# Kept separate from TOKEN_RE so already-minted regions are recognised with the
# same (narrower) shape the tokenizer produces.
_TOKEN_PLACEHOLDER_RE = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6}\]")


def _token_regions(text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in _TOKEN_PLACEHOLDER_RE.finditer(text)]


def _overlaps_token_region(start: int, end: int,
                           regions: list[tuple[int, int]]) -> bool:
    return any(start < token_end and end > token_start
               for token_start, token_end in regions)


def _replace_outside_tokens(text: str, value: str, token: str) -> str:
    """Replace ``value`` with ``token`` everywhere it appears EXCEPT inside an
    existing token region, so already-minted tokens are never rewritten."""
    if value not in text:
        return text
    chunks = []
    cursor = 0
    for match in TOKEN_RE.finditer(text):
        chunks.append(text[cursor:match.start()].replace(value, token))
        chunks.append(match.group(0))
        cursor = match.end()
    chunks.append(text[cursor:].replace(value, token))
    return "".join(chunks)


def _replace_outside_tokens_word(text: str, value: str, token: str) -> str:
    """Like ``_replace_outside_tokens`` but only replaces whole-word matches.

    Used for short known values (balanced-mode surnames, acronyms) where the
    bare substring replace would rewrite the inside of unrelated words — a
    stored 'Li' must tokenize "ask Li" but never mangle "Lithium"."""
    if value not in text:
        return text
    pattern = re.compile(rf"(?<!\w){re.escape(value)}(?!\w)")
    chunks = []
    cursor = 0
    for match in TOKEN_RE.finditer(text):
        chunks.append(pattern.sub(token, text[cursor:match.start()]))
        chunks.append(match.group(0))
        cursor = match.end()
    chunks.append(pattern.sub(token, text[cursor:]))
    return "".join(chunks)

# ── Regex: structured PII, secrets, and credentials ───────────────────────────

# A line break in a footerless PEM body: a real one, or the two characters \n in a JSON/.env value.
_PEM_EOL = r"(?:\r?\n|(?:\\r)?\\n)"

SECRET_PATTERNS = [
    # Structured PII (high confidence, cheap, and should not depend on GLiNER)
    # Trailing lookaheads: reject continuations (word char, hyphen, or a dot
    # that starts another label) but allow a sentence-ending period.
    (r"(?i)(?<![\w.+%-])[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}(?![\w\-])(?!\.[\w\-])", "EMAIL_ADDRESS"),
    # Phone numbers in international +CC form, including space/paren/hyphen grouping
    # (e.g. a WhatsApp sender label "+31 6 12345678"). High confidence and GLiNER-
    # independent: requires a leading + and 8+ digit-ish chars, so it does not fire on
    # short "+5" / "C++"-style tokens. National (no-+) forms are left to NER.
    (r"(?<![\w+])\+\d[\d ().-]{6,18}\d(?!\w)", "PHONE_NUMBER"),
    # Specific token formats (high confidence)
    (r"sk-[a-zA-Z0-9\-_]{20,}",              "API_KEY"),
    (r"ghp_[a-zA-Z0-9]{36}",                  "GITHUB_TOKEN"),
    (r"glpat-[a-zA-Z0-9\-_]{20,}",            "GITLAB_TOKEN"),
    (r"xox[baprs]-[a-zA-Z0-9\-]+",            "SLACK_TOKEN"),
    (r"AKIA[0-9A-Z]{16}",                      "AWS_KEY"),
    # Whole PEM block (header, base64 body, footer). With no footer: the header plus the
    # whole lines after it that are base64 or Proc-Type/DEK-Info, so a truncated key's
    # body is not left raw. (?:[A-Z]+ )* also matches PKCS#8 "BEGIN PRIVATE KEY".
    # The body may not cross another "-----": a lazy [\s\S]*? rescanned to the end of
    # the text for every footerless header (quadratic, GIL held).
    (r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"
     r"(?:(?:(?!-----)[\s\S])*-----END (?:[A-Z]+ )*PRIVATE KEY-----"
     rf"|(?:{_PEM_EOL}+[ \t]*(?:(?:Proc-Type|DEK-Info):[^\r\n\\]*"
     rf"|[A-Za-z0-9+/=]+[ \t]*(?={_PEM_EOL}|\Z)))*)",
     "PRIVATE_KEY"),
    # Key=value assignments (only match actual assignments, not mentions)
    (r"(?i)password\s*[:=]\s*['\"]?\S{6,}",   "PASSWORD"),
    (r"(?i)secret\s*[:=]\s*['\"]?\S{6,}",     "SECRET"),
    (r'(?i)api[_\-]?key\s*[:=]\s*[\'"]?\S{8,}', "API_KEY"),
    (r'(?i)token\s*[:=]\s*[\'"]?\S{8,}',      "TOKEN"),
]

# IBAN (ISO 13616), compact or space-grouped in fours, uppercase. Kept out of
# SECRET_PATTERNS because the shape alone is too loose: the mod-97 check keeps
# uppercase IDs and hashes of the same shape from being tokenized.
_IBAN_RE = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}"
    r"(?:[A-Z0-9]{11,30}|(?: [A-Z0-9]{4}){2,7}(?: [A-Z0-9]{1,3})?)(?![A-Za-z0-9])"
)


def _iban_checksum_ok(raw: str) -> bool:
    compact = raw.replace(" ", "")
    if not 15 <= len(compact) <= 34:
        return False
    return int("".join(str(int(c, 36)) for c in compact[4:] + compact[:4])) % 97 == 1


def _longest_valid_prefix(raw: str) -> str:
    while not _iban_checksum_ok(raw):
        if " " not in raw:
            return ""
        raw = raw.rsplit(" ", 1)[0]
    return raw


def iban_spans(text: str) -> list[tuple[int, int, str]]:
    """``(start, end, "IBAN")`` for every checksum-valid IBAN in ``text``.

    A grouped match can swallow following all-caps words ("... 7034 VOOR DE"), even
    a second IBAN; trailing groups are dropped until the checksum holds, and the
    scan resumes right after the kept IBAN (or the failed start) so nothing
    swallowed is skipped.
    """
    spans = []
    pos = 0
    while m := _IBAN_RE.search(text, pos):
        raw = _longest_valid_prefix(m.group(0))
        if raw:
            spans.append((m.start(), m.start() + len(raw), "IBAN"))
            pos = m.start() + len(raw)
        else:
            pos = m.start() + 1
    return spans
