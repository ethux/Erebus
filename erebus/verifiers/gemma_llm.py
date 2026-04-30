"""
Gemma 3 1B contextual PII verifier.

Looks for PII that GLiNER and openai/privacy-filter can't catch on pure
structural grounds: narrative leaks ("the engineer who owns the Rotterdam
office"),
nicknames, obliquely identifying context, and anything else that requires
reasoning rather than pattern recognition.

Runs via Ollama so users don't need another runtime; defaults to
`gemma3:1b` but any Ollama tag can be configured. Returns an empty list
if Ollama isn't running, the model isn't pulled, or the response doesn't
parse — the rest of the filter keeps working.
"""
import json
import re

from . import Span

_SYSTEM_PROMPT = """You are a privacy verifier. Your only job is to flag personally identifying
information (PII) or story-level leaks in a piece of text that another
layer has already processed.

Rules:
  * Flag only real PII or identifying context. Do not flag pronouns,
    job titles alone, or common nouns.
  * Return tokens like [PERSON_1_abc] unchanged - they are already handled.
  * Prefer false negatives over false positives.
  * If in doubt, do not flag.

Respond with ONLY a JSON object matching this schema:
  {"spans": [{"text": "<exact substring>", "label": "<kind>"}]}

Valid labels: PERSON, EMAIL_ADDRESS, PHONE_NUMBER, ADDRESS, ORGANIZATION,
IBAN, CREDIT_CARD_NUMBER, SOCIAL_SECURITY_NUMBER, DATE_OF_BIRTH, IP_ADDRESS,
PASSPORT_NUMBER, BANK_ACCOUNT_NUMBER, USERNAME, SENSITIVE.

If nothing is flagged return {"spans": []}."""


def _find_all_occurrences(haystack: str, needle: str) -> list[tuple[int, int]]:
    """Return all non-overlapping (start, end) offsets of needle in haystack."""
    if not needle:
        return []
    out = []
    pos = 0
    while True:
        idx = haystack.find(needle, pos)
        if idx < 0:
            break
        out.append((idx, idx + len(needle)))
        pos = idx + len(needle)
    return out


def predict(text: str, model: str = "gemma3:1b") -> list[Span]:
    """Ask the LLM for any PII the prior passes missed. Best-effort."""
    if not text or not text.strip():
        return []
    try:
        import ollama  # noqa: F401
    except ImportError:
        return []
    try:
        import ollama
        resp = ollama.chat(
            model=model,
            messages=[
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": text},
            ],
            format="json",
            options={"temperature": 0, "num_predict": 400},
        )
        body = resp["message"]["content"]
    except Exception:
        return []

    # Ollama with format=json is usually strict but be defensive.
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        # Last-chance regex extract of the first {...} block.
        m = re.search(r"\{.*\}", body or "", re.DOTALL)
        if not m:
            return []
        try:
            data = json.loads(m.group(0))
        except json.JSONDecodeError:
            return []

    raw_spans = data.get("spans") if isinstance(data, dict) else None
    if not isinstance(raw_spans, list):
        return []

    spans: list[Span] = []
    for s in raw_spans:
        if not isinstance(s, dict):
            continue
        needle = s.get("text")
        label = s.get("label", "SENSITIVE")
        if not isinstance(needle, str) or not needle:
            continue
        label = str(label).upper().replace(" ", "_")
        # The LLM may hallucinate spans that aren't in the text. We only
        # trust spans we can actually locate by exact match.
        for start, end in _find_all_occurrences(text, needle):
            spans.append(Span(start=start, end=end, text=needle, label=label))
    return spans
