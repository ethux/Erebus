"""Verifier dispatch — optional second-pass PII checks after the main passes.

Concrete verifier modules (piiranha, openai-pf, gemma) are imported lazily so
the filter keeps working when a verifier isn't installed.
"""
from __future__ import annotations

import uuid

from .patterns import _overlaps_token_region, _token_regions


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
                from ..verifiers import piiranha
                spans = piiranha.predict(text)
            except Exception:
                spans = []
        elif n in ("openai-pf", "openai", "pf"):
            try:
                from ..verifiers import openai_pf
                spans = openai_pf.predict(text, url=openai_pf_url)
            except Exception:
                spans = []
        elif n in ("gemma", "llm"):
            try:
                from ..verifiers import gemma_llm
                spans = gemma_llm.predict(text, model=llm_model)
            except Exception:
                spans = []
        # An unknown name is a silent no-op so the rest of the filter
        # keeps working when a verifier isn't installed.
        collected.extend(spans)

    if not collected:
        return text, extra

    # Drop spans overlapping existing token placeholders.
    token_regions = _token_regions(text)

    # Process right-to-left; drop duplicates and overlapping/allowed/in-token spans.
    seen: list[tuple[int, int]] = []
    result = text
    for sp in sorted(collected, key=lambda s: (s.start, -s.end), reverse=True):
        if sp.end <= sp.start:
            continue
        if _overlaps_token_region(sp.start, sp.end, token_regions):
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
