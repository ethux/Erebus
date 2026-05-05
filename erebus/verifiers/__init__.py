"""
Second-pass PII verifiers that run after GLiNER + regex + blacklist.

Each verifier is a pluggable pass that returns a list of `Span` objects
it thinks are PII. The filter pipeline tokenizes anything the earlier
passes didn't already cover.

Verifiers:
  * piiranha:  iiiorg/piiranha-v1-detect-personal-information, an
               mdeberta-v3 fine-tune (~750MB, CPU-friendly). 17 PII
               types across six languages.
  * openai-pf: openai/privacy-filter, a 1.5B sparse MoE token classifier
               (50M active params). Bigger and GPU-friendly. Apache 2.0.
  * gemma:     a small local LLM (Gemma 3 1B by default via Ollama) that
               flags contextual / narrative leaks a NER model can't see
               ("the engineer who runs the Rotterdam office").

Only ONE NER verifier runs at a time - piiranha and openai-pf overlap in
purpose, so the user picks one based on hardware and parse_verifier_list
keeps the first NER in the list and drops the rest. Other verifier kinds
(e.g. an LLM contextual pass) layer on top.

All verifiers degrade to a no-op if the underlying model is missing, so
the rest of the filter keeps working in environments without them.
"""
from dataclasses import dataclass


@dataclass
class Span:
    """A flagged PII span. start/end are character offsets into the source text."""
    start: int
    end: int
    text: str
    label: str  # normalized entity label (matches filter._MIN_LENGTHS keys)


_NER_VERIFIERS = {"piiranha", "openai-pf", "openai", "pf"}


def parse_verifier_list(spec: str) -> list[str]:
    """Parse a config string like 'piiranha,gemma' into a list of names.

    Whitespace is trimmed, names are lowercased, blanks are skipped.

    Only one NER verifier may run at a time (piiranha and openai-pf both
    do structural span detection and would be wasteful together). If the
    spec lists more than one NER, the first one is kept and the rest are
    dropped. Non-NER verifiers (e.g. gemma) pass through unchanged.
    """
    if not spec:
        return []
    items = [s.strip().lower() for s in spec.split(",") if s.strip()]
    out: list[str] = []
    seen_ner = False
    for name in items:
        if name in _NER_VERIFIERS:
            if seen_ner:
                continue
            seen_ner = True
        out.append(name)
    return out
