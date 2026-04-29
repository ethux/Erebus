"""
Second-pass PII verifiers that run after GLiNER + regex + blacklist.

Each verifier is a pluggable pass that returns a list of `Span` objects
it thinks are PII. The filter pipeline tokenizes anything the earlier
passes didn't already cover.

Verifiers:
  * piiranha: iiiorg/piiranha-v1-detect-personal-information, an
              mdeberta-v3 fine-tune (~750MB, CPU-friendly). 17 PII
              types across six languages.

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


def parse_verifier_list(spec: str) -> list[str]:
    """Parse a config string like 'piiranha,gemma' into a list of names.

    Whitespace is trimmed, names are lowercased, blanks are skipped.
    """
    if not spec:
        return []
    return [s.strip().lower() for s in spec.split(",") if s.strip()]
