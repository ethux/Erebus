"""
Piiranha PII verifier (local / CPU-friendly).

Uses `iiiorg/piiranha-v1-detect-personal-information`, an mdeberta-v3-base
fine-tune that supports 17 PII types across six languages. ~750MB on disk
and fast enough on CPU.

Pair this with the bigger `openai-pf` verifier when you have GPU available.
The two have different failure modes, so running both gives the best
recall on labeled corpora at the cost of extra latency.

Model: https://huggingface.co/iiiorg/piiranha-v1-detect-personal-information
"""
from functools import lru_cache

from . import Span

MODEL_ID = "iiiorg/piiranha-v1-detect-personal-information"

# Piiranha's label taxonomy mapped to our internal taxonomy. Anything not
# listed here falls through to its own uppercased label name.
_LABEL_MAP = {
    "GIVENNAME": "PERSON",
    "SURNAME": "PERSON",
    "EMAIL": "EMAIL_ADDRESS",
    "USERNAME": "USERNAME",
    "TELEPHONENUM": "PHONE_NUMBER",
    "TELEPHONE": "PHONE_NUMBER",
    "SOCIALNUM": "SOCIAL_SECURITY_NUMBER",
    "CREDITCARDNUMBER": "CREDIT_CARD_NUMBER",
    "IDCARDNUM": "PASSPORT_NUMBER",
    "DRIVERLICENSENUM": "PASSPORT_NUMBER",
    "TAXNUM": "PASSPORT_NUMBER",
    "ACCOUNTNUM": "BANK_ACCOUNT_NUMBER",
    "DATEOFBIRTH": "DATE_OF_BIRTH",
    "IP_ADDRESS": "IP_ADDRESS",
    "STREET": "ADDRESS",
    "CITY": "ADDRESS",
    "ZIPCODE": "ADDRESS",
    "BUILDINGNUM": "ADDRESS",
}


@lru_cache(maxsize=1)
def _get_pipeline():
    """Lazy-load the Piiranha token-classification pipeline."""
    from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForTokenClassification.from_pretrained(MODEL_ID)
    return pipeline(
        "token-classification",
        model=model,
        tokenizer=tok,
        aggregation_strategy="simple",
    )


def predict(text: str, threshold: float = 0.75) -> list[Span]:
    """Run Piiranha on `text` and return spans above `threshold`.

    Returns an empty list on any failure so the rest of the filter
    pipeline degrades gracefully.
    """
    if not text or not text.strip():
        return []
    try:
        pipe = _get_pipeline()
    except Exception:
        return []

    try:
        raw = pipe(text)
    except Exception:
        return []

    spans: list[Span] = []
    for ent in raw:
        score = float(ent.get("score", 0.0))
        if score < threshold:
            continue
        label = ent.get("entity_group", ent.get("entity", "")).upper()
        for prefix in ("B-", "I-", "E-", "S-"):
            if label.startswith(prefix):
                label = label[len(prefix):]
                break
        start = int(ent.get("start", 0))
        end = int(ent.get("end", 0))
        if end <= start:
            continue
        mapped = _LABEL_MAP.get(label, label)
        spans.append(Span(start=start, end=end, text=text[start:end], label=mapped))
    return spans
