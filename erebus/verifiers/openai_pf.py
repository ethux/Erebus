"""
OpenAI Privacy Filter verifier.

Uses `openai/privacy-filter` (Apache 2.0), a 1.5B-param sparse MoE token
classifier with 50M active params. Eight categories: account_number,
private_address, private_date, private_email, private_person,
private_phone, private_url, secret.

Two deployment modes:
  * Local: load the model in-process via HuggingFace transformers.
  * Remote: POST to an HTTP endpoint (vLLM, FastAPI shim, HF Inference
    Endpoint, RunPod, etc) so a separate GPU box can do the work.

Remote endpoint contract:
    POST <url>          { "text": "<input>" }
    -> 200 OK           { "spans": [{ "start": int, "end": int,
                                       "text": str, "label": str }, ...] }

Model: https://huggingface.co/openai/privacy-filter
"""
import json
from functools import lru_cache

from . import Span

MODEL_ID = "openai/privacy-filter"

# OpenAI labels -> our internal taxonomy. Anything missing falls through
# to its own label name (uppercase) and the default min-length rules.
_LABEL_MAP = {
    "account_number": "BANK_ACCOUNT_NUMBER",
    "private_address": "ADDRESS",
    "private_date": "DATE_OF_BIRTH",
    "private_email": "EMAIL_ADDRESS",
    "private_person": "PERSON",
    "private_phone": "PHONE_NUMBER",
    "private_url": "SENSITIVE",
    "secret": "SECRET",
}


@lru_cache(maxsize=1)
def _get_pipeline():
    """Lazy-load the privacy-filter pipeline. Errors propagate to the caller."""
    from transformers import AutoTokenizer, AutoModelForTokenClassification, pipeline
    tok = AutoTokenizer.from_pretrained(MODEL_ID)
    model = AutoModelForTokenClassification.from_pretrained(MODEL_ID)
    return pipeline(
        "token-classification",
        model=model,
        tokenizer=tok,
        aggregation_strategy="simple",
    )


def _normalize(raw_entities: list[dict], text: str, threshold: float) -> list[Span]:
    """Convert HF pipeline entities to Span objects, filtering by score."""
    spans: list[Span] = []
    for ent in raw_entities:
        score = float(ent.get("score", 1.0))
        if score < threshold:
            continue
        label = ent.get("entity_group", ent.get("entity", ent.get("label", "")))
        for prefix in ("B-", "I-", "E-", "S-"):
            if label.startswith(prefix):
                label = label[len(prefix):]
                break
        start = int(ent.get("start", 0))
        end = int(ent.get("end", 0))
        if end <= start:
            continue
        mapped = _LABEL_MAP.get(label, label.upper())
        spans.append(Span(start=start, end=end, text=text[start:end], label=mapped))
    return spans


def _predict_remote(text: str, url: str, threshold: float, timeout: float) -> list[Span]:
    """POST to a user-provided endpoint. The remote service is responsible
    for running the model on whatever GPU it has."""
    try:
        import httpx
    except ImportError:
        return []
    try:
        resp = httpx.post(url, json={"text": text}, timeout=timeout)
        resp.raise_for_status()
        body = resp.json()
    except Exception:
        return []
    raw = body.get("spans") if isinstance(body, dict) else None
    if not isinstance(raw, list):
        return []
    return _normalize(raw, text, threshold)


def predict(text: str, threshold: float = 0.75,
            url: str = "", timeout: float = 30.0) -> list[Span]:
    """Return spans flagged by openai/privacy-filter above `threshold`.

    If `url` is set, POST to that endpoint instead of loading the model
    locally. Either way, returns [] on any failure so the rest of the
    filter pipeline keeps working.
    """
    if not text or not text.strip():
        return []

    if url:
        return _predict_remote(text, url, threshold, timeout)

    try:
        pipe = _get_pipeline()
    except Exception:
        return []
    try:
        raw = pipe(text)
    except Exception:
        return []
    return _normalize(raw, text, threshold)
