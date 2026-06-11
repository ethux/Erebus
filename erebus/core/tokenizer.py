"""tokenize()/detokenize() — the main PII replacement pipeline.

Composes the detection passes: NER (via core.detect, called as a module
attribute so test patches on the owning module intercept), hard blacklist,
secret/structured regex, custom entities, and optional verifiers.
"""
from __future__ import annotations

import fnmatch
import re
import uuid

from . import detect, verify
from .escapes import _parse_escapes
from .modes import (
    DEFAULT_ALLOWED,
    DEFAULT_MODE,
    MODES,
    _balanced_name_replacement,
    _classify_blacklist_term,
    _should_tokenize_entity,
)
from .patterns import SECRET_PATTERNS, _overlaps_token_region, _token_regions
from .state import _reset_detector_state


def tokenize(text: str, extra_entities: list[str] | None = None,  # noqa: C901
             allowed_names: list[str] | None = None,
             mode: str = DEFAULT_MODE,
             blacklist: list[str] | None = None,
             verifiers: list[str] | None = None,
             verifier_llm_model: str = "gemma3:1b",
             verifier_openai_pf_url: str = "",
             _predicted_entities: list[dict] | None = None) -> tuple[str, dict]:
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

    # Start each call assuming full-strength detection; the predictor marks the
    # call degraded if NER could not run (see core.state._DETECTOR_STATE).
    if _predicted_entities is None:
        _reset_detector_state()

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
        if any(fnmatch.fnmatch(v, w) for w in _wild):  # noqa: SIM103
            return True
        return False

    # Step 1: GLiNER NER (fast, multilingual)
    # Run GLiNER on the cleaned text (~ stripped) so offsets match `result`
    try:
        entities = (_predicted_entities if _predicted_entities is not None
                    else detect._predict_entities_windowed(result))
        existing_token_regions = _token_regions(result)
        # Process right-to-left so replacements don't shift offsets
        for ent in sorted(entities, key=lambda e: e["start"], reverse=True):
            if _overlaps_token_region(ent["start"], ent["end"], existing_token_regions):
                continue
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

    # Step 2: Hard blacklist — case-insensitive whole-word/phrase match, always
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
            def _replace_blacklist(m, k=kind, ck=counter_key):
                counters[ck] = counters.get(ck, 0) + 1
                uid = uuid.uuid4().hex[:6]
                tok = f"[BLACKLIST_{k}_{counters[ck]}_{uid}]"
                token_map[tok] = m.group(0)  # preserve original casing
                return tok
            result = pattern.sub(_replace_blacklist, result)

    # Step 3: Regex secrets (always runs regardless of mode — secrets are always sensitive)
    for pattern, label in SECRET_PATTERNS:
        def _replace(m, lbl=label):
            counters[lbl] = counters.get(lbl, 0) + 1
            uid = uuid.uuid4().hex[:6]
            tok = f"[{lbl}_{counters[lbl]}_{uid}]"
            token_map[tok] = m.group(0)
            return tok
        result = re.sub(pattern, _replace, result)

    # Step 4: Custom entities from .erebus/pii-filter.json (exact match)
    if extra_entities:
        for entity in extra_entities:
            if entity in result:
                counters["SENSITIVE"] = counters.get("SENSITIVE", 0) + 1
                uid = uuid.uuid4().hex[:6]
                token = f"[SENSITIVE_{counters['SENSITIVE']}_{uid}]"
                token_map[token] = entity
                result = result.replace(entity, token)

    # Step 5: Optional verifiers - second-pass checks that run after
    # everything else and only flag spans not already covered by an
    # existing token or an allowlist entry. Concrete verifier modules
    # (e.g. piiranha, openai-pf, gemma) hook themselves into the
    # dispatcher in verify._run_verifiers.
    if verifiers:
        result, extra_tokens = verify._run_verifiers(
            result, verifiers, verifier_llm_model, verifier_openai_pf_url,
            _is_allowed, counters,
        )
        token_map.update(extra_tokens)

    return result, token_map


def detokenize(text: str, token_map: dict) -> str:
    """Swap tokens back to real values in Claude's response."""
    for _ in range(10):
        changed = False
        for token, real_value in token_map.items():
            if token in text:
                text = text.replace(token, real_value)
                changed = True
        if not changed:
            break
    return text
