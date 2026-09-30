"""Field rules deciding which source fields hold PII (spec 015 D2).

Pure: no store, config or connector import, so the editor scan, the sync worker and
the gateway can share it. Two rule sets live here. The laptop set is the editor
catalog's, unchanged (``tests/gateway/test_field_rules_laptop.py`` holds its golden
output). The gateway set (``gateway_rules``) adds the guards that keep IDs, flags,
dates, IPs and product names out of a tenant's known values.
"""
from __future__ import annotations

import ipaddress
import re
from collections import Counter
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .field_types import type_class
from .stop_words import STOP_WORDS

LAPTOP_EMAIL_RE = re.compile(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")
LAPTOP_PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,}$")

LAPTOP_ROLE_TO_CATEGORY = {
    "email": "EMAIL_ADDRESS",
    "phone": "PHONE_NUMBER",
    "mobile": "PHONE_NUMBER",
    "person": "PERSON",
    "name": "PERSON",
    "first_name": "PERSON",
    "last_name": "PERSON",
    "address": "ADDRESS",
    "identifier": "IDENTIFIER",
}

LAPTOP_LABEL_TO_CATEGORY = {
    "PERSON": "PERSON",
    "EMAIL_ADDRESS": "EMAIL_ADDRESS",
    "PHONE_NUMBER": "PHONE_NUMBER",
    "ADDRESS": "ADDRESS",
    "ORGANIZATION": "ORGANIZATION",
    "USERNAME": "USERNAME",
    "DATE_OF_BIRTH": "DATE_OF_BIRTH",
    "BANK_ACCOUNT_NUMBER": "BANK_ACCOUNT_NUMBER",
    "PASSPORT_NUMBER": "PASSPORT_NUMBER",
    "SOCIAL_SECURITY_NUMBER": "SOCIAL_SECURITY_NUMBER",
    "IBAN": "IBAN",
}


def laptop_category_from_field(field_name: str, pii_hint: str = "") -> tuple[str | None, str]:
    """The editor scan's category for a field by its name or connector hint."""
    hint = pii_hint.lower().strip()
    if hint in LAPTOP_ROLE_TO_CATEGORY:
        return LAPTOP_ROLE_TO_CATEGORY[hint], f"connector hint: {hint}"
    lower = field_name.lower()
    if "email" in lower:
        return "EMAIL_ADDRESS", "field name"
    if "phone" in lower or "mobile" in lower:
        return "PHONE_NUMBER", "field name"
    if lower in ("name", "first_name", "last_name", "full_name") or lower.endswith("_name"):
        return "PERSON", "field name"
    if "address" in lower or "street" in lower:
        return "ADDRESS", "field name"
    if "account" in lower or lower.endswith("_id"):
        return "IDENTIFIER", "field name"
    return None, ""


def laptop_classify_value(field_name: str, value: Any, pii_hint: str = "") -> tuple[str | None, str, str]:
    """The editor scan's (category, confidence, reason) for one value of a field."""
    text = "" if value is None else str(value).strip()
    if not text:
        return None, "low", ""
    if LAPTOP_EMAIL_RE.match(text):
        return "EMAIL_ADDRESS", "deterministic", "email pattern"
    if LAPTOP_PHONE_RE.match(text) and len(re.sub(r"\D", "", text)) >= 7:
        return "PHONE_NUMBER", "deterministic", "phone pattern"
    category, reason = laptop_category_from_field(field_name, pii_hint)
    if category:
        return category, "deterministic", reason
    return None, "low", ""


# --- Gateway rule set (spec 015 D2, D9, "Sync behaviour") ---------------------------

MIN_VALUE_CHARS = 3
AUTO_PATTERN_SHARE = 0.8  # of non-empty samples matching a pattern label's pattern
MODEL_HIT_SHARE = 0.2  # of non-empty samples with a model span
WHOLE_VALUE_SHARE = 0.8  # of model hits whose span covers the whole value
_MIN_NUMERIC_DIGITS = 6
_NUMERIC = re.compile(r"[0-9]+")

_FIRST = frozenset({"firstname", "givenname", "voornaam"})
_MIDDLE = frozenset({"middlename", "tussenvoegsel", "voorvoegsel"})
_LAST = frozenset({"lastname", "surname", "familyname", "achternaam"})
_ORGANIZATION = frozenset({"company", "companyname", "organisation", "organization", "accountname"})
_PERSON = frozenset({"fullname", "contactname", "customername"})
_PEOPLE = frozenset({"customers", "contacts", "users", "people", "persons", "employees", "members", "leads",
                     "klanten"})
_HINTS = {"organization": "ORGANIZATION", "person": "PERSON", "name": "PERSON", "email": "EMAIL_ADDRESS",
          "phone": "PHONE_NUMBER", "mobile": "PHONE_NUMBER", "address": "ADDRESS", "identifier": "IDENTIFIER"}


@dataclass(frozen=True)
class FieldSpec:
    """One column as a connector reports it. ``hint`` is set by app connectors only:
    database connectors' name-derived ``pii_hint`` is ignored."""

    name: str
    db_type: str = ""
    primary_key: bool = False
    hint: str = ""


@dataclass(frozen=True)
class FieldRule:
    """The gateway rules' decision for one field or name tuple (a ``source_fields`` row).

    ``parts`` names a tuple's columns in join order (first, middles, last); empty for a
    plain field. ``label`` is what a confirm would sync under (``None``: nothing found).
    """

    collection: str
    field: str
    db_type: str
    label: str | None
    decision: str  # auto, pending or ignored
    reason: str
    confirmable: bool = True
    parts: tuple[str, ...] = ()


Model = Callable[[str], Sequence[tuple[int, int, str]]]


def split_words(name: str) -> list[str]:
    """Lowercase words of a field or collection name: split on ``_``, ``-``, spaces,
    dots, camelCase and letter/digit changes."""
    words: list[str] = []
    for chunk in re.split(r"[\s_.\-]+", name):
        cur = ""
        for i, ch in enumerate(chunk):
            nxt = chunk[i + 1] if i + 1 < len(chunk) else ""
            prev = chunk[i - 1] if i else ""
            if cur and (
                (ch.isupper() and (prev.islower() or prev.isdigit() or (prev.isupper() and nxt.islower())))
                or (ch.isdigit() != prev.isdigit())
            ):
                words.append(cur.lower())
                cur = ""
            cur += ch
        if cur:
            words.append(cur.lower())
    return words


def name_part(field_name: str) -> str | None:
    """``first``, ``middle`` or ``last`` for a name-part column, else ``None``."""
    joined = "".join(split_words(field_name))
    for part, names in (("first", _FIRST), ("middle", _MIDDLE), ("last", _LAST)):
        if joined in names:
            return part
    return None


def _clean(value: Any) -> str:
    return "" if value is None else " ".join(str(value).split())


def join_name(first: Any, middles: Iterable[Any], last: Any) -> str | None:
    """A full name from its parts ("Jan de Vries"); ``None`` without a first and a last part."""
    head, tail = _clean(first), _clean(last)
    if not head or not tail:
        return None
    return " ".join([head, *(m for m in map(_clean, middles) if m), tail])


def tuple_value(rule: FieldRule, row: Mapping[str, Any]) -> str | None:
    """The full name a name-tuple rule syncs from one row."""
    first, *middles, last = (row.get(p) for p in rule.parts)
    return join_name(first, middles, last)


def clean_value(value: str) -> str:
    """The stored form of a known value: whitespace runs collapsed, ends trimmed."""
    return " ".join(value.split())


def reject_value(value: str, label: str, *, stop_words: Collection[str] = STOP_WORDS) -> str | None:
    """Why a synced value never becomes a known value, or ``None`` to keep it.

    Short values, numeric-only values under 6 digits, single-word PERSON values and
    single words on the stop-list are dropped. ``label`` is compared case-insensitively;
    ``stop_words`` are casefolded single words.
    """
    cleaned = clean_value(value)
    if len(cleaned) < MIN_VALUE_CHARS:
        return "short"
    if _NUMERIC.fullmatch(cleaned) and len(cleaned) < _MIN_NUMERIC_DIGITS:
        return "numeric"
    single = " " not in cleaned
    if single and label.upper() == "PERSON":
        return "single_word"
    if single and cleaned.casefold() in stop_words:
        return "stop_word"
    return None


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _at_least(count: int, total: int, share: float) -> bool:
    return total > 0 and count >= share * total - 1e-9


def _is_email(text: str) -> bool:
    return bool(LAPTOP_EMAIL_RE.match(text))


def _is_phone(text: str) -> bool:
    return bool(LAPTOP_PHONE_RE.match(text)) and len(re.sub(r"\D", "", text)) >= 7


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


_PATTERNS = {"EMAIL_ADDRESS": _is_email, "PHONE_NUMBER": _is_phone}


def _people_collection(collection: str) -> bool:
    words = split_words(collection)
    return bool(words) and words[-1] in _PEOPLE


def _is_address(words: list[str]) -> bool:
    for i, word in enumerate(words):
        if word in ("address", "street"):
            before = words[i - 1] if i else ""
            after = words[i + 1] if i + 1 < len(words) else ""
            if before not in ("ip", "mac") and after != "id":
                return True
    return False


def _named_label(collection: str, spec: FieldSpec) -> tuple[str | None, str | None, str]:
    """(label, pending reason or None, how it matched) from the hint or the field name."""
    hint = _HINTS.get(spec.hint.strip().lower())
    if hint:
        return hint, ("identifier" if hint == "IDENTIFIER" else None), "connector hint"
    words = split_words(spec.name)
    joined = "".join(words)
    if joined in _ORGANIZATION:
        return "ORGANIZATION", None, "name"
    if joined in _PERSON:
        return "PERSON", None, "name"
    if words == ["name"]:
        return "PERSON", (None if _people_collection(collection) else "name outside a people collection"), "name"
    if len(words) > 1 and words[-1] == "name":
        return "PERSON", "other *_name", "name"
    if "email" in joined:
        return "EMAIL_ADDRESS", None, "name"
    if "phone" in joined or "mobile" in joined:
        return "PHONE_NUMBER", None, "name"
    if _is_address(words):
        return "ADDRESS", None, "name"
    if "account" in words or words[-1:] == ["id"]:
        return "IDENTIFIER", "identifier", "name"
    return None, None, ""


def _model_rule(make, samples: list[str], model: Model) -> FieldRule | None:
    hits = [(text, spans) for text in samples if (spans := model(text))]
    if not _at_least(len(hits), len(samples), MODEL_HIT_SHARE) or not hits:
        return None
    labels: Counter[str] = Counter()
    whole: Counter[str] = Counter()
    whole_values = 0
    for text, spans in hits:
        covered = False
        for start, end, label in spans:
            norm = str(label).strip().upper().replace(" ", "_")
            labels[norm] += 1
            if text[start:end].strip() == text:
                whole[norm] += 1
                covered = True
        whole_values += covered
    if not _at_least(whole_values, len(hits), WHOLE_VALUE_SHARE):
        return make(labels.most_common(1)[0][0], "pending", "free text", confirmable=False)
    return make(whole.most_common(1)[0][0], "pending", "model flagged")


def _unnamed_rule(make, samples: list[str], model: Model | None) -> FieldRule:
    if not samples:
        return make(None, "ignored", "empty sample")
    if _at_least(sum(map(_is_email, samples)), len(samples), AUTO_PATTERN_SHARE):
        return make("EMAIL_ADDRESS", "auto", "pattern")
    if _at_least(sum(map(_is_phone, samples)), len(samples), AUTO_PATTERN_SHARE):
        return make("PHONE_NUMBER", "pending", "phone pattern only")
    flagged = _model_rule(make, samples, model) if model is not None else None
    return flagged or make(None, "ignored", "no pii signal")


def _field_rule(collection: str, spec: FieldSpec, values: list[Any], model: Model | None) -> FieldRule:
    def make(label, decision, reason, confirmable=True):
        return FieldRule(collection, spec.name, spec.db_type, label, decision, reason, confirmable)

    cls = type_class(spec.db_type)
    if cls == "binary":
        return make(None, "ignored", "binary type", confirmable=False)
    if cls == "unknown":
        return make(None, "pending", "unsupported type")
    if cls != "text":
        return make(None, "ignored", "non-text type")
    if spec.primary_key or split_words(spec.name) == ["id"]:
        return make("IDENTIFIER", "pending", "primary key")
    samples = [t for t in map(_text, values) if t]
    label, pending, how = _named_label(collection, spec)
    if label is None:
        return _unnamed_rule(make, samples, model)
    if pending:
        return make(label, "pending", pending)
    if not samples:
        return make(label, "pending", "empty sample")
    if label in _PATTERNS:
        if not _at_least(sum(map(_PATTERNS[label], samples)), len(samples), AUTO_PATTERN_SHARE):
            return make(label, "pending", "pattern below threshold")
        how = f"{how} and pattern"
    if label == "ADDRESS" and any(map(_is_ip, samples)):
        return make(label, "pending", "ip-shaped samples")
    return make(label, "auto", how)


def _name_tuple(collection: str, fields: Sequence[FieldSpec], rows: list[Mapping[str, Any]]):
    """(tuple rule or None, rule per name-part column) for one collection."""
    groups: dict[str, list[FieldSpec]] = {"first": [], "middle": [], "last": []}
    for spec in fields:
        part = name_part(spec.name)
        if part and type_class(spec.db_type) == "text":
            groups[part].append(spec)
    named = [spec for group in groups.values() for spec in group]

    def part_rules(reason: str) -> dict[str, FieldRule]:
        return {s.name: FieldRule(collection, s.name, s.db_type, None, "ignored", reason, False) for s in named}

    if len(groups["first"]) > 1 or len(groups["last"]) > 1:
        return None, part_rules("ambiguous name parts")
    if not groups["first"] or not groups["last"]:
        return None, part_rules("pair required")
    order = [*groups["first"], *sorted(groups["middle"], key=fields.index), *groups["last"]]
    parts = tuple(s.name for s in order)
    rule = FieldRule(collection, "+".join(parts), "+".join(s.db_type for s in order), "PERSON", "auto",
                     "name tuple", True, parts)
    if not any(tuple_value(rule, row) for row in rows):
        rule = FieldRule(collection, rule.field, rule.db_type, "PERSON", "pending", "empty sample", True, parts)
    return rule, part_rules("in name tuple")


def gateway_rules(
    collection: str,
    fields: Sequence[FieldSpec],
    rows: Iterable[Mapping[str, Any]],
    *,
    model: Model | None = None,
) -> list[FieldRule]:
    """Decide every field of one sampled collection, plus its name tuple if it has one.

    ``rows`` are the sampled records (field name to value). ``model`` finds spans in a
    value (GLiNER in the worker; ``None`` when model review is off) and is asked only
    about text fields no rule decided; its errors propagate.
    """
    sample = list(rows)
    fields = list(fields)
    name_rule, parts = _name_tuple(collection, fields, sample)
    out = [parts.get(spec.name) or _field_rule(collection, spec, [r.get(spec.name) for r in sample], model)
           for spec in fields]
    if name_rule is not None:
        out.append(name_rule)
    return out
