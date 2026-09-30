"""Field rules deciding which source fields hold PII (spec 015 D2).

Pure: no store, config or connector import, so the editor scan, the sync worker and
the gateway can share it. Two rule sets live here. The laptop set is the editor
catalog's, unchanged (``tests/gateway/test_field_rules_laptop.py`` holds its golden
output). The gateway set (``gateway_rules``) adds the guards that keep IDs, flags,
dates, IPs and product names out of a tenant's known values.
"""
from __future__ import annotations

import re
from typing import Any

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
