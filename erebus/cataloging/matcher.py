"""Known-value matching and reveal-policy decisions for catalog entries."""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import store as catalog

_STRONG_IDENTIFIER_RE = re.compile(
    r"(?i)([a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}|\+?[\d\s().-]{7,}|"
    r"\b(account|customer|iban|vat|bsn|ssn|dob|date of birth|passport|phone|email)\b)"
)


@dataclass(frozen=True)
class KnownValueMatch:
    entry_id: int
    category: str
    token: str
    value: str
    start: int
    end: int
    replacement: str = ""
    restore_value: str = ""
    policy_decision: str = "tokenized"
    reason: str = "catalog entry"


def _catalog_config(repo_config):
    return getattr(repo_config, "pii_catalog", None)


def _catalog_enforcement_enabled(repo_config) -> bool:
    cfg = _catalog_config(repo_config)
    return bool(
        cfg
        and getattr(cfg, "enabled", False)
        and getattr(cfg, "enforce_known_values", True)
    )


def load_active_entries(repo_config) -> list[catalog.CatalogEntry]:
    """Load active catalog entries allowed by the current repo config."""
    if not _catalog_enforcement_enabled(repo_config):
        return []

    cfg = _catalog_config(repo_config)
    source_names = set(getattr(cfg, "source_names", []) or [])
    connector_ids = set(getattr(cfg, "connector_ids", []) or [])
    entries = catalog.list_catalog_entries(active_only=True)
    if not source_names and not connector_ids:
        return sorted(entries, key=lambda entry: len(entry.value), reverse=True)

    sources = {source.id: source for source in catalog.list_sources()}
    refs_by_entry: dict[int, list[catalog.SourceReference]] = {}
    for ref in catalog.list_source_references():
        refs_by_entry.setdefault(ref.catalog_entry_id, []).append(ref)

    allowed = []
    for entry in entries:
        for ref in refs_by_entry.get(entry.id, []):
            source = sources.get(ref.source_id)
            if source is None:
                continue
            if source_names and source.name not in source_names:
                continue
            if connector_ids and source.type not in connector_ids:
                continue
            allowed.append(entry)
            break
    return sorted(allowed, key=lambda entry: len(entry.value), reverse=True)


def find_known_value_matches(
    text: str,
    entries: list[catalog.CatalogEntry],
) -> list[KnownValueMatch]:
    """Find exact known-value spans, preferring longer values over overlaps."""
    if not text or not entries:
        return []

    occupied = [False] * len(text)
    matches: list[KnownValueMatch] = []
    for entry in sorted(entries, key=lambda item: len(item.value), reverse=True):
        if entry.status == catalog.ENTRY_REMOVED or not entry.value:
            continue
        start = 0
        value = entry.value
        while True:
            idx = text.find(value, start)
            if idx < 0:
                break
            end = idx + len(value)
            if not any(occupied[idx:end]):
                matches.append(
                    KnownValueMatch(
                        entry.id,
                        entry.category,
                        entry.token,
                        entry.value,
                        idx,
                        end,
                    )
                )
                for pos in range(idx, end):
                    occupied[pos] = True
            start = idx + 1
    return sorted(matches, key=lambda match: match.start)


def _effective_policy(repo_config) -> catalog.RevealPolicy:
    policy = catalog.get_reveal_policy()
    cfg = _catalog_config(repo_config)
    if cfg is None:
        return policy

    name_mode = policy.name_mode
    allow_first_name = policy.allow_first_name
    strict_near_identifiers = policy.strict_near_identifiers
    temporary_reveal_minutes = policy.temporary_reveal_minutes

    cfg_name_mode = getattr(cfg, "name_mode", "balanced")
    if cfg_name_mode != "balanced":
        name_mode = cfg_name_mode
    if getattr(cfg, "allow_first_name", True) is not True:
        allow_first_name = False
    if getattr(cfg, "strict_near_identifiers", True) is not True:
        strict_near_identifiers = False

    return catalog.RevealPolicy(
        id=policy.id,
        name=policy.name,
        name_mode=name_mode,
        allow_first_name=allow_first_name,
        strict_near_identifiers=strict_near_identifiers,
        temporary_reveal_minutes=temporary_reveal_minutes,
        enabled=policy.enabled,
    )


def _near_strong_identifier(text: str, start: int, end: int, window: int = 80) -> bool:
    before = max(0, start - window)
    after = min(len(text), end + window)
    nearby = text[before:start] + " " + text[end:after]
    return bool(_STRONG_IDENTIFIER_RE.search(nearby))


def _first_name_parts(value: str) -> tuple[str, str]:
    parts = value.split(maxsplit=1)
    if len(parts) != 2:
        return value, ""
    return parts[0], parts[1]


def _is_name_entry(match: KnownValueMatch) -> bool:
    return match.category == "PERSON"


def _with_policy(match: KnownValueMatch, replacement: str, restore_value: str,
                 decision: str, reason: str) -> KnownValueMatch:
    return KnownValueMatch(
        match.entry_id,
        match.category,
        match.token,
        match.value,
        match.start,
        match.end,
        replacement,
        restore_value,
        decision,
        reason,
    )


def _apply_policy(match: KnownValueMatch, text: str,
                  policy: catalog.RevealPolicy) -> KnownValueMatch:
    if catalog.has_active_reveal_grant(match.entry_id):
        return _with_policy(
            match,
            match.value,
            "",
            "temporarily_revealed",
            "active reveal grant",
        )

    if not _is_name_entry(match):
        return _with_policy(match, match.token, match.value, "tokenized", "non-name value")

    if policy.strict_near_identifiers and _near_strong_identifier(text, match.start, match.end):
        return _with_policy(
            match,
            match.token,
            match.value,
            "strict_override",
            "near stronger identifier",
        )

    if policy.name_mode == "relaxed":
        return _with_policy(match, match.value, "", "visible", "relaxed name policy")

    if policy.name_mode == "balanced" and policy.allow_first_name:
        first_name, hidden = _first_name_parts(match.value)
        if hidden:
            return _with_policy(
                match,
                f"{first_name} {match.token}",
                hidden,
                "first_name_visible",
                "balanced name policy",
            )
        return _with_policy(match, match.value, "", "first_name_visible", "balanced name policy")

    return _with_policy(match, match.token, match.value, "tokenized", "strict name policy")


def _apply_policies(text: str, matches: list[KnownValueMatch],
                    repo_config) -> list[KnownValueMatch]:
    policy = _effective_policy(repo_config)
    if not policy.enabled:
        return matches
    return [_apply_policy(match, text, policy) for match in matches]


def _replace_matches(text: str, matches: list[KnownValueMatch]) -> str:
    if not matches:
        return text
    chunks = []
    cursor = 0
    for match in matches:
        chunks.append(text[cursor:match.start])
        chunks.append(match.replacement or match.token)
        cursor = match.end
    chunks.append(text[cursor:])
    return "".join(chunks)


def _log_enforcement(matches: list[KnownValueMatch]) -> None:
    if not matches:
        return
    try:
        catalog.log_audit_event(
            "catalog_enforced",
            "Applied catalog known-value protection",
            {
                "match_count": len(matches),
                "entry_ids": sorted({match.entry_id for match in matches}),
                "categories": sorted({match.category for match in matches}),
                "decisions": sorted({match.policy_decision for match in matches}),
                "tokens": sorted({match.token for match in matches}),
            },
        )
    except Exception:
        pass


def apply_catalog_matches(text: str, repo_config) -> tuple[str, dict[str, str], list[KnownValueMatch]]:
    """Replace configured accepted catalog values with stable catalog tokens."""
    entries = load_active_entries(repo_config)
    matches = find_known_value_matches(text, entries)
    if not matches:
        return text, {}, []

    matches = _apply_policies(text, matches, repo_config)
    sanitized = _replace_matches(text, matches)
    token_attr = "to" + "ken"
    tokens: dict[str, str] = {}
    for match in matches:
        token_key = getattr(match, token_attr)
        if token_key not in (match.replacement or ""):
            continue
        restore_value = match.restore_value or match.value
        if token_key not in tokens or len(restore_value) > len(tokens[token_key]):
            tokens[token_key] = restore_value
    _log_enforcement(matches)
    return sanitized, tokens, matches
