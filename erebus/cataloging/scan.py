"""Source scanning and PII discovery for the local catalog."""
from __future__ import annotations

import re
from typing import Any

from . import sources as source_plugins
from . import store as catalog

_EMAIL_RE = re.compile(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$")
_PHONE_RE = re.compile(r"^\+?[\d\s().-]{7,}$")

_ROLE_TO_CATEGORY = {
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

_LABEL_TO_CATEGORY = {
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


def _category_from_field(field_name: str, pii_hint: str = "") -> tuple[str | None, str]:
    hint = pii_hint.lower().strip()
    if hint in _ROLE_TO_CATEGORY:
        return _ROLE_TO_CATEGORY[hint], f"connector hint: {hint}"
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


def classify_value(field_name: str, value: Any, pii_hint: str = "") -> tuple[str | None, str, str]:
    text = "" if value is None else str(value).strip()
    if not text:
        return None, "low", ""
    if _EMAIL_RE.match(text):
        return "EMAIL_ADDRESS", "deterministic", "email pattern"
    if _PHONE_RE.match(text) and len(re.sub(r"\D", "", text)) >= 7:
        return "PHONE_NUMBER", "deterministic", "phone pattern"
    category, reason = _category_from_field(field_name, pii_hint)
    if category:
        return category, "deterministic", reason
    return None, "low", ""


def model_assisted_findings(value: Any) -> list[tuple[str, str, str]]:
    """Return model-assisted PII candidates as (category, text, reason)."""
    text = "" if value is None else str(value).strip()
    if not text or len(text) > 500:
        return []
    try:
        from ..core import predict_entities
        entities = predict_entities(text)
    except Exception:
        return []
    found = []
    for entity in entities:
        label = entity.get("label", "").upper().replace(" ", "_")
        category = _LABEL_TO_CATEGORY.get(label)
        ent_text = entity.get("text") or text[entity.get("start", 0):entity.get("end", 0)]
        if category and ent_text:
            found.append((category, ent_text, f"model label: {label}"))
    return found


def _scan_scopes(source: catalog.ExternalDataSource,
                 requested_scopes: list[dict[str, Any]] | None,
                 row_limit: int | None) -> list[catalog.ScanScope]:
    if requested_scopes:
        return [
            catalog.ScanScope(
                id=0,
                source_id=source.id,
                dataset=item["dataset"],
                columns=item.get("columns") or [],
                row_limit=row_limit,
                enabled=True,
            )
            for item in requested_scopes
        ]
    scopes = catalog.list_scopes(source.id)
    if scopes:
        return scopes
    settings = dict(source.connector_config)
    if source.location_ref and "path" not in settings:
        settings["path"] = source.location_ref
    row_source = source_plugins.connect_source(source.type, settings, source.secret_refs)
    try:
        return [
            catalog.ScanScope(0, source.id, collection.name, [], row_limit, {}, True)
            for collection in row_source.list_collections()
        ]
    finally:
        row_source.close()


def _accept_if_ready(finding: catalog.PIIFinding) -> None:
    if finding.confidence in ("deterministic", "high"):
        catalog.accept_finding(finding.id, "auto_accepted")


def scan_source(source_name: str | int,
                scopes: list[dict[str, Any]] | None = None,
                limit: int | None = None,
                review_threshold: str = "medium") -> catalog.ScanRun:
    source = catalog.get_source(source_name)
    if source is None:
        raise ValueError(f"Unknown source: {source_name}")
    selected_scopes = _scan_scopes(source, scopes, limit)
    scan = catalog.create_scan_run(
        source.id,
        [{"dataset": scope.dataset, "columns": scope.columns} for scope in selected_scopes],
    )
    rows_seen = 0
    settings = dict(source.connector_config)
    if source.location_ref and "path" not in settings:
        settings["path"] = source.location_ref
    row_source = source_plugins.connect_source(source.type, settings, source.secret_refs)
    try:
        for scope in selected_scopes:
            fields = row_source.list_fields(scope.dataset)
            hints = {field.name: field.pii_hint for field in fields}
            columns = scope.columns or [field.name for field in fields]
            for record in row_source.iter_records(scope.dataset, columns, scope.row_limit or limit):
                rows_seen += 1
                values = record.values
                first = values.get("first_name") or values.get("firstname")
                last = values.get("last_name") or values.get("lastname")
                if first and last:
                    full_name = f"{first} {last}"
                    finding = catalog.create_finding(
                        scan.id,
                        source.id,
                        {
                            "dataset": scope.dataset,
                            "column": "first_name,last_name",
                            "row_ref": record.record_ref,
                        },
                        "PERSON",
                        full_name,
                        "deterministic",
                        "combined name fields",
                    )
                    _accept_if_ready(finding)
                for column, value in values.items():
                    category, confidence, reason = classify_value(column, value, hints.get(column, ""))
                    candidates = (
                        [(category, str(value), confidence, reason)]
                        if category is not None
                        else [
                            (model_category, model_value, "medium", model_reason)
                            for model_category, model_value, model_reason
                            in model_assisted_findings(value)
                        ]
                    )
                    for candidate_category, candidate_value, candidate_confidence, candidate_reason in candidates:
                        finding = catalog.create_finding(
                            scan.id,
                            source.id,
                            {
                                "dataset": scope.dataset,
                                "column": column,
                                "row_ref": record.record_ref,
                            },
                            candidate_category,
                            candidate_value,
                            candidate_confidence,
                            candidate_reason,
                        )
                        _accept_if_ready(finding)
        status = catalog.SCAN_COMPLETED
        return catalog.finish_scan_run(scan.id, status=status, rows_seen=rows_seen)
    except Exception as exc:
        return catalog.finish_scan_run(
            scan.id,
            status=catalog.SCAN_FAILED if rows_seen == 0 else catalog.SCAN_COMPLETED_WITH_ERRORS,
            rows_seen=rows_seen,
            error_summary=catalog.sanitize_error(exc),
        )
    finally:
        row_source.close()


def refresh_source(source_name: str | int,
                   limit: int | None = None,
                   review_threshold: str = "medium") -> catalog.ScanRun:
    source = catalog.get_source(source_name)
    if source is None:
        raise ValueError(f"Unknown source: {source_name}")
    scan = scan_source(source_name, limit=limit, review_threshold=review_threshold)
    stale_count = 0
    if scan.status in {catalog.SCAN_COMPLETED, catalog.SCAN_COMPLETED_WITH_ERRORS}:
        seen_entry_ids = {
            ref.catalog_entry_id
            for ref in catalog.list_source_references()
            if ref.source_id == source.id and ref.last_seen_scan_run_id == scan.id
        }
        stale_count = catalog.mark_entries_stale_for_source(source.id, seen_entry_ids)
    catalog.log_audit_event(
        "catalog_refresh",
        "Refreshed catalog source",
        {
            "source_id": source.id,
            "scan_run_id": scan.id,
            "status": scan.status,
            "rows_seen": scan.rows_seen,
            "stale_count": stale_count,
        },
    )
    return scan
