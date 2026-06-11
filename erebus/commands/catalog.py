"""CLI for registering sources, scanning, reviewing, and maintaining the catalog."""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import Any

from ..audit import logger
from ..cataloging import scan as catalog_scan
from ..cataloging import sources as source_plugins
from ..cataloging import store as catalog


def _parse_key_value(items: list[str] | None) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise ValueError(f"Expected key=value, got {item!r}")
        key, value = item.split("=", 1)
        if not key:
            raise ValueError(f"Expected key=value, got {item!r}")
        result[key] = value
    return result


def _parse_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Expected true or false, got {value!r}")


def parse_scope(scope: str) -> dict[str, Any]:
    dataset, sep, columns = scope.partition(":")
    dataset = dataset.strip()
    if not dataset:
        raise ValueError("Scope dataset cannot be empty")
    return {
        "dataset": dataset,
        "columns": [part.strip() for part in columns.split(",") if part.strip()] if sep else [],
    }


def _source_payload(source: catalog.ExternalDataSource) -> dict[str, Any]:
    return {
        "id": source.id,
        "name": source.name,
        "type": source.type,
        "location_ref": source.location_ref,
        "connector_config": source.connector_config,
        "credential_refs": source.secret_refs,
        "status": source.status,
        "last_error": source.last_error,
    }


def _scan_payload(scan: catalog.ScanRun) -> dict[str, Any]:
    return {
        "id": scan.id,
        "source_id": scan.source_id,
        "status": scan.status,
        "rows_seen": scan.rows_seen,
        "findings_total": scan.findings_total,
        "accepted_total": scan.accepted_total,
        "uncertain_total": scan.uncertain_total,
        "rejected_total": scan.rejected_total,
        "error_summary": scan.error_summary,
    }


def _policy_payload(policy: catalog.RevealPolicy) -> dict[str, Any]:
    return {
        "id": policy.id,
        "name": policy.name,
        "name_mode": policy.name_mode,
        "allow_first_name": policy.allow_first_name,
        "strict_near_identifiers": policy.strict_near_identifiers,
        "temporary_reveal_minutes": policy.temporary_reveal_minutes,
        "enabled": policy.enabled,
    }


def _grant_payload(grant: catalog.RevealGrant) -> dict[str, Any]:
    return {
        "id": grant.id,
        "catalog_entry_id": grant.catalog_entry_id,
        "created_at": grant.created_at,
        "expires_at": grant.expires_at,
        "status": grant.status,
    }


def _finding_payload(finding: catalog.PIIFinding, reveal: bool = False) -> dict[str, Any]:
    value = finding.value if reveal else catalog.mask_value(finding.value)
    return {
        "id": finding.id,
        "scan_run_id": finding.scan_run_id,
        "source_id": finding.source_id,
        "source_ref": finding.source_ref,
        "category": finding.category,
        "value": value,
        "masked": not reveal,
        "confidence": finding.confidence,
        "detection_reason": finding.detection_reason,
        "status": finding.status,
        "catalog_entry_id": finding.catalog_entry_id,
    }


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _cmd_source_connectors(args) -> int:
    connectors = [asdict(item) for item in source_plugins.list_connectors()]
    if args.json:
        _print_json({"connectors": connectors})
    else:
        for item in connectors:
            print(f"{item['id']}\t{item['name']}\t{item['version']}")
    return 0


def _cmd_source_add(args) -> int:
    connector = source_plugins.get_connector(args.connector_id)
    if connector is None:
        available = ", ".join(item.id for item in source_plugins.list_connectors())
        print(
            catalog.sanitize_error(f"Unknown connector '{args.connector_id}'. Available: {available}"),
            file=sys.stderr,
        )
        return 1
    try:
        settings = _parse_key_value(args.setting)
        credential_refs = _parse_key_value(args.secret_env)
        scopes = [parse_scope(item) for item in args.scope or []]
    except ValueError as exc:
        print(catalog.sanitize_error(exc), file=sys.stderr)
        return 1
    location_ref = args.location or settings.get("base_url", "")
    if args.connector_id == "sqlite":
        if not args.location:
            print("SQLite source requires a path", file=sys.stderr)
            return 1
        settings.setdefault("path", args.location)
    source = catalog.add_source(
        args.name,
        args.connector_id,
        location_ref=location_ref,
        connector_config=settings,
        secret_refs=credential_refs,
    )
    for scope in scopes:
        catalog.add_scope(source.id, scope["dataset"], scope["columns"])
    payload = {"source": _source_payload(source), "scopes": scopes}
    if args.json:
        _print_json(payload)
    else:
        print(f"added source {source.name} ({source.type})")
    return 0


def _cmd_source_list(args) -> int:
    sources = [_source_payload(source) for source in catalog.list_sources()]
    if args.json:
        _print_json({"sources": sources})
    else:
        for source in sources:
            print(f"{source['id']}\t{source['name']}\t{source['type']}\t{source['status']}")
    return 0


def _cmd_scan(args) -> int:
    try:
        scopes = [parse_scope(item) for item in args.scope or []] or None
        scan = catalog_scan.scan_source(
            args.source,
            scopes=scopes,
            limit=args.limit,
            review_threshold=args.review_threshold,
        )
    except Exception as exc:
        print(catalog.sanitize_error(exc), file=sys.stderr)
        return 1
    payload = {"scan": _scan_payload(scan)}
    if args.json:
        _print_json(payload)
    else:
        print(
            f"scan {scan.status}: rows={scan.rows_seen} "
            f"findings={scan.findings_total} accepted={scan.accepted_total}"
        )
    return 0 if scan.status != catalog.SCAN_FAILED else 1


def _cmd_refresh(args) -> int:
    try:
        scan = catalog_scan.refresh_source(
            args.source,
            limit=args.limit,
            review_threshold=args.review_threshold,
        )
    except Exception as exc:
        print(catalog.sanitize_error(exc), file=sys.stderr)
        return 1
    payload = {"scan": _scan_payload(scan)}
    if args.json:
        _print_json(payload)
    else:
        print(
            f"refresh {scan.status}: rows={scan.rows_seen} "
            f"findings={scan.findings_total} accepted={scan.accepted_total}"
        )
    return 0 if scan.status != catalog.SCAN_FAILED else 1


def _cmd_policy_set(args) -> int:
    current = catalog.get_reveal_policy()
    try:
        allow_first_name = (
            _parse_bool(args.allow_first_name)
            if args.allow_first_name is not None
            else current.allow_first_name
        )
        strict_near_identifiers = (
            _parse_bool(args.strict_near_identifiers)
            if args.strict_near_identifiers is not None
            else current.strict_near_identifiers
        )
        policy = catalog.set_reveal_policy(
            name=catalog.POLICY_NAME_DEFAULT,
            name_mode=args.name_mode or current.name_mode,
            allow_first_name=allow_first_name,
            strict_near_identifiers=strict_near_identifiers,
            temporary_reveal_minutes=(
                args.temporary_reveal_minutes
                if args.temporary_reveal_minutes is not None
                else current.temporary_reveal_minutes
            ),
            enabled=True,
        )
    except ValueError as exc:
        print(catalog.sanitize_error(exc), file=sys.stderr)
        return 1
    payload = {"policy": _policy_payload(policy)}
    if args.json:
        _print_json(payload)
    else:
        print(
            f"policy {policy.name}: mode={policy.name_mode} "
            f"first_name={str(policy.allow_first_name).lower()}"
        )
    return 0


def _cmd_reveal(args) -> int:
    try:
        policy = catalog.get_reveal_policy()
        grant = catalog.create_reveal_grant(
            args.catalog_entry_id,
            args.reason,
            minutes=args.minutes if args.minutes is not None else policy.temporary_reveal_minutes,
        )
    except ValueError as exc:
        print(catalog.sanitize_error(exc), file=sys.stderr)
        return 1
    payload = {"grant": _grant_payload(grant)}
    if args.json:
        _print_json(payload)
    else:
        print(f"reveal grant {grant.id} active until {grant.expires_at}")
    return 0


def _cmd_findings_list(args) -> int:
    source_id = None
    if args.source:
        source = catalog.get_source(args.source)
        if source is None:
            print(catalog.sanitize_error(f"Unknown source: {args.source}"), file=sys.stderr)
            return 1
        source_id = source.id
    findings = catalog.list_findings(status=args.status, source_id=source_id)
    if args.category:
        findings = [item for item in findings if item.category == args.category]
    if args.reveal and findings:
        catalog.log_audit_event(
            "catalog_reveal",
            "Revealed finding values",
            {"finding_ids": [item.id for item in findings]},
        )
    payload = {"findings": [_finding_payload(item, reveal=args.reveal) for item in findings]}
    if args.json:
        _print_json(payload)
    else:
        for item in payload["findings"]:
            print(
                f"{item['id']}\t{item['category']}\t{item['confidence']}\t"
                f"{item['status']}\t{item['value']}"
            )
    return 0


def _cmd_findings_accept(args) -> int:
    accepted = []
    try:
        for finding_id in args.finding_ids:
            entry = catalog.accept_finding(finding_id)
            finding = catalog.get_finding(finding_id)
            accepted.append(
                {
                    "finding_id": finding_id,
                    "catalog_entry_id": entry.id,
                    "category": entry.category if finding is None else finding.category,
                    "token": entry.token,
                }
            )
    except ValueError as exc:
        print(catalog.sanitize_error(exc), file=sys.stderr)
        return 1
    if args.json:
        _print_json({"accepted": accepted})
    else:
        for item in accepted:
            print(f"accepted finding {item['finding_id']} -> entry {item['catalog_entry_id']}")
    return 0


def _cmd_findings_reject(args) -> int:
    rejected = []
    try:
        for finding_id in args.finding_ids:
            catalog.reject_finding(finding_id, args.reason or "")
            rejected.append({"finding_id": finding_id, "status": catalog.FINDING_REJECTED})
    except ValueError as exc:
        print(catalog.sanitize_error(exc), file=sys.stderr)
        return 1
    if args.json:
        _print_json({"rejected": rejected})
    else:
        for item in rejected:
            print(f"rejected finding {item['finding_id']}")
    return 0


def _cmd_forget(args) -> int:
    term = args.value.strip()
    if not term:
        print("Empty forget value", file=sys.stderr)
        return 1
    if not args.yes:
        print("Forget requires confirmation; rerun with --yes", file=sys.stderr)
        return 1
    catalog_removed = catalog.forget_catalog_value(term)
    logger.init_db()
    log_removed = logger.forget_term(term)
    payload = {"catalog_removed": catalog_removed, "log_removed": log_removed}
    if args.json:
        _print_json(payload)
    else:
        print(f"removed catalog={catalog_removed} log={log_removed}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="erebus-catalog")
    sub = parser.add_subparsers(dest="command", required=True)

    source = sub.add_parser("source")
    source_sub = source.add_subparsers(dest="source_command", required=True)

    connectors = source_sub.add_parser("connectors")
    connectors.add_argument("--json", action="store_true")
    connectors.set_defaults(func=_cmd_source_connectors)

    add = source_sub.add_parser("add")
    add.add_argument("connector_id")
    add.add_argument("name")
    add.add_argument("location", nargs="?")
    add.add_argument("--setting", action="append", default=[])
    add.add_argument("--secret-env", action="append", default=[])
    add.add_argument("--scope", action="append", default=[])
    add.add_argument("--json", action="store_true")
    add.set_defaults(func=_cmd_source_add)

    list_parser = source_sub.add_parser("list")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=_cmd_source_list)

    scan = sub.add_parser("scan")
    scan.add_argument("source")
    scan.add_argument("--scope", action="append", default=[])
    scan.add_argument("--limit", type=int, default=None)
    scan.add_argument("--review-threshold", choices=("low", "medium", "high"), default="medium")
    scan.add_argument("--json", action="store_true")
    scan.set_defaults(func=_cmd_scan)

    refresh = sub.add_parser("refresh")
    refresh.add_argument("source")
    refresh.add_argument("--limit", type=int, default=None)
    refresh.add_argument("--review-threshold", choices=("low", "medium", "high"), default="medium")
    refresh.add_argument("--json", action="store_true")
    refresh.set_defaults(func=_cmd_refresh)

    policy = sub.add_parser("policy")
    policy_sub = policy.add_subparsers(dest="policy_command", required=True)

    policy_set = policy_sub.add_parser("set")
    policy_set.add_argument("--name-mode", choices=("strict", "balanced", "relaxed"), default=None)
    policy_set.add_argument("--allow-first-name", choices=("true", "false"), default=None)
    policy_set.add_argument("--strict-near-identifiers", choices=("true", "false"), default=None)
    policy_set.add_argument("--temporary-reveal-minutes", type=int, default=None)
    policy_set.add_argument("--json", action="store_true")
    policy_set.set_defaults(func=_cmd_policy_set)

    reveal = sub.add_parser("reveal")
    reveal.add_argument("catalog_entry_id", type=int)
    reveal.add_argument("--reason", required=True)
    reveal.add_argument("--minutes", type=int, default=None)
    reveal.add_argument("--json", action="store_true")
    reveal.set_defaults(func=_cmd_reveal)

    findings = sub.add_parser("findings")
    findings_sub = findings.add_subparsers(dest="findings_command", required=True)

    findings_list = findings_sub.add_parser("list")
    findings_list.add_argument("--source", default=None)
    findings_list.add_argument(
        "--status",
        choices=(
            catalog.FINDING_CANDIDATE,
            catalog.FINDING_ACCEPTED,
            catalog.FINDING_REJECTED,
            catalog.FINDING_REMOVED,
            catalog.FINDING_STALE,
        ),
        default=None,
    )
    findings_list.add_argument("--category", default=None)
    findings_list.add_argument("--reveal", action="store_true")
    findings_list.add_argument("--json", action="store_true")
    findings_list.set_defaults(func=_cmd_findings_list)

    findings_accept = findings_sub.add_parser("accept")
    findings_accept.add_argument("finding_ids", nargs="+", type=int)
    findings_accept.add_argument("--json", action="store_true")
    findings_accept.set_defaults(func=_cmd_findings_accept)

    findings_reject = findings_sub.add_parser("reject")
    findings_reject.add_argument("finding_ids", nargs="+", type=int)
    findings_reject.add_argument("--reason", default="")
    findings_reject.add_argument("--json", action="store_true")
    findings_reject.set_defaults(func=_cmd_findings_reject)

    forget = sub.add_parser("forget")
    forget.add_argument("value")
    forget.add_argument("--yes", action="store_true")
    forget.add_argument("--json", action="store_true")
    forget.set_defaults(func=_cmd_forget)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point for the erebus-catalog command."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args) or 0


if __name__ == "__main__":
    raise SystemExit(main())
