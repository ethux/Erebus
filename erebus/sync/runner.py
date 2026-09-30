"""Run one claimed sync job (spec 015 "Sync behaviour").

``execute`` opens the source and runs the job; ``classify`` turns whatever it raised
into a job error class. Before any connector runs, the source must not be paused, its
type must be known and its settings must pass the network policy; only then are its
credentials decrypted (tenant key, AAD = source id).

* **sample**: up to ``SAMPLE_ROWS`` rows per collection (``settings.collections``, or
  every collection the connector lists), the gateway field rules, one ``source_fields``
  write; the transaction marking the job done queues the full sync if a field is
  accepted.
* **full**: distinct values of every accepted field (a name tuple as one distinct tuple,
  stored as the full name), batch-upserted and linked under the job id. Only when every
  field was read, within ``max_values`` and the tenant cap, does one transaction retire
  the links this sync did not see, bump the catalog version and mark the job done.
  Anything short of that fails the job and retires nothing.

The worker contract with connectors, beyond ``erebus.sources``: a database connector
may offer ``iter_distinct_values(collection, fields, limit)`` yielding tuples in
``fields`` order (without it the worker de-duplicates ``iter_records``), connects to the
``hostaddr`` it is handed, and raises ``ConnectorError`` (``incomplete`` for a capped
query or skipped values). Every write is fenced by the job's lease: a worker that lost
it writes nothing.
"""
from __future__ import annotations

import logging
import socket
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import psycopg

from ..cataloging import connector_types, field_rules
from ..cataloging import sources as contract
from ..cataloging.connector_errors import ConnectorError, LicenseRequired
from ..gateway import catalog
from ..gateway.connectors import fields, jobs, sources
from ..gateway.crypto.keyprovider import CryptoErased, KeyProvider
from ..gateway.detection import DetectionUnavailable
from ..gateway.governance import audit
from ..gateway.store import catalog_versions
from ..gateway.store.known_value_store import open_scope_crypto
from ..gateway.store.scope_context import scoped
from .config import SyncConfig
from .netpolicy import PolicyError, prepare_settings

log = logging.getLogger("erebus.sync")

SAMPLE_ROWS = 1000
UPSERT_BATCH = 2000
ACTOR = "sync-worker"


class LeaseLost(Exception):
    """This worker's lease on the job ended; it must write nothing more."""


class JobFailed(Exception):
    """A job failure of ``error_class`` (a ``policy.ERROR_TEXT`` key)."""

    def __init__(self, error_class: str, *, reset_at: datetime | None = None, license_message: str | None = None):
        super().__init__(error_class)
        self.error_class = error_class
        self.reset_at = reset_at
        self.license_message = license_message


@dataclass
class Context:
    """What a job needs besides the job row."""

    conn: psycopg.Connection
    provider: KeyProvider
    config: SyncConfig
    connectors: Callable[[str], Any]
    lease: Any  # has check(): raises LeaseLost
    model: Callable[[str], Any] | None = None
    resolve: Callable[..., list] = socket.getaddrinfo


def _reset_at(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str):
        try:
            return _reset_at(datetime.fromisoformat(value.replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def classify(exc: BaseException) -> JobFailed:
    """The job failure ``exc`` stands for; unknown exceptions are ``internal``."""
    if isinstance(exc, JobFailed):
        return exc
    if isinstance(exc, ConnectorError):
        return JobFailed(exc.kind, reset_at=_reset_at(exc.reset_at))
    if isinstance(exc, LicenseRequired):
        return JobFailed("license", license_message=str(exc))
    if isinstance(exc, PolicyError):
        return JobFailed(exc.kind)
    if isinstance(exc, CryptoErased):
        return JobFailed("crypto_erased")
    if isinstance(exc, sources.SecretsUnreadable):
        return JobFailed("auth")  # the admin re-enters the credentials either way
    if isinstance(exc, catalog.TenantCapExceeded):
        return JobFailed("incomplete")
    if isinstance(exc, DetectionUnavailable):
        return JobFailed("model")
    return JobFailed("internal")


def _open(ctx: Context, job: jobs.Job, source: sources.SourceInfo, crypto) -> tuple[Any, connector_types.ConnectorType]:
    ctype = connector_types.get(source.connector_type)
    if ctype is None:
        raise JobFailed("unknown_type")
    settings = prepare_settings(ctx.config.policy, ctype, source.settings, resolve=ctx.resolve)
    connector = ctx.connectors(source.connector_type)
    if connector is None:
        raise JobFailed("unknown_type")
    secrets = sources.read_secrets(ctx.conn, crypto, job.scope_id, job.source_id)
    return connector.connect(settings, secrets), ctype


def _field_spec(info: Any, family: str) -> field_rules.FieldSpec:
    return field_rules.FieldSpec(
        name=info.name,
        db_type=str(getattr(info, "db_type", "") or ""),
        primary_key=bool(getattr(info, "primary_key", False)),
        hint=str(getattr(info, "pii_hint", "") or "") if family == "app" else "",
    )


def _sample(ctx: Context, job: jobs.Job, source: sources.SourceInfo, rows_source: Any, family: str) -> dict:
    wanted = source.settings.get("collections")
    names = [c.name for c in rows_source.list_collections()]
    if wanted:
        names = [n for n in names if n in wanted]
    samples: list[fields.FieldSample] = []
    rows_seen = 0
    for collection in names:
        ctx.lease.check()
        specs = [_field_spec(f, family) for f in rows_source.list_fields(collection)]
        rows = [r.values for r in rows_source.iter_records(collection, limit=SAMPLE_ROWS)]
        rows_seen += len(rows)
        for rule in field_rules.gateway_rules(collection, specs, rows, model=ctx.model):
            samples.append(fields.FieldSample(rule.collection, rule.field, rule.db_type, rule.label, rule.decision,
                                              rule.reason, rule.confirmable))
    with ctx.conn.transaction():
        if not jobs.hold_lease(ctx.conn, job):
            raise LeaseLost()
        accepted = fields.record_sample(ctx.conn, job.scope_id, job.source_id, samples)
        counts = {"rows_seen": rows_seen, "fields": len(samples), "accepted": accepted}
        _succeed(ctx, job, counts, then="full" if accepted else None)
    return counts


def _field_values(rows_source: Any, collection: str, field: fields.SourceField, limit: int) -> Iterator[str]:
    parts = field.field.split("+")
    for row in contract.distinct_values(rows_source, collection, parts, limit):
        if len(parts) > 1:
            value = field_rules.join_name(row[0], row[1:-1], row[-1])
        else:
            value = None if row[0] is None else str(row[0])
        if value:
            yield value


def _full(ctx: Context, job: jobs.Job, source: sources.SourceInfo, rows_source: Any, crypto) -> dict:
    by_collection: dict[str, list[fields.SourceField]] = {}
    for f in fields.accepted_fields(ctx.conn, job.scope_id, job.source_id):
        by_collection.setdefault(f.collection, []).append(f)
    present = {c.name for c in rows_source.list_collections()} if by_collection else set()
    seen = added = 0
    batch: list[tuple[str, str]] = []

    def flush() -> None:
        nonlocal added
        ctx.lease.check()
        if batch:
            added += catalog.upsert_values(ctx.conn, crypto, job.scope_id, job.source_id, job.id, batch,
                                           tenant_max=ctx.config.tenant_max_values).added
            batch.clear()

    for collection, accepted in by_collection.items():
        ctx.lease.check()
        if collection not in present:
            raise JobFailed("incomplete")
        columns = {f.name for f in rows_source.list_fields(collection)}
        for f in accepted:
            if not set(f.field.split("+")) <= columns or f.label is None:
                raise JobFailed("incomplete")  # a skipped column: the sync is not complete
            for value in _field_values(rows_source, collection, f, source.max_values - seen + 1):
                seen += 1
                if seen > source.max_values:
                    raise JobFailed("incomplete")
                batch.append((value, f.label))
                if len(batch) >= UPSERT_BATCH:
                    flush()
    flush()
    with ctx.conn.transaction():
        if not jobs.hold_lease(ctx.conn, job):
            raise LeaseLost()
        retired = catalog.retire_unseen(ctx.conn, job.scope_id, job.source_id, job.id)
        if added or retired:
            catalog_versions.bump(ctx.conn, job.scope_id)
        counts = {"rows_seen": seen, "values_added": added, "values_retired": retired}
        _succeed(ctx, job, counts)
    return counts


def _succeed(ctx: Context, job: jobs.Job, counts: dict, *, then: str | None = None) -> None:
    """Inside the result transaction: clear needs_attention, audit, mark the job done."""
    with scoped(ctx.conn, job.scope_id):
        ctx.conn.execute(
            "UPDATE sources SET status = 'active', updated_at = now() "
            "WHERE scope_id = %s AND id = %s AND status = 'needs_attention'",
            (job.scope_id, job.source_id),
        )
    audit_job(ctx.conn, job, "done", counts)
    if not jobs.finish(ctx.conn, job, rows_seen=counts.get("rows_seen", 0),
                       values_added=counts.get("values_added", 0), values_retired=counts.get("values_retired", 0),
                       then=then):
        raise LeaseLost()


def audit_job(conn: psycopg.Connection, job: jobs.Job, outcome: str, metadata: dict) -> None:
    """Append a ``sync`` audit event: ids, the job kind and counts or error class only."""
    audit.append(conn, job.scope_id, {
        "event_type": "sync", "actor_id": ACTOR, "actor_role": ACTOR, "category": "sync", "outcome": outcome,
        "metadata": {"job_id": str(job.id), "source_id": str(job.source_id), "kind": job.kind, **metadata},
    })


def execute(ctx: Context, job: jobs.Job) -> dict:
    """Run ``job`` to completion and commit its result; return its counts.

    Raises ``JobFailed`` (or an exception ``classify`` maps) on failure and
    ``LeaseLost`` when the lease ended; neither leaves a partial result retired.
    """
    source = sources.get_source(ctx.conn, job.scope_id, job.source_id)
    if source is None:
        raise JobFailed("internal")  # a source FK: only a race with its delete gets here
    if source.status == "paused":
        raise JobFailed("paused")
    if job.kind not in ("sample", "full", "incremental"):
        raise JobFailed("unsupported")
    crypto = open_scope_crypto(ctx.conn, ctx.provider, job.scope_id)
    rows_source, ctype = _open(ctx, job, source, crypto)
    try:
        if job.kind == "sample":
            return _sample(ctx, job, source, rows_source, ctype.family)
        # Phase 1 connectors keep no cursor: an incremental job reads everything.
        return _full(ctx, job, source, rows_source, crypto)
    finally:
        try:
            rows_source.close()
        except Exception:
            log.warning("job %s: closing the source failed", job.id)
