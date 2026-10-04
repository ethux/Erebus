"""Run one claimed sync job (spec 015 "Sync behaviour").

``execute`` opens the source and runs the job; ``classify`` turns whatever it raised
into a job error class. Before any connector runs, the source must not be paused, its
type must be known and its settings must pass the network policy; only then are its
credentials decrypted (tenant key, AAD = source id).

* **sample**: up to ``SAMPLE_ROWS`` rows per collection (``settings.collections``, or
  every collection the connector lists), the gateway field rules, one ``source_fields``
  write; the transaction marking the job done queues the full sync if a field is
  accepted. A ``collections`` entry names a listed collection as written or as the
  source reads an unquoted name (``ConnectorType.identifiers``); one that names none
  fails the sample as ``settings``.
* **full**: distinct values of every accepted field (a name tuple as one distinct tuple,
  stored as the full name), batch-upserted and linked under the job id. Only when every
  field was read, within ``max_values`` and the tenant cap, does one transaction retire
  the links this sync did not see, bump the catalog version and mark the job done.
  Anything short of that fails the job and retires nothing, but bumps the version when
  it committed values; ``max_values`` counts every distinct row read, value or not.
  Databases and warehouses keep no cursor: an incremental job of theirs is a full sync.
* **app sources** (family ``app``) are read record by record and every value is linked
  to its record (``catalog_entry_records``). A full sync reads every record, then drops
  the links it did not renew and stores each collection's cursor. An incremental sync
  reads the records changed since the stored cursors, then replaces the links of every
  record it read (a deleted record's are dropped) and stores the new cursors. Entries
  left with no link retire, in the transaction that marks the job done; a failure
  retires nothing and keeps the old cursors. With no cursor, or one the source calls
  expired, the job reads everything instead. ``max_values`` counts values read.

The worker contract with connectors, beyond ``erebus.sources``: a database connector
may offer ``iter_distinct_values(collection, fields, limit)`` yielding tuples in
``fields`` order (without it the worker de-duplicates ``iter_records``) and a warehouse
``iter_distinct_groups`` (all accepted fields of a table in one query), connects to the
``hostaddr`` it is handed, and raises ``ConnectorError`` (``incomplete`` for a capped
query or skipped values). ``egress_exceptions(settings)`` may name ``(address, port)``
pairs a source must reach past the host lists. Every connector call runs under the
job's connect guard (``egress``). Every write is fenced by the job's lease: a worker
that lost it writes nothing.
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
from ..cataloging.connector_errors import ConnectorError, CursorExpired, DriverMissing, LicenseRequired
from ..gateway import catalog
from ..gateway.connectors import fields, jobs, sources
from ..gateway.crypto.keyprovider import CryptoErased, KeyProvider
from ..gateway.detection import DetectionUnavailable
from ..gateway.governance import audit
from ..gateway.store import catalog_versions
from ..gateway.store.known_value_store import open_scope_crypto
from ..gateway.store.scope_context import scoped
from . import egress
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

    def __init__(self, error_class: str, *, reset_at: datetime | None = None, detail: str | None = None):
        super().__init__(error_class)
        self.error_class = error_class
        self.reset_at = reset_at
        self.detail = detail


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
        return JobFailed("license", detail=str(exc))
    if isinstance(exc, DriverMissing):
        return JobFailed("driver", detail=str(exc))
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
    declared = getattr(connector, "egress_exceptions", None)
    guard = egress.Guard.for_source(ctx.config.policy, ctype, settings, resolve=ctx.resolve,
                                    exceptions=declared(settings) if declared is not None else ())
    return egress.GuardedSource(guard.call(connector.connect, settings, secrets), guard), ctype


def _field_spec(info: Any, family: str) -> field_rules.FieldSpec:
    return field_rules.FieldSpec(
        name=info.name,
        db_type=str(getattr(info, "db_type", "") or ""),
        primary_key=bool(getattr(info, "primary_key", False)),
        hint=str(getattr(info, "pii_hint", "") or "") if family == "app" else "",
    )


def _reads_as(rule: str, name: str, entry: str) -> bool:
    """Whether the source reads ``entry``, given unquoted, as the listed ``name``."""
    if rule == "insensitive":
        return name.casefold() == entry.casefold()
    fold = {"upper": str.upper, "lower": str.lower}.get(rule)
    parts, asked = name.split("."), entry.split(".")
    return fold is not None and len(parts) == len(asked) and all(
        part in (word, fold(word)) for part, word in zip(parts, asked, strict=True))


def selected(ctype: connector_types.ConnectorType, listed: list[str], wanted: list[str]) -> list[str]:
    """The ``listed`` collections the ``collections`` setting names, in listed order. An
    exact match wins over one by the source's reading of an unquoted name; an entry that
    names nothing fails the job as ``settings``, so a typo never passes as an empty source."""
    chosen: set[str] = set()
    for entry in wanted:
        hits = [n for n in listed if n == entry] or [n for n in listed if _reads_as(ctype.identifiers, n, entry)]
        if not hits:
            raise JobFailed("settings")
        chosen.update(hits)
    return [n for n in listed if n in chosen]


def _sample(ctx: Context, job: jobs.Job, source: sources.SourceInfo, rows_source: Any,
            ctype: connector_types.ConnectorType) -> dict:
    wanted = source.settings.get("collections")
    names = [c.name for c in rows_source.list_collections()]
    if wanted:
        names = selected(ctype, names, [str(w) for w in wanted])
    family = ctype.family
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


def _value(field: fields.SourceField, row: tuple) -> str | None:
    """A distinct row of ``field`` as one value (a name tuple joined), or ``None``."""
    if "+" in field.field:
        return field_rules.join_name(row[0], row[1:-1], row[-1])
    return None if row[0] is None else str(row[0])


def _bump_after_failure(ctx: Context, job: jobs.Job) -> None:
    """Batches this attempt committed are active: let the replicas load them (retires nothing)."""
    try:
        catalog_versions.bump(ctx.conn, job.scope_id)
    except Exception as exc:  # a retry bumps too (attempts > 0)
        log.warning("job %s: bumping the catalog version failed (%s)", job.id, type(exc).__name__)


def _accepted_rows(ctx: Context, rows_source: Any, by_collection: dict[str, list[fields.SourceField]],
                   max_values: int) -> Iterator[tuple[str | None, str]]:
    """``(value or None, label)`` per distinct row of every accepted field; ``incomplete``
    on a missing collection or column, or past ``max_values`` rows. All accepted fields
    of a collection are asked for at once (one query per table where the source can)."""
    present = {c.name for c in rows_source.list_collections()} if by_collection else set()
    rows = 0
    for collection, accepted in by_collection.items():
        ctx.lease.check()
        if collection not in present:
            raise JobFailed("incomplete")
        columns = {f.name for f in rows_source.list_fields(collection)}
        for f in accepted:
            if not set(f.field.split("+")) <= columns or f.label is None:
                raise JobFailed("incomplete")  # a skipped column: the sync is not complete
        groups = [f.field.split("+") for f in accepted]
        for index, row in contract.distinct_groups(rows_source, collection, groups, max_values - rows + 1):
            rows += 1  # every row returned counts, or a capped query would pass as complete
            if rows > max_values:
                raise JobFailed("incomplete")
            yield _value(accepted[index], row), accepted[index].label


def _full(ctx: Context, job: jobs.Job, source: sources.SourceInfo, rows_source: Any, crypto) -> dict:
    by_collection: dict[str, list[fields.SourceField]] = {}
    for f in fields.accepted_fields(ctx.conn, job.scope_id, job.source_id):
        by_collection.setdefault(f.collection, []).append(f)
    seen = added = 0
    batch: list[tuple[str, str]] = []

    def flush() -> None:
        nonlocal added
        ctx.lease.check()
        if batch:
            added += catalog.upsert_values(ctx.conn, crypto, job.scope_id, job.source_id, job.id, batch,
                                           tenant_max=ctx.config.tenant_max_values).added
            batch.clear()

    try:
        for value, label in _accepted_rows(ctx, rows_source, by_collection, source.max_values):
            seen += 1
            if value:
                batch.append((value, label))
                if len(batch) >= UPSERT_BATCH:
                    flush()
        flush()
    except BaseException:
        if added:
            _bump_after_failure(ctx, job)
        raise
    with ctx.conn.transaction():
        if not jobs.hold_lease(ctx.conn, job):
            raise LeaseLost()
        retired = catalog.retire_unseen(ctx.conn, job.scope_id, job.source_id, job.id)
        # A retry may re-see values an earlier attempt committed: they count as existing here.
        if added or retired or job.attempts:
            catalog_versions.bump(ctx.conn, job.scope_id)
        counts = {"rows_seen": seen, "values_added": added, "values_retired": retired}
        _succeed(ctx, job, counts)
    return counts


def _record_value(field: fields.SourceField, values: dict) -> str | None:
    """One accepted field of a record as a value (a name tuple joined), or ``None``."""
    if "+" in field.field:
        first, *middles, last = (values.get(p) for p in field.field.split("+"))
        return field_rules.join_name(first, middles, last)
    value = values.get(field.field)
    return str(value) if isinstance(value, str | int | float) and not isinstance(value, bool) else None


def _check_columns(rows_source: Any, collection: str, accepted: list[fields.SourceField], present: set[str]
                   ) -> list[str]:
    """The record fields to read for ``accepted``; ``incomplete`` when one is gone."""
    if collection not in present:
        raise JobFailed("incomplete")
    columns = {f.name for f in rows_source.list_fields(collection)}
    for f in accepted:
        if not set(f.field.split("+")) <= columns or f.label is None:
            raise JobFailed("incomplete")
    return sorted({part for f in accepted for part in f.field.split("+")})


def _read_records(ctx: Context, job: jobs.Job, source: sources.SourceInfo, rows_source: Any, crypto,
                  by_collection: dict[str, list[fields.SourceField]], since: dict[str, str] | None) -> dict:
    """Read an app source (every record, or with ``since`` the changes) and commit the result."""
    present = {c.name for c in rows_source.list_collections()} if by_collection else set()
    seen = values = added = 0
    batch: list[tuple[str, str, str, str]] = []
    touched: set[tuple[str, str]] = set()
    cursors: dict[str, str] = {}

    def flush() -> None:
        nonlocal added
        ctx.lease.check()
        if batch:
            added += catalog.upsert_record_values(ctx.conn, crypto, job.scope_id, job.source_id, job.id, batch,
                                                  tenant_max=ctx.config.tenant_max_values).added
            batch.clear()

    try:
        for collection, accepted in by_collection.items():
            ctx.lease.check()
            wanted = _check_columns(rows_source, collection, accepted, present)
            records = rows_source.iter_records(collection, fields=wanted) if since is None \
                else rows_source.iter_changes(collection, wanted, since[collection])
            for record in records:
                seen += 1
                record_id = str(record.record_ref)
                touched.add((collection, record_id))
                if record.metadata.get("deleted"):
                    continue
                items = [(collection, record_id, value, f.label) for f in accepted
                         if (value := _record_value(f, record.values)) is not None]
                values += len(items)
                if values > source.max_values:
                    raise JobFailed("incomplete")
                batch += items
                if len(batch) >= UPSERT_BATCH:
                    flush()
            position = rows_source.cursor(collection) if hasattr(rows_source, "cursor") else None
            if position is not None:
                cursors[collection] = str(position)
        flush()
    except BaseException:
        if added:
            _bump_after_failure(ctx, job)
        raise
    with ctx.conn.transaction():
        if not jobs.hold_lease(ctx.conn, job):
            raise LeaseLost()
        if since is None:
            retired = catalog.retire_unseen_records(ctx.conn, job.scope_id, job.source_id, job.id)
        else:
            retired = catalog.relink_records(ctx.conn, job.scope_id, job.source_id, job.id, touched)
            cursors = {c: cursors.get(c, since[c]) for c in by_collection}
        sources.set_cursor(ctx.conn, job.scope_id, job.source_id, cursors)
        if added or retired or job.attempts:
            catalog_versions.bump(ctx.conn, job.scope_id)
        counts = {"rows_seen": seen, "values_added": added, "values_retired": retired,
                  "read": "all" if since is None else "changes"}
        _succeed(ctx, job, counts)
    return counts


def _records(ctx: Context, job: jobs.Job, source: sources.SourceInfo, rows_source: Any, crypto) -> dict:
    """A full or incremental sync of an app source; see the module docstring."""
    by_collection: dict[str, list[fields.SourceField]] = {}
    for f in fields.accepted_fields(ctx.conn, job.scope_id, job.source_id):
        by_collection.setdefault(f.collection, []).append(f)
    stored = {c: v for c, v in source.cursor.items() if isinstance(v, str)}
    if job.kind == "incremental" and hasattr(rows_source, "iter_changes") and set(by_collection) <= set(stored):
        try:
            return _read_records(ctx, job, source, rows_source, crypto, by_collection, stored)
        except CursorExpired:
            log.info("job %s: the source's cursor expired, reading every record", job.id)
    return _read_records(ctx, job, source, rows_source, crypto, by_collection, None)


def _note_expiry(ctx: Context, job: jobs.Job, rows_source: Any) -> None:
    """Store when the credentials expire, if the source can tell."""
    method = getattr(rows_source, "credentials_expire_at", None)
    when = method() if method is not None else None
    if isinstance(when, datetime) and when.tzinfo is not None:
        ctx.lease.check()
        sources.set_credentials_expiry(ctx.conn, job.scope_id, job.source_id, when)


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
        _note_expiry(ctx, job, rows_source)
        if job.kind == "sample":
            return _sample(ctx, job, source, rows_source, ctype)
        if ctype.family == "app":
            return _records(ctx, job, source, rows_source, crypto)
        return _full(ctx, job, source, rows_source, crypto)
    finally:
        try:
            rows_source.close()
        except Exception:
            log.warning("job %s: closing the source failed", job.id)
