# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""BigQuery source connector (Erebus Pro, feature ``connectors.bigquery``).

Signs in with a service-account key (``service_account_key``, the JSON key file) or,
with ``auth: attached``, the identity attached to the worker (ADC, on GCP). The key's
token endpoint and universe are pinned to Google's, so a key file cannot send the
worker anywhere else; a workload identity (external account) file is refused. The client
talks only to Google's BigQuery API: no setting names a host. The worker checks every
address it connects to against its deny list, and its allow list when one is set; with
``auth: attached`` the GCP metadata server is let through (``egress_exceptions``).

Collections are ``dataset.table``; fields come from each dataset's
``INFORMATION_SCHEMA.COLUMNS``. Without ``location`` each query runs where its dataset
lives; with it every job runs there and datasets in other locations are skipped (a query
there would fail as not found). Every query bills at least 10 MB, so the distinct values
of all asked field groups of a table come from one query: a ``UNION ALL`` of per-group
``SELECT DISTINCT``, tagged by group, name parts as extra columns. Every query is capped
by ``max_bytes_billed`` when set (on-demand pricing only; slot pricing ignores it), and a
capped query fails the sync as ``incomplete``. Sample rows come from the free table-read
API. The documented read-only role is the guard; the connector only sends SELECTs.
Every client failure is a fixed-text ``ConnectorError`` raised ``from None``.
"""
from __future__ import annotations

import itertools
import json
import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from erebus.cataloging.connector_errors import ConnectorError
from erebus.cataloging.sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord

from . import _warehouse
from ._licensed import LicensedConnector

_PROJECT = re.compile(r"(?:[a-z][a-z0-9.-]{0,62}:)?[a-z][a-z0-9-]{4,28}[a-z0-9]")
_LOCATION = re.compile(r"[A-Za-z0-9-]{2,64}")
_AUTH = re.compile(r"key|attached")
_SCOPES = ["https://www.googleapis.com/auth/bigquery"]
_GOOGLE = {"token_uri": "https://oauth2.googleapis.com/token", "universe_domain": "googleapis.com"}
_METADATA = (("169.254.169.254", 80), ("fd20:ce::254", 80))  # GCP's metadata server, IPv4 and IPv6
_LABELS = {"erebus": "sync"}
_REQUEST_TIMEOUT_S = 60
_PAGE = 2000
_COLUMNS = ("SELECT table_name, column_name, data_type, is_nullable FROM {}.{}.INFORMATION_SCHEMA.COLUMNS "
            "WHERE is_hidden = 'NO' ORDER BY table_name, ordinal_position")
_LIMIT_REASONS = frozenset({"rateLimitExceeded", "quotaExceeded", "jobRateLimitExceeded"})
# BigQuery bills every query at least 10 MiB, so a lower max_bytes_billed caps every query.
_MIN_BYTES_BILLED = 10 * 1024 * 1024


def _kind(exc: BaseException) -> str:
    import google.auth.exceptions as auth_errors
    from google.api_core import exceptions as api

    if isinstance(exc, auth_errors.TransportError):
        return "unreachable"
    if isinstance(exc, (auth_errors.GoogleAuthError, api.Unauthorized)):
        return "auth"
    reasons = {e.get("reason") for e in getattr(exc, "errors", None) or () if isinstance(e, dict)}
    if "bytesBilledLimitExceeded" in reasons:
        return "incomplete"
    if reasons & _LIMIT_REASONS or isinstance(exc, api.TooManyRequests):
        return "limit"
    if isinstance(exc, (api.Forbidden, api.NotFound)):
        return "permission"
    if isinstance(exc, (api.ServerError, api.RetryError, ConnectionError, TimeoutError, OSError)):
        return "unreachable"
    try:
        import requests
        if isinstance(exc, requests.exceptions.ConnectionError):
            return "unreachable"
    except ImportError:
        pass
    return "query"


def _quota_reset() -> datetime:
    """The next midnight in America/Los_Angeles, when BigQuery's daily quotas reset."""
    try:
        zone: Any = ZoneInfo("America/Los_Angeles")
    except ZoneInfoNotFoundError:  # no time zone data: standard time, at worst one early retry in summer
        zone = timezone(timedelta(hours=-8))
    today = datetime.now(UTC).astimezone(zone).date()
    return datetime.combine(today + timedelta(days=1), time(), tzinfo=zone)


def _failure(exc: BaseException) -> ConnectorError:
    """The fixed-text error ``exc`` stands for; a daily quota says when it resets."""
    kind = _kind(exc)
    reasons = {e.get("reason") for e in getattr(exc, "errors", None) or () if isinstance(e, dict)}
    if kind == "limit" and "quotaExceeded" in reasons:
        return ConnectorError(kind, reset_at=_quota_reset())
    return ConnectorError(kind)


def _quote(identifier: str) -> str:
    return "`" + identifier.replace("\\", "\\\\").replace("`", "\\`") + "`"


def _byte_cap(settings: dict[str, Any]) -> int | None:
    cap = settings.get("max_bytes_billed")
    if cap is None:
        return None
    if type(cap) is not int or cap < _MIN_BYTES_BILLED:
        raise ConnectorError("settings") from None
    return cap


def _credentials(settings: dict[str, Any], secrets: dict[str, str]) -> Any:
    """Service-account credentials pinned to Google, or the worker's ADC when asked for."""
    mode = _warehouse.setting(settings, "auth", _AUTH) or "key"
    try:
        if mode == "attached":
            import google.auth
            return google.auth.default(scopes=_SCOPES)[0]
        raw = secrets.get("service_account_key")
        info = json.loads(raw) if isinstance(raw, str) and raw.strip() else None
        if not isinstance(info, dict) or info.get("type") != "service_account":
            raise ValueError("not a service-account key")
        from google.oauth2 import service_account
        return service_account.Credentials.from_service_account_info({**info, **_GOOGLE}, scopes=_SCOPES)
    except Exception:  # a missing, malformed or foreign key, or no attached identity
        raise ConnectorError("auth") from None


def _client(project: str, credentials: Any, location: str | None) -> Any:
    from google.cloud import bigquery
    return bigquery.Client(project=project, credentials=credentials, location=location)


class BigQueryRowSource:
    """A BigQuery project through a read-only role; collections are ``dataset.table``."""

    def __init__(self, client: Any, project: str, datasets: list[str] | None, cap: int | None, retry_s: float,
                 location: str | None = None):
        from google.cloud import bigquery

        self.client = client
        self._project = project
        self._datasets = datasets
        self._location = location.lower() if location else None
        self._cap = cap
        self._retry = bigquery.DEFAULT_RETRY.with_timeout(retry_s)
        self._columns = _warehouse.Columns()

    def _call(self, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except ConnectorError:
            raise
        except Exception as exc:
            raise _failure(exc) from None

    def _iterate(self, rows: Any) -> Iterator[Any]:
        it = iter(self._call(lambda: rows))
        while True:
            row = self._call(lambda: next(it, StopIteration))
            if row is StopIteration:
                return
            yield row

    def _query(self, sql: str) -> Iterator[Any]:
        from google.cloud import bigquery

        config = bigquery.QueryJobConfig(labels=dict(_LABELS), job_timeout_ms=_warehouse.STATEMENT_TIMEOUT_S * 1000)
        if self._cap is not None:
            config.maximum_bytes_billed = self._cap
        job = self._call(lambda: self.client.query(sql, job_config=config, retry=self._retry,
                                                   timeout=_REQUEST_TIMEOUT_S, job_retry=None))
        yield from self._iterate(self._call(lambda: job.result(
            page_size=_PAGE, retry=self._retry, timeout=_warehouse.STATEMENT_TIMEOUT_S + _REQUEST_TIMEOUT_S,
            job_retry=None)))

    def list_collections(self) -> list[CollectionInfo]:
        listed = self._call(lambda: [d.dataset_id for d in self.client.list_datasets(
            self._project, retry=self._retry, timeout=_REQUEST_TIMEOUT_S)])
        wanted = [d for d in listed if (self._datasets is None or d in self._datasets) and self._located(d)]
        rows: list[tuple[str, str, FieldInfo]] = []
        for dataset in wanted:
            sql = _COLUMNS.format(_quote(self._project), _quote(dataset))
            rows += [(dataset, table, FieldInfo(column, db_type=dtype, nullable=nullable == "YES"))
                     for table, column, dtype, nullable in self._query(sql)]
        return [CollectionInfo(name) for name in self._columns.fill(rows)]

    def _located(self, dataset: str) -> bool:
        """Whether ``dataset`` can be queried from the pinned location (any, when none is set).
        A query there would answer 404 (not found in that location): the dataset is skipped."""
        if self._location is None:
            return True
        where = self._call(lambda: self.client.get_dataset(f"{self._project}.{dataset}", retry=self._retry,
                                                           timeout=_REQUEST_TIMEOUT_S).location)
        return not where or where.lower() == self._location

    def list_fields(self, collection: str) -> list[FieldInfo]:
        if not self._columns.known():
            self.list_collections()
        return list(self._columns.get(collection)[2])

    def _table(self, collection: str) -> tuple[str, str, list[FieldInfo]]:
        fields = self.list_fields(collection)
        dataset, table, _ = self._columns.get(collection)
        return dataset, table, fields

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        dataset, table, infos = self._table(collection)
        selected = _warehouse.check_fields(infos, fields)
        ref = f"{self._project}.{dataset}.{table}"
        meta = self._call(lambda: self.client.get_table(ref, retry=self._retry, timeout=_REQUEST_TIMEOUT_S))
        if meta.table_type == "TABLE":  # the table-read API bills nothing
            by_name = {f.name: f for f in meta.schema}
            if any(n not in by_name for n in selected):
                raise ConnectorError("query") from None
            rows = self._iterate(self._call(lambda: self.client.list_rows(
                meta, selected_fields=[by_name[n] for n in selected], max_results=limit,
                page_size=max(1, page_size), retry=self._retry, timeout=_REQUEST_TIMEOUT_S)))
        else:  # a view has no stored rows to read
            sql = (f"SELECT {', '.join(map(_quote, selected))} FROM "
                   f"{_quote(self._project)}.{_quote(dataset)}.{_quote(table)}")
            rows = self._query(sql + ("" if limit is None else f" LIMIT {max(0, int(limit))}"))
        for count, row in enumerate(itertools.islice(rows, limit), 1):
            yield SourceRecord(f"{collection}:{count}", dict(zip(selected, tuple(row.values()), strict=True)), {})

    def iter_distinct_groups(self, collection: str, groups: list[list[str]], limit: int
                             ) -> Iterator[tuple[int, tuple]]:
        """``(group index, distinct tuple as text)`` for every group, from one query."""
        dataset, table, infos = self._table(collection)
        groups = _warehouse.check_groups(infos, groups)
        source = f"{_quote(self._project)}.{_quote(dataset)}.{_quote(table)}"
        width = max(len(g) for g in groups)
        branches = []
        for index, group in enumerate(groups):
            inner = ", ".join(f"{_quote(f)} AS _c{k}" for k, f in enumerate(group))
            some = " OR ".join(f"{_quote(f)} IS NOT NULL" for f in group)
            values = ", ".join(f"CAST(_c{k} AS STRING) AS v{k}" if k < len(group) else f"CAST(NULL AS STRING) AS v{k}"
                               for k in range(width))
            branches.append(f"SELECT {index} AS g, {values} FROM (SELECT DISTINCT {inner} FROM {source} WHERE {some})")
        sql = f"SELECT * FROM ({' UNION ALL '.join(branches)}) LIMIT {max(0, int(limit))}"
        for row in self._query(sql):
            index = row[0]
            yield index, tuple(row[1:1 + len(groups[index])])

    def iter_distinct_values(self, collection: str, fields: list[str], limit: int) -> Iterator[tuple]:
        for _index, row in self.iter_distinct_groups(collection, [fields], limit):
            yield row

    def close(self) -> None:
        try:
            self.client.close()
        except Exception:
            pass


class BigQueryConnector(LicensedConnector):
    type_id = "bigquery"
    retry_s: float = 60  # how long one API call may retry transient failures

    def __init__(self, entitlements: Any = None, *, client_factory: Callable[..., Any] | None = None) -> None:
        super().__init__(entitlements)
        self._client_factory = client_factory or _client

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="bigquery",
            name="BigQuery",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records", "distinct_values", "distinct_groups"],
            settings_schema={"project": {"required": True}, "location": {}, "max_bytes_billed": {}, "auth": {},
                             "schemas": {}, "collections": {}},
            secrets_schema={"service_account_key": {}},
        )

    def egress_exceptions(self, settings: dict[str, Any]) -> tuple[tuple[str, int], ...]:
        """With ``auth: attached`` the client fetches its token from the GCP metadata server,
        which the worker's deny list covers; nothing else passes its host lists."""
        return _METADATA if settings.get("auth") == "attached" else ()

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        self.require_license()
        project = _warehouse.setting(settings, "project", _PROJECT, required=True)
        location = _warehouse.setting(settings, "location", _LOCATION)
        cap = _byte_cap(settings)
        datasets = _warehouse.schema_filter(settings)
        credentials = _credentials(settings, secrets)
        try:
            client = self._client_factory(project, credentials, location)
        except Exception:
            raise ConnectorError("auth") from None
        return BigQueryRowSource(client, project, datasets, cap, self.retry_s, location)
