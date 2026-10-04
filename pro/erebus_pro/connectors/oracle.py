# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Oracle source connector (Erebus Pro, feature ``connectors.oracle``).

python-oracledb in thin mode: no Instant Client, Oracle Database 12.1 or later. Like the
free database connectors it dials the ``hostaddr`` the sync worker checked against its
host lists, never a name it resolves itself, and keeps ``host`` for TLS. The driver
follows a listener's redirect before it signs in (a RAC SCAN listener's, say); the
worker refuses any address but the checked one, so a redirecting listener fails the
sync as denied. ``sslmode``
defaults to ``verify-full``: TCPS, the certificate verified against the system CAs (and
a wallet's, when given) and its name matched against ``host`` during the handshake.
``verify-ca`` skips the name, ``require`` the certificate, ``disable`` uses plain TCP
(thin mode has no native network encryption). There is no ``prefer``: Oracle serves TLS
on its own port. No connect string, tnsnames.ora or sqlnet.ora is read.

The user signs in with a password, optionally over mutual TLS with a wallet
(``wallet_pem``, the wallet's ``ewallet.pem``, and ``wallet_password``) as Autonomous
Database requires; with ``auth: wallet`` the wallet's certificate alone signs in
(external authentication). A wallet is written to a private directory under the worker's
own root for the handshake and removed before ``connect`` returns; a worker sweeps what a
killed one left there when it starts (``_wallet``).

Fields come from ``ALL_TAB_COLUMNS``, Oracle-maintained schemas left out; collections are
``OWNER.TABLE``. Every read runs in ``SET TRANSACTION READ ONLY`` and the connection rests
in such a transaction between reads, so a write through it fails (ORA-01456); every
round trip has a call timeout. Distinct values are compared in the binary collation, so
a column or session that compares linguistically (ignoring case or accents, by a logon
trigger, say) keeps every spelling: each session is set to ``NLS_COMP = BINARY`` and,
from Oracle 12.2 (which has the ``COLLATE`` operator), every value is read ``COLLATE
BINARY``. CLOB and NCLOB values are read through
``DBMS_LOB.SUBSTR`` up to 1,000 characters (4,000 bytes at most); longer values are
skipped. The documented read-only user is the real guard. Every driver failure is a
fixed-text ``ConnectorError`` raised ``from None``.
"""
from __future__ import annotations

import ipaddress
import re
import ssl
from collections.abc import Iterator
from typing import Any

from erebus.cataloging.connector_errors import ConnectorError
from erebus.cataloging.sources import CollectionInfo, ConnectorMetadata, FieldInfo, RowSource, SourceRecord

from . import _warehouse
from ._licensed import LicensedConnector
from ._wallet import wallet_dir

_SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.$#-]{0,127}")
_USER = re.compile(r"[A-Za-z0-9_$#]{1,128}")
_AUTH = re.compile(r"password|wallet")
_SSL_MODES = frozenset({"verify-full", "verify-ca", "require", "disable"})
_LOB_CHARS = 1000
_TEXT_TYPES = frozenset({"VARCHAR2", "NVARCHAR2", "CHAR", "NCHAR", "VARCHAR"})
_LOB_TYPES = frozenset({"CLOB", "NCLOB", "BLOB"})
_COLUMNS = (
    "SELECT c.OWNER, c.TABLE_NAME, c.COLUMN_NAME, c.DATA_TYPE, c.NULLABLE, c.DATA_PRECISION, c.DATA_SCALE "
    "FROM ALL_TAB_COLUMNS c JOIN ALL_USERS u ON u.USERNAME = c.OWNER "
    "WHERE u.ORACLE_MAINTAINED = 'N' AND c.TABLE_NAME NOT LIKE 'BIN$%' "
    "ORDER BY c.OWNER, c.TABLE_NAME, c.COLUMN_ID"
)
_KEYS = (
    "SELECT k.OWNER, k.TABLE_NAME, kc.COLUMN_NAME FROM ALL_CONSTRAINTS k "
    "JOIN ALL_CONS_COLUMNS kc ON kc.OWNER = k.OWNER AND kc.CONSTRAINT_NAME = k.CONSTRAINT_NAME "
    "JOIN ALL_USERS u ON u.USERNAME = k.OWNER "
    "WHERE k.CONSTRAINT_TYPE = 'P' AND u.ORACLE_MAINTAINED = 'N'"
)
_AUTH_CODES = frozenset({"ORA-01017", "ORA-01004", "ORA-01005", "ORA-28000", "ORA-28001", "ORA-28040", "DPY-4001"})
_PERMISSION_CODES = frozenset({"ORA-01031", "ORA-01045", "ORA-00942", "ORA-01456", "ORA-04043"})
_UNREACHABLE_CODES = frozenset({"ORA-12514", "ORA-12505", "ORA-12541", "ORA-12170", "ORA-12537", "ORA-03113",
                                "ORA-03114", "ORA-03135", "ORA-01033", "ORA-01034", "ORA-01089", "ORA-01109",
                                "DPY-4011"})


def _kind(exc: BaseException, *, connecting: bool) -> str:
    error = exc.args[0] if exc.args else None
    code = getattr(error, "full_code", None) or ""
    if code in _AUTH_CODES:
        return "auth"
    if code in _PERMISSION_CODES:
        return "permission"
    if connecting or code in _UNREACHABLE_CODES or code.startswith("DPY-6"):
        return "unreachable"
    return "query"


def _quote(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def _db_type(data_type: str, precision: Any, scale: Any) -> str:
    if data_type == "NUMBER" and scale is not None:
        return f"NUMBER({38 if precision is None else precision},{scale})"
    return data_type


class _HostChecking(ssl.SSLContext):
    """A client context that checks the certificate against ``server_name``.

    python-oracledb turns ``check_hostname`` off and would match the certificate against
    the address it dialled (the worker's checked ``hostaddr``); this context sends the
    host name as SNI and lets the handshake itself check the certificate against it.
    """

    server_name = ""

    def wrap_socket(self, sock, server_side=False, do_handshake_on_connect=True, suppress_ragged_eofs=True,
                    server_hostname=None, session=None):
        del server_hostname  # the driver passes none, or a name it derived; the source's host decides
        self.check_hostname = True
        return super().wrap_socket(sock, server_side=server_side, do_handshake_on_connect=do_handshake_on_connect,
                                   suppress_ragged_eofs=suppress_ragged_eofs, server_hostname=self.server_name,
                                   session=session)


def _tls(sslmode: str, host: str) -> ssl.SSLContext:
    if sslmode == "verify-full":
        ctx: ssl.SSLContext = _HostChecking(ssl.PROTOCOL_TLS_CLIENT)
        ctx.server_name = host
    else:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        if sslmode == "require":
            ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if ctx.verify_mode != ssl.CERT_NONE:
        ctx.load_default_certs()
    return ctx


def _hostaddr(settings: dict[str, Any]) -> str:
    """The address the worker checked; the connector dials exactly this."""
    addr = settings.get("hostaddr")
    try:
        return str(ipaddress.ip_address(addr))
    except ValueError:
        raise ValueError("the sync worker must supply a checked hostaddr") from None


def _params(settings: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Driver arguments from the settings, and the auth mode; ``settings`` errors first."""
    host = _warehouse.setting(settings, "host", required=True)
    port = settings.get("port", 1521)
    sslmode = settings.get("sslmode") or "verify-full"
    if type(port) is not int or not 0 < port < 65536 or sslmode not in _SSL_MODES:
        raise ConnectorError("settings") from None
    service = _warehouse.setting(settings, "service_name", _SERVICE, required=True)
    auth = _warehouse.setting(settings, "auth", _AUTH) or "password"
    user = _warehouse.setting(settings, "user", _USER, required=auth == "password")
    params: dict[str, Any] = {
        "host": _hostaddr(settings), "port": port, "service_name": service,
        "protocol": "tcp" if sslmode == "disable" else "tcps", "tcp_connect_timeout": _warehouse.LOGIN_TIMEOUT_S,
        "retry_count": 0, "program": _warehouse.QUERY_TAG,
    }
    if sslmode != "disable":
        params.update(ssl_context=_tls(sslmode, host), ssl_server_dn_match=False)
    if auth == "password":
        params["user"] = user
    return params, auth


def _collates(version: Any) -> bool:
    """Whether a server of ``version`` ("19.3.0.0.0") has the ``COLLATE`` operator (12.2+)."""
    try:
        major, minor = (int(part) for part in str(version).split(".")[:2])
    except ValueError:
        return True
    return (major, minor) >= (12, 2)


class OracleRowSource:
    """An Oracle database read in read-only transactions; collections are ``OWNER.TABLE``."""

    def __init__(self, conn: Any, schemas: list[str] | None) -> None:
        self.conn = conn
        self._schemas = schemas
        self._columns = _warehouse.Columns()
        self._binary = " COLLATE BINARY" if _collates(getattr(conn, "version", "")) else ""

    def compare_binary(self) -> None:
        """Compare text byte for byte in this session, whatever a logon trigger set."""
        with self.conn.cursor() as cur:
            cur.execute("ALTER SESSION SET NLS_COMP = BINARY NLS_SORT = BINARY")

    def begin(self) -> None:
        """End any transaction and start a read-only one."""
        self.conn.rollback()
        with self.conn.cursor() as cur:
            cur.execute("SET TRANSACTION READ ONLY")

    def _rows(self, query: str, page_size: int) -> Iterator[tuple]:
        import oracledb

        try:
            self.begin()
            cur = self.conn.cursor()
            cur.arraysize = max(1, page_size)
            cur.prefetchrows = cur.arraysize + 1
            cur.execute(query, fetch_lobs=False)
        except oracledb.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None
        try:
            while rows := cur.fetchmany():
                yield from rows
        except oracledb.Error as exc:
            raise ConnectorError(_kind(exc, connecting=False)) from None
        finally:
            try:
                cur.close()
                self.begin()
            except oracledb.Error:
                pass

    def _wanted(self, owner: str) -> bool:
        return self._schemas is None or any(owner in (s, s.upper()) for s in self._schemas)

    def list_collections(self) -> list[CollectionInfo]:
        keys = {(o, t, c) for o, t, c in self._rows(_KEYS, 2000)}
        names = self._columns.fill(
            (owner, table, FieldInfo(column, db_type=_db_type(dtype, prec, scale), nullable=nullable == "Y",
                                     primary_key=(owner, table, column) in keys))
            for owner, table, column, dtype, nullable, prec, scale in self._rows(_COLUMNS, 2000)
            if self._wanted(owner))
        return [CollectionInfo(name) for name in names]

    def list_fields(self, collection: str) -> list[FieldInfo]:
        if not self._columns.known():
            self.list_collections()
        return list(self._columns.get(collection)[2])

    def _table(self, collection: str) -> tuple[str, dict[str, FieldInfo]]:
        fields = self.list_fields(collection)
        owner, table, _ = self._columns.get(collection)
        return f"{_quote(owner)}.{_quote(table)}", {f.name: f for f in fields}

    @staticmethod
    def _lob(info: FieldInfo) -> bool:
        return info.db_type in _LOB_TYPES

    def iter_records(
        self,
        collection: str,
        fields: list[str] | None = None,
        limit: int | None = None,
        page_size: int = 500,
    ) -> Iterator[SourceRecord]:
        table, infos = self._table(collection)
        selected = _warehouse.check_fields(list(infos.values()), fields)
        pks = [n for n, f in infos.items() if f.primary_key]
        pk = pks[0] if len(pks) == 1 else None
        columns = selected + ([pk] if pk and pk not in selected else [])
        exprs = [f"DBMS_LOB.SUBSTR({_quote(n)}, {_LOB_CHARS}, 1)" if self._lob(infos[n]) else _quote(n)
                 for n in columns]
        query = f"SELECT {', '.join(exprs)} FROM {table}"
        if limit is not None:
            query += f" FETCH FIRST {max(0, int(limit))} ROWS ONLY"
        for count, row in enumerate(self._rows(query, page_size), 1):
            values = dict(zip(columns, row, strict=True))
            ref = values[pk] if pk else count
            yield SourceRecord(f"{collection}:{ref}", {f: values[f] for f in selected}, {})

    def iter_distinct_values(self, collection: str, fields: list[str], limit: int) -> Iterator[tuple]:
        """``SELECT DISTINCT`` of ``fields`` as text compared byte for byte, all-NULL rows
        and long LOB values skipped, at most ``limit``."""
        table, infos = self._table(collection)
        selected = _warehouse.check_fields(list(infos.values()), fields)
        cols, guards = [], []
        for name in selected:
            q, dtype = _quote(name), infos[name].db_type
            if dtype in _LOB_TYPES:
                cols.append(f"DBMS_LOB.SUBSTR({q}, {_LOB_CHARS}, 1){self._binary}")
                guards.append(f"({q} IS NULL OR DBMS_LOB.GETLENGTH({q}) <= {_LOB_CHARS})")
            else:
                cols.append((q if dtype in _TEXT_TYPES else f"TO_CHAR({q})") + self._binary)
        some = " OR ".join(f"{_quote(f)} IS NOT NULL" for f in selected)
        where = " AND ".join([f"({some})", *guards])
        query = (f"SELECT DISTINCT {', '.join(cols)} FROM {table} WHERE {where} "
                 f"FETCH FIRST {max(0, int(limit))} ROWS ONLY")
        for row in self._rows(query, 2000):
            yield tuple(row)

    def close(self) -> None:
        try:
            self.conn.close()
        except Exception:
            pass


class OracleConnector(LicensedConnector):
    type_id = "oracle"

    def connector_metadata(self) -> ConnectorMetadata:
        return ConnectorMetadata(
            id="oracle",
            name="Oracle",
            version="1.0",
            capabilities=["list_collections", "list_fields", "page_records", "distinct_values"],
            settings_schema={"host": {"required": True}, "port": {}, "service_name": {"required": True}, "user": {},
                             "sslmode": {}, "auth": {}, "schemas": {}, "collections": {}},
            secrets_schema={"password": {}, "wallet_pem": {}, "wallet_password": {}},
        )

    def connect(self, settings: dict[str, Any], secrets: dict[str, str]) -> RowSource:
        self.require_license()
        params, auth = _params(settings)
        schemas = _warehouse.schema_filter(settings)
        wallet = secrets.get("wallet_pem") or None
        if wallet is not None and (not isinstance(wallet, str) or "-----BEGIN " not in wallet):
            raise ConnectorError("auth") from None
        if wallet is not None and params["protocol"] != "tcps":
            raise ConnectorError("settings") from None
        if auth == "wallet":
            if wallet is None:
                raise ConnectorError("auth") from None
            params["externalauth"] = True
        else:
            password = secrets.get("password")
            if not isinstance(password, str) or not password:
                raise ConnectorError("auth") from None
            params["password"] = password
        if wallet is not None and secrets.get("wallet_password"):
            params["wallet_password"] = secrets["wallet_password"]
        import oracledb

        try:
            with wallet_dir(wallet) as where:
                if where is not None:
                    params["wallet_location"] = where
                conn = oracledb.connect(**params)
        except oracledb.Error as exc:
            raise ConnectorError(_kind(exc, connecting=True)) from None
        except OSError:
            raise ConnectorError("unreachable") from None
        source = OracleRowSource(conn, schemas)
        try:
            conn.call_timeout = _warehouse.STATEMENT_TIMEOUT_S * 1000
            source.compare_binary()
            source.begin()
        except oracledb.Error as exc:
            source.close()
            raise ConnectorError(_kind(exc, connecting=True)) from None
        return source
