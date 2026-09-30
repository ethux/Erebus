"""One contract suite for every free source connector (spec 015 SC-6, SC-9).

Runs the same checks against SQLite (a temp file), Postgres (this test's own database
as the source) and MySQL (a throwaway server named by ``EREBUS_TEST_MYSQL_DSN``;
skipped without it unless ``EREBUS_REQUIRE_MYSQL=1``). A connector lists collections
(user schemas only) and fields (db type, nullable, primary key), streams records and
distinct values, stays read-only (a raw write through its own connection is refused:
SQLite read-only, Postgres 25006, MySQL 1792), raises only fixed-text errors (no host,
DSN, user, password or value in the message or traceback) and dials only the address
the worker's network policy checked. Connector modules import their driver only in
``connect()``, and the database ones register through ``erebus.sources``.
"""
import os
import subprocess
import sys
import traceback
from collections.abc import Iterator
from importlib import metadata
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from connector_backends import BACKENDS, FIELDS, MySQLBackend

from erebus.cataloging import connector_types, sources
from erebus.cataloging.connector_errors import CONNECTOR_TEXT, ConnectorError
from erebus.cataloging.field_types import type_class
from erebus.sync import netpolicy
from erebus.sync.netpolicy import HostList, NetworkPolicy, PolicyError

_REPO = Path(__file__).resolve().parents[2]
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _error(fn):
    try:
        fn()
    except ConnectorError as exc:
        return exc
    return None


def _fixed(exc, kind):
    return exc is not None and exc.kind == kind and str(exc) == CONNECTOR_TEXT[kind]


def _lists(b, src):
    names = [c.name for c in src.list_collections()]
    check(f"{b.name}: lists its collections", {b.collection("customers"), b.collection("orders")} <= set(names))
    if b.schemas:
        check(f"{b.name}: lists every user schema", any(n.endswith(".orders") and n != b.collection("orders")
                                                        for n in names))
        system = ("pg_catalog", "pg_toast", "information_schema", "mysql", "sys", "performance_schema")
        check(f"{b.name}: lists no system schema", not any(n.split(".")[0] in system for n in names))


def _fields(b, src):
    fields = {f.name: f for f in src.list_fields(b.collection("customers"))}
    check(f"{b.name}: lists fields in column order", list(fields) == FIELDS)
    check(f"{b.name}: marks the primary key", fields["id"].primary_key
          and not any(f.primary_key for n, f in fields.items() if n != "id"))
    classes = {n: type_class(f.db_type) for n, f in fields.items()}
    check(f"{b.name}: reports db types the field rules classify",
          classes["id"] == "integer" and classes["email"] == "text" and classes["notes"] == "text"
          and classes["signup"] == "datetime" and classes["active"] in ("boolean", "integer"))
    check(f"{b.name}: reports nullability", fields["notes"].nullable is True and fields["full_name"].nullable is False
          and fields["id"].nullable is False)


def _streams(b, src):
    coll = b.collection("customers")
    it = src.iter_records(coll, limit=2)
    check(f"{b.name}: iter_records streams (an iterator, not a list)", isinstance(it, Iterator))
    records = list(it)
    check(f"{b.name}: honours the limit", len(records) == 2)
    check(f"{b.name}: a record carries every field", set(records[0].values) == set(FIELDS))
    check(f"{b.name}: a record ref names the primary key", {r.record_ref for r in records}
          == {f"{coll}:1", f"{coll}:2"})
    only = list(src.iter_records(coll, fields=["email"]))
    check(f"{b.name}: reads only the asked fields", len(only) == 4 and all(set(r.values) == {"email"} for r in only))


def _distinct(b, src):
    coll = b.collection("customers")
    if b.name != "sqlite" or hasattr(src, "iter_distinct_values"):
        check(f"{b.name}: has its own iter_distinct_values", callable(getattr(src, "iter_distinct_values", None)))
    emails = list(sources.distinct_values(src, coll, ["email"], 100))
    check(f"{b.name}: distinct values skip NULLs and duplicates",
          sorted(emails) == [("mila.brandt@acme.example",), ("zyx.qorbel@acme.example",)])
    pairs = set(sources.distinct_values(src, coll, ["first_name", "last_name"], 100))
    check(f"{b.name}: distinct tuples come in field order",
          pairs == {("Zyx", "Qorbel"), ("Mila", "Brandt"), ("Anna", "Visser")})
    check(f"{b.name}: distinct values honour the limit",
          len(list(sources.distinct_values(src, coll, ["full_name"], 1))) == 1)


def _read_only(b, src):
    try:
        b.write_probe(src)
        refused = None
    except Exception as exc:
        refused = exc
    check(f"{b.name}: a write through its connection is refused", refused is not None and b.is_write_refusal(refused))
    check(f"{b.name}: the source still reads after the refused write",
          len(list(src.iter_records(b.collection("orders")))) == 1)


def _query_errors(b, src):
    coll = b.collection("customers")
    check(f"{b.name}: an unknown collection is a fixed query error",
          _fixed(_error(lambda: src.list_fields("nope_zq.nope_zq")), "query"))
    check(f"{b.name}: an unknown field is a fixed query error",
          _fixed(_error(lambda: list(src.iter_records(coll, fields=["no_such_zq"]))), "query"))
    evil = 'email"; DROP TABLE orders; --'
    check(f"{b.name}: a crafted field name is refused, not run",
          _fixed(_error(lambda: list(sources.distinct_values(src, coll, [evil], 10))), "query"))
    check(f"{b.name}: ... and the table is still there", len(list(src.iter_records(b.collection("orders")))) == 1)


def _schema_filter(b, connector):
    wanted = b.collection("orders").split(".")[0]
    src = connector.connect(b.settings(schemas=[wanted]), b.secrets())
    try:
        names = [c.name for c in src.list_collections()]
    finally:
        src.close()
    check(f"{b.name}: the schemas setting limits the collections",
          names and all(n.startswith(wanted + ".") for n in names))


def _sanitized(b, connector):
    for case, settings, secrets, kind, hidden in b.bad_cases():
        def attempt(settings=settings, secrets=secrets):
            src = connector.connect(settings, secrets)
            try:
                src.list_collections()
            finally:
                src.close()
        exc = _error(attempt)
        check(f"{b.name}: {case} fails as '{kind}' with fixed text", _fixed(exc, kind))
        shown = repr(exc) + "".join(traceback.format_exception(exc))
        check(f"{b.name}: {case}: no host, DSN, user, password or value shown",
              not any(h in shown for h in hidden) and "Zyx" not in shown)
        check(f"{b.name}: {case}: the driver error is not chained", exc.__cause__ is None and exc.__suppress_context__)


def _sqlite_policy(b, connector):
    ctype = connector_types.get("sqlite")
    policy = NetworkPolicy(denied=HostList(), sqlite_dir=b.root)
    settings = netpolicy.prepare_settings(policy, ctype, {"path": "crm.db"})
    src = connector.connect(settings, {})
    try:
        check("sqlite: opens a file inside the SQLite directory", len(src.list_collections()) == 2)
    finally:
        src.close()
    outside = b.root.parent / f"outside-{os.getpid()}.db"
    outside.write_bytes((b.root / "crm.db").read_bytes())
    link = b.root / "link.db"
    link.symlink_to(outside)
    try:
        for label, path in (("a relative escape", f"../{outside.name}"), ("an absolute path", str(outside)),
                            ("a symlink out", "link.db")):
            try:
                netpolicy.prepare_settings(policy, ctype, {"path": path})
                kind = None
            except PolicyError as exc:
                kind = exc.kind
            check(f"sqlite: {label} outside the directory is denied", kind == "denied")
        try:
            netpolicy.prepare_settings(NetworkPolicy(denied=HostList()), ctype, {"path": "crm.db"})
            kind = None
        except PolicyError as exc:
            kind = exc.kind
        check("sqlite: without EREBUS_SYNC_SQLITE_DIR SQLite is off", kind == "denied")
    finally:
        link.unlink()
        outside.unlink()


def _db_policy(b, connector):
    ctype = connector_types.get(b.name)
    raw = {k: v for k, v in b.settings().items() if k != "hostaddr"}
    try:
        netpolicy.prepare_settings(NetworkPolicy(denied=netpolicy.default_denied("")), ctype, raw)
        kind = None
    except PolicyError as exc:
        kind = exc.kind
    check(f"{b.name}: the default policy denies a loopback source", kind == "denied")
    settings = netpolicy.prepare_settings(NetworkPolicy(denied=HostList()), ctype, raw)
    src = connector.connect(settings, b.secrets())
    try:
        check(f"{b.name}: connects to the address the policy checked", len(src.list_collections()) >= 2)
        if hasattr(b, "tls_in_use"):
            check(f"{b.name}: sslmode require dials the checked address over TLS", b.tls_in_use(src))
    finally:
        src.close()
    try:
        connector.connect(raw, b.secrets())
        refused = False
    except ValueError:
        refused = True
    check(f"{b.name}: refuses to dial without a checked hostaddr", refused)


def _run(backend_cls):
    b = backend_cls()
    reason = b.unavailable()
    if reason:
        if b.name == "mysql" and os.environ.get("EREBUS_REQUIRE_MYSQL") == "1":
            raise AssertionError(f"mysql is required here: {reason}")
        print(f"  - {b.name}: skipped ({reason})")
        return
    print(f"  [{b.name}]")
    b.setup()
    try:
        connector = b.connector()
        ctype = connector_types.get(connector.connector_id())
        check(f"{b.name}: its id is a known connector type", ctype is not None and ctype.tier == "free")
        src = connector.connect(b.settings(), b.secrets())
        try:
            for part in (_lists, _fields, _streams, _distinct, _read_only, _query_errors):
                part(b, src)
        finally:
            src.close()
        if b.schemas:
            _schema_filter(b, connector)
        _sanitized(b, connector)
        (_sqlite_policy if b.name == "sqlite" else _db_policy)(b, connector)
    finally:
        b.teardown()


def _registration():
    eps = {ep.name: ep.value for ep in metadata.entry_points(group=sources.GROUP)}
    check("postgres registers through erebus.sources",
          eps.get("postgres") == "erebus.cataloging.connectors.postgres:PostgresConnector")
    code = "import sys; import erebus.cataloging.connectors.postgres; print('psycopg' in sys.modules)"
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=_REPO, check=True)
    check("importing a connector module loads no driver", out.stdout.split() == ["False"])


def main():
    print("\n=== source connector contract (spec 015 SC-6) ===\n")
    _registration()
    for backend in BACKENDS:
        if backend is not MySQLBackend:
            _run(backend)
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
