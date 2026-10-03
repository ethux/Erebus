"""The shared source connector contract suite (spec 015 SC-6, SC-9); not a test module itself.

``run(backend_cls)`` puts one connector through the same checks, whatever its family:
it lists collections (user schemas only) and fields (db type, nullable, primary key),
streams records and distinct values, stays read-only, raises only fixed-text errors (no
host, DSN, user, password or value in the message or traceback) and connects only where
the worker's network policy let it. A Pro connector also refuses to connect without its
license feature.

A backend (see ``connector_backends``) builds the fixture and says what its source can
show. Optional attributes, with their defaults: ``tier`` ("free"), ``primary_key`` (True:
the source reports primary keys), ``nullability`` (True), ``integer_classes``
(("integer",)), ``connector_type()`` (the installed type). Read-only is proven by a
refused raw write (``write_probe``) or, where a fake cannot refuse one (warehouses: the
documented role is the guard), by ``statements(source)``: every statement the connector
sent, which must all be single reads.
"""
from __future__ import annotations

import contextlib
import os
import re
import traceback
from collections.abc import Iterator

from connector_backends import FIELDS

from erebus.cataloging import connector_types, sources
from erebus.cataloging.connector_errors import CONNECTOR_TEXT, ConnectorError, LicenseRequired
from erebus.cataloging.field_types import type_class
from erebus.sync import netpolicy
from erebus.sync.netpolicy import HostList, NetworkPolicy, PolicyError

_SYSTEM = ("pg_catalog", "pg_toast", "information_schema", "mysql", "sys", "performance_schema")
_READ = re.compile(r"\s*(SELECT|WITH|SHOW)\b[^;]*;?\s*", re.I | re.S)
passed = 0


def check(name, cond):
    global passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    passed += 1


def _error(fn):
    try:
        fn()
    except ConnectorError as exc:
        return exc
    return None


def _fixed(exc, kind):
    return exc is not None and exc.kind == kind and str(exc) == CONNECTOR_TEXT[kind]


def _ctype(b, connector):
    getter = getattr(b, "connector_type", None)
    return getter() if getter else connector_types.get(connector.connector_id())


def _lists(b, src):
    names = [c.name for c in src.list_collections()]
    check(f"{b.name}: lists its collections", {b.collection("customers"), b.collection("orders")} <= set(names))
    if b.schemas:
        check(f"{b.name}: lists every user schema", any(n.endswith(".orders") and n != b.collection("orders")
                                                        for n in names))
        check(f"{b.name}: lists no system schema", not any(n.split(".")[0].lower() in _SYSTEM for n in names))


def _fields(b, src):
    fields = {f.name: f for f in src.list_fields(b.collection("customers"))}
    check(f"{b.name}: lists fields in column order", list(fields) == FIELDS)
    if getattr(b, "primary_key", True):
        check(f"{b.name}: marks the primary key", fields["id"].primary_key
              and not any(f.primary_key for n, f in fields.items() if n != "id"))
    else:
        check(f"{b.name}: marks no primary key it cannot know", not any(f.primary_key for f in fields.values()))
    classes = {n: type_class(f.db_type) for n, f in fields.items()}
    check(f"{b.name}: reports db types the field rules classify",
          classes["id"] in getattr(b, "integer_classes", ("integer",)) and classes["email"] == "text"
          and classes["notes"] == "text" and classes["signup"] == "datetime"
          and classes["active"] in ("boolean", "integer"))
    if getattr(b, "nullability", True):
        check(f"{b.name}: reports nullability", fields["notes"].nullable is True
              and fields["full_name"].nullable is False and fields["id"].nullable is False)


def _streams(b, src):
    coll = b.collection("customers")
    it = src.iter_records(coll, limit=2)
    check(f"{b.name}: iter_records streams (an iterator, not a list)", isinstance(it, Iterator))
    records = list(it)
    check(f"{b.name}: honours the limit", len(records) == 2)
    check(f"{b.name}: a record carries every field", set(records[0].values) == set(FIELDS))
    refs = {r.record_ref for r in records}
    if getattr(b, "primary_key", True):
        check(f"{b.name}: a record ref names the primary key", refs == {f"{coll}:1", f"{coll}:2"})
    else:
        check(f"{b.name}: record refs are distinct and name the collection",
              len(refs) == 2 and all(r.startswith(f"{coll}:") for r in refs))
    only = list(src.iter_records(coll, fields=["email"]))
    check(f"{b.name}: reads only the asked fields", len(only) == 5 and all(set(r.values) == {"email"} for r in only))


def _distinct(b, src):
    coll = b.collection("customers")
    if b.name != "sqlite" or hasattr(src, "iter_distinct_values"):
        check(f"{b.name}: has its own iter_distinct_values", callable(getattr(src, "iter_distinct_values", None)))
    emails = list(sources.distinct_values(src, coll, ["email"], 100))
    check(f"{b.name}: distinct values skip NULLs and duplicates, keep case variants",
          sorted(emails) == [("Zyx.Qorbel@ACME.example",), ("mila.brandt@acme.example",),
                             ("zyx.qorbel@acme.example",)])
    pairs = set(sources.distinct_values(src, coll, ["first_name", "last_name"], 100))
    check(f"{b.name}: distinct tuples come in field order, accent variants kept",
          pairs == {("Zyx", "Qorbel"), ("Zyx", "Qorbël"), ("Mila", "Brandt"), ("Anna", "Visser")})
    check(f"{b.name}: distinct values honour the limit",
          len(list(sources.distinct_values(src, coll, ["full_name"], 1))) == 1)
    groups = [["email"], ["first_name", "last_name"], ["notes"]]
    got = list(sources.distinct_groups(src, coll, groups, 100))
    check(f"{b.name}: distinct groups tag each tuple with its group",
          sorted(row for i, row in got if i == 0) == sorted(emails)
          and {row for i, row in got if i == 1} == pairs and [row for i, row in got if i == 2] == [("vip",)])
    check(f"{b.name}: distinct groups share one limit", len(list(sources.distinct_groups(src, coll, groups, 4))) == 4)


def _read_only(b, src):
    if hasattr(b, "write_probe"):
        try:
            b.write_probe(src)
            refused = None
        except Exception as exc:
            refused = exc
        check(f"{b.name}: a write through its connection is refused",
              refused is not None and b.is_write_refusal(refused))
    else:
        sent = b.statements(src)
        check(f"{b.name}: sends only single read statements (the documented role guards writes)",
              sent and all(_READ.fullmatch(s) for s in sent))
    check(f"{b.name}: the source still reads", len(list(src.iter_records(b.collection("orders")))) == 1)


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


def _shown(exc):
    """What a log of ``exc`` would show beyond code: its repr and every message in the
    printed chain. Frame lines are left out: they hold paths and source, not runtime
    values, and a path such as ``connectors/postgres.py`` would match a password ``postgres``."""
    parts = [repr(exc)]
    while exc is not None:
        parts += traceback.format_exception_only(exc)
        exc = exc.__cause__ if exc.__cause__ is not None else (None if exc.__suppress_context__ else exc.__context__)
    return "".join(parts)


def _sanitized(b, connector):
    """``bad_cases()`` rows: (case, settings, secrets, kind, hidden texts[, a context manager
    the attempt runs in, for a failure only the driver boundary can raise])."""
    for case, settings, secrets, kind, hidden, *around in b.bad_cases():
        def attempt(settings=settings, secrets=secrets):
            src = connector.connect(settings, secrets)
            try:
                src.list_collections()
            finally:
                src.close()
        with around[0] if around else contextlib.nullcontext():
            exc = _error(attempt)
        check(f"{b.name}: {case} fails as '{kind}' with fixed text", _fixed(exc, kind))
        shown = _shown(exc)
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
            check(f"sqlite: {label} outside the directory is denied",
                  _policy_kind(policy, ctype, {"path": path}) == "denied")
        check("sqlite: without EREBUS_SYNC_SQLITE_DIR SQLite is off",
              _policy_kind(NetworkPolicy(denied=HostList()), ctype, {"path": "crm.db"}) == "denied")
    finally:
        link.unlink()
        outside.unlink()


def _policy_kind(policy, ctype, settings):
    try:
        netpolicy.prepare_settings(policy, ctype, settings)
    except PolicyError as exc:
        return exc.kind
    return None


def _db_policy(b, connector, ctype):
    raw = {k: v for k, v in b.settings().items() if k != "hostaddr"}
    check(f"{b.name}: the default policy denies a loopback source",
          _policy_kind(NetworkPolicy(denied=netpolicy.default_denied("")), ctype, raw) == "denied")
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


def _warehouse_policy(b, connector, ctype):
    """A SaaS warehouse takes an account or project id, never a host, DSN or endpoint."""
    policy = NetworkPolicy(denied=netpolicy.default_denied(""))
    settings = netpolicy.prepare_settings(policy, ctype, b.settings())
    check(f"{b.name}: the worker passes its settings as they are (the vendor host is derived)",
          settings == b.settings() and "hostaddr" not in settings)
    for key, value in (("host", "evil.example"), ("dsn", "x://u:p@evil.example"), ("api_endpoint", "http://x"),
                       ("port", 443)):
        check(f"{b.name}: a '{key}' setting is refused",
              _policy_kind(policy, ctype, {**b.settings(), key: value}) == "settings")
    src = connector.connect(settings, b.secrets())
    try:
        check(f"{b.name}: connects with the settings the worker checked", len(src.list_collections()) >= 2)
    finally:
        src.close()


class _Watched(dict):
    """A secrets dict that records whether anyone read it."""

    touched = False

    def __getitem__(self, key):
        self.touched = True
        return super().__getitem__(key)

    def get(self, key, default=None):
        self.touched = True
        return super().get(key, default)


def _license(b):
    feature = f"connectors.{b.name}"
    for case, ents in b.unlicensed():
        secrets = _Watched(b.secrets())
        try:
            b.connector(entitlements=ents).connect(b.settings(), secrets)
            exc = None
        except LicenseRequired as raised:
            exc = raised
        check(f"{b.name}: {case}: refuses to connect with LicenseRequired",
              exc is not None and exc.feature == feature and str(exc) == f"requires Erebus Pro (feature {feature})")
        check(f"{b.name}: {case}: before reading a credential", not secrets.touched)


def run(backend_cls):
    b = backend_cls()
    reason = b.unavailable()
    if reason:
        if b.name == "mysql" and os.environ.get("EREBUS_REQUIRE_MYSQL") == "1":
            raise AssertionError(f"mysql is required here: {reason}")
        if os.environ.get(f"EREBUS_REQUIRE_{b.name.upper()}") == "1":
            raise AssertionError(f"{b.name} is required here: {reason}")
        print(f"  - {b.name}: skipped ({reason})")
        return
    print(f"  [{b.name}]")
    b.setup()
    try:
        connector = b.connector()
        ctype = _ctype(b, connector)
        tier = getattr(b, "tier", "free")
        check(f"{b.name}: its id is a known {tier} connector type", ctype is not None and ctype.tier == tier
              and ctype.id == connector.connector_id())
        if tier == "pro":
            _license(b)
        src = connector.connect(b.settings(), b.secrets())
        try:
            for part in (_lists, _fields, _streams, _distinct, _read_only, _query_errors):
                part(b, src)
        finally:
            src.close()
        if b.schemas:
            _schema_filter(b, connector)
        _sanitized(b, connector)
        if ctype.family == "file":
            _sqlite_policy(b, connector)
        elif ctype.family == "warehouse":
            _warehouse_policy(b, connector, ctype)
        else:
            _db_policy(b, connector, ctype)
    finally:
        b.teardown()
