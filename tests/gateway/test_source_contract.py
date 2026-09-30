"""The ``erebus.sources`` contract additions (spec 015 "Architecture": contract additions).

Pure. ``FieldInfo`` gains db type, nullable and primary key without breaking positional
use; ``distinct_values`` uses a source's optional ``iter_distinct_values`` and otherwise
de-duplicates ``iter_records`` (so SQLite and third-party connectors keep working); the
worker loads entry points strictly (a broken plugin raises) while the laptop skips it;
the built-in SQLite connector lives in ``erebus.cataloging.connectors`` and loads lazily.
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.cataloging import sources
from erebus.cataloging.sources import CollectionInfo, FieldInfo, SourceRecord

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


class _RecordsOnly:
    """A third-party source with no ``iter_distinct_values``."""

    def __init__(self, rows):
        self.rows = rows
        self.asked = []

    def list_collections(self):
        return [CollectionInfo("people")]

    def list_fields(self, collection):
        return [FieldInfo("email"), FieldInfo("name")]

    def iter_records(self, collection, fields=None, limit=None, page_size=500):
        self.asked.append((collection, tuple(fields or ()), limit))
        for i, row in enumerate(self.rows):
            yield SourceRecord(f"{collection}:{i}", {k: row.get(k) for k in (fields or row)})

    def close(self):
        pass


class _WithDistinct(_RecordsOnly):
    def iter_distinct_values(self, collection, fields, limit):
        self.asked.append(("distinct", collection, tuple(fields), limit))
        yield ("from-method",)


class _EP:
    def __init__(self, name, target):
        self.name = name
        self._target = target

    def load(self):
        if isinstance(self._target, BaseException):
            raise self._target
        return self._target


class _Plugin:
    def __init__(self, cid):
        self.cid = cid

    def connector_id(self):
        return self.cid


def test_field_info():
    old = FieldInfo("email", "Email", "email", "email")
    check("FieldInfo keeps its positional fields",
          (old.label, old.kind_hint, old.pii_hint) == ("Email", "email", "email"))
    check("the new fields default to unknown", (old.db_type, old.nullable, old.primary_key) == ("", None, False))
    new = FieldInfo("id", db_type="integer", nullable=False, primary_key=True)
    check("the new fields can be set", (new.db_type, new.nullable, new.primary_key) == ("integer", False, True))


def test_distinct_values():
    rows = [{"email": "a@x.example", "name": "A"}, {"email": "a@x.example", "name": "A"},
            {"email": "b@x.example", "name": "B"}, {"email": "c@x.example", "name": "C"}]
    plain = _RecordsOnly(rows)
    got = list(sources.distinct_values(plain, "people", ["email", "name"], 10))
    check("the fallback de-duplicates records into tuples in field order",
          got == [("a@x.example", "A"), ("b@x.example", "B"), ("c@x.example", "C")])
    check("the fallback reads only the asked fields", plain.asked == [("people", ("email", "name"), None)])
    check("the fallback stops at the limit", len(list(sources.distinct_values(_RecordsOnly(rows), "people",
                                                                               ["email"], 2))) == 2)
    method = _WithDistinct(rows)
    check("a source's own iter_distinct_values is used",
          list(sources.distinct_values(method, "people", ["email"], 5)) == [("from-method",)])
    check("it gets the collection, fields and limit", method.asked == [("distinct", "people", ("email",), 5)])


def test_entry_points():
    saved = dict(sources._CONNECTORS)
    try:
        sources._CONNECTORS.clear()
        broken = [_EP("good", _Plugin("good-one")), _EP("bad", ImportError("no driver"))]
        sources.load_connectors(eps=broken)
        check("the laptop skips a plugin that fails to load", "good-one" in sources._CONNECTORS)
        sources._CONNECTORS.clear()
        try:
            sources.load_connectors(strict=True, eps=broken)
            raised = False
        except ImportError:
            raised = True
        check("the worker's strict load raises it", raised)
        sources._CONNECTORS.clear()
        dup = [_EP("a", _Plugin("same")), _EP("b", _Plugin("same"))]
        try:
            sources.load_connectors(strict=True, eps=dup)
            raised = False
        except ValueError:
            raised = True
        check("a strict load refuses two plugins with one id", raised)
    finally:
        sources._CONNECTORS.clear()
        sources._CONNECTORS.update(saved)


def test_worker_loads_strictly():
    import contextlib
    import io

    from erebus.sync import cli

    real = sources.load_connectors
    calls = []

    def broken(**kw):
        calls.append(kw)
        raise ImportError("secret-dsn-text")

    sources.load_connectors = broken
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            cli._load_connectors()
        code = None
    except SystemExit as exc:
        code = exc.code
    finally:
        sources.load_connectors = real
    check("the worker loads connectors strictly", calls == [{"strict": True}])
    check("a connector that fails to load stops the worker (exit 2)", code == 2)
    check("the message names the exception type only",
          "ImportError" in err.getvalue() and "secret-dsn-text" not in err.getvalue())


def test_sqlite_lazy():
    code = (
        "import sys; from erebus.cataloging import sources;"
        "a = 'erebus.cataloging.connectors' in sys.modules;"
        "c = sources.get_connector('sqlite');"
        "b = 'erebus.cataloging.connectors.sqlite' in sys.modules;"
        "print(a, b, type(c).__module__, sources.SQLiteConnector is type(c))"
    )
    root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=root, check=True).stdout
    check("importing the contract loads no connector module", out.split()[0] == "False")
    check("asking for sqlite loads it from erebus.cataloging.connectors",
          out.split()[1:3] == ["True", "erebus.cataloging.connectors.sqlite"])
    check("sources.SQLiteConnector still names it", out.split()[3] == "True")


def main():
    print("source contract")
    test_field_info()
    test_distinct_values()
    test_entry_points()
    test_worker_loads_strictly()
    test_sqlite_lazy()
    print(f"  {_passed} checks passed")


if __name__ == "__main__":
    main()
