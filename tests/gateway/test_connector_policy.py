"""Connector store rules that need no Postgres (spec 015 "Sync behaviour", "Failure").

Pure: the job failure and lease policy, the value rules applied at upsert, the fixed
error texts, and the source-secrets envelope (AAD bound to the source id). A fake
connection that records every statement stands in for Postgres to prove the store
never sends a plaintext credential and never decrypts on the write path.
"""
import contextlib
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from cryptography.exceptions import InvalidTag

from erebus.gateway.connectors import policy, sources
from erebus.gateway.crypto.envelope import ScopeCrypto
from erebus.gateway.crypto.keyprovider import LocalKms

_passed = 0
_NOW = datetime(2026, 9, 30, 12, 0, tzinfo=UTC)
_T = policy.JobTimings()


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _raises(exc_type, fn):
    try:
        fn()
    except exc_type:
        return True
    return False


def _fail(error_class, attempts=0, limited_since=None, **kw):
    return policy.failure_outcome(error_class, attempts=attempts, limited_since=limited_since, now=_NOW,
                                  timings=_T, **kw)


def _check_failure_policy():
    for cls in ("auth", "permission", "incomplete", "crypto_erased"):
        out = _fail(cls)
        check(f"{cls} fails unretried and flags the source", (out.status, out.needs_attention) == ("failed", True))
        check(f"{cls} counts as an attempt", out.attempts == 1)

    lic = _fail("license", detail="requires Erebus Pro (feature connectors.snowflake)")
    check("LicenseRequired fails unretried and flags the source", (lic.status, lic.needs_attention) == ("failed", True))
    check("LicenseRequired text is stored verbatim", lic.error == "requires Erebus Pro (feature connectors.snowflake)")
    odd = _fail("license", detail="requires Erebus Pro (feature x) password=hunter2")
    check("a license message of another shape falls back to fixed text", "hunter2" not in odd.error)
    drv = _fail("driver", detail="requires the erebus-pro[mssql-entra] extra")
    check("a missing driver fails unretried and flags the source",
          (drv.status, drv.needs_attention) == ("failed", True))
    check("... naming the extra to install", drv.error == "requires the erebus-pro[mssql-entra] extra")
    odd = _fail("driver", detail="requires the x[y] extra; password=hunter2")
    check("a driver message of another shape falls back to fixed text",
          odd.error == policy.ERROR_TEXT["driver"] and "hunter2" not in odd.error)
    check("a license message is not kept for another class",
          _fail("driver", detail="requires Erebus Pro (feature x)").error == policy.ERROR_TEXT["driver"])

    for cls in ("unreachable", "query"):
        waits = []
        attempts = 0
        for _ in range(3):
            out = _fail(cls, attempts=attempts)
            check(f"{cls} attempt {attempts + 1} re-queues", out.status == "queued" and not out.needs_attention)
            waits.append((out.not_before - _NOW).total_seconds())
            attempts = out.attempts
        check(f"{cls} backs off 1, 5, 15 minutes", waits == [60, 300, 900])
        last = _fail(cls, attempts=attempts)
        check(f"{cls} fails after three retries", last.status == "failed" and last.attempts == 4)
        check(f"{cls} exhaustion does not flag the source (a long outage is not a setup error)",
              last.needs_attention is False)

    other = _fail("SomethingElse('postgres://u:pw@db')")
    check("an unknown class is retried as internal", other.status == "queued")
    check("an unknown class stores the fixed internal text", other.error == policy.ERROR_TEXT["internal"])

    reset = _NOW + timedelta(minutes=7)
    lim = _fail("limit", attempts=2, reset_at=reset)
    check("limit waits until the reset signal", lim.status == "queued" and lim.not_before == reset)
    check("limit is not an attempt", lim.attempts == 2)
    check("limit records when the wait began", lim.limited_since == _NOW)
    later = _fail("limit", limited_since=_NOW - timedelta(hours=47), reset_at=_NOW + timedelta(minutes=30))
    check("limit keeps the first wait start", later.limited_since == _NOW - timedelta(hours=47))
    check("limit still waits inside 48 h", later.status == "queued")
    gone = _fail("limit", limited_since=_NOW - timedelta(hours=48, seconds=1))
    check("limit fails once it has waited 48 h", gone.status == "failed" and not gone.needs_attention)
    beyond = _fail("limit", limited_since=_NOW - timedelta(hours=1), reset_at=_NOW + timedelta(hours=48))
    check("limit fails at once when the reset lies past the 48 h window", beyond.status == "failed")
    bare = _fail("limit")
    check("limit without a reset signal waits the first backoff step",
          bare.not_before == _NOW + timedelta(seconds=60))

    for n, expect in ((0, "queued"), (1, "queued"), (2, "failed")):
        out = policy.lease_outcome(attempts=n, timings=_T)
        check(f"lease expiry after {n} failed attempts -> {expect}", out.status == expect)
    check("the third lease expiry flags the source", policy.lease_outcome(attempts=2, timings=_T).needs_attention)
    check("every stored error is fixed text", all(isinstance(v, str) and v for v in policy.ERROR_TEXT.values()))


def _check_value_rules():
    r = policy.reject_reason
    check("a value under 3 characters is rejected", r("Al", "PERSON") == "short")
    check("whitespace does not count toward the length", r("  a  ", "IDENTIFIER") == "short")
    check("numeric-only under 6 digits is dropped", r("12345", "IDENTIFIER") == "numeric")
    check("6 digits are kept", r("123456", "IDENTIFIER") is None)
    check("a single-word PERSON is dropped", r("Mark", "PERSON") == "single_word")
    check("a single-word PERSON is dropped whatever the label spelling", r("Mark", "person") == "single_word")
    check("a two-word PERSON is kept", r("Jan de Vries", "PERSON") is None)
    check("a single-word email is kept", r("jan@acme.com", "EMAIL_ADDRESS") is None)
    check("a stop word is dropped", r("Support", "ORGANIZATION", stop_words={"support"}) == "stop_word")
    check("a stop word only drops single words", r("Support Desk BV", "ORGANIZATION", stop_words={"support"}) is None)
    check("clean_value collapses whitespace runs", policy.clean_value("  Jan \t de\nVries ") == "Jan de Vries")


class _FakeCursor:
    def __init__(self, row):
        self._row = row

    def fetchone(self):
        return self._row

    def fetchall(self):
        return [self._row] if self._row else []


class _FakeConn:
    """Records (sql, params); answers every statement with ``row``."""

    def __init__(self, row=None):
        self.calls = []
        self.row = row

    def execute(self, query, params=()):
        self.calls.append((query, params))
        return _FakeCursor(self.row)

    @contextlib.contextmanager
    def transaction(self):
        yield


def _flat(params):
    for p in params:
        if isinstance(p, (list, tuple)):
            yield from _flat(p)
        else:
            yield p


def _check_secrets():
    kms = LocalKms()
    scope = uuid.uuid4()
    crypto, _wrapped = ScopeCrypto.create(kms, str(scope))
    secret = {"password": "hunter2-Zyx", "api_key": "sk-live-XYZ"}
    conn = _FakeConn(row=(uuid.uuid4(),))
    sid = sources.create_source(conn, crypto, scope, name="crm", connector_type="postgres",
                                settings={"host": "db.example", "dbname": "crm"}, secrets=secret)
    check("create_source returns the id it bound the secrets to", isinstance(sid, uuid.UUID))
    blob = repr([list(_flat(p)) for _q, p in conn.calls])
    check("no plaintext credential reaches the database", "hunter2" not in blob and "sk-live" not in blob)
    insert = next((q, p) for q, p in conn.calls if "INSERT INTO sources" in q)
    params = insert[1]
    ct, nonce = next(p for p in params if isinstance(p, bytes) and len(p) > 12), \
        next(p for p in params if isinstance(p, bytes) and len(p) == 12)
    check("the row id is the AAD the secrets were sealed to",
          json.loads(sources.open_secrets(crypto, sid, nonce, ct)) == secret)
    check("the ciphertext does not open under another source id",
          _raises(InvalidTag, lambda: sources.open_secrets(crypto, uuid.uuid4(), nonce, ct)))
    check("secrets must be a JSON object", _raises(ValueError, lambda: sources.seal_secrets(crypto, sid, ["x"])))

    conn2 = _FakeConn(row=(1,))
    sources.update_source(conn2, crypto, scope, sid, secrets={"password": "rotated-Qq9"})
    blob2 = repr([list(_flat(p)) for _q, p in conn2.calls])
    check("replacing credentials sends no plaintext either", "rotated-Qq9" not in blob2)
    check("the write path never selects the stored ciphertext",
          not any("SELECT" in q and "secrets_ciphertext" in q for q, _ in conn.calls + conn2.calls))

    check("SourceBusy has fixed text", str(sources.SourceBusy()) == "a sync job is running for this source")
    check("SecretsUnreadable has fixed text", str(sources.SecretsUnreadable()) == "source credentials cannot be read")


def main():
    print("\n=== Connector store policy (spec 015 Sync behaviour, Failure) ===\n")
    _check_failure_policy()
    _check_value_rules()
    _check_secrets()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
