"""Admin API request bodies for sources (spec 015 "Admin API", "Security").

Pure: bodies are parsed by hand, so a bad one is refused with fixed text that echoes no
input (no credential, setting value or unknown key reaches an error). Types and setting
keys come from ``connector_types``; values are the worker's to check.
"""
import os
import sys
import uuid
from datetime import UTC, datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from erebus.gateway import sources_body as body
from erebus.gateway.sources_body import BodyError

_SECRET = "Zq-hunter2-secret"
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
    except BodyError as exc:
        return str(exc)
    return None


def _valid():
    return {"name": "crm", "type": "postgres", "settings": {"host": "db.example", "dbname": "crm"},
            "credentials": {"password": _SECRET}}


def _check_create():
    got = body.parse_create(_valid())
    check("a valid create parses", got.name == "crm" and got.connector_type == "postgres"
          and got.settings == {"host": "db.example", "dbname": "crm"} and got.secrets == {"password": _SECRET})
    check("defaults: no expiry, default cap", got.credentials_expire_at is None and got.max_values is None)
    got = body.parse_create({**_valid(), "credentials_expire_at": "2027-08-31T00:00:00Z", "max_values": 5000})
    check("expiry and cap parse", got.credentials_expire_at == datetime(2027, 8, 31, tzinfo=UTC)
          and got.max_values == 5000)
    check("sqlite takes no credentials", body.parse_create(
        {"name": "local", "type": "sqlite", "settings": {"path": "crm.db"}}).secrets == {})
    cases = {
        "a list body": ([], "request body must be a JSON object"),
        "no name": ({**_valid(), "name": ""}, "name must be a non-empty string"),
        "a long name": ({**_valid(), "name": "x" * 201}, "name must be a non-empty string"),
        "an unknown type": ({**_valid(), "type": "oracle"}, "unknown connector type"),
        "a non-string type": ({**_valid(), "type": 5}, "unknown connector type"),
        "settings not an object": ({**_valid(), "settings": "host=db"}, "settings must be an object"),
        "a raw DSN key": ({**_valid(), "settings": {"dsn": f"postgresql://u:{_SECRET}@h/db"}},
                          "settings contain a key this connector type does not allow"),
        "a libpq file key": ({**_valid(), "settings": {"host": "h", "sslkey": "/etc/key"}},
                             "settings contain a key this connector type does not allow"),
        "credentials not an object": ({**_valid(), "credentials": _SECRET}, "credentials must be an object"),
        "a naive expiry": ({**_valid(), "credentials_expire_at": "2027-08-31T00:00:00"},
                           "credentials_expire_at must be an ISO 8601 time with a timezone"),
        "a junk expiry": ({**_valid(), "credentials_expire_at": _SECRET},
                          "credentials_expire_at must be an ISO 8601 time with a timezone"),
        "a zero cap": ({**_valid(), "max_values": 0}, "max_values must be a positive integer"),
        "a bool cap": ({**_valid(), "max_values": True}, "max_values must be a positive integer"),
        "a huge cap": ({**_valid(), "max_values": 2**31}, "max_values must be a positive integer"),
        "an unknown field": ({**_valid(), _SECRET: 1}, "request body has an unknown field"),
        "a status on create": ({**_valid(), "status": "paused"}, "request body has an unknown field"),
    }
    for label, (value, text) in cases.items():
        err = _error(lambda v=value: body.parse_create(v))
        check(f"create refuses {label} with fixed text", err == text)
    errors = [_error(lambda v=v: body.parse_create(v)) for v, _ in cases.values()]
    check("no create error echoes a credential or setting value", not any(_SECRET in e for e in errors))


def _check_update():
    check("an empty update is refused", _error(lambda: body.parse_update({})) == "nothing to update")
    got = body.parse_update({"status": "paused"})
    check("pause parses and touches nothing else", got.status == "paused" and got.settings is None
          and got.secrets is None and got.name is None and not got.expiry_given)
    check("resume parses", body.parse_update({"status": "active"}).status == "active")
    check("needs_attention cannot be set by hand",
          _error(lambda: body.parse_update({"status": "needs_attention"})) == "status must be active or paused")
    got = body.parse_update({"credentials": {"password": "new"}, "credentials_expire_at": None})
    check("credentials replace whole; a null expiry clears it",
          got.secrets == {"password": "new"} and got.expiry_given and got.credentials_expire_at is None)
    check("settings are checked against the stored type", _error(
        lambda: body.parse_update({"settings": {"path": "x"}}, "postgres"))
        == "settings contain a key this connector type does not allow")
    check("a type change is refused", _error(lambda: body.parse_update({"type": "mysql"}))
          == "request body has an unknown field")
    check("null credentials are refused", _error(lambda: body.parse_update({"credentials": None}))
          == "credentials must be an object")


def _check_other():
    check("a decision parses", body.parse_decision({"decision": "confirmed"}) == "confirmed")
    check("only confirmed or ignored", _error(lambda: body.parse_decision({"decision": "auto"}))
          == "decision must be confirmed or ignored")
    check("an erase value parses", body.parse_erase({"value": "Zyx Qorbel"}) == "Zyx Qorbel")
    for bad in ({}, {"value": ""}, {"value": 5}, {"value": "x" * 1001}, {"value": "a", "label": "PERSON"}):
        err = _error(lambda b=bad: body.parse_erase(b))
        check(f"erase refuses {sorted(bad)} with fixed text",
              err in ("value must be a non-empty string", "request body has an unknown field"))
    sid = uuid.uuid4()
    check("an id parses", body.parse_id(str(sid)) == sid)
    check("a malformed id is None", body.parse_id("../etc") is None and body.parse_id("") is None)
    check("a job limit defaults to 50", body.parse_limit(None) == 50 and body.parse_limit("10") == 10)
    check("a job limit outside 1..500 is refused",
          all(_error(lambda v=v: body.parse_limit(v)) == "limit must be an integer from 1 to 500"
              for v in ("0", "501", "x")))


def main():
    print("\n=== Admin API source bodies (015) ===\n")
    _check_create()
    _check_update()
    _check_other()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
