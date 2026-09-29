"""The first operator comes from a one-time CLI, never over HTTP (010 D2).

``erebus-gateway create-operator`` runs migrations, reuses or creates the reserved operator
home scope, inserts an operator credential and prints its token once on stdout (the
credential id on stderr). A wrong master key against existing scope keys aborts non-zero
with no write. Plain ``erebus-gateway`` still takes the serving path. Live Postgres;
self-skips without it.
"""
import base64
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

import psycopg

from erebus.gateway import rbac
from erebus.gateway.config import ConfigError
from erebus.gateway.server import create_operator
from erebus.gateway.store import credentials_directory, db

_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_010_create_operator")
_KEY = base64.b64encode(os.urandom(32)).decode()
_WRONG = base64.b64encode(os.urandom(32)).decode()
_HOME = credentials_directory.OPERATOR_SCOPE_KEY
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _env(key=_KEY, **extra):
    return {"EREBUS_PG_DSN": _DSN, "EREBUS_GATEWAY_MASTER_KEY": key, **extra}


def _cli(*args, key=_KEY):
    env = {k: v for k, v in os.environ.items() if not k.startswith("EREBUS_")}
    env.update(_env(key), PYTHONPATH=_ROOT)
    return subprocess.run([sys.executable, "-m", "erebus.gateway.server", *args],
                          env=env, capture_output=True, text=True, timeout=120, check=False)


def _counts(conn):
    return (conn.execute("SELECT count(*) FROM scopes").fetchone()[0],
            conn.execute("SELECT count(*) FROM scope_credentials").fetchone()[0])


def _config_checks():
    for missing in ("EREBUS_PG_DSN", "EREBUS_GATEWAY_MASTER_KEY"):
        env = _env()
        env.pop(missing)
        try:
            create_operator(env)
            raised = ""
        except ConfigError as exc:
            raised = str(exc)
        check(f"create_operator without {missing} raises ConfigError naming it", missing in raised)


def _db_checks(conn):
    cred_id, token = create_operator(_env(), label="ops-alice")
    record = credentials_directory.lookup(conn, token)
    check("the first run returns an egw_ token", token.startswith("egw_"))
    check("the token resolves to an operator credential in the home scope",
          record is not None and record.privilege == rbac.OPERATOR and record.scope_key == _HOME
          and record.credential_id == cred_id)
    home = conn.execute("SELECT id FROM scopes WHERE scope_key = %s", (_HOME,)).fetchone()[0]
    check("the home scope was provisioned with a key", conn.execute(
        "SELECT count(*) FROM tenant_keys WHERE scope_id = %s", (home,)).fetchone()[0] == 1)
    check("the label is stored", conn.execute(
        "SELECT label FROM scope_credentials WHERE id = %s", (cred_id,)).fetchone()[0] == "ops-alice")

    before = _counts(conn)
    _, second = create_operator(_env())
    check("a re-run reuses the home scope and adds one credential",
          _counts(conn) == (before[0], before[1] + 1)
          and credentials_directory.lookup(conn, second).scope_id == home)

    run = _cli("create-operator", "--label", "cli")
    out = run.stdout.strip()
    rec = credentials_directory.lookup(conn, out) if out else None
    check("the CLI exits 0 and prints only the token on stdout",
          run.returncode == 0 and out.startswith("egw_") and len(run.stdout.splitlines()) == 1)
    check("the CLI token is an operator credential", rec is not None and rec.privilege == rbac.OPERATOR)
    check("the credential id goes to stderr and the token does not",
          rec is not None and str(rec.credential_id) in run.stderr and out not in run.stderr)

    before = _counts(conn)
    bad = _cli("create-operator", key=_WRONG)
    check("a wrong master key exits non-zero with nothing on stdout",
          bad.returncode != 0 and bad.stdout == "")
    check("the wrong-key message names the setting, never a key",
          "EREBUS_GATEWAY_MASTER_KEY" in bad.stderr and _WRONG not in bad.stderr and _KEY not in bad.stderr)
    check("a wrong master key writes nothing", _counts(conn) == before)
    try:
        create_operator(_env(_WRONG))
        refused = False
    except ConfigError:
        refused = True
    check("create_operator refuses a wrong master key with ConfigError", refused and _counts(conn) == before)

    serve = _cli()
    check("plain erebus-gateway still takes the serving path (config check, no operator created)",
          serve.returncode != 0 and "EREBUS_GATEWAY_PROVIDER" in serve.stderr and _counts(conn) == before)


def main():
    print("\n=== create-operator bootstrap (010 D2) ===\n")
    _config_checks()
    try:
        conn = psycopg.connect(_DSN, autocommit=True)
    except Exception as exc:
        print(f"  (skipped DB checks: no Postgres at {_DSN}: {exc})")
        print(f"\n{_passed}/{_passed} passed\n")
        return
    try:
        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")
        _db_checks(conn)
    finally:
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
