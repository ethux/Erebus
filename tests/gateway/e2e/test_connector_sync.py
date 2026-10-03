"""Connected database to tokenized chat, over real processes (spec 015 SC-1 and SC-4).

Runs ``erebus-gateway`` and ``erebus-sync`` as real subprocesses against this test's
database, next to a mock provider. The source is a ``crm`` schema in the same Postgres,
read by a dedicated read-only role (the documented setup). An operator adds the source
over the admin API; the worker samples it and runs the full sync it queues. Within 60 s
of that sync a chat naming "Zyx Qorbel" (a made-up name no detector finds) and their
email reaches the provider only as tokens, and the client gets both values back (SC-1).

The leak scan (SC-4) then greps everything both processes printed (application and
access logs), the operator bootstrap's output, the ``sync_jobs``, ``source_fields`` and
``audit_events`` rows and every admin API response, errors included (a source with a
wrong login and a body that smuggles a credential), for the synced values and both
passwords. Self-skips only when Postgres is unreachable.
"""
import base64
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))

import httpx
import psycopg
from psycopg import sql

from erebus.gateway.connectors.policy import ERROR_TEXT
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.providers import credentials, quota
from erebus.gateway.store import credentials_directory, db
from erebus.gateway.store.known_value_store import open_store, provision_scope

_ROOT = Path(__file__).resolve().parents[3]
_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_e2e_connector_sync")
_KEY = base64.b64encode(os.urandom(32)).decode()
_NAME = "Zyx Qorbel"
_EMAIL = "zyx.qorbel@acme.example"
_PASSWORD = "Pw-e2e-" + uuid.uuid4().hex[:12]
_WRONG = "Wrong-e2e-" + uuid.uuid4().hex[:12]
_CENTRAL = "CENTRAL-e2e-" + uuid.uuid4().hex[:8]
_TOKEN = re.compile(r"\[[A-Z_]+_\d+_[0-9a-f]{6}\]")
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _wait(predicate, message, timeout=60.0, step=0.25):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except Exception:
            pass
        time.sleep(step)
    raise RuntimeError(message)


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Provider:
    """Records each upstream request and echoes the last message's content."""

    def __init__(self):
        self.requests = []
        recorder = self.requests

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                return

            def do_POST(self):  # BaseHTTPRequestHandler dispatch hook
                raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
                body = json.loads(raw or b"{}")
                recorder.append(body)
                content = (body.get("messages") or [{}])[-1].get("content", "")
                data = json.dumps({"choices": [{"message": {"role": "assistant", "content": content}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def stop(self):
        self._server.shutdown()
        self._server.server_close()


class _Process:
    """A console script run as ``python -m <module>``, output captured to a file."""

    def __init__(self, module, env, args=()):
        self.log = Path(tempfile.mkstemp(suffix=".log")[1])
        self._fh = self.log.open("wb")
        self.proc = subprocess.Popen([sys.executable, "-m", module, *args], cwd=_ROOT, env=env,
                                     stdout=self._fh, stderr=subprocess.STDOUT)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(5)
        self._fh.close()
        return self.log.read_text(errors="replace")


def _env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("EREBUS_")}
    env.update({"EREBUS_PG_DSN": _DSN, "EREBUS_GATEWAY_MASTER_KEY": _KEY, "EREBUS_DISABLE_GLINER": "1",
                "PYTHONUNBUFFERED": "1"})
    env.update({k: str(v) for k, v in extra.items()})
    return env


def _source_db(admin, role):
    """The ``crm`` schema and a read-only login that may read only ``crm.customers``."""
    ident = sql.Identifier(role)
    for stmt in (
        sql.SQL("DROP SCHEMA IF EXISTS crm CASCADE"), sql.SQL("CREATE SCHEMA crm"),
        sql.SQL("CREATE TABLE crm.customers (id INTEGER PRIMARY KEY, full_name TEXT, email TEXT)"),
        sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(ident, sql.Literal(_PASSWORD)),
        sql.SQL("ALTER ROLE {} SET default_transaction_read_only = on").format(ident),
        sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(admin.info.dbname), ident),
        sql.SQL("GRANT USAGE ON SCHEMA crm TO {}").format(ident),
        sql.SQL("GRANT SELECT ON crm.customers TO {}").format(ident),
    ):
        admin.execute(stmt)
    admin.execute("INSERT INTO crm.customers VALUES (1, %s, %s), (2, 'Mila Brandt', 'mila.brandt@acme.example'), "
                  "(3, 'Anna Visser', 'anna.visser@acme.example')", (_NAME, _EMAIL))


def _tenant(conn, kms, provider_url):
    sid = provision_scope(conn, kms, "e2e/connectors")
    cred = credentials_directory.provision(conn, sid, "e2e/connectors", label="e2e")
    credentials.store_credential(conn, open_store(conn, kms, sid)._crypto, sid, "openai", _CENTRAL)
    rid = credentials.add_route(conn, sid, "openai", provider_url, model_allowlist=["gpt-4o"])
    credentials.approve_route(conn, sid, rid)
    quota.set_quota(conn, sid, 1000, 100000, 60)
    return sid, cred


def _create_operator():
    out = subprocess.run([sys.executable, "-m", "erebus.gateway.server", "create-operator", "--label", "e2e"],
                         cwd=_ROOT, env=_env(), capture_output=True, text=True, timeout=120, check=True)
    return out.stdout.strip(), out.stderr


class _Admin:
    """Admin API calls with an operator credential; keeps every response text."""

    def __init__(self, client, base, token, scope_id):
        self.client, self.base, self.scope = client, base, scope_id
        self.headers = {"Authorization": f"Bearer {token}"}
        self.texts = []

    def call(self, method, path, **kw):
        resp = self.client.request(method, f"{self.base}/v1/admin/scopes/{self.scope}{path}", headers=self.headers,
                                   **kw)
        self.texts.append(resp.text)
        return resp

    def job(self, source_id, kind, status):
        jobs = self.call("GET", "/sync-jobs", params={"source_id": source_id}).json()["jobs"]
        return next((j for j in jobs if j["kind"] == kind and j["status"] == status), None)


def _settings(user, pg):
    return {"host": "localhost", "port": pg.port or 5432, "dbname": pg.dbname, "user": user,
            "sslmode": "disable", "schemas": ["crm"]}


def _check_sync(admin, pg, role):
    resp = admin.call("POST", "/sources", json={"name": "crm", "type": "postgres", "settings": _settings(role, pg),
                                                "credentials": {"password": _PASSWORD}})
    check("an operator adds the Postgres source; a sample job is queued",
          resp.status_code == 200 and resp.json()["job"]["kind"] == "sample")
    source_id = resp.json()["source"]["id"]
    done = _wait(lambda: admin.job(source_id, "full", "done"), "the full sync never completed", timeout=90)
    fields = {f["field"]: f for f in admin.call("GET", f"/sources/{source_id}/fields").json()["fields"]}
    check("the worker's sample auto-accepted the name and email columns",
          fields["full_name"]["decision"] == "auto" and fields["email"]["decision"] == "auto")
    check("the full sync it queued ran in the worker and stored the values",
          done["values_added"] >= 3 and done["error"] is None)
    return time.monotonic()


def _check_chat(client, base, cred, provider, synced_at):
    prompt = f"Draft a reply to {_NAME} at {_EMAIL} about the renewal"

    def tokenized():
        provider.requests.clear()
        resp = client.post(f"{base}/v1/chat/completions", headers={"Authorization": f"Bearer {cred}"},
                           json={"model": "gpt-4o", "messages": [{"role": "user", "content": prompt}]})
        sent = json.dumps(provider.requests[-1]) if provider.requests else ""
        return resp if resp.status_code == 200 and "qorbel" not in sent.lower() else None

    resp = _wait(tokenized, "the synced name was never tokenized", timeout=60)
    check("the chat is tokenized within 60 s of the sync completing (SC-1)", time.monotonic() - synced_at < 60)
    sent = provider.requests[-1]["messages"][-1]["content"]
    check("the provider sees neither value, only tokens",
          _NAME not in sent and _EMAIL not in sent and len(_TOKEN.findall(sent)) >= 2)
    check("the client gets both values back", resp.json()["choices"][0]["message"]["content"] == prompt)


def _check_errors(admin, pg):
    bad = admin.call("POST", "/sources", json={"name": "bad", "type": "postgres",
                                               "settings": _settings("no_such_role_zq", pg),
                                               "credentials": {"password": _WRONG}})
    source_id = bad.json()["source"]["id"]
    failed = _wait(lambda: admin.job(source_id, "sample", "failed"), "the wrong login never failed")
    check("a wrong login fails its job with the fixed auth text", failed["error"] == ERROR_TEXT["auth"])
    smuggled = admin.call("POST", "/sources", json={"name": "x", "type": "postgres", "password": _WRONG,
                                                    "settings": {"host": "localhost", "dsn": _WRONG}})
    check("a body smuggling a credential is refused", smuggled.status_code == 400)


def _scan(texts):
    needles = (_NAME, _EMAIL, "Qorbel", _PASSWORD, _WRONG)
    return sorted({f"{label}: {n}" for label, text in texts.items() for n in needles if n.lower() in text.lower()})


def _rows(conn, table):
    return "\n".join(r[0] for r in conn.execute(sql.SQL("SELECT row_to_json(t)::text FROM {} t").format(
        sql.Identifier(table))).fetchall())


def main():
    print("\n=== Connected database to tokenized chat (spec 015 SC-1, SC-4) ===\n")
    try:
        conn = psycopg.connect(_DSN, autocommit=True)
    except Exception as exc:
        print(f"  (skipped: no Postgres at {_DSN}: {type(exc).__name__})")
        return
    role = f"erebus_e2e_ro_{uuid.uuid4().hex[:8]}"
    provider = gateway = worker = None
    kms = MasterKeyKms(_DSN, _KEY)
    outputs = {}
    try:
        db.run_migrations(conn)
        conn.execute("TRUNCATE scopes CASCADE")
        _source_db(conn, role)
        provider = _Provider()
        scope_id, cred = _tenant(conn, kms, provider.url)
        op_token, outputs["create-operator"] = _create_operator()
        gw_port = _free_port()
        gateway = _Process("erebus.gateway.server", _env(EREBUS_GATEWAY_PROVIDER="openai",
                                                          EREBUS_GATEWAY_HOST="127.0.0.1",
                                                          EREBUS_GATEWAY_PORT=gw_port,
                                                          EREBUS_GATEWAY_CATALOG_POLL_S=1))
        worker = _Process("erebus.sync.cli", _env(EREBUS_SYNC_POLL_S=1, EREBUS_SYNC_DENIED_HOSTS="none"))
        base = f"http://127.0.0.1:{gw_port}"
        pg = conn.info
        with httpx.Client(timeout=30.0) as client:
            _wait(lambda: client.get(f"{base}/readyz").status_code == 200, "the gateway never became ready", 120)
            admin = _Admin(client, base, op_token, scope_id)
            synced_at = _check_sync(admin, pg, role)
            _check_chat(client, base, cred, provider, synced_at)
            _check_errors(admin, pg)
        outputs["gateway"] = gateway.stop()
        outputs["worker"] = worker.stop()
        gateway = worker = None
        check("the gateway's access log was captured", "/v1/admin/scopes/" in outputs["gateway"])
        check("the worker's log was captured", "sample" in outputs["worker"] and "full" in outputs["worker"])
        texts = dict(outputs)
        for table in ("sync_jobs", "source_fields", "audit_events"):
            texts[table] = _rows(conn, table)
        texts["admin API responses"] = "\n".join(admin.texts)
        check("the scan finds a planted value, in any case",
              set(_scan({"probe": f"x {_NAME.upper()} y {_PASSWORD}"}))
              == {f"probe: {_NAME}", "probe: Qorbel", f"probe: {_PASSWORD}"})
        leaks = _scan(texts)
        for leak in leaks:
            print(f"  ✗ leaked in {leak}", file=sys.stderr)
        check("no log, job row, field row, audit event or API response holds a value or credential (SC-4)",
              not leaks)
        print(f"\n{_passed}/{_passed} passed\n")
    finally:
        for proc in (gateway, worker):
            if proc is not None:
                print(proc.stop()[-3000:], file=sys.stderr)
        if provider is not None:
            provider.stop()
        kms.close()
        conn.execute("DROP SCHEMA IF EXISTS crm CASCADE")
        if conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone():
            conn.execute(sql.SQL("DROP OWNED BY {}").format(sql.Identifier(role)))
            conn.execute(sql.SQL("DROP ROLE {}").format(sql.Identifier(role)))
        conn.close()


if __name__ == "__main__":
    main()
