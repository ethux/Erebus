"""The ``erebus-sync`` entrypoint (spec 015 "Config and deploy").

Live Postgres on its own database; the worker runs as a real process. Without a master
key it exits 2 naming the variable. With only the DSN, the master key and
EREBUS_SYNC_* (no gateway provider settings) it verifies the key, migrates, claims a
queued job for a SQLite source inside its SQLite directory, runs it and exits 0 on
SIGTERM. Its output carries no credential, key or value.
"""
import base64
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from helpers import fresh_db

from erebus.gateway.connectors import jobs, sources
from erebus.gateway.crypto.keyprovider import MasterKeyKms
from erebus.gateway.store.known_value_store import open_scope_crypto, provision_scope

_DSN = os.environ.get("EREBUS_PG_DSN", "postgresql:///erebus_gw_sync_cli")
_KEY = base64.b64encode(os.urandom(32)).decode()
_REPO = Path(__file__).resolve().parents[2]
_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


def _env(**extra):
    env = {k: v for k, v in os.environ.items() if not k.startswith("EREBUS_")}
    env.update({"PYTHONPATH": str(_REPO), **extra})
    return env


def _start(env):
    return subprocess.Popen([sys.executable, "-c", "from erebus.sync.cli import main; main()"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def _check_bad_config():
    proc = _start(_env(EREBUS_PG_DSN=_DSN))
    out, _ = proc.communicate(timeout=60)
    check("a missing master key exits 2", proc.returncode == 2)
    check("the message names the variable", "EREBUS_GATEWAY_MASTER_KEY" in out)


def _check_runs_a_job(conn, root):
    kms = MasterKeyKms(_DSN, _KEY)
    try:
        scope_id = provision_scope(conn, kms, "tenant-cli")
        crypto = open_scope_crypto(conn, kms, scope_id)
        source_id = sources.create_source(conn, crypto, scope_id, name="crm", connector_type="sqlite",
                                          settings={"path": "crm.db"}, secrets={"password": "Pw-Zq-cli"})
        conn.commit()
    finally:
        kms.close()
    db = sqlite3.connect(root / "crm.db")
    db.execute("CREATE TABLE customers (id INTEGER PRIMARY KEY, email TEXT, full_name TEXT)")
    db.execute("INSERT INTO customers (email, full_name) VALUES ('zyx.qorbel@acme.example', 'Zyx Qorbel')")
    db.commit()
    db.close()
    job, _ = jobs.enqueue(conn, scope_id, source_id, "sample")
    conn.commit()
    proc = _start(_env(EREBUS_PG_DSN=_DSN, EREBUS_GATEWAY_MASTER_KEY=_KEY, EREBUS_SYNC_POLL_S="1",
                       EREBUS_DISABLE_GLINER="1", EREBUS_SYNC_SQLITE_DIR=str(root)))
    deadline = time.time() + 60
    status = None
    while time.time() < deadline and proc.poll() is None:
        status = jobs.get_job(conn, scope_id, job.id).status
        if status in ("done", "failed"):
            break
        time.sleep(0.3)
    check("the worker starts without EREBUS_GATEWAY_PROVIDER and runs the job", status == "done")
    proc.send_signal(signal.SIGTERM)
    out, _ = proc.communicate(timeout=60)
    check("SIGTERM stops the worker cleanly", proc.returncode == 0)
    check("its output holds no credential, key or value",
          "Pw-Zq-cli" not in out and _KEY not in out and "Qorbel" not in out)
    check("its output names the job", str(job.id) in out)


def main():
    print("\n=== erebus-sync entrypoint (spec 015) ===\n")
    conn = fresh_db("erebus_gw_sync_cli")
    try:
        _check_bad_config()
        with tempfile.TemporaryDirectory() as root:
            _check_runs_a_job(conn, Path(root))
    finally:
        conn.close()
    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
