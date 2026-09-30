"""``erebus-sync``: the sync worker's console script (spec 015 D1).

Reads ``SyncConfig.from_env()`` (no gateway provider settings needed), checks that the
database answers and that the master key unseals the existing scope keys, runs the
advisory-locked migrations, loads the ``erebus.sources`` connectors strictly and the
worker extensions, then polls for jobs until SIGTERM
or SIGINT. Startup failures print a fixed message naming the setting and exit 2; they
never echo a secret.
"""
from __future__ import annotations

import logging
import signal
import sys
import threading
from types import SimpleNamespace

import psycopg

from ..cataloging import sources as contract
from ..gateway.config import ConfigError
from ..gateway.crypto.keyprovider import MasterKeyKms
from ..gateway.store import db
from .config import SyncConfig
from .extensions import WorkerHooks, load_extensions
from .worker import Worker

log = logging.getLogger("erebus.sync")


def _die(message: str) -> None:
    print(f"erebus-sync: {message}", file=sys.stderr)
    raise SystemExit(2)


def _prepare(config: SyncConfig) -> MasterKeyKms:
    try:
        kms = MasterKeyKms(config.dsn, config.master_key_b64)
    except Exception as exc:  # pool errors can carry DSN parts: name the type only
        _die(f"database or key custody unavailable (check EREBUS_PG_DSN): {type(exc).__name__}")
    try:
        with psycopg.connect(config.dsn, autocommit=True) as conn:
            kms.verify(conn)
            db.run_migrations(conn)
    except ValueError as exc:
        kms.close()
        _die(str(exc))
    except Exception as exc:
        kms.close()
        _die(f"database unreachable at EREBUS_PG_DSN: {type(exc).__name__}")
    return kms


def _load_connectors() -> None:
    # Strict: a connector that cannot load stops the worker instead of failing its jobs.
    try:
        contract.load_connectors(strict=True)
    except Exception as exc:  # an import error can quote a path: name the type only
        _die(f"a source connector failed to load: {type(exc).__name__}")


def main(argv: list[str] | None = None) -> None:
    """Run the worker until stopped."""
    del argv  # no arguments yet; configuration is the environment
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        config = SyncConfig.from_env()
    except ConfigError as exc:
        _die(str(exc))
    _load_connectors()
    kms = _prepare(config)
    from psycopg_pool import ConnectionPool

    pool = ConnectionPool(config.dsn, min_size=1, max_size=config.concurrency + 1, open=True)
    try:
        worker = Worker(config, pool=pool, provider=kms)
        hooks = WorkerHooks(state=SimpleNamespace(config=config, pool=pool, provider=kms),
                            add_periodic=worker.add_periodic, enqueue_job=worker.enqueue_job)
        names = load_extensions(hooks)
        stop = threading.Event()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, lambda *_a: stop.set())
        log.info("sync worker started (concurrency %d, extensions: %s)", config.concurrency,
                 ", ".join(names) or "none")
        if config.detection_disabled:
            log.info("model review is off (EREBUS_DISABLE_GLINER)")
        worker.run_forever(stop)
        log.info("sync worker stopped")
    finally:
        pool.close()
        kms.close()


if __name__ == "__main__":
    main()
