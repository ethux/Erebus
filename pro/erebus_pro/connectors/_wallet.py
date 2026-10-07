# SPDX-License-Identifier: Elastic-2.0
# Copyright (c) 2026 ETHUX
"""Where the Oracle connector puts a wallet while it connects, and the sweep of wallets a
stopped worker left behind (a sync worker extension, run when the worker starts).

A wallet holds a private key. The connector writes it to a 0700 directory named
``erebus-wallet-<pid>-...`` under the worker's own root, ``<tmp>/erebus-sync-<uid>``
(0700, owned by the worker's user, not a link), and removes it before ``connect``
returns. A worker killed while connecting cannot, so every worker sweeps the root as it
starts: it removes a wallet whose process is gone, one carrying its own process id (a
restarted container reuses it) and any older than an hour. A root it cannot trust is
not used: the wallet then goes to a private directory in the system's temporary
directory, outside the sweep.
"""
from __future__ import annotations

import contextlib
import logging
import os
import shutil
import stat
import tempfile
import time
from collections.abc import Iterator
from typing import Any

log = logging.getLogger("erebus_pro.connectors")

PREFIX = "erebus-wallet-"
STALE_S = 3600


def root() -> str | None:
    """The worker's wallet root, created if missing; ``None`` when it cannot be trusted."""
    path = os.path.join(tempfile.gettempdir(), f"erebus-sync-{os.getuid()}")
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    except OSError:
        return None
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        return None
    return path


@contextlib.contextmanager
def wallet_dir(pem: str | None) -> Iterator[str | None]:
    """A private directory holding ``pem`` as ``ewallet.pem`` while the driver connects."""
    if pem is None:
        yield None
        return
    where = tempfile.mkdtemp(prefix=f"{PREFIX}{os.getpid()}-", dir=root())  # mode 0700
    try:
        fd = os.open(os.path.join(where, "ewallet.pem"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(pem)
        yield where
    finally:
        shutil.rmtree(where, ignore_errors=True)


def _gone(name: str) -> bool:
    """Whether the process that named a wallet ``name`` is gone (or is this one, restarted)."""
    try:
        pid = int(name[len(PREFIX):].split("-", 1)[0])
    except ValueError:
        return True
    if pid == os.getpid():
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except PermissionError:  # alive, another user's
        return False
    return False


def sweep() -> int:
    """Remove stale wallets from the root; return how many. Only when the worker starts:
    a wallet with this process's id would be in use later on."""
    base = root()
    if base is None:
        return 0
    removed = 0
    now = time.time()
    with os.scandir(base) as entries:
        for entry in entries:
            if not entry.name.startswith(PREFIX) or not entry.is_dir(follow_symlinks=False):
                continue
            try:
                old = now - entry.stat(follow_symlinks=False).st_mtime > STALE_S
            except OSError:
                continue
            if old or _gone(entry.name):
                shutil.rmtree(entry.path, ignore_errors=True)
                removed += 1
    return removed


def register(hooks: Any) -> None:
    """Worker extension entry point: sweep the wallet root once, at worker start."""
    del hooks  # nothing to schedule
    removed = sweep()
    if removed:
        log.warning("removed %d Oracle wallet(s) a stopped worker left behind", removed)
