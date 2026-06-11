"""Small network diagnostics shared by the proxy and the installer."""
from __future__ import annotations

import subprocess


def describe_port_holder(port: int) -> str | None:
    """Name the process listening on `port`, e.g. 'PID 19845 (python3.1)'.

    Returns None when the port is free or lsof is unavailable. Only the first
    LISTEN line is reported; with separate IPv4/IPv6 binds that is the v4 one,
    which is the bind erebus services use.
    """
    try:
        out = subprocess.run(["lsof", "-nP", f"-i:{port}", "-sTCP:LISTEN"],
                             capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = out.stdout.strip().splitlines()
    if len(lines) < 2:
        return None
    fields = lines[1].split()
    return f"PID {fields[1]} ({fields[0]})" if len(fields) >= 2 else lines[1]
