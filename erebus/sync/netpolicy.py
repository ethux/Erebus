"""Where the sync worker may connect (spec 015 "Security": network and local resources).

Before a connector opens a source the worker checks its settings here:

* only the type's setting keys (``connector_types``), with checked values: never a raw
  DSN, a libpq file key or a driver option;
* the host is resolved once; every address must stay out of the deny list (default: the
  gateway's own DB host, loopback, unspecified, link-local and cloud metadata addresses)
  and inside the allow list when one is set. The connector receives the checked address
  as ``hostaddr`` and must connect to exactly that address, checking TLS against
  ``host``, so a second DNS answer (rebinding) is never used; ``egress`` refuses any
  other address while the connector runs;
* a SQLite path must resolve (symlinks followed) inside the SQLite directory; without
  one SQLite is off.

``PolicyError.kind`` is ``settings`` (malformed settings), ``denied`` (the policy
refuses the target) or ``unreachable`` (the name or file does not exist). Messages are
fixed text: nothing here echoes a host, path or value.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from psycopg import conninfo

from ..cataloging.connector_types import ConnectorType
from ..gateway.connectors.policy import ERROR_TEXT

Network = ipaddress.IPv4Network | ipaddress.IPv6Network
Address = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[..., list]

# Loopback, unspecified, link-local (AWS/GCP/Azure metadata live at 169.254.169.254),
# AWS's IPv6 metadata address and Alibaba Cloud's metadata address.
DEFAULT_DENIED_NETWORKS = (
    "127.0.0.0/8", "::1/128", "0.0.0.0/8", "::/128", "169.254.0.0/16", "fe80::/10",
    "fd00:ec2::254/128", "100.100.100.200/32",
)
SSL_MODES = frozenset({"disable", "prefer", "require", "verify-ca", "verify-full"})
_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.\-]{0,251}[A-Za-z0-9])?|\[?[0-9A-Fa-f:.]{2,45}\]?")
_TEXT_KEYS = frozenset({"dbname", "user"})
_LIST_KEYS = frozenset({"schemas", "collections"})
_MAX_TEXT = 256
_MAX_ITEMS = 1000


class PolicyError(Exception):
    """The worker refuses a source's settings or target; ``kind`` classes it."""

    def __init__(self, kind: str) -> None:
        super().__init__(ERROR_TEXT[kind])
        self.kind = kind


@dataclass(frozen=True)
class HostList:
    """Networks and host names of a deny or allow list."""

    networks: tuple[Network, ...] = ()
    names: tuple[str, ...] = ()


@dataclass(frozen=True)
class NetworkPolicy:
    """The worker's policy. ``allowed`` is ``None`` when no allow list is set."""

    denied: HostList
    allowed: HostList | None = None
    sqlite_dir: Path | None = None


def parse_hosts(raw: str) -> HostList:
    """Parse a comma-separated list of host names, addresses and CIDR networks.

    Raises ``ValueError`` for an entry that is neither.
    """
    networks: list[Network] = []
    names: list[str] = []
    for item in (p.strip() for p in raw.split(",")):
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item.strip("[]"), strict=False))
            continue
        except ValueError:
            pass
        if "/" in item or not _HOST.fullmatch(item):
            raise ValueError("malformed host entry")
        names.append(item.lower().rstrip("."))
    return HostList(tuple(networks), tuple(names))


def default_denied(dsn: str) -> HostList:
    """The default deny list: the gateway DB's host(s) from ``dsn`` plus the fixed networks.

    Denying the DB host denies its whole cluster by design. A socket DSN (no host, or a
    path) is covered by the loopback networks.
    """
    try:
        info = conninfo.conninfo_to_dict(dsn)
    except Exception:
        info = {}
    hosts = [h for key in ("host", "hostaddr") for h in str(info.get(key) or "").split(",")]
    db_hosts = ",".join(h for h in hosts if h and not h.startswith("/"))
    extra = parse_hosts(db_hosts) if db_hosts else HostList()
    fixed = parse_hosts(",".join(DEFAULT_DENIED_NETWORKS))
    return HostList(fixed.networks + extra.networks, extra.names)


def address(raw: str) -> Address:
    """The address ``raw`` spells (an IPv4-mapped one as IPv4); ``ValueError`` for a name."""
    ip = ipaddress.ip_address(raw.split("%", 1)[0])
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        return ip.ipv4_mapped
    return ip


def _resolve(host: str, port: int, resolve: Resolver) -> set[Address]:
    try:
        return {address(host)}
    except ValueError:
        pass
    try:
        answers = resolve(host, port, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return set()
    return {address(a[4][0]) for a in answers}


def resolve_names(names: Iterable[str], port: int, resolve: Resolver) -> set[Address]:
    # A name that does not resolve matches by name only.
    return {a for name in names for a in _resolve(name.strip("[]"), port, resolve)}


def _listed(host: str, addrs: set[Address], hosts: HostList, port: int, resolve: Resolver, *, every: bool) -> bool:
    """Whether ``addrs`` are on ``hosts``: any of them (``every=False``) or all of them."""
    if host.lower().rstrip(".") in hosts.names:
        return True
    named = resolve_names(hosts.names, port, resolve)
    hits = [a in named or any(a in net for net in hosts.networks) for a in addrs]
    return all(hits) if every else any(hits)


def check_host(policy: NetworkPolicy, host: str, port: int, *, resolve: Resolver = socket.getaddrinfo) -> str:
    """Resolve ``host`` once and return the address to connect to, or raise ``PolicyError``.

    Every resolved address must pass (one denied address refuses the host, so a mixed
    answer cannot slip through); the deny list wins over the allow list.
    """
    addrs = _resolve(host.strip("[]"), port, resolve)
    if not addrs:
        raise PolicyError("unreachable")
    if _listed(host, addrs, policy.denied, port, resolve, every=False):
        raise PolicyError("denied")
    if policy.allowed is not None and not _listed(host, addrs, policy.allowed, port, resolve, every=True):
        raise PolicyError("denied")
    return str(sorted(addrs, key=lambda a: (a.version, a.packed))[0])


def sqlite_path(policy: NetworkPolicy, path: Any) -> str:
    """The real path of a SQLite file inside the SQLite directory, or ``PolicyError``."""
    if policy.sqlite_dir is None:
        raise PolicyError("denied")
    if not isinstance(path, str) or not path or len(path) > 4096 or any(c in path for c in "\x00?#%"):
        raise PolicyError("denied")
    base = policy.sqlite_dir.resolve()
    try:
        real = (base / path).resolve(strict=True)
    except (OSError, RuntimeError):
        raise PolicyError("unreachable") from None
    if not real.is_relative_to(base):
        raise PolicyError("denied")
    if not real.is_file():
        raise PolicyError("unreachable")
    return str(real)


def _text(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_TEXT and value.isprintable()


def _check_values(ctype: ConnectorType, settings: Mapping[str, Any]) -> None:
    for key, value in settings.items():
        if key in _LIST_KEYS:
            ok = isinstance(value, list) and len(value) <= _MAX_ITEMS and all(_text(v) for v in value)
        elif key == "port":
            ok = type(value) is int and 1 <= value <= 65535
        elif key == "sslmode":
            ok = value in SSL_MODES
        elif key == "host":
            ok = isinstance(value, str) and bool(_HOST.fullmatch(value))
        elif key == "path":
            ok = isinstance(value, str)  # sqlite_path checks it
        elif key in _TEXT_KEYS:
            ok = _text(value)
        else:  # a key a Pro type declares: plain text only, the connector checks the rest
            ok = _text(value) or (type(value) is int)
        if not ok:
            raise PolicyError("settings")
    if ctype.default_port is not None and "host" not in settings:
        raise PolicyError("settings")


def prepare_settings(
    policy: NetworkPolicy,
    ctype: ConnectorType,
    settings: Mapping[str, Any],
    *,
    resolve: Resolver = socket.getaddrinfo,
) -> dict[str, Any]:
    """The settings to hand the connector: checked, with ``hostaddr`` or the real SQLite path.

    Returns a new dict; ``settings`` is not changed.
    """
    if not isinstance(settings, Mapping) or any(k not in ctype.setting_keys for k in settings):
        raise PolicyError("settings")
    _check_values(ctype, settings)
    out = dict(settings)
    if ctype.family == "file":
        out["path"] = sqlite_path(policy, settings.get("path"))
    elif ctype.default_port is not None:
        out.setdefault("port", ctype.default_port)
        out["hostaddr"] = check_host(policy, str(settings["host"]), out["port"], resolve=resolve)
    return out
