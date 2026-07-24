"""Residency enforcement, pure logic (FR-023/FR-034).

A per-tenant scope is pinned to a residency region. Raw PII for that scope must
never be stored or processed outside its permitted jurisdiction. This module is
the pure decision core used by the gateway request path and the provider router;
it touches no database and holds no mutable process-global state (FR-041..043).

Two decisions live here:

* :func:`decide` answers, for a single request, whether raw handling in a given
  instance region is allowed, must be pushed to edge tokenization, or must be
  refused. Cross-region raw handling on the gateway side is never allowed: it is
  refused, or forced to edge tokenization when the scope permits edge mode
  (FR-034). This decision is meant to be recorded as a per-request residency
  decision by the caller.
* :func:`routable_candidates` filters provider routes to those inside the scope's
  residency region, so routing and failover can never cross a tenant's residency
  boundary (FR-023). Failover is selection among the in-region candidates only;
  there is no cross-boundary fallback.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Literal, Protocol, runtime_checkable

Decision = Literal["allow", "force_edge", "refuse"]

# Tokenization modes a scope may permit (mirrors the gateway policy vocabulary).
# "edge" lets the request be tokenized at the edge before any raw value would be
# handled in a foreign region; "gateway" handles raw values gateway-side only.
GATEWAY_MODE = "gateway"
EDGE_MODE = "edge"


def _norm(region: str | None) -> str:
    """Canonicalize a region tag for comparison (case/space-insensitive)."""
    return (region or "").strip().casefold()


def decide(scope_region: str, instance_region: str, mode: str) -> Decision:
    """Decide raw-handling residency for one request (FR-034).

    ``scope_region`` is the tenant's permitted residency region, ``instance_region``
    is the region of the gateway instance about to handle the request, and ``mode``
    is the scope's tokenization mode (``"edge"`` permits edge tokenization).

    Returns:
        * ``"allow"`` when the instance is in the scope's residency region, so raw
          handling stays in-jurisdiction.
        * ``"force_edge"`` when the instance is out of region but the scope permits
          edge tokenization, so no raw value crosses the boundary.
        * ``"refuse"`` when the instance is out of region and edge is not permitted.

    Raw handling cross-region on the gateway side is never allowed.
    """
    if _norm(scope_region) == _norm(instance_region):
        return "allow"
    # Out of region: never handle raw gateway-side. Edge tokenization keeps raw
    # values inside the boundary, so permit it when the scope allows edge mode.
    if _norm(mode) == EDGE_MODE:
        return "force_edge"
    return "refuse"


@runtime_checkable
class _RouteLike(Protocol):
    """A provider route exposing a residency region (attribute access)."""

    residency_region: str


def _route_region(route: Any) -> str | None:
    """Extract a route's residency region from a mapping or an object."""
    if isinstance(route, Mapping):
        return route.get("residency_region")
    return getattr(route, "residency_region", None)


def routable_candidates(
    routes: Iterable[Mapping[str, Any] | _RouteLike],
    scope_region: str,
) -> Sequence[Any]:
    """Filter provider routes to those inside the scope's residency region (FR-023).

    Routing and failover select only among the returned in-region candidates;
    out-of-region routes are dropped so failover can never cross the tenant's
    residency boundary. Input order is preserved (the caller still applies its own
    priority/failover ordering). Accepts route mappings or objects exposing a
    ``residency_region``.
    """
    target = _norm(scope_region)
    return [route for route in routes if _norm(_route_region(route)) == target]
