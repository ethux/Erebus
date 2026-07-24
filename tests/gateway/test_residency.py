"""Residency enforcement tests (FR-023/FR-034), pure unit test, no DB.

Verifies the residency decision core and in-region route filtering: same-region
raw handling is allowed; cross-region gateway-side raw handling is refused; a
cross-region scope that permits edge tokenization is forced to edge; and failover
candidates exclude out-of-region routes so failover never crosses the residency
boundary. Mirrors the check()/"N/N passed" style of test_store.py but needs no
Postgres.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from dataclasses import dataclass

from erebus.gateway.residency import (
    EDGE_MODE,
    GATEWAY_MODE,
    decide,
    routable_candidates,
)

_passed = 0


def check(name, cond):
    global _passed
    if not cond:
        raise AssertionError(name)
    print(f"  ✓ {name}")
    _passed += 1


@dataclass(frozen=True)
class Route:
    """An object-style provider route (the module also accepts dict routes)."""

    provider: str
    residency_region: str
    priority: int = 0


def main():
    print("\n=== Gateway residency enforcement (FR-023/FR-034) ===\n")

    # --- decide(): same-region raw handling is allowed (FR-034) ---
    check("same-region gateway-side -> allow", decide("eu-west", "eu-west", GATEWAY_MODE) == "allow")
    check("same-region edge -> allow", decide("eu-west", "eu-west", EDGE_MODE) == "allow")
    check("region match is case/space-insensitive", decide("EU-West", " eu-west ", GATEWAY_MODE) == "allow")

    # --- decide(): cross-region gateway-side raw handling is refused (FR-034) ---
    check("cross-region gateway-side -> refuse", decide("eu-west", "us-east", GATEWAY_MODE) == "refuse")
    check(
        "cross-region with unknown/none mode -> refuse (never raw cross-region)",
        decide("eu-west", "us-east", "") == "refuse",
    )

    # --- decide(): cross-region with edge permitted is forced to edge (FR-034) ---
    check("cross-region edge-permitted -> force_edge", decide("eu-west", "us-east", EDGE_MODE) == "force_edge")
    check("force_edge never allows raw cross-region", decide("eu-west", "us-east", EDGE_MODE) != "allow")

    # --- routable_candidates(): failover excludes out-of-region routes (FR-023) ---
    routes = [
        Route("openai-eu", "eu-west", priority=0),
        Route("anthropic-us", "us-east", priority=1),
        Route("azure-eu", "EU-West", priority=2),  # case variant, still in region
        Route("bedrock-apac", "ap-south", priority=3),
    ]
    in_region = routable_candidates(routes, "eu-west")
    check("only in-region routes survive filtering", {r.provider for r in in_region} == {"openai-eu", "azure-eu"})
    check(
        "no out-of-region route can be a failover candidate (FR-023)",
        all(r.residency_region.strip().casefold() == "eu-west" for r in in_region),
    )
    check("candidate order is preserved for the caller's failover ordering", [r.priority for r in in_region] == [0, 2])

    # Dict-shaped routes are accepted too (matches provider_routes rows).
    dict_routes = [
        {"provider": "p-eu", "residency_region": "eu-west"},
        {"provider": "p-us", "residency_region": "us-east"},
    ]
    dict_in_region = routable_candidates(dict_routes, "eu-west")
    check("dict routes filter to in-region only", [r["provider"] for r in dict_in_region] == ["p-eu"])

    # No in-region candidate -> empty failover set, never a cross-boundary fallback.
    no_match = routable_candidates(routes, "sa-east")
    check("no in-region route yields no candidates (no cross-boundary fallback)", no_match == [])

    print(f"\n{_passed}/{_passed} passed\n")


if __name__ == "__main__":
    main()
