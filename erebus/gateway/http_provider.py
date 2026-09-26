"""Real HTTP provider transport over a shared httpx.AsyncClient (008 R5).

``transport.build_upstream_call`` already abstracts the upstream poster behind
``HttpPost = Callable[[str, dict, dict], Awaitable[dict]]`` so the credential/route
selection stays network-free in unit tests. The only new piece here is the live
client: an async ``http_post`` (non-stream completion) and ``http_stream`` (SSE),
both over one pooled :class:`httpx.AsyncClient` whose timeout and connection limits
come from :class:`~erebus.gateway.config.GatewayConfig`.

The client is shared process-wide (connection pooling), built once at startup and
closed on shutdown. A non-2xx upstream is raised (``httpx.HTTPStatusError``) so the
chat handler can fail closed rather than restore an error body as if it were a
completion. No secret is logged here; headers (which carry the central credential)
are passed straight to httpx and never echoed.
"""
from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable

import httpx

from .config import GatewayConfig

# Match transport.HttpPost so this plugs into transport.build_upstream_call unchanged.
HttpPost = Callable[[str, dict, dict], Awaitable[dict]]
HttpStream = Callable[[str, dict, dict], AsyncIterator[str]]

# Cap pooled connections so one gateway replica cannot exhaust upstream sockets.
_MAX_CONNECTIONS = 100
_MAX_KEEPALIVE = 20


def build_client(config: GatewayConfig) -> httpx.AsyncClient:
    """Build the shared AsyncClient with timeout + connection limits from config."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(float(config.http_timeout_s)),
        limits=httpx.Limits(
            max_connections=_MAX_CONNECTIONS,
            max_keepalive_connections=_MAX_KEEPALIVE,
        ),
    )


def build_http_post(
    config: GatewayConfig,
    client: httpx.AsyncClient | None = None,
) -> tuple[HttpPost, HttpStream, httpx.AsyncClient]:
    """Return ``(http_post, http_stream, aclient)`` over a shared httpx.AsyncClient.

    Pass ``client`` to inject a pre-built client (e.g. one wired to an
    ``httpx.MockTransport`` in tests); otherwise one is built from ``config``.
    Close the returned client on shutdown via :func:`close_client`.
    """
    aclient = client if client is not None else build_client(config)

    async def http_post(url: str, headers: dict, payload: dict) -> dict:
        """POST ``payload`` as JSON to ``url`` with ``headers``; return decoded JSON.

        A non-2xx upstream raises ``httpx.HTTPStatusError`` (fail-closed at the caller).
        """
        response = await aclient.post(url, headers=headers, json=payload)
        response.raise_for_status()  # non-2xx -> error, never a fake completion
        return response.json()

    async def http_stream(url: str, headers: dict, payload: dict) -> AsyncIterator[str]:
        """POST and yield each upstream SSE ``data:`` payload (skipping ``[DONE]``).

        Yields the raw ``data:`` field values as strings so the streaming restorer
        can reassemble and detokenize them. A non-2xx upstream raises before any
        fragment is yielded.
        """
        async with aclient.stream("POST", url, headers=headers, json=payload) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.startswith("data:"):
                    continue
                data = line[len("data:"):].strip()
                if data and data != "[DONE]":
                    yield data

    return http_post, http_stream, aclient


async def close_client(client: httpx.AsyncClient) -> None:
    """Close the shared client, releasing pooled connections (shutdown drain)."""
    await client.aclose()
