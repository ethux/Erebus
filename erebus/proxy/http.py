"""Transport plumbing: guarded HTTP deps, endpoint classification, headers."""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx
    from aiohttp import web

if not TYPE_CHECKING:
    try:
        import httpx  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - exercised in lightweight helper tests
        httpx = None  # type: ignore[assignment]

    try:
        from aiohttp import web  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - exercised in lightweight helper tests
        web = None  # type: ignore[assignment]

PROXY_CLIENT_MAX_SIZE = 16 * 1024 * 1024

# Hop-by-hop request headers the proxy must not forward.
_SKIP_REQUEST_HEADERS = {"host", "content-length", "transfer-encoding", "connection"}
# Response headers recomputed by aiohttp / invalidated by re-encoding the body.
_SKIP_RESPONSE_HEADERS = {"content-length", "transfer-encoding", "connection", "content-encoding"}


def _get_target_url(request: web.Request) -> str:
    """Determine the real upstream URL from the request headers or config."""
    # X-Target-URL header allows per-request override
    target = request.headers.get("X-Target-URL")
    if target:
        return target.rstrip("/")
    # Fall back to app-level default
    return request.app["target_url"]


def _is_chat_endpoint(path: str) -> bool:
    return "/chat/completions" in path or "/messages" in path


def _is_responses_endpoint(path: str) -> bool:
    return "/responses" in path


def forwardable_request_headers(request: web.Request) -> dict[str, str]:
    """Copy request headers, skipping hop-by-hop fields."""
    return {k: v for k, v in request.headers.items() if k.lower() not in _SKIP_REQUEST_HEADERS}


def copy_response_headers(upstream_headers, response, degraded_reason: str = "") -> None:
    """Copy upstream response headers onto `response` + the degraded signal."""
    for k, v in upstream_headers.items():
        if k.lower() not in _SKIP_RESPONSE_HEADERS:
            response.headers[k] = v
    if degraded_reason:
        response.headers["X-Erebus-Degraded"] = degraded_reason
