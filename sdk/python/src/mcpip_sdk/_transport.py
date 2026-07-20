"""
mcpip_sdk._transport — the shared HTTP layer under every SDK client.

One httpx.Client per SDK client: strict timeouts, bearer attachment via
:class:`mcpip_sdk.tokens.TokenSource`, and ONE place that maps the gateway's
error statuses onto the typed exception family. Two rules are load-bearing:

  * NEVER auto-retry. A ``POST /v1/authorize`` retry after a deny is a real
    ``pin_not_found`` consume replay and double-counts WORM audit events; a
    GET retry would mask a genuinely shedding gateway. Back-off belongs to the
    caller, informed by ``MCPIPUnavailable.retry_after``.
  * Never interpret a deny. 401/403/500 all collapse to :class:`MCPIPDenied`
    carrying only the correlation id — exactly what the wire disclosed.

The ``transport`` parameter accepts any ``httpx.BaseTransport`` so tests can
drive a real in-process ASGI gateway and embedders can add mTLS/proxy layers.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any, Final, Mapping, TypeVar, cast

import httpx

from mcpip_sdk.errors import (
    MCPIPDenied,
    MCPIPError,
    MCPIPInvalidRequest,
    MCPIPNotFound,
    MCPIPUnavailable,
)
from mcpip_sdk.tokens import TokenProvider, TokenSource

# Strict by default: 10s ceiling per request, 5s to establish the connection.
DEFAULT_TIMEOUT: Final[httpx.Timeout] = httpx.Timeout(10.0, connect=5.0)

# Every gateway response echoes the correlation id in this header — the
# fallback when an error body is unparseable.
CORRELATION_HEADER: Final[str] = "x-mcpip-correlation-id"

_USER_AGENT: Final[str] = "mcpip-sdk-python/0.1.0"

# ``typing.Self`` needs 3.11; the SDK floor is 3.10 — a bound TypeVar keeps
# ``with SandboxClient(...) as client:`` precisely typed for subclasses.
_TClient = TypeVar("_TClient", bound="_BaseClient")


def _json_object(response: httpx.Response) -> dict[str, Any]:
    """Parse a response body as a JSON object — anything else is a protocol error."""
    try:
        payload: Any = response.json()
    except ValueError as exc:
        raise MCPIPError(
            f"gateway returned a non-JSON body (HTTP {response.status_code})"
        ) from exc
    if not isinstance(payload, dict):
        raise MCPIPError(
            f"gateway returned a non-object JSON body (HTTP {response.status_code})"
        )
    return cast("dict[str, Any]", payload)


def _body_correlation(response: httpx.Response) -> str | None:
    """The ``correlation_id`` from the response BODY only (used to distinguish
    a sandbox-only 404 — no body id — from a live not-found, which carries one)."""
    try:
        payload: Any = response.json()
    except ValueError:
        return None
    if isinstance(payload, dict):
        corr = payload.get("correlation_id")
        if isinstance(corr, str) and corr:
            return corr
    return None


def _correlation_of(response: httpx.Response) -> str:
    """Best-effort correlation id: body first, echoed header as fallback."""
    corr = _body_correlation(response)
    if corr is not None:
        return corr
    header: Any = response.headers.get(CORRELATION_HEADER, "")
    return header if isinstance(header, str) else ""


def _retry_after_seconds(response: httpx.Response) -> float | None:
    raw = response.headers.get("retry-after")
    if raw is None:
        return None
    try:
        return float(raw)
    except ValueError:
        return None


class _BaseClient:
    """
    Shared plumbing for :class:`MCPIPClient` / :class:`MCPIPAdminClient`.

    Context-manager friendly (``with MCPIPClient(...) as client:``) and safe to
    ``close()`` explicitly. Not thread-safe per instance (httpx.Client is, but
    the token cache is unsynchronized) — use one client per worker.
    """

    def __init__(
        self,
        base_url: str,
        token: TokenProvider | None = None,
        *,
        timeout: httpx.Timeout | float = DEFAULT_TIMEOUT,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self._tokens = TokenSource(token)
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout,
            transport=transport,
            headers={"User-Agent": _USER_AGENT},
        )

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Release the underlying connection pool. Idempotent."""
        self._client.close()

    def __enter__(self: _TClient) -> _TClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- identity ----------------------------------------------------------

    def set_token(self, token: TokenProvider | None) -> None:
        """
        Replace the bearer source: a literal JWT (used verbatim) or a zero-arg
        callable minting one (invoked lazily, cached, refreshed ~30s before its
        own ``exp``). ``None`` sends no Authorization header — the gateway then
        answers authenticated routes with its usual opaque deny.
        """
        self._tokens.replace(token)

    # -- the one request path ----------------------------------------------

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Mapping[str, Any] | None = None,
        params: Mapping[str, str] | None = None,
        authenticated: bool = True,
        tolerate: tuple[int, ...] = (),
    ) -> httpx.Response:
        """
        Issue one request and map error statuses to typed exceptions.

        ``tolerate`` lists statuses the CALLER interprets (e.g. 503 on
        ``/readyz`` is an honest "not ready", 404 on sandbox-only endpoints is
        "this gateway is production"). Everything else: 401/403/500 →
        MCPIPDenied, 422/413/4xx → MCPIPInvalidRequest, 404 → MCPIPNotFound,
        503/5xx/transport failures → MCPIPUnavailable. No retries, ever.
        """
        headers: dict[str, str] = {}
        if authenticated:
            bearer = self._tokens.bearer()
            if bearer is not None:
                headers["Authorization"] = f"Bearer {bearer}"
        try:
            response = self._client.request(
                method,
                path,
                json=json_body,
                params=dict(params) if params is not None else None,
                headers=headers,
            )
        except httpx.TimeoutException as exc:
            raise MCPIPUnavailable(f"gateway timed out: {exc!r}") from exc
        except httpx.TransportError as exc:
            raise MCPIPUnavailable(f"gateway unreachable: {exc!r}") from exc

        status = response.status_code
        if status in tolerate or status < 400:
            return response
        if status == 503:
            raise MCPIPUnavailable(
                "gateway is shedding load or not ready (HTTP 503)",
                retry_after=_retry_after_seconds(response),
            )
        if status in (401, 403, 500):
            # Opaque by design: only the correlation id crossed the boundary.
            raise MCPIPDenied(_correlation_of(response), http_status=status)
        if status == 404:
            raise MCPIPNotFound(
                f"{path} answered 404", correlation_id=_body_correlation(response)
            )
        if status in (413, 422):
            raise MCPIPInvalidRequest(
                "request body too large (HTTP 413)"
                if status == 413
                else "invalid request envelope (HTTP 422)",
                correlation_id=_correlation_of(response) or None,
            )
        if status >= 500:
            raise MCPIPUnavailable(f"unexpected gateway status {status}")
        raise MCPIPInvalidRequest(
            f"unexpected gateway status {status}",
            correlation_id=_correlation_of(response) or None,
        )


__all__ = [
    "DEFAULT_TIMEOUT",
    "CORRELATION_HEADER",
    "_BaseClient",
    "_json_object",
    "_body_correlation",
    "_correlation_of",
]
