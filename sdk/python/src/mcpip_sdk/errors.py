"""
mcpip_sdk.errors — the SDK's typed failure surface.

    ◐ "Opaque to agents, precise to operators."

The gateway is fail-closed and OPAQUE BY DESIGN: a policy denial is exactly
``{"error": "MCPIP: request denied by policy.", "correlation_id": ...}`` — no
reason, no field name, no hint. The concrete cause exists only in the gateway's
WORM audit log, where an operator can look it up by the correlation id. The SDK
mirrors that boundary structurally: :class:`MCPIPDenied` carries ONLY the
correlation id and the HTTP status. It never guesses, parses, or infers a deny
cause, and neither should calling code — quote ``correlation_id`` to a human
operator instead.

``MCPIPStaged`` deliberately does NOT exist. A staged step-up (HTTP 202) is a
successful outcome of ``authorize()`` — :class:`mcpip_sdk.models.Staged`, a
result carrying the ``challenge_id`` to complete — never an exception.
"""

from __future__ import annotations

from typing import Final

# The gateway's fixed agent-facing denial text — byte-identical to
# ``interfaces.AGENT_FACING_DENY_MESSAGE`` on the server.
AGENT_FACING_DENY_MESSAGE: Final[str] = "MCPIP: request denied by policy."


class MCPIPError(Exception):
    """Base class for every error the SDK raises on gateway interactions."""


class MCPIPDenied(MCPIPError):
    """
    The gateway denied the request — opaque by design.

    The only diagnostic the agent boundary ever discloses is ``correlation_id``,
    the handle an operator can resolve against the WORM audit log (the concrete
    deny reason lives there and ONLY there). Do not retry a denied call: token
    expiry and policy denials are indistinguishable on the wire, and a retried
    step-up consume is a real ``pin_not_found`` deny that double-counts audit
    events. Handle a deny by surfacing the correlation id.

    ``http_status`` is 403 for the REST edge, 200 for the MCP JSON-RPC edge
    (denies there are JSON-RPC ``-32000`` errors inside an HTTP 200), and 500
    for the gateway's opaque internal-failure envelope.
    """

    def __init__(self, correlation_id: str, http_status: int = 403) -> None:
        super().__init__(AGENT_FACING_DENY_MESSAGE)
        self.correlation_id = correlation_id
        self.http_status = http_status


class MCPIPInvalidRequest(MCPIPError):
    """
    The gateway rejected the envelope before authorization ran (HTTP 422/413,
    or a JSON-RPC ``-32700``/``-32600``/``-32601``). This is a malformed or
    oversized request — a programming error, not a policy decision.
    """

    def __init__(
        self, message: str = "invalid request", correlation_id: str | None = None
    ) -> None:
        super().__init__(message)
        self.correlation_id = correlation_id


class MCPIPUnavailable(MCPIPError):
    """
    The gateway could not be reached or is shedding load (HTTP 503, timeouts,
    transport failures). ``retry_after`` surfaces the gateway's ``Retry-After``
    header when present. The SDK never retries automatically — not even here —
    so callers keep full control over back-off.
    """

    def __init__(self, message: str, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class MCPIPNotFound(MCPIPError):
    """
    A referenced resource does not exist on an otherwise-live endpoint — e.g.
    an unknown/expired authenticator challenge or an audit event not yet sealed
    into a signed epoch. Distinct from :class:`MCPIPSandboxOnly`, which means
    the ENDPOINT itself does not exist on this gateway.
    """

    def __init__(self, message: str, correlation_id: str | None = None) -> None:
        super().__init__(message)
        self.correlation_id = correlation_id


class MCPIPSandboxOnly(MCPIPError):
    """
    A sandbox-only affordance was called against a production gateway.

    ``/v1/dev/token``, ``/v1/authenticator/{challenge_id}``, ``/v1/audit/verify``
    and ``/v1/audit/proof/{event_id}`` exist ONLY when the gateway runs with
    ``MCPIP_SANDBOX_MODE=true``; in production they answer 404 (identity stays
    IdP-sovereign, OTPs arrive out-of-band, audit is verified externally).
    """

    def __init__(self, endpoint: str) -> None:
        super().__init__(
            f"{endpoint} is sandbox-only and does not exist on this gateway "
            "(production gateways answer 404 here by design)"
        )
        self.endpoint = endpoint


__all__ = [
    "AGENT_FACING_DENY_MESSAGE",
    "MCPIPError",
    "MCPIPDenied",
    "MCPIPInvalidRequest",
    "MCPIPUnavailable",
    "MCPIPNotFound",
    "MCPIPSandboxOnly",
]
