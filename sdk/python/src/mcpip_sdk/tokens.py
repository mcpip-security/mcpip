"""
mcpip_sdk.tokens — bearer-token providers with proactive refresh.

The gateway verifies JWTs; it never mints them. Clients therefore hold either a
static token (production: minted/rotated by the customer's IdP) or a callback
that fetches a fresh one (the IdP/STS integration point). The SDK refreshes
PROACTIVELY, ~30 seconds before the JWT's own ``exp`` — never reactively on a
deny, because a deny is opaque (expiry and policy are indistinguishable) and a
retry would double-count every legitimate denial as two WORM audit events.
This mirrors ``scripts/claude_mcp_bridge.py`` and the console's token cache.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Callable, Final, Union

# A bearer source: a literal JWT (used verbatim, never refreshed) or a zero-arg
# callable returning one (invoked lazily; cached until ~exp - slack).
TokenProvider = Union[str, Callable[[], str]]

# Re-mint this many seconds before the token's own ``exp`` (sandbox dev tokens
# live ~5 minutes). Same constant as the reference bridge and console clients.
TOKEN_EXP_SLACK_SECONDS: Final[float] = 30.0


def jwt_exp_seconds(token: str) -> float | None:
    """
    Best-effort decode of a JWT's ``exp`` claim (epoch seconds).

    No signature verification happens (or could — the gateway holds the keys);
    this only schedules the client-side refresh. Returns None when unreadable,
    in which case the provider is simply consulted on every request.
    """
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # restore base64 padding
        claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except (ValueError, IndexError):
        return None
    if not isinstance(claims, dict):
        return None
    exp = claims.get("exp")
    return float(exp) if isinstance(exp, (int, float)) else None


class TokenSource:
    """
    Resolve the Authorization bearer for each request.

    * ``None``      — no header is attached; the gateway answers with its usual
                      opaque deny on authenticated routes (the gateway, not the
                      SDK, is the authority on what needs identity).
    * ``str``       — used verbatim on every request, never refreshed. Rotation
                      is the operator's IdP's job.
    * ``callable``  — invoked lazily and cached; re-invoked once the cached
                      token is within :data:`TOKEN_EXP_SLACK_SECONDS` of its
                      ``exp`` (or on every request when ``exp`` is unreadable).
    """

    def __init__(self, provider: TokenProvider | None) -> None:
        self._provider = provider
        self._cached: str | None = None
        self._expires_at: float | None = None

    def replace(self, provider: TokenProvider | None) -> None:
        """Swap the provider and drop any cached token."""
        self._provider = provider
        self._cached = None
        self._expires_at = None

    def bearer(self) -> str | None:
        """The token to attach right now, refreshing proactively if needed."""
        provider = self._provider
        if provider is None:
            return None
        if isinstance(provider, str):
            return provider
        stale = (
            self._cached is None
            or self._expires_at is None
            or time.time() >= self._expires_at - TOKEN_EXP_SLACK_SECONDS
        )
        if stale:
            self._cached = provider()
            self._expires_at = jwt_exp_seconds(self._cached)
        return self._cached


__all__ = ["TokenProvider", "TokenSource", "TOKEN_EXP_SLACK_SECONDS", "jwt_exp_seconds"]
