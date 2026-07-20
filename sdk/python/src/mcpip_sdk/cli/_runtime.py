"""
mcpip_sdk.cli._runtime — the per-invocation resolved state + typed client
factories shared by every command handler.

A :class:`Runtime` bundles the resolved gateway target, the output mode, and the
raw token flags, and hands back a constructed SDK client on demand (the bearer
is resolved lazily so read-only unauthenticated commands never touch a token
source). ``set_transport_override`` is a TEST-ONLY seam: the contract suite
drives the REAL in-process gateway through an ``httpx.ASGITransport`` exactly
like ``tests/test_sdk_python.py`` — production always leaves it ``None`` and
talks over real sockets.
"""

from __future__ import annotations

from dataclasses import dataclass

import httpx

from mcpip_sdk.admin import MCPIPAdminClient
from mcpip_sdk.client import MCPIPClient, SandboxClient
from mcpip_sdk.cli.auth import resolve_token
from mcpip_sdk.cli.config import Resolved
from mcpip_sdk.cli.render import OutputMode
from mcpip_sdk.tokens import TokenProvider

_TRANSPORT_OVERRIDE: httpx.BaseTransport | None = None


def set_transport_override(transport: httpx.BaseTransport | None) -> None:
    """TEST ONLY — route every CLI-built client through this transport."""
    global _TRANSPORT_OVERRIDE
    _TRANSPORT_OVERRIDE = transport


@dataclass
class Runtime:
    """Resolved invocation state + client factories."""

    resolved: Resolved
    mode: OutputMode
    token_file: str | None = None
    token_stdin: bool = False
    token_cmd: str | None = None

    def token_provider(self) -> TokenProvider | None:
        return resolve_token(
            token_file=self.token_file,
            token_stdin=self.token_stdin,
            token_cmd=self.token_cmd,
            context_token_source=self.resolved.token_source,
        )

    def agent_client(self) -> MCPIPClient:
        return MCPIPClient(
            self.resolved.base_url,
            self.token_provider(),
            transport=_TRANSPORT_OVERRIDE,
        )

    def sandbox_client(self) -> SandboxClient:
        return SandboxClient(
            self.resolved.base_url,
            self.token_provider(),
            transport=_TRANSPORT_OVERRIDE,
        )

    def admin_client(self) -> MCPIPAdminClient:
        return MCPIPAdminClient(
            self.resolved.base_url,
            self.token_provider(),
            transport=_TRANSPORT_OVERRIDE,
        )


__all__ = ["Runtime", "set_transport_override"]
