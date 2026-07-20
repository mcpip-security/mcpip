"""
mcpip_sdk.cli — the ``mcpip`` command-line interface.

A thin, elite-ergonomics wrapper over the typed SDK clients
(:class:`~mcpip_sdk.client.MCPIPClient` / :class:`~mcpip_sdk.client.SandboxClient`
/ :class:`~mcpip_sdk.admin.MCPIPAdminClient`) — it reimplements NONE of the wire
protocol, auth, or envelope logic. Fail-closed and opaque like the gateway: a
deny prints only a ``correlation_id``, secrets never reach stdout/argv/logs, and
exit codes are stable so the CLI composes in scripts and CI.

The console entry point is ``mcpip_sdk.cli:main``.
"""

from __future__ import annotations

from mcpip_sdk import __version__
from mcpip_sdk.cli.errors import ExitCode
from mcpip_sdk.cli.main import main

__all__ = ["main", "ExitCode", "__version__"]
