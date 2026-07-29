"""
mcpip_sdk.cli.errors — the CLI's exit-code contract + exception→code mapping.

The gateway is fail-closed and OPAQUE; the CLI mirrors that at the process
boundary. Exit codes are STABLE and DISTINCT so a script or CI job can branch
on *what kind* of outcome occurred without ever learning *why* a deny happened
(only the ``correlation_id`` crosses — see :mod:`mcpip_sdk.cli.render`).

Two CLI-local exceptions live here because they have no gateway analogue:
:class:`CLIConfigError` (a local config/permission problem — its message is
about the user's OWN files, so it is safe to print) and :class:`StepUpPending`
(``authorize`` returned :class:`~mcpip_sdk.models.Staged` in a non-interactive
run with no OTP — the envelope was persisted, resume with ``mcpip complete``).
"""

from __future__ import annotations

from enum import IntEnum

from mcpip_sdk.errors import (
    MCPIPDenied,
    MCPIPError,
    MCPIPInvalidRequest,
    MCPIPNotFound,
    MCPIPSandboxOnly,
    MCPIPUnavailable,
)


class ExitCode(IntEnum):
    """The CLI's process exit codes — documented in ``docs/start/CLI.md``."""

    OK = 0
    # 1 is the catch-all for an unexpected/unhandled error (see main()).
    ERROR = 1
    # 2 is argparse's own usage-error code — raised as SystemExit(2) by the
    # parser, never returned through this map. Named here for documentation.
    USAGE = 2
    DENIED = 3
    UNAVAILABLE = 4
    INVALID_REQUEST = 5
    NOT_FOUND = 6
    SANDBOX_ONLY = 7
    CONFIG = 8
    STEP_UP_PENDING = 9


class CLIConfigError(Exception):
    """
    A LOCAL configuration or permission problem — a missing context, a bad
    token-source reference, or a config/token file that is group- or
    world-readable. Unlike a gateway deny, this is about the user's own machine,
    so its message names the concrete problem (it discloses no gateway state).
    """


class StepUpPending(Exception):
    """
    ``authorize`` staged a step-up (HTTP 202) but the invocation ran
    non-interactively with no OTP available. The exact envelope was persisted to
    the 0600 staged-state store; resume with ``mcpip complete --challenge <id>``.
    """

    def __init__(self, challenge_id: str, correlation_id: str) -> None:
        super().__init__(
            f"step-up required; resume with: mcpip complete --challenge {challenge_id}"
        )
        self.challenge_id = challenge_id
        self.correlation_id = correlation_id


def map_exception(exc: BaseException) -> ExitCode:
    """Map any raised error to its stable, distinct exit code."""
    if isinstance(exc, MCPIPDenied):
        return ExitCode.DENIED
    if isinstance(exc, MCPIPUnavailable):
        return ExitCode.UNAVAILABLE
    if isinstance(exc, MCPIPSandboxOnly):
        return ExitCode.SANDBOX_ONLY
    if isinstance(exc, MCPIPNotFound):
        return ExitCode.NOT_FOUND
    if isinstance(exc, MCPIPInvalidRequest):
        return ExitCode.INVALID_REQUEST
    if isinstance(exc, StepUpPending):
        return ExitCode.STEP_UP_PENDING
    if isinstance(exc, CLIConfigError):
        return ExitCode.CONFIG
    if isinstance(exc, MCPIPError):
        return ExitCode.ERROR
    return ExitCode.ERROR


__all__ = ["ExitCode", "CLIConfigError", "StepUpPending", "map_exception"]
