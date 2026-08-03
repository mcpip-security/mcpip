"""
mcpip_sdk.cli.auth — resolve the bearer, the step-up OTP, and secret material
WITHOUT ever letting any of them touch argv (which leaks via ``ps`` and shell
history) or stdout/stderr/logs.

The bearer resolves to the SDK's :data:`~mcpip_sdk.tokens.TokenProvider` — a
literal ``str`` (used verbatim) or a zero-arg CALLABLE (re-invoked by the SDK
for proactive ~30s-before-exp refresh). A ``cmd:`` source is wrapped as a
callable so the CLI never caches the raw token to disk. There is deliberately NO
``--token STRING`` flag.

Precedence, first present wins:
  --token-file PATH  →  --token-stdin  →  --token-cmd 'CMD'  →  MCPIP_TOKEN env
  →  the active context's token-source reference (env: | file: | cmd:).
"""

from __future__ import annotations

import getpass
import os
import subprocess
import sys
from typing import Any, Callable

from mcpip_sdk.cli.config import read_secret_file
from mcpip_sdk.cli.errors import CLIConfigError
from mcpip_sdk.tokens import TokenProvider


def resolve_token(
    *,
    token_file: str | None,
    token_stdin: bool,
    token_cmd: str | None,
    context_token_source: str | None,
) -> TokenProvider | None:
    """
    Build the bearer provider from the first present source. Returns ``None``
    when no source resolves — the gateway then answers authenticated routes with
    its usual opaque deny (the CLI never invents identity).
    """
    if token_file is not None:
        return read_secret_file(token_file)  # verbatim str; perms enforced.
    if token_stdin:
        return _read_stdin_line("token")
    if token_cmd is not None:
        return _command_provider(token_cmd)
    env_token = os.environ.get("MCPIP_TOKEN")
    if env_token:
        return env_token
    if context_token_source is not None:
        return _from_source_ref(context_token_source)
    return None


def _from_source_ref(ref: str) -> TokenProvider:
    """Resolve a context's ``env:`` / ``file:`` / ``cmd:`` token-source ref."""
    if ref.startswith("env:"):
        var = ref[len("env:"):]
        value = os.environ.get(var)
        if not value:
            raise CLIConfigError(
                f"token-source env:{var} is not set in the environment"
            )
        return value
    if ref.startswith("file:"):
        return read_secret_file(ref[len("file:"):])
    if ref.startswith("cmd:"):
        return _command_provider(ref[len("cmd:"):])
    raise CLIConfigError(f"unrecognized token-source: {ref!r}")


def _command_provider(command: str) -> Callable[[], str]:
    """Wrap a shell command whose stdout is the token as a refreshable callable.
    The token is never cached to disk by the CLI; the SDK caches it in memory and
    re-invokes this callable ~30s before the token's ``exp``."""

    def provider() -> str:
        try:
            completed = subprocess.run(  # noqa: S602 - operator-supplied command
                command,
                shell=True,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as exc:
            raise CLIConfigError(
                f"token-cmd failed to launch: {exc.strerror}"
            ) from exc
        if completed.returncode != 0:
            # Do NOT echo the command's stderr — it may carry sensitive detail.
            raise CLIConfigError(
                f"token-cmd exited {completed.returncode}"
            )
        token = completed.stdout.strip()
        if not token:
            raise CLIConfigError("token-cmd produced no token on stdout")
        return token

    return provider


def _read_stdin_line(what: str) -> str:
    line = sys.stdin.readline()
    if not line:
        raise CLIConfigError(f"expected a {what} on stdin, got EOF")
    return line.strip()


# ---------------------------------------------------------------------------
# Step-up OTP — interactive getpass (no echo) or stdin, NEVER argv/logs.
# ---------------------------------------------------------------------------


def resolve_otp(*, otp_stdin: bool, otp_prompt: bool) -> str:
    """
    Read the one-time step-up code without echoing it.

    ``--otp-stdin`` reads one line from stdin (for pipes/CI); ``--otp-prompt``
    forces an interactive no-echo prompt. With neither, an interactive TTY gets
    a getpass prompt and a non-TTY raises so a non-interactive run fails loud
    (the caller resumes with ``mcpip complete`` once it has the code) rather than
    hanging. The code is passed once to ``complete`` and discarded.
    """
    if otp_stdin:
        return _read_stdin_line("one-time code")
    if otp_prompt or sys.stdin.isatty():
        return getpass.getpass("one-time code: ")
    # Naming only the mechanism (--otp-stdin) left the caller with nowhere to GET
    # a code. Name the source; both commands fetch and complete in one step.
    raise CLIConfigError(
        "no OTP available non-interactively. Fetch and complete in one command "
        "instead:\n"
        "  sandbox     mcpip sandbox authenticator <challenge>\n"
        "  production  mcpip authenticator reveal --challenge <id> --code <digits>\n"
        "Or pipe a code you already hold with --otp-stdin, or run in a TTY."
    )


def has_interactive_otp(*, otp_stdin: bool, otp_prompt: bool) -> bool:
    """Whether an OTP can be obtained in THIS invocation (used by ``authorize``
    to decide inline-complete vs. persist-and-exit-9)."""
    return otp_stdin or otp_prompt or sys.stdin.isatty()


# ---------------------------------------------------------------------------
# Secret material (vault) — file/stdin only, never --arg/argv.
# ---------------------------------------------------------------------------


def resolve_material(
    *, material_file: str | None, material_stdin: bool
) -> dict[str, str]:
    """
    Load flat ``{name: value}`` secret material from a JSON file or stdin — never
    from argv. Every value must be a string (bounded broker credential fields).
    """
    from mcpip_sdk.cli.args import load_document

    if material_stdin:
        raw: Any = load_document("-")
    elif material_file is not None:
        raw = load_document(f"@{material_file}")
    else:
        raise CLIConfigError(
            "secret material must come from --material-file or --material-stdin "
            "(never --arg/argv, which leaks via ps/history)"
        )
    if not isinstance(raw, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in raw.items()
    ):
        raise CLIConfigError(
            "secret material must be a flat JSON object of string values"
        )
    return {str(k): str(v) for k, v in raw.items()}


__all__ = [
    "resolve_token",
    "resolve_otp",
    "has_interactive_otp",
    "resolve_material",
]
