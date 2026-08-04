"""
mcpip_sdk.cli.render — human tables + key:value blocks + a stable ``--json``
serializer, and the ONE opaque error renderer.

Two output modes, one truth: the human default is kubectl-style (aligned column
tables for lists, ``key: value`` blocks for single objects); ``--json`` emits the
frozen dataclass model as a stable JSON object/array for scripting. Because the
SDK models are structurally free of secrets/targets/reasons, no redaction pass
can miss one — opacity is a property of the data, not of this renderer.

A deny renders IDENTICALLY everywhere and discloses ONLY the correlation id.
Human errors go to stderr; ``--json`` errors go to stdout (so a pipeline can
capture and branch on them) — both leave stdout otherwise empty.
"""

from __future__ import annotations

import dataclasses
import json
import sys
from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from mcpip_sdk.errors import (
    MCPIPDenied,
    MCPIPInvalidRequest,
    MCPIPNotFound,
    MCPIPSandboxOnly,
    MCPIPUnavailable,
)
from mcpip_sdk.cli.errors import CLIConfigError, StepUpPending


@dataclass(frozen=True)
class OutputMode:
    """Resolved output flags for one invocation."""

    json: bool = False
    quiet: bool = False
    color: bool = True

    @property
    def use_color(self) -> bool:
        return self.color and sys.stdout.isatty()


# ---------------------------------------------------------------------------
# JSON serialization.
# ---------------------------------------------------------------------------


def to_jsonable(obj: Any) -> Any:
    """Recursively convert frozen dataclass models (and lists/dicts/tuples of
    them) to JSON-safe primitives."""
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {k: to_jsonable(v) for k, v in dataclasses.asdict(obj).items()}
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [to_jsonable(v) for v in obj]
    return obj


def emit_json(obj: Any) -> None:
    print(json.dumps(to_jsonable(obj), indent=2, sort_keys=False))


# ---------------------------------------------------------------------------
# Human rendering primitives.
# ---------------------------------------------------------------------------


def table(headers: Sequence[str], rows: Iterable[Sequence[Any]]) -> str:
    """Render an aligned column table (kubectl-style, uppercase headers)."""
    materialized = [[_cell(c) for c in row] for row in rows]
    cols = len(headers)
    widths = [len(h) for h in headers]
    for row in materialized:
        for i in range(cols):
            widths[i] = max(widths[i], len(row[i]) if i < len(row) else 0)
    out_lines = ["  ".join(h.upper().ljust(widths[i]) for i, h in enumerate(headers))]
    for row in materialized:
        out_lines.append(
            "  ".join(
                (row[i] if i < len(row) else "").ljust(widths[i])
                for i in range(cols)
            ).rstrip()
        )
    return "\n".join(out_lines)


def block(pairs: Sequence[tuple[str, Any]]) -> str:
    """Render a single object as an aligned ``key: value`` block."""
    width = max((len(k) for k, _ in pairs), default=0)
    return "\n".join(f"{k.ljust(width)} : {_cell(v)}" for k, v in pairs)


def _cell(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return ", ".join(_cell(v) for v in value) if value else "-"
    return str(value)


def empty(resource: str, mode: OutputMode) -> None:
    """Honest empty: ``[]`` for JSON, ``No <resource>.`` for humans — never an
    invented row."""
    if mode.json:
        print("[]")
    else:
        print(f"No {resource}.")


# ---------------------------------------------------------------------------
# Top-level emit helpers used by command handlers.
# ---------------------------------------------------------------------------


def emit_object(mode: OutputMode, model: Any, human: str, *, quiet_id: str = "") -> None:
    if mode.quiet:
        if quiet_id:
            print(quiet_id)
        return
    if mode.json:
        emit_json(model)
    else:
        print(human)


def emit_list(
    mode: OutputMode,
    models: Sequence[Any],
    resource: str,
    human: str,
    *,
    quiet_ids: Sequence[str] = (),
) -> None:
    if not models:
        if mode.quiet:
            return
        empty(resource, mode)
        return
    if mode.quiet:
        for qid in quiet_ids:
            print(qid)
        return
    if mode.json:
        emit_json(list(models))
    else:
        print(human)


# ---------------------------------------------------------------------------
# The opaque error renderer — mirrors MCPIPDenied exactly.
# ---------------------------------------------------------------------------


def render_error(mode: OutputMode, exc: BaseException) -> None:
    """
    Render any raised error. A deny discloses ONLY the correlation id; transport
    and not-found/invalid errors collapse to generic text with no gateway
    internals. LOCAL config errors (the user's own files) print their concrete
    message. JSON errors go to stdout, human errors to stderr.
    """
    if isinstance(exc, MCPIPDenied):
        # A deny discloses ONLY the opaque correlation id. exc.http_status varies
        # by CAUSE and EDGE (401 authless / 403 policy / 200 MCP JSON-RPC / 500
        # internal) — surfacing it would hand a scripted caller a reason/edge
        # discriminator the gateway deliberately collapses. The exit code (3) is
        # the single, uniform deny signal; "error":"denied" is the invariant field.
        _error(
            mode,
            human=f"denied: request denied by policy (correlation_id={exc.correlation_id})",
            payload={
                "error": "denied",
                "correlation_id": exc.correlation_id,
            },
        )
        return
    if isinstance(exc, MCPIPUnavailable):
        payload: dict[str, Any] = {"error": "unavailable"}
        human = "error: gateway unreachable"
        if exc.retry_after is not None:
            payload["retry_after"] = exc.retry_after
            human += f" (retry_after={exc.retry_after}s)"
        _error(mode, human=human, payload=payload)
        return
    if isinstance(exc, MCPIPSandboxOnly):
        _error(
            mode,
            human="error: endpoint not available on this gateway",
            payload={"error": "sandbox_only"},
        )
        return
    if isinstance(exc, MCPIPNotFound):
        _error(
            mode,
            human="error: referenced resource not found",
            payload={
                "error": "not_found",
                "correlation_id": exc.correlation_id,
            },
        )
        return
    if isinstance(exc, MCPIPInvalidRequest):
        _error(
            mode,
            human="error: request rejected before authorization",
            payload={
                "error": "invalid_request",
                "correlation_id": exc.correlation_id,
            },
        )
        return
    if isinstance(exc, StepUpPending):
        _error(
            mode,
            # The hint used to name `mcpip complete --challenge <id>` alone, which
            # fails in any non-TTY with "no OTP available" — it needs a code no
            # command could fetch. Both working paths are named instead, because
            # the renderer cannot see whether this gateway is a sandbox.
            human=(
                "step-up required: envelope persisted. Resume with:\n"
                f"  sandbox     mcpip sandbox authenticator {exc.challenge_id}\n"
                f"  production  mcpip authenticator reveal --challenge {exc.challenge_id} "
                "--code <6 digits from your enrolled authenticator>"
            ),
            payload={
                "error": "step_up_pending",
                "challenge_id": exc.challenge_id,
                "correlation_id": exc.correlation_id,
            },
        )
        return
    if isinstance(exc, CLIConfigError):
        # LOCAL problem — the message names the user's own file/flag, discloses
        # no gateway state, so it is safe (and helpful) to print verbatim.
        _error(mode, human=f"error: {exc}", payload={"error": "config", "detail": str(exc)})
        return
    # Unexpected: keep the message generic on the human path; the type is enough.
    _error(
        mode,
        human=f"error: {type(exc).__name__}",
        payload={"error": "unexpected"},
    )


def _error(mode: OutputMode, *, human: str, payload: dict[str, Any]) -> None:
    if mode.json:
        print(json.dumps(payload, sort_keys=False))
    else:
        print(human, file=sys.stderr)


__all__ = [
    "OutputMode",
    "to_jsonable",
    "emit_json",
    "table",
    "block",
    "empty",
    "emit_object",
    "emit_list",
    "render_error",
]
