"""
mcpip_sdk.cli.commands.agent — the agent surface: catalog, authorize (+ inline
or deferred step-up), complete, the AuthZEN decision query, and the MCP edge.

Two disciplines are load-bearing here:

* The step-up envelope is PERSISTED byte-identically to a 0600 state file keyed
  by ``challenge_id`` and REPLAYED from disk by ``complete`` — never rebuilt from
  args, so argument canonicalization can never drift into an opaque deny that
  looks like a CLI bug.
* A vended cloud credential on an ``Allowed`` receipt is a real secret. It is
  NEVER written to stdout — not on a TTY, not down a pipe, not to a redirect
  (``isatty()`` is false for a CI pipe, ``| tee``, ``| logger`` and ``> file``
  alike, so it is no proxy for a private sink). Human output SUMMARIZES it (field
  names + expiry only); ``--json`` emits a redaction marker. To CAPTURE the
  material, pass ``--credential-out FILE`` — it lands via the same O_EXCL 0600
  path the dev-token / OTP affordances use, and only the path is printed.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from mcpip_sdk import envelopes
from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.args import collect_args, load_document
from mcpip_sdk.cli.auth import has_interactive_otp, resolve_otp
from mcpip_sdk.cli.config import (
    read_secret_file,
    staged_dir,
    write_secret_file,
)
from mcpip_sdk.cli.errors import CLIConfigError, ExitCode, StepUpPending
from mcpip_sdk.cli.render import block, emit_json, emit_object, table, to_jsonable
from mcpip_sdk.models import Allowed, AuthorizeEnvelope, Staged
from mcpip_sdk.errors import MCPIPNotFound


# ---------------------------------------------------------------------------
# catalog
# ---------------------------------------------------------------------------


def cmd_catalog(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        items = client.catalog()
    if not items:
        if not rt.mode.quiet:
            if rt.mode.json:
                print("[]")
            else:
                print("No catalog entries.")
        return ExitCode.OK
    if rt.mode.quiet:
        for item in items:
            print(item.alias)
    elif rt.mode.json:
        emit_json(items)
    else:
        print(
            table(
                ["alias", "risk_tier", "transport_class", "classification", "compartment"],
                [
                    (i.alias, i.risk_tier, i.transport_class, i.classification, i.compartment)
                    for i in items
                ],
            )
        )
    return ExitCode.OK


# ---------------------------------------------------------------------------
# authorize / complete
# ---------------------------------------------------------------------------


def cmd_authorize(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        if args.tool_call is not None:
            if args.alias is not None or args.arg:
                raise CLIConfigError(
                    "pass either ALIAS [--arg ...] or --tool-call, not both"
                )
            tool_call = load_document(args.tool_call)
            if not isinstance(tool_call, dict):
                raise CLIConfigError("--tool-call must be a JSON object")
            if args.vendor is not None:
                outcome = client.authorize(tool_call=tool_call, vendor=args.vendor)
            else:
                outcome = client.authorize(
                    tool_call=tool_call, source_format=args.format or envelopes.RAW_MCP
                )
        else:
            if args.alias is None:
                raise CLIConfigError("an ALIAS (or --tool-call) is required")
            outcome = client.authorize(
                args.alias, collect_args(args.arg), source_format=args.format
            )

        credential_out = getattr(args, "credential_out", None)
        if isinstance(outcome, Allowed):
            _render_receipt(rt, outcome, credential_out=credential_out)
            return ExitCode.OK

        # Staged (HTTP 202): persist the EXACT envelope, then step up inline or defer.
        _persist_staged(outcome)
        if has_interactive_otp(otp_stdin=args.otp_stdin, otp_prompt=args.otp_prompt):
            otp = resolve_otp(otp_stdin=args.otp_stdin, otp_prompt=args.otp_prompt)
            receipt = client.complete(outcome, otp)
            _discard_staged(outcome.challenge_id)
            _render_receipt(rt, receipt, credential_out=credential_out)
            return ExitCode.OK
        raise StepUpPending(outcome.challenge_id, outcome.correlation_id)


def cmd_complete(rt: Runtime, args: argparse.Namespace) -> int:
    staged = _load_staged(args.challenge)
    otp = resolve_otp(otp_stdin=args.otp_stdin, otp_prompt=args.otp_prompt)
    with rt.agent_client() as client:
        receipt = client.complete(staged, otp)
    _discard_staged(args.challenge)
    _render_receipt(rt, receipt, credential_out=getattr(args, "credential_out", None))
    return ExitCode.OK


def _render_receipt(
    rt: Runtime, receipt: Allowed, *, credential_out: str | None = None
) -> None:
    # A vended cloud credential is a real secret: it NEVER reaches stdout. If the
    # caller asked to capture it, write it to a 0600 O_EXCL file (the dev-token /
    # OTP pattern) and disclose only the path; stdout always sees a redaction.
    written_path: str | None = None
    if receipt.vended_credential is not None and credential_out is not None:
        write_secret_file(
            credential_out,
            json.dumps(receipt.vended_credential, sort_keys=True),
            exclusive=True,
        )
        written_path = credential_out

    if rt.mode.quiet:
        print(receipt.transaction_ref)
        return
    if rt.mode.json:
        emit_json(_receipt_json(receipt, written_path))
        return
    pairs: list[tuple[str, Any]] = [
        ("decision", receipt.decision),
        ("status", receipt.status),
        ("transaction_ref", receipt.transaction_ref),
        ("executed_target_class", receipt.executed_target_class),
        ("worm_sequence", receipt.worm_sequence),
        ("correlation_id", receipt.correlation_id),
    ]
    if receipt.vended_credential is not None:
        pairs.append(("vended_credential", _summarize_credential(receipt.vended_credential)))
        if written_path is not None:
            pairs.append(("credential_written_to", written_path))
    print(block(pairs))


def _receipt_json(receipt: Allowed, written_path: str | None = None) -> dict[str, Any]:
    """The receipt as JSON. The vended credential material is a real secret and is
    ALWAYS redacted from stdout (a pipe/CI/redirect is not a private sink); it is
    captured only via ``--credential-out FILE`` (O_EXCL 0600)."""
    payload: dict[str, Any] = dict(to_jsonable(receipt))
    if receipt.vended_credential is not None:
        if written_path is not None:
            payload["vended_credential"] = {"redacted": True, "written_to": written_path}
        else:
            payload["vended_credential"] = {
                "redacted": True,
                "reason": "vended credential withheld from stdout; capture it with "
                "`mcpip authorize --credential-out FILE` (O_EXCL 0600)",
            }
    return payload


def _summarize_credential(cred: dict[str, Any]) -> str:
    """A NON-SECRET one-line summary — key names and any expiry, never a value."""
    expiry = None
    for key in ("expiration", "expires_at", "expiry", "expires"):
        if isinstance(cred.get(key), (str, int, float)):
            expiry = cred[key]
            break
    fields = ", ".join(sorted(cred.keys()))
    return f"present (fields: {fields}; expiry: {expiry if expiry is not None else '-'})"


# ---------------------------------------------------------------------------
# staged step-up envelope persistence (0600, keyed by challenge_id)
# ---------------------------------------------------------------------------


def _staged_path(challenge_id: str) -> str:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in challenge_id)
    if not safe:
        raise CLIConfigError("empty challenge id")
    return os.path.join(staged_dir(), f"{safe}.json")


def _persist_staged(staged: Staged) -> None:
    record = {
        "challenge_id": staged.challenge_id,
        "correlation_id": staged.correlation_id,
        "risk_tier": staged.risk_tier,
        "action_required": staged.action_required,
        "tool_call": staged.envelope.tool_call,
        "source_format": staged.envelope.source_format,
        "vendor": staged.envelope.vendor,
    }
    write_secret_file(
        _staged_path(staged.challenge_id),
        json.dumps(record, sort_keys=True),
        exclusive=False,
    )


def _load_staged(challenge_id: str) -> Staged:
    path = _staged_path(challenge_id)
    if not os.path.exists(path):
        raise MCPIPNotFound(f"no staged challenge {challenge_id!r} on this machine")
    raw = json.loads(read_secret_file(path))
    envelope = AuthorizeEnvelope(
        tool_call=dict(raw.get("tool_call") or {}),
        source_format=raw.get("source_format"),
        vendor=raw.get("vendor"),
    )
    return Staged(
        correlation_id=str(raw.get("correlation_id", "")),
        action_required=str(raw.get("action_required", "")),
        challenge_id=str(raw.get("challenge_id", challenge_id)),
        risk_tier=str(raw.get("risk_tier", "pin_required")),
        envelope=envelope,
    )


def _discard_staged(challenge_id: str) -> None:
    try:
        os.remove(_staged_path(challenge_id))
    except (FileNotFoundError, CLIConfigError):
        pass


# ---------------------------------------------------------------------------
# decision (AuthZEN PDP verdict — decision-only)
# ---------------------------------------------------------------------------


def cmd_decision(rt: Runtime, args: argparse.Namespace) -> int:
    context = load_document(args.authz_context) if args.authz_context else None
    if context is not None and not isinstance(context, dict):
        raise CLIConfigError("--authz-context must be a JSON object")
    with rt.agent_client() as client:
        decision = client.authz_decision(
            args.alias,
            collect_args(args.arg),
            context=context,
            action_name=args.action,
        )
    emit_object(
        rt.mode,
        decision,
        block(
            [
                ("decision", decision.decision),
                ("obligations", decision.obligation_ids),
            ]
        ),
        quiet_id="permit" if decision.decision else "deny",
    )
    return ExitCode.OK


# ---------------------------------------------------------------------------
# MCP edge
# ---------------------------------------------------------------------------


def cmd_mcp_initialize(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        result = client.mcp_call("initialize")
    _emit_raw(rt, result)
    return ExitCode.OK


def cmd_mcp_tools_list(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        result = client.mcp_call("tools/list")
    if not rt.mode.json and isinstance(result, dict) and isinstance(result.get("tools"), list):
        tools = result["tools"]
        if not tools:
            print("No tools.")
            return ExitCode.OK
        print(
            table(
                ["name", "description"],
                [
                    (
                        t.get("name", "-") if isinstance(t, dict) else "-",
                        (t.get("description", "-") if isinstance(t, dict) else "-"),
                    )
                    for t in tools
                ],
            )
        )
        return ExitCode.OK
    _emit_raw(rt, result)
    return ExitCode.OK


def cmd_mcp_tools_call(rt: Runtime, args: argparse.Namespace) -> int:
    arguments = collect_args(args.arg)
    with rt.agent_client() as client:
        result = client.mcp_call(
            "tools/call", {"name": args.alias, "arguments": arguments}
        )
        if _is_step_up(result):
            staged_info = _mcp_step_up_challenge(result)
            challenge_id = str(staged_info.get("challenge_id", ""))
            correlation_id = str(staged_info.get("correlation_id", ""))
            # Completion resubmits the IDENTICAL JSON-RPC dict via /v1/authorize —
            # the payload lock is format-independent. Persist that exact envelope
            # so `mcpip complete --challenge <id>` can replay it byte-identically.
            jsonrpc = envelopes.mcp_tools_call(args.alias, arguments)
            staged = Staged(
                correlation_id=correlation_id,
                action_required=str(staged_info.get("action_required", "")),
                challenge_id=challenge_id,
                risk_tier=str(staged_info.get("risk_tier", "pin_required")),
                envelope=AuthorizeEnvelope(
                    tool_call=jsonrpc, source_format=envelopes.MCP_JSONRPC
                ),
            )
            _persist_staged(staged)
            if not has_interactive_otp(otp_stdin=args.otp_stdin, otp_prompt=False):
                raise StepUpPending(challenge_id, correlation_id)
            otp = resolve_otp(otp_stdin=args.otp_stdin, otp_prompt=False)
            receipt = client.complete(staged, otp)
            _discard_staged(challenge_id)
            _render_receipt(rt, receipt, credential_out=getattr(args, "credential_out", None))
            return ExitCode.OK
    _emit_raw(rt, result)
    return ExitCode.OK


def _is_step_up(result: Any) -> bool:
    return isinstance(result, dict) and bool(result.get("isError"))


def _mcp_step_up_challenge(result: dict[str, Any]) -> dict[str, Any]:
    """Extract the staged challenge JSON from an isError tools/call result."""
    content = result.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict) and isinstance(item.get("text"), str):
                try:
                    parsed = json.loads(item["text"])
                except ValueError:
                    continue
                if isinstance(parsed, dict) and parsed.get("challenge_id"):
                    return parsed
    # A structured MRT step-up carries requestState instead of a text challenge.
    if isinstance(result.get("requestState"), str):
        return {"challenge_id": result["requestState"], "correlation_id": ""}
    raise CLIConfigError("tools/call returned an unrecognized step-up result")


def _emit_raw(rt: Runtime, result: Any) -> None:
    if rt.mode.quiet:
        return
    if rt.mode.json:
        emit_json(result)
    elif isinstance(result, (dict, list)):
        print(json.dumps(to_jsonable(result), indent=2))
    else:
        print(result if result is not None else "-")


__all__ = [
    "cmd_catalog",
    "cmd_authorize",
    "cmd_complete",
    "cmd_decision",
    "cmd_mcp_initialize",
    "cmd_mcp_tools_list",
    "cmd_mcp_tools_call",
]
