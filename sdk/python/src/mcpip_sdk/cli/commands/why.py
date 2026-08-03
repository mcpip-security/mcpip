"""
mcpip_sdk.cli.commands.why — turn an opaque correlation id into the next action.

`mcpip why <correlation_id>` is the operator/developer counterpart to the agent
boundary's deliberate silence. It changes nothing about that boundary: it reads
the two surfaces that were already capability-gated and audited, and renders what
they return in a form a person can act on.

Two sources, tried in order, because they fail in different ways:

1. ``GET /v1/admin/forensic/{id}`` (``CAP_FORENSIC_READ``) — carries the deny
   reason AND the real arguments, which is usually what makes a malformed-payload
   deny obvious. Returns an honest miss when capture is off, the TTL has passed,
   or the id belongs to another tenant.
2. ``GET /v1/admin/decisions`` filtered to the id (``CAP_DIRECTORY_ADMIN``) — the
   whitelist projection. No arguments, but the deny reason is there, and this
   works on a gateway with forensic capture disabled.

If neither answers, the command says so and names the reason it could not tell.
It never infers a deny reason it did not read.
"""

from __future__ import annotations

import argparse

from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.diagnose import explain, family_of
from mcpip_sdk.cli.errors import ExitCode
from mcpip_sdk.cli.render import emit_json
from mcpip_sdk.errors import MCPIPDenied


def _lookup(rt: Runtime, correlation_id: str) -> tuple[dict[str, object], list[str]]:
    """Read the decision from whichever surface answers. Returns (record, notes)."""
    record: dict[str, object] = {}
    notes: list[str] = []

    with rt.admin_client() as client:
        try:
            payload = client.forensic_get(correlation_id)
        except MCPIPDenied:
            payload = None
            notes.append(
                "forensic read denied — this token does not carry CAP_FORENSIC_READ "
                "(which is distinct from CAP_DIRECTORY_ADMIN)"
            )
        if payload is not None:
            record = {
                "correlation_id": payload.correlation_id,
                "decision": payload.decision,
                "deny_reason": payload.deny_reason,
                "alias": payload.alias,
                "agent_id": payload.agent_id,
                "source_format": payload.source_format,
                "arguments": payload.arguments,
                "source": "forensic",
            }
            return record, notes

        if not notes:
            notes.append(
                "no forensic capture for this id — it may be disabled on this gateway, "
                "past its TTL, or owned by another tenant"
            )

        # Fall back to the decision projection: no arguments, but the reason is there.
        try:
            page = client.decisions_query(
                filters={"correlation_id": correlation_id}, limit=1
            )
        except MCPIPDenied:
            notes.append(
                "decision history denied — this token does not carry CAP_DIRECTORY_ADMIN"
            )
            return record, notes

        rows = list(page.decisions)
        if not rows:
            notes.append(
                "no decision found for this id — check the id, or the retention horizon "
                "(`mcpip admin` reports it) if the call is older than the hot buffer"
            )
            return record, notes

        row = rows[0]
        record = {
            "correlation_id": row.correlation_id,
            "decision": row.decision,
            "deny_reason": row.deny_reason,
            "alias": row.alias,
            "agent_id": row.agent_id,
            "source_format": row.source_format,
            "arguments": None,
            "source": "decisions",
        }
        return record, notes


def cmd_why(rt: Runtime, args: argparse.Namespace) -> int:
    record, notes = _lookup(rt, args.correlation_id)
    reason = record.get("deny_reason")
    remedy = explain(reason if isinstance(reason, str) else None)
    family = family_of(reason if isinstance(reason, str) else None)

    if rt.mode.json:
        # A STABLE shape: the same keys whether or not a decision was found, so a
        # script can read `.deny_reason` without first testing for the key. An
        # unread decision is null everywhere, with `notes` carrying why.
        emit_json(
            {
                "correlation_id": record.get("correlation_id") or args.correlation_id,
                "decision": record.get("decision"),
                "deny_reason": record.get("deny_reason"),
                "alias": record.get("alias"),
                "agent_id": record.get("agent_id"),
                "source_format": record.get("source_format"),
                "arguments": record.get("arguments"),
                "source": record.get("source"),
                "family": family,
                "means": remedy.means if remedy else None,
                "fix": remedy.fix if remedy else None,
                "notes": notes,
            }
        )
        return ExitCode.OK if record else ExitCode.NOT_FOUND

    if rt.mode.quiet:
        if isinstance(reason, str):
            print(reason)
            return ExitCode.OK
        return ExitCode.NOT_FOUND

    if not record:
        print(f"Could not read a decision for {args.correlation_id}.")
        for note in notes:
            print(f"  - {note}")
        print(
            "\nThe agent-facing wire is opaque by design, so the reason only ever lives "
            "in the audit log. Reading it needs a credential."
        )
        return ExitCode.NOT_FOUND

    decision = str(record.get("decision") or "unknown")
    print(f"{args.correlation_id}  {decision.upper()}")
    if record.get("alias"):
        print(f"  alias          {record['alias']}")
    if record.get("agent_id"):
        print(f"  agent          {record['agent_id']}")
    if record.get("source_format"):
        print(f"  format         {record['source_format']}")

    if decision == "allow":
        print("\nThis call was authorized. Nothing to fix.")
        return ExitCode.OK

    if not isinstance(reason, str):
        print("\nDenied, but this gateway recorded no reason for it.")
        for note in notes:
            print(f"  - {note}")
        return ExitCode.OK

    print(f"  reason         {reason}" + (f"  ({family})" if family else ""))
    if record.get("arguments") is not None:
        print(f"  arguments      {record['arguments']}")

    if remedy is None:
        # A reason this CLI does not know about — report it plainly rather than
        # inventing guidance for it.
        print(
            f"\nThis CLI has no guidance for '{reason}'. It is a real reason from the "
            "audit log; check the gateway's release notes if it is newer than this CLI."
        )
        return ExitCode.OK

    print(f"\n{remedy.means}\n\n  Fix: {remedy.fix}")
    for note in notes:
        print(f"\n  note: {note}")
    return ExitCode.OK
