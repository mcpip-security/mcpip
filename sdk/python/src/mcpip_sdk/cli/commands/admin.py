"""
mcpip_sdk.cli.commands.admin — the ``CAP_DIRECTORY_ADMIN`` control plane: skills,
community extensions, the live decision feed, forensic reconstruction, principals,
quarantine/canary rosters, directory, policy, workspace, cloud-env, and the vault.

Every handler wraps a :class:`~mcpip_sdk.admin.MCPIPAdminClient` method one-to-one.
Reads render honest empties (``No <resource>.`` / ``[]``), never an invented row;
a forensic miss is an honest ``None`` (exit 0), not a fabricated record; a deny is
the single opaque renderer everywhere.
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone
from typing import Any

from mcpip_sdk.admin import DECISION_FILTER_FIELDS, _reject_unknown_filter_field
from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.args import load_document
from mcpip_sdk.cli.auth import resolve_material
from mcpip_sdk.cli.errors import CLIConfigError, ExitCode
from mcpip_sdk.cli.render import block, emit_json, emit_object, table
from mcpip_sdk.errors import MCPIPUnavailable


# ---------------------------------------------------------------------------
# skills
# ---------------------------------------------------------------------------


def cmd_skills_ls(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        skills = client.skills_registered()
    if not skills:
        _empty(rt, "registered skills")
        return ExitCode.OK
    if rt.mode.quiet:
        for s in skills:
            print(s.alias)
    elif rt.mode.json:
        emit_json(skills)
    else:
        print(table(["alias", "registered_at"], [(s.alias, s.registered_at) for s in skills]))
    return ExitCode.OK


def cmd_skills_disabled(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        disabled = client.skills_disabled()
    _emit_str_list(rt, disabled, "disabled skills", "alias")
    return ExitCode.OK


def cmd_skills_register(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        alias = client.skills_register(
            args.alias, args.target, args.risk_tier, args.classification
        )
    emit_object(rt.mode, {"registered": alias}, block([("registered", alias)]), quiet_id=alias)
    return ExitCode.OK


def cmd_skills_deregister(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        removed = client.skills_deregister(args.alias)
    emit_object(rt.mode, {"removed": removed}, block([("removed", removed)]), quiet_id=args.alias)
    return ExitCode.OK


def cmd_skills_disable(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        alias = client.skills_disable(args.alias)
    emit_object(rt.mode, {"disabled": alias}, block([("disabled", alias)]), quiet_id=alias)
    return ExitCode.OK


def cmd_skills_enable(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        removed = client.skills_enable(args.alias)
    emit_object(rt.mode, {"removed": removed}, block([("removed", removed)]), quiet_id=args.alias)
    return ExitCode.OK


# ---------------------------------------------------------------------------
# community extensions
# ---------------------------------------------------------------------------


def cmd_extensions_submit(rt: Runtime, args: argparse.Namespace) -> int:
    manifest = load_document(args.manifest)
    if not isinstance(manifest, dict):
        raise CLIConfigError("--manifest must be a JSON object")
    with rt.admin_client() as client:
        submission_id = client.extension_submit(manifest)
    emit_object(
        rt.mode,
        {"submission_id": submission_id},
        block([("submission_id", submission_id)]),
        quiet_id=submission_id,
    )
    return ExitCode.OK


def cmd_extensions_pending(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        pending = client.extensions_pending()
    if not pending:
        _empty(rt, "pending extensions")
        return ExitCode.OK
    if rt.mode.quiet:
        for p in pending:
            print(p.submission_id)
    elif rt.mode.json:
        emit_json(pending)
    else:
        # `target` and `conflicts` are the two columns a review actually turns on,
        # and neither was here. The model has carried both all along and its own
        # docstring calls the target "a REVIEWER-only surface — it is the reviewer's
        # job to inspect it before approving", but the human table showed only the
        # alias, so a benign `skill_reports -> rest.reports.read` and an attempted
        # hijack `skill_reports -> attacker.example.com` rendered as identical rows.
        # The detail was reachable only via --json, which is not what a person
        # reviewing a queue types. Nothing new is disclosed: this surface is
        # CAP_CATALOG_REVIEWER-gated and the target never crosses the agent wire.
        print(
            table(
                [
                    "submission_id",
                    "kind",
                    "alias/gate",
                    "target",
                    "risk_tier",
                    "conflicts",
                    "approvable",
                ],
                [
                    (
                        p.submission_id,
                        p.kind,
                        (p.alias if p.kind == "skill" else p.gate_id) or "-",
                        p.target or "-",
                        p.risk_tier or "-",
                        # An approve would be refused additive-only, so this row is
                        # either a mistake or a hijack attempt. Loud on purpose.
                        "YES" if p.conflicts_existing_alias else "-",
                        p.approvable,
                    )
                    for p in pending
                ],
            )
        )
    return ExitCode.OK


def cmd_extensions_approve(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        alias = client.extension_approve(args.submission_id)
    emit_object(rt.mode, {"approved": alias}, block([("approved", alias)]), quiet_id=alias)
    return ExitCode.OK


def cmd_extensions_reject(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        rejected = client.extension_reject(args.submission_id)
    emit_object(rt.mode, {"rejected": rejected}, block([("rejected", rejected)]), quiet_id=rejected)
    return ExitCode.OK


# ---------------------------------------------------------------------------
# registry governance (verified-publisher allow-list, X3)
# ---------------------------------------------------------------------------


def cmd_publishers_get(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        publishers = client.verified_publishers_get()
    if rt.mode.json:
        emit_json(publishers)
        return ExitCode.OK
    if rt.mode.quiet:
        for ns in publishers.namespaces:
            print(ns)
        return ExitCode.OK
    if not publishers.namespaces:
        print(f"schema : {publishers.schema}\nNo verified publishers (nothing registry-sourced can be approved).")
        return ExitCode.OK
    print(f"schema : {publishers.schema}")
    print(table(["namespace"], [(ns,) for ns in publishers.namespaces]))
    return ExitCode.OK


def cmd_publishers_set(rt: Runtime, args: argparse.Namespace) -> int:
    # Namespaces enter via --namespace (repeatable) or --file (a JSON list, or a
    # {schema, namespaces} document); the whole set is REPLACED (not merged).
    namespaces: list[str]
    if args.file:
        document = load_document(args.file)
        if isinstance(document, dict):
            raw = document.get("namespaces")
        else:
            raw = document
        if not isinstance(raw, list) or not all(isinstance(n, str) for n in raw):
            raise CLIConfigError("--file must be a JSON list of namespaces (or a {namespaces:[...]} document)")
        namespaces = list(raw)
    else:
        namespaces = list(args.namespace or [])
    with rt.admin_client() as client:
        client.verified_publishers_put(namespaces)
    emit_object(
        rt.mode,
        {"ok": True, "count": len(namespaces)},
        block([("ok", True), ("count", len(namespaces))]),
        quiet_id="true",
    )
    return ExitCode.OK


# ---------------------------------------------------------------------------
# compliance evidence (portable bundle, X1)
# ---------------------------------------------------------------------------


def cmd_compliance_evidence(rt: Runtime, args: argparse.Namespace) -> int:
    """Export the portable compliance-EVIDENCE bundle. The full signed bundle is
    the deliverable — default to JSON (an auditor/verifier hands it on); the human
    view is a faithful, honest summary that never claims a certification."""
    with rt.admin_client() as client:
        evidence = client.compliance_evidence()
    # The full bundle is the artifact — emit it verbatim for --json / redirection.
    if rt.mode.json:
        emit_json(evidence)
        return ExitCode.OK
    if rt.mode.quiet:
        # Load-bearing id: the signing key the epoch signature binds to.
        print(evidence.attestation.signing_key_id)
        return ExitCode.OK
    att = evidence.attestation
    print(
        block(
            [
                ("generated_at", evidence.generated_at),
                ("gateway_version", evidence.gateway_version),
                ("release.version", evidence.release.version),
                ("release.verified", evidence.release.verified),
                ("sealed", evidence.sealed),
                ("chain_intact", att.intact),
                ("first_bad_epoch", att.first_bad_epoch),
                ("sealed_epoch", att.epoch),
                ("signing_key_id", att.signing_key_id),
                ("merkle_root", att.merkle_root),
                ("frameworks", tuple(f.framework for f in evidence.control_mapping)),
            ]
        )
    )
    if evidence.empty_state_note is not None:
        print(f"\n{evidence.empty_state_note}")
    # Always restate the honesty invariant on the human path — evidence != cert.
    print(f"\nEVIDENCE, NOT A CERTIFICATION.\n{evidence.disclaimer}")
    print("\nRun with --json to export the full signed bundle for an external verifier.")
    return ExitCode.OK


# ---------------------------------------------------------------------------
# deployment / license & usage stats (local live numbers)
# ---------------------------------------------------------------------------


def cmd_stats(rt: Runtime, args: argparse.Namespace) -> int:
    """The LOCAL live deployment stats — the caller's OWN tenant's REAL running
    numbers (governed-agent identity cardinality + allow/deny/staged totals), the
    boot-verified license posture, and the HONEST opt-in vendor-telemetry state
    (enabled / disabled / air-gap + last-sent). Served locally — no beacon, no vendor,
    no network. Never fabricates a client, number, license, or 'connected' status; a
    fresh tenant shows honest zeros and an air-gapped/sandbox deployment shows
    ``air-gap`` (it never phones home)."""
    with rt.admin_client() as client:
        stats = client.stats()
    if rt.mode.json:
        emit_json(stats)
        return ExitCode.OK
    if rt.mode.quiet:
        # Load-bearing number: the governed-agent identity cardinality (the value metric).
        print(stats.governed_agent_identity_count)
        return ExitCode.OK
    lic = stats.license
    tel = stats.telemetry
    feats = stats.features
    if feats is None:
        # The gateway reported no features block (older gateway) — honest UNKNOWN, never
        # a fabricated "off".
        forensic_line = "unknown (gateway did not report a features posture)"
        external_pdp_line = "unknown"
    else:
        forensic_status = feats.forensic_capture
        forensic_line = (
            forensic_status.status
            if forensic_status.reason is None
            else f"{forensic_status.status} ({forensic_status.reason})"
        )
        external_pdp_line = feats.external_pdp.status
    license_line = (
        f"{lic.tier or 'licensed'} ({lic.license_id or '-'})"
        if lic.licensed
        else "unlicensed"
    )
    last_sent = (
        datetime.fromtimestamp(tel.last_sent, tz=timezone.utc).isoformat(
            timespec="seconds"
        )
        if tel.last_sent is not None
        else "never"
    )
    print(
        block(
            [
                ("version", stats.version),
                ("governed_agent_identities", stats.governed_agent_identity_count),
                ("decisions.allow", stats.decisions.allow),
                ("decisions.deny", stats.decisions.deny),
                ("decisions.staged", stats.decisions.staged),
                ("license", license_line),
                ("license.expires_at", lic.expires_at or "-"),
                ("telemetry", tel.status),
                ("telemetry.last_sent", last_sent),
                ("telemetry.last_result", tel.last_result),
                ("forensic_capture", forensic_line),
                ("external_pdp", external_pdp_line),
            ]
        )
    )
    return ExitCode.OK


# ---------------------------------------------------------------------------
# decision feed (+ --watch)
# ---------------------------------------------------------------------------


def cmd_decisions(rt: Runtime, args: argparse.Namespace) -> int:
    if args.watch:
        return _watch_decisions(rt, args)
    with rt.admin_client() as client:
        decisions = client.decisions_recent(limit=args.limit)
    if not decisions:
        _empty(rt, "decisions")
        return ExitCode.OK
    if rt.mode.quiet:
        for d in decisions:
            print(d.correlation_id)
    elif rt.mode.json:
        emit_json(decisions)
    else:
        print(_decisions_table(decisions))
    return ExitCode.OK


def _watch_decisions(rt: Runtime, args: argparse.Namespace) -> int:
    """Poll the feed politely; print only NEW rows; never fabricate a row during
    a blip — a transport error surfaces as unavailable (exit 4)."""
    seen: set[str] = set()
    interval = max(0.5, args.interval)
    try:
        with rt.admin_client() as client:
            while True:
                try:
                    decisions = client.decisions_recent(limit=args.limit)
                except MCPIPUnavailable:
                    raise  # exit 4 — honest, never a silent empty tail.
                fresh = [
                    d
                    for d in reversed(decisions)
                    if (d.correlation_id or str(d.worm_sequence)) not in seen
                ]
                for d in fresh:
                    seen.add(d.correlation_id or str(d.worm_sequence))
                    if rt.mode.json:
                        emit_json(d)
                    else:
                        print(_decisions_table([d], header=False))
                time.sleep(interval)
    except KeyboardInterrupt:
        return ExitCode.OK


def _decisions_table(decisions: list[Any], *, header: bool = True) -> str:
    rows = [
        (d.decision, d.alias, d.deny_reason, d.risk_tier, d.worm_sequence, d.correlation_id)
        for d in decisions
    ]
    if not header:
        # single-row append during --watch: reuse the table renderer then drop
        # its header line so the stream stays flat.
        rendered = table(
            ["decision", "alias", "deny_reason", "risk_tier", "worm_seq", "correlation_id"], rows
        )
        return rendered.split("\n", 1)[1] if "\n" in rendered else rendered
    return table(
        ["decision", "alias", "deny_reason", "risk_tier", "worm_seq", "correlation_id"], rows
    )


def _parse_decision_filters(pairs: list[str] | None) -> dict[str, str]:
    """``--filter key=value`` pairs → the endpoint's comma-joined facet map.

    Repeating a key ORs its values (``--filter decision=allow --filter
    decision=deny`` → ``decision=allow,deny``); a value may itself be comma-
    separated.

    Both failure modes are LOUD, and that is the whole point. A malformed pair
    used to be dropped and an unknown key used to be forwarded; the gateway
    ignores query parameters outside its whitelist, so ``--filter agentid=x``
    printed *every* row in the window with exit 0 and no warning. An operator
    filtering an audit to one agent silently got the whole tenant — the answer
    was not merely wrong, it looked authoritative.
    """
    filters: dict[str, str] = {}
    for pair in pairs or []:
        key, sep, value = pair.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key or not value:
            raise CLIConfigError(
                f"--filter expects KEY=VALUE with both sides non-empty; got {pair!r}"
            )
        try:
            _reject_unknown_filter_field(key)
        except ValueError as exc:
            raise CLIConfigError(str(exc)) from None
        filters[key] = f"{filters[key]},{value}" if key in filters else value
    return filters


def cmd_decisions_history(rt: Runtime, args: argparse.Namespace) -> int:
    """Date-ranged, multi-filtered, cursor-paged decision HISTORY (at scale).

    ``--all`` walks the whole window (the "export all" primitive; pipe ``--json``
    to a file); otherwise one page prints and, in human mode, a resume hint for
    ``--cursor`` goes to stderr so machine output stays clean."""
    filters = _parse_decision_filters(getattr(args, "filter", None))
    next_cursor: str | None = None
    with rt.admin_client() as client:
        if args.all:
            rows = list(
                client.decisions_iter(
                    from_ms=args.from_ms,
                    to_ms=args.to_ms,
                    filters=filters or None,
                    page_limit=args.limit,
                )
            )
        else:
            page = client.decisions_query(
                from_ms=args.from_ms,
                to_ms=args.to_ms,
                cursor=args.cursor,
                limit=args.limit,
                filters=filters or None,
            )
            rows = list(page.decisions)
            next_cursor = page.next_cursor
    if not rows:
        _empty(rt, "decisions")
        return ExitCode.OK
    if rt.mode.quiet:
        for d in rows:
            print(d.correlation_id)
    elif rt.mode.json:
        emit_json(rows)
    else:
        print(_decisions_table(rows))
        if next_cursor is not None:
            print(f"more rows — resume with: --cursor {next_cursor}", file=sys.stderr)
    return ExitCode.OK


# ---------------------------------------------------------------------------
# forensic
# ---------------------------------------------------------------------------


def cmd_forensic_get(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        payload = client.forensic_get(args.correlation_id)
    if payload is None:
        # Honest, opaque miss — a real answer (exit 0), never a fabricated record.
        if rt.mode.quiet:
            return ExitCode.OK
        if rt.mode.json:
            print("null")
        else:
            print("not found")
        return ExitCode.OK
    emit_object(
        rt.mode,
        payload,
        block(
            [
                ("correlation_id", payload.correlation_id),
                ("tenant_id", payload.tenant_id),
                ("agent_id", payload.agent_id),
                ("role", payload.role),
                ("alias", payload.alias),
                ("source_format", payload.source_format),
                ("decision", payload.decision),
                ("deny_reason", payload.deny_reason),
                ("arguments", payload.arguments),
            ]
        ),
        quiet_id=payload.correlation_id,
    )
    return ExitCode.OK


# ---------------------------------------------------------------------------
# operator/team users (email-keyed roster, CAP_DIRECTORY_ADMIN)
# ---------------------------------------------------------------------------


def cmd_users_ls(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        page = client.users_list(cursor=args.cursor, limit=args.limit)
    if rt.mode.json:
        emit_json(page)
        return ExitCode.OK
    if rt.mode.quiet:
        for u in page.users:
            print(u.email)
        return ExitCode.OK
    if not page.users:
        print("No operator users yet. Invite one:  mcpip admin users invite <email>")
        return ExitCode.OK
    print(
        table(
            ["email", "role", "status", "invited_by"],
            [(u.email, u.role, u.status, u.invited_by) for u in page.users],
        )
    )
    if page.next_cursor != "0":
        print(f"\n(more — re-run with --cursor {page.next_cursor})")
    return ExitCode.OK


def cmd_users_invite(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        result = client.users_invite(args.email, role=args.role)
    u = result.user
    # The invite token is the ONLY sensitive field — surfaced once for the admin to
    # send, exactly as the gateway returns it (a reference, not a credential).
    emit_object(
        rt.mode,
        {
            "email": u.email,
            "role": u.role,
            "status": u.status,
            "invite_token": result.invite_token,
        },
        block(
            [
                ("email", u.email),
                ("role", u.role),
                ("status", u.status),
                ("invite_token", result.invite_token),
            ]
        ),
        quiet_id=result.invite_token,
    )
    return ExitCode.OK


def cmd_users_update(rt: Runtime, args: argparse.Namespace) -> int:
    if args.role is None and args.status is None:
        raise CLIConfigError("provide --role and/or --status")
    with rt.admin_client() as client:
        u = client.users_update(args.email, role=args.role, status=args.status)
    emit_object(
        rt.mode,
        {"email": u.email, "role": u.role, "status": u.status},
        block([("email", u.email), ("role", u.role), ("status", u.status)]),
        quiet_id=u.email,
    )
    return ExitCode.OK


def cmd_users_remove(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        removed = client.users_remove(args.email)
    emit_object(
        rt.mode,
        {"removed": removed},
        block([("removed", removed)]),
        quiet_id="true" if removed else "false",
    )
    return ExitCode.OK


# ---------------------------------------------------------------------------
# principals
# ---------------------------------------------------------------------------


def cmd_principals_ls(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        revoked = client.principals_revoked()
    _emit_str_list(rt, revoked, "revoked principals", "agent_id")
    return ExitCode.OK


def cmd_principals_revoke(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        agent = client.principals_revoke(args.agent_id, args.reason)
    emit_object(rt.mode, {"revoked": agent}, block([("revoked", agent)]), quiet_id=agent)
    return ExitCode.OK


def cmd_principals_reactivate(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        removed = client.principals_reactivate(args.agent_id)
    emit_object(rt.mode, {"removed": removed}, block([("removed", removed)]), quiet_id=args.agent_id)
    return ExitCode.OK


# ---------------------------------------------------------------------------
# rosters
# ---------------------------------------------------------------------------


def cmd_quarantine(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        rows = client.quarantine()
    if not rows:
        _empty(rt, "quarantined agents")
        return ExitCode.OK
    if rt.mode.quiet:
        for r in rows:
            print(r.agent_id)
    elif rt.mode.json:
        emit_json(rows)
    else:
        # `tripped_alias` is the column an operator actually triages on: one agent
        # frozen on one alias is a mistake, five agents frozen on five different
        # decoys is an enumeration sweep, and the roster is where that shape shows
        # up first. `correlation_id` is carried so `mcpip why <id>` and the WORM
        # lookup are a copy-paste away rather than a separate hunt.
        print(
            table(
                ["agent_id", "ttl_seconds", "tripped_alias", "correlation_id"],
                [
                    (
                        r.agent_id,
                        r.ttl_seconds,
                        r.tripped_alias or "-",
                        r.correlation_id or "-",
                    )
                    for r in rows
                ],
            )
        )
    return ExitCode.OK


def cmd_canaries(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        rows = client.canaries()
    if not rows:
        _empty(rt, "canaries")
        return ExitCode.OK
    if rt.mode.quiet:
        for r in rows:
            print(r.alias)
    elif rt.mode.json:
        emit_json(rows)
    else:
        print(
            table(
                ["alias", "risk_tier", "classification"],
                [(r.alias, r.risk_tier, r.classification) for r in rows],
            )
        )
    return ExitCode.OK


# ---------------------------------------------------------------------------
# directory
# ---------------------------------------------------------------------------


def cmd_directory_get(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        document = client.directory_get()
    if document is None:
        if not rt.mode.quiet:
            print("null" if rt.mode.json else "No directory document.")
        return ExitCode.OK
    if rt.mode.json:
        emit_json(document)
    else:
        emit_json(document)  # a directory doc is arbitrary JSON — pretty-print it.
    return ExitCode.OK


def cmd_directory_put(rt: Runtime, args: argparse.Namespace) -> int:
    document = load_document(args.file)
    if not isinstance(document, dict):
        raise CLIConfigError("--file must be a JSON object")
    with rt.admin_client() as client:
        client.directory_put(document)
    if not rt.mode.quiet:
        emit_object(rt.mode, {"ok": True}, block([("ok", True)]))
    return ExitCode.OK


def cmd_directory_relations(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        result = client.directory_relations(
            subject=args.subject, relation=args.relation, object_uuid=args.object_uuid
        )
    if rt.mode.json:
        emit_json(result)
        return ExitCode.OK
    if not result.relations:
        print("No relations.")
    else:
        print(
            table(
                ["subject", "relation", "object", "grant_id"],
                [(e.subject, e.relation, e.object_uuid, e.grant_id) for e in result.relations],
            )
        )
    if result.allowed is not None:
        print(f"\nallowed : {'true' if result.allowed else 'false'}")
    return ExitCode.OK


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


def cmd_policy_get(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        document = client.policy_get()
    if rt.mode.json:
        emit_json(document)
        return ExitCode.OK
    if not document.rules:
        print(f"schema : {document.schema}\nNo policy rules (no limits — opt-in).")
        return ExitCode.OK
    print(f"schema : {document.schema}")
    print(
        table(
            ["kind", "scope", "scope_value", "max_actions", "window_s", "amount_field", "max_amount"],
            [
                (r.kind, r.scope, r.scope_value, r.max_actions, r.window_seconds, r.amount_field, r.max_amount)
                for r in document.rules
            ],
        )
    )
    return ExitCode.OK


def cmd_policy_put(rt: Runtime, args: argparse.Namespace) -> int:
    document = load_document(args.file)
    if not isinstance(document, dict):
        raise CLIConfigError("--file must be a JSON object")
    with rt.admin_client() as client:
        client.policy_put(document)
    if not rt.mode.quiet:
        emit_object(rt.mode, {"ok": True}, block([("ok", True)]))
    return ExitCode.OK


def cmd_policy_delete(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        ok = client.policy_delete()
    emit_object(rt.mode, {"ok": ok}, block([("ok", ok)]), quiet_id="true" if ok else "false")
    return ExitCode.OK


# ---------------------------------------------------------------------------
# workspace
# ---------------------------------------------------------------------------


def cmd_workspace_draft(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        draft = client.workspace_draft(
            brief=args.brief, company=args.company, tenant=args.tenant
        )
    # The plan JSON is the deliverable — emit it for review (stdout or redirect).
    emit_json({"plan": draft.plan, "summary": _summary(draft.summary)})
    return ExitCode.OK


def cmd_workspace_validate(rt: Runtime, args: argparse.Namespace) -> int:
    plan = _plan_from_file(args.file)
    with rt.admin_client() as client:
        result = client.workspace_validate(plan)
    emit_object(
        rt.mode,
        result,
        block(
            [
                ("ok", result.ok),
                ("errors", result.errors),
                ("warnings", result.warnings),
                ("summary", _summary(result.summary)),
            ]
        ),
        quiet_id="true" if result.ok else "false",
    )
    return ExitCode.OK if result.ok else ExitCode.INVALID_REQUEST


def cmd_workspace_apply(rt: Runtime, args: argparse.Namespace) -> int:
    plan = _plan_from_file(args.file)
    with rt.admin_client() as client:
        result = client.workspace_apply(plan)
    emit_object(
        rt.mode,
        result,
        block(
            [
                ("applied", result.applied),
                ("created", result.created),
                ("skipped", result.skipped),
                ("summary", _summary(result.summary)),
            ]
        ),
        quiet_id="true" if result.applied else "false",
    )
    return ExitCode.OK


def _plan_from_file(spec: str) -> dict[str, Any]:
    document = load_document(spec)
    # Accept either a bare plan or a {"plan": ...} wrapper (as `workspace draft` emits).
    if isinstance(document, dict) and "plan" in document and isinstance(document["plan"], dict):
        return document["plan"]
    if not isinstance(document, dict):
        raise CLIConfigError("--file must be a JSON object (a workspace plan)")
    return document


def _summary(summary: Any) -> str:
    return f"org_units={summary.org_units} teams={summary.teams} skills={summary.skills}"


# ---------------------------------------------------------------------------
# cloud-env
# ---------------------------------------------------------------------------


def cmd_cloud_env_ls(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        envs = client.cloud_environments_list()
    if not envs:
        _empty(rt, "cloud environments")
        return ExitCode.OK
    if rt.mode.quiet:
        for e in envs:
            print(e.env_id)
    elif rt.mode.json:
        emit_json(envs)
    else:
        print(
            table(
                ["env_id", "provider", "role", "region", "session_ttl", "vault_secret_id"],
                [
                    (e.env_id, e.provider, e.role, e.region, e.session_ttl, e.vault_secret_id)
                    for e in envs
                ],
            )
        )
    return ExitCode.OK


def cmd_cloud_env_put(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        env = client.cloud_environments_put(
            args.env_id,
            args.provider,
            args.role,
            args.region,
            compartment=args.compartment,
            session_ttl=args.session_ttl,
            vault_secret_id=args.vault_secret_id,
        )
    emit_object(
        rt.mode,
        env,
        block(
            [
                ("env_id", env.env_id),
                ("provider", env.provider),
                ("role", env.role),
                ("region", env.region),
                ("session_ttl", env.session_ttl),
                ("vault_secret_id", env.vault_secret_id),
            ]
        ),
        quiet_id=env.env_id,
    )
    return ExitCode.OK


def cmd_cloud_env_rm(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        removed = client.cloud_environments_delete(args.env_id)
    emit_object(rt.mode, {"removed": removed}, block([("removed", removed)]), quiet_id=args.env_id)
    return ExitCode.OK


# ---------------------------------------------------------------------------
# vault (write-only values)
# ---------------------------------------------------------------------------


def cmd_vault_ls(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        listing = client.vault_secrets_list()
    if rt.mode.json:
        emit_json(listing)
        return ExitCode.OK
    if not listing.secrets:
        print(f"vault_enabled : {'true' if listing.vault_enabled else 'false'}\nNo secrets.")
        return ExitCode.OK
    print(f"vault_enabled : {'true' if listing.vault_enabled else 'false'}")
    print(
        table(
            ["secret_id", "vendor", "fingerprint", "description"],
            [(s.secret_id, s.vendor, s.fingerprint, s.description) for s in listing.secrets],
        )
    )
    return ExitCode.OK


def cmd_vault_put(rt: Runtime, args: argparse.Namespace) -> int:
    # Secret material enters ONLY via file/stdin — never --arg/argv.
    material = resolve_material(
        material_file=args.material_file, material_stdin=args.material_stdin
    )
    with rt.admin_client() as client:
        secret = client.vault_secrets_put(
            args.secret_id, args.vendor, material, description=args.description
        )
    emit_object(
        rt.mode,
        secret,
        block(
            [
                ("secret_id", secret.secret_id),
                ("vendor", secret.vendor),
                ("fingerprint", secret.fingerprint),
                ("description", secret.description),
            ]
        ),
        quiet_id=secret.secret_id,
    )
    return ExitCode.OK


def cmd_vault_rm(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.admin_client() as client:
        removed = client.vault_secrets_delete(args.secret_id)
    emit_object(rt.mode, {"removed": removed}, block([("removed", removed)]), quiet_id=args.secret_id)
    return ExitCode.OK


# ---------------------------------------------------------------------------
# shared helpers
# ---------------------------------------------------------------------------


def _empty(rt: Runtime, resource: str) -> None:
    if rt.mode.quiet:
        return
    if rt.mode.json:
        print("[]")
    else:
        print(f"No {resource}.")


def _emit_str_list(rt: Runtime, values: list[str], resource: str, header: str) -> None:
    if not values:
        _empty(rt, resource)
        return
    if rt.mode.quiet:
        for v in values:
            print(v)
    elif rt.mode.json:
        emit_json(values)
    else:
        print(table([header], [(v,) for v in values]))


__all__ = [name for name in dir() if name.startswith("cmd_")]
