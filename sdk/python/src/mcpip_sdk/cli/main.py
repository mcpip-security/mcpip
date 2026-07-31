"""
mcpip_sdk.cli.main — the ``mcpip`` root parser, the subcommand tree, and the
single dispatch + exception→exit-code mapping.

Stdlib argparse only (httpx stays the SDK's ONE runtime dependency). Global
options are attached with ``argparse.SUPPRESS`` defaults to a shared parent so
they may appear before OR after the subcommand without a later default clobbering
an earlier value — the kubectl/gh ergonomics without a third-party parser.
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Callable, Sequence

from mcpip_sdk import __version__ as _sdk_version
from mcpip_sdk.cli import config as cfg
from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.errors import CLIConfigError, ExitCode, map_exception
from mcpip_sdk.cli.render import OutputMode, render_error
from mcpip_sdk.cli.commands import admin, agent, connect, reads, sandbox, up

_S = argparse.SUPPRESS
Handler = Callable[[Runtime, argparse.Namespace], int]


def _client_version() -> str:
    return f"mcpip {_sdk_version} (mcpip_sdk {_sdk_version})"


def _add_global(parser: argparse.ArgumentParser) -> None:
    """Attach the global options (SUPPRESS defaults) to a parser."""
    g = parser.add_argument_group("global options")
    g.add_argument("--gateway", metavar="URL", default=_S, help="gateway base URL")
    g.add_argument("--context", metavar="NAME", default=_S, help="named context to use")
    g.add_argument(
        "--sandbox",
        action=argparse.BooleanOptionalAction,
        default=_S,
        help="treat the gateway as a sandbox (--no-sandbox to force off)",
    )
    g.add_argument("--config", metavar="PATH", default=_S, help="alternate config file")
    g.add_argument(
        "--token-file", metavar="PATH", default=_S, help="read the bearer from a 0600 file"
    )
    g.add_argument(
        "--token-stdin", action="store_true", default=_S, help="read the bearer from stdin"
    )
    g.add_argument(
        "--token-cmd", metavar="CMD", default=_S, help="run CMD; its stdout is the bearer"
    )
    g.add_argument("--json", action="store_true", default=_S, help="emit JSON")
    g.add_argument(
        "--quiet", "-q", action="store_true", default=_S, help="print only load-bearing ids"
    )
    g.add_argument("--no-color", action="store_true", default=_S, help="disable colored output")


def _leaf(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    name: str,
    func: Handler,
    *,
    help: str,
    needs_resolve: bool = True,
    parent: argparse.ArgumentParser,
) -> argparse.ArgumentParser:
    p = subparsers.add_parser(name, help=help, parents=[parent], description=help)
    p.set_defaults(func=func, _needs_resolve=needs_resolve)
    return p


def _otp_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--otp-stdin", action="store_true", default=False, help="read the OTP from stdin")
    p.add_argument(
        "--otp-prompt", action="store_true", default=False, help="force an interactive OTP prompt"
    )


def build_parser() -> argparse.ArgumentParser:
    parent = argparse.ArgumentParser(add_help=False)
    _add_global(parent)

    root = argparse.ArgumentParser(
        prog="mcpip",
        description="MCPIP — authorize every AI action before execution. "
        "Local sandbox in one command: mcpip up. "
        "Zero-to-authorized in three commands: login, sandbox dev-token, authorize.",
        parents=[parent],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    root.add_argument(
        "--version",
        action="version",
        version=_client_version(),
        help="print the CLI + SDK version and exit (no gateway call)",
    )
    sub = root.add_subparsers(dest="_group", metavar="<command>", required=True)

    _build_up(sub, parent)
    _build_connect(sub, parent)
    _build_agent(sub, parent)
    _build_reads(sub, parent)
    _build_sandbox(sub, parent)
    _build_admin(sub, parent)

    return root


# ---------------------------------------------------------------------------
# up: the one blessed front door (local sandbox stack)
# ---------------------------------------------------------------------------


def _build_up(sub: argparse._SubParsersAction[argparse.ArgumentParser], parent: argparse.ArgumentParser) -> None:
    p = _leaf(
        sub,
        "up",
        up.cmd_up,
        help="boot the local sandbox stack — Redis + gateway + live walkthrough, one command",
        needs_resolve=False,
        parent=parent,
    )
    p.add_argument(
        "--repo",
        metavar="PATH",
        default=None,
        help="path to an MCPIP checkout (default: auto-detect from the current directory upward)",
    )
    p.add_argument(
        "--print-only",
        action="store_true",
        default=False,
        help="print what would run without starting anything",
    )
    p.add_argument(
        "--auto",
        action="store_true",
        default=False,
        help="self-driving setup: draft a deny-by-default workspace plan, validate it, "
        "and apply only on explicit consent (sandbox-only)",
    )
    p.add_argument(
        "--yes",
        action="store_true",
        default=False,
        help="with --auto: consent to apply the validated plan without prompting",
    )
    p.add_argument(
        "--brief",
        metavar="TEXT",
        default="",
        help="with --auto: the company brief the workspace draft is derived from",
    )
    p.add_argument(
        "--company",
        metavar="NAME",
        default="My Company",
        help="with --auto: the company name for the drafted workspace",
    )


# ---------------------------------------------------------------------------
# connect: login, whoami, config, context
# ---------------------------------------------------------------------------


def _build_connect(sub: argparse._SubParsersAction[argparse.ArgumentParser], parent: argparse.ArgumentParser) -> None:
    login = _leaf(sub, "login", connect.cmd_login, help="validate reachability and save a context", needs_resolve=False, parent=parent)
    login.add_argument("--token-source", metavar="REF", help="env:VAR | file:PATH | cmd:'...'")

    _leaf(sub, "whoami", connect.cmd_whoami, help="decode the active bearer and confirm the gateway accepts it", parent=parent)

    config = _leaf(sub, "config", _needs_group, help="read/write the config file", needs_resolve=False, parent=parent)
    csub = config.add_subparsers(dest="_sub", metavar="<action>", required=True)
    _leaf(csub, "list", connect.cmd_config_list, help="list all config (secrets redacted)", needs_resolve=False, parent=parent)
    cget = _leaf(csub, "get", connect.cmd_config_get, help="read one config value", needs_resolve=False, parent=parent)
    cget.add_argument("key")
    cset = _leaf(csub, "set", connect.cmd_config_set, help="set one config value", needs_resolve=False, parent=parent)
    cset.add_argument("key")
    cset.add_argument("value")
    cunset = _leaf(csub, "unset", connect.cmd_config_unset, help="unset one config value", needs_resolve=False, parent=parent)
    cunset.add_argument("key")

    context = _leaf(sub, "context", _needs_group, help="manage named contexts", needs_resolve=False, parent=parent)
    ctxsub = context.add_subparsers(dest="_sub", metavar="<action>", required=True)
    _leaf(ctxsub, "list", connect.cmd_context_list, help="list contexts (marks current)", needs_resolve=False, parent=parent)
    _leaf(ctxsub, "current", connect.cmd_context_current, help="print the current context", needs_resolve=False, parent=parent)
    cuse = _leaf(ctxsub, "use", connect.cmd_context_use, help="switch the current context", needs_resolve=False, parent=parent)
    cuse.add_argument("name")
    ctxset = _leaf(ctxsub, "set", connect.cmd_context_set, help="create/update a context", needs_resolve=False, parent=parent)
    ctxset.add_argument("name")
    ctxset.add_argument("--token-source", metavar="REF", help="env:VAR | file:PATH | cmd:'...'")
    cdel = _leaf(ctxsub, "delete", connect.cmd_context_delete, help="delete a context", needs_resolve=False, parent=parent)
    cdel.add_argument("name")


# ---------------------------------------------------------------------------
# agent: catalog, authorize, complete, decision, mcp
# ---------------------------------------------------------------------------


def _build_agent(sub: argparse._SubParsersAction[argparse.ArgumentParser], parent: argparse.ArgumentParser) -> None:
    _leaf(sub, "catalog", agent.cmd_catalog, help="list the aliases this identity may see", parent=parent)

    auth = _leaf(sub, "authorize", agent.cmd_authorize, help="authorize one tool call through the choke point", parent=parent)
    auth.add_argument("alias", nargs="?", help="the opaque skill alias")
    auth.add_argument("--arg", action="append", metavar="K=V", help="an argument (str by default; int:/float:/bool:/json: to coerce)")
    auth.add_argument("--format", metavar="FMT", choices=list(_FORMATS), help="source format for a built envelope")
    auth.add_argument("--tool-call", metavar="@FILE|-", help="a prebuilt provider envelope (JSON)")
    auth.add_argument("--vendor", metavar="V", help="vendor declaration (with --tool-call)")
    auth.add_argument("--credential-out", metavar="FILE", dest="credential_out", help="capture a vended cloud credential to FILE (O_EXCL 0600); never printed")
    _otp_flags(auth)

    comp = _leaf(sub, "complete", agent.cmd_complete, help="finish a staged step-up from the persisted envelope", parent=parent)
    comp.add_argument("--challenge", required=True, metavar="ID", help="the staged challenge id")
    comp.add_argument("--credential-out", metavar="FILE", dest="credential_out", help="capture a vended cloud credential to FILE (O_EXCL 0600); never printed")
    _otp_flags(comp)

    dec = _leaf(sub, "decision", agent.cmd_decision, help="ask for an AuthZEN PDP verdict (nothing executes)", parent=parent)
    dec.add_argument("alias")
    dec.add_argument("--arg", action="append", metavar="K=V")
    dec.add_argument("--action", metavar="NAME", help="AuthZEN action name (default: invoke)")
    dec.add_argument(
        "--authz-context",
        dest="authz_context",
        metavar="@FILE|-",
        help="AuthZEN request context (JSON object)",
    )

    mcp = _leaf(sub, "mcp", _needs_group, help="speak the MCP JSON-RPC edge", parent=parent)
    mcpsub = mcp.add_subparsers(dest="_sub", metavar="<action>", required=True)
    _leaf(mcpsub, "initialize", agent.cmd_mcp_initialize, help="unauthenticated edge handshake", parent=parent)
    tools = _leaf(mcpsub, "tools", _needs_group, help="tools/list and tools/call", parent=parent)
    tsub = tools.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(tsub, "list", agent.cmd_mcp_tools_list, help="tools/list", parent=parent)
    call = _leaf(tsub, "call", agent.cmd_mcp_tools_call, help="tools/call", parent=parent)
    call.add_argument("alias")
    call.add_argument("--arg", action="append", metavar="K=V")
    call.add_argument("--otp-stdin", action="store_true", default=False)
    call.add_argument("--credential-out", metavar="FILE", dest="credential_out", help="capture a vended cloud credential to FILE (O_EXCL 0600); never printed")


# ---------------------------------------------------------------------------
# reads: health, ready, version, license, discovery, audit attestation
# ---------------------------------------------------------------------------


def _build_reads(sub: argparse._SubParsersAction[argparse.ArgumentParser], parent: argparse.ArgumentParser) -> None:
    _leaf(sub, "health", reads.cmd_health, help="liveness probe (unauthenticated)", parent=parent)
    _leaf(sub, "ready", reads.cmd_ready, help="readiness (503 is an honest ready=false)", parent=parent)
    version = _leaf(sub, "version", _version_dispatch, help="running release + provenance", needs_resolve=False, parent=parent)
    version.add_argument("--client", action="store_true", help="print the local CLI+SDK version only")
    _leaf(sub, "license", reads.cmd_license, help="boot-verified entitlement view", parent=parent)
    _leaf(sub, "discovery", reads.cmd_discovery, help="public RFC 9728 resource metadata (no token)", parent=parent)

    audit = _leaf(sub, "audit", _needs_group, help="audit surfaces", parent=parent)
    asub = audit.add_subparsers(dest="_sub", metavar="<action>", required=True)
    _leaf(asub, "attestation", reads.cmd_audit_attestation, help="signed WORM attestation (CAP_DIRECTORY_ADMIN)", parent=parent)


def _version_dispatch(rt: Runtime, args: argparse.Namespace) -> int:
    if getattr(args, "client", False):
        print(_client_version())
        return ExitCode.OK
    return reads.cmd_version(rt, args)


# ---------------------------------------------------------------------------
# sandbox: dev-token, authenticator, audit verify/proof
# ---------------------------------------------------------------------------


def _build_sandbox(sub: argparse._SubParsersAction[argparse.ArgumentParser], parent: argparse.ArgumentParser) -> None:
    sb = _leaf(sub, "sandbox", _needs_group, help="sandbox-only affordances (404 in production)", parent=parent)
    ssub = sb.add_subparsers(dest="_sub", metavar="<action>", required=True)

    dev = _leaf(ssub, "dev-token", sandbox.cmd_sandbox_dev_token, help="mint a dev JWT into the 0600 token store (never printed)", needs_resolve=False, parent=parent)
    dev.add_argument("--tenant", default="tenant-acme")
    dev.add_argument("--agent", default="agent-orchestrator-1")
    dev.add_argument("--role", default="ops")
    dev.add_argument("--cap", action="append", metavar="UUID", help="a capability UUID claim")
    dev.add_argument("--compartment", metavar="UUID")
    dev.add_argument(
        "--session-id",
        metavar="UUID",
        default=None,
        help="session identity stamped into the token (WORM attribution); defaults to the context's stable id, minted once and reused",
    )
    dev.add_argument("--out", metavar="FILE", help="write the token to FILE (O_EXCL 0600) instead")

    auth = _leaf(ssub, "authenticator", sandbox.cmd_sandbox_authenticator, help="fetch a step-up OTP and complete inline (never echoed)", parent=parent)
    auth.add_argument("challenge")
    auth.add_argument("--out", metavar="FILE", help="write the OTP to FILE (O_EXCL 0600) instead of completing")
    auth.add_argument("--credential-out", metavar="FILE", dest="credential_out", help="capture a vended cloud credential to FILE (O_EXCL 0600); never printed")

    audit = _leaf(ssub, "audit", _needs_group, help="force-verify and inclusion proofs", parent=parent)
    aud = audit.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(aud, "verify", sandbox.cmd_sandbox_audit_verify, help="force epoch close + chain verify", parent=parent)
    proof = _leaf(aud, "proof", sandbox.cmd_sandbox_audit_proof, help="Merkle inclusion proof for one event", parent=parent)
    proof.add_argument("event_id")


# ---------------------------------------------------------------------------
# admin: the control plane
# ---------------------------------------------------------------------------


def _build_admin(sub: argparse._SubParsersAction[argparse.ArgumentParser], parent: argparse.ArgumentParser) -> None:
    ad = _leaf(sub, "admin", _needs_group, help="the CAP_DIRECTORY_ADMIN control plane", parent=parent)
    asub = ad.add_subparsers(dest="_sub", metavar="<group>", required=True)

    # skills
    skills = asub.add_parser("skills", help="alias registry + kill-switch", parents=[parent])
    ssub = skills.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(ssub, "ls", admin.cmd_skills_ls, help="registered (deregisterable) aliases", parent=parent)
    _leaf(ssub, "disabled", admin.cmd_skills_disabled, help="currently-disabled aliases", parent=parent)
    reg = _leaf(ssub, "register", admin.cmd_skills_register, help="register a new overlay alias", parent=parent)
    reg.add_argument("alias")
    reg.add_argument("target")
    reg.add_argument("--risk-tier", default="auto", choices=["auto", "pin_required"])
    reg.add_argument("--classification", default="unclassified")
    dereg = _leaf(ssub, "deregister", admin.cmd_skills_deregister, help="remove an overlay alias", parent=parent)
    dereg.add_argument("alias")
    dis = _leaf(ssub, "disable", admin.cmd_skills_disable, help="kill-switch an alias", parent=parent)
    dis.add_argument("alias")
    en = _leaf(ssub, "enable", admin.cmd_skills_enable, help="lift a kill-switch", parent=parent)
    en.add_argument("alias")

    # extensions
    ext = asub.add_parser("extensions", help="community extension review", parents=[parent])
    esub = ext.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    sub_e = _leaf(esub, "submit", admin.cmd_extensions_submit, help="submit a manifest (Contributor)", parent=parent)
    sub_e.add_argument("--manifest", required=True, metavar="@FILE|-")
    _leaf(esub, "pending", admin.cmd_extensions_pending, help="pending submissions (Reviewer)", parent=parent)
    appr = _leaf(esub, "approve", admin.cmd_extensions_approve, help="approve a submission", parent=parent)
    appr.add_argument("submission_id")
    rej = _leaf(esub, "reject", admin.cmd_extensions_reject, help="reject a submission", parent=parent)
    rej.add_argument("submission_id")

    # registry governance — verified-publisher allow-list (Reviewer)
    pub = asub.add_parser("publishers", help="verified-publisher allow-list (registry governance)", parents=[parent])
    pubsub = pub.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(pubsub, "get", admin.cmd_publishers_get, help="read the pinned publisher namespaces", parent=parent)
    pubset = _leaf(pubsub, "set", admin.cmd_publishers_set, help="replace the pinned publisher namespaces", parent=parent)
    pubset.add_argument("--namespace", action="append", metavar="NS", help="a publisher namespace (reverse-DNS, repeatable)")
    pubset.add_argument("--file", metavar="@FILE|-", help="a JSON list of namespaces (or a {namespaces:[...]} doc)")

    # compliance evidence — portable bundle (CAP_DIRECTORY_ADMIN)
    comp = asub.add_parser("compliance", help="portable compliance-evidence bundle", parents=[parent])
    compsub = comp.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(compsub, "evidence", admin.cmd_compliance_evidence, help="export the evidence bundle (--json for the full signed artifact)", parent=parent)

    # decisions
    dec = _leaf(asub, "decisions", admin.cmd_decisions, help="recent allow/deny feed", parent=parent)
    dec.add_argument("--limit", type=int, default=50)
    dec.add_argument("--watch", action="store_true", help="poll and stream new rows")
    dec.add_argument("--interval", type=float, default=2.0, help="poll interval seconds for --watch")

    # decisions history — date-ranged, multi-filtered, cursor-paged (at scale)
    dhist = _leaf(
        asub,
        "decisions-history",
        admin.cmd_decisions_history,
        help="decision history: date range + multi-filter + paging (--all to export)",
        parent=parent,
    )
    dhist.add_argument("--from-ms", dest="from_ms", type=int, default=None, help="inclusive lower bound (epoch ms)")
    dhist.add_argument("--to-ms", dest="to_ms", type=int, default=None, help="inclusive upper bound (epoch ms)")
    dhist.add_argument("--cursor", default=None, help="resume token from a prior page's next_cursor")
    dhist.add_argument("--limit", type=int, default=100, help="rows per page (clamped server-side)")
    dhist.add_argument(
        "--filter",
        action="append",
        metavar="KEY=VALUE",
        help="facet filter, repeatable; VALUE may be comma-separated "
        "(decision/deny_reason/alias/transport/risk_tier/classification/"
        "agent_id/source_format/correlation_id/transaction_ref)",
    )
    dhist.add_argument("--all", action="store_true", help="walk the whole window (export all; pipe --json)")

    # forensic
    for_ = asub.add_parser("forensic", help="query reconstruction (CAP_FORENSIC_READ)", parents=[parent])
    fsub = for_.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    fget = _leaf(fsub, "get", admin.cmd_forensic_get, help="reconstruct the query for a correlation id", parent=parent)
    fget.add_argument("correlation_id")

    # principals
    prin = asub.add_parser("principals", help="revocation kill-switch", parents=[parent])
    psub = prin.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(psub, "ls", admin.cmd_principals_ls, help="revoked agent ids", parent=parent)
    prev = _leaf(psub, "revoke", admin.cmd_principals_revoke, help="revoke an agent", parent=parent)
    prev.add_argument("agent_id")
    prev.add_argument("--reason")
    prea = _leaf(psub, "reactivate", admin.cmd_principals_reactivate, help="lift a revocation", parent=parent)
    prea.add_argument("agent_id")

    # operator/team users — the email-keyed console roster (CAP_DIRECTORY_ADMIN)
    usr = asub.add_parser("users", help="operator/team roster — invite & manage by email", parents=[parent])
    usrsub = usr.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    uls = _leaf(usrsub, "ls", admin.cmd_users_ls, help="list the roster (cursor-paginated)", parent=parent)
    uls.add_argument("--limit", type=int, default=200)
    uls.add_argument("--cursor", default="0", help="continuation cursor from a prior page")
    uinv = _leaf(usrsub, "invite", admin.cmd_users_invite, help="invite a member by email", parent=parent)
    uinv.add_argument("email")
    uinv.add_argument("--role", default="member", choices=["admin", "member", "viewer"])
    uupd = _leaf(usrsub, "update", admin.cmd_users_update, help="change role/status (enable/disable)", parent=parent)
    uupd.add_argument("email")
    uupd.add_argument("--role", choices=["admin", "member", "viewer"])
    uupd.add_argument("--status", choices=["invited", "active", "disabled"])
    urm = _leaf(usrsub, "rm", admin.cmd_users_remove, help="remove a member", parent=parent)
    urm.add_argument("email")

    _leaf(asub, "quarantine", admin.cmd_quarantine, help="canary-frozen agents", parent=parent)
    _leaf(asub, "canaries", admin.cmd_canaries, help="seeded decoy aliases", parent=parent)

    # deployment / license & usage stats — the LOCAL live numbers (no beacon/vendor)
    _leaf(asub, "stats", admin.cmd_stats, help="local live deployment/license/usage numbers + telemetry state", parent=parent)

    # directory
    dir_ = asub.add_parser("directory", help="operator directory + ReBAC relations", parents=[parent])
    dsub = dir_.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(dsub, "get", admin.cmd_directory_get, help="read the directory document", parent=parent)
    dput = _leaf(dsub, "put", admin.cmd_directory_put, help="persist the directory document", parent=parent)
    dput.add_argument("--file", required=True, metavar="@FILE|-")
    drel = _leaf(dsub, "relations", admin.cmd_directory_relations, help="ReBAC relation edges", parent=parent)
    drel.add_argument("--subject")
    drel.add_argument("--relation")
    drel.add_argument("--object", dest="object_uuid")

    # policy
    pol = asub.add_parser("policy", help="deny-only policy overlay", parents=[parent])
    posub = pol.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(posub, "get", admin.cmd_policy_get, help="read the policy document", parent=parent)
    pput = _leaf(posub, "put", admin.cmd_policy_put, help="persist the policy document", parent=parent)
    pput.add_argument("--file", required=True, metavar="@FILE|-")
    _leaf(posub, "delete", admin.cmd_policy_delete, help="remove the policy document", parent=parent)

    # workspace
    ws = asub.add_parser("workspace", help="workspace draft/validate/apply", parents=[parent])
    wsub = ws.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    draft = _leaf(wsub, "draft", admin.cmd_workspace_draft, help="draft a plan (writes plan JSON)", parent=parent)
    draft.add_argument("--brief", default="")
    draft.add_argument("--company", default="My Company")
    draft.add_argument("--tenant", default="")
    val = _leaf(wsub, "validate", admin.cmd_workspace_validate, help="dry-run validate a plan", parent=parent)
    val.add_argument("--file", required=True, metavar="@FILE|-")
    app = _leaf(wsub, "apply", admin.cmd_workspace_apply, help="apply a reviewed plan", parent=parent)
    app.add_argument("--file", required=True, metavar="@FILE|-")

    # cloud-env
    ce = asub.add_parser("cloud-env", help="cloud IAM environments", parents=[parent])
    cesub = ce.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(cesub, "ls", admin.cmd_cloud_env_ls, help="list bindings", parent=parent)
    ceput = _leaf(cesub, "put", admin.cmd_cloud_env_put, help="create/update a binding", parent=parent)
    ceput.add_argument("env_id")
    ceput.add_argument("--provider", required=True)
    ceput.add_argument("--role", required=True)
    ceput.add_argument("--region", required=True)
    ceput.add_argument("--compartment")
    ceput.add_argument("--session-ttl", type=int, default=900, dest="session_ttl")
    ceput.add_argument("--vault-secret-id", dest="vault_secret_id")
    cerm = _leaf(cesub, "rm", admin.cmd_cloud_env_rm, help="remove a binding", parent=parent)
    cerm.add_argument("env_id")

    # vault
    va = asub.add_parser("vault", help="secret vault (write-only values)", parents=[parent])
    vasub = va.add_subparsers(dest="_subsub", metavar="<action>", required=True)
    _leaf(vasub, "ls", admin.cmd_vault_ls, help="list secret metadata + fingerprints", parent=parent)
    vput = _leaf(vasub, "put", admin.cmd_vault_put, help="store/rotate a secret (material via file/stdin)", parent=parent)
    vput.add_argument("secret_id")
    vput.add_argument("--vendor", required=True)
    vput.add_argument("--description", default="")
    vput.add_argument("--material-file", metavar="FILE", dest="material_file")
    vput.add_argument("--material-stdin", action="store_true", dest="material_stdin")
    vrm = _leaf(vasub, "rm", admin.cmd_vault_rm, help="remove a secret", parent=parent)
    vrm.add_argument("secret_id")


_FORMATS = (
    "raw_mcp",
    "openai_tool_call",
    "anthropic_tool_use",
    "gemini_function_call",
    "bedrock_tool_use",
    "mcp_jsonrpc",
)


def _needs_group(rt: Runtime, args: argparse.Namespace) -> int:
    # A group with no action selected — argparse's required=True subparsers make
    # this unreachable, but keep an honest usage exit if it is ever hit.
    print("error: a subcommand is required", file=sys.stderr)
    return ExitCode.USAGE


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse usage errors / --help / --version
        return int(exc.code) if isinstance(exc.code, int) else ExitCode.OK

    if getattr(args, "config", None):
        os.environ["MCPIP_CONFIG"] = args.config

    mode = OutputMode(
        json=bool(getattr(args, "json", False)),
        quiet=bool(getattr(args, "quiet", False)),
        color=not bool(getattr(args, "no_color", False)),
    )

    func: Handler | None = getattr(args, "func", None)
    if func is None:
        parser.print_help()
        return ExitCode.USAGE

    try:
        config = cfg.load()
        resolved = cfg.resolve(
            config,
            gateway=getattr(args, "gateway", None),
            context=getattr(args, "context", None),
            sandbox=getattr(args, "sandbox", None),
            strict=bool(getattr(args, "_needs_resolve", True)),
        )
    except CLIConfigError as exc:
        render_error(mode, exc)
        return int(map_exception(exc))

    rt = Runtime(
        resolved=resolved,
        mode=mode,
        token_file=getattr(args, "token_file", None),
        token_stdin=bool(getattr(args, "token_stdin", False)),
        token_cmd=getattr(args, "token_cmd", None),
    )

    try:
        return int(func(rt, args))
    except Exception as exc:  # noqa: BLE001 - one place maps everything to a code
        # KeyboardInterrupt / SystemExit are NOT Exception — they propagate.
        render_error(mode, exc)
        return int(map_exception(exc))


__all__ = ["main", "build_parser"]
