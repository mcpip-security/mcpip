"""
mcpip_sdk.cli.commands.sandbox — the SANDBOX-ONLY affordances: dev-token minting,
the stand-in authenticator, and audit verify/proof. Each 404s opaquely as
:class:`~mcpip_sdk.errors.MCPIPSandboxOnly` (exit 7) on a production gateway.

Secrets never reach a terminal here: a minted dev token is written straight into
a 0600 token store (or ``--out`` file) and NEVER printed; a fetched OTP is piped
into an inline ``complete`` or written to a 0600 file, NEVER echoed.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import uuid
from dataclasses import replace

from mcpip_sdk.cli import config as cfg
from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.commands.agent import _discard_staged, _load_staged, _render_receipt
from mcpip_sdk.cli.errors import CLIConfigError, ExitCode
from mcpip_sdk.cli.render import block, emit_list, emit_object, table


def _agent_id_of_token_file(path: str) -> str | None:
    """The ``agent_id`` in an existing token file, or ``None`` if unreadable.

    Display only, and deliberately forgiving: this exists to name whose bearer is
    about to be rotated away, so anything unparseable simply means the note is
    skipped. It never gates the mint.
    """
    try:
        with open(path, encoding="utf-8") as handle:
            token = handle.read().strip()
        segment = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))
    except Exception:  # noqa: BLE001 — a missing or malformed file is not an error here
        return None
    agent = claims.get("agent_id") or claims.get("sub")
    return str(agent) if agent else None


def cmd_sandbox_dev_token(rt: Runtime, args: argparse.Namespace) -> int:
    # Session identity, resolved before minting: an explicit --session-id wins;
    # otherwise the context's stable id (minted once, then reused on every
    # re-mint so token refreshes stay ONE session in the WORM chain); a fresh
    # UUID when neither exists yet.
    name = rt.resolved.context_name or "default"
    config = cfg.load()
    existing = config.contexts.get(name)
    session_id: str = (
        args.session_id
        or (existing.session_id if existing is not None else None)
        or str(uuid.uuid4())
    )
    with rt.sandbox_client() as client:
        token = client.dev_token(
            tenant_id=args.tenant,
            agent_id=args.agent,
            role=args.role,
            compartment=args.compartment,
            capabilities=args.cap or None,
            session_id=session_id,
        )

    if args.out is not None:
        cfg.write_secret_file(args.out, token, exclusive=True)  # O_EXCL 0600
        path = args.out
        wired = False
        replaced_agent = None
    else:
        path = cfg.default_token_path(name)
        # One bearer per context. Overwriting is the intended behaviour (a re-mint
        # must rotate), but doing it silently makes command ORDER load-bearing in a
        # way nothing announces: mint an admin identity, mint an agent identity,
        # and the admin token is simply gone — the next `admin` call answers an
        # opaque 403 that reads exactly like a missing capability. Read who is
        # about to be displaced so it can be said out loud.
        replaced_agent = _agent_id_of_token_file(path)
        cfg.write_secret_file(path, token, exclusive=False)  # atomic 0600 rotate
        # Wire the context's token-source at file:PATH so later commands use it,
        # and persist the session id so the next mint reuses it.
        #
        # The gateway recorded here MUST be the one the token was actually minted
        # against. It used to keep `existing.base_url` whenever the context already
        # existed, so `mcpip sandbox dev-token --gateway http://other:8080` minted
        # from `other`, wired the context to the OLD gateway, and reported
        # `context_wired: true` — after which every command sent one gateway's
        # token to another and got an opaque 403 with nothing pointing at the
        # cause. An explicit --gateway is a statement about which gateway this
        # context means; honour it, since `rt.resolved.base_url` is exactly the
        # URL the mint above used.
        explicit_gateway = getattr(args, "gateway", None)
        base_url = (
            rt.resolved.base_url
            if explicit_gateway is not None or existing is None
            else existing.base_url
        )
        ctx = cfg.Context(
            name=name,
            base_url=base_url,
            sandbox=existing.sandbox if existing else rt.resolved.sandbox,
            token_source=f"file:{path}",
            session_id=session_id,
        )
        contexts = dict(config.contexts)
        contexts[name] = ctx
        current = config.current_context or name
        cfg.save(replace(config, contexts=contexts, current_context=current))
        wired = True

    # A higher-precedence source silently outranks what we just wired, so the next
    # command would use a DIFFERENT identity and the mismatch would surface as an
    # opaque 403 with nothing pointing at the cause. Say so here instead.
    shadow: str | None = None
    if wired:
        if os.environ.get("MCPIP_TOKEN"):
            shadow = "MCPIP_TOKEN is set and outranks the context — unset it, or pass --token-file"
        elif rt.token_file or rt.token_stdin or rt.token_cmd:
            shadow = "an explicit --token-* flag outranks the context for this invocation"
    if shadow is not None and not rt.mode.quiet and not rt.mode.json:
        print(f"warning: {shadow}")
    if (
        replaced_agent is not None
        and replaced_agent != args.agent
        and not rt.mode.quiet
        and not rt.mode.json
    ):
        print(
            f"note: replaced the bearer for {replaced_agent!r} in context "
            f"{name!r} — one token per context. Keep both with "
            f"--out FILE, or a second context."
        )

    # NEVER print the token — only where it landed.
    emit_object(
        rt.mode,
        {
            "token_written": True,
            "path": path,
            "context_wired": wired,
            "gateway": ctx.base_url if wired else None,  # noqa: F821 — bound iff wired
            "shadowed_by": shadow,
            "replaced_agent_id": replaced_agent if replaced_agent != args.agent else None,
            "agent_id": args.agent,
            "session_id": session_id,
        },
        block(
            [
                ("token_written", True),
                ("path", path),
                ("context_wired", wired),
                # The gateway the token was minted against AND the one the context
                # now points at — they were allowed to disagree; naming it makes a
                # future divergence visible rather than a silent 403.
                *([("gateway", ctx.base_url)] if wired else []),
                ("agent_id", args.agent),
                ("session_id", session_id),
            ]
        ),
        quiet_id=path,
    )
    return ExitCode.OK


def cmd_sandbox_authenticator(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.sandbox_client() as client:
        otp = client.authenticator_code(args.challenge)

        if args.out is not None:
            cfg.write_secret_file(args.out, otp, exclusive=True)  # 0600 O_EXCL, no echo
            emit_object(
                rt.mode,
                {"otp_written": True, "path": args.out},
                block([("otp_written", True), ("path", args.out)]),
                quiet_id=args.out,
            )
            return ExitCode.OK

        # No --out: pipe the OTP directly into an inline complete of the staged
        # challenge (never echoed). Requires a locally-persisted staged envelope.
        try:
            staged = _load_staged(args.challenge)
        except Exception as exc:  # noqa: BLE001 - re-raise as an actionable config error
            raise CLIConfigError(
                "no locally-staged challenge to complete; pass --out FILE to "
                "capture the OTP into a 0600 file instead"
            ) from exc
        receipt = client.complete(staged, otp)
    _discard_staged(args.challenge)
    _render_receipt(rt, receipt, credential_out=getattr(args, "credential_out", None))
    return ExitCode.OK


def cmd_sandbox_audit_verify(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.sandbox_client() as client:
        result = client.audit_verify()
    emit_object(
        rt.mode,
        result,
        block([("intact", result.intact), ("first_bad_epoch", result.first_bad_epoch)]),
        quiet_id="true" if result.intact else "false",
    )
    return ExitCode.OK


def cmd_sandbox_audit_proof(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.sandbox_client() as client:
        proof = client.audit_proof(args.event_id)
    emit_object(
        rt.mode,
        proof,
        block(
            [
                ("event_id", proof.event_id),
                ("epoch", proof.epoch),
                ("index", proof.index),
                ("merkle_root", proof.merkle_root),
                ("epoch_hash", proof.epoch_hash),
                ("proof_len", len(proof.proof)),
            ]
        ),
        quiet_id=proof.event_id,
    )
    return ExitCode.OK


__all__ = [
    "cmd_sandbox_dev_token",
    "cmd_sandbox_authenticator",
    "cmd_sandbox_audit_verify",
    "cmd_sandbox_audit_proof",
]


def cmd_sandbox_capabilities(rt: Runtime, args: argparse.Namespace) -> int:
    """The well-known capability UUIDs, by name.

    Every privileged action gates on a capability UUID in the JWT `capabilities`
    claim — never on a role string — so minting an admin token requires knowing
    the UUID. The endpoint existed and the docs recommended it, but there was no
    command for it, which left `curl` as the only way to answer "what do I pass
    to --cap?" from a terminal.
    """
    with rt.sandbox_client() as client:
        caps = client.capabilities()
    rows = sorted(caps.items())
    emit_list(
        rt.mode,
        [{"name": name, "uuid": value} for name, value in rows],
        "capabilities",
        table(("name", "uuid"), rows),
        quiet_ids=[value for _, value in rows],
    )
    return ExitCode.OK
