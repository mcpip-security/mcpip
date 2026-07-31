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
import uuid
from dataclasses import replace

from mcpip_sdk.cli import config as cfg
from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.commands.agent import _discard_staged, _load_staged, _render_receipt
from mcpip_sdk.cli.errors import CLIConfigError, ExitCode
from mcpip_sdk.cli.render import block, emit_object


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
    else:
        path = cfg.default_token_path(name)
        cfg.write_secret_file(path, token, exclusive=False)  # atomic 0600 rotate
        # Wire the context's token-source at file:PATH so later commands use it,
        # and persist the session id so the next mint reuses it.
        ctx = cfg.Context(
            name=name,
            base_url=existing.base_url if existing else rt.resolved.base_url,
            sandbox=existing.sandbox if existing else rt.resolved.sandbox,
            token_source=f"file:{path}",
            session_id=session_id,
        )
        contexts = dict(config.contexts)
        contexts[name] = ctx
        current = config.current_context or name
        cfg.save(replace(config, contexts=contexts, current_context=current))
        wired = True

    # NEVER print the token — only where it landed.
    emit_object(
        rt.mode,
        {
            "token_written": True,
            "path": path,
            "context_wired": wired,
            "agent_id": args.agent,
            "session_id": session_id,
        },
        block(
            [
                ("token_written", True),
                ("path", path),
                ("context_wired", wired),
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
