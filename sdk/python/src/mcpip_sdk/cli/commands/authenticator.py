"""
mcpip_sdk.cli.commands.authenticator — the PRODUCTION step-up channel.

A ``pin_required`` alias stages rather than allows, and finishing the cycle needs
a one-time code that reached a human out of band. The sandbox stands in for that
human (``mcpip sandbox authenticator``); production uses an enrolled RFC 6238
authenticator, and these are the commands that drive it.

They exist because they did not: the five ``/v1/authenticator/*`` endpoints had no
CLI and no client, so the only production path through MCPIP's signature feature
was hand-rolled HTTP. ``mcpip authorize`` would stage, print "resume with
``mcpip complete``", and that command could not succeed without a code no command
could fetch.

Secrets never reach a terminal. Enrollment material is written to a 0600 file and
only its path is printed; the released OTP is piped straight into an inline
``complete`` and never echoed.
"""

from __future__ import annotations

import argparse

from mcpip_sdk.cli import config as cfg
from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.commands.agent import _discard_staged, _load_staged, _render_receipt
from mcpip_sdk.cli.errors import CLIConfigError, ExitCode
from mcpip_sdk.cli.render import block, emit_object


def cmd_authenticator_status(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        status = client.authenticator_status()
    enrolled = bool(status.get("enrolled"))
    emit_object(
        rt.mode,
        status,
        block(
            [
                ("enrolled", enrolled),
                ("pending", bool(status.get("pending"))),
                ("enrolled_at", status.get("enrolled_at") or "-"),
            ]
        ),
        quiet_id="true" if enrolled else "false",
    )
    return ExitCode.OK


def cmd_authenticator_enroll(rt: Runtime, args: argparse.Namespace) -> int:
    """
    Begin enrollment and write the provisioning material to a 0600 file.

    The material is returned EXACTLY ONCE and the ``otpauth://`` URI embeds the
    secret, so it is never printed — the path is. Read it deliberately (``cat``,
    or a QR renderer) rather than having it land in scrollback and shell history.
    """
    with rt.agent_client() as client:
        begin = client.authenticator_enroll()
    uri = str(begin.get("provisioning_uri", ""))
    cfg.write_secret_file(args.out, uri + "\n", exclusive=True)
    emit_object(
        rt.mode,
        {
            "enrollment_started": True,
            "path": args.out,
            "digits": begin.get("digits"),
            "period_s": begin.get("period_s"),
        },
        block(
            [
                ("enrollment_started", True),
                ("path", args.out),
                ("digits", begin.get("digits")),
                ("period_s", begin.get("period_s")),
                ("next", "mcpip authenticator confirm --code <6 digits>"),
            ]
        ),
        quiet_id=args.out,
    )
    return ExitCode.OK


def cmd_authenticator_confirm(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        enrolled = client.authenticator_confirm(args.code)
    emit_object(
        rt.mode,
        {"enrolled": enrolled},
        block([("enrolled", enrolled)]),
        quiet_id="true" if enrolled else "false",
    )
    return ExitCode.OK


def cmd_authenticator_disable(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        client.authenticator_disable(args.code)
    emit_object(rt.mode, {"disabled": True}, block([("disabled", True)]), quiet_id="true")
    return ExitCode.OK


def cmd_authenticator_reveal(rt: Runtime, args: argparse.Namespace) -> int:
    """
    Release the payload-bound OTP for a staged challenge and complete it inline.

    Mirrors ``mcpip sandbox authenticator`` deliberately: one command from staged
    to receipt, with the OTP never crossing a terminal. ``--out`` captures the code
    instead of completing, for callers driving ``complete`` themselves.
    """
    with rt.agent_client() as client:
        otp = client.authenticator_reveal(args.challenge, args.code)

        if args.out is not None:
            cfg.write_secret_file(args.out, otp, exclusive=True)
            emit_object(
                rt.mode,
                {"otp_written": True, "path": args.out},
                block([("otp_written", True), ("path", args.out)]),
                quiet_id=args.out,
            )
            return ExitCode.OK

        try:
            staged = _load_staged(args.challenge)
        except Exception as exc:  # noqa: BLE001 — re-raise as an actionable config error
            raise CLIConfigError(
                "no locally-staged challenge to complete; pass --out FILE to "
                "capture the OTP into a 0600 file instead"
            ) from exc
        receipt = client.complete(staged, otp)
    _discard_staged(args.challenge)
    _render_receipt(rt, receipt, credential_out=getattr(args, "credential_out", None))
    return ExitCode.OK
