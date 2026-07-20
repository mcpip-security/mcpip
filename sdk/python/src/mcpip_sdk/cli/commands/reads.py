"""
mcpip_sdk.cli.commands.reads — liveness/version/license/discovery/attestation.

Thin wrappers over :class:`~mcpip_sdk.client.MCPIPClient` reads. ``ready`` treats
a 503 as an HONEST ``ready=false`` (exit 0, not an error): the SDK already maps
it that way, so nothing here re-raises it.
"""

from __future__ import annotations

import argparse

from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.errors import ExitCode
from mcpip_sdk.cli.render import block, emit_object


def cmd_health(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        health = client.health()
    emit_object(
        rt.mode,
        health,
        block(
            [
                ("status", health.status),
                ("version", health.version),
                ("loop", health.loop),
                ("glyph", health.glyph),
            ]
        ),
        quiet_id=health.status,
    )
    return ExitCode.OK


def cmd_ready(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        readiness = client.ready()
    emit_object(
        rt.mode,
        readiness,
        block(
            [
                ("ready", readiness.ready),
                ("status", readiness.status),
                ("redis", readiness.redis),
            ]
        ),
        quiet_id="true" if readiness.ready else "false",
    )
    return ExitCode.OK


def cmd_version(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        version = client.version()
    emit_object(
        rt.mode,
        version,
        block(
            [
                ("running", version.running),
                ("latest", version.latest),
                ("update_available", version.update_available),
                ("channel", version.channel),
                ("update_policy", version.update_policy),
                ("release.version", version.release.version),
                ("release.signing_key_id", version.release.signing_key_id),
                ("release.verified", version.release.verified),
            ]
        ),
        quiet_id=version.running,
    )
    return ExitCode.OK


def cmd_license(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        info = client.license()
    emit_object(
        rt.mode,
        info,
        block(
            [
                ("licensed", info.licensed),
                ("license_id", info.license_id),
                ("customer", info.customer),
                ("tier", info.tier),
                ("issued_at", info.issued_at),
                ("expires_at", info.expires_at),
                ("entitlements", info.entitlements),
            ]
        ),
        quiet_id="true" if info.licensed else "false",
    )
    return ExitCode.OK


def cmd_discovery(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        meta = client.protected_resource_metadata()
    emit_object(
        rt.mode,
        meta,
        block(
            [
                ("resource", meta.resource),
                ("authorization_servers", meta.authorization_servers),
                ("bearer_methods_supported", meta.bearer_methods_supported),
            ]
        ),
        quiet_id=meta.resource,
    )
    return ExitCode.OK


def cmd_audit_attestation(rt: Runtime, args: argparse.Namespace) -> int:
    with rt.agent_client() as client:
        att = client.audit_attestation()
    emit_object(
        rt.mode,
        att,
        block(
            [
                ("signing_key_id", att.signing_key_id),
                ("intact", att.intact),
                ("epoch", att.epoch),
                ("end_seq", att.end_seq),
                ("merkle_root", att.merkle_root),
                ("epoch_hash", att.epoch_hash),
                ("first_bad_epoch", att.first_bad_epoch),
                ("anchor_epoch", att.anchor_epoch),
            ]
        ),
        quiet_id=att.signing_key_id,
    )
    return ExitCode.OK


__all__ = [
    "cmd_health",
    "cmd_ready",
    "cmd_version",
    "cmd_license",
    "cmd_discovery",
    "cmd_audit_attestation",
]
