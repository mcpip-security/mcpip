"""
mcpip_sdk.cli.commands.connect — the zero-to-connected surface: login, whoami,
and the config / context (kubeconfig-style) management commands.

``login`` mints NO token — it validates reachability with
:meth:`~mcpip_sdk.client.MCPIPClient.health` and persists a named context.
``whoami`` decodes the active bearer's JWT claims LOCALLY and UNVERIFIED (for
display only — the gateway holds the keys), then confirms the gateway actually
accepts the token via :meth:`~mcpip_sdk.client.MCPIPClient.version`. Neither ever
prints the token itself.
"""

from __future__ import annotations

import argparse
import base64
import json
import time
from typing import Any

from mcpip_sdk.cli import config as cfg
from mcpip_sdk.cli._runtime import Runtime
from mcpip_sdk.cli.errors import CLIConfigError, ExitCode
from mcpip_sdk.cli.render import block, emit_object, table
from mcpip_sdk.client import MCPIPClient
from mcpip_sdk.errors import MCPIPDenied, MCPIPUnavailable
from mcpip_sdk.cli import _runtime


# ---------------------------------------------------------------------------
# login
# ---------------------------------------------------------------------------


def cmd_login(rt: Runtime, args: argparse.Namespace) -> int:
    # Every global is attached with `default=argparse.SUPPRESS` so it may appear
    # before OR after the subcommand without a later default clobbering an earlier
    # value — which also means the attribute DOES NOT EXIST unless the flag was
    # typed. Reading it directly made bare `mcpip login` die with a naked
    # AttributeError, and the README only ever showed the four-token form that
    # happens to pass all three, so nothing caught it.
    context = getattr(args, "context", None)
    gateway = getattr(args, "gateway", None)
    sandbox_flag = getattr(args, "sandbox", None)

    name = context or "default"
    base_url = gateway or (
        rt.resolved.base_url if context is None else "http://localhost:8080"
    )
    sandbox = bool(sandbox_flag) if sandbox_flag is not None else rt.resolved.sandbox
    token_source = args.token_source
    if token_source is not None:
        cfg.validate_token_source(token_source)

    # Validate reachability — never mints or sends a token. Also read readiness:
    # a gateway can be reachable (healthz live) yet NOT ready (its Redis-backed
    # WORM audit store is down). Because MCPIP is fail-closed — no audit write,
    # no execute — an un-ready gateway denies EVERY governed call with the opaque
    # "request denied by policy". Surfacing it here is the one place that turns
    # that otherwise-inscrutable deny into an obvious "your Redis is down".
    with MCPIPClient(base_url, transport=_runtime._TRANSPORT_OVERRIDE) as client:
        health = client.health()
        readiness = client.ready()

    config = cfg.load()
    contexts = dict(config.contexts)
    contexts[name] = cfg.Context(
        name=name,
        base_url=base_url,
        sandbox=sandbox,
        token_source=token_source
        or (contexts[name].token_source if name in contexts else None),
    )
    from dataclasses import replace

    cfg.save(replace(config, contexts=contexts, current_context=name))

    emit_object(
        rt.mode,
        {
            "context": name,
            "gateway": base_url,
            "sandbox": sandbox,
            "reachable": True,
            "gateway_version": health.version,
            "ready": readiness.ready,
            "redis": readiness.redis,
        },
        block(
            [
                ("context", name),
                ("gateway", base_url),
                ("sandbox", sandbox),
                ("reachable", True),
                ("gateway_version", health.version),
                ("ready", readiness.ready),
                ("redis", readiness.redis),
            ]
            + (
                []
                if readiness.ready
                else [
                    (
                        "note",
                        "gateway reachable but NOT ready — its audit store (Redis) is "
                        "down, so it fails closed and every call is denied until Redis "
                        "recovers (GET /readyz)",
                    )
                ]
            )
        ),
        quiet_id=name,
    )
    return ExitCode.OK


# ---------------------------------------------------------------------------
# whoami
# ---------------------------------------------------------------------------


def cmd_whoami(rt: Runtime, args: argparse.Namespace) -> int:
    provider = rt.token_provider()
    if provider is None:
        raise CLIConfigError(
            "no bearer resolved for the active context "
            "(set MCPIP_TOKEN, --token-file, --token-cmd, or a context token-source)"
        )
    token = provider() if callable(provider) else provider
    claims = _decode_claims_unverified(token)

    # Confirm the gateway actually accepts this identity (never prints the token).
    #
    # A REFUSAL IS AN ANSWER, NOT AN ERROR. This used to let the deny propagate, so
    # `whoami` exited 3 with "request denied by policy" — the very message the
    # `exp` rendering below exists to stop a developer chasing — precisely when the
    # bearer was expired or rejected. The local decode is the whole value of this
    # command in that state, and it was being thrown away to report the failure it
    # was supposed to explain. Verified: a token 807s past `exp` printed the opaque
    # deny and nothing else, because 807s is far outside the 60s JWT leeway that
    # kept `/v1/version` answering for the first minute.
    accepted = True
    gateway_running = None
    gateway_error: str | None = None
    try:
        with rt.agent_client() as client:
            version = client.version()
            gateway_running = version.running
    except MCPIPDenied:
        accepted = False
        gateway_error = "denied"
    except MCPIPUnavailable:
        # Distinct from a refusal: "I could not ask" is not "you were rejected",
        # and conflating them would send someone hunting for a bad token when the
        # gateway is simply down.
        accepted = False
        gateway_error = "unreachable"

    # A raw epoch is not an answer to "why is everything denied?". An expired dev
    # token denies EVERY call with the same opaque body as a policy refusal — so
    # the one command that decodes the bearer locally has to say so plainly.
    expires_in = None
    raw_exp = claims.get("exp")
    if isinstance(raw_exp, (int, float)):
        expires_in = int(raw_exp - time.time())

    model: dict[str, Any] = {
        "expires_in_s": expires_in,
        "expired": expires_in is not None and expires_in <= 0,
        "tenant_id": claims.get("tenant_id"),
        "agent_id": claims.get("agent_id") or claims.get("sub"),
        "role": claims.get("role"),
        "session_id": claims.get("session_id"),
        "exp": claims.get("exp"),
        "capabilities": claims.get("capabilities", []),
        "gateway_accepts": accepted,
        "gateway_error": gateway_error,
        "context": rt.resolved.context_name,
    }
    emit_object(
        rt.mode,
        model,
        block(
            [
                ("context", rt.resolved.context_name),
                ("tenant_id", model["tenant_id"]),
                ("agent_id", model["agent_id"]),
                ("role", model["role"]),
                ("session_id", model["session_id"]),
                ("exp", _expiry_label(expires_in, model["exp"])),
                ("capabilities", model["capabilities"]),
                ("gateway_accepts", accepted),
                ("gateway_running", gateway_running if gateway_running is not None else "-"),
                *(
                    [("why", _refusal_hint(gateway_error, expires_in))]
                    if gateway_error is not None
                    else []
                ),
            ]
        ),
        quiet_id=str(model["agent_id"] or ""),
    )
    return ExitCode.OK


def _refusal_hint(gateway_error: str, expires_in: int | None) -> str:
    """Say why the gateway would not confirm this identity.

    The bearer being expired is by far the most common cause and the least
    obvious, because the gateway answers it with the same opaque body as a real
    policy refusal. When the local decode already proves expiry, say so outright
    rather than making the reader correlate two lines.
    """
    if gateway_error == "unreachable":
        return "gateway unreachable — check --gateway / the context's base_url"
    if expires_in is not None and expires_in <= 0:
        return "the bearer is EXPIRED — that is why every call denies; re-mint it"
    return (
        "gateway refused this bearer (opaque by design). Common causes: wrong "
        "issuer/audience, a revoked or quarantined principal, or a token minted "
        "for a different gateway"
    )


def _expiry_label(expires_in: int | None, raw_exp: Any) -> str:
    """Render `exp` as something a human can act on, not a Unix epoch.

    An expired bearer is the single most confusing state in the CLI: the gateway
    denies every call with the same opaque body it uses for a real policy refusal,
    so a developer reads "request denied by policy" and goes looking for a missing
    capability. Saying EXPIRED here ends that search in one command.
    """
    if expires_in is None:
        return str(raw_exp)
    if expires_in <= 0:
        return f"EXPIRED {-expires_in}s ago — re-mint: mcpip sandbox dev-token"
    if expires_in < 120:
        return f"{expires_in}s left — expiring"
    return f"{expires_in // 60}m left"


def _decode_claims_unverified(token: str) -> dict[str, Any]:
    """Decode a JWT's claims WITHOUT verifying the signature (display only — the
    gateway holds the keys). Never raises on a malformed token; returns {}."""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
    except (ValueError, IndexError):
        return {}
    return claims if isinstance(claims, dict) else {}


# ---------------------------------------------------------------------------
# config
# ---------------------------------------------------------------------------


def cmd_config_list(rt: Runtime, args: argparse.Namespace) -> int:
    config = cfg.load()
    rows: list[tuple[str, str]] = []
    if config.current_context is not None:
        rows.append(("current-context", config.current_context))
    for name in sorted(config.contexts):
        ctx = config.contexts[name]
        rows.append((f"context.{name}.base_url", ctx.base_url))
        rows.append((f"context.{name}.sandbox", "true" if ctx.sandbox else "false"))
        ts_key = f"context.{name}.token-source"
        rows.append((ts_key, cfg.redact(ts_key, ctx.token_source) or "-"))
    if rt.mode.json:
        from mcpip_sdk.cli.render import emit_json

        emit_json({k: v for k, v in rows})
        return ExitCode.OK
    if not rows:
        print("No config.")
        return ExitCode.OK
    print(table(["key", "value"], rows))
    return ExitCode.OK


def cmd_config_get(rt: Runtime, args: argparse.Namespace) -> int:
    value = cfg.config_get(cfg.load(), args.key)
    value = cfg.redact(args.key, value)
    if value is None:
        # honest empty — the key is not set (a real answer, not a failure)
        if not rt.mode.quiet:
            print("" if rt.mode.json else "-")
        return ExitCode.OK
    print(value)
    return ExitCode.OK


def cmd_config_set(rt: Runtime, args: argparse.Namespace) -> int:
    config = cfg.config_set(cfg.load(), args.key, args.value)
    cfg.save(config)
    if not rt.mode.quiet:
        cfg.stderr_note(f"set {args.key}")
    return ExitCode.OK


def cmd_config_unset(rt: Runtime, args: argparse.Namespace) -> int:
    config = cfg.config_unset(cfg.load(), args.key)
    cfg.save(config)
    if not rt.mode.quiet:
        cfg.stderr_note(f"unset {args.key}")
    return ExitCode.OK


# ---------------------------------------------------------------------------
# context
# ---------------------------------------------------------------------------


def cmd_context_list(rt: Runtime, args: argparse.Namespace) -> int:
    config = cfg.load()
    if not config.contexts:
        if not rt.mode.quiet:
            print("[]" if rt.mode.json else "No contexts.")
        return ExitCode.OK
    if rt.mode.quiet:
        for name in sorted(config.contexts):
            print(name)
        return ExitCode.OK
    if rt.mode.json:
        from mcpip_sdk.cli.render import emit_json

        emit_json(
            [
                {
                    "name": c.name,
                    "current": c.name == config.current_context,
                    "base_url": c.base_url,
                    "sandbox": c.sandbox,
                    "token_source": cfg.redact(
                        f"context.{c.name}.token-source", c.token_source
                    ),
                }
                for c in (config.contexts[n] for n in sorted(config.contexts))
            ]
        )
        return ExitCode.OK
    rows = []
    for name in sorted(config.contexts):
        c = config.contexts[name]
        marker = "*" if name == config.current_context else ""
        rows.append((marker, c.name, c.base_url, "true" if c.sandbox else "false", c.token_source))
    print(table(["current", "name", "base_url", "sandbox", "token_source"], rows))
    return ExitCode.OK


def cmd_context_current(rt: Runtime, args: argparse.Namespace) -> int:
    current = cfg.load().current_context
    if current is None:
        if not rt.mode.quiet:
            print("-")
        return ExitCode.OK
    print(current)
    return ExitCode.OK


def cmd_context_use(rt: Runtime, args: argparse.Namespace) -> int:
    from dataclasses import replace

    config = cfg.load()
    if args.name not in config.contexts:
        raise CLIConfigError(f"no such context: {args.name!r}")
    cfg.save(replace(config, current_context=args.name))
    if not rt.mode.quiet:
        cfg.stderr_note(f"switched to context {args.name!r}")
    return ExitCode.OK


def cmd_context_set(rt: Runtime, args: argparse.Namespace) -> int:
    from dataclasses import replace

    config = cfg.load()
    existing = config.contexts.get(args.name)
    token_source = args.token_source
    if token_source is not None:
        cfg.validate_token_source(token_source)
    ctx = cfg.Context(
        name=args.name,
        base_url=getattr(args, "gateway", None)
        or (existing.base_url if existing else "http://localhost:8080"),
        sandbox=bool(getattr(args, "sandbox", None))
        if getattr(args, "sandbox", None) is not None
        else (existing.sandbox if existing else False),
        token_source=token_source or (existing.token_source if existing else None),
    )
    contexts = dict(config.contexts)
    contexts[args.name] = ctx
    cfg.save(replace(config, contexts=contexts))
    if not rt.mode.quiet:
        cfg.stderr_note(f"context {args.name!r} saved")
    return ExitCode.OK


def cmd_context_delete(rt: Runtime, args: argparse.Namespace) -> int:
    from dataclasses import replace

    config = cfg.load()
    if args.name not in config.contexts:
        raise CLIConfigError(f"no such context: {args.name!r}")
    contexts = dict(config.contexts)
    del contexts[args.name]
    current = None if config.current_context == args.name else config.current_context
    cfg.save(replace(config, contexts=contexts, current_context=current))
    if not rt.mode.quiet:
        cfg.stderr_note(f"deleted context {args.name!r}")
    return ExitCode.OK


__all__ = [
    "cmd_login",
    "cmd_whoami",
    "cmd_config_list",
    "cmd_config_get",
    "cmd_config_set",
    "cmd_config_unset",
    "cmd_context_list",
    "cmd_context_current",
    "cmd_context_use",
    "cmd_context_set",
    "cmd_context_delete",
]
