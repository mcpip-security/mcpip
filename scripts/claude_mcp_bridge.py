#!/usr/bin/env python3
"""
MCPIP ↔ Claude — a stdio MCP server that lets Claude (Claude Code / Claude Desktop)
use an MCPIP gateway as a tool provider.

Why this exists
---------------
MCPIP's MCP edge (``POST /v1/mcp``) is zero-trust and fail-closed: identity comes
ONLY from a verified JWT on the ``Authorization: Bearer`` header. A vanilla MCP
client has no way to obtain or attach that token, so if you point Claude straight
at ``/v1/mcp`` every ``tools/list`` / ``tools/call`` is DENIED — correctly, by
design. This bridge is the missing piece: it speaks the MCP stdio transport to
Claude and forwards each call to MCPIP over HTTP, attaching a valid JWT (and
pinning the right tenant) so calls are authorized instead of denied.

  Claude  ──stdio(JSON-RPC)──▶  this bridge  ──HTTPS + Bearer JWT──▶  MCPIP /v1/mcp
                                                    │
                                             (mints a sandbox token, or uses
                                              MCPIP_TOKEN for a real IdP JWT)

It is a thin, honest proxy: it never fabricates a tool result — every response is
the gateway's real authorize decision (allow receipt or opaque deny). The real
target and payload never leave the gateway.

Configuration (environment)
---------------------------
  MCPIP_URL     Gateway base URL             (default http://localhost:8080)
  MCPIP_TENANT  Tenant the agent acts under  (default tenant-acme)
  MCPIP_AGENT   Agent id for the minted JWT  (default claude)
  MCPIP_TOKEN   A pre-issued JWT to use as-is (PRODUCTION: supply your IdP's token
                here; when set, the sandbox dev-token minter is never called)

Register with Claude Code (project ``.mcp.json``) or Claude Desktop:

  {
    "mcpServers": {
      "mcpip": {
        "command": "python3",
        "args": ["scripts/claude_mcp_bridge.py"],
        "env": { "MCPIP_URL": "http://localhost:8080", "MCPIP_TENANT": "mcpip-inc" }
      }
    }
  }

Stdlib only — no third-party deps, so Claude can launch it anywhere Python 3.9+ runs.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any

MCPIP_URL = os.environ.get("MCPIP_URL", "http://localhost:8080").rstrip("/")
MCPIP_TENANT = os.environ.get("MCPIP_TENANT", "tenant-acme")
# Vendor-prefixed by convention (vendor is part of the agent id), so every decision in
# the WORM ledger / live feed is attributed to its framework out of the box.
MCPIP_AGENT = os.environ.get("MCPIP_AGENT", "anthropic-claude")
MCPIP_TOKEN_ENV = os.environ.get("MCPIP_TOKEN")

# Methods that must carry the Bearer JWT (the authorizing calls). ``initialize`` and
# ``notifications/initialized`` are unauthenticated on the MCPIP edge.
_AUTHED_METHODS = frozenset({"tools/list", "tools/call"})

# A single cached token, minted lazily and re-minted PROACTIVELY before it expires.
# Reactive retry-on-deny is deliberately avoided: a deny is opaque (-32000 whether the
# cause is an expired token or a real policy deny), so retrying would double-count every
# legitimate deny as two WORM events. Proactive refresh by the JWT's own exp is exact.
_token: str | None = MCPIP_TOKEN_ENV
_token_exp: float | None = None  # epoch seconds; None = unknown/never expires.
# Re-mint this many seconds before exp (sandbox tokens live ~5 min).
_EXP_SLACK_S = 30.0


def _jwt_exp_seconds(jwt: str) -> float | None:
    """Best-effort decode of a JWT's ``exp`` claim (epoch seconds). None if unreadable."""
    try:
        payload_b64 = jwt.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)  # restore base64 padding
        claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
        exp = claims.get("exp")
        return float(exp) if isinstance(exp, (int, float)) else None
    except (ValueError, IndexError, KeyError):
        return None


def _log(msg: str) -> None:
    """Diagnostics go to stderr — stdout is the JSON-RPC channel and must stay clean."""
    print(f"[mcpip-bridge] {msg}", file=sys.stderr, flush=True)


def _http_post(path: str, body: dict[str, Any], token: str | None = None) -> tuple[int, dict[str, Any]]:
    """POST JSON to the gateway; return (status, parsed-json-or-empty). Never raises."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(f"{MCPIP_URL}{path}", data=data, method="POST")
    req.add_header("content-type", "application/json")
    if token:
        req.add_header("authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return resp.status, (json.loads(raw) if raw.strip() else {})
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8") if exc.fp else ""
        try:
            return exc.code, (json.loads(raw) if raw.strip() else {})
        except ValueError:
            return exc.code, {}
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        _log(f"transport error to {path}: {exc}")
        return 0, {}


def _mint_token() -> str | None:
    """Mint a sandbox JWT for the configured tenant/agent. Returns None if unavailable
    (e.g. a production gateway where /v1/dev/token is 404 — then set MCPIP_TOKEN)."""
    status, payload = _http_post(
        "/v1/dev/token",
        {"tenant_id": MCPIP_TENANT, "agent_id": MCPIP_AGENT, "role": "ops"},
    )
    jwt = payload.get("jwt")
    if status == 200 and isinstance(jwt, str):
        _log(f"minted sandbox token for tenant={MCPIP_TENANT} agent={MCPIP_AGENT}")
        return jwt
    _log(
        "could not mint a sandbox token "
        f"(status={status}). For a production gateway, set MCPIP_TOKEN to a real IdP JWT."
    )
    return None


def _ensure_token() -> str | None:
    """Return a usable token, minting/refreshing PROACTIVELY before it expires (unless a
    real MCPIP_TOKEN was supplied, which is used verbatim and never re-minted)."""
    global _token, _token_exp
    if MCPIP_TOKEN_ENV:
        return MCPIP_TOKEN_ENV
    stale = _token is None or (_token_exp is not None and time.time() >= _token_exp - _EXP_SLACK_S)
    if stale:
        _token = _mint_token()
        _token_exp = _jwt_exp_seconds(_token) if _token else None
    return _token


def _forward(message: dict[str, Any]) -> dict[str, Any]:
    """Forward one JSON-RPC request to MCPIP's /v1/mcp, attaching the JWT when needed.
    Returns the gateway's JSON-RPC response VERBATIM — allow receipt or opaque deny, never
    fabricated, never retried (a deny is final; token freshness is handled proactively)."""
    method = message.get("method")
    token = _ensure_token() if method in _AUTHED_METHODS else None
    status, resp = _http_post("/v1/mcp", message, token=token)

    if status == 0 or not isinstance(resp, dict):
        return {
            "jsonrpc": "2.0",
            "id": message.get("id"),
            "error": {"code": -32001, "message": "MCPIP bridge: gateway unreachable"},
        }
    return resp


def main() -> None:
    _log(f"starting · gateway={MCPIP_URL} · tenant={MCPIP_TENANT} · agent={MCPIP_AGENT}")
    # MCP stdio transport: one JSON-RPC message per line (newline-delimited), no framing.
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            sys.stdout.write(
                json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}) + "\n"
            )
            sys.stdout.flush()
            continue

        # Notifications (no "id") get no response, per JSON-RPC. Forward the
        # initialized notification for symmetry but never write a reply.
        is_notification = "id" not in message
        response = _forward(message)
        if is_notification:
            continue
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
