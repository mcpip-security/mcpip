#!/usr/bin/env python3
"""
MCPIP — live MCP connector in the terminal.

An interactive MCP **client** session against a running gateway, speaking the same
JSON-RPC protocol every MCP host (Claude Code, IDEs, agent frameworks) speaks:

    initialize → notifications/initialized → tools/list → tools/call

Every line is a REAL round-trip through the zero-trust pipeline — the tools you see
are what YOUR identity may enumerate, a call either commits (WORM-logged) or comes
back as the opaque deny an agent actually experiences. Nothing is simulated.

    python scripts/mcp_terminal.py                      # connect to :8080, then type commands
    python scripts/mcp_terminal.py --base http://host:8080
    echo "login agent-eng-1 engineering\ntools\ncall skill_company_overview" | \
        python scripts/mcp_terminal.py                  # scriptable (reads stdin)

Commands:
    login <agent-id> [team]   mint a sandbox identity (teams of the demo company:
                              engineering · finance) — production agents bring an
                              IdP-minted license instead
    tools                     tools/list — what THIS identity can enumerate
    call <tool> [json-args]   tools/call — one real authorization
    whoami · help · exit

Sandbox-only convenience: identity minting uses POST /v1/dev/token, which 404s in
production (identity is IdP-sovereign) — there, export MCPIP_TOKEN instead and the
client uses it as-is.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Optional

# Demo company topology (mirrors obfuscator/tenant_catalog.py `mcpip-inc`).
DEFAULT_TENANT = "mcpip-inc"
TEAMS: dict[str, str] = {
    "engineering": "e0900000-0000-4000-8000-e0900000e090",
    "finance": "f1a00000-0000-4000-8000-f1a00000f1a0",
}

_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""

PROMPT = f"{CYAN}mcp❯{RESET} "


def _post(base: str, path: str, body: dict[str, Any], token: Optional[str] = None) -> tuple[int, dict[str, Any]]:
    """POST JSON; return (status, parsed body). HTTP errors return their status, never raise."""
    req = urllib.request.Request(f"{base}{path}", data=json.dumps(body).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except Exception:  # noqa: BLE001
            return exc.code, {}


class McpSession:
    """One live MCP client session: a connected base + the current identity."""

    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/")
        self.token: Optional[str] = os.environ.get("MCPIP_TOKEN") or None
        self.identity: str = "(env MCPIP_TOKEN)" if self.token else "(none)"
        self._rpc_id = 0

    # -- MCP JSON-RPC --------------------------------------------------------
    def rpc(self, method: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        self._rpc_id += 1
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self._rpc_id, "method": method}
        if params is not None:
            body["params"] = params
        _, resp = _post(self.base, "/v1/mcp", body, self.token)
        return resp

    def initialize(self) -> Optional[dict[str, Any]]:
        """The MCP handshake, exactly as a host performs it."""
        resp = self.rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "mcpip-terminal", "version": "1.0"}})
        result = resp.get("result")
        if not isinstance(result, dict):
            return None
        # Fire-and-forget per spec; the gateway answers 202.
        _post(self.base, "/v1/mcp", {"jsonrpc": "2.0", "method": "notifications/initialized"}, self.token)
        return result

    # -- identity -------------------------------------------------------------
    def login(self, agent_id: str, team: Optional[str], tenant: str) -> Optional[str]:
        """Mint a sandbox identity (production: bring an IdP license via MCPIP_TOKEN)."""
        claims: dict[str, Any] = {"tenant_id": tenant, "agent_id": agent_id}
        label = f"{agent_id} @ {tenant}"
        if team:
            compartment = TEAMS.get(team.lower())
            if compartment is None:
                return f"unknown team '{team}' — known: {' · '.join(TEAMS)}"
            claims["compartment"] = compartment
            label += f" · team {team.lower()}"
        status, body = _post(self.base, "/v1/dev/token", claims)
        token = body.get("jwt") or body.get("token")
        if status != 200 or not isinstance(token, str):
            return "mint unavailable — production gateways never mint; export MCPIP_TOKEN with an IdP-issued license"
        self.token = token
        self.identity = label
        return None


def cmd_tools(s: McpSession) -> None:
    resp = s.rpc("tools/list")
    if "error" in resp:
        err = resp["error"]
        corr = (err.get("data") or {}).get("correlation_id", "—")
        print(f"{RED}✕ {err.get('message', 'denied')}{RESET} {DIM}· correlation {corr}{RESET}")
        return
    tools = (resp.get("result") or {}).get("tools") or []
    if not tools:
        print(f"{DIM}this identity enumerates nothing{RESET}")
        return
    print(f"{GREEN}✓ {len(tools)} tool(s) visible to {s.identity}{RESET}")
    for t in tools:
        print(f"  {BOLD}{t.get('name')}{RESET}  {DIM}{t.get('description', '')}{RESET}")
    print(f"{DIM}  anything not listed is invisible to this identity — not merely forbidden.{RESET}")


def cmd_call(s: McpSession, tool: str, raw_args: str) -> None:
    try:
        arguments = json.loads(raw_args) if raw_args.strip() else {}
    except ValueError:
        print(f"{RED}arguments must be JSON, e.g. call {tool} {{\"period\":\"Q3\"}}{RESET}")
        return
    resp = s.rpc("tools/call", {"name": tool, "arguments": arguments})
    if "error" in resp:
        err = resp["error"]
        corr = (err.get("data") or {}).get("correlation_id", "—")
        print(f"{RED}✕ DENY — \"{err.get('message', '')}\"{RESET}")
        print(f"{DIM}  correlation {corr} · the concrete reason lives only in the WORM ledger.{RESET}")
        return
    result = resp.get("result") or {}
    content = result.get("content") or []
    text = next((c.get("text") for c in content if isinstance(c, dict) and c.get("type") == "text"), None)
    print(f"{GREEN}✓ ALLOW — committed through the pipeline (WORM-logged before dispatch){RESET}")
    # cloud_iam skills return a short-lived, scoped credential — highlight it (the whole
    # point: the agent never held a standing cloud key, this was vended for THIS call).
    receipt = {}
    if text:
        try:
            receipt = json.loads(text)
        except ValueError:
            receipt = {}
    vended = receipt.get("vended_credential") if isinstance(receipt, dict) else None
    if isinstance(vended, dict):
        tag = " (SANDBOX — fake)" if vended.get("simulated") else ""
        print(f"{CYAN}  ⛅ vended cloud credential{tag}:{RESET} {vended.get('fingerprint', '')}")
        cred = vended.get("credential") or {}
        akid = cred.get("access_key_id", "")
        print(f"{DIM}     {vended.get('provider')} · {vended.get('region')} · expires in {vended.get('expires_in')}s · key {akid}{RESET}")
        print(f"{DIM}     the agent uses this directly, then it expires — no standing key ever existed.{RESET}")
    elif text:
        print(f"{DIM}  {text}{RESET}")


HELP = f"""{BOLD}commands{RESET}
  login <agent-id> [team]   mint an identity (teams: {' · '.join(TEAMS)})
  tools                     tools/list — what THIS identity can enumerate
  call <tool> [json-args]   tools/call — one real authorization
  whoami · help · exit"""


def main() -> int:
    parser = argparse.ArgumentParser(description="Live MCP connector session in the terminal.")
    parser.add_argument("--base", default="http://localhost:8080", help="gateway base URL")
    parser.add_argument("--tenant", default=DEFAULT_TENANT, help=f"tenant for login (default {DEFAULT_TENANT})")
    args = parser.parse_args()

    session = McpSession(args.base)
    server = session.initialize()
    if server is None:
        print(f"{RED}no MCP server answered at {session.base}/v1/mcp{RESET} — start one: ./scripts/quickstart_demo.sh")
        return 2
    info = server.get("serverInfo") or {}
    print(f"{BOLD}◐ connected{RESET} — {info.get('name', '?')} v{info.get('version', '?')} · MCP {server.get('protocolVersion', '?')} · {session.base}")
    print(f"{DIM}the same handshake Claude Code performs · every command is a real round-trip{RESET}")
    print(HELP)

    interactive = sys.stdin.isatty()
    while True:
        try:
            if interactive:
                line = input(PROMPT)
            else:
                line = input()
                print(f"{PROMPT}{line}")  # echo piped commands so transcripts read naturally
        except (EOFError, KeyboardInterrupt):
            # Ctrl-C / Ctrl-D exit the session cleanly — never a traceback.
            print()
            break
        parts = line.strip().split(maxsplit=2)
        if not parts:
            continue
        verb = parts[0].lower()
        if verb in {"exit", "quit"}:
            break
        elif verb == "help":
            print(HELP)
        elif verb == "whoami":
            print(f"{session.identity}")
        elif verb == "login":
            if len(parts) < 2:
                print(f"{RED}usage: login <agent-id> [team]{RESET}")
                continue
            err = session.login(parts[1], parts[2] if len(parts) > 2 else None, args.tenant)
            if err:
                print(f"{RED}{err}{RESET}")
            else:
                print(f"{GREEN}✓ licensed{RESET} {session.identity} {DIM}· token held in memory only{RESET}")
        elif verb == "tools":
            cmd_tools(session)
        elif verb == "call":
            if len(parts) < 2:
                print(f"{RED}usage: call <tool> [json-args]{RESET}")
                continue
            cmd_call(session, parts[1], parts[2] if len(parts) > 2 else "")
        else:
            print(f"{YELLOW}unknown command '{verb}' — try 'help'{RESET}")

    print(f"{DIM}session closed.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
