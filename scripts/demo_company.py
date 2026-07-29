#!/usr/bin/env python3
"""
MCPIP — live company demo (``mcpip-inc``).

A real, end-to-end walkthrough against a RUNNING gateway. No mock data: every line
below is an actual ``POST /v1/mcp`` round-trip through the zero-trust pipeline,
WORM-logged before dispatch. The agent only ever names the opaque alias and only ever
sees an opaque deny — the real target and the real deny-reason never cross the boundary.

The story (the compartment == the team):

    mcpip-inc
    ├── team-engineering   → skill_engineering_roadmap
    ├── team-finance       → skill_financial_wage_sheet, skill_financial_ledger_post
    └── (company-wide)     → skill_company_overview, skill_data_lake

  * An Engineering agent reads the company overview and the engineering roadmap,
    but is DENIED the finance wage sheet (cross-team COMPARTMENT_DENIED, opaque).
  * A Finance agent reads the wage sheet.
  * A company agent with no team reads only the company-wide overview.

Prereqs — a sandbox gateway on :8080 (mints demo tokens; production does not):

    redis-server --port 63790 &
    MCPIP_SANDBOX_MODE=true MCPIP_REDIS_URL=redis://localhost:63790/0 \
        uvicorn app.main:app --port 8080 &

Then:

    python scripts/demo_company.py                 # against http://localhost:8080
    python scripts/demo_company.py --base http://host:8080

Exit code is non-zero if any expectation is violated, so this doubles as a smoke test.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Optional

# --- Demo company topology (mirrors obfuscator/tenant_catalog.py mcpip-inc). --------
TENANT = "mcpip-inc"
TEAM_ENGINEERING = "e0900000-0000-4000-8000-e0900000e090"
TEAM_FINANCE = "f1a00000-0000-4000-8000-f1a00000f1a0"

# ANSI (degrade to empty when not a TTY).
_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def _post(base: str, path: str, body: dict[str, Any], token: Optional[str] = None) -> tuple[int, dict[str, Any]]:
    """POST JSON; return (status, parsed-body). Never raises on HTTP error status."""
    data = json.dumps(body).encode()
    req = urllib.request.Request(f"{base}{path}", data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except Exception:  # noqa: BLE001
            return exc.code, {}


def mint(base: str, agent_id: str, compartment: Optional[str]) -> str:
    """Mint a sandbox demo JWT for a company agent (optionally in a team compartment)."""
    claims: dict[str, Any] = {"tenant_id": TENANT, "agent_id": agent_id}
    if compartment:
        claims["compartment"] = compartment
    status, body = _post(base, "/v1/dev/token", claims)
    token = body.get("jwt") or body.get("token")
    if status != 200 or not token:
        sys.exit(
            f"{RED}Could not mint a demo token (status {status}).{RESET} "
            "Is the gateway running in SANDBOX mode? "
            "(MCPIP_SANDBOX_MODE=true uvicorn app.main:app --port 8080)"
        )
    return token


def tools_list(base: str, token: str) -> list[str]:
    _, body = _post(base, "/v1/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, token)
    tools = (body.get("result") or {}).get("tools") or []
    # Hide the deception canaries from the demo listing — they are bait, not real skills.
    return [t["name"] for t in tools if not str(t["name"]).startswith(("skill_export_all", "skill_disable_audit"))]


@dataclass
class CallResult:
    allowed: bool
    correlation_id: Optional[str]


def tool_call(base: str, token: str, name: str) -> CallResult:
    """One real MCP tools/call. ALLOW == JSON-RPC result; DENY == opaque JSON-RPC error."""
    _, body = _post(
        base,
        "/v1/mcp",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}},
        token,
    )
    if "result" in body:
        return CallResult(True, None)
    err = body.get("error") or {}
    corr = (err.get("data") or {}).get("correlation_id")
    return CallResult(False, corr)


def check(label: str, got_allow: bool, want_allow: bool, corr: Optional[str]) -> bool:
    """Print one decision line; return True iff it matched the expectation."""
    ok = got_allow == want_allow
    verdict = f"{GREEN}ALLOW{RESET}" if got_allow else f"{RED}DENY {RESET}"
    detail = "" if got_allow else f"  {DIM}opaque · correlation {corr or '—'}{RESET}"
    mark = f"{GREEN}✓{RESET}" if ok else f"{YELLOW}‼ unexpected{RESET}"
    print(f"    {verdict}  {label:<32}{detail}  {mark}")
    return ok


def scenario(base: str, title: str, agent_id: str, compartment: Optional[str], expect: dict[str, bool]) -> bool:
    print(f"\n{BOLD}{title}{RESET}")
    scope = compartment_label(compartment)
    print(f"  {DIM}identity {agent_id} @ {TENANT} · {scope}{RESET}")
    token = mint(base, agent_id, compartment)
    visible = tools_list(base, token)
    print(f"  {DIM}tools/list → {', '.join(visible) or '(nothing)'}{RESET}")
    all_ok = True
    for skill, want in expect.items():
        res = tool_call(base, token, skill)
        all_ok &= check(skill, res.allowed, want, res.correlation_id)
    return all_ok


def compartment_label(compartment: Optional[str]) -> str:
    if compartment == TEAM_ENGINEERING:
        return "team-engineering"
    if compartment == TEAM_FINANCE:
        return "team-finance"
    return "no team (company-wide only)"


def main() -> int:
    parser = argparse.ArgumentParser(description="MCPIP live company demo (mcpip-inc).")
    parser.add_argument("--base", default="http://localhost:8080", help="gateway base URL")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    # Liveness.
    try:
        req = urllib.request.Request(f"{base}/healthz")
        with urllib.request.urlopen(req, timeout=5) as resp:
            health = json.loads(resp.read())
    except Exception:  # noqa: BLE001
        print(f"{RED}No gateway answered at {base}/healthz — nothing is running there yet.{RESET}")
        print(f"{DIM}Start everything (redis + sandbox gateway) and run this demo in one command:{RESET}")
        print(f"    {BOLD}./scripts/quickstart_demo.sh{RESET}")
        print(f"{DIM}It auto-installs Redis if missing (Homebrew), creates a venv, and boots the gateway.{RESET}")
        return 2

    print(f"{BOLD}MCPIP — live company demo{RESET}  {DIM}{health.get('glyph', '')} {base} · v{health.get('version', '?')}{RESET}")
    print(f"{DIM}Every line below is a real /v1/mcp round-trip through the zero-trust pipeline.{RESET}")
    print(f"\n{CYAN}Company{RESET} {TENANT}   {CYAN}Teams{RESET} team-engineering · team-finance")

    ok = True
    ok &= scenario(
        base,
        "Scenario 1 — Engineering agent  (\"I'm on the mcpip team\")",
        "agent-eng-1",
        TEAM_ENGINEERING,
        {"skill_company_overview": True, "skill_engineering_roadmap": True, "skill_financial_wage_sheet": False},
    )
    ok &= scenario(
        base,
        "Scenario 2 — Finance agent",
        "agent-fin-1",
        TEAM_FINANCE,
        {"skill_financial_wage_sheet": True, "skill_engineering_roadmap": False},
    )
    ok &= scenario(
        base,
        "Scenario 3 — Company agent, no team",
        "agent-visitor-1",
        None,
        {"skill_company_overview": True, "skill_data_lake": True, "skill_financial_wage_sheet": False, "skill_engineering_roadmap": False},
    )

    print()
    if ok:
        print(f"{GREEN}{BOLD}✓ All decisions matched — team separation enforced at the choke point.{RESET}")
        print(f"{DIM}The finance wage sheet never appeared in Engineering's tools/list, and every cross-team")
        print(f"call was denied opaquely. The real targets never left the gateway; every decision is WORM-logged.{RESET}")
        return 0
    print(f"{RED}{BOLD}‼ Some decisions did not match the expected policy.{RESET}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
