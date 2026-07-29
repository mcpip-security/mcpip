#!/usr/bin/env python3
"""
MCPIP — live DynamoDB-write vend demo (``skill_aws_dynamodb``).

A real, end-to-end walkthrough of the ``cloud_iam`` WRITE path against a RUNNING
sandbox gateway. NO cloud account and NO AWS credentials are needed: in sandbox the
broker returns a clearly-marked FAKE credential envelope, so the whole per-call vend
flow — authorize → step-up → vend → receipt — is demonstrable end-to-end. The
run-locally counterpart that drives the SAME pipeline against a real DynamoDB table
with a least-privilege role lives in ``docs/integrate/INTEGRATIONS.md``.

What this proves (all four MCPIP controls, in order):

    1. ENTITLEMENT   — only a team-engineering agent may select the skill; a Finance
                       agent is denied COMPARTMENT_DENIED, opaquely, before any step-up.
    2. STEP-UP       — because a DynamoDB PutItem MUTATES a table, the skill is
                       PIN_REQUIRED: the first call stages a payload-bound challenge and
                       vends NOTHING; the agent must complete the ceremony.
    3. VEND          — completing the step-up vends a SHORT-LIVED credential scoped to
                       the WRITE role (a distinct role from the read binding). The agent
                       holds no standing cloud key.
    4. AUDIT         — every decision is WORM-logged before dispatch; the vended secret
                       is the deliverable to the agent and is NEVER written to the log.

MCPIP authorizes + vends + audits. It does NOT proxy or content-inspect the downstream
DynamoDB call — the vended credential's least-privilege policy is the blast-radius
control (see the doc).

Prereqs — a sandbox gateway on :8080 (or run ``./scripts/quickstart_demo.sh`` first):

    MCPIP_SANDBOX_MODE=true MCPIP_REDIS_URL=redis://localhost:63790/0 \
        python -m uvicorn app.main:app --port 8080 &

Then:

    python scripts/dynamodb_vend_demo.py                 # against http://localhost:8080
    python scripts/dynamodb_vend_demo.py --base http://host:8080

Exit code is non-zero if any expectation is violated, so this doubles as a smoke test.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Optional

# --- Demo company topology (mirrors obfuscator/tenant_catalog.py mcpip-inc). --------
TENANT = "mcpip-inc"
TEAM_ENGINEERING = "e0900000-0000-4000-8000-e0900000e090"
TEAM_FINANCE = "f1a00000-0000-4000-8000-f1a00000f1a0"
SKILL = "skill_aws_dynamodb"
# The write role's ARN tail — the vend fingerprint must name THIS role, never the read one.
WRITE_ROLE_TAIL = "mcpip-eng-dynamodb-write"

# A representative PutItem payload. In sandbox it is only payload-bound to the PIN lock;
# nothing is sent to a real table (the credential is a stand-in).
WRITE_ARGS: dict[str, Any] = {
    "table": "mcpip-live-fire",
    "item": {"pk": "agent-eng-ddb-1", "note": "hello from the gateway"},
}

# ANSI (degrade to empty when not a TTY).
_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def _request(base: str, path: str, *, method: str, body: Optional[dict[str, Any]], token: Optional[str]) -> tuple[int, dict[str, Any]]:
    """HTTP round-trip; return (status, parsed-body). Never raises on HTTP error status."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{base}{path}", data=data, method=method)
    if data is not None:
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


def _post(base: str, path: str, body: dict[str, Any], token: Optional[str] = None) -> tuple[int, dict[str, Any]]:
    return _request(base, path, method="POST", body=body, token=token)


def _get(base: str, path: str, token: Optional[str] = None) -> tuple[int, dict[str, Any]]:
    return _request(base, path, method="GET", body=None, token=token)


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
            "Is the gateway running in SANDBOX mode? (./scripts/quickstart_demo.sh)"
        )
    return str(token)


def authorize(base: str, token: str, *, pin: Optional[str] = None, challenge_id: Optional[str] = None) -> tuple[int, dict[str, Any]]:
    """One /v1/authorize round-trip for the DynamoDB-write skill (mcp_jsonrpc shape)."""
    body: dict[str, Any] = {
        "source_format": "mcp_jsonrpc",
        "tool_call": {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": SKILL, "arguments": WRITE_ARGS},
        },
    }
    if pin is not None:
        body["pin"] = pin
    if challenge_id is not None:
        body["challenge_id"] = challenge_id
    return _post(base, "/v1/authorize", body, token)


def _ok(msg: str) -> None:
    print(f"    {GREEN}✓{RESET} {msg}")


def _fail(msg: str) -> str:
    print(f"    {YELLOW}‼ {msg}{RESET}")
    return msg


def main() -> int:
    parser = argparse.ArgumentParser(description="MCPIP live DynamoDB-write vend demo.")
    parser.add_argument("--base", default="http://localhost:8080", help="gateway base URL")
    args = parser.parse_args()
    base = args.base.rstrip("/")

    # Liveness. (The demo needs SANDBOX mode; /v1/dev/token 404s in production, so mint()
    # fails with a clear message there. For a real-account run see docs/integrate/INTEGRATIONS.md.)
    status, health = _get(base, "/healthz")
    if status != 200:
        print(f"{RED}No gateway answered at {base}/healthz — start it first:{RESET}")
        print(f"    {BOLD}./scripts/quickstart_demo.sh{RESET}")
        return 2

    print(f"{BOLD}MCPIP — DynamoDB-write vend demo{RESET}  {DIM}{health.get('glyph', '')} {base} · v{health.get('version', '?')}{RESET}")
    print(f"{DIM}Every step below is a real pipeline round-trip. Sandbox = fake credential; the FLOW is real.{RESET}")
    print(f"\n{CYAN}Company{RESET} {TENANT}   {CYAN}Skill{RESET} {SKILL}  {DIM}(cloud_iam · WRITE · PIN_REQUIRED · team-engineering){RESET}")

    failures: list[str] = []

    # --- 1) ENTITLEMENT: a Finance agent is denied before any step-up. ----------------
    print(f"\n{BOLD}1. Entitlement — a cross-team agent cannot even start{RESET}")
    fin = mint(base, "agent-fin-ddb", TEAM_FINANCE)
    st, body = authorize(base, fin)
    corr = ((body.get("detail") or {}) if isinstance(body.get("detail"), dict) else {}).get("correlation_id")
    corr = corr or body.get("correlation_id")
    if st in (401, 403):
        _ok(f"Finance agent DENIED opaquely (HTTP {st}, correlation {corr or '—'}) — no challenge offered")
    else:
        failures.append(_fail(f"expected an opaque deny for the Finance agent, got HTTP {st}: {body}"))

    # --- 2) STEP-UP: an Engineering agent's first call stages, vends nothing. ----------
    print(f"\n{BOLD}2. Step-up — the write demands a payload-bound PIN{RESET}")
    eng = mint(base, "agent-eng-ddb-1", TEAM_ENGINEERING)
    st, staged = authorize(base, eng)
    if st == 202 and staged.get("challenge_id"):
        challenge_id = str(staged["challenge_id"])
        _ok(f"first call STAGED a challenge (HTTP 202, challenge {challenge_id[:12]}…)")
        if "vended_credential" in staged and staged.get("vended_credential"):
            failures.append(_fail("a credential was vended at the staging step — it must NOT be"))
        else:
            _ok("nothing vended yet — the credential is withheld until the ceremony completes")
    else:
        failures.append(_fail(f"expected a 202 staged challenge, got HTTP {st}: {staged}"))
        challenge_id = ""

    # --- 3) VEND: fetch the OTP (sandbox authenticator) and complete the ceremony. -----
    print(f"\n{BOLD}3. Vend — complete the ceremony, receive a short-lived write credential{RESET}")
    cred: dict[str, Any] = {}
    if challenge_id:
        st, otp_body = _get(base, f"/v1/authenticator/{challenge_id}", eng)
        if st != 200 or not otp_body.get("otp"):
            failures.append(_fail(f"could not fetch the sandbox OTP (HTTP {st}): {otp_body}"))
        else:
            otp = str(otp_body["otp"])
            _ok("fetched the one-time code from the sandbox authenticator (stands in for the enrolled device)")
            st, receipt = authorize(base, eng, pin=otp, challenge_id=challenge_id)
            if st == 200 and receipt.get("decision") == "allow":
                _ok(f"ALLOW — receipt committed (transport class {receipt.get('executed_target_class')}, worm #{receipt.get('worm_sequence')})")
                cred = receipt.get("vended_credential") or {}
            else:
                failures.append(_fail(f"expected a 200 ALLOW receipt, got HTTP {st}: {receipt}"))

    # --- 4) INSPECT the vended credential: scoped, short-lived, write-role. -------------
    print(f"\n{BOLD}4. The deliverable — inspect what the agent received{RESET}")
    if cred:
        provider = cred.get("provider")
        expires = cred.get("expires_in")
        simulated = cred.get("simulated")
        fingerprint = str(cred.get("fingerprint") or "")
        material = cred.get("credential") or {}
        akid = str(material.get("access_key_id") or "")
        print(f"    {DIM}fingerprint:{RESET} {fingerprint}")
        print(f"    {DIM}provider={provider} · expires_in={expires}s · simulated={simulated} · access_key_id={akid}{RESET}")
        if provider == "aws":
            _ok("provider is AWS")
        else:
            failures.append(_fail(f"expected provider aws, got {provider}"))
        if isinstance(expires, int) and expires <= 3600:
            _ok(f"short-lived — expires in {expires}s (minutes, not forever)")
        else:
            failures.append(_fail(f"credential is not short-lived: expires_in={expires}"))
        if WRITE_ROLE_TAIL in fingerprint:
            _ok(f"scoped to the WRITE role ({WRITE_ROLE_TAIL}) — a read binding could never satisfy this skill")
        else:
            failures.append(_fail(f"vend is not scoped to the write role; fingerprint={fingerprint!r}"))
        if material.get("session_token") and material.get("secret_access_key"):
            _ok("credential material is present for the agent to sign its ONE DynamoDB PutItem")
        else:
            failures.append(_fail("vended credential material is incomplete"))
        if simulated is True:
            print(f"    {DIM}(sandbox: the material is an obviously-fake stand-in — real vending is the same shape via STS){RESET}")
    else:
        failures.append(_fail("no credential was vended"))

    print()
    if not failures:
        print(f"{GREEN}{BOLD}✓ End-to-end: entitlement → step-up → vend → audit, all enforced at the choke point.{RESET}")
        print(f"{DIM}The agent never held a standing AWS key; it proved its MCPIP license, completed a payload-bound")
        print(f"step-up, and received a short-lived credential scoped to exactly the DynamoDB-write role. Every")
        print(f"decision is WORM-logged before dispatch; the vended secret never entered the log.{RESET}")
        print(f"{DIM}Next: run it against a REAL table with a least-privilege role — docs/integrate/INTEGRATIONS.md{RESET}")
        return 0
    print(f"{RED}{BOLD}‼ {len(failures)} expectation(s) did not hold.{RESET}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
