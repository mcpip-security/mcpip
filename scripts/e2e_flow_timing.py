#!/usr/bin/env python3
"""
MCPIP — end-to-end flow TIMING harness.

Answers "how long does the full flow take?" for each way a client reaches the
gateway — as an app (MCP), the SDK, the CLI; as a plain user and as an admin —
including token issuance and evidence (forensic payload) reconstruction. Every
number is a real wall-clock measurement against a RUNNING sandbox gateway; no
segment is estimated.

Run (sandbox gateway on :8080, forensic capture on):

    redis-server --port 63790 &
    MCPIP_SANDBOX_MODE=true MCPIP_FORENSIC_CAPTURE=true \
      MCPIP_REDIS_URL=redis://localhost:63790/2 uvicorn app.main:app --port 8080 &
    python scripts/e2e_flow_timing.py --base http://localhost:8080 --iters 25

Prints a per-segment table (p50 / mean / p95 ms) and per-persona totals, and
writes the raw results to --json for downstream review. Best-effort: a segment
that can't run reports "n/a" with the reason instead of aborting the run.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Optional

_REPO = Path(__file__).resolve().parent.parent
# Import the REAL capability UUIDs so the admin token carries genuine caps.
try:
    from interfaces import CAP_DIRECTORY_ADMIN, CAP_FORENSIC_READ  # type: ignore
except Exception:  # noqa: BLE001
    CAP_DIRECTORY_ADMIN = CAP_FORENSIC_READ = None  # harness still runs the user segments

TENANT = "mcpip-inc"
TEAM_ENGINEERING = "e0900000-0000-4000-8000-e0900000e090"


# --------------------------------------------------------------------------- http
def _req(method: str, url: str, body: Optional[dict[str, Any]], token: Optional[str]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if body is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except Exception:  # noqa: BLE001
            return exc.code, {}


def mint(base: str, agent_id: str, compartment: Optional[str], caps: Optional[list[str]]) -> Optional[str]:
    claims: dict[str, Any] = {"tenant_id": TENANT, "agent_id": agent_id}
    if compartment:
        claims["compartment"] = compartment
    if caps:
        claims["capabilities"] = caps
    status, body = _req("POST", f"{base}/v1/dev/token", claims, None)
    if status != 200:
        return None
    return body.get("jwt") or body.get("token")


def mcp_call(base: str, token: str, name: str) -> tuple[bool, Optional[str]]:
    _, body = _req(
        "POST", f"{base}/v1/mcp",
        {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {}}},
        token,
    )
    if "result" in body:
        return True, None
    corr = ((body.get("error") or {}).get("data") or {}).get("correlation_id")
    return False, corr


# --------------------------------------------------------------------------- timing
def timed(fn: Callable[[], Any], iters: int) -> dict[str, Any]:
    """Run fn iters times; return {p50, mean, p95, ms:[...], ok, note}."""
    samples: list[float] = []
    last: Any = None
    for _ in range(iters):
        t0 = time.perf_counter()
        try:
            last = fn()
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "note": f"error: {type(exc).__name__}: {exc}"}
        samples.append((time.perf_counter() - t0) * 1000.0)
    samples.sort()
    return {
        "ok": True,
        "p50": round(statistics.median(samples), 1),
        "mean": round(statistics.fmean(samples), 1),
        "p95": round(samples[min(len(samples) - 1, int(len(samples) * 0.95))], 1),
        "n": len(samples),
        "last": last,
    }


def one(fn: Callable[[], Any]) -> dict[str, Any]:
    return timed(fn, 1)


# --------------------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser(description="MCPIP end-to-end flow timing.")
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--iters", type=int, default=25)
    ap.add_argument("--json", default="")
    args = ap.parse_args()
    base = args.base.rstrip("/")
    n = args.iters
    results: dict[str, Any] = {}

    # Readiness.
    st, _ = _req("GET", f"{base}/healthz", None, None)
    if st != 200:
        print(f"gateway not healthy at {base} (status {st}). Is the sandbox gateway up?", file=sys.stderr)
        return 2

    # --- tokens ---------------------------------------------------------------
    results["token_mint_user"] = timed(lambda: mint(base, "agent-timing", None, None), n)
    admin_caps = [c for c in (CAP_DIRECTORY_ADMIN, CAP_FORENSIC_READ) if c]
    results["token_mint_admin"] = timed(lambda: mint(base, "admin-timing", None, admin_caps or None), n)

    user_token = mint(base, "agent-timing", None, None)
    eng_token = mint(base, "agent-eng", TEAM_ENGINEERING, None)
    admin_token = mint(base, "admin-timing", None, admin_caps or None)

    # --- user via app (MCP) ---------------------------------------------------
    if user_token:
        results["user_mcp_allow"] = timed(lambda: mcp_call(base, user_token, "skill_company_overview"), n)
    if eng_token:
        results["user_mcp_deny"] = timed(lambda: mcp_call(base, eng_token, "skill_financial_wage_sheet"), n)

    # --- admin init: first admin read ----------------------------------------
    if admin_token:
        results["admin_stats"] = timed(lambda: _req("GET", f"{base}/v1/admin/stats", None, admin_token), n)
        results["admin_decisions_recent"] = timed(
            lambda: _req("GET", f"{base}/v1/admin/decisions/recent", None, admin_token), n
        )
    else:
        results["admin_init"] = {"ok": False, "note": "no admin caps importable from interfaces"}

    # --- WORM attestation -----------------------------------------------------
    results["worm_attestation"] = timed(lambda: _req("GET", f"{base}/v1/audit/attestation", None, admin_token), n)
    results["worm_verify"] = timed(lambda: _req("GET", f"{base}/v1/audit/verify", None, admin_token), n)

    # --- evidence reconstruction (forensic) -----------------------------------
    # Generate a captured event (a deny exposes its correlation_id), then have the
    # CAP_FORENSIC_READ admin reconstruct the full payload from it.
    corr = None
    if eng_token:
        _, corr = mcp_call(base, eng_token, "skill_financial_wage_sheet")
    if corr and admin_token:
        def reconstruct() -> tuple[int, dict[str, Any]]:
            return _req("GET", f"{base}/v1/admin/forensic/{corr}", None, admin_token)
        r = one(reconstruct)
        st_f = (r.get("last") or (None, None))[0] if r.get("ok") else None
        if r.get("ok") and st_f == 200:
            results["evidence_reconstruct"] = timed(reconstruct, max(5, n // 3))
        else:
            results["evidence_reconstruct"] = {"ok": False, "note": f"forensic GET status={st_f} (capture off / not admin?)"}
    else:
        results["evidence_reconstruct"] = {"ok": False, "note": "no correlation_id or admin token"}

    # --- SDK (in-process) -----------------------------------------------------
    sdk_src = _REPO / "sdk" / "python" / "src"
    if sdk_src.is_dir():
        sys.path.insert(0, str(sdk_src))
    try:
        from mcpip_sdk import MCPIPClient  # type: ignore
        if user_token:
            def sdk_call() -> Any:
                client = MCPIPClient(base_url=base, token=user_token)
                try:
                    return client.authorize("skill_company_overview", arguments={})
                except Exception:  # noqa: BLE001 — deny raises in some SDK versions; that's a valid timed op
                    return None
            results["sdk_authorize"] = timed(sdk_call, n)
    except Exception as exc:  # noqa: BLE001
        results["sdk_authorize"] = {"ok": False, "note": f"SDK import failed: {type(exc).__name__}"}

    # --- CLI (subprocess, best-effort) ---------------------------------------
    cli = None
    for cand in (["mcpip"], [sys.executable, "-m", "mcpip_sdk.cli"]):
        try:
            p = subprocess.run(cand + ["version"], capture_output=True, timeout=20,
                               cwd=str(_REPO), env={**__import__("os").environ, "PYTHONPATH": str(sdk_src)})
            if p.returncode in (0, 1):  # 1 = ran but gateway unreachable; the binary resolved
                cli = cand
                break
        except Exception:  # noqa: BLE001
            continue
    if cli:
        def cli_health() -> int:
            p = subprocess.run(cli + ["health", "--gateway", base], capture_output=True, timeout=20,
                               cwd=str(_REPO), env={**__import__("os").environ, "PYTHONPATH": str(sdk_src)})
            return p.returncode
        results["cli_health"] = timed(cli_health, max(5, n // 5))
    else:
        results["cli_health"] = {"ok": False, "note": "mcpip CLI not resolvable"}

    # --- report ---------------------------------------------------------------
    print("\n◐ MCPIP end-to-end flow timing  (sandbox, " + base + ")")
    print("-" * 74)
    print(f"{'segment':<26}{'p50 ms':>9}{'mean':>9}{'p95':>9}   note")
    print("-" * 74)
    order = [
        "token_mint_user", "token_mint_admin", "user_mcp_allow", "user_mcp_deny",
        "admin_stats", "admin_decisions_recent", "evidence_reconstruct",
        "worm_attestation", "worm_verify", "sdk_authorize", "cli_health",
    ]
    for k in order:
        r = results.get(k)
        if not r:
            continue
        if r.get("ok"):
            print(f"{k:<26}{r['p50']:>9}{r['mean']:>9}{r['p95']:>9}   {r.get('n', '')} samples")
        else:
            print(f"{k:<26}{'n/a':>9}{'':>9}{'':>9}   {r.get('note', '')}")
    print("-" * 74)

    # Per-persona end-to-end (sum of the segments a persona actually performs).
    def p50(k: str) -> Optional[float]:
        r = results.get(k)
        return r["p50"] if r and r.get("ok") else None

    def total(parts: list[str]) -> Optional[float]:
        vals = [p50(k) for k in parts]
        return round(sum(v for v in vals if v is not None), 1) if all(v is not None for v in vals) else None

    personas = {
        "user · app (MCP)": ["token_mint_user", "user_mcp_allow"],
        "user · SDK": ["token_mint_user", "sdk_authorize"],
        "admin · init": ["token_mint_admin", "admin_stats"],
        "admin · reconstruct evidence": ["token_mint_admin", "admin_decisions_recent", "evidence_reconstruct"],
    }
    print("per-persona end-to-end (p50 sum):")
    for label, parts in personas.items():
        t = total(parts)
        print(f"  {label:<32}{(str(t) + ' ms') if t is not None else 'n/a'}")
    print("-" * 74)

    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=2, default=str))
        print(f"raw results → {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
