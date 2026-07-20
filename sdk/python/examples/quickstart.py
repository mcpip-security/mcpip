#!/usr/bin/env python3
"""
mcpip-sdk quickstart — the agent surface end to end against a SANDBOX gateway.

Start the gateway first (Redis on :63790, then)::

    MCPIP_SANDBOX_MODE=true uvicorn app.main:app --port 8080

then run::

    python sdk/python/examples/quickstart.py [http://localhost:8080]

Everything below is REAL traffic: a minted sandbox identity, a live catalog
read, an authorized call with its audit receipt, an opaque denial, and the
full PIN step-up ceremony (stage → sandbox authenticator OTP → complete).
"""

from __future__ import annotations

import os
import sys

try:
    from mcpip_sdk import Allowed, MCPIPDenied, SandboxClient, Staged
except ImportError:  # running from the repo without `pip install mcpip-sdk`.
    sys.path.insert(
        0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
    )
    from mcpip_sdk import Allowed, MCPIPDenied, SandboxClient, Staged


def main() -> int:
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"

    with SandboxClient(base_url) as client:
        # 1) Connectivity — /healthz is unauthenticated and never shed.
        health = client.health()
        print(f"gateway  : {base_url}  v{health.version}  loop={health.loop}")

        # 2) Identity — SANDBOX ONLY. In production your IdP mints the JWT and
        #    you pass it (or a refresh callback) to the client instead.
        client.set_token(lambda: client.dev_token(agent_id="agent-quickstart"))

        # 3) What may this identity even see? Metadata only — never targets.
        items = client.catalog()
        print(f"catalog  : {len(items)} aliases visible")
        for item in items[:5]:
            print(f"           {item.alias}  [{item.risk_tier}]")

        # 4) An AUTO-tier call: authorized, audit-logged, dispatched — one POST.
        outcome = client.authorize("skill_spend_summary", {"period": "2026-Q2"})
        assert isinstance(outcome, Allowed)
        print(f"allowed  : {outcome.transaction_ref}  worm#{outcome.worm_sequence}")

        # 5) A denial is OPAQUE: no reason, only a correlation id an operator
        #    can resolve against the WORM audit log. Never retry a deny.
        try:
            client.authorize("skill_export_everything", {})
        except MCPIPDenied as denied:
            print(f"denied   : correlation_id={denied.correlation_id} (opaque by design)")

        # 6) The PIN ceremony on a pin_required alias: stage → OTP → complete.
        staged = client.authorize("skill_payroll_run", {"run_id": "QS-1"})
        assert isinstance(staged, Staged)
        print(f"staged   : challenge={staged.challenge_id}  ttl={staged.expires_in}s")
        otp = client.authenticator_code(staged.challenge_id)  # sandbox stand-in
        receipt = client.complete(staged, otp)                # identical payload
        print(f"stepped  : {receipt.transaction_ref}  worm#{receipt.worm_sequence}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
