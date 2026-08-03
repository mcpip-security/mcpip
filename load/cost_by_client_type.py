#!/usr/bin/env python3
"""
MCPIP — what one governed step costs each client type, measured.

Regenerates the cost table in ``docs/evidence/LOAD_AT_SCALE.md``. Bytes are ground
truth (the exact request and response bodies on the wire); the token columns are an
estimate at 4 bytes/token, the standard ``cl100k`` rule of thumb, and JSON tokenizes
somewhat worse than prose — so treat them as a FLOOR, not a figure.

Discipline, matching the k6 suite:

  * Tokens are SUPPLIED, never minted here. MCPIP never issues identity, so a
    measurement harness must not either. Mint with ``scripts/mint_principal.py``.
  * Every row records the status code it actually got. A ``pin_required`` alias
    that answers ``403`` instead of ``202`` is a *different measurement* (no OTP
    sink / no enrolled authenticator) and is labelled as one — never as a staged
    step-up, whose response is a challenge envelope more than twice the size.
  * ``--repeat`` runs each row N times and reports the median wall clock; a single
    sample of a network call is noise.

Usage::

    export MCPIP_BASE=http://127.0.0.1:8080
    export MCPIP_AGENT_TOKEN=...      # no capability
    export MCPIP_DEV_TOKEN=...        # no capability
    export MCPIP_ADMIN_TOKEN=...      # CAP_DIRECTORY_ADMIN
    python load/cost_by_client_type.py --allow-alias cf.d1.databases.list \\
                                       --stepup-alias cf.d1.query
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from typing import Any

BYTES_PER_TOKEN = 4


def _call(
    base: str, method: str, path: str, token: str, body: dict[str, Any] | None
) -> tuple[int, int, int, float]:
    """One request. Returns (status, request bytes, response bytes, milliseconds)."""
    raw = json.dumps(body, separators=(",", ":")).encode() if body is not None else None
    req = urllib.request.Request(f"{base}{path}", data=raw, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if raw is not None:
        req.add_header("Content-Type", "application/json")
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(req) as resp:
            payload = resp.read()
            status = resp.status
    except urllib.error.HTTPError as exc:  # a deny is a measurement, not an error
        payload = exc.read()
        status = exc.code
    elapsed_ms = (time.perf_counter() - started) * 1000
    return status, len(raw or b""), len(payload), elapsed_ms


def _tools_call(alias: str, args: dict[str, Any], call_id: int) -> dict[str, Any]:
    return {
        "vendor": "claude_code",
        "tool_call": {
            "jsonrpc": "2.0",
            "id": call_id,
            "method": "tools/call",
            "params": {"name": alias, "arguments": args},
        },
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", default=os.environ.get("MCPIP_BASE", "http://127.0.0.1:8080"))
    p.add_argument("--allow-alias", required=True, help="an `auto` risk-tier alias")
    p.add_argument("--stepup-alias", required=True, help="a `pin_required` risk-tier alias")
    p.add_argument("--unknown-alias", default="never.registered.alias")
    p.add_argument("--repeat", type=int, default=5)
    p.add_argument("--markdown", action="store_true", help="emit the docs table")
    args = p.parse_args(argv)

    tokens = {
        "agent": os.environ.get("MCPIP_AGENT_TOKEN", ""),
        "developer": os.environ.get("MCPIP_DEV_TOKEN", ""),
        "operator": os.environ.get("MCPIP_ADMIN_TOKEN", ""),
    }
    missing = [name for name, value in tokens.items() if not value]
    if missing:
        print(
            f"supply {', '.join('MCPIP_' + n.upper() + '_TOKEN' for n in missing)} — "
            "this harness never mints identity",
            file=sys.stderr,
        )
        return 2

    steps: list[tuple[str, str, str, str, str, dict[str, Any] | None]] = [
        ("agent", "authorize · allow", "agent", "POST", "/v1/authorize",
         _tools_call(args.allow_alias, {}, 1)),
        ("agent", "authorize · step-up staged", "agent", "POST", "/v1/authorize",
         _tools_call(args.stepup_alias, {"sql": "DROP TABLE customers"}, 2)),
        ("agent", "authorize · deny", "agent", "POST", "/v1/authorize",
         _tools_call(args.unknown_alias, {}, 3)),
        ("developer", "`POST /v1/mcp` tools/list", "developer", "POST", "/v1/mcp",
         {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}),
        ("developer", "`GET /v1/catalog`", "developer", "GET", "/v1/catalog", None),
        # ``subject`` is advisory echo only — identity comes solely from the JWT — but
        # the AuthZEN 1.0 body requires the field, so it is sent and ignored.
        ("pdp", "authz decision", "agent", "POST", "/v1/authz/decision",
         {"subject": {"id": "agent"}, "resource": {"id": args.allow_alias},
          "action": {"properties": {}}}),
        ("operator", "decisions/recent (25)", "operator", "GET",
         "/v1/admin/decisions/recent?limit=25", None),
        ("operator", "admin/stats", "operator", "GET", "/v1/admin/stats", None),
        ("auditor", "audit/attestation", "operator", "GET", "/v1/audit/attestation", None),
    ]

    rows: list[dict[str, Any]] = []
    for client, label, token_name, method, path, body in steps:
        samples = [
            _call(args.base, method, path, tokens[token_name], body)
            for _ in range(args.repeat)
        ]
        status, req_b, resp_b, _ = samples[0]
        statuses = {s[0] for s in samples}
        if len(statuses) != 1:
            print(f"unstable status for {label}: {sorted(statuses)}", file=sys.stderr)
            return 1
        rows.append({
            "client": client,
            "step": label,
            "status": status,
            "req_b": req_b,
            "resp_b": resp_b,
            "in_tok": req_b // BYTES_PER_TOKEN,
            "out_tok": resp_b // BYTES_PER_TOKEN,
            "ms": round(statistics.median(s[3] for s in samples), 1),
        })

    if args.markdown:
        print("| client type | step | HTTP | req B | resp B | ~in tok | ~out tok | ms |")
        print("|---|---|---:|---:|---:|---:|---:|---:|")
        for r in rows:
            print(
                f"| {r['client']} | {r['step']} | {r['status']} | {r['req_b']:,} | "
                f"{r['resp_b']:,} | {r['in_tok']:,} | {r['out_tok']:,} | {r['ms']} |"
            )
    else:
        print(json.dumps(rows, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
