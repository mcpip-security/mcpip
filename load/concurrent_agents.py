#!/usr/bin/env python3
"""
MCPIP — many agents at once, from many client hosts.

The harness behind the concurrency tables in
``docs/evidence/ORGANIZATION_AT_SCALE.md``. It fires N authorize calls from each of
several agent identities against a running gateway and reports, per agent, the
status distribution and the wall-clock latency spread.

What it is for is not throughput. It is the two properties that only show up with
several identities in flight at once:

  * **Attribution does not blur under concurrency** — every decision keeps its own
    correlation id, ``worm_sequence`` and verified ``agent_id``.
  * **One identity's posture does not leak into another's** — an agent refused a
    ``pin_required`` alias is refused every time while its peers run clean.

``--bind-source-ips`` gives each agent its own loopback source address, so the
gateway sees genuinely separate client hosts rather than one process. The verdicts
must not change: identity comes from the signed token, never from the network.

Tokens are SUPPLIED, never minted here — MCPIP never issues identity, so a harness
must not either. Mint with ``scripts/mint_principal.py``.

Usage::

    python load/concurrent_agents.py --base http://127.0.0.1:8080 \\
      --agent cf-agent-a=/run/cf_a.jwt:cf.d1.databases.list \\
      --agent data-agent-1=/run/data.jwt:cf.d1.query \\
      --calls 12 --workers 24 [--bind-source-ips]
"""

from __future__ import annotations

import argparse
import http.client
import json
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse


class Agent:
    __slots__ = ("name", "token", "alias", "source_ip")

    def __init__(self, name: str, token: str, alias: str, source_ip: str | None):
        self.name, self.token, self.alias, self.source_ip = name, token, alias, source_ip


def _parse_agent(spec: str) -> tuple[str, str, str]:
    """``name=/path/to/token.jwt:alias`` — the alias may itself contain no colon."""
    name, _, rest = spec.partition("=")
    token_path, _, alias = rest.rpartition(":")
    if not (name and token_path and alias):
        raise argparse.ArgumentTypeError(f"expected name=tokenfile:alias, got {spec!r}")
    return name, token_path, alias


def _one_call(base: str, agent: Agent, call_id: int) -> tuple[str, str, int, float]:
    url = urlparse(base)
    body = json.dumps(
        {
            "vendor": "claude_code",
            "tool_call": {
                "jsonrpc": "2.0",
                "id": call_id,
                "method": "tools/call",
                "params": {"name": agent.alias, "arguments": {}},
            },
        },
        separators=(",", ":"),
    )
    source = (agent.source_ip, 0) if agent.source_ip else None
    conn = http.client.HTTPConnection(
        url.hostname or "127.0.0.1", url.port or 80, timeout=30, source_address=source
    )
    started = time.perf_counter()
    try:
        conn.request(
            "POST",
            "/v1/authorize",
            body=body,
            headers={
                "Authorization": f"Bearer {agent.token}",
                "Content-Type": "application/json",
            },
        )
        resp = conn.getresponse()
        resp.read()
        status = resp.status
    finally:
        conn.close()
    return agent.name, agent.alias, status, (time.perf_counter() - started) * 1000


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--base", default="http://127.0.0.1:8080")
    p.add_argument("--agent", action="append", required=True, type=_parse_agent,
                   metavar="NAME=TOKENFILE:ALIAS")
    p.add_argument("--calls", type=int, default=12, help="calls per agent")
    p.add_argument("--workers", type=int, default=24, help="calls in flight at once")
    p.add_argument("--bind-source-ips", action="store_true",
                   help="give each agent its own 127.0.0.x source address")
    args = p.parse_args(argv)

    agents: list[Agent] = []
    for index, (name, token_path, alias) in enumerate(args.agent):
        with open(token_path) as handle:
            token = handle.read().strip()
        source = f"127.0.0.{index + 2}" if args.bind_source_ips else None
        agents.append(Agent(name, token, alias, source))

    work = [(agent, n) for agent in agents for n in range(args.calls)]
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda item: _one_call(args.base, *item), work))
    wall = time.perf_counter() - started

    latencies = sorted(r[3] for r in results)
    def pct(fraction: float) -> float:
        return latencies[min(len(latencies) - 1, int(len(latencies) * fraction))]

    source_note = ", each agent from its OWN source IP" if args.bind_source_ips else ""
    print(
        f"fired {len(results)} concurrent authorize calls in {wall:.2f}s  "
        f"({len(results) / wall:.0f} req/s, {args.workers} workers){source_note}"
    )
    print(
        f"latency  p50={statistics.median(latencies):.1f}ms  "
        f"p95={pct(0.95):.1f}ms  max={latencies[-1]:.1f}ms\n"
    )

    header = f"{'agent':<14}"
    if args.bind_source_ips:
        header += f"{'source ip':<12}"
    print(header + f"{'alias':<26}{'200':>4}{'202':>5}{'403':>5}")
    for agent in agents:
        mine = [r for r in results if r[0] == agent.name]
        row = f"{agent.name:<14}"
        if args.bind_source_ips:
            row += f"{agent.source_ip:<12}"
        row += f"{agent.alias:<26}"
        for code in (200, 202, 403):
            row += f"{sum(1 for r in mine if r[2] == code):>{4 if code == 200 else 5}}"
        print(row)

    unexpected = sorted({r[2] for r in results} - {200, 202, 403})
    if unexpected:
        print(f"\nunexpected status codes: {unexpected}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
