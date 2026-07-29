---
name: mcpip-load-test
description: Run k6 load tests against an MCPIP gateway, organised by client type (agent, developer, operator, auditor, PDP). Use when asked to load test, stress test, benchmark, measure throughput/latency, or check whether MCPIP's authorization invariants hold at scale. Also use when asked to regenerate the load-test evidence report.
---

# Load-testing MCPIP at scale

## The one thing to get right

MCPIP is an authorization gateway. A load test that only measures throughput and
latency is measuring the wrong thing — **a gateway that gets fast by letting a
`pin_required` call through has not improved, it has broken.**

So every run is gated on behaviour first:

- a `pin_required` alias must **never** return `200` without a completed step-up;
- an unregistered alias must **always** deny;
- a deny body must stay **opaque** (no reason, target, or topology) under load;
- `tools/list` must never leak a real target;
- the audit chain must report `intact` while the ledger is being written at rate.

These are tagged `{kind:invariant}` and thresholded at `rate==1.0`. If one breaks,
the run failed regardless of the latency numbers. Never relax an invariant
threshold to make a run pass — that is deleting the result, not achieving it.

## Prerequisites

```bash
k6 version                     # install: https://k6.io/docs/get-started/installation/
curl -sf "$MCPIP_BASE/healthz" # the gateway must already be running
```

Tokens are **supplied, never minted here**. MCPIP never issues identity, so the
harness must not either. Mint them with the real IdP key:

```bash
python3 scripts/mint_principal.py --idp-key <idp.key> \
  --tenant <tenant> --agent load-agent-1 --role ops \
  --issuer <MCPIP_JWT_ISSUER> --audience <MCPIP_JWT_AUDIENCE> --ttl 7200
```

The operator token needs `CAP_DIRECTORY_ADMIN`
(`b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20`).

**The auditor token needs `CAP_DIRECTORY_ADMIN` too — not `CAP_FORENSIC_READ`.**
This trips people (it tripped this skill's first draft): `/v1/audit/attestation`
commits to the **global** WORM head, a fleet-wide ledger height rather than a
per-tenant view, so a narrower principal reading it would leak cross-tenant
activity volume and could force a full `verify_chain`. `CAP_FORENSIC_READ`
(`d5f0c9a2-4b71-4e6a-9c83-1a7f2e6b4d90`) buys the payload-capture route
(`/v1/admin/forensic/{correlation_id}`), not the attestation.

Capabilities here are non-hierarchical in both directions — `CAP_DIRECTORY_ADMIN`
does **not** subsume `CAP_FORENSIC_READ` either — so mint whichever the surface you
are exercising actually requires, and do not assume an admin token opens everything.

## Running

```bash
export MCPIP_BASE=http://127.0.0.1:8080
export MCPIP_AGENT_TOKEN=... MCPIP_DEV_TOKEN=... \
       MCPIP_ADMIN_TOKEN=... MCPIP_AUDITOR_TOKEN=...

# all five client types concurrently
MCPIP_RATE=50 MCPIP_DURATION=30s k6 run load/k6/by-client-type.js

# one client type only
k6 run --scenario agent load/k6/by-client-type.js

# machine-readable output for the report
k6 run --summary-export=/tmp/k6-summary.json load/k6/by-client-type.js
```

`MCPIP_RATE` is the **agent** arrival rate per second; the other types are scaled
from it (developer ÷2, PDP ÷5, operator ÷10, auditor ÷20), which approximates a
real estate where machines dominate and humans are rare.

## Choosing a rate

Start at `MCPIP_RATE=25` and climb. The gateway is deliberately expensive per
allow: every one requires an **fsync-durable ledger write before it returns**
(`appendfsync always`). That is the write-before-execute contract being paid for,
not a bug to tune away. If you want a bigger number, add workers and Redis
throughput — do not weaken durability, and never suggest doing so.

Watch for the shape, not the peak:

- `mcpip_latency_operator` climbing faster than `mcpip_latency_agent` means the
  admin plane is contending with the hot path — worth reporting.
- `http_req_failed` rising is the harness failing to ask the question; that is not
  a deny and must not be counted as one. **503 is not a failure either** — it is the
  designed load shedder (`MCPIP_MAX_IN_FLIGHT`, opaque 503 + `Retry-After`). Counting
  it as breakage once made this suite report a gateway shedding exactly as specified
  as a gateway falling over. `mcpip_shed_503` tracks it separately; rising sheds mean
  back-pressure is engaging, which is correct behaviour, not an incident.
- **Watch the auditor against everything else.** `/v1/audit/attestation` runs a full
  `verify_chain` and shares a worker with the hot path: four concurrent readers were
  measured inflating authorize p50 by 32× (8.2 ms → 260 ms). If you are diagnosing
  "the gateway got slow", ask what is polling attestation before you look anywhere
  else.
- any `{kind:invariant}` check below `1.0` is a correctness finding: stop, and
  report it as such rather than re-running until it passes.

## Interpreting and reporting

Write results **by client type**, never as one aggregate — the whole point is
which surface degrades first. For each type report p50/p95/p99, the decision mix,
and the invariant results. Update `docs/evidence/LOAD_AT_SCALE.md`.

State the environment honestly: single worker vs `--workers N`, local vs network
Redis, loopback vs real RTT. A loopback single-worker number is a *shape*, not a
capacity figure, and must be labelled as such. Never present one as a benchmark.

## Extending

Add a client type by adding an `exec` function plus a scenario entry in
`options.scenarios`. Keep the correctness checks tagged `{kind:invariant}` — a new
surface without behavioural gates is a throughput number pretending to be a test.

Envelope builders live in `load/k6/lib/envelopes.js`. The wire dialect is
**declared**, never sniffed, so a new client type needs its real envelope shape —
a synthetic body that skips the bridge's deep validation measures a path
production never takes.
