# Load at scale — by client type

Companion to [`E2E_WALKTHROUGH.md`](E2E_WALKTHROUGH.md) (one call, end to end) and
[`ORGANIZATION_AT_SCALE.md`](ORGANIZATION_AT_SCALE.md) (a whole org, concurrently).
This one asks what happens when you push until it breaks — and, more importantly,
**which way it breaks**.

Every figure below came from k6 against a real production-posture `3.0.0` gateway
(`MCPIP_SANDBOX_MODE=false`, license verified, fsync-durable Redis). Harness:
`load/k6/by-client-type.js`. Driven by the `mcpip-load-test` skill in
`.claude/skills/`.

---

## Why by client type

Aggregating five very different callers into one requests/sec number hides the
only thing worth knowing: **which surface degrades first**. MCPIP's behaviour
genuinely differs per caller — an agent proposes tool calls, a developer
integrates through one of five surfaces, an operator reads the admin plane, an
auditor reads signed evidence, a PDP consumer asks for a verdict that executes
nothing.

| client type | surface | share of load |
|---|---|---|
| agent | `POST /v1/authorize` (MCP JSON-RPC `tools/call`) | 1× (base rate) |
| developer | `POST /v1/authorize` + `POST /v1/mcp` | ÷2 |
| pdp | `POST /v1/authz/decision` (AuthZEN; executes nothing) | ÷5 |
| operator | `GET /v1/admin/decisions/recent`, `/v1/admin/stats` | ÷10 |
| auditor | `GET /v1/audit/attestation` | ÷20 |

The ratios approximate a real estate: machines dominate, humans are rare.

## Correctness is a wall, latency is a budget

A load test for an authorization gateway that only measures throughput is
measuring the wrong thing. **A gateway that gets fast by letting a `pin_required`
call through has not improved — it has broken.** So the suite gates on behaviour
first, tagged `{kind:invariant}` and thresholded at `rate==1.0`:

- a `pin_required` alias is never allowed without a completed step-up;
- an unregistered alias is never allowed;
- a deny body stays opaque (no reason, target, or topology);
- `tools/list` never leaks a real target;
- the audit chain reports `intact` while the ledger is written at rate;
- a PDP verdict carries no reason.

## Run 1 — rate 50/s, 45s, single worker

```
throughput          92.8 req/s sustained
checks              5545 pass / 0 fail
invariants          2006 pass / 0 fail   (100%)
transport failures  0.00%
```

Latency by client type (ms):

| client type | p50 | p95 | p99 | max |
|---|---:|---:|---:|---:|
| developer | 18.0 | 170.8 | 256.4 | 388.0 |
| pdp | 29.8 | 162.3 | 244.4 | 295.0 |
| agent | 35.1 | 219.6 | 299.2 | 402.6 |
| operator | 45.3 | 176.1 | 236.1 | 265.5 |
| **auditor** | **146.9** | **359.4** | 458.5 | 488.3 |

Decision mix: 1601 allow · 432 staged · 218 denied.

**The auditor surface is 4× the agent's p50 and the first to degrade.** That is
not a defect — `/v1/audit/attestation` forces a fresh `verify_chain` over the
signed epoch chain, so it is doing materially more work than an authorize. It is
worth knowing before someone points a dashboard at it on a 5-second refresh.

`pdp` being cheaper than `agent` is the expected shape: it evaluates and returns a
verdict without the execution commit.

## Run 2 — rate 150/s: past the knee

```
throughput          239.9 req/s
transport failures  62.3%          <- most requests never answered
invariants          5999 pass / 0 fail   (100%)
```

| client type | p95 |
|---|---:|
| pdp | 402 ms |
| operator | 411 ms |
| developer | 478 ms |
| agent | 518 ms |
| **auditor** | **10,203 ms** |

This is the result that matters:

> **At saturation — with 62% of requests never answered — not one safety invariant
> broke.** The gateway shed load by timing out and denying. It never shed load by
> allowing.

That is fail-closed under overload, demonstrated rather than asserted. The failure
mode an authorization gateway must not have is degrading into permissiveness when
it is busy; this one degrades into unavailability instead, which is the correct
direction for a choke point.

The auditor surface collapses first and hardest (10.2 s p95): a `verify_chain`
contending with a ledger being written at rate.

## A harness bug worth recording

Run 2 initially reported **360 invariant failures**, which reads as a fail-open. It
was not. The check asserted `status === 403` for an unregistered alias — but under
saturation a request times out and k6 reports status `0`, which fails an
equality-to-403 check. That scored a **fail-closed** outcome as a **fail-open** one.

Safety and liveness are different properties and conflating them makes the suite
lie in both directions. The invariant now asserts `status !== 200` (never allowed);
whether a `403` actually came back is a separate, non-invariant liveness check. Run
2 re-run with them separated: **5999 invariant passes, 0 fails.**

Recorded here because the same trap catches anyone writing correctness checks for a
system under load, and because a suite that cries wolf gets ignored.

## Two corrections this exercise produced

**`/v1/audit/attestation` is `CAP_DIRECTORY_ADMIN`-gated, not `CAP_FORENSIC_READ`.**
The skill's first draft assumed the auditor persona could read it and every auditor
request 403'd. The attestation commits to the **global** WORM head — a fleet-wide
ledger height, not a per-tenant view — so a narrower principal reading it would leak
cross-tenant activity volume and could force a full `verify_chain`.
`CAP_FORENSIC_READ` buys the payload-capture route, not this one. Capabilities here
are non-hierarchical in both directions.

**k6 counts a deny as a failed request.** By default any non-2xx increments
`http_req_failed`, so a suite that deliberately exercises denials measures how much
policy the gateway enforced and reports it as breakage. The harness widens the
expected set to `200, 202, 403, 409`, leaving `http_req_failed` to mean what it
should: the harness never got to ask the question.

## Honest limits

- **Single worker, loopback, local Redis, one tenant.** These are shapes, not
  capacity figures. Production runs `--workers N` behind a load balancer.
- **The per-allow cost is deliberate.** Every allow requires an fsync-durable ledger
  write *before* it returns (`appendfsync always`). That is the write-before-execute
  contract being paid for. Raise throughput with workers and Redis, never by
  weakening durability.
- **No step-up completions under load.** `pin_required` calls were staged or refused,
  never completed — completing them needs an out-of-band OTP sink.
- **No cross-tenant load.** One tenant throughout, so nothing here exercises tenant
  isolation.
- **The 62% transport-failure run is a saturation probe, not a recommendation.** It
  exists to establish the direction of failure, not a supported operating point.

## Reproducing

```bash
export MCPIP_BASE=http://127.0.0.1:8080
export MCPIP_AGENT_TOKEN=... MCPIP_DEV_TOKEN=... \
       MCPIP_ADMIN_TOKEN=... MCPIP_AUDITOR_TOKEN=...   # auditor needs CAP_DIRECTORY_ADMIN

MCPIP_RATE=50 MCPIP_DURATION=45s k6 run load/k6/by-client-type.js
k6 run --scenario auditor load/k6/by-client-type.js        # one client type
```

Tokens are supplied, never minted by the harness — MCPIP never issues identity, so
a load test must not either. Mint with `scripts/mint_principal.py`.
