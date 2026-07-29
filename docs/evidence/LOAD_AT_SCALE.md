# Load at scale — by client type

Companion to [`E2E_WALKTHROUGH.md`](E2E_WALKTHROUGH.md) (one call, end to end) and
[`ORGANIZATION_AT_SCALE.md`](ORGANIZATION_AT_SCALE.md) (a whole org, concurrently).
This one pushes until something gives, and asks **what gives, and in which
direction**.

Every figure came from k6 and a direct concurrency harness against a real
production-posture `3.0.0` gateway (`MCPIP_SANDBOX_MODE=false`, license verified,
fsync-durable Redis, single worker). Harness: `load/k6/by-client-type.js`.

**The headline is not the throughput number.** It is that one client type — the
auditor — degrades every other one, and that finding survived a first draft of this
document that got the overload story wrong. Both are below.

---

## Why by client type

Aggregating five different callers into one requests/sec number hides the only
thing worth knowing: which surface degrades first.

| client type | surface | share of load |
|---|---|---|
| agent | `POST /v1/authorize` (MCP JSON-RPC `tools/call`) | 1× (base rate) |
| developer | `POST /v1/authorize` + `POST /v1/mcp` | ÷2 |
| pdp | `POST /v1/authz/decision` (AuthZEN; executes nothing) | ÷5 |
| operator | `GET /v1/admin/decisions/recent`, `/v1/admin/stats` | ÷10 |
| auditor | `GET /v1/audit/attestation` | ÷20 |

## Correctness is a wall, latency is a budget

**A gateway that gets fast by letting a `pin_required` call through has not
improved — it has broken.** So behavioural checks are tagged `{kind:invariant}` and
thresholded at `rate==1.0`: `pin_required` never allowed without step-up,
unregistered never allowed, deny bodies opaque, `tools/list` never leaking a
target, the chain `intact` while written at rate, PDP verdicts carrying no reason.

## Run 1 — rate 50/s, 45s

```
throughput          92.8 req/s sustained
checks              5545 pass / 0 fail
invariants          2006 pass / 0 fail   (100%)
unanswered          0.00%
```

| client type | p50 | p95 | p99 |
|---|---:|---:|---:|
| developer | 18.0 | 170.8 | 256.4 |
| pdp | 29.8 | 162.3 | 244.4 |
| agent | 35.1 | 219.6 | 299.2 |
| operator | 45.3 | 176.1 | 236.1 |
| **auditor** | **146.9** | **359.4** | 458.5 |

Decision mix: 1601 allow · 432 staged · 218 denied.

## Run 2 — rate 150/s, past the knee

```
throughput          239.5 req/s
invariants          4339 pass / 0 fail   (100%)
shed with 503       4298
unanswered          0.00%
```

| client type | p50 | p95 |
|---|---:|---:|
| pdp | 45.7 | 459 |
| operator | 49.2 | 502 |
| developer | 47.3 | 578 |
| agent | 49.1 | 636 |
| **auditor** | **46.1** | **10,259** |

## Is overload a bug here?

**The overload *response* is not.** MCPIP has a designed load shedder: past
`MCPIP_MAX_IN_FLIGHT` (default 64) a new arrival gets an opaque `503` +
`Retry-After`, and the limiter "only ever REJECTS or TIMES OUT — it never lets a
request skip a gate" (`app/main.py:2457-2464`). Measured directly, 250 concurrent
clients against `max_in_flight=64`:

```
4893 responses (360/s)
  200   4822   98.5%
  503     71    1.5%     Retry-After: 1
  timeouts            0
  refused connections 0
```

No collapse, no timeouts, no refused connections — clean back-pressure with a
retry hint. And across both k6 runs, **not one safety invariant broke**: the
gateway sheds load by refusing to answer, never by allowing.

**A correction, because the first version of this page got it wrong.** It reported
"62.3% transport failure" and called it saturation. That figure was an artifact of
this harness, not the gateway: k6 counts any non-2xx as `http_req_failed`, and the
expected-status set had been widened to `200, 202, 403, 409` — omitting **503**. So
every correctly-shed request was scored as a failure, and a gateway behaving
exactly as specified was reported as falling over. With 503 included the same run
reports **0.00% unanswered and 4298 sheds**. This is the same mistake as counting a
deny as a failure, which the suite had already fixed once and then repeated one
status code over. It is recorded rather than quietly corrected because a suite that
miscounts correct behaviour as breakage will get its real findings ignored too.

## The actual bug: the auditor starves the hot path

This is the finding worth acting on, and it is not about overload at all.

`GET /v1/audit/attestation` runs a full `verify_chain` over the signed epoch chain.
It shares a worker with `POST /v1/authorize`. Measured — four authorize probes at a
steady rate, with a varying number of concurrent attestation readers alongside:

| concurrent attestation readers | authorize p50 | authorize p95 |
|---|---:|---:|
| 0 (baseline) | **8.2 ms** | 17.4 ms |
| 4 | **260.1 ms** | 368.3 ms |
| 24 | 306.1 ms | 384.4 ms |

**Four concurrent readers inflate authorize p50 by 32×.** Not forty. Four — an
operator dashboard plus a monitoring probe. The curve then plateaus (4 → 24 barely
moves it), which is the in-flight limiter bounding the damage; but the damage is
already done at four.

Why this matters more than a throughput ceiling: MCPIP is fail-closed, so its own
chart notes that losing the gateway "denies all agent actions"
(`chart/values.yaml`). Availability is therefore a **security** property here, not
just an SLO. A well-meaning dashboard polling the attestation endpoint on a short
interval degrades every agent in the estate.

It is not remotely triggerable — the endpoint is `CAP_DIRECTORY_ADMIN`-gated — so
this is a self-inflicted foot-gun rather than a DoS vector. That makes it more
likely to happen, not less: nobody is defending against their own monitoring.

Worth considering: a short-TTL cache on the attestation result (the epoch head only
moves when an epoch seals), a dedicated concurrency budget for the admin plane so
it cannot consume the hot path's, or serving attestation from a replica. Not
implemented here — this document reports the measurement, not a fix.

## Two corrections this exercise produced

**`/v1/audit/attestation` is `CAP_DIRECTORY_ADMIN`-gated, not `CAP_FORENSIC_READ`.**
The skill's first draft assumed the auditor persona could read it and every auditor
request 403'd. The attestation commits to the **global** WORM head — a fleet-wide
ledger height, not a per-tenant view — so a narrower principal reading it would leak
cross-tenant activity volume and could force a full `verify_chain`.
`CAP_FORENSIC_READ` buys the payload-capture route instead. Capabilities here are
non-hierarchical in both directions.

**Safety and liveness are different properties.** Run 2 first reported 360 invariant
failures, which reads as a fail-open. It was not: the check asserted `status === 403`
for an unregistered alias, and a request that never gets answered reports status `0`,
failing an equality-to-403 check — scoring a **fail-closed** outcome as a
**fail-open** one. The invariant now asserts `status !== 200` (never allowed); whether
a `403` came back is a separate liveness check.

## Honest limits

- **Single worker, loopback, local Redis, one tenant.** Shapes, not capacity figures.
  Production runs `--workers N` behind a load balancer.
- **The per-allow cost is deliberate.** Every allow requires an fsync-durable ledger
  write *before* it returns. That is write-before-execute being paid for. Raise
  throughput with workers and Redis, never by weakening durability.
- **No step-up completions under load** — completing them needs an out-of-band OTP sink.
- **No cross-tenant load**, so nothing here exercises tenant isolation.
- **The amplification test used a synthetic reader loop**, not a real dashboard; the
  32× figure is the shape of the contention, not a prediction for your monitoring.

## Reproducing

```bash
export MCPIP_BASE=http://127.0.0.1:8080
export MCPIP_AGENT_TOKEN=... MCPIP_DEV_TOKEN=... \
       MCPIP_ADMIN_TOKEN=... MCPIP_AUDITOR_TOKEN=...   # auditor needs CAP_DIRECTORY_ADMIN

MCPIP_RATE=50 MCPIP_DURATION=45s k6 run load/k6/by-client-type.js
k6 run --scenario auditor load/k6/by-client-type.js        # one client type
```

Tokens are supplied, never minted by the harness — MCPIP never issues identity, so a
load test must not either. Mint with `scripts/mint_principal.py`.
