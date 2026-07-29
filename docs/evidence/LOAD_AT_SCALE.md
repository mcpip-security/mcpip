# Load at scale — the cross-type comparison

Companion to [`E2E_WALKTHROUGH.md`](E2E_WALKTHROUGH.md) (one call, end to end) and
[`ORGANIZATION_AT_SCALE.md`](ORGANIZATION_AT_SCALE.md) (a whole org, concurrently).
This one pushes until something gives, and asks **what gives, and in which
direction**.

**Looking for one client type?** Each has its own detail sheet —
[agent](clients/agent.md) · [developer](clients/developer.md) ·
[PDP](clients/pdp.md) · [operator](clients/operator.md) ·
[auditor](clients/auditor.md) · [reviewer](clients/reviewer.md) — carrying that
caller's capabilities, latency and per-step cost. This document keeps the part that
only works side by side: the **ranking**, and which surface degrades first.

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
| [agent](clients/agent.md) | `POST /v1/authorize` (MCP JSON-RPC `tools/call`) | 1× (base rate) |
| [developer](clients/developer.md) | `POST /v1/authorize` + `POST /v1/mcp` | ÷2 |
| [pdp](clients/pdp.md) | `POST /v1/authz/decision` (AuthZEN; executes nothing) | ÷5 |
| [operator](clients/operator.md) | `GET /v1/admin/decisions/recent`, `/v1/admin/stats` | ÷10 |
| [auditor](clients/auditor.md) | `GET /v1/audit/attestation` | ÷20 |

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
(`deploy/chart/values.yaml`). Availability is therefore a **security** property here, not
just an SLO. A well-meaning dashboard polling the attestation endpoint on a short
interval degrades every agent in the estate.

It is not remotely triggerable — the endpoint is `CAP_DIRECTORY_ADMIN`-gated — so
this is a self-inflicted foot-gun rather than a DoS vector. That makes it more
likely to happen, not less: nobody is defending against their own monitoring.

Worth considering: a short-TTL cache on the attestation result (the epoch head only
moves when an epoch seals), a dedicated concurrency budget for the admin plane so
it cannot consume the hot path's, or serving attestation from a replica. Not
implemented here — this document reports the measurement, not a fix.

## Cost per step, by client type

### MCPIP's own token cost is zero

Not "low" — **zero**, and structurally so. The gateway makes no model call anywhere
in the authorization path, and it cannot: `requirements.txt` is

```
pydantic · redis · PyJWT · cryptography · httpx · fastapi · uvicorn ·
pydantic-settings · prometheus-client
```

There is no inference library to call one with. `services/workspace_plan.py` and
`/v1/admin/workspace/draft` are deterministic heuristics, documented inference-free,
and the optional drafting model is client-side and not wired into a console panel
(see [`LOCAL_MODEL.md`](../integrate/LOCAL_MODEL.md)).

This is worth stating plainly because the obvious alternative — an LLM-based
guardrail that reads each tool call and judges it — has a per-decision token bill,
a per-decision latency floor set by a model, and a non-deterministic verdict. MCPIP
has none of the three. Its decisions cost CPU and one fsync, and are reproducible.

### What a governed call costs the *calling agent*

There is a real token cost, but it lands in the **caller's** context window, not in
MCPIP. Measured exactly (bytes are ground truth; tokens estimated at 4 bytes/token,
the standard `cl100k` rule of thumb — JSON tokenizes somewhat worse than prose, so
treat the token columns as a floor):

| client type | step | HTTP | req B | resp B | ~in tok | ~out tok | ms |
|---|---|---:|---:|---:|---:|---:|---:|
| agent | authorize · allow | 200 | 152 | 234 | 38 | 59 | 13.0 |
| agent | authorize · staged | 403 | 172 | 96 | 43 | 24 | 8.7 |
| agent | authorize · deny | 403 | 153 | 96 | 39 | 24 | 15.6 |
| developer | `POST /v1/mcp` tools/list | 200 | 51 | 660 | 13 | 165 | 4.4 |
| developer | `GET /v1/catalog` | 200 | 0 | 748 | 0 | 187 | 2.2 |
| pdp | authz decision | 200 | 150 | 17 | 38 | 5 | 4.9 |
| operator | decisions/recent (25) | 200 | 0 | 10,731 | 0 | 2,683 | 84.0 |
| operator | admin/stats | 200 | 0 | 1,107 | 0 | 277 | 3.7 |
| auditor | audit/attestation | 200 | 0 | 560 | 0 | 140 | 526.3 |

**A governed call costs an agent ~97 tokens round-trip** (38 in + 59 out). For
comparison, that is smaller than most tool *results* the call would return.

**The opaque deny is also a cost control.** A denied call is 63 tokens and the tool
never runs — versus executing it and pulling the result into context. The opacity
that exists as a security property (no reason, no target, no topology) turns out to
be the cheapest possible response: 96 bytes. Denying early saves the caller both the
execution and the context it would have consumed.

The PDP verdict is the cheapest surface on the gateway at **5 output tokens**
(`{"decision":true}`) — sensible for a PEP that already knows what it wants to do
and only needs a yes/no.

The expensive row is `decisions/recent?limit=25` at **~2,683 tokens**. That is a
human/dashboard surface and never touches agent context — but if you ever hand an
agent `CAP_DIRECTORY_ADMIN` and let it poll the decision feed, that is what each
poll costs it. Page it or filter it; do not put it in a loop.

### The costs that are real

| cost | per what | measured |
|---|---|---|
| tokens (MCPIP itself) | any decision | **0** — no model, no inference dependency |
| tokens (caller's context) | governed call | ~97 allow / ~63 deny |
| CPU + latency | authorize | 8.2 ms p50 unloaded, 35–49 ms under load |
| fsync | **every allow** | one durable ledger write *before* the allow returns |
| storage | every decision | one WORM record, retained indefinitely by design |

The fsync is the floor on per-worker throughput and it is deliberate — it is the
write-before-execute contract. Buy throughput with workers and Redis, never by
weakening it.

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

## Is this ready for scale?

Qualified yes, and the qualifications matter more than the yes.

**What holds up.** Correctness never bent: across every run, at every rate,
including past the knee, not one safety invariant broke. Back-pressure is real and
clean — 503 + `Retry-After`, no timeouts, no refused connections. Attribution stays
per-identity under concurrency. The architecture scales the right way: workers are
stateless, state is in Redis, so horizontal scaling is adding workers rather than
redesigning anything. And the per-decision cost is CPU and one fsync, not a model
call — so cost scales linearly and predictably with traffic, which is not true of an
LLM-based guardrail.

**What blocks "point it at production and forget it".**

1. **The attestation amplification.** Four concurrent readers degrade the hot path
   32×. Until that has a cache, a separate concurrency budget, or a replica, someone
   *will* wire a dashboard to it and slow every agent in the estate. This is the one
   I would fix before scaling, not after.
2. **Every number here is single-worker loopback.** They establish shape and
   direction, not capacity. A real plan needs `--workers N` behind a load balancer,
   HA Redis holding `appendfsync always`, and measurement on your own network — the
   fsync cost changes completely when Redis is a network hop away.
3. **Untested at scale here:** cross-tenant isolation, step-up completion under load
   (needs an out-of-band OTP sink), and WORM growth over time. The ledger is retained
   indefinitely by design, so ledger size and `verify_chain` cost both grow with
   history — and `verify_chain` is already the slowest thing on the box.

The honest summary: the *design* scales and the *safety properties* hold under
pressure. The deployment story needs the attestation fix and a real multi-worker
measurement before anyone should quote a capacity number.

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
