# Client type: agent

The caller MCPIP exists for — an autonomous model-driven client asking to run a tool.
It is the only client type whose requests are *authorized and then executed*, and the
only one on the fsync-durable write-before-execute path.

| | |
|---|---|
| **Surface** | `POST /v1/authorize` · `POST /v1/mcp` (MCP JSON-RPC `tools/call`) |
| **Capabilities** | none — an agent needs no capability UUID to be authorized |
| **Share of load** | 1× (the base rate every other type is scaled against) |
| **Transcript** | [`E2E_WALKTHROUGH.md` §7–8](../E2E_WALKTHROUGH.md#7-governed-calls--cloudflare-and-github) |

## What it may and may not do

Nothing administrative. An agent token carries no capability UUID, and every admin
route refuses it:

| route | agent |
|---|---|
| `GET /v1/catalog` | `200` |
| `POST /v1/authorize` | `200` |
| `GET /v1/admin/stats` | `403` |
| `GET /v1/admin/decisions/recent` | `403` |
| `POST /v1/admin/skills/register` | `403` |
| `GET /v1/admin/forensic/{corr}` | `403` |

The refusal that matters most is the last two: an agent cannot register a new alias,
so it cannot self-grant a route to a target it was not already permitted to reach,
and it cannot read payload forensics. `role: "platform-ops"` in the token claims
changes none of this — authorization reads capability UUIDs, never role strings.

## Latency

| rate | p50 | p95 | p99 |
|---|---:|---:|---:|
| 50/s | 35.1 ms | 219.6 ms | 299.2 ms |
| 150/s (past the knee) | 49.1 ms | 636 ms | — |

Past the knee the agent path sheds with `503 + Retry-After` rather than slowing
without bound. Across 4339 invariant checks at that rate, **not one safety invariant
broke** — no `pin_required` call was allowed without step-up, no unregistered target
was allowed, no deny body leaked a reason. It sheds by denying, never by allowing.

## Cost

| step | HTTP | req B | resp B | ~in tok | ~out tok | ms |
|---|---|---:|---:|---:|---:|---:|
| authorize · allow | `200` | 139 | 231 | 34 | 57 | 5.5 |
| authorize · step-up staged | `202` | 158 | 273 | 39 | 68 | 46.8 |
| authorize · deny | `403` | 141 | 96 | 35 | 24 | 5.8 |

**A governed call costs ~91 tokens round-trip** (34 in + 57 out) — smaller than most
tool *results* the same call would return. MCPIP's own token cost is zero and
structurally so: there is no inference library in `requirements.txt` to call a model
with.

**The opaque deny is also the cheapest response.** 63 tokens, 96 bytes, and the tool
never runs. The opacity exists as a security property — no reason, no target, no
topology — and it happens to also save the caller both the execution and the context
that execution would have consumed.

## What to watch

* **One fsync per allow** is the per-worker throughput floor, and it is deliberate:
  the ledger write is durable *before* the allow returns. Buy throughput with workers
  and Redis, never by weakening it.
* **The auditor can starve this path.** A concurrent `verify_chain` walk is
  CPU-bound and event-loop-blocking; it pushed agent p95 to 636 ms while the auditor's
  own p95 hit 10.3 s. See [`auditor.md`](auditor.md) and
  [`LOAD_AT_SCALE.md`](../LOAD_AT_SCALE.md#the-actual-bug-the-auditor-starves-the-hot-path).
* A `pin_required` alias stages rather than allows. The step-up cycle is
  [`E2E_WALKTHROUGH.md` §11](../E2E_WALKTHROUGH.md#11-step-up--the-pin-cycle).
