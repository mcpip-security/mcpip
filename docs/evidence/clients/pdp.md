# Client type: PDP consumer (AuthZEN)

Not a person — an existing Policy Enforcement Point that already knows what it wants to
do and needs only a yes/no. It calls the AuthZEN decision endpoint, which **executes
nothing**: no tool runs, no ledger allow is written on its behalf.

| | |
|---|---|
| **Surface** | `POST /v1/authz/decision` (AuthZEN) |
| **Capabilities** | none |
| **Share of load** | ÷5 |
| **Transcript** | [`E2E_WALKTHROUGH.md` §9a](../E2E_WALKTHROUGH.md#9a-developer-path--the-other-integration-options) |

## What makes it different

Every other client type either gets a tool executed or reads gateway state. This one
gets a verdict and acts on it itself. Two consequences:

* **It is off the fsync path**, so it is not bounded by the write-before-execute
  durability floor the agent path pays.
* **The verdict carries no reason.** `{"decision":true}` or `{"decision":false}` and
  nothing else — thresholded as an invariant at `rate==1.0`, because a PDP response
  that explained itself would be an oracle for probing the policy surface from outside
  the tenant.

## Latency

| rate | p50 | p95 | p99 |
|---|---:|---:|---:|
| 50/s | 29.8 ms | 162.3 ms | 244.4 ms |
| 150/s (past the knee) | 45.7 ms | 459 ms | — |

Best p95 of any client type past the knee — the cheapest surface degrades most
gracefully, which is what you want from the one that fronts someone else's PEP.

## Cost

| step | HTTP | req B | resp B | ~in tok | ~out tok | ms |
|---|---|---:|---:|---:|---:|---:|
| authz decision | `200` | 94 | 17 | 23 | 4 | 4.4 |

**The cheapest surface on the gateway at 4 output tokens.** 17 bytes.

## What to watch

* **You own enforcement.** MCPIP returns a verdict; nothing stops your PEP from
  ignoring it. The write-before-execute guarantee and the WORM allow record belong to
  the `/v1/authorize` path — if you need the audit trail to prove the call was
  *authorized before it ran*, use that instead.
* Identity rules are unchanged: a signed JWT with all 8 required claims, `EdDSA` or
  `RS256`. MCPIP never mints identity and never derives it from the network.
