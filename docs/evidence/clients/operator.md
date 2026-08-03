# Client type: operator

Runs the tenant: registers the tool surface, watches the decision feed, revokes an
agent mid-incident. Holds `CAP_DIRECTORY_ADMIN` — and, importantly, **not** the other
two capabilities.

| | |
|---|---|
| **Surface** | `GET /v1/admin/decisions/recent` · `/v1/admin/stats` · `POST /v1/admin/skills/register` · the console |
| **Capabilities** | `CAP_DIRECTORY_ADMIN` = `b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20` |
| **Share of load** | ÷10 |
| **Transcript** | [`E2E_WALKTHROUGH.md` §10, §13](../E2E_WALKTHROUGH.md#10-developer-vs-operator--the-capability-boundary) · [`ORGANIZATION_AT_SCALE.md` §4](../ORGANIZATION_AT_SCALE.md#4-an-incident-mid-traffic) |

## What it may and may not do

There is **no super-admin**, and the operator is where that is easiest to see — it is
refused two routes outright:

| route | operator |
|---|---|
| `GET /v1/admin/stats` | `200` |
| `GET /v1/admin/decisions/recent` | `200` |
| `POST /v1/admin/skills/register` | `200` |
| `GET /v1/admin/forensic/{corr}` | **`403`** |
| `GET /v1/admin/extensions/pending` | **`403`** |

`CAP_DIRECTORY_ADMIN` does not subsume `CAP_FORENSIC_READ` or
`CAP_CATALOG_REVIEWER`. **Compromising the operator does not yield payload forensics
or extension approval** — those belong to [`auditor.md`](auditor.md) and
[`reviewer.md`](reviewer.md).

## Latency

| rate | p50 | p95 | p99 |
|---|---:|---:|---:|
| 50/s | 45.3 ms | 176.1 ms | 236.1 ms |
| 150/s (past the knee) | 49.2 ms | 502 ms | — |

## Cost

| step | HTTP | req B | resp B | ~in tok | ~out tok | ms |
|---|---|---:|---:|---:|---:|---:|
| `decisions/recent?limit=25` | `200` | 0 | 11,507 | 0 | 2,876 | 4.8 |
| `admin/stats` | `200` | 0 | 1,096 | 0 | 274 | 2.9 |

`decisions/recent` at **~2,876 tokens** is the most expensive surface on the gateway.
It is a human/dashboard surface and never touches agent context — but if you ever hand
an agent `CAP_DIRECTORY_ADMIN` and let it poll the decision feed, that is what each
poll costs it. Page it or filter it; do not put it in a loop.

## What to watch

* **The console needs a real operator token in production.** The sandbox IdP is
  absent when `MCPIP_SANDBOX_MODE=false`, so the console reads
  `identitySource: "operator-token"` and prompts. Screenshot:
  [`console-operator-token.png`](../images/console-operator-token.png).
* **Registration is the sharpest tool here.** `POST /v1/admin/skills/register` is how
  a new target becomes reachable at all. The posture floor refuses a weaker duplicate
  on a target that already carries a stricter alias (`409
  target_posture_conflict`) — including via a template that subsumes a literal, and
  including when the storage read fails, because a floor that admits on error is a
  floor an attacker opens by breaking Redis.
* **Revocation is live and mid-traffic.** Worked example with concurrent load in
  [`ORGANIZATION_AT_SCALE.md` §4](../ORGANIZATION_AT_SCALE.md#4-an-incident-mid-traffic).
