# Client type: developer

A human building against the gateway — reading the catalog, wiring an SDK, getting
calls authorized from their own machine. Same IdP and same tenant as the operator;
the difference is exactly one capability UUID.

| | |
|---|---|
| **Surface** | `POST /v1/authorize` · `POST /v1/mcp` · `GET /v1/catalog` · `GET /v1/whoami` |
| **Capabilities** | none |
| **Share of load** | ÷2 |
| **Transcript** | [`E2E_WALKTHROUGH.md` §9, §9a](../E2E_WALKTHROUGH.md#9-developer-path--the-sdk) |

## What it may and may not do

| endpoint | developer token | operator token |
|---|---|---|
| `GET /v1/whoami` | `200` | `200` |
| `GET /v1/catalog` | `200` | `200` |
| `GET /v1/admin/decisions/recent` | **`403`** | `200` |
| `GET /v1/admin/stats` | **`403`** | `200` |
| `POST /v1/admin/skills/register` | **`403`** | `200` |

A developer can see the catalog and get calls authorized. They cannot read other
agents' decisions, read tenant statistics, or register a new alias — so **the identity
that would most benefit from self-granting a route to a new target cannot do it.**
That is the boundary, and it is one capability UUID
(`CAP_DIRECTORY_ADMIN` = `b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20`) wide.

## Integration paths

Five, all exercised in [§9a](../E2E_WALKTHROUGH.md#9a-developer-path--the-other-integration-options):

| path | when |
|---|---|
| Python SDK (`sdk/python`) | a Python agent or service |
| TypeScript SDK (`sdk/typescript`) | a Node agent, or the `mcpip` CLI |
| MCP endpoint (`POST /v1/mcp`) | an MCP host that already speaks JSON-RPC |
| AuthZEN PDP (`POST /v1/authz/decision`) | an existing PEP — see [`pdp.md`](pdp.md) |
| raw HTTP | anything else; it is one POST |

## Latency

| rate | p50 | p95 | p99 |
|---|---:|---:|---:|
| 50/s | 18.0 ms | 170.8 ms | 256.4 ms |
| 150/s (past the knee) | 47.3 ms | 578 ms | — |

The fastest of the five authorizing client types at 50/s, because `tools/list` and
`GET /v1/catalog` are read-only and never touch the fsync path.

## Cost

| step | HTTP | req B | resp B | ~in tok | ~out tok | ms |
|---|---|---:|---:|---:|---:|---:|
| `POST /v1/mcp` `tools/list` | `200` | 46 | 546 | 11 | 136 | 1.5 |
| `GET /v1/catalog` | `200` | 0 | 608 | 0 | 152 | 1.4 |

`tools/list` never leaks a target — that is a thresholded invariant, not a
convention. What the developer sees is the alias surface, not the URLs behind it.

## What to watch

* **Aliases are non-hierarchical and additive.** Registration is
  `CAP_DIRECTORY_ADMIN`-gated, so ask an operator; a weaker duplicate of an existing
  alias on the same target is refused outright by the posture floor
  (`409 target_posture_conflict`).
* Local model drafting is **client-side and optional** — the gateway is
  inference-free. See [`LOCAL_MODEL.md`](../../integrate/LOCAL_MODEL.md).
