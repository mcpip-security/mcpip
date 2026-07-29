# Client type: catalog reviewer

Approves pending catalog extensions — the one client type that can let a *new tool
surface* into the tenant. Holds `CAP_CATALOG_REVIEWER` and nothing else.

| | |
|---|---|
| **Surface** | `GET /v1/admin/extensions/pending` |
| **Capabilities** | `CAP_CATALOG_REVIEWER` = `7a1f9c34-2e58-4b6d-9f01-3c7a5e2b8d46` |
| **Share of load** | not load-tested — see below |
| **Transcript** | [`E2E_WALKTHROUGH.md` §10](../E2E_WALKTHROUGH.md#10-developer-vs-operator--the-capability-boundary) |

## What it may and may not do

This row is the clearest single demonstration that MCPIP has no super-admin:

| route | operator | reviewer |
|---|---|---|
| `GET /v1/admin/stats` | `200` | `403` |
| `GET /v1/admin/decisions/recent` | `200` | `403` |
| `POST /v1/admin/skills/register` | `200` | `403` |
| `GET /v1/admin/extensions/pending` | **`403`** | **`200`** |

The operator — the most privileged human persona — is **refused** the route the
reviewer is granted, and the reviewer is refused everything the operator holds. Neither
capability subsumes the other. Compromising the operator does not yield extension
approval; compromising the reviewer does not yield the decision feed.

That separation is the point: registering an alias (operator) and approving a *new
catalog surface* (reviewer) are the two ways the reachable-target set can grow, and
they deliberately require two different identities.

## Load and cost — not measured

**Honestly: this client type has no load profile.** `load/k6/by-client-type.js`
exercises five types — agent, developer, PDP, operator, auditor — and the reviewer is
not among them. Extension approval is a low-frequency human workflow, not a surface
under sustained traffic, so it was scoped out rather than measured badly.

What that means when reading the evidence: the capability boundary above **is**
verified (it comes from a real request matrix against a production-posture gateway),
and the latency/cost columns every other client file carries simply do not exist here.
No number has been estimated to fill the gap.
