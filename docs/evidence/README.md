# Evidence

Real runs against a production-posture `3.0.0` gateway (`MCPIP_SANDBOX_MODE=false`,
license verified, fsync-durable Redis), with transcripts, screenshots and the harness
that produced each figure.

> **What "real" means here, and where it stops.** Every figure below was measured, not
> estimated, and each scenario document opens with a **provenance note** naming which of
> its sections came from which run — because a page assembled from two sessions and
> presented as one continuous transcript is misleading even when every line in it is
> genuine. Where a section could not be re-executed (a live provider credential, a longer
> ledger than a fresh gateway can have), it says so at the point of use.
>
> These remain records of runs at a point in time, not a live check: commands, flags and
> outputs drift as the product changes. Treat a transcript as evidence that something
> *did* work, not as a copy-paste recipe; the runnable paths are in
> [Getting Started](../start/GETTING_STARTED.md) and [API](../start/API.md), which are
> re-executed against a live gateway when they change. The measurement tables have
> committed harnesses — [`load/cost_by_client_type.py`](../../load/cost_by_client_type.py)
> and [`load/concurrent_agents.py`](../../load/concurrent_agents.py) — so you can
> regenerate them here rather than trust ours.

Two axes, because they answer different questions.

## By client type — "what does MCPIP look like for *me*?"

One file per caller: the surface it touches, the capabilities it holds **and is
refused**, its measured latency, and what a call costs it.

| client type | surface | holds | share of load |
|---|---|---|---|
| [**agent**](clients/agent.md) | `POST /v1/authorize`, `/v1/mcp` | *(no capability)* | 1× |
| [**developer**](clients/developer.md) | `+ /v1/catalog`, `/v1/whoami` | *(no capability)* | ÷2 |
| [**PDP consumer**](clients/pdp.md) | `POST /v1/authz/decision` | *(no capability)* | ÷5 |
| [**operator**](clients/operator.md) | `/v1/admin/decisions`, `/stats`, `skills/register` | `CAP_DIRECTORY_ADMIN` | ÷10 |
| [**auditor**](clients/auditor.md) | `/admin/forensic` (`CAP_FORENSIC_READ`); `/v1/audit/attestation` needs `CAP_DIRECTORY_ADMIN` — [two disjoint capabilities](clients/auditor.md) | `CAP_FORENSIC_READ` | ÷20 |
| [**reviewer**](clients/reviewer.md) | `/v1/admin/extensions/pending` | `CAP_CATALOG_REVIEWER` | not load-tested |

Read any two of these side by side and the non-hierarchical capability model becomes
concrete: the **operator** is refused the reviewer's route and the auditor's forensics,
and neither of those identities can read the decision feed. There is no super-admin.

## By scenario — "does the whole thing work?"

| document | question it answers |
|---|---|
| [**E2E_WALKTHROUGH.md**](E2E_WALKTHROUGH.md) | One production cycle end to end: key ceremony · signed license · the four gates that refuse a production boot · governed Cloudflare and GitHub calls with full request/response · the PIN step-up cycle including replay denial · WORM trace and tamper detection · period SOC 2 reporting. |
| [**ORGANIZATION_AT_SCALE.md**](ORGANIZATION_AT_SCALE.md) | A whole org at once: concurrent multi-agent traffic from separate client hosts, the persona matrix, and a live revocation mid-traffic. |
| [**LOAD_AT_SCALE.md**](LOAD_AT_SCALE.md) | Cross-type comparison under load: which surface degrades **first** (the auditor's `verify_chain`), and the direction of failure past the knee. |

The client files are the per-caller detail sheets; `LOAD_AT_SCALE.md` is the comparison
that only makes sense with all five side by side. Numbers live in one place and are
cited from the other — a figure that appears twice is the same measurement, not two.

## Reproducing

The k6 suite is [`load/k6/by-client-type.js`](../../load/k6/by-client-type.js) — see
[`load/README.md`](../../load/README.md). Correctness checks are tagged
`{kind:invariant}` and thresholded at `rate==1.0`, so a run that gets faster by
allowing something it should have denied fails rather than scores well.

`images/` holds the console screenshots referenced from the scenario documents.
