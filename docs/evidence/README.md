# Evidence

Real runs against a production-posture `3.0.0` gateway (`MCPIP_SANDBOX_MODE=false`,
license verified, fsync-durable Redis), with transcripts, screenshots and the harness
that produced each figure. Nothing here is illustrative.

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
| [**auditor**](clients/auditor.md) | `/v1/audit/attestation`, `/admin/forensic` | `CAP_FORENSIC_READ` | ÷20 |
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
