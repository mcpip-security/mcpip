# An organization on MCPIP — many agents, many people, in parallel

A companion to [`E2E_WALKTHROUGH.md`](E2E_WALKTHROUGH.md), which follows a single
call end to end. This one asks the other question: what does it look like when a
whole organization runs on the gateway — several teams' agents firing
concurrently, several kinds of human alongside them, and an incident in the
middle of it.

Every number, status code and ledger row below came from a real run against a
production-posture `3.0.0` gateway (`MCPIP_SANDBOX_MODE=false`).

> **Provenance.** §2, §2.1, §2.2, §3 and §4 were re-executed for this revision
> against a freshly provisioned production gateway, using the committed harness in
> [Reproducing](#reproducing) — so every figure in them can be regenerated rather
> than taken on trust. §3 and the shape of §4 reproduced exactly; the throughput and
> sequence numbers are this run's. §5's tenant totals and §5a's period report are
> from the original fleet run, which had more history behind it than a fresh gateway
> can have.

---

## 1. The organization

One tenant, `acme-platform`. Six machine identities and three kinds of human, all
minted by the same IdP, all verified by the gateway against one public key.

| principal | role claim | capability | what it is |
|---|---|---|---|
| `cf-agent-a`, `cf-agent-b` | `platform-ops` | — | Cloudflare infrastructure agents |
| `gh-agent-a`, `gh-agent-b` | `release-ops` | — | GitHub release agents |
| `ci-agent-1` | `ci` | — | build pipeline |
| `data-agent-1` | `analytics` | — | analytics agent |
| `mcpip-admin` | `platform-admin` | `CAP_DIRECTORY_ADMIN` | platform operator |
| `auditor-1` | `auditor` | `CAP_FORENSIC_READ` | compliance / IR |
| `reviewer-1` | `reviewer` | `CAP_CATALOG_REVIEWER` | extension reviewer |

`role` is a **descriptive** claim and authorizes nothing. The capability UUID is
the entitlement. An agent with `role: "platform-admin"` and no capability is an
ordinary agent.

## 2. Everyone at once

72 authorize calls from six agents, 24 in flight at a time, against the
production gateway:

```
fired 72 concurrent authorize calls in 0.35s  (204 req/s, 24 workers)
latency  p50=81.4ms  p95=152.1ms  max=175.6ms

agent         alias                      200  202  403
cf-agent-a    cf.d1.databases.list        12    0    0
cf-agent-b    cf.d1.databases.list        12    0    0
gh-agent-a    gh.branches.list            12    0    0
gh-agent-b    gh.branches.list            12    0    0
ci-agent-1    gh.branches.list            12    0    0
data-agent-1  cf.d1.query                  0   12    0
```

Two things to read here.

**Concurrency does not blur attribution.** Every one of the 72 decisions carries
its own correlation id, its own `worm_sequence`, and the verified `agent_id` of
the caller. Six agents interleaving produce six cleanly separable audit trails,
not one merged stream.

**One agent's posture does not leak into another's.** `data-agent-1` reached for
`cf.d1.query` — a `pin_required`, `restricted` alias — and was held for step-up all
12 times while five peers ran clean at full rate. Not one of the twelve became an
allow. The verdict is per-call and per-identity; there is no circuit that trips for
everyone, and no amount of peer traffic softens it.

`202` rather than `403` on that row is a **deployment** difference, not a policy
one: this gateway has a TOTP channel configured (`MCPIP_AUTHN_TOTP_KEY_PATH`), so a
`pin_required` alias can seal a challenge and stage. With no channel configured at
all the same twelve calls fail closed with `403` / `otp_delivery_failed` instead —
the shape MCPIP takes when it has no way to reach a human. Either way the alias is
never allowed without a completed step-up, which is the invariant; and staging is
not permission — completing it needs an enrolled authenticator, which
`data-agent-1` does not have.

Every deny is byte-identical to the caller. The reasons live in the ledger, not in
the response.

### 2.1 Same run, six distinct client hosts

The run above shares a process and a source address, which is not what an
organization looks like. Repeated with each agent dialling from its **own
loopback source IP**, so the gateway sees six separate client hosts opening
independent connections:

```
fired 150 concurrent authorize calls in 0.66s  (228 req/s, 24 workers), each agent from its OWN source IP
latency  p50=59.4ms  p95=242.6ms  max=270.4ms

agent         source ip   alias                      200  202  403
cf-agent-a    127.0.0.2   cf.d1.databases.list        25    0    0
cf-agent-b    127.0.0.3   cf.d1.databases.list        25    0    0
gh-agent-a    127.0.0.4   gh.branches.list            25    0    0
gh-agent-b    127.0.0.5   gh.pr.list                  25    0    0
ci-agent-1    127.0.0.6   gh.branches.list            25    0    0
data-agent-1  127.0.0.7   cf.d1.query                  0   25    0
```

No transport errors, and the verdicts are identical to the shared-source run:
distinct hosts change throughput characteristics, not decisions. (`gh-agent-b`
switches alias between the two runs — `gh.branches.list` to `gh.pr.list` — because
both are `auto`; the point is that the *decision* does not move.)

### 2.2 The network contributes nothing to identity

Worth proving rather than assuming. The same `cf-agent-a` token, dialled from
three different client hosts:

```
token=cf-agent-a  source_ip=127.0.0.8    -> HTTP 200  seq=298  corr=c7be25dd4831…
token=cf-agent-a  source_ip=127.0.0.9    -> HTTP 200  seq=299  corr=afeac940186b…
token=cf-agent-a  source_ip=127.0.0.10   -> HTTP 200  seq=300  corr=464e7d2aaceb…
```

Ledger attribution for those three calls:

```
seq 300  agent_id=cf-agent-a  tenant=acme-platform  alias=cf.d1.databases.list
seq 299  agent_id=cf-agent-a  tenant=acme-platform  alias=cf.d1.databases.list
seq 298  agent_id=cf-agent-a  tenant=acme-platform  alias=cf.d1.databases.list
```

Identical attribution from three different addresses. Identity comes from the
signed token and nothing else — there is no network-derived signal to spoof, no
allowlisted subnet that silently becomes an authorization boundary, and moving an
agent between hosts, pods or regions changes no decision and no audit trail.

The flip side, stated plainly: **the ledger does not record source IP.** That is
deliberate — it is not an authorization input, so it is not evidence the gateway
claims to hold. If your incident process needs network provenance, it comes from
your ingress or service-mesh logs, joined to MCPIP records on `correlation_id`.

## 3. The humans are not one role

The most common way an authorization layer fails an organization is a
super-admin: one entitlement that, once stolen, opens everything. MCPIP's
capabilities are deliberately non-hierarchical. Measured:

| route | operator | auditor | reviewer | agent |
|---|---|---|---|---|
| `GET /v1/catalog` | `200` | `200` | `200` | `200` |
| `GET /v1/admin/stats` | `200` | `403` | `403` | `403` |
| `GET /v1/admin/decisions/recent` | `200` | `403` | `403` | `403` |
| `POST /v1/admin/skills/register` | `200` | `403` | `403` | `403` |
| `GET /v1/admin/forensic/{corr}` | **`403`** | `404`¹ | `403` | `403` |
| `GET /v1/admin/extensions/pending` | **`403`** | `403` | **`200`** | `403` |

¹ `404`, not `403` — the auditor *is* authorized; there was simply no forensic
capture stored for that correlation id. The distinction matters: a `403` is a
capability refusal, a `404` is an authorized lookup that found nothing.

Read the operator column. The platform operator — who can register aliases,
read every decision and revoke any principal — **cannot** read a forensic payload
capture and **cannot** review a pending extension. `CAP_DIRECTORY_ADMIN` does not
subsume `CAP_FORENSIC_READ` or `CAP_CATALOG_REVIEWER`; they are separate grants
held by separate people.

The practical consequence: stealing the operator's token does not get you the
payload contents of past calls. That is a different capability, and the theft of
one does not compound into the other.

## 4. An incident, mid-traffic

A platform operator suspects `cf-agent-a`'s key is compromised while the fleet is
running. The agent holds a valid, unexpired, correctly-signed JWT.

Six calls, in order. The token is never re-issued, edited or re-signed at any
point — the same bearer is presented throughout:

| # | call | as | result |
|---|---|---|---|
| 1 | `POST /v1/authorize` | `cf-agent-a` | `200` |
| 2 | `POST /v1/admin/principals/cf-agent-a/revoke`<br>`{"reason":"suspected key compromise"}` | operator | `{"revoked":"cf-agent-a"}` |
| 3 | `POST /v1/authorize` — same token, still valid, still unexpired | `cf-agent-a` | **`403`** |
| 4 | `POST /v1/authorize` | `cf-agent-b` | `200` — peer unaffected |
| 5 | `POST /v1/admin/principals/cf-agent-a/reactivate`<br>`{"reason":"key rotated"}` | operator | `{"reactivated":"cf-agent-a","removed":true}` |
| 6 | `POST /v1/authorize` | `cf-agent-a` | `200` |

The ledger, with the reason the agent never saw:

```
seq 314  allow                       cf-agent-a
seq 312  allow                       cf-agent-b
seq 311  deny   principal_revoked    cf-agent-a
seq 309  allow                       cf-agent-a
```

The gaps are the point, not an omission. The decision feed lists *decisions*; 310
and 313 are the revoke and the reactivate themselves, sitting in the same ledger as
admin actions:

```json
{
  "actor_agent_id": "mcpip-admin",
  "admin_action": "principal_revoke",
  "correlation_id": "b481f8e3d3e54581a8ae3c4e46f2c3aa",
  "decision": "admin_action",
  "deny_reason": null,
  "reason": "suspected key compromise",
  "subject_agent_id": "cf-agent-a",
  "tenant_id": "acme-platform"
}
```

Actor, subject and reason, written before the kill-switch takes effect.

Three properties worth naming:

- **Containment is per-identity.** `cf-agent-b`, same team, same alias, same
  second, never noticed.
- **No credential was touched.** MCPIP did not mint, edit, or re-sign anything.
  The IdP remains the sole source of identity; the gateway simply refuses a
  principal. That is what makes the control safe to hand to an operator who is
  not trusted to issue credentials.
- **The revocation is itself audited.** The admin action is WORM-logged with
  actor, subject and reason *before* it takes effect — an IAM control that is not
  auditable is not a control.

Revocation outlives the token: it holds until an admin reactivates, so a stolen
JWT cannot be waited out until expiry.

## 5. What the tenant looks like afterwards

`GET /v1/admin/stats` answers in JSON. Reduced to the three lines that matter here:

```console
$ curl -s -H "Authorization: Bearer $OPERATOR" "$GW/v1/admin/stats" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("governed agent identities:", d["governed_agent_identity_count"])
print("decisions               :", d["decisions"])
print("license                 :", d["license"]["customer"], "|", d["license"]["tier"])'
```

which for this run printed:

```
governed agent identities: 8
decisions               : {'allow': 63, 'deny': 17, 'staged': 0}
license                 : Cloudflare Platform Ops | self-hosted
```

That count is discovered from traffic, not read from a roster someone maintained by
hand. It is a HyperLogLog cardinality over the distinct `agent_id`s the gateway
verified on the authorization path during the run — so it counts identities that
actually did something, and it is a number, never a list: the ids themselves are
never stored or exposed by this endpoint. The full response carries
more than these three fields (telemetry and response-playbook state, and a
`features` block explaining why forensic capture is off by default in production);
the reduction above is this document's, not the gateway's.

The console view of the same state (from the sandbox instance used for the
screenshot, since the console authenticates via a sandbox-only route — see
[`E2E_WALKTHROUGH.md` §13](E2E_WALKTHROUGH.md#13-the-operator-console)):

![MCPIP console Live monitor: 9 decisions since start — 3 allow, 3 deny, 3 staged — gateway p50 62.5 ms, audit chain Intact at seq 12 epoch 2, readiness Ready, catalog 9](images/console-live.png)

## 5a. Reporting across the period

The console shows now; an audit asks about ninety days. `scripts/soc2_report.py`
walks the paged decision history for a window and emits a period report where
every figure names the records behind it:

```bash
python3 scripts/soc2_report.py --gateway <url> --token-file operator.jwt \
  --days 90 --out report.md --json report.json
# report -> report.md  (225 decisions, coverage=exhausted)
```

For the fleet above it reported 225 decisions across `worm_sequence` 11–238,
bound to a signed period-end commitment (epoch 33, Merkle root
`81c4a9b6…`, `intact: true`), with per-agent, per-alias, per-deny-reason
breakdowns that each carry their sequence range and sample correlation ids. See
[`E2E_WALKTHROUGH.md` §13a](E2E_WALKTHROUGH.md#13a-from-a-number-back-to-the-records--the-soc-2-report).

## 6. Scaling notes, honestly

- **The 204–228 req/s figures are a shape, not a benchmark.** Single worker,
  local Redis, loopback, one tenant, on a shared box. Production runs
  `--workers N` behind a load balancer. Treat them as evidence that concurrent
  multi-agent traffic keeps clean per-identity attribution, not as capacity
  numbers — an earlier run of the same harness on a quieter machine reached
  336 req/s with the identical verdicts.
- **"Different source IPs" here means loopback aliases,** not separate machines.
  It exercises distinct client hosts and independent connections against the same
  kernel — it does not exercise real network latency, NAT, TLS termination, or a
  load balancer's connection reuse.
- **The p50 is dominated by the durability contract.** Every allow requires an
  fsync-durable ledger write *before* it returns (`appendfsync always`). That is
  the write-before-execute guarantee being paid for, and it is the right trade
  for an audit-bearing choke point.
- **One tenant only.** Cross-tenant isolation is a real control but was not
  exercised here — every principal above shares `acme-platform`. The refusals in §2
  and §3 come from risk tiers and capabilities, not from tenant separation.
- **Compartments were not used.** All aliases were registered with
  `compartment: null`. Compartment scoping is how a large organization stops
  `gh-agent-*` from even *seeing* the Cloudflare aliases; this run relied on the
  risk gate instead.

## Reproducing

Two committed harnesses, both supplied tokens and neither minting any — MCPIP never
issues identity, so a harness must not either. Mint with `scripts/mint_principal.py`.

```bash
export GW=http://127.0.0.1:8080

# 2 — everyone at once
python load/concurrent_agents.py --base $GW \
  --agent cf-agent-a=cf_a.jwt:cf.d1.databases.list \
  --agent cf-agent-b=cf_b.jwt:cf.d1.databases.list \
  --agent gh-agent-a=gh_a.jwt:gh.branches.list \
  --agent gh-agent-b=gh_b.jwt:gh.branches.list \
  --agent ci-agent-1=ci.jwt:gh.branches.list \
  --agent data-agent-1=data.jwt:cf.d1.query \
  --calls 12 --workers 24

# 2.1 — the same run, each agent from its own client host
python load/concurrent_agents.py --base $GW --bind-source-ips --calls 25 [--agent ...]
```

Sustained-rate figures and the per-client-type comparison come from the k6 suite
instead — see [`LOAD_AT_SCALE.md`](LOAD_AT_SCALE.md#reproducing).
