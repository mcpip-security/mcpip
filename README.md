# MCPIP

**Authorize every AI agent action before it executes.**

[![CI](https://github.com/mcpip-security/mcpip/actions/workflows/ci.yml/badge.svg)](https://github.com/mcpip-security/mcpip/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-3.0.0-informational)](CHANGELOG.md)
[![Core license](https://img.shields.io/badge/core-BSL%201.1-blue)](#license)
[![SDK license](https://img.shields.io/badge/SDKs-Apache--2.0-blue)](#license)

![Two agents on one gateway: engineering never sees the finance wage sheet in its tool
list, asks for it anyway, and gets an opaque deny](docs/evidence/images/quickstart.gif)

<sub>Recorded from `./scripts/quickstart.sh` on an ordinary laptop. The raw capture is
[`quickstart.ansi`](docs/evidence/images/quickstart.ansi) and the frames are drawn from it by
[`scripts/render_quickstart_gif.py`](scripts/render_quickstart_gif.py) — lines are omitted for
length, none are reworded. Run it yourself and the correlation ids will differ; nothing else
should.</sub>

MCPIP is a self-hosted authorization gateway that sits between an AI agent's tool call and the
system that runs it. The agent proposes an action; MCPIP decides whether it is allowed; your
systems execute. Nothing reaches production without a signed, immutable record written first.

It is deliberately narrow. It does not host models, run agents, or proxy prompts.

---

## Quickstart

Requires Python 3.12 and Redis. One command then brings up Redis, the gateway, and a
governed walkthrough, and prints your time-to-first-authorized-call. Idempotent, so it is
safe to re-run.

```bash
git clone https://github.com/mcpip-security/mcpip.git && cd mcpip
./scripts/quickstart.sh
```

**13 seconds** from a cold clone to nine real decisions — five allowed, four denied
opaquely — and about **15** to a first authorized call in full fail-closed production
posture, self-issued keys and signed license included. Measured, with transcripts and the
caveats, in [Time to first authorized call](docs/evidence/TIME_TO_FIRST_CALL.md); the
script prints *your* number rather than ours.

On macOS the script installs Redis via Homebrew if it is missing. On Linux, install it
first — `sudo apt-get install redis-server`, or the equivalent for your distribution.

In sandbox mode the gateway mints identities for you, standing in for your IdP. Get one:

```bash
JWT=$(curl -s -X POST http://localhost:8080/v1/dev/token \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-acme","agent_id":"agent-1"}' | jq -r .jwt)
```

Then authorize a call — straight HTTP:

```bash
curl -s -X POST http://localhost:8080/v1/authorize \
  -H "authorization: Bearer $JWT" -H 'content-type: application/json' -d '{
    "source_format": "openai_tool_call",
    "tool_call": {"id":"call_1","type":"function","function":{
      "name":"skill_spend_summary","arguments":"{\"period\":\"2026-Q2\"}"}}
  }'
```

Through the CLI:

```bash
pipx install mcpip-sdk
mcpip login --gateway http://localhost:8080 --sandbox --context sbx
mcpip --context sbx sandbox dev-token --agent ops-1
mcpip --context sbx authorize skill_spend_summary --arg period=2026-Q2
```

Or from any MCP client — the gateway *is* an MCP server. Use the `$JWT` from above:

```json
{
  "mcpServers": {
    "mcpip": {
      "type": "http",
      "url": "http://localhost:8080/v1/mcp",
      "headers": { "Authorization": "Bearer eyJhbGciOi..." }
    }
  }
}
```

When a call denies, `mcpip why <correlation_id>` tells you the reason and the fix — the
agent-facing wire stays opaque, but you are the operator.

Full walkthrough: [Getting Started](docs/start/GETTING_STARTED.md).

## Where to go next

| You are | Start here |
|---|---|
| A developer connecting an agent | [Getting Started](docs/start/GETTING_STARTED.md), then [SDK](docs/start/SDK.md) or [CLI](docs/start/CLI.md) |
| An operator running the gateway | [Operations](docs/operate/OPERATIONS.md) and [Compliance](docs/operate/COMPLIANCE.md) |
| An architect evaluating the design | [Architecture](docs/integrate/ARCHITECTURE.md) and the [whitepaper](docs/background/WHITEPAPER.md) |
| A security reviewer | [Threat model](docs/SECURITY_THREAT_MODEL.md) and [Evidence](docs/evidence/README.md) |

## How it works

Every request walks the same four stages, in the same order. A failure at any stage denies
immediately and writes a signed audit record; the caller receives only a correlation id.

```
  agent tool call (any dialect) + signed JWT
                 |
                 v
  +-----------+  +--------------+  +----------+  +---------+
  |  BRIDGE   |->|  OBFUSCATOR  |->|   AUTH   |->|  AUDIT  |-> execute
  | normalize |  | alias->target|  | identity |  | signed  |
  |  + schema |  |  tenant +    |  | + payload|  | Merkle  |
  |  rigidity |  | compartment  |  |   lock   |  |  epoch  |
  +-----------+  +--------------+  +----------+  +---------+
                                                      |
                          real target the agent never learns
```

| Stage | Guarantees |
|---|---|
| **Bridge** | Any provider tool call becomes one `NormalizedIntent`. The parser is chosen by the **declared** format, never by inspecting payload bytes. Depth and size caps, illegal-character rejection, identity-injection hard-deny. |
| **Obfuscator** | Tenant-scoped `alias → target`. Agents call `skill_payroll_run`; they never see `mainframe.cics.PAYR`. Unknown or cross-tenant resolves to a deny. |
| **Auth** | Identity comes only from a verified JWT. High-risk actions require a 6-digit code bound to the SHA-256 of the canonical payload, spent exactly once via a single Redis Lua `EVAL`. |
| **Audit** | Every decision is durably buffered **before** the action is authorized, then sealed into per-epoch Merkle roots that are root-chained and Ed25519-signed. Inclusion proofs are O(log n). |

Two properties do most of the work:

**Fail-closed.** If any check cannot complete — Redis is down, a key is missing, a document is
malformed — the request is denied. MCPIP cannot authorize what it cannot audit.

**Opaque.** A denial returns one generic message and a `correlation_id`. The agent never learns
which check fired, or whether the alias even exists. Reasons live in the audit log.

## Connecting agents

One ingress for every framework. Seven wire formats, selected by a declared `source_format`.
82 named vendor ids resolve onto six of them through a hash-pinned registry — `raw_mcp` is the
direct form and has no vendor alias. Every id is listed in [API.md](docs/start/API.md).

| Format | Source |
|---|---|
| `openai_tool_call` | OpenAI, Azure OpenAI, and the OpenAI-compatible ecosystem |
| `anthropic_tool_use` | Anthropic, including Bedrock- and Vertex-hosted |
| `gemini_function_call` | Gemini, Vertex AI |
| `bedrock_tool_use` | Bedrock Converse |
| `mcp_jsonrpc` | Any MCP client |
| `raw_mcp` | The direct `{tool, arguments}` form |
| `a2a_task` | A2A task envelopes |

The format is declared because sniffing lets a caller pick the parser that validates least. An
unknown vendor is an opaque `403`; a request declaring neither field is a `422`.

### Host integrations

Because the gateway *is* an MCP server, any MCP client can put its tool calls behind it with
no new code. [`integrations/openclaw/`](integrations/openclaw/) is that, packaged as a
drop-in skill for [OpenClaw](https://docs.openclaw.ai) — a local-first assistant that holds
real credentials, acts on a heartbeat, and runs community-authored markdown skills. It also
tells the agent how to behave when it is refused, which is the half that usually goes
missing: do not retry, do not route around, report the correlation id and stop.

MCPIP is an authorization **interceptor, not a proxy**. Your application calls its model
directly, with its own keys and its own billing. MCPIP receives only the resulting tool call.
Every connector is a pure parser: no LLM SDKs, no credentials, no outbound network. That is
mechanically enforced — `tests/test_connector_conformance.py` scans every connector module and
fails the build on any such import.

## What it enforces, and what it does not

The most useful thing a security component can tell you is where it stops.

**MCPIP enforces**

- Per-call authorization on the exact payload — not a session, not a scope granted an hour ago
- Alias-to-target resolution, so the real host and credential never cross the boundary
- Payload-bound step-up: change one field and the approval no longer covers the action
- Write-before-execute audit, so evidence cannot be lost by the thing it was recording
- Compartment and capability separation, plus canary aliases that trip on enumeration

**Your identity provider owns** who an agent is. MCPIP only ever *verifies* JWTs. It never mints
identity, and the `role` claim authorizes nothing — entitlements come from capability UUIDs and
grants. Hosting the gateway does not put us in your authentication trust path.

**Your runtime owns** which files and shells the agent can touch, model choice, billing, and the
sandbox it executes in. MCPIP governs what reaches *your systems*, not what happens inside the
agent.

**MCPIP does not provide**

- An agent execution environment or sandbox
- Model hosting, inference, or any LLM credential — the gateway never calls a model
- A memory or vector store
- An LLM proxy. Tool calls cross the authorization boundary; prompts and completions never do.
- **Meaningful constraint on an open-ended alias** — see below. This is the sharpest limit here.

### The open-ended tool problem

Everything above works because an alias names a *narrow* action. Point one at `run_shell(cmd)`
or `execute_sql(query)` and most of it stops paying: the alias is a single catalog entry, the
payload is arbitrary, and per-call authorization collapses into a binary "may this agent shell
at all." That is one alias away from allow-everything, and no policy language fixes it — the
tool is the problem, not the expression.

Three honest positions, in order of how much they actually buy:

1. **Don't expose the open-ended tool.** The indirection is exactly the instrument for this:
   replace `run_shell` with `skill_restart_service`, `skill_tail_log`, `skill_rollback_deploy`.
   That converts an ungovernable surface into a governable one. It is real work, and it is the
   only option here that *prevents* anything.
2. **Where you cannot, the gate stops being prevention and becomes attribution.** The payload is
   still bound and written to the signed ledger before execution, so every command is
   non-repudiably tied to an identity, a session and a correlation id. That is a genuinely
   weaker claim and is labelled weaker on purpose.
3. **Where an agent truly needs arbitrary shell, this is the wrong layer.** Use OS confinement —
   seccomp, an LSM, a container boundary. Complementary to MCPIP, not competing with it.

The same asymmetry applies upstream: MCPIP does nothing about *where a skill came from*. What it
does is make provenance less load-bearing, since a malicious skill still cannot call what the
identity was never granted. Both, not either.

## Status

Version 3.0.0. Source-available core under BSL 1.1; SDKs under Apache-2.0.

**Shipped and tested**

- The full pipeline, fail-closed and opaque end to end
- 7 wire formats, plus 82 named vendor ids mapping onto six of them through a hash-pinned registry that refuses to boot on drift
- Payload-bound one-time step-up; a changed byte is a different request with no approval behind it
- Ed25519 Merkle audit written before dispatch, with offline re-verification
- Compartment and capability separation, canary tripwires, ReBAC projection, the operator console
- 1,600+ tests, `mypy --strict`, and a self-verifying 29-check proof that exits non-zero if any check fails

**Being wired up**

- **Out-of-band approval delivery.** The step-up ceremony is complete; the transport that reaches
  a human is a documented integration point. With none configured the gateway fails closed rather
  than staging a challenge nobody can answer.
- **Long-horizon decision retention.** Signed epoch roots are durable; per-decision rows are a
  bounded hot buffer, and a query reports its own horizon rather than answering an out-of-range
  window with a confident "nothing happened".
- **SSO, SAML, SCIM.** Planned, not shipped. Named here because it appears on pricing pages.

**Deliberately not built**

- No execution sandbox, model hosting, or LLM credential
- No identity minting — your IdP stays sovereign
- No inference in the authorization path. Decisions are deterministic, which is what makes them
  replayable and auditable.

## The executable proof

`python main.py` runs the pipeline in-process against 29 checks — 7 allow-paths and 22 attacks,
covering identity, the payload lock, compartments, capability grants, canary tripwires and the
deny-only policy overlay. Each prints `PASS` or `FAIL`. The process exits `0` only if every
check holds, then re-reads the audit log and asserts the signed Merkle chain is intact.

It exercises the engine directly rather than over HTTP, so it proves the authorization logic,
not a running deployment. To check a deployment, use `mcpip verify` for the release and
`GET /readyz` plus a real authorize call for the gateway.

## Operator console

```bash
cd dashboard && npm install && npm run dev     # http://localhost:5173
```

Live decision stream, catalog, principals, delegation lineage, audit verification, and the
compliance evidence bundle. Desktop builds are in [Operations](docs/operate/OPERATIONS.md).

## Documentation

| Area | Docs |
|---|---|
| **Start** | [Getting Started](docs/start/GETTING_STARTED.md) · [API reference](docs/start/API.md) · [SDK](docs/start/SDK.md) · [CLI](docs/start/CLI.md) |
| **Operate** | [Operations](docs/operate/OPERATIONS.md) · [Compliance](docs/operate/COMPLIANCE.md) · [Response playbook](docs/operate/RESPONSE_PLAYBOOK.md) · [Telemetry](docs/operate/TELEMETRY.md) · [Release](docs/operate/RELEASE.md) |
| **Build** | [Architecture](docs/integrate/ARCHITECTURE.md) · [Repository reference](docs/integrate/REPOSITORY.md) · [Integrations](docs/integrate/INTEGRATIONS.md) · [Extensibility](docs/integrate/EXTENSIBILITY.md) · [Workspace generate](docs/integrate/WORKSPACE_GENERATE.md) · [Local model](docs/integrate/LOCAL_MODEL.md) |
| **Understand** | [Whitepaper](docs/background/WHITEPAPER.md) · [Threat model](docs/SECURITY_THREAT_MODEL.md) · [Session delegation](docs/SESSION_DELEGATION_DESIGN.md) |
| **Verify** | [Evidence](docs/evidence/README.md) — real runs, with transcripts, including what each run did *not* prove · [Time to first call](docs/evidence/TIME_TO_FIRST_CALL.md) |

Everything is indexed in [`docs/`](docs/README.md).

## Security

Report vulnerabilities per [SECURITY.md](SECURITY.md). Please do not open public issues for
security reports.

The invariants that hold on every request — timing safety, the TOCTOU payload lock, deep schema
rigidity, identity sovereignty, capability-not-role authorization, fail-closed opacity, and
stateless nodes — are specified with their mechanisms and enforcement points in the
[threat model](docs/SECURITY_THREAT_MODEL.md).

## Project

- [Contributing](.github/CONTRIBUTING.md) · [Code of conduct](.github/CODE_OF_CONDUCT.md) · [Support](.github/SUPPORT.md)
- [Changelog](CHANGELOG.md)
- Policies: [licensing](docs/policies/LICENSING.md) · [privacy](docs/policies/PRIVACY.md) · [terms](docs/policies/TERMS.md) · [trademark](docs/policies/TRADEMARK.md) · [notices](docs/policies/NOTICES.md)

## License

The core is source-available under the Business Source License 1.1 — free to self-host, read,
modify, and run, including in production, with the single restriction that you may not offer
MCPIP itself as a competing hosted service. Both client SDKs are Apache-2.0, so anything you
build against the gateway carries no copyleft or field-of-use restriction.

See [LICENSE](LICENSE) and [licensing policy](docs/policies/LICENSING.md).
