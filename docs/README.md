# MCPIP Documentation

MCPIP is a self-hosted, fail-closed, **opaque authorization gateway** that sits between
an AI agent's tool call and the system that executes it — *"AI reasons, MCPIP authorizes,
systems execute."* Pipeline: **Bridge** (normalize 7 provider dialects → one intent) →
**Obfuscator** (opaque alias → hidden target) → **Auth** (verified-JWT identity +
payload-bound one-time PIN) → **Audit** (Ed25519 Merkle WORM log, written *before*
execution).

The documentation is organized into the hubs below — each is a folder. Start with
**Getting Started**; operators go to **Operations**.

```
docs/
├── start/       first contact — quickstart, SDKs, CLI
├── operate/     running it — day-2, compliance, telemetry, incident response
├── integrate/   integrating and extending — architecture, connectors, skills, models
├── background/  the whitepaper
└── evidence/    real end-to-end runs, with the transcripts and screenshots
```

## Start here

| Doc | What's inside |
|---|---|
| [GETTING_STARTED.md](start/GETTING_STARTED.md) | Quickstart · connect an agent (REST + MCP) · Claude/MCP client setup · standing up a gateway · the end-to-end request lifecycle · the runnable walkthrough. |
| [API.md](start/API.md) | The HTTP API reference — the five-endpoint agent surface, the step-up flow, the operator and audit surfaces, and which five endpoints exist only in sandbox. |
| [SDK.md](start/SDK.md) | The Python + TypeScript client SDKs — the three-client model, PIN ceremony, envelope builders, admin surface, opaque-deny semantics (full console parity). |
| [CLI.md](start/CLI.md) | The first-class `mcpip` CLI (git/kubectl-style) — commands, flags, and plug-and-play usage. |

## Operate

| Doc | What's inside |
|---|---|
| [OPERATIONS.md](operate/OPERATIONS.md) | Running MCPIP · day-2 runbook (keys, releases, `mcpip verify`, audit export, upgrades) · network enforcement & non-bypassability · deploying behind a service mesh / IAP · desktop packaging · multi-region topology & residency. |
| [COMPLIANCE.md](operate/COMPLIANCE.md) | The portable compliance-evidence posture (SOC 2 CC6.x, EU AI Act, ISO 42001, …) — evidence, never a certification. |
| [TELEMETRY.md](operate/TELEMETRY.md) | The opt-in, off-hot-path signed telemetry beacon — what it sends (aggregate integers only), and how to disable it. |

## Build & integrate

| Doc | What's inside |
|---|---|
| [ARCHITECTURE.md](integrate/ARCHITECTURE.md) | The design references: the A2A side-effect choke point, the data-plane-fork owner memo, and the WORM group-commit throughput design. |
| [REPOSITORY.md](integrate/REPOSITORY.md) | Where everything lives — the tree, the four pipeline stages module by module, the service layer, and the tests that carry specific weight. |
| [INTEGRATIONS.md](integrate/INTEGRATIONS.md) | Cloud/identity integration patterns: workload identity (SPIFFE), the OAuth 2.1 resource-server metadata, the governed-alias pattern, and the DynamoDB cloud-IAM live-fire walkthrough. |
| [EXTENSIBILITY.md](integrate/EXTENSIBILITY.md) | Author-your-own community **skills** (implemented) and **gates** (CEL runtime deferred) — reviewer-approval + WORM record + hash-pin. |
| [WORKSPACE_GENERATE.md](integrate/WORKSPACE_GENERATE.md) | Brief → governed workspace scaffold: the draft/validate/apply endpoints, inference-free core with an optional local-first LLM toolchain. |
| [LOCAL_MODEL.md](integrate/LOCAL_MODEL.md) | Bring your own model — the gateway is inference-free and never calls one; the optional drafting path takes any OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM, LM Studio, your own). Two settings, no bundled weights. |
| [IMPLEMENTATION_WEB.md](integrate/IMPLEMENTATION_WEB.md) | **Design spec, not shipped** — the contract for a dedicated human-in-the-loop approval UI (a `/v2/*` surface the gateway does not serve). Kept for its trust-boundary analysis; the shipped console is `dashboard/`. |

## Background

| Doc | What's inside |
|---|---|
| [WHITEPAPER.md](background/WHITEPAPER.md) | The technical whitepaper (standalone artifact). |
| [SESSION_DELEGATION_DESIGN.md](SESSION_DELEGATION_DESIGN.md) | Session attribution + attenuated delegation (**shipped**): every decision names the session that made it; a session can grant a child ⊆ of its own authority via `POST /v1/delegate`, the authorize path intersects, and revocation cascades down the subtree. Behind `MCPIP_DELEGATION_ENABLED` (default off). |

## Evidence

Real runs against a real gateway — every command, input, output and screenshot
reproduced from an actual execution, including what each run did *not* prove.

Split two ways — start at [`evidence/README.md`](evidence/README.md).

**By client type** — one file per caller: its surface, the capabilities it holds *and
is refused*, its measured latency, what a call costs it.

| Client | Holds | Reading it tells you |
|---|---|---|
| [agent](evidence/clients/agent.md) | *(none)* | ~97 tokens per governed call; the only type on the fsync write-before-execute path |
| [developer](evidence/clients/developer.md) | *(none)* | five integration paths, and why the identity that would most benefit cannot register an alias |
| [PDP consumer](evidence/clients/pdp.md) | *(none)* | the cheapest surface — 5 output tokens — and that you own enforcement |
| [operator](evidence/clients/operator.md) | `CAP_DIRECTORY_ADMIN` | the most expensive surface (~2,683 tokens), and the two routes the operator is refused |
| [auditor](evidence/clients/auditor.md) | `CAP_FORENSIC_READ` | the starvation finding: `verify_chain` degrades every other client type |
| [reviewer](evidence/clients/reviewer.md) | `CAP_CATALOG_REVIEWER` | that no super-admin exists — it holds the one route the operator cannot reach |

**By scenario** — does the whole thing work?

| Doc | What's inside |
|---|---|
| [E2E_WALKTHROUGH.md](evidence/E2E_WALKTHROUGH.md) | One production cycle end to end: key ceremony · signed license · the four gates that refuse a production boot · governed Cloudflare and GitHub calls with full request/response · the five developer integration paths · the persona capability matrix · the PIN step-up cycle including replay denial · WORM trace and tamper detection · period SOC 2 reporting. |
| [ORGANIZATION_AT_SCALE.md](evidence/ORGANIZATION_AT_SCALE.md) | A whole org on the gateway: concurrent multi-agent traffic from separate client hosts, the non-hierarchical capability matrix (no super-admin), and a live revocation mid-traffic. |
| [LOAD_AT_SCALE.md](evidence/LOAD_AT_SCALE.md) | The cross-type comparison under load — which surface degrades first (the auditor's `verify_chain`), and the direction of failure past the knee: at 62% transport failure not one safety invariant broke, so it sheds load by denying, never by allowing. |

---

Repo-root docs also worth knowing: [`../README.md`](../README.md) (project overview),
[`../SECURITY.md`](../SECURITY.md) + [`../docs/SECURITY_THREAT_MODEL.md`](../docs/SECURITY_THREAT_MODEL.md)
(adversary model + ASI coverage), [`../docs/policies/LICENSING.md`](../docs/policies/LICENSING.md) (BSL core / Apache
SDKs), [`../docs/operate/RELEASE.md`](../docs/operate/RELEASE.md) (release ceremony), and [`../CHANGELOG.md`](../CHANGELOG.md).

Project policies: [`../docs/policies/TERMS.md`](../docs/policies/TERMS.md) (terms of use) ·
[`../docs/policies/PRIVACY.md`](../docs/policies/PRIVACY.md) (data handling) · [`../docs/policies/TRADEMARK.md`](../docs/policies/TRADEMARK.md)
(name & mark) · [`../.github/CONTRIBUTING.md`](../.github/CONTRIBUTING.md) ·
[`../.github/CODE_OF_CONDUCT.md`](../.github/CODE_OF_CONDUCT.md).
