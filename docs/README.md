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
| [GETTING_STARTED.md](start/GETTING_STARTED.md) | Quickstart · connect an agent (REST + MCP) · Claude/MCP client setup · standing up a gateway · the end-to-end request lifecycle · the runnable demo-company walkthrough. |
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
| [INTEGRATIONS.md](integrate/INTEGRATIONS.md) | Cloud/identity integration patterns: workload identity (SPIFFE), the OAuth 2.1 resource-server metadata, the governed-alias pattern, and the DynamoDB cloud-IAM live-fire walkthrough. |
| [EXTENSIBILITY.md](integrate/EXTENSIBILITY.md) | Author-your-own community **skills** (implemented) and **gates** (CEL runtime deferred) — reviewer-approval + WORM record + hash-pin. |
| [WORKSPACE_GENERATE.md](integrate/WORKSPACE_GENERATE.md) | Brief → governed workspace scaffold: the draft/validate/apply endpoints, inference-free core with an optional local-first LLM toolchain. |
| [LOCAL_MODEL.md](integrate/LOCAL_MODEL.md) | Bring your own model — the gateway is inference-free and never calls one; the optional drafting path takes any OpenAI-compatible endpoint (Ollama, llama.cpp, vLLM, LM Studio, your own). Two settings, no bundled weights. |
| [IMPLEMENTATION_WEB.md](integrate/IMPLEMENTATION_WEB.md) | The web/console implementation reference. |

## Background

| Doc | What's inside |
|---|---|
| [WHITEPAPER.md](background/WHITEPAPER.md) | The technical whitepaper (standalone artifact). |

## Evidence

Real runs against a real gateway — every command, input, output and screenshot
reproduced from an actual execution, including what each run did *not* prove.

| Doc | What's inside |
|---|---|
| [E2E_WALKTHROUGH.md](evidence/E2E_WALKTHROUGH.md) | One production cycle end to end: key ceremony · signed license · the four gates that refuse a production boot · governed Cloudflare and GitHub calls with full request/response · the five developer integration paths · the persona capability matrix · the PIN step-up cycle including replay denial · WORM trace and tamper detection · period SOC 2 reporting. |
| [ORGANIZATION_AT_SCALE.md](evidence/ORGANIZATION_AT_SCALE.md) | A whole org on the gateway: concurrent multi-agent traffic from separate client hosts, the non-hierarchical capability matrix (no super-admin), and a live revocation mid-traffic. |
| [LOAD_AT_SCALE.md](evidence/LOAD_AT_SCALE.md) | k6 load results by client type — which surface degrades first (the auditor's `verify_chain`), and the direction of failure past the knee: at 62% transport failure not one safety invariant broke, so it sheds load by denying, never by allowing. |

---

Repo-root docs also worth knowing: [`../README.md`](../README.md) (project overview),
[`../SECURITY.md`](../SECURITY.md) + [`../SECURITY_THREAT_MODEL.md`](../SECURITY_THREAT_MODEL.md)
(adversary model + ASI coverage), [`../LICENSING.md`](../LICENSING.md) (BSL core / Apache
SDKs), [`../RELEASE.md`](../RELEASE.md) (release ceremony), and [`../CHANGELOG.md`](../CHANGELOG.md).

Project policies: [`../TERMS.md`](../TERMS.md) (terms of use) ·
[`../PRIVACY.md`](../PRIVACY.md) (data handling) · [`../TRADEMARK.md`](../TRADEMARK.md)
(name & mark) · [`../CONTRIBUTING.md`](../CONTRIBUTING.md) ·
[`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md).
