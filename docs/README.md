# MCPIP Documentation

MCPIP is a self-hosted, fail-closed, **opaque authorization gateway** that sits between
an AI agent's tool call and the system that executes it — *"AI reasons, MCPIP authorizes,
systems execute."* Pipeline: **Bridge** (normalize 7 provider dialects → one intent) →
**Obfuscator** (opaque alias → hidden target) → **Auth** (verified-JWT identity +
payload-bound one-time PIN) → **Audit** (Ed25519 Merkle WORM log, written *before*
execution).

The documentation is organized into the hubs below. Start with
**Getting Started**; operators go to **Operations**.

## Start here

| Doc | What's inside |
|---|---|
| [GETTING_STARTED.md](GETTING_STARTED.md) | Quickstart · connect an agent (REST + MCP) · Claude/MCP client setup · standing up a gateway · the end-to-end request lifecycle · the runnable demo-company walkthrough. |
| [SDK.md](SDK.md) | The Python + TypeScript client SDKs — the three-client model, PIN ceremony, envelope builders, admin surface, opaque-deny semantics (full console parity). |
| [CLI.md](CLI.md) | The first-class `mcpip` CLI (git/kubectl-style) — commands, flags, and plug-and-play usage. |

## Operate

| Doc | What's inside |
|---|---|
| [OPERATIONS.md](OPERATIONS.md) | Running MCPIP · day-2 runbook (keys, releases, `mcpip verify`, audit export, upgrades) · network enforcement & non-bypassability · deploying behind a service mesh / IAP · desktop packaging · multi-region topology & residency. |
| [COMPLIANCE.md](COMPLIANCE.md) | The portable compliance-evidence posture (SOC 2 CC6.x, EU AI Act, ISO 42001, …) — evidence, never a certification. |
| [TELEMETRY.md](TELEMETRY.md) | The opt-in, off-hot-path signed telemetry beacon — what it sends (aggregate integers only), and how to disable it. |

## Build & integrate

| Doc | What's inside |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The design references: the A2A side-effect choke point, the data-plane-fork owner memo, and the WORM group-commit throughput design. |
| [INTEGRATIONS.md](INTEGRATIONS.md) | Cloud/identity integration patterns: workload identity (SPIFFE), the OAuth 2.1 resource-server metadata, the governed-alias pattern, and the DynamoDB cloud-IAM live-fire walkthrough. |
| [EXTENSIBILITY.md](EXTENSIBILITY.md) | Author-your-own community **skills** (implemented) and **gates** (CEL runtime deferred) — reviewer-approval + WORM record + hash-pin. |
| [WORKSPACE_GENERATE.md](WORKSPACE_GENERATE.md) | Brief → governed workspace scaffold: the draft/validate/apply endpoints, inference-free core with an optional local-first LLM toolchain. |
| [IMPLEMENTATION_WEB.md](IMPLEMENTATION_WEB.md) | The web/console implementation reference. |

## Background

| Doc | What's inside |
|---|---|
| [WHITEPAPER.md](WHITEPAPER.md) | The technical whitepaper (standalone artifact). |

---

Repo-root docs also worth knowing: [`../README.md`](../README.md) (project overview),
[`../SECURITY.md`](../SECURITY.md) + [`../SECURITY_THREAT_MODEL.md`](../SECURITY_THREAT_MODEL.md)
(adversary model + ASI coverage), [`../LICENSING.md`](../LICENSING.md) (BSL core / Apache
SDKs), [`../RELEASE.md`](../RELEASE.md) (release ceremony), and [`../CHANGELOG.md`](../CHANGELOG.md).

Project policies: [`../TERMS.md`](../TERMS.md) (terms of use) ·
[`../PRIVACY.md`](../PRIVACY.md) (data handling) · [`../TRADEMARK.md`](../TRADEMARK.md)
(name & mark) · [`../CONTRIBUTING.md`](../CONTRIBUTING.md) ·
[`../CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md).
