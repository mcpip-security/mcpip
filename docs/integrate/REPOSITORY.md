# Repository Reference

Where everything lives, and what each module is responsible for. If you are integrating rather
than contributing, you want [Getting Started](../start/GETTING_STARTED.md) instead.

## Shape of the tree

```
mcpip/
  interfaces.py        Shared primitives: models, enums, limits, canonical_json,
                       reject_unsafe_string, the abstract engine contracts, MCPIPDenied
  main.py              The MCPIPGateway pipeline and the 10-gate proof (python main.py)

  bridge/              Stage 1 — normalize any provider tool call
  obfuscator/          Stage 2 — resolve a tenant-scoped alias to a real target
  auth/                Stage 3 — identity from a verified JWT, plus the payload lock
  audit/               Stage 4 — the tamper-evident decision ledger

  app/                 The HTTP edge (FastAPI, uvicorn app.main:app)
  core/                Configuration, boot integrity, licensing, metrics, logging
  models/              The HTTP request/response wire contract
  services/            Thin adapters and stores the gateway composes

  dashboard/           The operator console (Vite, React, TypeScript, Tailwind)
  sdk/python/          The typed Python client and the mcpip CLI
  sdk/typescript/      The zero-dependency TypeScript/ESM client
  rust/                The optional fast-walk extension (byte- and decision-identical)
  mcpip_verify/        Standalone release verification

  deploy/              Kubernetes manifests and the Helm chart
  packaging/           Desktop and distribution packaging
  release/             Signed release manifests, SBOM, public keys
  scripts/             Operational and build scripts
  load/                Load-generation harnesses
  training/            Dataset and model tooling for the optional drafting path
  tests/               The suite (1,590 tests)
  docs/                This documentation
```

The four pipeline stages are the load-bearing part. Everything else composes them.

## The pipeline

Every request walks Bridge → Obfuscator → Auth → Audit, in that order, every time. A failure at
any stage denies immediately and emits a signed WORM record; the caller receives only a
`correlation_id`.

### `bridge/` — Stage 1, normalize

| Module | Responsibility |
|---|---|
| `intent_parser.py` | Declared-format dispatch to a `NormalizedIntent`. Owns the argument-safety walker and the identity-injection hard-deny. |
| `errors.py` | The bridge deny taxonomy (`UnknownFormat`, `UnknownVendor`, …) the gateway maps to a `DenyReason`. |
| `fastwalk.py` | Opt-in Rust fast-walk shim (`MCPIP_FAST_WALKER=1`). Byte- and decision-identical to the pure-Python default. |
| `connectors/` | Pure tool-call parsers. No SDKs, no keys, no network. |

**`bridge/connectors/`** is where the seven wire formats and 82 vendor ids live.

| Module | Responsibility |
|---|---|
| `base.py` | The `Candidate` + `FormatParser` contract. No logic. |
| `formats.py` | The seven real parsers: openai, anthropic, gemini, bedrock, mcp_jsonrpc, raw_mcp, a2a. |
| `registry.py` | The hash-pinned vendor → format registry. Refuses to boot on drift. |
| `openai.py` `claude.py` `gemini.py` `bedrock.py` `mcp_standard.py` `a2a.py` | Vendor bindings for the native dialects. |
| `copilot.py` `deepseek.py` `qwen.py` `ernie.py` `kimi.py` `openai_compatible.py` `local_runtime.py` `llm_gateway.py` `enterprise_ai.py` `mcp_framework.py` `mcp_platform.py` | Vendor bindings that resolve to an existing dialect. |

A connector that imports an LLM SDK, opens a socket, or reads a credential env var is a defect,
not a feature. `tests/test_connector_conformance.py` AST-scans every module here and fails the
build on any such import.

### `obfuscator/` — Stage 2, resolve

| Module | Responsibility |
|---|---|
| `alias_registry.py` | Bi-directional, per-tenant alias ↔ target resolution. Fail-closed. |
| `tenant_catalog.py` | The multi-industry tenant catalog. |

### `auth/` — Stage 3, identity and the payload lock

| Module | Responsibility |
|---|---|
| `token_resolver.py` | JWT identity sovereignty (EdDSA/RS256). The only source of `tenant_id`, `agent_id`, `capabilities`. |
| `pin_validator.py` | The canonical payload lock: a 6-digit PIN bound to the SHA-256 of the canonical payload, consumed exactly once in a single Redis Lua `EVAL`. |
| `pop.py` | Proof-of-possession (sender-constrained tokens) and the RFC 8693 delegation chain. |
| `jwks_refresher.py` | Off-hot-path verification-key-set rotation. Fail-closed, never empty. |
| `oauth_metadata.py` | OAuth 2.1 Protected Resource Metadata (RFC 9728). |

### `audit/` — Stage 4, the ledger

| Module | Responsibility |
|---|---|
| `worm_logger.py` | The hybrid Merkle-epoch WORM: durable Redis-Stream buffer, then per-epoch Ed25519-signed roots. Owns `verify_chain()` and `inclusion_proof()`. |
| `merkle.py` | Pure Merkle primitives: domain-separated leaf/node hashing, root, O(log n) proofs. |
| `anchor.py` | The out-of-tamper-domain head anchor — rollback and truncation evidence. |

## The HTTP edge

| Module | Responsibility |
|---|---|
| `app/main.py` | The FastAPI gateway: composition root plus all 63 endpoints. |
| `models/schemas.py` | The strict Pydantic v2 wire contract: `AuthorizeRequest`, `StagedChallenge`, `ExecutionReceipt`, and the rest. |

## `core/` — configuration and boot

| Module | Responsibility |
|---|---|
| `config.py` | Typed, environment-driven settings (`MCPIP_*`, pydantic-settings). |
| `integrity.py` | Startup integrity self-check. Verified boot, fail-closed. |
| `licensing.py` | The offline license and entitlement gate. Boot-time only. |
| `security.py` | The opaque-deny boundary control: `new_correlation_id`, `GatewayDeny`, `map_engine_exception`. |
| `metrics.py` | Prometheus metrics, with label discipline enforced by construction. |
| `logging_setup.py` | Structured JSON logging. Standard library only. |
| `version.py` | The single source of truth for the release version. |

## `services/` — the composed stores and adapters

These are thin. They adapt or persist; they do not reimplement the engine.

**On the authorization path**

| Module | Responsibility |
|---|---|
| `auth_engine.py` | Identity and payload-lock orchestration. |
| `obfuscator.py` | Fail-closed alias resolution pass-through. |
| `policy_engine.py` | The deny-only overlay: velocity cap and amount ceiling. Can only ever add a deny. |
| `grant_store.py` | UUID capability-based delegated compartment grants. |
| `grant_cache.py` | A bounded, per-worker TTL negative cache for grant lookups. |
| `revocation.py` | The operator principal kill switch. |
| `quarantine.py` | Canary-tripwire agent freeze. |
| `skill_gate.py` | The operator skill kill switch. |
| `delegation.py` | Attenuated session grants. |
| `external_pdp.py` | Outbound PEP mode — consult an external AuthZEN PDP. |

**Catalog and extensions**

| Module | Responsibility |
|---|---|
| `catalog_overlay.py` | Operator-registered skills, layered over the config catalog. |
| `extension_manifest.py` | The `mcpip-extension/1` manifest schema and its self-pin. |
| `extension_submissions.py` | Community submit/review state. |
| `registry_publishers.py` | The verified-publisher allow-list a registry-server approval is checked against. |
| `community_gate.py` | The author-your-own gate seam. The CEL runtime is deferred. |

**Approval and credentials**

| Module | Responsibility |
|---|---|
| `authenticator_enrollment.py` | Per-principal authenticator enrollment (RFC 6238 TOTP). |
| `authn_channel.py` | Out-of-band OTP delivery channels. Fail-closed with none configured. |
| `secret_vault.py` | Operator-stored broker credentials. |
| `cloud_broker.py` | The cloud IAM credential broker behind the `cloud_iam` transport. |

**Operator and evidence**

| Module | Responsibility |
|---|---|
| `directory_store.py` | Operator directory persistence. Non-authoritative metadata. |
| `operator_users.py` | The console team roster. The `role` is a label; it authorizes nothing. |
| `relation_store.py` | Zanzibar-style ReBAC relation-tuple projection from committed grants. |
| `forensic_store.py` | Encrypted payload capture for incident investigation. AES-256-GCM, TTL-bounded. |
| `compliance_evidence.py` | Compliance-evidence bundle assembly. Pure, I/O-free. |
| `response_playbook.py` | The deterministic deny-response automation loop. |
| `telemetry.py` | Opt-in, off-hot-path aggregate telemetry. |
| `license_refresh.py` | Off-hot-path license refresh, verified against the root. |
| `workspace_plan.py` | Brief → governed workspace scaffold. |

## Clients

| Path | What it is |
|---|---|
| `sdk/python/` | The typed Python client, distribution `mcpip-sdk`. Installing it puts the `mcpip` CLI on your PATH. |
| `sdk/typescript/` | The zero-dependency TypeScript/ESM client, `@mcpip/sdk`. |
| `dashboard/` | The operator console. `npm run dev` on port 5173. |
| `mcpip_verify/` | Standalone release verification, so a verifier needs no gateway. |

Both SDKs are Apache-2.0 and wrap the same wire contract. Both are fail-closed and opaque: a
deny surfaces only a `correlation_id`, and neither auto-retries.

## Build, deploy, and verify

| Path | What it is |
|---|---|
| `deploy/k8s/` | Raw Kubernetes manifests. Shape-validated by kubeconform in CI. |
| `deploy/chart/` | The Helm chart, with a compliance values file. |
| `packaging/` | Desktop packaging for the console. |
| `release/` | Signed release manifest, SBOM, provenance, and public keys. |
| `scripts/` | Quickstart, release signing, SBOM generation, integrity manifest, benchmarks. |
| `rust/` | The optional fast-walk extension. |

## Tests

`tests/` holds 1,590 tests. A few carry specific weight:

| File | What it protects |
|---|---|
| `test_connector_conformance.py` | That no connector imports an LLM SDK, opens a socket, or reads a credential. |
| `test_production_package.py` | That the distribution allow-list agrees with the repository — nothing untracked rides along. |
| `test_deploy_manifests.py` | The manifest rules kubeconform cannot model (ConfigMap key charset, mounted-key agreement). |
| `test_redteam_regressions.py` | Confirmed findings from adversarial campaigns, pinned so they cannot regress. |

Run everything with `pytest -q` against a real Redis on `63790`. See
[Operations](../operate/OPERATIONS.md) for the harness.
