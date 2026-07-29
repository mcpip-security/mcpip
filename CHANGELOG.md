# Changelog

All notable changes to MCPIP are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- **`mcpip export-audit --verify` now verifies the whole signed chain, not just the
  Merkle roots (audit-integrity defect).** The offline exporter — which
  `docs/operate/OPERATIONS.md` names as THE continuous tamper check for
  production, because `/v1/audit/verify` is sandbox-gated — recomputed per-epoch Merkle
  roots ONLY: it checked no Ed25519 epoch signature, no `prev_epoch_hash` linkage, no
  `epoch_hash`, and no rollback watermark, so a rolled-back ledger and a ledger with a
  flipped signature byte both printed `audit chain: intact` and exited `0` while the
  gateway's own `/v1/audit/verify` returned `{"intact": false}`. It now runs the same five
  checks `WormLogger.verify_chain` runs — chain linkage (+ monotonic epoch numbers and
  contiguous `seq` coverage), Merkle roots (leaves cross-checked against the stored
  `leaf_hash`), `epoch_hash` recomputation over every persisted header field, the Ed25519
  epoch signature, and the out-of-tamper-domain anchor low-watermark — plus the signed
  super-checkpoint on a compacted chain. It fails closed on a missing key, an unparseable
  header, an absent signature or a partially-deleted epoch, and the verdict lines NAME
  every check performed (and any that was not). `mcpip_verify/audit_export.py` reads only
  `XRANGE`/`HGETALL`/`GET` and still takes no lock. New gate:
  `tests/test_audit_export_verify.py`.

### Added

- **Connector coverage wave — 27 → 82 vendor ids (`REGISTRY_VERSION` 3 → 4, deliberate
  hash re-pin).** MCPIP now names the callers an operator actually runs. Added Kimi /
  Moonshot (`bridge/connectors/kimi.py`); the remaining popular OpenAI-compatible
  inference clouds (Zhipu/GLM, MiniMax, Perplexity, Cerebras, SambaNova, NVIDIA NIM,
  DeepInfra, Nebius); **self-hosted runtimes** — Ollama, vLLM, SGLang, llama.cpp,
  LM Studio, TGI, LocalAI (`local_runtime.py`), so an air-gapped operator's local model
  gets the identical boundary, not a degraded one; enterprise data platforms — Databricks,
  watsonx, Snowflake Cortex (`enterprise_ai.py`); LLM gateways/routers — LiteLLM, Portkey,
  Cloudflare Workers AI, Vercel AI Gateway, GitHub Models (`llm_gateway.py`);
  `claude_vertex` (Vertex-hosted Claude emits the identical `tool_use` block, exactly like
  `claude_bedrock`); eleven more MCP hosts — Zed, VS Code, JetBrains, Continue, Roo Code,
  Kilo Code, Codex CLI, Gemini CLI, Amp, Crush, Warp; assistant/automation platforms
  speaking MCP — ChatGPT, Copilot Studio, LibreChat, Open WebUI, n8n, Dify, Langflow,
  Flowise (`mcp_platform.py`); and agent frameworks acting as MCP clients — LangGraph,
  CrewAI, AutoGen, OpenAI Agents SDK, Pydantic AI, LlamaIndex, Semantic Kernel, Mastra,
  Strands (`mcp_framework.py`).

  **Every addition is a pure alias onto an EXISTING parser** — no new wire shape, no new
  parsing code, and **no change to any pre-existing vendor→format binding**; the modules
  stay pure parser bindings (no SDK, no network, no env, enforced by the AST purity
  guard). The registry hash was recomputed and re-pinned deliberately with the version
  bump, so a gateway whose connector table drifts still refuses to boot. `grok` remains
  deliberately unbound (xAI's id is `xai`) — an unrecognized vendor is still a fail-closed
  `UNKNOWN_VENDOR` deny, never a guess.

- **Mechanical connector-coverage guards.** `tests/test_connector_conformance.py` now
  asserts that every registered vendor has a pinned fixture vector (and no fixture pins a
  vendor the registry dropped), that every vendor id is an exact lowercase token (a
  mixed-case binding would be unreachable under exact-match lookup), that the TypeScript
  SDK's `Vendor` / `SourceFormat` unions match the registry and the engine, and that every
  SDK envelope builder's output survives the real strict ingress with byte-identical
  canonical arguments. Coverage is now enforced, not remembered.

- **`a2a_task` envelope builders in both SDKs** (`envelopes.a2a_task` /
  `a2aTask`) — the 7th dialect shipped in the gateway but neither SDK could construct it,
  and the TypeScript `SourceFormat` union omitted it entirely.

- **`mcpip export-audit --pubkey / --anchor-path / --require-anchor`.** `--pubkey` (the
  `worm_signing_ed25519.pub.pem` half of the key ceremony) was already advertised by
  `docs/start/GETTING_STARTED.md` and `scripts/provision_gateway_keys.py` but rejected by the
  parser; it is now real and REQUIRED by `--verify` (no key ⇒ no verdict, rather than a
  green verdict no signature backed). `--anchor-path` defaults to
  `MCPIP_WORM_ANCHOR_PATH`, else `<MCPIP_WORM_PATH>.anchor`, exactly like the gateway;
  `--require-anchor` makes a missing rollback witness a failure for scheduled checks.

## [3.0.0] - 2026-07-17

**MCPIP GA milestone.** This is the General-Availability cut of the fail-closed,
opaque zero-trust authorization gateway. It gathers every additive, backward-compatible
wave shipped since 2.1.0 (community extensibility, ReBAC projection, JWKS rotation, WORM
attestation + compliance evidence, SLSA provenance, opt-in vendor telemetry + license
refresh, the AuthZEN/COAZ + OAuth 2.1 RS + RFC 8693 delegation + MCP MRT interop
surfaces, and the A2A choke-point connector) behind one release version.

> **Semver note (a conscious choice, not an implied breaking-change claim).** Every wave
> since 2.1.0 was strictly ADDITIVE and backward-compatible — default-OFF opt-ins, new
> endpoints, and audit-only fields; the authorization hot path, the payload lock
> (`canonical_json` / `enforce_argument_safety` / scrypt PIN-hash / Rust mirror), the WORM
> epoch-header signed bytes, and the `{EdDSA, RS256}` alg gate are all byte-for-byte
> unchanged. By strict SemVer that is a MINOR bump (2.2.0). The owner has deliberately
> chosen **3.0.0** as the GA marketing milestone; there is **no** removed/renamed API and
> **no** breaking change. See `docs/operate/RELEASE.md` for the matching note.

### Added

- **Opt-in vendor telemetry with a load-bearing privacy boundary** — `services/telemetry.py`
  ships a strictly default-OFF, fail-open beacon whose body is a CLOSED set of exactly eight
  aggregate fields (a random `install_id`, license tier/id, version, a single governed-agent
  cardinality integer, allow/deny/staged decision counts, uptime, timestamp) — never a
  tenant/agent/alias/target/correlation id or any per-tenant breakdown. Air-gap and sandbox
  never phone home. `MCPIP_TELEMETRY_*` settings; a half-configuration fails boot closed. The
  two on-path recorders are swallow-only side effects that can never fail a decision. `GET
  /v1/admin/stats` surfaces the honest enabled/disabled/air-gap `TelemetryStatus` alongside
  the real governed-agent count + decision totals; mirrored through both SDKs (`stats()` →
  `DeploymentStats`), the `mcpip admin stats` CLI, and the console's Deployment · License &
  Usage panel. `docs/operate/TELEMETRY.md`.
- **Opt-in, off-hot-path license refresh (fail-open, never widens trust)** —
  `services/license_refresh.py` + `core/licensing.py` verify a candidate license against the
  EXISTING license-root ONLY and atomically swap in a strictly-newer valid document; absent
  `MCPIP_LICENSE_REFRESH_*` URL ⇒ byte-identical offline behavior; the boot license gate is
  unchanged. New `mcpip_license_refresh_total{event}` metric + `MAX_LICENSE_DOC_BYTES`.
- **Read-only compliance-evidence bundle (X1)** — `GET /v1/admin/compliance/evidence`
  (`CAP_DIRECTORY_ADMIN`) reuses `WormLogger.attestation()` verbatim and feeds the real
  attestation + running version + signed release provenance into the pure
  `services/compliance_evidence.build_evidence_bundle` with a static regulatory cross-walk
  (EU AI Act, SEC 17a-4/FINRA, DORA, NIST 800-53, SOC 2, ISO 42001). **No fabrication:** every
  clause says "provides-evidence-for", carries an EXTERNAL-third-party `certification_note`,
  and asserts NO SOC2/FedRAMP/ISO certificate, no customer, no auditor sign-off. Available in
  production; mirrored by the SDKs + `mcpip admin compliance evidence`.
- **Registry-sourced skills governed by a reviewer-pinned verified-publisher allow-list (X3)**
  — a `RegistryServerManifest` (`kind='registry_server'`) projects an MCP-Registry `server.json`
  into the SAME hardened Phase-1 overlay path (`cloud_rest` forced by construction, additive-only
  HSETNX, no privileged transport). Approval requires the parsed publisher namespace to be a
  member of the per-tenant allow-list (`services/registry_publishers.py`), read FAIL-CLOSED and
  re-checked at boot. Admin surface `GET`/`PUT /v1/admin/extensions/publishers`
  (`CAP_CATALOG_REVIEWER`); mirrored by the SDKs + `mcpip admin publishers get/set`. MCPIP
  network-fetches no live registry — the server.json is pasted.
- **AuthZEN / COAZ decision surface + external-PDP scaffold (N1)** — inbound
  `POST /v1/authz/decision` (decision-only, opaque, JWT-only identity, obligations-not-reasons),
  plus a default-OFF outbound external-PDP PEP scaffold (`services/external_pdp.py`,
  `DenyOnlyGateChain`, composed only when `MCPIP_EXTERNAL_PDP_URL` is set) — default OFF ⇒ the hot
  path is byte-identical. Mirrored by both SDKs (`authz_decision` / `authzDecision`).
- **OAuth 2.1 Resource-Server metadata + issuer pinning (N2)** — public, unauthenticated
  `GET /.well-known/oauth-protected-resource` (RFC 9728; `resource` + `authorization_servers`
  only, no scopes/secret/topology), and an optional SEP-2352 `iss_binding` claim honored AFTER
  full verification. RFC 8707 audience binding and the `{EdDSA, RS256}` alg gate are unchanged.
  `docs/integrate/INTEGRATIONS.md`.
- **RFC 8693 full delegation chain + ID-JAG recognition (N3, audit-only)** — `project_act_chain`
  walks the nested `act` chain (fail-closed at every hop, bounded by `MAX_DELEGATION_CHAIN`) into
  a new audit-only `Identity.act_chain`; `is_id_jag` recognizes the ID-JAG token-type marker. Both
  authorize NOTHING and are recorded to WORM only; the chain never crosses the agent wire. No new
  trust root, no alg change.
- **MCP MRT / SEP-2322 step-up transport (N4, opt-in, `mcp_edge` only)** — the payload-bound PIN
  step-up is mapped onto the MCP Multi-Round-Trip `InputRequired` shape over the UNCHANGED
  `register_lock`/`consume_and_execute` path (no parallel state store). Opt-in via
  `stepUp='mrt'`; without it the branch is byte-for-byte the classic staged edge. `initialize`
  advertises `capabilities.experimental.mcpipStepUp={"mode":"mrt"}` — inert unless the client opts
  in.
- **A2A `a2a_task` connector (F1)** — a pure normalizer for one strict A2A Task envelope into the
  SAME `NormalizedIntent` the other six dialects produce (byte-identical payload-lock hash);
  declared A2A `message.metadata` is recorded-not-trusted into the non-locked `a2a_context` (WORM
  only, never merged into arguments, never crossed to the agent wire). Adds `Vendor.A2A` + the a2a
  binding as the 7th `SOURCE_FORMAT`, re-pinning the hash-pinned connector registry
  (`REGISTRY_VERSION` 2→3, `_PINNED_REGISTRY_SHA256` recomputed). `docs/integrate/ARCHITECTURE.md`.
- **Author-your-own community SKILLS with reviewer approval (Phase 1, shipped for real)** —
  customers and the community can now author their own skills instead of MCPIP hand-building
  every connector. A community skill is inert declarative data — one additive `alias → target`
  catalog entry — minted through the SAME hardened overlay path an operator `register_skill`
  uses, so it inherits every overlay ceiling by construction: **additive-only** (never repoints
  an alias that already resolves), **`cloud_rest`-transport only** (`legacy_mainframe`/
  `grant_issue`/`cloud_iam` unreachable), and **`restricted ⇒ pin_required`** (no stolen-bearer
  exfil of a restricted AUTO read). New `services/extension_manifest.py` (the strict
  `mcpip-extension/1` manifest — `extra='forbid'`, `reject_unsafe_string` on every human field,
  an identity-shaped-key hard-deny on `id`/`author`/`alias`, and a `sha256` **self-pin** over a
  new `core.integrity.canonical_manifest_bytes` that is DISTINCT from the payload-lock
  `canonical_json`, so no gate/lock hash is ever recomputed) and `services/extension_submissions.py`
  (`ExtensionSubmissionStore` — per-tenant `mcpip:ext:pending:{tenant}` bounded by the new
  `MAX_PENDING_SUBMISSIONS` + `mcpip:ext:approved:{tenant}`; writes fail closed, reads fail soft;
  tenant comes only from the JWT so cross-tenant approve is structurally impossible). Two capabilities
  gate the flow (both distinct UUIDs, matched constant-time; `role` authorizes nothing): a
  **Contributor** is any authenticated principal, a **Reviewer** holds the new
  **`CAP_CATALOG_REVIEWER`** (separable from `CAP_DIRECTORY_ADMIN` and `CAP_FORENSIC_READ`). New
  endpoints `POST /v1/extensions/submit` (Contributor — deliberately OUTSIDE the `/v1/admin/*`
  prefix; validates fail-closed, bounds the queue, WORM-records `extension_submit` BEFORE storing,
  does not probe alias existence to avoid an alias oracle), `GET /v1/admin/extensions/pending`
  (Reviewer, strict whitelist projection + a `conflicts_existing_alias` diff + a `submitter_is_reviewer`
  separation-of-duties hint), and `POST /v1/admin/extensions/{id}/{approve,reject}` (Reviewer;
  approve re-runs the authoritative `_overlay_skill_invalid` + additive-only `has_alias` +
  `MAX_OVERLAY_ENTRIES` + the `sha256` pin, WORM-records `extension_approve` **BEFORE** apply
  (write-before-execute → a hash-chained, Ed25519-epoch-signed, non-repudiable approval), then mints
  through the shared `_apply_overlay_skill` and hash-pins the manifest). **Rug-pull defense on load:**
  `_hydrate_catalog_overlay` re-verifies each community row's pinned manifest against
  `mcpip:ext:approved:{tenant}` and cross-checks the overlay fields, skipping any mismatch (re-review
  required) — the same "refuse on unexpected edit" discipline as the hash-pinned connector registry.
  A skill submit/approve/reject failure is simply the opaque `MCPIPDenied` (no new agent-facing deny
  string). Both entrypoints stay in lockstep — the authorization hot path is unchanged.
- **Community GATES ship as a manifest schema + a deny-only seam (Phase 2 — CEL runtime deferred by
  owner decision)** — the scaffold for author-your-own hot-path deny predicates, wired without adopting
  a CEL engine. New `DenyReason.POLICY_GATE_DENIED` (`policy_gate_denied` — DISTINCT from the G3
  `POLICY_DENIED` and from `RATE_LIMITED`; no `skill_` substring so it clears the metric-label guard),
  the `MAX_GATE_COST` budget, the `GATE_CONTEXT_FIELDS` whitelist, and the frozen
  `CommunityGateContext`/`GateDecision`/`CommunityGateProvider` seam types (`interfaces.py` §1.5d). A new
  pipeline **step 4c′** (`_community_gate`, right after the mandate gate and adjacent to the G3 policy
  gate, **identically ordered in both `main.py` and `app/main.py`**) evaluates the registered provider
  over a **topology-free** context (opaque alias + coarse transport class + risk tier + classification —
  no target, no secrets, no arguments, no identity handle) and is **deny-only by construction**:
  `GateDecision` has no allow outcome, so it can only ADD a `POLICY_GATE_DENIED`, never rescue an earlier
  deny, mint identity, or mutate the resolved action; `evaluate()` is wrapped fail-closed. The shipped
  default `NoOpCommunityGateProvider` (`services/community_gate.py`) is a strict NO-OP — the honest "no
  community gate engine configured" state, never a fabricated pass. `services/extension_manifest.py` adds
  the `kind='gate'` `GateManifest` variant (`language='cel'`, `source`, `referenced_context_fields ⊆
  GATE_CONTEXT_FIELDS`, `max_cost ≤ MAX_GATE_COST`, the same `sha256` self-pin) — validated as pure DATA
  only, **no CEL parse** — routed via `manifest_kind` through the SAME submit/review/WORM/hash-pin flow as
  skills. **The CEL parse/lint/evaluate runtime is DEFERRED** as an explicit owner dependency decision
  (`cel-python`/`celpy` pulls a native chain — `google-re2` [native C++], `pendulum`, `jmespath` + parser
  machinery — into the fail-closed authorizer, materially widening its air-gap/SBOM/CVE surface): **no CEL
  library is added to `requirements*`/`pyproject.toml`, and `celpy` is never hard-imported** (a test asserts
  the app never pulls it). Consequently **gate approval is fail-closed — no approve-without-proof**: a gate
  can be submitted + schema-validated + stored PENDING, but approving one requires a static cost/whitelist
  prover that ships bundled with a CEL engine, so `approve_extension` refuses a `kind='gate'` manifest while
  no engine is registered. Enabling the runtime later is purely additive — a single
  `register_community_gate_engine(...)` supplies both the hot-path provider and the approve-time prover.
  Design + deferred-footprint rationale in `docs/integrate/EXTENSIBILITY.md §8`.
- **ReBAC relation-tuple projection — the operator Knowledge-Graph made real (strictly additive)** — a
  Zanzibar-style relation-tuple layer (`services/relation_store.py`, `RelationTupleStore` + `RelationEdge`)
  that is a best-effort, Redis-auto-expiring **projection** of committed compartment grants, NOT a second
  authorization source. `GrantStore.issue`/`has_active_grant`/`revoke`, the payload lock, and WORM are
  byte-for-byte unchanged; `GrantStore` takes an OPTIONAL injected `relations` store and projects a member
  tuple ONLY after the authoritative grant `.set()` succeeds (`revoke` best-effort removes it AFTER the
  authoritative delete). One tuple per grant, `mcpip:rel:{tenant}:{object}#{relation}@{subject}` (object =
  compartment UUID, relation = `member`, subject = agent id), written with `EX=ttl` MIRRORING the grant so
  the projection self-heals to grant expiry — even a dropped remove can't outlive the grant. `project_member`/
  `remove_member` swallow every `RedisError` (metric only) and NEVER raise into the grant path; `relations=None`
  ⇒ `GrantStore` behaves exactly as before. The pipeline NEVER consults it — the capability-UUID + grant gates
  remain the SOLE authority; a documented rule keeps the `check` deny-only/additive IF ever promoted. Read
  surface `GET /v1/admin/directory/relations` (`CAP_DIRECTORY_ADMIN`, tenant-scoped, glob-escaped SCAN,
  fail-soft `[]`, bounded by `MAX_RELATION_ROSTER`) lists the projected `member` + read-time-derived `grantor`
  edges; a full `(subject, member, object)` triple also returns the BOUNDED transitive-closure `check`
  (hop-capped `MAX_RELATION_DEPTH`, fanout-capped `MAX_RELATION_FANOUT`, fail-closed). New closed-enum metric
  `mcpip_relation_projection_total{event}` (`projected`/`project_error`/`removed`) and new hard limits
  `MAX_RELATION_DEPTH`/`MAX_RELATION_FANOUT`/`MAX_RELATION_ROSTER` + `RELATION_KEY_PREFIX` in `interfaces.py`.
  Emits no new WORM record (the grant action was already logged). Parity untouched (`_key` is plain f-string
  interpolation; shares nothing with `canonical_json`/`enforce_argument_safety`/the scrypt PIN-hash).
- **JWKS refresh helper — off-hot-path verification-key-set rotation that never goes empty** — completes the
  existing `JWKSKeyProvider` with its other half (`auth/jwks_refresher.py`, `JWKSRefresher` + `JWKSRefreshError`).
  `JWKSRefresher` is itself a `KeyProvider` wrapping a live inner `JWKSKeyProvider`; `resolve` simply delegates
  (the only per-request op — still no synchronous JWKS fetch on the auth path). `refresh`/`bootstrap` fetch a
  fresh JWKS document off the hot path over an **SSRF-guarded, hermetic** client (https-only; resolve + reject
  ANY private/loopback/link-local/reserved/multicast/unspecified IP; connection PINNED to the validated IP with
  original-host SNI/cert to defeat DNS-rebinding; `follow_redirects=False`; bounded timeout; bounded read
  `MAX_JWKS_DOC_BYTES`; `trust_env=False` + `proxy=None` so ambient `HTTPS_PROXY`/`SSL_CERT_FILE` can't reroute
  or MITM the key fetch — reuses `services.authn_channel._is_blocked_ip` via a deferred import to avoid an
  auth↔services cycle), build + fully validate a NEW `JWKSKeyProvider` (re-runs the authoritative non-empty /
  well-formed / no-private-material / unique-`kid` checks + the `MAX_JWKS_KEYS` cap) **BEFORE** the single
  atomic `self._current` rebind. **Any failure raises `JWKSRefreshError` and RETAINS the last good set — the
  verification key set is never silently emptied**; an unknown `kid` after a failed refresh still fails CLOSED.
  `bootstrap` makes the seed a MANDATORY non-empty provider (boot fails closed rather than come up empty). The
  `TokenResolver` alg allow-list `{EdDSA, RS256}` stays the gate — a rotated set can add keys but never widen
  it. New hard limits `MAX_JWKS_KEYS`/`MAX_JWKS_DOC_BYTES` in `interfaces.py`. Strictly opt-in and additive: it
  is a standalone helper (construct directly from a mounted document or via `bootstrap`) — the existing
  `StaticPEMKeyProvider` / single-IdP boot path is entirely unchanged and is not wired into the composition root.
- **Read-only WORM attestation endpoint — a portable, externally-checkable audit snapshot** — `GET
  /v1/audit/attestation` (`app/main.py` `audit_attestation`, backed by `WormLogger.attestation()` →
  `WormAttestation` + `WormLogger.signing_key_id()`). Returns the latest SEALED epoch header
  (`epoch`/`end_seq`/`merkle_root`/`epoch_hash`/`signature`), the WORM epoch key's public
  `signing_key_id` (a domain-separated fingerprint of the PUBLIC key, never secret material), a FRESH
  `verify_chain` result (`intact` + `first_bad_epoch`), and the out-of-tamper-domain anchor low-watermark
  (`anchor_epoch`/`anchor_epoch_hash`). Every signed field was Ed25519-signed at epoch close / anchor append —
  the endpoint **mints no key, signs nothing new, closes no epoch, and touches no counter**, so it never runs
  on or blocks the emit hot path. It discloses only the signed commitments `/v1/audit/proof` and
  `/v1/audit/verify` already surface (no hidden target, payload, or secret), so it is plain-JWT-gated like
  `/v1/version` — and, unlike the sandbox-only verify/proof routes, is available **in production** because a
  portable attestation is a production artifact. Epoch fields come back `None` before the first epoch is sealed
  (an honest empty state, never a fabricated header). Any auth or engine/transport failure is an opaque
  `MCPIPDenied`.
- **SLSA v1 / in-toto provenance generation in the release ceremony** — `scripts/gen_slsa_provenance.py` emits
  ONE in-toto Statement (`https://in-toto.io/Statement/v1`) carrying a SLSA v1 provenance predicate
  (`https://slsa.dev/provenance/v1`) → `release/provenance.intoto.json`. `subject` = the release artifacts
  (name + SHA-256) copied **verbatim** from the signed `release/manifest.json` (never re-hashed, so provenance
  can never disagree with the signed release); `resolvedDependencies` = the pinned git source commit +
  `requirements*.txt` + `VERSION` hashed from disk; `runDetails` = the REQUIRED `--builder-id` (never
  defaulted/fabricated) + invocation metadata + the signed release/integrity manifests as byproducts. Honest
  fail-closed: an absent/unreadable manifest, an empty subject set, or a missing pinned input is a hard error.
  **The generator SIGNS NOTHING** — cosign attestation with the owner's offline key is a separate, deliberate
  OWNER action (`docs/operate/RELEASE.md §6`), exactly like the release-root / license-root signing boundary; the predicate
  is gitignored and never committed. Ceremony + `docs/operate/RELEASE.md` step order updated (provenance runs AFTER the
  integrity manifest, writing only to `release/` so it doesn't perturb the hashed source set).
- **REAL WORM-emit throughput benchmark** — `scripts/bench_worm_emit.py` drives the actual
  `WormLogger.emit` (the SAME atomic `INCR`+`XADD` Lua / `_redact` / leaf hashing — `audit/worm_logger.py`
  is **not** touched) against the sandbox Redis (:63790) and measures sustained emits/sec + per-emit
  latency (p50/p95/p99) under `appendfsync=always` (production durable), `appendfsync=everysec`
  (non-durable contrast), and the as-found posture, reporting the durability it observed via the existing
  `read_persistence_posture` probe. It **measures, never fabricates** (it says so and reports only what it
  could measure if a managed Redis refuses `CONFIG SET`), isolates onto a dedicated logical DB, flushes
  only WORM keys, and restores the server's original AOF config on exit (behavior-neutral). Backs the
  benchmark half of `docs/integrate/ARCHITECTURE.md`.
- **Behavior-neutral `MCPIP_REGION` observability tag** — a new optional `region` setting
  (`core/config.py`) surfaced read-only on `/healthz` and `/v1/version` for console/SDK display and log
  correlation. It is **purely an observability annotation**: it changes NOTHING about routing,
  authorization, Redis key derivation, or storage (every key is already tenant-prefixed, so region pinning
  is an edge/deployment concern), is deliberately **never a metric label** (a free-form operator string
  would break the closed-enum label discipline in `core/metrics.py`), and `None` ⇒ the tag is simply
  absent (boot is byte-for-byte unchanged when unset). Design in `docs/operate/OPERATIONS.md`.
- **Three FUTURE-wave design docs (designs + decisions, no substrate rewrite)** — the roadmap's FUTURE
  items are now addressed as rigorous design work, explicitly NOT as built substrate changes:
  - `docs/integrate/ARCHITECTURE.md` — the group-commit WORM throughput ceiling: the REAL benchmark above plus
    the app-managed-WAL group-commit design that would raise it (batch N emits → ONE fsync → each waiter
    returns only post-fsync, so durable-before-authorize is PRESERVED), crash-safety + tamper-evidence +
    migration story. Raising the ceiling is a substrate rewrite of the tamper-evidence core — an explicit
    **owner decision, deferred**; the emit/durability path in `audit/worm_logger.py` is unchanged.
  - `docs/operate/OPERATIONS.md` — region-pinned tenants as a deployment topology (one MCPIP + Redis cell per
    region), per-region WORM ledger + anchor + signing key with NO cross-region chain, residency-by-
    partition posture. Ships only the behavior-neutral `MCPIP_REGION` tag; a cross-region control plane
    stays deferred.
  - `docs/integrate/ARCHITECTURE.md` — a decision memo on the single most consequential product call: whether
    MCPIP should ever enter the model's prompt/content path (the "oracle inversion" / taint-tracking
    data-plane pillars), which contradicts today's "interceptor, not a proxy" positioning. Recommendation:
    hold the line; the call is an explicit **owner decision, pending**. Writes NO data-plane code and
    reserves no `{{PTR_}}` pointer token.

## [2.1.0] - 2026-07-17

### Added

- **Out-of-band authenticator delivery for the step-up code (pluggable, SSRF-guarded)** —
  how the payload-bound one-time code reaches the operator is now a **delivery
  seam**, not part of the lock. `register_lock` still mints the code with
  `secrets` and still registers the payload-bound scrypt lock **byte-identically**
  (canonical-JSON, register/consume, and the Rust mirror are untouched — G1
  changes only *delivery*, never derivation or binding). A new
  `BaseAuthenticatorChannel` ABC (`interfaces.py` §1.5b) with an immutable
  `AuthenticatorNotice` fronts two concrete channels in `services/authn_channel.py`:
  `SandboxRedisAuthenticatorChannel` (the runnable-demo stash+`peek`, wired only in
  sandbox — the `mcpip:otp:*` key and `GET /v1/authenticator/{challenge_id}` behave
  exactly as before) and `WebhookAuthenticatorChannel` (the one real production
  channel — it **pushes** the notice to a tenant-configured sink over an
  SSRF-guarded, HMAC-SHA256-signed HTTPS request and **persists no OTP anywhere**).
  The SSRF guard runs per delivery: https-only, resolve-and-reject any
  private/loopback/link-local (`169.254.169.254`)/reserved/multicast/unspecified
  address (IPv4-mapped unwrapped), connection **pinned to the validated IP** to
  defeat DNS-rebinding while SNI/cert stay on the original host, no redirect
  following, bounded timeout, 2xx-or-raise with a bounded response read. Delivery
  is **fail-closed**: with no channel configured (unconfigured production) or a
  `deliver` that raises, `register_lock` denies with the new distinct
  `DenyReason.OTP_DELIVERY_FAILED` **before any `202`/`challenge_id` is produced**,
  so a `pin_required` action can never silently allow or stage an unanswerable
  challenge. New settings `MCPIP_AUTHN_WEBHOOK_URL` / `MCPIP_AUTHN_WEBHOOK_SECRET_PATH`
  (raw ≥32-byte HMAC secret) / `MCPIP_AUTHN_WEBHOOK_TIMEOUT_S` (clamped `[0.5s, 30s]`);
  production requires **both** url and secret (setting exactly one is a fail-closed
  boot error; neither ⇒ delivery absent), plus hard limits
  `MAX_AUTHN_WEBHOOK_RESPONSE_BYTES` / `MIN`+`MAX_AUTHN_WEBHOOK_TIMEOUT_S`
  (`interfaces.py`). `otp` is added to the WORM redaction set as defense-in-depth
  (it never enters the `ctx`, the `202`, or the log by design).
- **Deny-only policy overlay — per-tenant velocity caps and amount ceilings** — a
  new stateless policy step (`services/policy_engine.py`,
  `VelocityAmountPolicyEngine`) runs on the authorize hot path **after** the
  entitlement/sender-constraint gates and **before** the risk gate, identically
  ordered in both entrypoints (`main.py` `_policy_gate`, `app/main.py` step 5b). It
  is **deny-only by construction**: the new `PolicyDecision` (`interfaces.py` §1.5c)
  carries no allow/override outcome, and the frozen `PolicyContext` exposes no
  target/identity handle — so the overlay can only ever *add* the new distinct
  `DenyReason.POLICY_DENIED`, never turn an earlier gate's deny into an allow, never
  mint identity, and never repoint a skill. Two rule kinds are enforced against a
  per-tenant `mcpip-policy/1` document: a **velocity** fixed-window action cap
  (atomic `INCR` + first-hit `EXPIRE`, a Lua script distinct from the payload-lock
  Lua and carrying no byte-identity obligation) and an **amount** ceiling on a named
  numeric argument (compared as `Decimal` — no float drift; a value smuggled as a
  string or other non-number is refused, not coerced; the pure amount check runs
  before the state-mutating velocity `INCR` so an over-ceiling request denies without
  spending velocity budget). It is **opt-in and honest**: no document ⇒ **no limits**
  (never a fabricated default), while a Redis transport error, a malformed stored
  document, or a raising provider all **fail closed** to `POLICY_DENIED`. The concrete
  cause rides only in the WORM `detail` — never over the agent wire, never as a metric
  label (deliberately distinct from `RATE_LIMITED`). Rules are read/written only via
  the new `CAP_DIRECTORY_ADMIN`-gated `PUT`/`GET /v1/admin/policy` (+ `POST
  /v1/admin/policy/delete`) — strict-validated (`MAX_POLICY_RULES` /
  `MAX_POLICY_DOC_BYTES`, `interfaces.py`), emit-before-mutate WORM-logged,
  tenant-scoped, opaque on failure — and the document holds **only** velocity/amount
  rules, never an alias→target mapping or identity. Surfaced by the Python/TypeScript
  admin SDKs.
- **Forensic payload reconstruction (investigator surface, access-audited)** —
  a new admin/investigator side-channel that reconstructs the REAL query an
  agent sent for a given `correlation_id`, closing the gap left by the
  deliberately opaque agent wire and the arguments-omitting decision feed. New
  `services/forensic_store.py` (`ForensicCaptureStore` + `ForensicRecord`)
  captures the alias, the already-normalized arguments, and non-secret identity
  context — AES-256-GCM encrypted at rest under a DEDICATED master key held
  OUTSIDE Redis (Redis holds ciphertext only), TTL-bounded
  (`FORENSIC_TTL_SECONDS`), with `(tenant, correlation_id)` bound as
  length-prefixed AAD so a transplanted blob won't decrypt. **Secrets are never
  captured** — the snapshot is run through the WORM `_redact` discipline before
  encryption and pin/jwt/proof/vended-credential/identity-shaped material is
  excluded at capture time. Capture is a **best-effort side-channel fired
  strictly AFTER the authoritative WORM decision emit** (any exception is
  swallowed), so it can never delay, reorder, or flip an ALLOW/DENY or the
  write-before-execute ordering. Retrieval is deny-by-default over the SOLE
  route `GET /v1/admin/forensic/{correlation_id}`, gated by `_require_forensic_read`
  on the new capability `CAP_FORENSIC_READ` (a DISTINCT UUID from
  `CAP_DIRECTORY_ADMIN` — directory-admin does NOT confer raw-payload read;
  `role` still authorizes nothing), constant-time, kill-switch-enforced,
  tenant-scoped, and opaque; every access emits a WORM
  `admin_action='forensic_read'` BEFORE disclosure (the payload is NOT copied
  into that record). Config flag `MCPIP_FORENSIC_CAPTURE` (unset ⇒ ON in
  sandbox, OFF in production — fail-safe; explicit true/false wins); in
  production capture ALSO requires a 32-byte key file at
  `MCPIP_FORENSIC_KEY_PATH` — the flag alone is not enough, and an absent key
  means the feature is ABSENT (fail-closed, never plaintext). New hard limits
  `FORENSIC_TTL_SECONDS` / `MAX_FORENSIC_PAYLOAD_BYTES` (`interfaces.py`) and a
  closed-enum metric `mcpip_forensic_total{event=captured|capture_skipped|capture_error|read_hit|read_miss|read_denied}`.
  Surfaced by the SDKs (`MCPIPAdminClient.forensic_get()` / `forensicGet()`) and
  the console's Audit Ledger "Reconstruct payload" inspector (admin-only, honest
  empty state when the feature is off/absent — no fabricated data).
- **11 new connector vendor aliases (registry v2)** — the hash-pinned
  vendor→format registry (`bridge/connectors/registry.py`, re-pinned +
  `REGISTRY_VERSION`→`2`) now resolves the coding-agent MCP hosts `cline`,
  `opencode`, `goose`, `openhands`, and `openclaw` (OpenClaw's MCP passthrough)
  onto `mcp_jsonrpc`, and the OpenAI-compatible providers `mistral`, `groq`,
  `together`, `fireworks`, `openrouter`, `xai` onto `openai_tool_call` (new
  `bridge/connectors/openai_compatible.py` binding). Pure aliases — no new wire
  shape, no parser change; conformance fixtures added. (OpenClaw's *native* flat
  tool-invoke envelope is a separate `SOURCE_FORMAT`, tracked for a follow-up.)
- **Lean operator console (6-tab IA, zero mock data)** — the dashboard is
  redesigned around six tabs (`lib/nav.ts`: Command Center · Audit Ledger ·
  Skills & Access · Directory · Gateway · Developers, grouped
  Operate/Govern/Administer), and every surface now runs on REAL gateway data:
  offline renders honest empty states, `lib/demo.ts` and every mock/fixture
  surface are deleted (the real protocol constants live in `lib/protocol.ts`,
  pinned to `interfaces.py`). New live instruments: an Authorize Probe firing
  real `/v1/authorize` calls, a real Prometheus `/metrics` scrape (decision
  counters + p50/p95 latency quantiles), a WORM-ledger session ring buffer
  whose per-event Merkle inclusion proofs (`/v1/audit/proof/{event_id}`) are
  INDEPENDENTLY re-verified in-browser (WebCrypto SHA-256, domain prefixes
  pinned to `audit/merkle.py`), a live canary/quarantine tripwire panel, a
  compartment-separation self-test over the operator's own teams, and a
  Developers page (agent connection + SDK quickstarts). The Principal
  Directory persists to the real tenant and reconciles revocations from
  `GET /v1/admin/principals/revoked`; its fabricated key-bindings/RBAC matrix
  gave way to an entitlements view of the real `/v1/license`. Deleted along
  the way: the Tenants/Execution-Policies/Threat-Policy views, Terminal,
  RequestInspector, and the React Flow (`@xyflow/react`) dependency.
- **Decision feed carries the audit-proof handle** — every
  `GET /v1/admin/decisions/recent` row now includes the WORM `event_id` (the
  emit-time random uuid4 handle `/v1/audit/proof/{event_id}` accepts) and
  `worm_sequence`, a deliberate whitelist extension so the console can verify
  each decision against the signed Merkle chain; opacity is otherwise
  unchanged (target/payload/secrets still never appear).
- **Admin tripwire rosters** — two new read-only, `CAP_DIRECTORY_ADMIN`-gated,
  opaque-deny endpoints: `GET /v1/admin/quarantine` (agents currently frozen
  by the canary tripwire, with remaining TTL — a tenant-scoped, glob-escaped
  SCAN bounded by the new `MAX_QUARANTINE_ROSTER=1000` hard limit; fail-soft
  read, enforcement stays the fail-closed `is_quarantined`) and
  `GET /v1/admin/canaries` (the decoy-alias roster — the ONLY surface that
  reveals the `canary` flag; the agent-facing `/v1/catalog` and MCP
  `tools/list` keep hiding it, test-asserted). `RevocationStore.list_revoked`
  now glob-escapes the tenant id with the same shared rule. Gate:
  `tests/test_admin_live_surfaces.py` (7 tests).
- **First-party SDKs (Python + TypeScript, full console parity)** —
  `sdk/python` ships the installable `mcpip-sdk` (import `mcpip_sdk`; httpx as
  the only runtime dep, `py.typed`, frozen dataclasses): `MCPIPClient.authorize`
  returns `Allowed | Staged` with `complete(staged, pin)` for the step-up
  ceremony, denials raise the opaque `MCPIPDenied(correlation_id)`;
  `SandboxClient` adds the sandbox-only affordances (dev token, authenticator
  code, audit verify/proof) and `MCPIPAdminClient` covers the whole
  `CAP_DIRECTORY_ADMIN` surface (skills, decisions feed, principals,
  directory, workspace, cloud environments, vault, quarantine/canary rosters),
  plus envelope builders for all six dialects. `sdk/typescript` ships
  `@mcpip/sdk`, a zero-dependency ESM mirror (`McpipClient` /
  `McpipSandboxClient` / `McpipAdminClient`, discriminated `AuthorizeResult`
  union, `McpipDenied{correlationId}`, `McpipSandboxOnly`) with a 30-check
  live smoke (`smoke.mjs`). Shared wire contract documented in `docs/start/SDK.md`;
  gate: `tests/test_sdk_python.py` (12 tests against the real in-process
  gateway via `httpx.ASGITransport`).
- **Operator principal kill-switch (real revocation)** — an admin holding the new
  `CAP_DIRECTORY_ADMIN` capability can **revoke a principal** and the gateway
  enforces it on the hot path: every subsequent request from that `(tenant, agent)`
  is denied `PRINCIPAL_REVOKED` (opaque to the agent; concrete reason in WORM only)
  until an admin **reactivates** it. New fail-closed `services/revocation.py`
  (`RevocationStore.is_revoked` runs one Redis GET right after the quarantine gate;
  a transport failure denies `LOCK_ERROR`), new `DenyReason.PRINCIPAL_REVOKED`, and
  JWT + capability-gated, WORM-logged, opaque-deny endpoints
  `POST /v1/admin/principals/{agent_id}/revoke` · `/reactivate` ·
  `GET /v1/admin/principals/revoked`. This is a **DENY-only** control — it blocks a
  principal's requests, it never mints/edits/re-signs a credential, so identity stays
  IdP-sovereign; and it is deliberately separate from the canary-tripwire quarantine
  (a deliberate admin block that persists until lifted vs an automatic TTL freeze).
  The console's Principal Directory revoke/reactivate now drives the real endpoint
  when live (tenant-scoped, with a success/failure note).
- **Temporary access is now a real grant** — the Principal Directory's "Grant
  temporary access" runs the full payload-bound `skill_compartment_grant` step-up
  ceremony against a live gateway (mint a compartment-scoped officer → 202 staged →
  one-time code → committed), landing a WORM-logged Redis `GrantStore` TTL grant; the
  row shows a LIVE badge + the committing `transaction_ref`. Offline keeps the local
  TTL staging model. (`lib/grantCeremony.ts`.)
- **Software Updates & License** — a new **Admin & Infrastructure → Updates &
  License** sub-tab, plus two JWT-gated operator-visibility endpoints on the
  gateway. `GET /v1/version` reports the running release, its signed release
  provenance (`signing_key_id`, verified against the release-root key), the
  entitlement channel, and — when an OPTIONAL signed update feed
  (`MCPIP_UPDATE_MANIFEST_PATH`) is present and its Ed25519 signature verifies —
  a newer `latest`/`update_available`. `GET /v1/license` reflects the boot-verified
  entitlement document (`{licensed: false}` under a sandbox boot). The console's
  "Check for updates" flow is a **notifier, never an installer**: MCPIP downloads
  and executes nothing — it compares this console build (baked-in
  `__APP_VERSION__`) against the gateway's running version and the signed manifest,
  and flags when a signed **redeploy** is due (`update_policy: "redeploy"`). An
  unverifiable update feed is ignored; no network is ever contacted. Both endpoints
  fail closed to an opaque `MCPIPDenied` without a valid JWT and are never consulted
  by the authorization pipeline (licensing still gates boot only). The Knowledge
  Graph is now rendered as **n8n-style workflow nodes** (icon-badged, ported cards).
- Operator console **2.1.0** — the Principal Directory is now an **interactive
  admin surface**, not a read-only tree: drag a principal between teams to
  reassign it, add/delete Org Units · Teams · Principals inline, revoke/reactivate
  a principal, and grant **time-boxed temporary access** (TTL 15m/1h/8h/24h) with
  a live countdown + one-click revoke — the UI model of the gateway's Redis
  `GrantStore` TTL grants. The RBAC matrix is click-to-toggle. Console/desktop
  version bumped to `2.1.0` (`dashboard/package.json`, `src-tauri/{Cargo.toml,
  tauri.conf.json}`); the gateway `VERSION` stays `2.0.0` (no gateway code
  changed — the signed release manifests are not disturbed). Note: these IAM
  edits are the operator's **staging model** — identity is IdP-sovereign
  (`mint_principal.py`) and the gateway serves no directory-write API by design;
  a temp grant maps to the real `skill_compartment_grant` mandate when wired to a
  live gateway.
- Execution Policies — the Knowledge Graph is now an **editable, Airflow-style DAG**
  (React Flow / `@xyflow/react`): a directed flow of principals (human · user ·
  agent) → the compartment gate → data compartments, with **draggable nodes**,
  **connect-by-handle** edges, select-and-`Delete` removal, a node palette
  (agent / user / compartment), a dotted-grid canvas, minimap, and zoom controls.
  Allow edges are animated slate; **cross-project / cross-compartment edges are
  dashed-red hard denies** — including an explicit `User·project-x → project-aegis
  ⊘` edge, the drawn form of the gateway's principal-agnostic `compartment_denied`
  rule (a human user is denied cross-project reach exactly as an agent is). The
  view is lazy-loaded so React Flow (~60 kB gzip) stays out of the initial bundle.
- Operator console — IAM & Knowledge-Graph views + native desktop packaging.
  Two new dashboard views: **Principal Directory** (`views/PrincipalDirectory` —
  a collapsible OU→Team→Agent hierarchy of cryptographic principals, an RBAC
  role×capability matrix, and an identity provisioning/revocation panel) and
  **Execution Policies** (`views/ExecutionPolicies` — a node-edge Knowledge-Graph
  schema of principals + data compartments with allow/deny traversal edges, plus
  editable per-relation traversal policies bounded by hop depth + capability).
  Both match the porcelain/ink design tokens and build clean under strict `tsc`.
  **Tauri v2 native shell** (`dashboard/src-tauri/`) bundles the same web build
  into `.dmg`/`.app`, `.msi` (WiX), `.deb`, and `.AppImage` — an inert,
  minimal-surface Rust wrapper (no shell/fs/process plugins; strict CSP; stripped
  release binary). The web portal is the same `dist/` served over HTTPS (the
  zero-install fallback). Cross-platform CI in
  `.github/workflows/desktop-release.yml`; details in `docs/operate/OPERATIONS.md`.
- Zero-trust credential provisioning. `scripts/provision_gateway_keys.py` — the
  gateway key ceremony: generates the WORM epoch-signing + IdP identity-signing
  Ed25519 keypairs in memory, writes private PEM `0600` to a gitignored keys dir
  (verified mode; never printed/logged), emits only public keys + SHA-256
  fingerprints, refuses overwrite without `--force`. `scripts/mint_principal.py`
  — the production analog of the sandbox `/v1/dev/token`: signs an EdDSA principal
  JWT scoping an agent to a tenant + capability/compartment entitlements (the exact
  claim shape the gateway verifies; `role` authorizes nothing), short-TTL, with
  optional `cnf.jkt` sender-constraint / `act.sub` delegation. `deploy/.env.production.example`
  (paths only, zero secrets — the sole committed `.env*` variant) + `scripts/deploy_hero.sh`
  (materializes secrets from the store `0600` onto tmpfs, scrubs, execs fail-closed).
  Regression-gated by `tests/test_provisioning.py` (ceremony → mint → verify → tamper,
  8 cases). Operations in OPERATIONS_RUNBOOK §2.4 + §6.5.
- Real-world connector simulation & tamper QA (`tests/test_connector_simulation.py`,
  28 cases): authentic MCP (JSON-RPC 2.0) end-to-end through `/v1/mcp` and Anthropic
  Claude `tool_use` blocks through `/v1/authorize`; prompt-injection disguised as a
  tool-call, malformed / oversized / deep payloads, and invalid signatures each
  denied fail-closed; WORM-records-reason-while-agent-sees-opacity, canary-over-MCP
  trip + quarantine, and audit-chain-intact-after-mixed-traffic integration. A bug
  hunt over degenerate MCP framing found zero unhandled-exception paths (locked in
  as a regression gate — every malformed shape fails closed, never HTTP 5xx).
- Sender-constrained tokens (proof-of-possession, DPoP-style / RFC 9449 +
  RFC 7638 + RFC 8693). A JWT that carries a `cnf.jkt` confirmation is no
  longer a bearer token: the caller must present a `DPoP` proof JWS signed by
  the matching private key and bound to *this* request. Step 2a of the
  authorization pipeline (right after identity verification) verifies, in
  order: proof `typ`/alg-allowlist (`{EdDSA, ES256}` — no `none`/HMAC), a
  public-only JWK whose RFC-7638 thumbprint matches `cnf.jkt` (constant-time),
  the JWS signature, `htm`/`htu` request binding, `iat` freshness, and
  single-use `jti` via an atomic Redis `SET NX EX` replay guard (fail-closed).
  A cnf-bound token with no proof — or a stolen/replayed/relayed proof — is
  denied `JWT_INVALID`, opaque to the agent. When the token is a delegation
  chain, the RFC 8693 `act.sub` (human principal) is recorded to WORM only.
  Tokens with no `cnf` are unaffected — additive and backward-compatible. New
  module `auth/pop.py`; `Identity` gains optional `cnf_jkt`/`act_sub`; gates:
  `tests/test_pop_delegation.py` (42 crypto-core cases) plus the `test_sc_*`
  end-to-end scenarios in `tests/test_authorize_api.py`.
- Proof-of-possession hardening (closes two red-team findings against the
  initial PoP):
  * **Action-bound proof.** The DPoP proof now also binds `ath` (SHA-256 of the
    presented access token) and `pch` (the canonical payload hash — the *same*
    `lock_payload_hash` digest the PIN lock uses), so a proof attests THIS exact
    token + alias + arguments, not merely "some call to this endpoint by this
    key." A sniffed / relayed proof can no longer be substituted onto another
    action at the shared endpoint URL. PoP verification consequently moves from
    step 2a to **step 5a** (after alias resolution, so the payload hash is known).
  * **Resource-side requirement.** `AliasEntry.require_sender_constraint` (new,
    default `False`) lets an alias DEMAND a key-proven token: a bare bearer JWT
    reaching such an alias is denied `SENDER_CONSTRAINT_REQUIRED` at the resource
    gate — closing the "stolen bearer reaches a sensitive AUTO-tier read
    (CLASSIFIED/PHI/PII, no PIN)" gap. Enforced AFTER the compartment/mandate
    gates to preserve cross-compartment timing-uniformity.
  * **Production boot-lint + secure-by-default catalog.**
    `_enforce_sender_constraint_policy` refuses production boot
    (`sandbox_mode=False`) if any RESTRICTED/CLASSIFIED, non-`PIN_REQUIRED`
    alias lacks `require_sender_constraint` — the secure posture cannot be
    silently forgotten (same family as the integrity/license/key boot
    refusals). The reference catalog is now secure-by-default: every sensitive
    AUTO read (`skill_falcon_telemetry`, `skill_sentinel_recon_feed`,
    `skill_patient_lookup`, `skill_lab_results`, `skill_taxpayer_lookup`) sets
    the flag, and the PHI/PII reads are correctly classified `RESTRICTED`
    (previously mislabeled `UNCLASSIFIED`). Sandbox/demo stays permissive
    (bearer tokens, no proof keys) so the compartment/grant model still
    demonstrates unchanged. New `AliasRegistry.all_entries()`; gate:
    `tests/test_boot_policy.py`.
- `JWKSKeyProvider` (`auth/token_resolver.py`): a multi-key `KeyProvider` that
  selects the JWT verification key by the token header's `kid` from a JWKS
  document — the drop-in for an IdP / workload-identity STS that rotates signing
  keys. Supports OKP/RSA/EC public keys; rejects private material, unknown/absent
  `kid`, and duplicate/malformed entries fail-closed; the alg allow-list remains
  the gate (an EC key in the JWKS still cannot smuggle an `ES256` identity
  token). Deliberately not network-fetching — the JWKS is supplied at boot, so
  the auth hot path takes no synchronous JWKS round-trip. New
  `docs/integrate/INTEGRATIONS.md` specifies the fleet-scale provisioning story
  (runtime attestation → RFC 8693 token-exchange → ephemeral per-session keys)
  and the MCPIP-vs-platform boundary. Gate: `tests/test_jwks_provider.py`.
- Multi-issuer trust + attesting-issuer scoping — closes the weak-issuer
  downgrade lane. `MultiIssuerResolver` (`auth/token_resolver.py`) verifies a JWT
  against a set of trusted issuers, routing by the *verified* `iss` (a forged
  `iss` selects a resolver that rejects the signature). Each issuer carries an
  `attesting` flag (`TokenResolver(..., attesting=…)`) that flows to
  `Identity.cnf_attested`; a resource that DEMANDS sender-constraint
  (`require_sender_constraint`) is now satisfied ONLY by an *attested* cnf, so
  trusting a lower-assurance identity IdP that also stamps `cnf` never downgrades
  the gate — a non-attested cnf is denied `SENDER_CONSTRAINT_REQUIRED` even with
  a valid proof. Single-issuer deployments treat their one issuer as attesting by
  default (behavior unchanged). `AuthEngine` now accepts the `IdentityResolver`
  protocol so either resolver drops in. Gates: `tests/test_multi_issuer.py` +
  `test_require_sc_denies_non_attested_cnf` (end-to-end).
- Canary-alias deception tripwire: decoy skills (`skill_export_all_credentials`,
  `skill_disable_audit_log`) are seeded into every tenant's catalog as visible
  bait. Selecting one denies `CANARY_TRIPPED` and freezes the caller in a
  TTL-bounded `QuarantineStore`; while frozen, every request denies
  `AGENT_QUARANTINED` immediately after identity verification. Both denials stay
  opaque to the agent (the concrete reasons land only in the WORM log), so a
  prompt-injected agent trips a silent alarm the operator alerts on. Wired into
  both the `main.py` engine demo (gates C11/C11b) and the `/v1/authorize` +
  `/v1/mcp` pipeline (`services/quarantine.py`).

## [2.0.0] - 2026-07-14

### Added

- `/v1/authorize` REST edge: JWT-only identity, atomic exactly-once approval
  lock, staged PIN challenges (202), opaque fail-closed deny responses.
- `/v1/mcp` MCP-standard edge exposing the gateway as an MCP server
  (`serverInfo: mcpip`).
- Merkle-epoch WORM audit log: domain-separated leaf/node hashing, per-epoch
  Ed25519-signed root chain, external anchor file, super-checkpoint compaction,
  O(log n) inclusion proofs, `verify_chain` tamper detection.
- UUID-capability compartment authorization: capabilities are opaque UUIDs
  (never role strings); compartmented team/MCP separation with tenant
  obfuscation and alias registry.
- Multi-vendor connector registry (parsers only — MCPIP never calls the LLM
  and never holds vendor keys): `openai`, `gemini`, `claude`, `bedrock`,
  `copilot`, `deepseek`, `ernie`, `qwen`, `mcp_standard`
  (see `bridge/connectors/`). Format is declared, never sniffed.
- Performance tier: uvloop/httptools loop backends, edge admission control
  (overload shedding, request-size and time ceilings), Rust fastwalk crate.
- Operations dashboard (Vite/React, dark theme).
- **Release & packaging capstone (this release):**
  - Ed25519-signed release manifest (`release/manifest.json` + detached
    `release/manifest.sig`) over SHA-256 artifact digests; offline root key,
    public key + rotation manifest shipped in `release/keys/`.
  - `mcpip verify` CLI (`mcpip_verify/`): read-only, fail-closed verification
    of manifests and offline air-gap bundles; `mcpip export-audit` read-only
    WORM export with independent Merkle re-verification.
  - CycloneDX SBOM (`release/sbom/`), hashed and listed in the signed release
    manifest; offline CVE-scan runbook.
  - Offline air-gap bundle builder (`scripts/build_bundle.sh`): manifest,
    signature, public keys, artifacts, SBOM, SHA256SUMS, and install runbook
    in one deterministic tarball — verification requires no network.
  - Verified boot: signed source integrity manifest
    (`release/integrity_manifest.json`) checked read-only at startup;
    any mismatch aborts before a socket is bound.
  - Ed25519-signed license/entitlement gate (boot-time only — never consulted
    per-request).
  - Prometheus `/metrics` endpoint with closed-set labels only (no tenant,
    alias, capability, correlation, or JWT material) and structured JSON
    logging.
  - Helm chart (`deploy/chart/`) and plain Kubernetes manifests (`deploy/k8s/`):
    digest-pinned images, non-root, read-only rootfs, default-deny
    NetworkPolicy, HPA.

### Changed

- Single source of version truth: the `VERSION` file (`2.0.0`), read at
  runtime by `core/version.py` and at build time by `pyproject.toml`;
  `/healthz` now reports the running version.
- Python packaging metadata added (`pyproject.toml`, setuptools backend) with
  the `mcpip` console entrypoint.

### Security

- Three strictly separated Ed25519 root keys: release-signing, license-signing,
  and audit epoch-signing. Private keys are never committed and never enter
  the image — only public keys and the rotation manifest ship.
- Releases are immutable and verifiable: artifacts are deployed by digest,
  boot fails closed on any change to the shipped source set, and there is
  **no runtime self-update path** — operators redeploy through change control.
- SBOM enables offline CVE scanning inside air-gapped enclaves; MCPIP never
  phones home.

---

Update automation (if ever wanted) would follow TUF/Sigstore — future work
only; nothing in this release mutates a running gateway.
