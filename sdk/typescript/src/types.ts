/* ---------------------------------------------------------------------------
   @mcpip/sdk — the wire contract.

   A 1:1 typed mirror of the gateway's HTTP surface (models/schemas.py,
   interfaces.py, app/main.py handlers). Everything snake_case here IS the
   wire: these shapes cross the boundary verbatim, so they are never renamed.
   The only SDK-invented shape is the AuthorizeResult discriminated union — a
   camelCase convenience over the 200/202 bodies. Denials never appear as a
   result variant: a deny is a thrown McpipDenied carrying ONLY a correlation
   id, because the gateway is opaque by design (the concrete reason lives
   solely in the WORM log).
--------------------------------------------------------------------------- */

// ---------------------------------------------------------------------------
// Protocol constants (mirrors interfaces.py — values are frozen contract).
// ---------------------------------------------------------------------------

/** The one and only generic message that ever crosses the agent boundary. */
export const AGENT_FACING_DENY_MESSAGE = 'MCPIP: request denied by policy.';

/** Capability UUID a JWT must carry (in `capabilities`) for /v1/admin/* + /v1/directory. */
export const CAP_DIRECTORY_ADMIN = 'b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20';

/**
 * Capability UUID a JWT must carry to read the raw reconstructed query behind a
 * correlation id (GET /v1/admin/forensic/{correlation_id}). DELIBERATELY
 * DISTINCT from CAP_DIRECTORY_ADMIN — a directory admin does NOT get to read raw
 * payloads; forensic read is a separately-grantable, higher-sensitivity
 * investigator authority. Pinned to interfaces.py.
 */
export const CAP_FORENSIC_READ = 'd5f0c9a2-4b71-4e6a-9c83-1a7f2e6b4d90';

/**
 * Capability UUID a JWT must carry to REVIEW community-extension submissions —
 * the reviewer half of the author-your-own-skill/gate workflow: read the pending
 * queue and approve/reject a manifest (GET /v1/admin/extensions/pending,
 * POST /v1/admin/extensions/{id}/{approve,reject}). DELIBERATELY DISTINCT from
 * CAP_DIRECTORY_ADMIN and CAP_FORENSIC_READ — "can approve community extensions"
 * is separable from "can revoke a principal" and "can read raw forensic
 * payloads"; holding either sibling does NOT confer it. SUBMITTING a manifest
 * needs no capability at all (any authenticated principal). Pinned to interfaces.py.
 */
export const CAP_CATALOG_REVIEWER = '7a1f9c34-2e58-4b6d-9f01-3c7a5e2b8d46';

/** Response header echoing the per-request correlation id on every route. */
export const CORRELATION_HEADER = 'X-MCPIP-Correlation-Id';

/** Step-up one-time code: decimal digits. */
export const PIN_LENGTH = 6;
/** Payload-lock TTL — a staged challenge expires this many seconds after the 202. */
export const PIN_TTL_SECONDS = 300;
/** Wrong-PIN attempts before the lock is destroyed. */
export const PIN_MAX_ATTEMPTS = 5;

// ---------------------------------------------------------------------------
// Closed enums (interfaces.py / bridge/connectors/registry.py — exact strings).
// ---------------------------------------------------------------------------

/** The six normalized provider dialects the Bridge accepts (SourceFormat enum). */
export type SourceFormat =
  | 'openai_tool_call'
  | 'anthropic_tool_use'
  | 'raw_mcp'
  | 'gemini_function_call'
  | 'bedrock_tool_use'
  | 'mcp_jsonrpc'
  | 'a2a_task';

/**
 * Every vendor id the hash-pinned connector registry binds. The wire field is
 * a free string (unknown vendor => WORM-audited opaque deny, not a 422), so
 * this union is the reference list, not a structural constraint.
 */
export type Vendor =
  // Frontier labs + their OpenAI-compatible surfaces.
  | 'openai'
  | 'azure_openai'
  | 'copilot'
  | 'deepseek'
  | 'qwen'
  | 'ernie'
  | 'kimi'
  | 'moonshot'
  // Third-party inference clouds (OpenAI tool-call shape).
  | 'mistral'
  | 'groq'
  | 'together'
  | 'fireworks'
  | 'openrouter'
  | 'xai'
  | 'zhipu'
  | 'glm'
  | 'minimax'
  | 'perplexity'
  | 'cerebras'
  | 'sambanova'
  | 'nvidia_nim'
  | 'deepinfra'
  | 'nebius'
  // Self-hosted OpenAI-compatible runtimes (the air-gapped path).
  | 'ollama'
  | 'vllm'
  | 'sglang'
  | 'llama_cpp'
  | 'lmstudio'
  | 'tgi'
  | 'localai'
  // Enterprise data-platform model endpoints.
  | 'databricks'
  | 'watsonx'
  | 'snowflake_cortex'
  // LLM gateways / routers.
  | 'litellm'
  | 'portkey'
  | 'cloudflare_workers_ai'
  | 'vercel_ai_gateway'
  | 'github_models'
  // Anthropic tool_use — incl. the Bedrock- and Vertex-hosted forms.
  | 'claude'
  | 'claude_bedrock'
  | 'claude_vertex'
  // Native cloud dialects.
  | 'bedrock'
  | 'gemini'
  | 'vertex'
  // MCP hosts: editors, IDEs, terminals, coding agents.
  | 'mcp'
  | 'claude_code'
  | 'cursor'
  | 'windsurf'
  | 'cline'
  | 'opencode'
  | 'goose'
  | 'openhands'
  | 'openclaw'
  | 'zed'
  | 'vscode'
  | 'jetbrains'
  | 'continue'
  | 'roo'
  | 'kilocode'
  | 'codex'
  | 'gemini_cli'
  | 'amp'
  | 'crush'
  | 'warp'
  // Assistant surfaces + automation platforms speaking MCP.
  | 'chatgpt'
  | 'copilot_studio'
  | 'librechat'
  | 'openwebui'
  | 'n8n'
  | 'dify'
  | 'langflow'
  | 'flowise'
  // Agent frameworks acting as MCP clients.
  | 'langgraph'
  | 'crewai'
  | 'autogen'
  | 'openai_agents'
  | 'pydantic_ai'
  | 'llamaindex'
  | 'semantic_kernel'
  | 'mastra'
  | 'strands'
  // A2A task envelope.
  | 'a2a';

export type RiskTier = 'auto' | 'pin_required';

export type TransportClass = 'cloud_rest' | 'legacy_mainframe' | 'grant_issue' | 'cloud_iam';

export type Classification = 'unclassified' | 'restricted' | 'classified';

export type Decision = 'allow' | 'deny';

/**
 * DenyReason — operator/WORM-side only; the agent boundary NEVER sees these.
 * Mirrors the full closed enum in interfaces.py (the values the admin decision
 * feed's `deny_reason` column can carry). Note the engine's SKILL_DISABLED
 * member serializes as 'alias_disabled'. 'policy_denied' is the G3 deny-only
 * velocity/amount overlay; 'policy_gate_denied' is the DISTINCT Phase-2 deny-only
 * community-gate seam (step 4c′) — both stay opaque to the agent.
 */
export type DenyReason =
  | 'identity_injection'
  | 'unknown_format'
  | 'unknown_vendor'
  | 'schema_violation'
  | 'depth_exceeded'
  | 'size_exceeded'
  | 'illegal_character'
  | 'unknown_alias'
  | 'cross_tenant'
  | 'jwt_invalid'
  | 'jwt_claims_missing'
  | 'pin_required'
  | 'pin_not_found'
  | 'pin_mismatch'
  | 'payload_mismatch'
  | 'lock_error'
  | 'transport_error'
  | 'rate_limited'
  | 'internal'
  | 'compartment_denied'
  | 'capability_denied'
  | 'sender_constraint_required'
  | 'canary_tripped'
  | 'agent_quarantined'
  | 'principal_revoked'
  | 'alias_disabled'
  | 'otp_delivery_failed'
  | 'policy_denied'
  | 'policy_gate_denied';

// ---------------------------------------------------------------------------
// POST /v1/authorize — request envelope (models/schemas.py AuthorizeRequest).
// ---------------------------------------------------------------------------

export interface Hop {
  hop_index: number;
  agent_id: string;
  parent_agent_id: string | null;
  purpose: string;
}

/** Multi-agent provenance; omitted => the gateway synthesizes a single hop. */
export interface SwarmTrace {
  trace_id: string;
  hops: Hop[];
}

interface AuthorizeRequestBase {
  /** Raw provider envelope — deep-validated server-side by the Bridge. */
  tool_call: Record<string, unknown>;
  /** Identity in the body; when absent it comes from Authorization: Bearer. */
  jwt?: string | null;
  trace?: SwarmTrace | null;
  /** Step-up completion pair — supplied together or neither (422 otherwise). */
  pin?: string | null;
  challenge_id?: string | null;
}

/**
 * The dialect is DECLARED, never sniffed: exactly one of `source_format` /
 * `vendor` must be present (supplying both or neither is a 422 fail-closed).
 * The union encodes that constraint at the type level.
 */
export type AuthorizeRequest =
  | (AuthorizeRequestBase & { source_format: SourceFormat; vendor?: never })
  | (AuthorizeRequestBase & { vendor: string; source_format?: never });

// ---------------------------------------------------------------------------
// /v1/authorize — response bodies (wire-verbatim).
// ---------------------------------------------------------------------------

/** HTTP 202 — a pin_required alias was recognized; the payload lock is staged. */
export interface StagedChallenge {
  correlation_id: string;
  action_required: string;
  challenge_id: string;
  risk_tier: RiskTier;
}

/**
 * The short-lived scoped cloud credential vended for one authorized cloud_iam
 * call — the deliverable itself; it is never persisted to WORM.
 */
export interface VendedCredential {
  provider: string;
  region: string;
  expires_in: number;
  simulated: boolean;
  fingerprint: string;
  credential: Record<string, string>;
}

/** HTTP 200 — authorized and dispatched. Target CLASS only — never topology. */
export interface ExecutionReceipt {
  correlation_id: string;
  decision: 'allow';
  status: 'committed';
  transaction_ref: string;
  executed_target_class: TransportClass;
  worm_sequence: number;
  /** Present (non-null) only for the cloud_iam transport. */
  vended_credential?: VendedCredential | null;
}

/** HTTP 4xx/5xx — the opaque envelope: generic message + correlation id, nothing else. */
export interface ErrorResponse {
  error: string;
  correlation_id: string;
}

// ---------------------------------------------------------------------------
// AuthorizeResult — the SDK-level discriminated union over the two SUCCESS
// terminals (200 allowed / 202 staged). A deny is a thrown McpipDenied.
// ---------------------------------------------------------------------------

export interface AuthorizeAllowed {
  status: 'allowed';
  correlationId: string;
  transactionRef: string;
  executedTargetClass: TransportClass;
  wormSequence: number;
  vendedCredential: VendedCredential | null;
  /** The verbatim wire body. */
  receipt: ExecutionReceipt;
}

export interface AuthorizeStaged {
  status: 'staged';
  correlationId: string;
  /** The payload-bound lock id — consumed by complete() with the out-of-band PIN. */
  challengeId: string;
  actionRequired: string;
  riskTier: RiskTier;
  /** The verbatim wire body. */
  challenge: StagedChallenge;
  /**
   * The exact request that staged the lock. complete() resubmits it verbatim,
   * making the gateway's identical-payload rule structural: the consume can
   * never drift from what was staged.
   */
  request: AuthorizeRequest;
}

export type AuthorizeResult = AuthorizeAllowed | AuthorizeStaged;

// ---------------------------------------------------------------------------
// Agent-surface reads.
// ---------------------------------------------------------------------------

/** GET /v1/catalog item — metadata only; real targets never cross this boundary. */
export interface CatalogItem {
  alias: string;
  risk_tier: RiskTier;
  transport_class: TransportClass;
  classification: Classification;
  compartment?: string | null;
}

/** GET /healthz — event-loop liveness. */
export interface HealthzInfo {
  status: string;
  glyph?: string;
  loop?: string;
  version?: string;
}

/** GET /readyz — Redis-gated readiness (a 503 body is a real answer, not a failure). */
export interface ReadyInfo {
  ready: boolean;
  redis: 'up' | 'down';
}

/** GET /v1/version — signed release provenance. */
export interface ReleaseProvenance {
  version: string | null;
  signing_key_id: string | null;
  /** true/false when the release-root key verified the manifest; null = stated, not proven. */
  verified: boolean | null;
}

export interface VersionInfo {
  running: string;
  latest: string;
  update_available: boolean;
  channel: string;
  /** Always "redeploy" — MCPIP never auto-installs. */
  update_policy: string;
  release: ReleaseProvenance;
}

/** GET /v1/license — the boot-verified entitlement document (sandbox: { licensed: false }). */
export interface LicenseInfo {
  licensed: boolean;
  license_id?: string;
  customer?: string;
  tier?: string;
  issued_at?: string;
  expires_at?: string;
  entitlements?: string[];
}

/**
 * The tenant's coarse decision totals — the SAME closed enum as the gateway's
 * core/metrics.py decision counters (allow / deny / staged). Honest zeros for a
 * fresh tenant; never a per-alias or per-reason breakdown.
 */
export interface DecisionTotals {
  allow: number;
  deny: number;
  staged: number;
}

/**
 * The HONEST opt-in vendor-telemetry posture reported by GET /v1/admin/stats.
 *
 * `status` is one of "air-gap" (sandbox — the beacon is structurally disabled and
 * no install identity was ever minted), "enabled" (the beacon is live), or
 * "disabled" (opt-out / unconfigured production). It is NEVER fabricated. No
 * install-id, URL, or secret is ever exposed here (nor as a metric label). When the
 * beacon is live, `last_sent` is the epoch-seconds of the last successful send
 * (null until the first) and `last_result` is coarse ("never" / "ok" / "error");
 * `interval_seconds` is the clamped beacon cadence.
 */
export interface TelemetryStatus {
  status: 'air-gap' | 'enabled' | 'disabled';
  last_sent: number | null;
  last_result: 'never' | 'ok' | 'error';
  interval_seconds?: number;
}

/**
 * The HONEST posture of ONE opt-in / dark feature, reported inside the `features`
 * block of GET /v1/admin/stats. Posture-only and never fabricated: `status` is the
 * coarse machine state, `reason` refines WHY when a disabled state has several causes
 * (e.g. "production-default" vs "explicit-opt-out" vs "flag-on-no-key"), and `detail`
 * is the human-readable explanation + how to enable. NO url/key/path/target/tenant or
 * per-id information is ever carried — the posture is coarse and deployment-wide.
 */
export interface FeatureStatus {
  status: string;
  reason?: string;
  detail: string;
}

/**
 * The additive `features` posture block on GET /v1/admin/stats — honest
 * disabled/why/how-to-enable states for the opt-in dark features. Back-compat: the
 * whole block is OPTIONAL (a gateway predating it omits it). `telemetry` is NOT here —
 * it stays a top-level DeploymentStats field (the finished reference model). MRT
 * step-up is also not here — it is always advertised and read live from the
 * unauthenticated `initialize` capability, never a static posture string.
 *
 * `forensic_capture.status`: "enabled" | "absent" | "disabled". `external_pdp.status`:
 * "off" | "staged" | "enforcing".
 */
export interface FeaturesInfo {
  forensic_capture: FeatureStatus;
  external_pdp: FeatureStatus;
}

/**
 * GET /v1/admin/stats — the LOCAL live-stats read: the caller's OWN tenant's REAL
 * running numbers, served locally (no beacon, no vendor, no network needed). This
 * is the client-side "see the numbers live" surface — the same aggregate the opt-in
 * beacon would report, but scoped to the caller's tenant and always REAL or an
 * honest empty state (never a fabricated client, number, license, or "connected"
 * status). CAP_DIRECTORY_ADMIN-gated, tenant-scoped, opaque deny.
 *
 * `governed_agent_identity_count` is the governed-agent CARDINALITY (a HyperLogLog
 * PFCOUNT integer — the agent_ids are never stored or exposed). NO
 * tenant/agent/alias/target ever crosses this boundary — only aggregate integers.
 */
export interface DeploymentStats {
  version: string;
  governed_agent_identity_count: number;
  decisions: DecisionTotals;
  license: LicenseInfo;
  telemetry: TelemetryStatus;
  /**
   * Honest opt-in / dark-feature posture (forensic capture + external PDP). OPTIONAL
   * for back-compat: a gateway that predates the block omits it.
   */
  features?: FeaturesInfo;
}

/**
 * Operator/team USER management (`/v1/admin/users`) — the admin-managed, email-keyed
 * console roster. The `role` is a MANAGEMENT label (it authorizes nothing — the
 * role-claim invariant; identity + authz stay JWT + capabilities).
 */
export type OperatorRole = 'admin' | 'member' | 'viewer';
export type OperatorStatus = 'invited' | 'active' | 'disabled';

/** One roster member (admin-facing projection — the invite-token hash is never sent). */
export interface OperatorUser {
  email: string;
  role: OperatorRole;
  status: OperatorStatus;
  invited_by: string;
  invited_at: string;
  updated_at: string;
}

/** A cursor page of the roster (HSCAN, never an offset). `next_cursor === '0'` ⇒ done. */
export interface OperatorUserPage {
  users: OperatorUser[];
  next_cursor: string;
  count: number;
  cap: number;
}

/** The invite result — the record + the ONE-TIME reference token to send (not a credential). */
export interface OperatorInvite {
  user: OperatorUser;
  invite_token: string;
}

/**
 * GET /v1/audit/attestation — a portable, signed snapshot of the CURRENT audit
 * state (JWT-gated, read-only). Mirrors audit/worm_logger.py WormAttestation
 * verbatim. Unlike the sandbox-only /v1/audit/verify + /v1/audit/proof this is
 * available in PRODUCTION and needs only a valid JWT (no CAP_DIRECTORY_ADMIN) —
 * a portable, externally-checkable attestation is a production artifact.
 *
 * The latest SEALED epoch header (epoch/end_seq/merkle_root/epoch_hash/signature,
 * all null before the first epoch closes — an honest empty state, never a
 * fabricated header), the WORM epoch key's public signing_key_id (always present:
 * a non-secret fingerprint an external verifier binds the epoch signature to), a
 * FRESH verify_chain result (intact + first_bad_epoch), and the
 * out-of-tamper-domain anchor low-watermark (anchor_epoch/anchor_epoch_hash, null
 * when no anchor is configured or nothing witnessed yet). Every signed field was
 * Ed25519-signed by the WORM key at epoch close / anchor append: the endpoint
 * mints no key and signs nothing new, so no target, payload, PIN/OTP, or secret
 * ever appears.
 */
export interface AuditAttestation {
  epoch: number | null;
  end_seq: number | null;
  merkle_root: string | null;
  epoch_hash: string | null;
  signature: string | null;
  signing_key_id: string;
  intact: boolean;
  first_bad_epoch: number | null;
  anchor_epoch: number | null;
  anchor_epoch_hash: string | null;
}

/** One control-clause → MCPIP-mechanism evidence row (services/compliance_evidence.py). */
export interface ComplianceControlClause {
  clause: string;
  mechanism: string;
  mcpip_evidence: string;
  code_pointer: string;
  /** Always 'provides-evidence-for' — never 'certified'/'passed'. */
  coverage: string;
}

/** One regulatory-framework block. `certification_note` restates that the certification itself is external. */
export interface ComplianceFramework {
  framework: string;
  reference: string;
  certification_note: string;
  clauses: ComplianceControlClause[];
}

/**
 * GET /v1/admin/compliance/evidence — a portable COMPLIANCE-EVIDENCE bundle
 * (CAP_DIRECTORY_ADMIN-gated, read-only; services/compliance_evidence.build_evidence_bundle).
 * Assembled from REAL running gateway state only: the signed WORM `attestation`
 * (same commitments /v1/audit/attestation surfaces), the running `gateway_version`
 * + signed `release_provenance`, and a STATIC `control_mapping` manifest.
 *
 * EVIDENCE, NOT a CERTIFICATION: `disclaimer` (and each framework's
 * `certification_note`) restates the bundle asserts no SOC 2 report, FedRAMP
 * authorization, ISO/DORA/EU-AI-Act certificate, named customer, or auditor
 * sign-off — those are external third-party processes this software cannot
 * produce. `sealed` is honest: before the first epoch seals the attestation header
 * fields are null and `empty_state_note` explains the empty state (never a
 * fabricated header). No target/payload/PIN/OTP/secret ever appears.
 */
export interface ComplianceEvidence {
  generated_at: string;
  gateway_version: string;
  release_provenance: ReleaseProvenance;
  sealed: boolean;
  attestation: AuditAttestation;
  control_mapping: ComplianceFramework[];
  disclaimer: string;
  /** Present only when no epoch has sealed yet (honest empty state). */
  empty_state_note?: string;
}

/** The schema tag every verified-publisher allow-list document carries (registry governance, X3). */
export const PUBLISHERS_SCHEMA = 'mcpip-registry-publishers/1' as const;

/**
 * GET/PUT /v1/admin/extensions/publishers — the tenant's verified-publisher
 * allow-list (registry governance, X3). A reviewer-PINNED set of allowed publisher
 * NAMESPACES (reverse-DNS prefixes such as `io.github.owner`) consulted fail-closed
 * when a registry-sourced skill is approved / re-verified at boot. Carries ONLY
 * publisher namespaces — never a target or identity. Honest empty `{ schema,
 * namespaces: [] }` when nothing is pinned.
 */
export interface VerifiedPublishers {
  schema: typeof PUBLISHERS_SCHEMA;
  namespaces: string[];
}

// ---------------------------------------------------------------------------
// Standards interop — OAuth 2.1 Resource-Server metadata (N2) + the
// OpenID-AuthZEN / COAZ decision surface (N1).
// ---------------------------------------------------------------------------

/**
 * GET /.well-known/oauth-protected-resource — the RFC 9728 OAuth 2.1 Protected
 * Resource Metadata document (auth/oauth_metadata.build_protected_resource_metadata).
 * PUBLIC and unauthenticated; a conformant MCP client reads it to learn MCPIP's
 * own resource identifier and the authorization server(s) that issue tokens for
 * it, so it presents a token bound to THIS resource (RFC 8707) rather than a
 * look-alike endpoint. NO scopes (MCPIP has none), NO secret, NO alias→target
 * topology — only the non-secret discovery identifiers.
 */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: string[];
}

/**
 * The AuthZEN request entities for POST /v1/authz/decision. `resource.id` is the
 * opaque alias; `action.properties` the tool-call arguments (deep-validated by
 * the SAME bridge walker as a real call). `subject` is advisory/echo ONLY and is
 * NEVER an identity input — identity comes solely from the verified JWT.
 */
export interface AuthzenDecisionRequest {
  subject: Record<string, unknown>;
  resource: { id: string; type?: string; properties?: Record<string, unknown> };
  action: { name?: string; properties?: Record<string, unknown> };
  context?: Record<string, unknown>;
}

/**
 * POST /v1/authz/decision response — the OpenID-AuthZEN Authorization API 1.0
 * decision (models/schemas.AuthzenDecisionResponse). MCPIP answers as a PDP,
 * DECISION-ONLY. A permit is `{ decision: true }` optionally carrying
 * standards-shaped `obligations` (e.g. `{ id: 'mcpip.step_up.pin' }`); a deny is
 * the bare, opaque `{ decision: false }` — NO reason/target/topology (the concrete
 * cause lives only in the WORM log). `obligations` is omitted, never `[]`, when
 * empty.
 */
export interface AuthzenDecisionResponse {
  decision: boolean;
  obligations?: Array<{ id: string; [k: string]: unknown }>;
}

// ---------------------------------------------------------------------------
// Sandbox-only surfaces (each answers 404 on a production gateway).
// ---------------------------------------------------------------------------

/**
 * Claims accepted by POST /v1/dev/token (app.main._DevTokenRequest). All
 * optional — an empty body mints the default sandbox identity. `compartment`
 * and `capabilities` are UUID strings projected onto the JWT's optional
 * authorization claims.
 */
export type DevTokenClaims = Partial<{
  tenant_id: string;
  agent_id: string;
  role: string;
  compartment: string;
  capabilities: string[];
}>;

/** GET /v1/audit/verify — end-to-end signed Merkle-epoch chain verification. */
export interface AuditVerifyResult {
  intact: boolean;
  first_bad_epoch: number | null;
}

/** GET /v1/audit/proof/{event_id} — O(log n) inclusion proof to a signed epoch root. */
export interface InclusionProof {
  event_id: string;
  epoch: number;
  index: number;
  record: string;
  proof: Array<[side: 'L' | 'R', siblingHex: string]>;
  merkle_root: string;
  epoch_hash: string;
  signature: string;
}

// ---------------------------------------------------------------------------
// Admin surface (/v1/admin/* + /v1/directory — CAP_DIRECTORY_ADMIN gated,
// always scoped to the admin JWT's own tenant).
// ---------------------------------------------------------------------------

/** One row of GET /v1/admin/decisions/recent — a strict whitelist projection. */
export interface RecentDecision {
  correlation_id: string;
  agent_id: string | null;
  alias: string | null;
  decision: Decision;
  deny_reason: string | null;
  transport: string | null;
  risk_tier: string | null;
  classification: string | null;
  source_format: string | null;
  transaction_ref: string | null;
  tenant_id: string;
  worm_sequence: number;
  timestamp_ns: number;
  /**
   * WORM event id — keys GET /v1/audit/proof/{event_id}. Null when the
   * connected gateway predates the projection extension that added it.
   */
  event_id: string | null;
}

/** Whitelist facets accepted by the decision-history query (each OR-able). */
export type DecisionFacet =
  | 'decision'
  | 'deny_reason'
  | 'alias'
  | 'transport'
  | 'risk_tier'
  | 'classification'
  | 'agent_id'
  | 'source_format'
  | 'correlation_id'
  | 'transaction_ref';

/**
 * Inputs to GET /v1/admin/decisions — the date-ranged, multi-filtered,
 * cursor-paged decision history (at scale). All optional: `fromMs`/`toMs` bound
 * an inclusive epoch-millisecond window; `cursor` resumes a prior page; `limit`
 * is clamped server-side; `filters` maps a facet to one value or a list (OR
 * within a facet, AND across facets).
 */
export interface DecisionQuery {
  fromMs?: number;
  toMs?: number;
  cursor?: string;
  limit?: number;
  filters?: Partial<Record<DecisionFacet, string | string[]>>;
}

/**
 * One page of GET /v1/admin/decisions — the same whitelist projection the live
 * feed serves (`decisions` are RecentDecision rows, newest first). Pass
 * `next_cursor` back as `cursor` for the next page; `null` means the window is
 * fully walked.
 */
export interface DecisionPage {
  decisions: RecentDecision[];
  next_cursor: string | null;
  scanned: number;
  exhausted: boolean;
}

/**
 * GET /v1/admin/forensic/{correlation_id} — the reconstructed REAL query an
 * agent sent for one correlation id, decrypted from the forensic capture store
 * for a CAP_FORENSIC_READ investigator.
 *
 * The ADMIN/investigator counterpart to the deliberately opaque agent wire and
 * the arguments-omitting decision feed: the opaque `alias`, the already-
 * canonicalized (and secret-redacted) `arguments`, and non-secret identity
 * context. NEVER reachable from an agent token — no agent JWT carries
 * CAP_FORENSIC_READ, and even CAP_DIRECTORY_ADMIN does not confer it — and every
 * retrieval is WORM-audited before disclosure. A miss (feature off, or an
 * unknown/expired/cross-tenant correlation id) is an honest `null`, never this
 * shape.
 */
export interface ForensicPayload {
  // Mirrors services/forensic_store.py ForensicRecord.public_view() verbatim.
  correlation_id: string;
  tenant_id: string;
  agent_id: string;
  role: string;
  issuer: string;
  alias: string;
  /** Already-canonicalized arguments, run through the WORM redaction discipline. */
  arguments: Record<string, unknown>;
  source_format: string;
  decision: string;
  deny_reason: string | null;
  /** RFC 8693 delegation actor (`act.sub`), when present. */
  act_sub: string | null;
  /** Wall-clock capture time (epoch seconds, float). */
  captured_at: number;
}

/** Body for POST /v1/admin/skills/register (additive-only; cloud_rest forced). */
export interface RegisterSkillBody {
  alias: string;
  target: string;
  /** Default 'auto'. 'restricted' classification requires 'pin_required'. */
  risk_tier?: RiskTier;
  /** Operator overlay can mint 'unclassified' | 'restricted' only. */
  classification?: 'unclassified' | 'restricted';
}

/** One operator-registered (deregisterable) skill. */
export interface RegisteredSkill {
  alias: string;
  /** ISO-8601 creation timestamp, or null on gateways predating the field. */
  registered_at: string | null;
}

/** One agent currently frozen by the canary tripwire (TTL-bounded, self-healing). */
export interface QuarantinedAgent {
  agent_id: string;
  /** Seconds remaining on the freeze, or null when the gateway omits it. */
  ttl_seconds: number | null;
}

/**
 * One canary decoy alias — operator view only. This is the sole surface where
 * the canary flag crosses the wire; the agent-facing catalog keeps hiding it.
 */
export interface CanaryDecoy {
  alias: string;
  risk_tier: string | null;
  classification: string | null;
}

/**
 * One ReBAC relation edge of GET /v1/admin/directory/relations — mirrors
 * services/relation_store.py RelationEdge verbatim (the row shape served). The
 * `subject` has `relation` to `object`: a committed grant projects a `member`
 * edge (agent -> compartment) and a read-time-derived `grantor` edge (issuing
 * principal -> compartment). The grant metadata (grant_id / correlation_id /
 * issued_at_ns) is null on a derived `grantor` edge or when the tuple value was
 * unreadable. NO target, secret, or alias->target mapping is ever here — these
 * are the SAME operator-facing identifiers already in the console Principal
 * Directory, not the hidden topology.
 */
export interface RelationEdge {
  object: string;
  relation: string;
  subject: string;
  grant_id: string | null;
  correlation_id: string | null;
  issued_at_ns: number | null;
}

/**
 * GET /v1/admin/directory/relations — the ReBAC edges projected from the admin's
 * OWN tenant's committed grants, plus (only when a FULL subject+relation+object
 * triple was queried) the bounded transitive-closure `allowed` verdict. A
 * best-effort PROJECTION backing the operator Knowledge-Graph: the gateway/Redis
 * grant state is authoritative, so a transport blip UNDER-reports edges (fail-soft
 * empty, never over-reports). `allowed` is absent unless a full triple was
 * supplied (only `member` is traversable in v1; `grantor` is a derived display
 * edge). READ/VISUALIZATION ONLY — the authorization pipeline NEVER consults it.
 */
export interface RelationList {
  relations: RelationEdge[];
  allowed?: boolean;
}

/** A cloud IAM environment binding (public view) — holds NO cloud secret. */
export interface CloudEnvironment {
  env_id: string;
  provider: string;
  role: string;
  region: string;
  compartment: string | null;
  session_ttl: number;
  /** Optional REFERENCE to a vault entry the broker spends — never a value. */
  vault_secret_id?: string | null;
}

/** Body for PUT /v1/admin/cloud/environments (create/update one binding). */
export interface CloudEnvironmentInput {
  env_id: string;
  provider: string;
  role: string;
  region: string;
  compartment?: string;
  /** Seconds; default 900, clamped server-side to the short-lived band. */
  session_ttl?: number;
  /** Must reference an EXISTING vault entry of this tenant, else opaque deny. */
  vault_secret_id?: string;
}

/** Vault entry metadata — the value is write-only and never returned by any endpoint. */
export interface VaultSecret {
  secret_id: string;
  vendor: string;
  description: string;
  fingerprint: string;
  created_at: number;
  updated_at: number;
}

/** Body for PUT /v1/admin/vault/secrets — the ONLY request carrying a secret value. */
export interface VaultSecretInput {
  secret_id: string;
  vendor: string;
  description?: string;
  /** Flat map of bounded strings (e.g. access_key_id / secret_access_key). */
  material: Record<string, string>;
}

/** GET /v1/admin/vault/secrets — metadata roster (values never appear). */
export interface VaultSecretList {
  vault_enabled: boolean;
  secrets: VaultSecret[];
}

/** A single generated skill inside a workspace plan. */
export interface PlanSkill {
  alias: string;
  target: string;
  risk_tier: string;
  classification: string;
}

/** A reviewable workspace scaffold: org chart + governed starter skill catalog. */
export interface WorkspacePlan {
  company: string;
  tenant: string;
  org_units: unknown[];
  skills: PlanSkill[];
}

export interface PlanSummary {
  org_units: number;
  teams: number;
  skills: number;
}

/** Body for POST /v1/admin/workspace/draft (all fields server-defaulted). */
export interface WorkspaceDraftBody {
  brief?: string;
  company?: string;
  /** Empty/omitted resolves to the admin's own tenant. */
  tenant?: string;
}

/** POST /v1/admin/workspace/draft — deterministic proposal, no mutation. */
export interface WorkspaceDraft {
  plan: WorkspacePlan;
  summary: PlanSummary;
}

/** POST /v1/admin/workspace/plan/validate — dry-run verdict. */
export interface PlanValidation {
  ok: boolean;
  errors: string[];
  warnings: string[];
  summary: PlanSummary;
}

/** POST /v1/admin/workspace/plan/apply — idempotent apply outcome. */
export interface WorkspaceApplyResult {
  applied: boolean;
  created: string[];
  skipped: string[];
  summary: PlanSummary;
}

/** The persisted operator directory — non-authoritative metadata (never gates auth). */
export interface DirectoryDocument {
  schema: 'mcpip-directory/1';
  org_units: unknown[];
  rbac?: Record<string, string[]>;
}

// ---------------------------------------------------------------------------
// Deny-only policy overlay (GET|PUT /v1/admin/policy, POST .../delete).
// ---------------------------------------------------------------------------

/** Which request field a rule keys on (services/policy_engine.py PolicyRule.scope). */
export type PolicyScope = 'alias' | 'transport_class';

/** The two deny-only rule kinds (services/policy_engine.py PolicyRule.kind). */
export type PolicyRuleKind = 'velocity' | 'amount';

/**
 * One deny-only policy rule (models/schemas.py PolicyRuleModel /
 * services/policy_engine.py PolicyRule). A rule MATCHES a request by `scope` +
 * `scope_value` (an opaque alias name or a coarse transport class) and, per
 * `kind`, carries EITHER the velocity fields (`max_actions` + `window_seconds`)
 * OR the amount fields (`amount_field` + `max_amount`). A stored rule (GET)
 * carries all keys with the off-kind ones null; a written rule (PUT) may omit
 * them — supplying a field for the wrong kind is a fail-closed opaque deny.
 */
export interface PolicyRule {
  kind: PolicyRuleKind;
  scope: PolicyScope;
  scope_value: string;
  /** Velocity rule: max actions per window (>= 1). Null/absent on an amount rule. */
  max_actions?: number | null;
  /** Velocity rule: fixed window seconds (1..86400). Null/absent on an amount rule. */
  window_seconds?: number | null;
  /** Amount rule: the numeric argument field to ceiling. Null/absent on a velocity rule. */
  amount_field?: string | null;
  /** Amount rule: the ceiling as a decimal STRING (no float drift). Null/absent on a velocity rule. */
  max_amount?: string | null;
}

/**
 * The per-tenant deny-only policy document (models/schemas.py
 * PolicyDocumentRequest / services/policy_engine.py PolicyRuleSet). Holds ONLY
 * velocity/amount rules — never an alias->target mapping or identity — so it can
 * never repoint a skill or mint a principal. NO stored document => the engine
 * imposes no limits (honest opt-in). A policy denial reaches the agent only as
 * the opaque McpipDenied (WORM-side deny_reason `policy_denied`).
 */
export interface PolicyDocument {
  schema: 'mcpip-policy/1';
  rules: PolicyRule[];
}

// ---------------------------------------------------------------------------
// Community extensions (author-your-own SKILLS + GATES). A Contributor (ANY
// authenticated principal) submits an `mcpip-extension/1` manifest for review;
// a Reviewer holding the DISTINCT CAP_CATALOG_REVIEWER acts on it. The SAME
// submit/review/WORM/hash-pin flow serves both kinds, routed by `kind`. GATES
// (Phase 2) ship as schema + a deny-only seam; the CEL parse/evaluate runtime is
// DEFERRED, so a gate is stored PENDING but can never be approved/enforced until
// an engine is registered (docs/EXTENSIBILITY.md §8). Mirrors app/main.py verbatim.
// ---------------------------------------------------------------------------

/** The two extension kinds the submit/review flow routes on (manifest `kind`). */
export type ExtensionKind = 'skill' | 'gate';

/**
 * A community-SKILL manifest (`mcpip-extension/1`, `kind: 'skill'`) a Contributor
 * authors and submits (services/extension_manifest.py ExtensionManifest).
 * Declarative data only: a NEW opaque `alias` onto a `cloud_rest` `target` — it
 * can never repoint an existing alias or reach a privileged transport. The
 * `sha256` is a SELF-PIN the author computes over the canonical manifest bytes
 * (sort_keys/compact, dropping `sha256` + the reserved `signature`), DISTINCT
 * from the payload-lock canonical_json; the gateway re-derives and compares it
 * fail-closed and pins it at approval for rug-pull defense.
 */
export interface ExtensionSkillManifest {
  schema: 'mcpip-extension/1';
  kind: 'skill';
  /** Operator-facing label only — never trusted for authorization or de-duplication. */
  id: string;
  author: string;
  /** 64-hex self-pin over the canonical manifest bytes. */
  sha256: string;
  alias: string;
  target: string;
  transport: 'cloud_rest';
  risk_tier: RiskTier;
  /** Overlay mints 'unclassified' | 'restricted' only; 'restricted' => 'pin_required'. */
  classification: 'unclassified' | 'restricted';
}

/**
 * A community-GATE manifest (`mcpip-extension/1`, `kind: 'gate'`, Phase 2) — a
 * DENY-ONLY declarative CEL predicate (services/extension_manifest.py
 * GateManifest), NOT an alias->target and never a transport. Validated as pure
 * DATA only; the CEL runtime is DEFERRED, so a gate can be SUBMITTED + stored but
 * NOT approved/enforced until an engine is registered. `referenced_context_fields`
 * must be a subset of the fixed topology-free whitelist { alias, risk_tier,
 * transport_class, classification } — never `target`, a secret, or topology.
 */
export interface ExtensionGateManifest {
  schema: 'mcpip-extension/1';
  kind: 'gate';
  id: string;
  author: string;
  sha256: string;
  /** The only substrate adopted — arbitrary code (WASM/Python) is rejected by construction. */
  language: 'cel';
  /** The CEL predicate text (charset-scrubbed server-side; NOT parsed — runtime deferred). */
  source: string;
  /** Subset of the fixed GATE_CONTEXT_FIELDS whitelist. Absent => none declared. */
  referenced_context_fields?: string[];
  /** Declared static CEL cost the deferred prover must confirm; 1..MAX_GATE_COST. */
  max_cost: number;
}

/** The authored manifest a Contributor submits — a skill or a gate (discriminated by `kind`). */
export type ExtensionManifest = ExtensionSkillManifest | ExtensionGateManifest;

/**
 * One PENDING community-SKILL submission as projected by
 * GET /v1/admin/extensions/pending — a strict reviewer-only whitelist over the
 * stored manifest. The submitter-declared `target` is visible to the reviewer
 * HERE but NEVER crosses the agent wire. `conflicts_existing_alias` is a rendered
 * additive-only diff (an approve would be refused if true) and
 * `submitter_is_reviewer` a separation-of-duties hint (procedural, not a control).
 */
export interface PendingSkillExtension {
  submission_id: string;
  kind: 'skill';
  alias: string;
  /** The real target — reviewer-visible ONLY; never reaches an agent. */
  target: string;
  transport: string;
  risk_tier: string;
  classification: string;
  /** Operator-facing manifest label — the AUTHORITATIVE actor is `submitter_agent_id`. */
  author: string;
  submitter_agent_id: string;
  manifest_sha256: string;
  created_at: string;
  /** Does this alias already resolve (config OR overlay)? An approve would be refused. */
  conflicts_existing_alias: boolean;
  /** Did the reviewer also submit this? (separation-of-duties hint) */
  submitter_is_reviewer: boolean;
}

/**
 * One PENDING community-GATE submission (Phase 2) as projected by
 * GET /v1/admin/extensions/pending. A gate is a topology-free deny predicate, not
 * an alias->target. `approvable` is the honest reviewer signal: gate approval is
 * BLOCKED until the deferred CEL prover/engine is registered, so it is `false` on
 * a gateway without one and `extensionApprove` would be an opaque deny.
 */
export interface PendingGateExtension {
  submission_id: string;
  kind: 'gate';
  gate_id: string;
  language: string;
  /** Declared static CEL cost; null when the stored manifest omits it. */
  max_cost: number | null;
  referenced_context_fields: string[];
  author: string;
  submitter_agent_id: string;
  manifest_sha256: string;
  created_at: string;
  submitter_is_reviewer: boolean;
  /** Can a reviewer approve this now? `false` until a CEL prover/engine is registered. */
  approvable: boolean;
}

/** One row of GET /v1/admin/extensions/pending — a skill or a gate, discriminated by `kind`. */
export type PendingExtension = PendingSkillExtension | PendingGateExtension;
