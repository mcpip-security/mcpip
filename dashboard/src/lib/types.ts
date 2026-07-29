/* ---------------------------------------------------------------------------
   Typed mirror of the FastAPI /v1/authorize contract (INTEGRATION SPEC §2.3, §2.7).
   These shapes are frozen against the gateway so a real fetch can be dropped in
   without touching the UI. Nothing here reimplements engine crypto — it only
   describes the JSON that crosses the wire.
--------------------------------------------------------------------------- */

/** Mirrors interfaces.py SourceFormat — the six normalized provider dialects. */
export type SourceFormat =
  | 'openai_tool_call'
  | 'anthropic_tool_use'
  | 'raw_mcp'
  | 'gemini_function_call'
  | 'bedrock_tool_use'
  | 'mcp_jsonrpc';

export type RiskTier = 'auto' | 'pin_required';

export type TransportClass = 'cloud_rest' | 'legacy_mainframe' | 'grant_issue' | 'cloud_iam';

export type Classification = 'unclassified' | 'restricted' | 'classified';

export type Decision = 'allow' | 'deny';

/**
 * DenyReason — operator/WORM-only; the agent boundary never sees these.
 * Mirrors the FULL closed enum in interfaces.py (every value the decision
 * feed and /metrics deny_reason labels can carry). Note the engine's
 * SKILL_DISABLED member serializes as 'alias_disabled'; likewise
 * 'otp_delivery_failed' (G1 — the out-of-band step-up code could not be
 * delivered, so the PIN_REQUIRED staging fails closed rather than staging an
 * unanswerable challenge), 'policy_denied' (G3 — the deny-only velocity /
 * amount-ceiling overlay refused the action) and 'policy_gate_denied' (Phase 2 —
 * the deny-only community-gate seam at pipeline step 4c′ refused the action;
 * DISTINCT from 'policy_denied') are operator/WORM-only reasons an agent never
 * sees; the concrete cause (which gate, why) rides only in the WORM detail.
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

export interface Hop {
  hop_index: number;
  agent_id: string;
  parent_agent_id: string | null;
  purpose: string;
}

export interface SwarmTrace {
  trace_id: string;
  hops: Hop[];
}

/** POST /v1/authorize request (§2.3 AuthorizeRequest). */
export interface AuthorizeRequest {
  source_format: SourceFormat;
  tool_call: Record<string, unknown>;
  jwt?: string | null;
  trace?: SwarmTrace | null;
  pin?: string | null;
  challenge_id?: string | null;
}

/** HTTP 202 (§2.3 StagedChallenge). */
export interface StagedChallenge {
  correlation_id: string;
  action_required: string;
  challenge_id: string;
  risk_tier: RiskTier;
}

/** HTTP 200 (§2.3 ExecutionReceipt). */
export interface ExecutionReceipt {
  correlation_id: string;
  decision: 'allow';
  status: 'committed';
  transaction_ref: string;
  executed_target_class: TransportClass;
  worm_sequence: number;
}

/** HTTP 4xx/5xx — opaque (§2.3 ErrorResponse). */
export interface ErrorResponse {
  error: string;
  correlation_id: string;
}

/** Discriminated union over the three terminal outcomes of /v1/authorize. */
export type AuthorizeOutcome =
  | { kind: 'executed'; receipt: ExecutionReceipt }
  | { kind: 'staged'; challenge: StagedChallenge }
  | { kind: 'denied'; error: ErrorResponse; wormReason: DenyReason };

/** One agent-visible skill from build_demo_registry() (SPEC §3). */
export interface AliasEntry {
  alias: string;
  target: string;
  transport: TransportClass;
  risk_tier: RiskTier;
  tenant_id: string;
  compartment?: string | null;
  classification?: Classification;
  required_capability?: string | null;
}

/** A UUID-identified team compartment (SPEC §1). */
export interface Compartment {
  compartment_uuid: string;
  label: string;
  classification: Classification;
}

/** Structured skill access level — advisory display metadata, never enforcement. */
export type SkillAccess = 'read' | 'write';

/** GET /v1/catalog item — metadata only, never the target (SPEC §1.9). */
export interface CatalogItem {
  alias: string;
  risk_tier: RiskTier;
  transport_class: TransportClass;
  classification: Classification;
  compartment?: string | null;
  /** Advisory display access mode ('read'/'write'), risk-derived when unannotated.
      Absent on older gateways — callers fall back to the risk tier. */
  access?: SkillAccess | null;
}

/** A delegated compartment grant (SPEC §1.5 GrantRecord). */
export interface GrantRecord {
  grant_id: string;
  tenant_id: string;
  subject_agent_id: string;
  compartment_uuid: string;
  issued_by: string;
  capability_used: string;
  issued_at_ns: number;
  expires_at_ns: number;
  correlation_id: string;
}

/** A closed, signed epoch header (hybrid Merkle-epoch WORM, SPEC §3.4). */
export interface EpochHeader {
  epoch: number;
  start_seq: number;
  end_seq: number;
  leaf_count: number;
  timestamp_ns: number;
  merkle_root: string;
  prev_epoch_hash: string;
  epoch_hash: string;
  signature: string;
}

/** An O(log n) inclusion proof to a signed epoch root (SPEC §3.6). */
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

/**
 * The redacted, reconstructed view of ONE captured request — the payload the
 * deliberately-opaque agent wire and the arguments-omitting decision feed never
 * surface. Mirrors `services/forensic_store.py` `ForensicRecord.public_view()`
 * verbatim (the body served by `GET /v1/admin/forensic/{correlation_id}` under
 * `forensic`). It carries the agent's QUERY — alias + already-normalized,
 * secret-scrubbed `arguments` — plus non-secret identity context ONLY. It NEVER
 * carries the hidden real `target`, the `payload_hash`, a PIN/JWT/proof, or any
 * vended credential: those are excluded at capture time and scrubbed by the WORM
 * `_redact` discipline as defence-in-depth. This is an INVESTIGATOR surface,
 * reachable only with CAP_FORENSIC_READ and only under a WORM `forensic_read`
 * audit — never on any agent-facing route.
 */
export interface ForensicRecord {
  correlation_id: string;
  tenant_id: string;
  agent_id: string;
  role: string;
  issuer: string;
  alias: string;
  /** Already-canonicalized, secret-redacted request arguments (never the target). */
  arguments: Record<string, unknown>;
  source_format: string;
  decision: string;
  deny_reason: string | null;
  /** RFC 8693 delegation actor (`act.sub`), when the request carried one. */
  act_sub: string | null;
  /** Wall-clock capture time (epoch seconds, float). */
  captured_at: number;
}

/**
 * A single row in the live authorization stream — a 1:1 projection of one
 * /v1/admin/decisions/recent row (audit/worm_logger.py recent_decisions
 * whitelist). Every field is REAL gateway data; nothing is synthesized
 * client-side (the old fabricated latencyMs column is gone — the gateway
 * cannot know per-row wall-clock latency after the fact, so the console does
 * not display one).
 */
export interface StreamEvent {
  /** Stable per-row key: `${worm_sequence}:${correlation_id}`. */
  id: string;
  /** Epoch milliseconds (rounded from the WORM record's nanosecond stamp). */
  ts: number;
  /** The REAL nanosecond timestamp from the WORM record. */
  timestampNs: number;
  tenant: string;
  alias: string;
  transport: TransportClass;
  decision: Decision;
  reason: DenyReason | null;
  correlationId: string;
  /** The principal that made the call (vendor-prefixed agent id), when known. */
  agent: string | null;
  /** The provider dialect the request arrived in (openai_tool_call, mcp_jsonrpc, …). */
  sourceFormat: string | null;
  /** The committed transaction ref (allow decisions only). */
  transactionRef: string | null;
  riskTier: RiskTier | null;
  classification: string | null;
  /**
   * The gateway-internal WORM event id — keys GET /v1/audit/proof/{event_id}
   * for a per-row inclusion proof. Null when the connected gateway predates
   * the projection extension.
   */
  eventId: string | null;
  /** The REAL per-row WORM sequence (monotonic ledger height at emit time). */
  wormSequence: number;
}

/**
 * Point-in-time metrics snapshot. Fleet-wide numbers come from the gateway's
 * OWN Prometheus exposition (GET /metrics — covers every agent's traffic, not
 * just this console's calls); console-side numbers are clearly separated.
 * `null` always means "no signal" (offline, series absent, or nothing
 * observed yet) and must render as an honest "—", never as 0.
 */
export interface MetricsSnapshot {
  /** Cumulative authorize decisions since gateway start (allow+deny+staged). */
  decisionsTotal: number | null;
  allowTotal: number | null;
  denyTotal: number | null;
  stagedTotal: number | null;
  /** REAL gateway-side latency quantiles (ms) from the mcpip_authorize_latency_seconds histogram. */
  gatewayP50Ms: number | null;
  gatewayP95Ms: number | null;
  /** Decisions/sec from successive scrape deltas (0 when idle; null before two scrapes). */
  decisionsPerSec: number | null;
  /** Monotonic WORM height (mcpip_worm_sequence gauge; feed max as fallback). */
  wormSequence: number | null;
  /** Last sealed audit epoch (mcpip_worm_epoch gauge). */
  wormEpoch: number | null;
  /** p50 (ms) of THIS console's own /v1/authorize probes only — never fleet data. */
  consoleProbeP50Ms: number | null;
}

/* ---------------------------------------------------------------------------
   Community extensions (author-your-own SKILLS + GATES). A Contributor (ANY
   authenticated principal, NO capability) submits an `mcpip-extension/1`
   manifest for review; a Reviewer holding the DISTINCT CAP_CATALOG_REVIEWER
   reads the pending queue and approves/rejects it. The SAME submit/review/WORM/
   hash-pin flow serves both kinds, routed by `kind`. GATES (Phase 2) ship as
   schema + a deny-only seam only; the CEL parse/evaluate runtime is DEFERRED, so
   a gate is stored PENDING but can NEVER be approved/enforced until an engine is
   registered (docs/build/EXTENSIBILITY.md §8) — the projection's `approvable` says so
   honestly. These shapes mirror `services/extension_manifest.py` +
   `app/main.py` verbatim (and the @mcpip/sdk types) so a real submit/review
   round-trips without reshaping.
--------------------------------------------------------------------------- */

/** The two extension kinds the submit/review flow routes on (manifest `kind`). */
export type ExtensionKind = 'skill' | 'gate';

/**
 * A community-SKILL manifest (`mcpip-extension/1`, `kind: 'skill'`) a Contributor
 * authors and submits. Declarative data only: a NEW opaque `alias` onto a
 * `cloud_rest` `target` — it can never repoint an existing alias or reach a
 * privileged transport. The `sha256` is a SELF-PIN the author computes over the
 * canonical manifest bytes (sort_keys/compact, dropping `sha256` + the reserved
 * `signature`), DISTINCT from the payload-lock canonical_json; the gateway
 * re-derives and compares it fail-closed and pins it at approval for rug-pull
 * defense (`core.integrity.canonical_manifest_bytes`).
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
 * DENY-ONLY declarative CEL predicate, NOT an alias→target and never a transport.
 * Validated as pure DATA only; the CEL runtime is DEFERRED, so a gate can be
 * SUBMITTED + stored but NOT approved/enforced until an engine is registered.
 * `referenced_context_fields` must be a subset of the fixed topology-free
 * whitelist { alias, risk_tier, transport_class, classification } — never
 * `target`, a secret, or topology. `max_cost` is bounded 1..MAX_GATE_COST.
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
  /** Subset of the fixed GATE_CONTEXT_FIELDS whitelist. */
  referenced_context_fields: string[];
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
 * an alias→target. `approvable` is the honest reviewer signal: gate approval is
 * BLOCKED until the deferred CEL prover/engine is registered, so it is `false` on
 * a gateway without one and an approve would be an opaque deny.
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
