/* ---------------------------------------------------------------------------
   Typed MCPIP gateway client — every function here talks to a REAL gateway
   endpoint (`uvicorn app.main:app`, default :8080 via VITE_API_BASE, or the
   same-origin Vite proxy when base is ''). There is no mock layer: each helper
   fails soft (null / false / empty) so callers can render an honest
   empty/unreachable state instead of fabricated data.
--------------------------------------------------------------------------- */

import type {
  AuthorizeOutcome,
  AuthorizeRequest,
  CatalogItem,
  ErrorResponse,
  ExecutionReceipt,
  ExtensionManifest,
  ForensicRecord,
  InclusionProof,
  PendingExtension,
  StagedChallenge,
} from './types';

export const API_BASE: string =
  (import.meta.env.VITE_API_BASE ?? 'http://localhost:8080').replace(/\/+$/, '');

const CORRELATION_HEADER = 'X-MCPIP-Correlation-Id';

export interface GatewayClientOptions {
  /** Bearer JWT for the agent identity. Sent as Authorization: Bearer <jwt>. */
  token?: string;
  /** AbortSignal for cancellation. */
  signal?: AbortSignal;
  /**
   * Override the gateway base URL for this call. `''` means same-origin
   * (the Vite dev/preview proxy forwards /healthz, /readyz and /v1 to the
   * gateway, sidestepping CORS). Defaults to API_BASE.
   */
  base?: string;
}

function baseOf(opts: GatewayClientOptions): string {
  return opts.base ?? API_BASE;
}

function authHeaders(token: string | undefined): Record<string, string> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

/**
 * POST /v1/authorize — the single authorization choke point.
 *
 * Maps the gateway's HTTP status to the AuthorizeOutcome union:
 *   200 → executed (ExecutionReceipt)
 *   202 → staged   (StagedChallenge)
 *   403/422/500 → denied (opaque ErrorResponse; wormReason stays unknown to us,
 *                 exactly as the agent boundary experiences it).
 */
export async function authorize(
  request: AuthorizeRequest,
  opts: GatewayClientOptions = {},
): Promise<AuthorizeOutcome> {
  const init: RequestInit = {
    method: 'POST',
    headers: authHeaders(opts.token),
    body: JSON.stringify(request),
  };
  if (opts.signal) {
    init.signal = opts.signal;
  }

  const res = await fetch(`${baseOf(opts)}/v1/authorize`, init);

  if (res.status === 200) {
    const receipt = (await res.json()) as ExecutionReceipt;
    return { kind: 'executed', receipt };
  }
  if (res.status === 202) {
    const challenge = (await res.json()) as StagedChallenge;
    return { kind: 'staged', challenge };
  }

  // Any non-2xx: opaque deny. The concrete deny_reason lives only in the WORM
  // log — the client legitimately cannot know it, so we surface 'internal'.
  const error = (await res.json().catch(() => ({
    error: 'MCPIP: request denied by policy.',
    correlation_id: res.headers.get(CORRELATION_HEADER) ?? 'unknown',
  }))) as ErrorResponse;
  return { kind: 'denied', error, wormReason: 'internal' };
}

/** GET /readyz — liveness of the gateway's Redis dependency. */
export async function readyz(
  opts: GatewayClientOptions = {},
): Promise<{ ready: boolean; redis: 'up' | 'down' }> {
  try {
    const init: RequestInit = { method: 'GET' };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/readyz`, init);
    const body = (await res.json()) as { redis?: string };
    return { ready: res.status === 200, redis: body.redis === 'up' ? 'up' : 'down' };
  } catch {
    return { ready: false, redis: 'down' };
  }
}

/** GET /healthz response shape. */
export interface HealthzInfo {
  status: string;
  glyph?: string;
  loop?: string;
  version?: string;
}

/**
 * GET /healthz — event-loop liveness probe. Fails soft: returns null when the
 * gateway is unreachable or the response is not the expected JSON shape (e.g.
 * an SPA fallback page answered instead of the gateway).
 */
export async function healthz(
  opts: GatewayClientOptions = {},
): Promise<HealthzInfo | null> {
  try {
    const init: RequestInit = { method: 'GET' };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/healthz`, init);
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as { status?: unknown; glyph?: unknown; loop?: unknown; version?: unknown };
    if (typeof body.status !== 'string') {
      return null;
    }
    const info: HealthzInfo = { status: body.status };
    if (typeof body.glyph === 'string') {
      info.glyph = body.glyph;
    }
    if (typeof body.loop === 'string') {
      info.loop = body.loop;
    }
    if (typeof body.version === 'string') {
      info.version = body.version;
    }
    return info;
  } catch {
    return null;
  }
}

function isCatalogItem(value: unknown): value is CatalogItem {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const item = value as Record<string, unknown>;
  return (
    typeof item.alias === 'string' &&
    typeof item.risk_tier === 'string' &&
    typeof item.transport_class === 'string'
  );
}

/**
 * GET /v1/catalog — the tenant-scoped, metadata-only skill catalog (targets
 * never cross this boundary).
 *
 * Distinguishes FAILURE from a genuinely-empty view: returns `null` on any
 * network error, non-2xx, or malformed body (so callers can fall back to a mock),
 * and a (possibly empty) `CatalogItem[]` only when the gateway actually answered
 * with a catalog array. An empty array therefore means "this identity enumerates
 * nothing", never "the fetch failed".
 */
export async function catalog(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<CatalogItem[] | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/v1/catalog`, init);
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as { catalog?: unknown };
    if (!Array.isArray(body.catalog)) {
      return null;
    }
    return body.catalog.filter(isCatalogItem);
  } catch {
    return null;
  }
}

/** GET /v1/audit/verify response shape. */
export interface AuditVerifyResult {
  intact: boolean;
  first_bad_epoch: number | null;
}

/**
 * GET /v1/audit/verify — verify the WORM epoch chain end-to-end. Fails soft:
 * returns null when unreachable or malformed.
 */
export async function auditVerify(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<AuditVerifyResult | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/v1/audit/verify`, init);
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as { intact?: unknown; first_bad_epoch?: unknown };
    if (typeof body.intact !== 'boolean') {
      return null;
    }
    return {
      intact: body.intact,
      first_bad_epoch: typeof body.first_bad_epoch === 'number' ? body.first_bad_epoch : null,
    };
  } catch {
    return null;
  }
}

/**
 * GET /v1/audit/attestation response — a portable, signed snapshot of the CURRENT
 * audit state (app/main.py audit_attestation → audit/worm_logger.WormAttestation).
 * Every signed field was Ed25519-signed by the WORM epoch key at epoch close / anchor
 * append; this read mints no key and signs nothing new. The epoch fields are null
 * BEFORE the first epoch has sealed — an honest empty state, never a fabricated header.
 * No hidden target, payload, or secret ever appears here.
 */
export interface AuditAttestation {
  /** Latest SEALED epoch header — null until the first epoch closes. */
  epoch: number | null;
  end_seq: number | null;
  merkle_root: string | null;
  epoch_hash: string | null;
  signature: string | null;
  /** Public fingerprint of the WORM Ed25519 epoch key (always present). */
  signing_key_id: string;
  /** Fresh verify_chain verdict over the whole signed chain. */
  intact: boolean;
  first_bad_epoch: number | null;
  /** Out-of-tamper-domain anchor low-watermark (null when unconfigured / unwitnessed). */
  anchor_epoch: number | null;
  anchor_epoch_hash: string | null;
}

/**
 * GET /v1/audit/attestation — the portable, signed attestation of the current audit
 * state. CAP_DIRECTORY_ADMIN-gated (app.main enforces _require_directory_admin: the
 * bundle commits to the GLOBAL WORM head, not one tenant's slice), and — unlike the
 * sandbox-only /v1/audit/verify and /v1/audit/proof — available in production, because a
 * portable, externally-checkable attestation is a production artifact. Fails soft: returns
 * null when unreachable, unsupported (a pre-endpoint gateway), or malformed.
 */
export async function auditAttestation(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<AuditAttestation | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/v1/audit/attestation`, init);
    if (!res.ok) {
      return null;
    }
    const b = (await res.json()) as Record<string, unknown>;
    // signing_key_id + intact are the always-present fields; the epoch header is nullable.
    if (typeof b.signing_key_id !== 'string' || typeof b.intact !== 'boolean') {
      return null;
    }
    const num = (v: unknown): number | null => (typeof v === 'number' ? v : null);
    const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
    return {
      epoch: num(b.epoch),
      end_seq: num(b.end_seq),
      merkle_root: str(b.merkle_root),
      epoch_hash: str(b.epoch_hash),
      signature: str(b.signature),
      signing_key_id: b.signing_key_id,
      intact: b.intact,
      first_bad_epoch: num(b.first_bad_epoch),
      anchor_epoch: num(b.anchor_epoch),
      anchor_epoch_hash: str(b.anchor_epoch_hash),
    };
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------------------------
   Compliance evidence (X1) — the portable bundle assembled from REAL running
   gateway state (services/compliance_evidence.build_evidence_bundle). EVIDENCE,
   never a CERTIFICATION: every framework block carries a `certification_note`,
   the bundle a `disclaimer`, and each clause is phrased "provides evidence for".
   CAP_DIRECTORY_ADMIN-gated, read-only. Fails soft.
--------------------------------------------------------------------------- */

/** One control-clause → MCPIP-mechanism evidence row. `coverage` is always 'provides-evidence-for'. */
export interface ComplianceControlClause {
  clause: string;
  mechanism: string;
  mcpip_evidence: string;
  code_pointer: string;
  coverage: string;
}

/** One regulatory-framework block. `certification_note` restates the certification is external. */
export interface ComplianceFramework {
  framework: string;
  reference: string;
  certification_note: string;
  clauses: ComplianceControlClause[];
}

/**
 * GET /v1/admin/compliance/evidence — a portable COMPLIANCE-EVIDENCE bundle. It is
 * EVIDENCE, NOT a CERTIFICATION: `disclaimer` (and each framework's
 * `certification_note`) restates the bundle asserts no SOC 2 report, FedRAMP
 * authorization, ISO/DORA/EU-AI-Act certificate, named customer, or auditor
 * sign-off. `sealed` is honest — before the first epoch seals the attestation
 * header fields are null and `empty_state_note` explains it (never a fabricated
 * header). No hidden target, payload, or secret ever appears.
 */
export interface ComplianceEvidence {
  generated_at: string;
  gateway_version: string;
  release_provenance: ReleaseProvenance;
  sealed: boolean;
  attestation: AuditAttestation;
  control_mapping: ComplianceFramework[];
  disclaimer: string;
  empty_state_note?: string;
}

/** Narrow one raw framework block (drops off-shape rows). */
function asComplianceFramework(value: unknown): ComplianceFramework | null {
  if (typeof value !== 'object' || value === null) return null;
  const f = value as Record<string, unknown>;
  if (typeof f.framework !== 'string') return null;
  const str = (v: unknown): string => (typeof v === 'string' ? v : '');
  const clauses = Array.isArray(f.clauses)
    ? f.clauses
        .filter((c): c is Record<string, unknown> => typeof c === 'object' && c !== null)
        .map((c) => ({
          clause: str(c.clause),
          mechanism: str(c.mechanism),
          mcpip_evidence: str(c.mcpip_evidence),
          code_pointer: str(c.code_pointer),
          coverage: str(c.coverage),
        }))
    : [];
  return {
    framework: f.framework,
    reference: str(f.reference),
    certification_note: str(f.certification_note),
    clauses,
  };
}

/**
 * GET /v1/admin/compliance/evidence — export the portable compliance-evidence
 * bundle for the caller's tenant. CAP_DIRECTORY_ADMIN-gated (it commits to the
 * GLOBAL WORM head). Fails soft: returns null on any network error, non-2xx
 * (opaque 403), a pre-endpoint gateway (404), or a malformed body — the panel
 * then shows "unavailable", distinct from an answered bundle. Never fabricates a
 * bundle or a certification.
 */
export async function complianceEvidence(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<ComplianceEvidence | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/compliance/evidence`, init);
    if (!res.ok) return null;
    const b = (await res.json()) as Record<string, unknown>;
    const att = b.attestation;
    if (
      typeof b.disclaimer !== 'string' ||
      typeof att !== 'object' ||
      att === null ||
      typeof (att as { signing_key_id?: unknown }).signing_key_id !== 'string'
    ) {
      return null;
    }
    const a = att as Record<string, unknown>;
    const num = (v: unknown): number | null => (typeof v === 'number' ? v : null);
    const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
    const rel = (b.release_provenance ?? {}) as Record<string, unknown>;
    const out: ComplianceEvidence = {
      generated_at: typeof b.generated_at === 'string' ? b.generated_at : '',
      gateway_version: typeof b.gateway_version === 'string' ? b.gateway_version : '',
      release_provenance: {
        version: str(rel.version),
        signing_key_id: str(rel.signing_key_id),
        verified: typeof rel.verified === 'boolean' ? rel.verified : null,
      },
      sealed: b.sealed === true,
      attestation: {
        epoch: num(a.epoch),
        end_seq: num(a.end_seq),
        merkle_root: str(a.merkle_root),
        epoch_hash: str(a.epoch_hash),
        signature: str(a.signature),
        signing_key_id: a.signing_key_id as string,
        intact: a.intact === true,
        first_bad_epoch: num(a.first_bad_epoch),
        anchor_epoch: num(a.anchor_epoch),
        anchor_epoch_hash: str(a.anchor_epoch_hash),
      },
      control_mapping: Array.isArray(b.control_mapping)
        ? b.control_mapping
            .map(asComplianceFramework)
            .filter((f): f is ComplianceFramework => f !== null)
        : [],
      disclaimer: b.disclaimer,
    };
    if (typeof b.empty_state_note === 'string') out.empty_state_note = b.empty_state_note;
    return out;
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------------------------
   Registry governance (X3) — the verified-publisher allow-list. A reviewer-PINNED
   set of publisher NAMESPACES (reverse-DNS prefixes) a registry-sourced skill must
   belong to before approval / boot re-verify. CAP_CATALOG_REVIEWER-gated; PUT is
   WORM-logged emit-before-mutate. Only namespaces — never a target or identity.
--------------------------------------------------------------------------- */

/** The schema tag every verified-publisher allow-list document carries. */
export const PUBLISHERS_SCHEMA = 'mcpip-registry-publishers/1' as const;




// ---------------------------------------------------------------------------
// Operator/team USER MANAGEMENT — the admin-managed, email-keyed console roster.
// CAP_DIRECTORY_ADMIN. The `role` is a MANAGEMENT label (authorizes nothing).
// ---------------------------------------------------------------------------

/** A management role LABEL — never an authorization gate. */
export type OperatorRole = 'admin' | 'member' | 'viewer';
export type OperatorStatus = 'invited' | 'active' | 'disabled';

/** One roster member (the admin-facing projection — no secret token). */
export interface OperatorUser {
  email: string;
  role: OperatorRole;
  status: OperatorStatus;
  invited_by: string;
  invited_at: string;
  updated_at: string;
}

/** A cursor page of the roster. `next_cursor === '0'` means the scan is complete. */
export interface OperatorUserPage {
  users: OperatorUser[];
  next_cursor: string;
  count: number;
  cap: number;
}

/** The result of an invite — the record plus the ONE-TIME reference token to send. */
export interface OperatorInviteResult {
  user: OperatorUser;
  invite_token: string;
}

function coerceUser(raw: unknown): OperatorUser | null {
  if (typeof raw !== 'object' || raw === null) return null;
  const r = raw as Record<string, unknown>;
  if (typeof r.email !== 'string') return null;
  return {
    email: r.email,
    role: (r.role as OperatorRole) ?? 'member',
    status: (r.status as OperatorStatus) ?? 'invited',
    invited_by: typeof r.invited_by === 'string' ? r.invited_by : '',
    invited_at: typeof r.invited_at === 'string' ? r.invited_at : '',
    updated_at: typeof r.updated_at === 'string' ? r.updated_at : '',
  };
}

/**
 * GET /v1/admin/users — a cursor page of the operator roster (CAP_DIRECTORY_ADMIN).
 * Fails soft: null on any network error, opaque 403, 404 (pre-endpoint gateway), or
 * malformed body. An empty roster is `{ users: [], next_cursor: '0', ... }`, never null.
 */
export async function operatorUsers(
  token: string,
  cursor = '0',
  limit = 200,
  opts: GatewayClientOptions = {},
): Promise<OperatorUserPage | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const q = `?cursor=${encodeURIComponent(cursor)}&limit=${encodeURIComponent(String(limit))}`;
    const res = await fetch(`${baseOf(opts)}/v1/admin/users${q}`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as Record<string, unknown>;
    const users = Array.isArray(body.users)
      ? body.users.map(coerceUser).filter((u): u is OperatorUser => u !== null)
      : [];
    return {
      users,
      next_cursor: typeof body.next_cursor === 'string' ? body.next_cursor : '0',
      count: typeof body.count === 'number' ? body.count : users.length,
      cap: typeof body.cap === 'number' ? body.cap : 0,
    };
  } catch {
    return null;
  }
}

/**
 * POST /v1/admin/users/invite — invite a NEW member by email + role. Returns the record
 * and the one-time invite reference token on 201; null on any failure (an existing email
 * is an opaque 403 conflict). Never throws.
 */
export async function inviteOperatorUser(
  token: string,
  email: string,
  role: OperatorRole,
  opts: GatewayClientOptions = {},
): Promise<OperatorInviteResult | null> {
  try {
    const init: RequestInit = {
      method: 'POST',
      headers: authHeaders(token),
      body: JSON.stringify({ email, role }),
    };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/users/invite`, init);
    if (res.status !== 201) return null;
    const body = (await res.json()) as Record<string, unknown>;
    const user = coerceUser(body.user);
    if (user === null || typeof body.invite_token !== 'string') return null;
    return { user, invite_token: body.invite_token };
  } catch {
    return null;
  }
}

/**
 * PUT /v1/admin/users/{email} — update a member's role and/or status (enable/disable).
 * Returns the updated record on 200, null otherwise. Never throws.
 */
export async function updateOperatorUser(
  token: string,
  email: string,
  patch: { role?: OperatorRole; status?: OperatorStatus },
  opts: GatewayClientOptions = {},
): Promise<OperatorUser | null> {
  try {
    const init: RequestInit = {
      method: 'PUT',
      headers: authHeaders(token),
      body: JSON.stringify(patch),
    };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/users/${encodeURIComponent(email)}`,
      init,
    );
    if (res.status !== 200) return null;
    const body = (await res.json()) as Record<string, unknown>;
    return coerceUser(body.user);
  } catch {
    return null;
  }
}

/**
 * DELETE /v1/admin/users/{email} — remove a member from the roster. Returns true on a
 * 200 (whether or not a record existed). Never throws.
 */
export async function removeOperatorUser(
  token: string,
  email: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = { method: 'DELETE', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/users/${encodeURIComponent(email)}`,
      init,
    );
    return res.status === 200;
  } catch {
    return false;
  }
}

/**
 * Claims accepted by the sandbox dev-token minter (mirrors app.main._DevTokenRequest).
 * All fields optional — an empty body mints the default sandbox identity. `compartment`
 * and `capabilities` are UUID strings that project onto the JWT's optional claims, so a
 * caller can mint the exact per-team / per-capability identities the compartment
 * separation demo needs (a project-falcon agent, a grant-issuing officer, …).
 */
export type DevTokenClaims = Partial<{
  tenant_id: string;
  agent_id: string;
  role: string;
  compartment: string;
  capabilities: string[];
}>;

/** Result of a cryptographic-proof verification attempt for one ledger event. */
export interface ProofResult {
  /** 'verified' — a signed O(log n) inclusion proof was returned for the event. */
  status: 'verified' | 'unsealed' | 'unavailable';
  proof: InclusionProof | null;
  /** Human-readable detail (e.g. "sealed in epoch 4, index 12"). */
  detail: string;
}

/**
 * GET /v1/audit/proof/{event_id} — SANDBOX ONLY, CAP_DIRECTORY_ADMIN-gated and
 * tenant-scoped. Fetch the O(log n) Merkle inclusion proof binding one buffered
 * event to a signed epoch root. 404 means the event is unknown, not yet sealed,
 * OR belongs to another tenant (indistinguishable — no cross-tenant existence
 * oracle). Fails soft.
 */
export async function auditProof(
  token: string,
  eventId: string,
  opts: GatewayClientOptions = {},
): Promise<ProofResult> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(
      `${baseOf(opts)}/v1/audit/proof/${encodeURIComponent(eventId)}`,
      init,
    );
    if (res.status === 404) {
      return { status: 'unsealed', proof: null, detail: 'event not yet sealed into a signed epoch' };
    }
    if (!res.ok) {
      return { status: 'unavailable', proof: null, detail: `proof endpoint returned ${res.status}` };
    }
    const proof = (await res.json()) as InclusionProof;
    return {
      status: 'verified',
      proof,
      detail: `sealed in epoch ${proof.epoch}, leaf index ${proof.index} · ${proof.proof.length}-hop path to a signed root`,
    };
  } catch {
    return { status: 'unavailable', proof: null, detail: 'proof endpoint unreachable' };
  }
}

/* ---------------------------------------------------------------------------
   Standards interop — OAuth 2.1 Resource-Server metadata (N2) + the
   OpenID-AuthZEN / COAZ decision surface (N1). Both talk to REAL gateway
   endpoints; the well-known doc is PUBLIC (no token) so the console can advertise
   the interop even before an operator credential exists.
--------------------------------------------------------------------------- */

/**
 * GET /.well-known/oauth-protected-resource — the RFC 9728 OAuth 2.1 Protected
 * Resource Metadata document (auth/oauth_metadata.build_protected_resource_metadata).
 * The two non-secret discovery identifiers — MCPIP's own `resource` (the RFC 8707
 * audience) and the `authorization_servers` that issue tokens for it — plus the
 * accepted bearer method. NO scopes (MCPIP has none), NO secret, NO alias→target
 * topology.
 */
export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: string[];
}

/**
 * GET /.well-known/oauth-protected-resource — PUBLIC and unauthenticated (no
 * token, never shed, in sandbox AND production). Confirms to an operator that the
 * gateway advertises OAuth 2.1 Resource-Server interop and names the trusted
 * authorization server(s). Fails soft: returns null when unreachable, unsupported
 * (a pre-endpoint gateway), or malformed — the console then shows "unavailable".
 */
export async function protectedResourceMetadata(
  opts: GatewayClientOptions = {},
): Promise<ProtectedResourceMetadata | null> {
  try {
    const init: RequestInit = { method: 'GET' };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/.well-known/oauth-protected-resource`, init);
    if (!res.ok) return null;
    const b = (await res.json()) as Record<string, unknown>;
    if (typeof b.resource !== 'string') return null;
    const strArray = (v: unknown): string[] =>
      Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : [];
    return {
      resource: b.resource,
      authorization_servers: strArray(b.authorization_servers),
      bearer_methods_supported: strArray(b.bearer_methods_supported),
    };
  } catch {
    return null;
  }
}

/**
 * The gateway's LIVE MCP step-up (MRT / SEP-2322) capability, read from the real
 * unauthenticated `initialize` reply. `advertised` is TRUE only when the actual response
 * carries `capabilities.experimental.mcpipStepUp` (with `mode` echoed when present) —
 * NEVER asserted from a static string, so a gateway predating the surface honestly reads
 * as not-advertised. `null` from the fetch means unreachable/unanswered (unknown).
 */
export interface McpStepUpCapability {
  advertised: boolean;
  mode: string | null;
}

/**
 * POST /v1/mcp `initialize` — the PUBLIC, unauthenticated MCP handshake (no token,
 * non-secret). Used to read the gateway's advertised step-up capability LIVE rather than
 * assert it. Fails soft: returns null when unreachable/unanswered/malformed (the console
 * then shows an honest "unavailable"); a well-formed reply WITHOUT the capability yields
 * `{ advertised: false }` — never a fabricated advertisement.
 */
export async function mcpStepUpCapability(
  opts: GatewayClientOptions = {},
): Promise<McpStepUpCapability | null> {
  try {
    const init: RequestInit = {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {},
      }),
    };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/mcp`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as Record<string, unknown>;
    const result = body.result as Record<string, unknown> | undefined;
    const caps = (result?.capabilities ?? {}) as Record<string, unknown>;
    const experimental = (caps.experimental ?? {}) as Record<string, unknown>;
    const stepUp = experimental.mcpipStepUp as Record<string, unknown> | undefined;
    if (stepUp && typeof stepUp === 'object') {
      return {
        advertised: true,
        mode: typeof stepUp.mode === 'string' ? stepUp.mode : null,
      };
    }
    return { advertised: false, mode: null };
  } catch {
    return null;
  }
}

/** One standards-shaped obligation on an AuthZEN permit (e.g. `mcpip.step_up.pin`). */
export interface AuthzenObligation {
  id: string;
  [k: string]: unknown;
}

/** POST /v1/authz/decision response — the AuthZEN decision + optional obligations. */
export interface AuthzenDecision {
  decision: boolean;
  obligations: AuthzenObligation[];
}


/** GET /v1/version — running release, signed provenance, and update posture. */
export interface ReleaseProvenance {
  version: string | null;
  signing_key_id: string | null;
  /** true/false when the release-root key verified the manifest; null = stated, not proven. */
  verified: boolean | null;
}

export interface VersionInfo {
  /** The gateway's running release (single-source VERSION file). */
  running: string;
  /** Newest APPROVED release from the signed update feed (== running when none configured). */
  latest: string;
  /** Server-side verdict: a signed feed advertised something strictly newer. */
  update_available: boolean;
  /** Entitlement channel (license tier), or "sandbox" when unlicensed. */
  channel: string;
  /** Always "redeploy" — MCPIP never auto-installs; an upgrade is a signed redeploy. */
  update_policy: string;
  release: ReleaseProvenance;
}

/**
 * GET /v1/version — the JWT-gated version/update surface. Fails soft: returns null
 * when unreachable, unauthorized, or malformed (the panel then shows "—").
 */
export async function versionInfo(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<VersionInfo | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/v1/version`, init);
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as Partial<VersionInfo> & { release?: Partial<ReleaseProvenance> };
    if (typeof body.running !== 'string') {
      return null;
    }
    const rel: Partial<ReleaseProvenance> = body.release ?? {};
    return {
      running: body.running,
      latest: typeof body.latest === 'string' ? body.latest : body.running,
      update_available: body.update_available === true,
      channel: typeof body.channel === 'string' ? body.channel : 'unknown',
      update_policy: typeof body.update_policy === 'string' ? body.update_policy : 'redeploy',
      release: {
        version: typeof rel.version === 'string' ? rel.version : null,
        signing_key_id: typeof rel.signing_key_id === 'string' ? rel.signing_key_id : null,
        verified: typeof rel.verified === 'boolean' ? rel.verified : null,
      },
    };
  } catch {
    return null;
  }
}

/** GET /v1/license — the boot-verified entitlement document (operator visibility). */
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
 * GET /v1/license — JWT-gated read-only view of the entitlement document. Fails
 * soft: returns null when unreachable/unauthorized. A sandbox gateway answers
 * ``{ licensed: false }`` (nothing to disclose), which is a valid, non-null result.
 */
export async function licenseInfo(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<LicenseInfo | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/v1/license`, init);
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as Partial<LicenseInfo>;
    if (typeof body.licensed !== 'boolean') {
      return null;
    }
    const info: LicenseInfo = { licensed: body.licensed };
    if (typeof body.license_id === 'string') info.license_id = body.license_id;
    if (typeof body.customer === 'string') info.customer = body.customer;
    if (typeof body.tier === 'string') info.tier = body.tier;
    if (typeof body.issued_at === 'string') info.issued_at = body.issued_at;
    if (typeof body.expires_at === 'string') info.expires_at = body.expires_at;
    if (Array.isArray(body.entitlements)) {
      info.entitlements = body.entitlements.filter((e): e is string => typeof e === 'string');
    }
    return info;
  } catch {
    return null;
  }
}

/** The tenant's coarse decision totals — the SAME closed enum as the gateway's
 * decision counters (allow / deny / staged). Honest zeros for a fresh tenant. */
export interface DecisionTotals {
  allow: number;
  deny: number;
  staged: number;
}

/** The HONEST opt-in vendor-telemetry posture from GET /v1/admin/stats. `status` is
 * one of "air-gap" (sandbox — structurally disabled, no identity minted, never phones
 * home), "enabled" (beacon live), or "disabled" (opt-out / unconfigured). NEVER a
 * fabricated "connected" state; no install-id/url/secret is ever exposed here. */
export interface TelemetryStatus {
  status: 'air-gap' | 'enabled' | 'disabled';
  last_sent: number | null;
  last_result: 'never' | 'ok' | 'error';
  interval_seconds?: number;
}

/** The HONEST posture of ONE opt-in / dark feature, from the `features` block of
 * GET /v1/admin/stats. Posture-only, never fabricated: `status` is the coarse machine
 * state, `reason` refines WHY a disabled state occurred, and `detail` is the human copy
 * (what it is + how to enable). NO url/key/path/target/tenant or per-id data is carried
 * — the posture is coarse and deployment-wide. */
export interface FeatureStatus {
  status: string;
  reason?: string;
  detail: string;
}

/** Forensic-capture posture. `status` is 'enabled' | 'absent' | 'disabled'; when
 * disabled, `reason` is 'production-default' | 'explicit-opt-out'; when absent it is
 * 'flag-on-no-key'. This is the PROACTIVE, deployment-wide signal that honestly
 * distinguishes off-vs-missing — the per-id GET /v1/admin/forensic/{corr} 404 stays
 * deliberately opaque and is NOT a posture oracle. */
export type ForensicFeatureStatus = FeatureStatus & {
  status: 'enabled' | 'absent' | 'disabled';
};

/** External-PDP consult posture. `status` is 'off' | 'staged' | 'enforcing'. No URL is
 * ever exposed — posture only. */
export type ExternalPdpFeatureStatus = FeatureStatus & {
  status: 'off' | 'staged' | 'enforcing';
};

/** The additive `features` block on GET /v1/admin/stats — honest disabled/why/how-to
 * states for the opt-in dark features. `telemetry` is NOT here (it stays a top-level
 * field, the reference model); MRT step-up is read live from `initialize`, not here. */
export interface FeaturesInfo {
  forensic_capture: ForensicFeatureStatus;
  external_pdp: ExternalPdpFeatureStatus;
}

/** GET /v1/admin/stats — the LOCAL live-stats read: the caller's OWN tenant's REAL
 * running numbers, served locally (no beacon, no vendor, no network). The client-side
 * "see the numbers live" surface. `governed_agent_identity_count` is a HyperLogLog
 * PFCOUNT cardinality (the agent_ids are never stored or exposed); NO
 * tenant/agent/alias/target ever crosses this boundary — only aggregate integers. */
export interface DeploymentStats {
  version: string;
  governed_agent_identity_count: number;
  decisions: DecisionTotals;
  license: LicenseInfo;
  telemetry: TelemetryStatus;
  /** Honest opt-in / dark-feature posture. OPTIONAL for back-compat: a gateway that
   * predates the block yields `undefined` (the console then shows an unknown posture). */
  features?: FeaturesInfo;
}

/** Normalize one raw `features.<name>` body to a FeatureStatus, honestly. A
 * non-object / missing status yields a neutral 'unknown' posture — NEVER a fabricated
 * enabled/connected state. */
function normalizeFeatureStatus(raw: unknown): FeatureStatus {
  const obj = (raw && typeof raw === 'object' ? raw : {}) as Partial<FeatureStatus>;
  const out: FeatureStatus = {
    status: typeof obj.status === 'string' ? obj.status : 'unknown',
    detail: typeof obj.detail === 'string' ? obj.detail : '',
  };
  if (typeof obj.reason === 'string') {
    out.reason = obj.reason;
  }
  return out;
}

/**
 * GET /v1/admin/stats — the local live deployment stats (CAP_DIRECTORY_ADMIN). Fails
 * SOFT: returns null when unreachable/unauthorized so the panel renders an honest
 * empty/connect state — it NEVER fabricates a client, number, license, or telemetry
 * activity. A fresh tenant yields honest zeros; an air-gapped/sandbox deployment
 * reports telemetry.status === "air-gap".
 */
export async function deploymentStats(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<DeploymentStats | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/v1/admin/stats`, init);
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as Partial<DeploymentStats>;
    if (typeof body.governed_agent_identity_count !== 'number') {
      return null;
    }
    const rawDec = (body.decisions ?? {}) as Partial<DecisionTotals>;
    const decisions: DecisionTotals = {
      allow: typeof rawDec.allow === 'number' ? rawDec.allow : 0,
      deny: typeof rawDec.deny === 'number' ? rawDec.deny : 0,
      staged: typeof rawDec.staged === 'number' ? rawDec.staged : 0,
    };
    const rawTel = (body.telemetry ?? {}) as Partial<TelemetryStatus>;
    const status: TelemetryStatus['status'] =
      rawTel.status === 'enabled' || rawTel.status === 'air-gap' ? rawTel.status : 'disabled';
    const telemetry: TelemetryStatus = {
      status,
      last_sent: typeof rawTel.last_sent === 'number' ? rawTel.last_sent : null,
      last_result:
        rawTel.last_result === 'ok' || rawTel.last_result === 'error'
          ? rawTel.last_result
          : 'never',
    };
    if (typeof rawTel.interval_seconds === 'number') {
      telemetry.interval_seconds = rawTel.interval_seconds;
    }
    const license: LicenseInfo =
      body.license && typeof body.license.licensed === 'boolean'
        ? body.license
        : { licensed: false };
    const result: DeploymentStats = {
      version: typeof body.version === 'string' ? body.version : '',
      governed_agent_identity_count: body.governed_agent_identity_count,
      decisions,
      license,
      telemetry,
    };
    // The features block is optional (back-compat). Only surface it when present —
    // an absent block honestly reads as "unknown posture", never a fabricated state.
    if (body.features && typeof body.features === 'object') {
      const rawFeat = body.features as Partial<FeaturesInfo>;
      result.features = {
        forensic_capture: normalizeFeatureStatus(
          rawFeat.forensic_capture,
        ) as ForensicFeatureStatus,
        external_pdp: normalizeFeatureStatus(
          rawFeat.external_pdp,
        ) as ExternalPdpFeatureStatus,
      };
    }
    return result;
  } catch {
    return null;
  }
}

/** A cloud IAM environment binding — role→compartment mapping. Holds NO cloud secret. */
export interface CloudEnvironment {
  env_id: string;
  provider: string;
  role: string;
  region: string;
  compartment: string | null;
  session_ttl: number;
  /** Optional REFERENCE to a vault entry the broker spends (never a value). null = host identity. */
  vault_secret_id?: string | null;
}

/** GET /v1/admin/cloud/environments — the caller's tenant's bindings. Requires admin. */
export async function listCloudEnvironments(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<CloudEnvironment[] | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/cloud/environments`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { environments?: unknown };
    return Array.isArray(body.environments) ? (body.environments as CloudEnvironment[]) : null;
  } catch {
    return null;
  }
}

/** PUT /v1/admin/cloud/environments — create/update one binding. Returns true on success. */
export async function putCloudEnvironment(
  token: string,
  env: CloudEnvironment,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = { method: 'PUT', headers: authHeaders(token), body: JSON.stringify(env) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/cloud/environments`, init);
    return res.status === 200;
  } catch {
    return false;
  }
}

/** POST /v1/admin/cloud/environments/{id}/delete — remove one binding. */
export async function deleteCloudEnvironment(
  token: string,
  envId: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = { method: 'POST', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/cloud/environments/${encodeURIComponent(envId)}/delete`, init);
    return res.status === 200;
  } catch {
    return false;
  }
}

/** Vault entry metadata — NEVER the value (the value is write-only, broker-read-only). */
export interface VaultSecret {
  secret_id: string;
  vendor: string;
  description: string;
  fingerprint: string;
  created_at: number;
  updated_at: number;
}

/** GET /v1/admin/vault/secrets — the tenant's stored broker credentials (METADATA only). */
export async function listVaultSecrets(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<{ enabled: boolean; secrets: VaultSecret[] } | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/vault/secrets`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { vault_enabled?: boolean; secrets?: unknown };
    return {
      enabled: body.vault_enabled === true,
      secrets: Array.isArray(body.secrets) ? (body.secrets as VaultSecret[]) : [],
    };
  } catch {
    return null;
  }
}

/** PUT /v1/admin/vault/secrets — store/rotate one broker credential. The value is sent once. */
export async function putVaultSecret(
  token: string,
  secret: { secret_id: string; vendor: string; description: string; material: Record<string, string> },
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = { method: 'PUT', headers: authHeaders(token), body: JSON.stringify(secret) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/vault/secrets`, init);
    return res.status === 200;
  } catch {
    return false;
  }
}

/** POST /v1/admin/vault/secrets/{id}/delete — remove one stored credential. */
export async function deleteVaultSecret(
  token: string,
  secretId: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = { method: 'POST', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/vault/secrets/${encodeURIComponent(secretId)}/delete`, init);
    return res.status === 200;
  } catch {
    return false;
  }
}

/** A single generated skill in a workspace plan (tenant-wide cloud_rest). */
export interface PlanSkill {
  alias: string;
  target: string;
  risk_tier: string;
  classification: string;
  /** Advisory display metadata carried through plan → apply into the overlay. */
  service?: string;
  access?: 'read' | 'write';
}

/** A reviewable workspace scaffold: org chart + a governed starter skill catalog. */
export interface WorkspacePlan {
  company: string;
  tenant: string;
  org_units: unknown[];
  skills: PlanSkill[];
}





/** GET /v1/admin/skills/disabled — alias names disabled in the caller's tenant. */
export async function listDisabledSkills(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<string[] | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/skills/disabled`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { disabled?: unknown };
    return Array.isArray(body.disabled) ? body.disabled.filter((a): a is string => typeof a === 'string') : null;
  } catch {
    return null;
  }
}

/** One operator-registered skill: creation timestamp plus the advisory permission-model
    display metadata (service label + read/write access) the gateway projects for it. */
export interface RegisteredSkill {
  alias: string;
  registered_at: string | null;
  service: string | null;
  access: 'read' | 'write' | null;
}

/**
 * GET /v1/admin/skills/registered — operator-registered (deregisterable) skills with
 * their creation timestamps and service/access display metadata. Reads the `entries`
 * field; falls back to the legacy `registered` names list for older gateways.
 */
export async function listRegisteredSkills(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<RegisteredSkill[] | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/skills/registered`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { registered?: unknown; entries?: unknown };
    if (Array.isArray(body.entries)) {
      return body.entries
        .filter((e): e is Record<string, unknown> & { alias: string } => !!e && typeof (e as { alias?: unknown }).alias === 'string')
        .map((e) => ({
          alias: e.alias,
          registered_at: typeof e.registered_at === 'string' ? e.registered_at : null,
          service: typeof e.service === 'string' ? e.service : null,
          access: e.access === 'read' || e.access === 'write' ? e.access : null,
        }));
    }
    return Array.isArray(body.registered)
      ? body.registered
          .filter((a): a is string => typeof a === 'string')
          .map((alias) => ({ alias, registered_at: null, service: null, access: null }))
      : null;
  } catch {
    return null;
  }
}

/** One operator-visible decision from the live feed — opaque, never the real target. */
export interface RecentDecision {
  correlation_id: string;
  agent_id: string | null;
  alias: string | null;
  decision: 'allow' | 'deny';
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
   * Gateway-internal WORM event id — keys GET /v1/audit/proof/{event_id} for a
   * per-row inclusion proof. Null when the connected gateway predates the
   * whitelist extension that added it (the projection is a strict whitelist in
   * audit/worm_logger.py recent_decisions).
   */
  event_id: string | null;
  /**
   * Session attribution: WHICH session of the agent made this call (a verified
   * JWT claim), and the delegation grant a narrowed call operated under. Null
   * for pre-session tokens and pre-extension gateways.
   */
  session_id: string | null;
  delegation_id: string | null;
}

/** One live delegation grant, as listed by GET /v1/admin/delegations. */
export interface DelegationGrantRow {
  delegation_id: string;
  parent_session_id: string;
  child_session_id: string;
  child_agent_id: string;
  capabilities: string[];
  compartment: string | null;
  expires_at: number;
  depth: number;
}

/**
 * GET /v1/admin/delegations — every LIVE attenuated grant for the admin's
 * tenant (CAP_DIRECTORY_ADMIN). Returns 'disabled' on 404 — the deployment has
 * delegation off, which the caller must render as its OWN state, never as an
 * error or an empty roster (an empty state that cannot name its cause is how
 * a correct gateway gets reported broken).
 */
export async function listDelegations(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<DelegationGrantRow[] | 'disabled' | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/delegations`, init);
    if (res.status === 404) return 'disabled';
    if (!res.ok) return null;
    const body = (await res.json()) as { delegations?: unknown };
    if (!Array.isArray(body.delegations)) return null;
    const rows: DelegationGrantRow[] = [];
    for (const raw of body.delegations) {
      if (typeof raw !== 'object' || raw === null) continue;
      const r = raw as Record<string, unknown>;
      if (
        typeof r.delegation_id !== 'string' ||
        typeof r.parent_session_id !== 'string' ||
        typeof r.child_session_id !== 'string' ||
        typeof r.child_agent_id !== 'string' ||
        typeof r.expires_at !== 'number' ||
        typeof r.depth !== 'number'
      ) {
        continue;
      }
      rows.push({
        delegation_id: r.delegation_id,
        parent_session_id: r.parent_session_id,
        child_session_id: r.child_session_id,
        child_agent_id: r.child_agent_id,
        capabilities: Array.isArray(r.capabilities)
          ? r.capabilities.filter((c): c is string => typeof c === 'string')
          : [],
        compartment: typeof r.compartment === 'string' ? r.compartment : null,
        expires_at: r.expires_at,
        depth: r.depth,
      });
    }
    return rows;
  } catch {
    return null;
  }
}

/** Normalize one raw feed row to the declared RecentDecision shape (or drop it). */
function asRecentDecision(value: unknown): RecentDecision | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const r = value as Record<string, unknown>;
  const decision = r.decision;
  if (
    typeof r.correlation_id !== 'string' ||
    (decision !== 'allow' && decision !== 'deny') ||
    typeof r.tenant_id !== 'string' ||
    typeof r.worm_sequence !== 'number' ||
    typeof r.timestamp_ns !== 'number'
  ) {
    return null;
  }
  const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
  return {
    correlation_id: r.correlation_id,
    agent_id: str(r.agent_id),
    alias: str(r.alias),
    decision,
    deny_reason: str(r.deny_reason),
    transport: str(r.transport),
    risk_tier: str(r.risk_tier),
    classification: str(r.classification),
    source_format: str(r.source_format),
    transaction_ref: str(r.transaction_ref),
    tenant_id: r.tenant_id,
    worm_sequence: r.worm_sequence,
    timestamp_ns: r.timestamp_ns,
    event_id: str(r.event_id),
    session_id: str(r.session_id),
    delegation_id: str(r.delegation_id),
  };
}

/**
 * GET /v1/admin/decisions/recent — the live decision stream for the caller's tenant
 * (real agent traffic included). CAP_DIRECTORY_ADMIN-gated; whitelist projection only.
 * Newest first; `limit` is clamped to the server's 1..200 range. Returns null on any
 * failure (never throws) — vs [] for a genuinely idle gateway.
 */
export async function recentDecisions(
  token: string,
  opts: GatewayClientOptions = {},
  limit = 50,
): Promise<RecentDecision[] | null> {
  try {
    const clamped = Math.min(200, Math.max(1, Math.floor(limit)));
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/decisions/recent?limit=${clamped}`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { decisions?: unknown };
    if (!Array.isArray(body.decisions)) return null;
    return body.decisions
      .map(asRecentDecision)
      .filter((row): row is RecentDecision => row !== null);
  } catch {
    return null;
  }
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
  | 'transaction_ref'
  | 'session_id';

/** Inputs to GET /v1/admin/decisions — the date-ranged, multi-filtered, paged history. */
export interface DecisionQuery {
  fromMs?: number;
  toMs?: number;
  cursor?: string;
  limit?: number;
  filters?: Partial<Record<DecisionFacet, string[]>>;
}

/** One page of GET /v1/admin/decisions (same whitelist projection as the live feed). */
export interface DecisionPage {
  decisions: RecentDecision[];
  next_cursor: string | null;
  scanned: number;
  exhausted: boolean;
  /**
   * Oldest decision still held, in epoch ms — null when the server does not
   * report one. With `window_precedes_retention` these exist so an empty page
   * cannot lie: without them a caller cannot tell "nothing happened in this
   * window" from "this window is older than anything I still hold", and for an
   * audit product those two answers are opposites.
   */
  retention_floor_ms: number | null;
  /** True when the requested window starts before `retention_floor_ms`. */
  window_precedes_retention: boolean;
}

/**
 * GET /v1/admin/decisions — the date-ranged, multi-filtered, cursor-paged decision
 * HISTORY (at scale) for the caller's tenant. CAP_DIRECTORY_ADMIN-gated; the SAME strict
 * whitelist projection as the live feed (no target/payload/secret). One page per call;
 * pass `next_cursor` back as `query.cursor` for the next page (null = window fully walked).
 * Returns null on any failure (never throws).
 */
export async function queryDecisions(
  token: string,
  opts: GatewayClientOptions = {},
  query: DecisionQuery = {},
): Promise<DecisionPage | null> {
  try {
    const params = new URLSearchParams();
    if (query.fromMs !== undefined) params.set('from_ms', String(Math.floor(query.fromMs)));
    if (query.toMs !== undefined) params.set('to_ms', String(Math.floor(query.toMs)));
    if (query.cursor) params.set('cursor', query.cursor);
    params.set('limit', String(Math.min(200, Math.max(1, Math.floor(query.limit ?? 100)))));
    for (const [facet, values] of Object.entries(query.filters ?? {})) {
      const joined = (values ?? []).filter(Boolean).join(',');
      if (joined) params.set(facet, joined);
    }
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/decisions?${params.toString()}`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as {
      decisions?: unknown;
      next_cursor?: unknown;
      scanned?: unknown;
      exhausted?: unknown;
      retention_floor_ms?: unknown;
      window_precedes_retention?: unknown;
    };
    if (!Array.isArray(body.decisions)) return null;
    return {
      decisions: body.decisions
        .map(asRecentDecision)
        .filter((row): row is RecentDecision => row !== null),
      next_cursor: typeof body.next_cursor === 'string' ? body.next_cursor : null,
      scanned: typeof body.scanned === 'number' ? body.scanned : 0,
      exhausted: body.exhausted === true,
      retention_floor_ms:
        typeof body.retention_floor_ms === 'number' ? body.retention_floor_ms : null,
      window_precedes_retention: body.window_precedes_retention === true,
    };
  } catch {
    return null;
  }
}

/**
 * The outcome of one forensic-reconstruction attempt for a correlation id.
 *
 *   'found'       — the gateway disclosed the redacted, reconstructed query.
 *   'absent'      — a 404: DELIBERATELY OPAQUE. Either forensic capture is off /
 *                   absent on this gateway (production default), or the capture
 *                   for this correlation id was never taken or has expired (TTL).
 *                   The gateway keeps these indistinguishable on purpose (no
 *                   exists-elsewhere oracle), so the console must not claim which.
 *   'denied'      — a 403 opaque MCPIPDenied: the presented token lacked
 *                   CAP_FORENSIC_READ (or was revoked/quarantined). Not expected
 *                   when the console minted a forensic credential, but surfaced
 *                   honestly rather than swallowed.
 *   'unavailable' — a transport error, a non-2xx other than 403/404, or a body
 *                   whose shape the console did not recognize.
 */
export type ForensicReadResult =
  | { status: 'found'; record: ForensicRecord }
  | { status: 'absent' }
  | { status: 'denied' }
  | { status: 'unavailable'; detail: string };

/** Normalize one raw forensic body under `forensic` to ForensicRecord (or drop it). */
function asForensicRecord(value: unknown): ForensicRecord | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const r = value as Record<string, unknown>;
  if (
    typeof r.correlation_id !== 'string' ||
    typeof r.tenant_id !== 'string' ||
    typeof r.alias !== 'string' ||
    typeof r.arguments !== 'object' ||
    r.arguments === null ||
    Array.isArray(r.arguments)
  ) {
    return null;
  }
  const str = (v: unknown, fallback = ''): string => (typeof v === 'string' ? v : fallback);
  return {
    correlation_id: r.correlation_id,
    tenant_id: r.tenant_id,
    agent_id: str(r.agent_id),
    role: str(r.role),
    issuer: str(r.issuer),
    alias: r.alias,
    arguments: r.arguments as Record<string, unknown>,
    source_format: str(r.source_format),
    decision: str(r.decision),
    deny_reason: typeof r.deny_reason === 'string' ? r.deny_reason : null,
    act_sub: typeof r.act_sub === 'string' ? r.act_sub : null,
    captured_at: typeof r.captured_at === 'number' ? r.captured_at : 0,
  };
}

/**
 * GET /v1/admin/forensic/{correlation_id} — reconstruct the REAL query an agent
 * sent (alias + normalized, secret-scrubbed arguments + non-secret identity
 * context) for one correlation id. This is the SOLE forensic-retrieval route and
 * an INVESTIGATOR surface: it requires a JWT carrying CAP_FORENSIC_READ (which no
 * agent token holds and which even CAP_DIRECTORY_ADMIN does not confer), it is
 * tenant-scoped from the verified JWT, and the gateway emits a WORM
 * `admin_action='forensic_read'` record BEFORE it discloses anything.
 *
 * Fails soft into an honest, non-error state:
 *   200 `{found:true, forensic:{…}}` → 'found'
 *   404 (feature off / unknown / expired — indistinguishable) → 'absent'
 *   403 (opaque MCPIPDenied: token lacked CAP_FORENSIC_READ) → 'denied'
 *   anything else / network error / bad shape → 'unavailable'
 * Never throws; the reconstructed payload is never fabricated.
 */
export async function forensicRead(
  token: string,
  correlationId: string,
  opts: GatewayClientOptions = {},
): Promise<ForensicReadResult> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/forensic/${encodeURIComponent(correlationId)}`,
      init,
    );
    if (res.status === 404) {
      return { status: 'absent' };
    }
    if (res.status === 403) {
      return { status: 'denied' };
    }
    if (!res.ok) {
      return { status: 'unavailable', detail: `forensic endpoint returned ${res.status}` };
    }
    const body = (await res.json()) as { found?: unknown; forensic?: unknown };
    if (body.found !== true) {
      // A 200 that is not an affirmative hit is treated as an honest miss.
      return { status: 'absent' };
    }
    const record = asForensicRecord(body.forensic);
    if (record === null) {
      return { status: 'unavailable', detail: 'forensic record shape was not recognized' };
    }
    return { status: 'found', record };
  } catch {
    return { status: 'unavailable', detail: 'forensic endpoint unreachable' };
  }
}

/** POST /v1/admin/skills/{alias}/disable|enable — the skill kill-switch. */
export async function setSkillDisabled(
  token: string,
  alias: string,
  disabled: boolean,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const verb = disabled ? 'disable' : 'enable';
    const init: RequestInit = { method: 'POST', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/skills/${encodeURIComponent(alias)}/${verb}`, init);
    return res.status === 200;
  } catch {
    return false;
  }
}

/** Fields for registering a NEW operator skill (a new alias→target). */
export interface RegisterSkillBody {
  alias: string;
  target: string;
  /** 'auto' (no step-up) or 'pin_required' (payload-bound PIN). Default 'auto'. */
  risk_tier?: 'auto' | 'pin_required';
  /** 'unclassified' or 'restricted' (operator overlay cannot mint 'classified'). */
  classification?: 'unclassified' | 'restricted';
  /** Human service label for the permission table (advisory display metadata). */
  service?: string;
  /** Structured access level ('read'/'write') — display metadata, never enforcement. */
  access?: 'read' | 'write';
}

/** Outcome of a skill registration — the gateway's concrete 409 is preserved. */
export type RegisterSkillResult =
  | { ok: true }
  | {
      ok: false;
      error: 'alias_exists' | 'target_posture_conflict' | 'denied' | 'unreachable';
      detail: string | null;
      /** Named only when the conflicting alias is tenant-wide (never a compartmented one). */
      conflictingAlias: string | null;
    };

/**
 * POST /v1/admin/skills/register — register a NEW skill for the caller's tenant.
 * ADDITIVE ONLY: opaque 403 if the alias already resolves (config or a prior overlay),
 * is malformed, or risk/classification is out of range. cloud_rest transport only.
 * Requires CAP_DIRECTORY_ADMIN. Returns true on 200. Never throws.
 */
export async function registerSkill(
  token: string,
  body: RegisterSkillBody,
  opts: GatewayClientOptions = {},
): Promise<RegisterSkillResult> {
  try {
    const init: RequestInit = {
      method: 'POST',
      headers: authHeaders(token),
      body: JSON.stringify(body),
    };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/skills/register`, init);
    if (res.status === 200) return { ok: true };
    // The gateway answers registration conflicts with a CONCRETE, non-opaque 409
    // on purpose — its own comment: "an operator who cannot tell 'already
    // registered' from 'refused' learns to ignore the refusal". Surfacing that
    // body is the whole point; collapsing it to a boolean threw it away.
    if (res.status === 409) {
      try {
        const b = (await res.json()) as Record<string, unknown>;
        const kind = b.error === 'target_posture_conflict' ? 'target_posture_conflict' : 'alias_exists';
        return {
          ok: false,
          error: kind,
          detail: typeof b.detail === 'string' ? b.detail : null,
          conflictingAlias: typeof b.conflicting_alias === 'string' ? b.conflicting_alias : null,
        };
      } catch {
        return { ok: false, error: 'alias_exists', detail: null, conflictingAlias: null };
      }
    }
    return { ok: false, error: 'denied', detail: null, conflictingAlias: null };
  } catch {
    return { ok: false, error: 'unreachable', detail: null, conflictingAlias: null };
  }
}

/**
 * POST /v1/admin/skills/{alias}/deregister — remove an OPERATOR-registered skill.
 * Config aliases are never removable (a request for one is a no-op success with
 * removed=false). Requires CAP_DIRECTORY_ADMIN. Returns { ok, removed }: ok reflects
 * the 200, removed reflects whether an overlay row was actually dropped. Never throws.
 */
export async function deregisterSkill(
  token: string,
  alias: string,
  opts: GatewayClientOptions = {},
): Promise<{ ok: boolean; removed: boolean }> {
  try {
    const init: RequestInit = { method: 'POST', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/skills/${encodeURIComponent(alias)}/deregister`,
      init,
    );
    if (res.status !== 200) return { ok: false, removed: false };
    const body = (await res.json().catch(() => ({}))) as { removed?: unknown };
    return { ok: true, removed: body.removed === true };
  } catch {
    return { ok: false, removed: false };
  }
}

/** The operator directory document (org chart + RBAC) — non-authoritative metadata. */
export interface DirectoryDocument {
  schema: 'mcpip-directory/1';
  org_units: unknown[];
  rbac?: Record<string, string[]>;
}

/**
 * The three distinct answers a directory read can give. 'absent' means the
 * gateway ANSWERED and holds no document (a real, saveable state); 'read-failed'
 * means the answer is unknown — never treat it as "nothing saved yet".
 */
export type DirectoryRead =
  | { kind: 'ok'; document: DirectoryDocument }
  | { kind: 'absent' }
  | { kind: 'read-failed' };

/**
 * GET /v1/directory — the persisted operator directory for the caller's tenant, or
 * null when nothing has been saved. Requires CAP_DIRECTORY_ADMIN; opaque 403
 * otherwise. Fails soft: returns null on any error (the console keeps its local tree).
 */
export async function getDirectory(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<DirectoryRead> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/v1/directory`, init);
    // A 403 (no CAP_DIRECTORY_ADMIN), a 404 (pre-endpoint gateway) and a real
    // 200 {"document":null} are THREE different answers. Collapsing them to one
    // null made the console adopt its purely local tree and badge it "Synced" —
    // claiming the gateway agreed when the read had in fact failed.
    if (!res.ok) {
      return { kind: 'read-failed' };
    }
    const body = (await res.json()) as { document?: unknown };
    const doc = body.document;
    if (doc === null || doc === undefined || typeof doc !== 'object') {
      return { kind: 'absent' };
    }
    return { kind: 'ok', document: doc as DirectoryDocument };
  } catch {
    return { kind: 'read-failed' };
  }
}

/**
 * PUT /v1/directory — persist the operator directory for the caller's tenant.
 * Requires CAP_DIRECTORY_ADMIN; opaque 403 on auth/validation failure. Returns true
 * on success. Never throws.
 */
export async function putDirectory(
  token: string,
  document: DirectoryDocument,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = {
      method: 'PUT',
      headers: authHeaders(token),
      body: JSON.stringify(document),
    };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(`${baseOf(opts)}/v1/directory`, init);
    return res.status === 200;
  } catch {
    return false;
  }
}

/* ---------------------------------------------------------------------------
   Deny-only policy overlay (G3) — the per-tenant velocity/amount-ceiling
   document, read/written via the CAP_DIRECTORY_ADMIN-gated /v1/admin/policy
   endpoints (services/policy_engine.py PolicyDocStore + models/schemas.py
   PolicyRuleModel). The document holds ONLY velocity/amount rules — never an
   alias->target mapping or identity — so it can never repoint a skill or mint a
   principal. NO stored document => the engine imposes no limits (honest opt-in).
--------------------------------------------------------------------------- */

/** The schema tag every stored/accepted policy document carries. */
export const POLICY_SCHEMA = 'mcpip-policy/1' as const;

/** Which request field a rule keys on (services/policy_engine.py PolicyRule.scope). */
export type PolicyScope = 'alias' | 'transport_class';

/** The two deny-only rule kinds (services/policy_engine.py PolicyRule.kind). */
export type PolicyRuleKind = 'velocity' | 'amount';

/**
 * One deny-only policy rule. A rule MATCHES a request by `scope` + `scope_value`
 * (an opaque alias name or a coarse transport class) and, per `kind`, carries
 * EITHER the velocity fields (`max_actions` + `window_seconds`) OR the amount
 * fields (`amount_field` + `max_amount`, a decimal STRING — no float drift). A
 * stored rule (GET) carries all keys with the off-kind ones null; a written rule
 * (PUT) omits them — supplying a field for the wrong kind is a fail-closed opaque
 * deny server-side.
 */
export interface PolicyRule {
  kind: PolicyRuleKind;
  scope: PolicyScope;
  scope_value: string;
  max_actions?: number | null;
  window_seconds?: number | null;
  amount_field?: string | null;
  max_amount?: string | null;
}

/** The per-tenant deny-only policy document (schema tag + a bounded rule list). */
export interface PolicyDocument {
  schema: typeof POLICY_SCHEMA;
  rules: PolicyRule[];
}

/** Narrow one raw JSON value to a PolicyRule (drops anything off-shape). */
function asPolicyRule(value: unknown): PolicyRule | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const r = value as Record<string, unknown>;
  if (
    (r.kind !== 'velocity' && r.kind !== 'amount') ||
    (r.scope !== 'alias' && r.scope !== 'transport_class') ||
    typeof r.scope_value !== 'string'
  ) {
    return null;
  }
  const num = (v: unknown): number | null => (typeof v === 'number' ? v : null);
  const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
  return {
    kind: r.kind,
    scope: r.scope,
    scope_value: r.scope_value,
    max_actions: num(r.max_actions),
    window_seconds: num(r.window_seconds),
    amount_field: str(r.amount_field),
    max_amount: str(r.max_amount),
  };
}

/**
 * GET /v1/admin/policy — the caller's tenant's deny-only policy document. The
 * gateway ALWAYS answers with a document: when nothing is stored it returns the
 * honest empty `{ schema: 'mcpip-policy/1', rules: [] }` (no limits — opt-in), so
 * an empty `rules` means "no guardrails configured", never a failed read.
 * Requires CAP_DIRECTORY_ADMIN. Fails soft: returns null on any network error,
 * non-2xx (opaque 403), or malformed body — the panel then shows "unavailable",
 * distinct from an answered-but-empty document.
 */
export async function getPolicy(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<PolicyDocument | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/policy`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { policy?: unknown };
    const doc = body.policy;
    if (doc === null || typeof doc !== 'object' || Array.isArray(doc)) return null;
    const rules = (doc as { rules?: unknown }).rules;
    return {
      schema: POLICY_SCHEMA,
      rules: Array.isArray(rules)
        ? rules.map(asPolicyRule).filter((r): r is PolicyRule => r !== null)
        : [],
    };
  } catch {
    return null;
  }
}

/**
 * PUT /v1/admin/policy — persist the caller's tenant's policy document. The body
 * IS the document (`{ schema, rules }`); the gateway strict-validates it
 * (<= 64 well-formed velocity/amount rules, size-bounded) and a malformed
 * document is the same opaque 403 that never leaks its cause. WORM-logged
 * emit-before-mutate. Requires CAP_DIRECTORY_ADMIN. Returns true on 200. Never
 * throws.
 */
export async function putPolicy(
  token: string,
  document: PolicyDocument,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = {
      method: 'PUT',
      headers: authHeaders(token),
      body: JSON.stringify(document),
    };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/policy`, init);
    return res.status === 200;
  } catch {
    return false;
  }
}

/**
 * POST /v1/admin/policy/delete — remove the caller's tenant's policy document,
 * back to the honest no-limits state. Idempotent. Requires CAP_DIRECTORY_ADMIN.
 * Returns true on 200. Never throws.
 */
export async function deletePolicy(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = { method: 'POST', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/policy/delete`, init);
    return res.status === 200;
  } catch {
    return false;
  }
}

/**
 * POST /v1/admin/principals/{agent_id}/revoke — admin kill-switch. Blocks every
 * request from (tenant, agent) until reactivated. Requires a JWT holding
 * CAP_DIRECTORY_ADMIN; any auth/authorization failure is an opaque 403. Returns
 * true on success, false otherwise. Never throws.
 */
export async function revokePrincipal(
  token: string,
  agentId: string,
  reason: string | null,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = {
      method: 'POST',
      headers: authHeaders(token),
      body: JSON.stringify({ reason }),
    };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/principals/${encodeURIComponent(agentId)}/revoke`,
      init,
    );
    return res.status === 200;
  } catch {
    return false;
  }
}

/**
 * POST /v1/admin/principals/{agent_id}/reactivate — lift a revocation. Requires
 * CAP_DIRECTORY_ADMIN; opaque 403 otherwise. Returns true on success. Never throws.
 */
export async function reactivatePrincipal(
  token: string,
  agentId: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = { method: 'POST', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/principals/${encodeURIComponent(agentId)}/reactivate`,
      init,
    );
    return res.status === 200;
  } catch {
    return false;
  }
}

/**
 * GET /v1/admin/principals/revoked — the AUTHORITATIVE list of agent_ids
 * currently revoked in the admin's own tenant. Requires CAP_DIRECTORY_ADMIN.
 * The console reconciles its directory display against this (never trusts its
 * own local copy of revocation state). Returns null on any failure.
 */
export async function revokedPrincipals(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<string[] | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/principals/revoked`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { revoked?: unknown };
    return Array.isArray(body.revoked)
      ? body.revoked.filter((a): a is string => typeof a === 'string')
      : null;
  } catch {
    return null;
  }
}

/**
 * One projected ReBAC relation edge (operator Knowledge-Graph). `subject` has
 * `relation` to `object` (a compartment UUID). Projected from a committed grant —
 * operator-facing identifiers + non-secret metadata only; never a target, secret,
 * or alias→target mapping.
 */
export interface RelationEdge {
  object: string;
  relation: string;
  subject: string;
  grant_id: string | null;
  correlation_id: string | null;
  issued_at_ns: number | null;
}

/** The relation roster plus, when a full triple was queried, the bounded-check result. */
export interface RelationRoster {
  relations: RelationEdge[];
  /** Present only when subject+relation+object were all supplied to the read. */
  allowed?: boolean;
}

/** Optional narrowing filters for the relation read (mirror the endpoint query params). */
export interface RelationFilters {
  subject?: string;
  relation?: string;
  object?: string;
}

/**
 * GET /v1/admin/directory/relations — the ReBAC relation edges projected from
 * the admin's own tenant's committed grants (app/main.py
 * list_directory_relations). Requires CAP_DIRECTORY_ADMIN. This is the
 * authoritative edge source for the Knowledge-Graph, closing the gap where the
 * console had no gateway-served grant/relation roster (grants live in Redis with
 * EX=ttl and were never read back).
 *
 * BEST-EFFORT PROJECTION: the gateway/Redis grant state is authoritative — a
 * missing edge under-reports access (fail-safe for a visualization), never over-
 * reports. Optional subject/relation/object filters narrow the edges; a full
 * triple additionally returns `allowed` (the bounded transitive-closure check).
 * Body: `{ relations: [...], allowed? }`. A 404 means the connected gateway
 * predates this endpoint. Returns null on any failure (offline / unsupported).
 */
export async function directoryRelations(
  token: string,
  filters: RelationFilters = {},
  opts: GatewayClientOptions = {},
): Promise<RelationRoster | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const qs = new URLSearchParams();
    if (filters.subject) qs.set('subject', filters.subject);
    if (filters.relation) qs.set('relation', filters.relation);
    if (filters.object) qs.set('object', filters.object);
    const suffix = qs.toString() ? `?${qs.toString()}` : '';
    const res = await fetch(`${baseOf(opts)}/v1/admin/directory/relations${suffix}`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { relations?: unknown; allowed?: unknown };
    if (!Array.isArray(body.relations)) return null;
    const out: RelationEdge[] = [];
    for (const entry of body.relations) {
      if (typeof entry !== 'object' || entry === null) {
        continue;
      }
      const e = entry as Record<string, unknown>;
      if (typeof e.object === 'string' && typeof e.relation === 'string' && typeof e.subject === 'string') {
        out.push({
          object: e.object,
          relation: e.relation,
          subject: e.subject,
          grant_id: typeof e.grant_id === 'string' ? e.grant_id : null,
          correlation_id: typeof e.correlation_id === 'string' ? e.correlation_id : null,
          issued_at_ns: typeof e.issued_at_ns === 'number' ? e.issued_at_ns : null,
        });
      }
    }
    const roster: RelationRoster = { relations: out };
    if (typeof body.allowed === 'boolean') roster.allowed = body.allowed;
    return roster;
  } catch {
    return null;
  }
}

/** One currently-quarantined principal (automatic canary-tripwire freeze). */
export interface QuarantinedAgent {
  agent_id: string;
  /** Remaining freeze TTL in seconds, or null when the gateway omits it. */
  ttl_seconds: number | null;
}

/**
 * GET /v1/admin/quarantine — the agents currently frozen by the canary
 * tripwire in the admin's own tenant, each with the seconds remaining on its
 * TTL-bounded freeze (app/main.py list_quarantined_agents). Requires
 * CAP_DIRECTORY_ADMIN. Read-only: expiry is Redis's clock; a deliberate
 * persistent block is the separate revocation kill-switch. Body:
 * `{ quarantined: [{ agent_id, ttl_seconds }] }`. A 404 means the connected
 * gateway predates this endpoint. Returns null on any failure.
 */
export async function quarantineRoster(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<QuarantinedAgent[] | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/quarantine`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { quarantined?: unknown };
    if (!Array.isArray(body.quarantined)) return null;
    const out: QuarantinedAgent[] = [];
    for (const entry of body.quarantined) {
      if (typeof entry !== 'object' || entry === null) {
        continue;
      }
      const e = entry as Record<string, unknown>;
      if (typeof e.agent_id === 'string') {
        out.push({
          agent_id: e.agent_id,
          ttl_seconds: typeof e.ttl_seconds === 'number' ? e.ttl_seconds : null,
        });
      }
    }
    return out;
  } catch {
    return null;
  }
}

/** One seeded canary decoy alias (operator view — the agent-facing catalog hides the flag). */
export interface CanaryDecoy {
  alias: string;
  risk_tier: string | null;
  classification: string | null;
}

/**
 * GET /v1/admin/canaries — the canary decoy-alias roster for the admin's own
 * tenant (app/main.py list_canary_aliases). Requires CAP_DIRECTORY_ADMIN; this
 * is the ONLY surface where the canary flag may cross the wire (the
 * agent-facing /v1/catalog and MCP tools/list keep hiding it), and it exposes
 * alias metadata only — never the tripwire sink or any target. Body:
 * `{ canaries: [{ alias, risk_tier, classification }] }`. A 404 means the
 * connected gateway predates this endpoint. Returns null on any failure.
 */
export async function canaryRoster(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<CanaryDecoy[] | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/canaries`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { canaries?: unknown };
    if (!Array.isArray(body.canaries)) return null;
    const out: CanaryDecoy[] = [];
    for (const entry of body.canaries) {
      if (typeof entry !== 'object' || entry === null) {
        continue;
      }
      const e = entry as Record<string, unknown>;
      if (typeof e.alias === 'string') {
        out.push({
          alias: e.alias,
          risk_tier: typeof e.risk_tier === 'string' ? e.risk_tier : null,
          classification: typeof e.classification === 'string' ? e.classification : null,
        });
      }
    }
    return out;
  } catch {
    return null;
  }
}

/**
 * POST /v1/dev/token — SANDBOX ONLY. Mints a demo JWT via the reused _DemoIdP so
 * the artifact is runnable end-to-end. 404s in production (identity sovereignty).
 * Claims are optional — an empty body mints the default sandbox identity.
 */
export async function mintDevToken(
  claims: DevTokenClaims = {},
  opts: GatewayClientOptions = {},
): Promise<string> {
  const init: RequestInit = {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(claims),
  };
  if (opts.signal) {
    init.signal = opts.signal;
  }
  const res = await fetch(`${baseOf(opts)}/v1/dev/token`, init);
  if (res.status !== 200) {
    throw new Error(`dev token minting unavailable (status ${res.status})`);
  }
  const body = (await res.json()) as { jwt?: string; token?: string };
  const token = body.jwt ?? body.token;
  if (!token) {
    throw new Error('dev token response missing jwt');
  }
  return token;
}

/**
 * GET /v1/authenticator/{challenge_id} — SANDBOX ONLY stand-in for the enrolled
 * authenticator delivering the one-time code. JWT-gated (the OTP is tenant-scoped to
 * the verified identity). Used ONLY to complete a step-up ceremony end-to-end from the
 * console; it 404s in production, exactly like the real out-of-band delivery it stands
 * in for. Fails soft: returns null when unreachable, unauthorized, or expired.
 */
export async function authenticatorOtp(
  token: string,
  challengeId: string,
  opts: GatewayClientOptions = {},
): Promise<string | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) {
      init.signal = opts.signal;
    }
    const res = await fetch(
      `${baseOf(opts)}/v1/authenticator/${encodeURIComponent(challengeId)}`,
      init,
    );
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as { otp?: unknown };
    return typeof body.otp === 'string' ? body.otp : null;
  } catch {
    return null;
  }
}

/* ---------------------------------------------------------------------------
   Community extensions (author-your-own SKILLS + GATES). The SAME submit/review/
   WORM/hash-pin flow serves both kinds, routed by the manifest `kind`. Submit is
   a Contributor action (ANY authenticated principal, NO capability, deliberately
   OFF the /v1/admin/* prefix); review is the DISTINCT CAP_CATALOG_REVIEWER. All
   four are opaque-deny + WORM-audited (every mutation logs BEFORE it takes
   effect). The declared `target` on a pending skill is a reviewer-only surface —
   it never crosses the agent wire. GATE approval is refused until the deferred
   CEL engine is registered (no approve-without-proof, docs/integrate/EXTENSIBILITY.md §8).
--------------------------------------------------------------------------- */

/**
 * POST /v1/extensions/submit — submit a community-extension MANIFEST for review.
 * Contributor surface: any authenticated principal (a revoked/quarantined one is
 * still denied), NO capability, OFF the /v1/admin/* prefix. The manifest carries
 * its own `sha256` self-pin (computed over the canonical manifest bytes); the
 * gateway re-derives + compares it fail-closed, so a mismatch — like any
 * validation failure — is the opaque MCPIPDenied. Returns the server-minted
 * submission id on 200, or null on any failure (never throws).
 */
export async function submitExtension(
  token: string,
  manifest: ExtensionManifest,
  opts: GatewayClientOptions = {},
): Promise<{ submission_id: string } | null> {
  try {
    const init: RequestInit = {
      method: 'POST',
      headers: authHeaders(token),
      body: JSON.stringify({ manifest }),
    };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/extensions/submit`, init);
    if (res.status !== 200) return null;
    const body = (await res.json()) as { submission_id?: unknown };
    return typeof body.submission_id === 'string' ? { submission_id: body.submission_id } : null;
  } catch {
    return null;
  }
}

/** Normalize one raw pending-extension row (discriminated by `kind`) — or drop it. */
function asPendingExtension(value: unknown): PendingExtension | null {
  if (typeof value !== 'object' || value === null) return null;
  const r = value as Record<string, unknown>;
  const str = (v: unknown, fallback = ''): string => (typeof v === 'string' ? v : fallback);
  const bool = (v: unknown): boolean => v === true;
  if (typeof r.submission_id !== 'string') return null;
  if (r.kind === 'gate') {
    return {
      submission_id: r.submission_id,
      kind: 'gate',
      gate_id: str(r.gate_id),
      language: str(r.language),
      max_cost: typeof r.max_cost === 'number' ? r.max_cost : null,
      referenced_context_fields: Array.isArray(r.referenced_context_fields)
        ? r.referenced_context_fields.filter((f): f is string => typeof f === 'string')
        : [],
      author: str(r.author),
      submitter_agent_id: str(r.submitter_agent_id),
      manifest_sha256: str(r.manifest_sha256),
      created_at: str(r.created_at),
      submitter_is_reviewer: bool(r.submitter_is_reviewer),
      approvable: bool(r.approvable),
    };
  }
  if (r.kind === 'registry_server') {
    // X3 registry-server rows carry publisher/verification fields a skill row has
    // none of. Falling through to the skill projection dropped every one of them
    // AND relabelled the row 'skill', so the reviewer lost the only signals the
    // decision actually turns on: which publisher, and is it verified right now.
    return {
      submission_id: r.submission_id,
      kind: 'registry_server',
      alias: str(r.alias),
      target: str(r.target),
      transport: str(r.transport),
      risk_tier: str(r.risk_tier),
      classification: str(r.classification),
      publisher_namespace: str(r.publisher_namespace),
      server_name: str(r.server_name),
      server_version: str(r.server_version),
      provenance:
        typeof r.provenance === 'object' && r.provenance !== null && !Array.isArray(r.provenance)
          ? (r.provenance as Record<string, unknown>)
          : null,
      author: str(r.author),
      submitter_agent_id: str(r.submitter_agent_id),
      manifest_sha256: str(r.manifest_sha256),
      created_at: str(r.created_at),
      verified: bool(r.verified),
      conflicts_existing_alias: bool(r.conflicts_existing_alias),
      submitter_is_reviewer: bool(r.submitter_is_reviewer),
    };
  }
  // Default to the skill projection (the backend labels skill rows `kind:'skill'`).
  return {
    submission_id: r.submission_id,
    kind: 'skill',
    alias: str(r.alias),
    target: str(r.target),
    transport: str(r.transport),
    risk_tier: str(r.risk_tier),
    classification: str(r.classification),
    author: str(r.author),
    submitter_agent_id: str(r.submitter_agent_id),
    manifest_sha256: str(r.manifest_sha256),
    created_at: str(r.created_at),
    conflicts_existing_alias: bool(r.conflicts_existing_alias),
    submitter_is_reviewer: bool(r.submitter_is_reviewer),
  };
}

/**
 * GET /v1/admin/extensions/pending — the tenant's PENDING submissions awaiting
 * review. Reviewer surface (CAP_CATALOG_REVIEWER — DISTINCT from
 * CAP_DIRECTORY_ADMIN), read-only, tenant-scoped, a strict whitelist projection
 * discriminated by `kind`. Fails soft: returns null on any network error, non-2xx
 * (opaque 403), or malformed body — vs [] for a genuinely empty queue.
 */
export async function extensionsPending(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<PendingExtension[] | null> {
  try {
    const init: RequestInit = { method: 'GET', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(`${baseOf(opts)}/v1/admin/extensions/pending`, init);
    if (!res.ok) return null;
    const body = (await res.json()) as { pending?: unknown };
    if (!Array.isArray(body.pending)) return null;
    return body.pending
      .map(asPendingExtension)
      .filter((row): row is PendingExtension => row !== null);
  } catch {
    return null;
  }
}

/**
 * POST /v1/admin/extensions/{submission_id}/approve — approve a PENDING submission.
 * Reviewer surface (CAP_CATALOG_REVIEWER), tenant-scoped, opaque deny. Re-runs the
 * AUTHORITATIVE checks fail-closed (re-parse + re-pin, `_overlay_skill_invalid`,
 * additive-only, overlay ceiling), WORM-records the approval BEFORE apply, then
 * mints the skill through the SAME hardened overlay path as a register. A GATE
 * approval is REFUSED (no approve-without-proof) until the deferred CEL engine is
 * registered. Returns the approved alias on 200, or null on any failure.
 */
export async function extensionApprove(
  token: string,
  submissionId: string,
  opts: GatewayClientOptions = {},
): Promise<{ approved: string } | null> {
  try {
    const init: RequestInit = { method: 'POST', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/extensions/${encodeURIComponent(submissionId)}/approve`,
      init,
    );
    if (res.status !== 200) return null;
    const body = (await res.json().catch(() => ({}))) as { approved?: unknown };
    return typeof body.approved === 'string' ? { approved: body.approved } : null;
  } catch {
    return null;
  }
}

/**
 * POST /v1/admin/extensions/{submission_id}/reject — reject a PENDING submission.
 * Reviewer surface (CAP_CATALOG_REVIEWER), tenant-scoped, opaque deny. WORM-records
 * the rejection BEFORE marking the submission terminal; NOTHING is applied to the
 * catalog. Works uniformly for a skill or a gate. Returns true on 200. Never throws.
 */
export async function extensionReject(
  token: string,
  submissionId: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const init: RequestInit = { method: 'POST', headers: authHeaders(token) };
    if (opts.signal) init.signal = opts.signal;
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/extensions/${encodeURIComponent(submissionId)}/reject`,
      init,
    );
    return res.status === 200;
  } catch {
    return false;
  }
}

/* ---------------------------------------------------------------------------
   Per-user authenticator (USER-BASED 2FA, RFC 6238 TOTP). Enrollment binds a
   standard authenticator app to the CALLER's principal; a staged step-up code
   becomes revealable only against a fresh, un-replayed code from that app. The
   payload-bound PIN itself is untouched — these surfaces gate WHO may read a
   delivered code. All failures are opaque by design; helpers return null/false
   rather than surfacing gateway internals.
--------------------------------------------------------------------------- */

export interface AuthnStatus {
  enrolled: boolean;
  pending: boolean;
  enrolled_at: number | null;
}

export interface AuthnProvisioning {
  secret: string;
  provisioning_uri: string;
  digits: number;
  period_s: number;
}

export interface AuthnEnrollmentRow {
  agent_id: string;
  state: string;
  enrolled_at: number | null;
}

/** GET /v1/authenticator — the caller's own enrollment state (never the secret). */
export async function authnStatus(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<AuthnStatus | null> {
  try {
    const res = await fetch(`${baseOf(opts)}/v1/authenticator`, {
      method: 'GET',
      headers: authHeaders(token),
    });
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as AuthnStatus;
    return typeof body.enrolled === 'boolean' ? body : null;
  } catch {
    return null;
  }
}

/** POST /v1/authenticator/enroll — provisioning material, returned exactly ONCE. */
export async function authnEnroll(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<AuthnProvisioning | null> {
  try {
    const res = await fetch(`${baseOf(opts)}/v1/authenticator/enroll`, {
      method: 'POST',
      headers: authHeaders(token),
    });
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as AuthnProvisioning;
    return typeof body.secret === 'string' && typeof body.provisioning_uri === 'string'
      ? body
      : null;
  } catch {
    return null;
  }
}

/** POST /v1/authenticator/enroll/confirm — prove possession, activate. */
export async function authnConfirm(
  token: string,
  code: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const res = await fetch(`${baseOf(opts)}/v1/authenticator/enroll/confirm`, {
      method: 'POST',
      headers: { ...authHeaders(token), 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** POST /v1/authenticator/disable — 2FA-off ceremony (valid current code required). */
export async function authnDisable(
  token: string,
  code: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const res = await fetch(`${baseOf(opts)}/v1/authenticator/disable`, {
      method: 'POST',
      headers: { ...authHeaders(token), 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
    });
    return res.ok;
  } catch {
    return false;
  }
}

/** POST /v1/authenticator/reveal — TOTP-gated single-use release of a staged code. */
export async function authnReveal(
  token: string,
  challengeId: string,
  code: string,
  opts: GatewayClientOptions = {},
): Promise<string | null> {
  try {
    const res = await fetch(`${baseOf(opts)}/v1/authenticator/reveal`, {
      method: 'POST',
      headers: { ...authHeaders(token), 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_id: challengeId, code }),
    });
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as { otp?: unknown };
    return typeof body.otp === 'string' ? body.otp : null;
  } catch {
    return null;
  }
}

/** GET /v1/admin/authenticator/enrollments — the tenant roster (admin). */
export async function authnEnrollments(
  token: string,
  opts: GatewayClientOptions = {},
): Promise<AuthnEnrollmentRow[] | null> {
  try {
    const res = await fetch(`${baseOf(opts)}/v1/admin/authenticator/enrollments`, {
      method: 'GET',
      headers: authHeaders(token),
    });
    if (!res.ok) {
      return null;
    }
    const body = (await res.json()) as { enrollments?: unknown };
    return Array.isArray(body.enrollments) ? (body.enrollments as AuthnEnrollmentRow[]) : null;
  } catch {
    return null;
  }
}

/** DELETE /v1/admin/authenticator/{agent} — lost-device removal (admin). */
export async function authnAdminDisable(
  token: string,
  agentId: string,
  opts: GatewayClientOptions = {},
): Promise<boolean> {
  try {
    const res = await fetch(
      `${baseOf(opts)}/v1/admin/authenticator/${encodeURIComponent(agentId)}`,
      { method: 'DELETE', headers: authHeaders(token) },
    );
    return res.ok;
  } catch {
    return false;
  }
}
