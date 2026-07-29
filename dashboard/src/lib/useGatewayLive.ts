/* ---------------------------------------------------------------------------
   Live gateway hook — the console's ONE data artery.

   Probes /healthz; when a real FastAPI gateway answers, every panel runs on
   REAL data: a dev JWT is minted once and the catalog / audit / version /
   license surfaces reflect actual gateway state; the decision stream is the
   gateway's own /v1/admin/decisions/recent feed (ALL agents' traffic, not just
   this console's calls); fleet-wide metrics come from the gateway's OWN
   Prometheus exposition (GET /metrics). With no gateway reachable the hook is
   offline and every field is honestly EMPTY (null / [] — never fabricated);
   views render their explicit connect/empty states.

   THE GatewayLive CONTRACT (views build against exactly this — see the
   interface below for per-field semantics):
     • `stream` — up to 50 newest decisions, each row a 1:1 projection of the
       real feed incl. per-row `wormSequence` + `eventId` (StreamEvent). The
       old fabricated latencyMs column is gone.
     • `metrics` — fleet-wide counters + REAL gateway-side p50/p95 from the
       mcpip_authorize_latency_seconds histogram, scraped on the decision-poll
       cadence; the console's own probe latency is kept SEPARATE as
       `consoleProbeP50Ms`. null = no signal, render "—", never 0.
     • `healthHistory` — a session-scoped ring (~120 ticks, one per /healthz
       probe ≈ 8 min) of REAL {t, live, redis} observations for the Health
       page's availability history. Nothing is backfilled or invented.
     • `authorizeSkill` / `completeStepUp` — one REAL /v1/authorize round-trip
       (and the sandbox step-up completion: OTP fetch + pin resubmit with
       byte-identical args, exactly-once).
     • `fetchDecisions` / `fetchProof` / `fetchRevokedPrincipals` /
       `fetchQuarantine` / `fetchCanaries` — token-caring async reads for the
       ledger / directory / canary views, so views never handle JWTs. All fail
       soft (null) offline or when unauthorized/unsupported.

   CORS note: the sandbox gateway allows all console origins; production lists
   them via MCPIP_CONSOLE_ORIGINS. When a direct cross-origin fetch is blocked
   anyway, the probe falls back to '' — the same-origin path the Vite
   dev/preview proxy forwards to the gateway (see vite.config.ts).

   Every network call fails soft; a single failed probe flips to offline
   (clearing per-connection state) and keeps retrying quietly.
--------------------------------------------------------------------------- */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  API_BASE,
  auditAttestation,
  auditProof,
  auditVerify,
  authenticatorOtp,
  authorize,
  canaryRoster,
  catalog as fetchCatalog,
  complianceEvidence,
  deploymentStats,
  directoryRelations,
  healthz,
  licenseInfo as fetchLicense,
  mintDevToken,
  quarantineRoster,
  queryDecisions,
  readyz,
  recentDecisions,
  revokedPrincipals,
  versionInfo as fetchVersion,
} from './api';
import type {
  AuditAttestation,
  AuditVerifyResult,
  CanaryDecoy,
  ComplianceEvidence,
  DecisionPage,
  DecisionQuery,
  DeploymentStats,
  DevTokenClaims,
  HealthzInfo,
  LicenseInfo,
  ProofResult,
  QuarantinedAgent,
  RecentDecision,
  RelationFilters,
  RelationRoster,
  VersionInfo,
} from './api';
import { scrapeMetrics } from './metricsClient';
import type {
  AuthorizeOutcome,
  AuthorizeRequest,
  CatalogItem,
  MetricsSnapshot,
  StreamEvent,
} from './types';
import { CAP_DIRECTORY_ADMIN } from './protocol';
import { loadCompanyConfig } from './companyConfig';

export type GatewayMode = 'live' | 'offline';

export interface Readiness {
  ready: boolean;
  redis: 'up' | 'down';
}

/** One real /v1/authorize round-trip: outcome + measured wall-clock latency. */
export interface LiveAuthResult {
  outcome: AuthorizeOutcome;
  latencyMs: number;
}

/** One REAL /healthz probe observation (session-scoped; never backfilled). */
export interface HealthTick {
  /** Epoch ms when the probe tick completed. */
  t: number;
  /** True when the gateway answered /healthz on this tick. */
  live: boolean;
  /** Latest /readyz redis verdict at tick time; null = no signal yet / offline. */
  redis: boolean | null;
}

export interface GatewayLive {
  mode: GatewayMode;
  /** The resolved base actually used for fetches ('' = same-origin proxy). */
  apiBase: string;
  /** Display host of the resolved base (e.g. "localhost:8080"). */
  apiHost: string;
  /** tenant_id decoded from the minted dev JWT (live mode only). */
  tenant: string | null;
  health: HealthzInfo | null;
  ready: Readiness | null;
  audit: AuditVerifyResult | null;
  catalog: CatalogItem[];
  /** Newest-first, up to 50 rows — REAL feed rows only (see StreamEvent). */
  stream: StreamEvent[];
  /** Fleet-wide /metrics scrape + console-probe stats (see MetricsSnapshot). */
  metrics: MetricsSnapshot;
  /** REAL probe-tick ring for the Health page (~120 ticks · one per 4s probe). */
  healthHistory: ReadonlyArray<HealthTick>;
  /**
   * Decisions/sec per scrape tick, from successive mcpip_authorize_decisions_total
   * deltas — true fleet throughput. Starts empty and grows one REAL point per
   * scrape (max 40); [] offline.
   */
  throughputHistory: number[];
  /** Running release + signed provenance + update posture (live mode; null offline). */
  version: VersionInfo | null;
  /** Boot-verified entitlement document (live mode; null offline). */
  license: LicenseInfo | null;
  /** Fire ONE real authorization (the Authorize Probe). Null offline/unmintable. */
  authorizeSkill: (alias: string) => Promise<LiveAuthResult | null>;
  /**
   * Complete a staged step-up for `alias`: fetch the one-time code from the
   * SANDBOX authenticator stand-in and resubmit with pin + challenge_id and
   * byte-identical arguments (the payload lock is over them). Null when the
   * authenticator is unavailable — in production the enrolled device delivers
   * the code out-of-band, so null there is the honest answer.
   */
  completeStepUp: (alias: string, challengeId: string) => Promise<LiveAuthResult | null>;
  /**
   * Own-poll read of /v1/admin/decisions/recent for the Audit Ledger (limit
   * clamped 1..200, default 200). Null offline / when the admin read is
   * unavailable; [] for a genuinely idle gateway.
   */
  fetchDecisions: (limit?: number, signal?: AbortSignal) => Promise<RecentDecision[] | null>;
  /**
   * One page of the date-ranged, multi-filtered, cursor-paged decision HISTORY
   * (GET /v1/admin/decisions) — the "activity at scale" read behind the History
   * view. Same whitelist projection as the live feed. Null offline / unavailable.
   */
  fetchDecisionsPage: (
    query: DecisionQuery,
    signal?: AbortSignal,
  ) => Promise<DecisionPage | null>;
  /** Per-event Merkle inclusion proof (sandbox-only endpoint; honest 'unavailable' otherwise). */
  fetchProof: (eventId: string, signal?: AbortSignal) => Promise<ProofResult>;
  /**
   * Portable, signed WORM attestation of the current audit state (/v1/audit/attestation).
   * Plain-JWT-gated and — unlike the sandbox-only verify/proof reads — available in
   * production. Null offline / when the read is unavailable / endpoint unsupported.
   */
  fetchAuditAttestation: (signal?: AbortSignal) => Promise<AuditAttestation | null>;
  /** Portable compliance-evidence bundle (CAP_DIRECTORY_ADMIN; evidence, never a cert). Fails soft. */
  fetchComplianceEvidence: (signal?: AbortSignal) => Promise<ComplianceEvidence | null>;
  /** LOCAL live deployment/license/usage stats (CAP_DIRECTORY_ADMIN; GET /v1/admin/stats). Fails soft — null offline/unauthorized. */
  fetchDeploymentStats: (signal?: AbortSignal) => Promise<DeploymentStats | null>;
  /** Mint (cached) a CAP_DIRECTORY_ADMIN token for admin-surfaced console calls (e.g. the
   * Users roster). Null offline / in production where the dev-token minter is 404 — the
   * caller then shows an honest empty/unavailable state. */
  ensureAdminToken: (signal?: AbortSignal) => Promise<string | null>;
  /** AUTHORITATIVE revoked-principal list for the operator's tenant. Null on failure. */
  fetchRevokedPrincipals: (signal?: AbortSignal) => Promise<string[] | null>;
  /** Currently-quarantined principals (+TTL). Null offline / endpoint unsupported. */
  fetchQuarantine: (signal?: AbortSignal) => Promise<QuarantinedAgent[] | null>;
  /** Canary decoy-alias roster (operator-only view). Null offline / unsupported. */
  fetchCanaries: (signal?: AbortSignal) => Promise<CanaryDecoy[] | null>;
  /**
   * ReBAC relation edges projected from committed grants (the Knowledge-Graph edge
   * source). Best-effort projection — a missing edge under-reports, never over-reports.
   * Null offline / when the admin read is unavailable / endpoint unsupported.
   */
  fetchDirectoryRelations: (
    filters?: RelationFilters,
    signal?: AbortSignal,
  ) => Promise<RelationRoster | null>;
  /** Force an immediate /v1/version re-check (the "Check for updates" button). */
  checkForUpdate: () => Promise<VersionInfo | null>;
  /** Operator-pinned gateway endpoint (persisted), or null = auto-detect. */
  configuredBase: string | null;
  /** Plug-and-play: probe + pin a gateway endpoint. Resolves true iff it answered. */
  connect: (base: string) => Promise<boolean>;
  /** Clear the pinned endpoint and return to offline / auto-detect. */
  disconnect: () => void;
  /**
   * Where this console's identity comes from:
   *   'operator-token' — an operator pinned a real IdP-minted bearer (production).
   *   'sandbox-forge'  — minted via POST /v1/dev/token (sandbox gateways only).
   *   'none'           — neither is available; live panels are honestly empty and
   *                      the UI should say so rather than render a blank state.
   */
  identitySource: 'operator-token' | 'sandbox-forge' | 'none';
  /** Pin (or clear, with null) an operator-supplied bearer token. Persisted. */
  setOperatorToken: (token: string | null) => void;
  /** True when a production gateway is connected but no operator token is pinned. */
  needsOperatorToken: boolean;
}

const PROBE_MS = 4000;
const REFRESH_MS = 5000;
// Poll the real decision feed + /metrics scrape on a snappy shared cadence.
const DECISIONS_POLL_MS = 2000;
const HISTORY = 40;
const HEALTH_TICKS = 120;
const LATENCY_WINDOW = 60;
const STREAM_LIMIT = 50;

/** The honest no-signal snapshot — every field is "unknown", never a fake zero. */
const EMPTY_METRICS: MetricsSnapshot = {
  decisionsTotal: null,
  allowTotal: null,
  denyTotal: null,
  stagedTotal: null,
  gatewayP50Ms: null,
  gatewayP95Ms: null,
  decisionsPerSec: null,
  wormSequence: null,
  wormEpoch: null,
  consoleProbeP50Ms: null,
};

interface DecodedClaims {
  tenant: string | null;
  /** exp in epoch ms, or null when absent/unreadable. */
  expMs: number | null;
}

function decodeClaims(jwt: string): DecodedClaims {
  try {
    const payload = jwt.split('.')[1];
    if (!payload) {
      return { tenant: null, expMs: null };
    }
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(json) as { tenant_id?: unknown; exp?: unknown };
    return {
      tenant: typeof claims.tenant_id === 'string' ? claims.tenant_id : null,
      expMs: typeof claims.exp === 'number' ? claims.exp * 1000 : null,
    };
  } catch {
    return { tenant: null, expMs: null };
  }
}

/** Re-mint this long before the JWT's exp (sandbox tokens live ~5 min). */
const TOKEN_EXP_SLACK_MS = 30_000;

function median(values: ReadonlyArray<number>): number | null {
  if (values.length === 0) {
    return null;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const value =
    sorted.length % 2 === 1 ? sorted[mid] ?? 0 : ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2;
  return Math.round(value * 10) / 10;
}

function hostOf(base: string): string {
  if (base === '') {
    return typeof window !== 'undefined' ? window.location.host : 'same-origin';
  }
  try {
    return new URL(base).host;
  } catch {
    return base;
  }
}

/**
 * The probe request for one alias. Stage + step-up completion MUST send
 * byte-identical arguments — the payload lock is over their canonical JSON —
 * so both paths build the request through this single function.
 */
function probeRequest(alias: string): AuthorizeRequest {
  return { source_format: 'raw_mcp', tool_call: { tool: alias, arguments: {} } };
}

/** Map one REAL feed row into the stream contract — a projection, never invention. */
function toStreamEvent(r: RecentDecision): StreamEvent {
  return {
    // worm_sequence is unique per WORM event, so the composite is a stable row key.
    id: `${r.worm_sequence}:${r.correlation_id}`,
    ts: Math.round(r.timestamp_ns / 1_000_000),
    timestampNs: r.timestamp_ns,
    tenant: r.tenant_id,
    alias: r.alias ?? '(unknown)',
    transport: (r.transport ?? 'cloud_rest') as StreamEvent['transport'],
    decision: r.decision,
    reason: (r.deny_reason ?? null) as StreamEvent['reason'],
    correlationId: r.correlation_id,
    agent: r.agent_id,
    sourceFormat: r.source_format,
    transactionRef: r.transaction_ref,
    riskTier: (r.risk_tier ?? null) as StreamEvent['riskTier'],
    classification: r.classification,
    eventId: r.event_id,
    wormSequence: r.worm_sequence,
  };
}

/** localStorage key for the operator-pinned gateway endpoint (plug-and-play). */
const GATEWAY_KEY = 'mcpip.gateway.base';

/**
 * localStorage key for an operator-supplied bearer token.
 *
 * The console's own identity normally comes from ``POST /v1/dev/token``, which is
 * a SANDBOX affordance — on a production gateway (``MCPIP_SANDBOX_MODE=false``)
 * that route is 404 and the console has no identity at all. Rather than leave
 * every live panel silently empty against production, an operator can pin a real
 * bearer token minted by their own IdP (``scripts/mint_principal.py``). It takes
 * precedence over the sandbox forge wherever one is needed.
 *
 * This is deliberately NOT a credential the console can mint: MCPIP never issues
 * identity, so the token is pasted in, stored locally, and sent as-is.
 */
const OPERATOR_TOKEN_KEY = 'mcpip.gateway.token';

function readPinnedBase(): string | null {
  try {
    return localStorage.getItem(GATEWAY_KEY);
  } catch {
    return null;
  }
}

function readPinnedToken(): string | null {
  try {
    const raw = localStorage.getItem(OPERATOR_TOKEN_KEY);
    return raw && raw.trim() ? raw.trim() : null;
  } catch {
    return null;
  }
}

export function useGatewayLive(): GatewayLive {
  const [configuredBase, setConfiguredBase] = useState<string | null>(() => readPinnedBase());
  /** Operator-pinned bearer (persisted). Wins over the sandbox forge when set. */
  const [operatorToken, setOperatorTokenState] = useState<string | null>(() => readPinnedToken());
  /**
   * Whether POST /v1/dev/token answered on this gateway: true = sandbox forge
   * available, false = 404 (production posture), null = not tried yet. Recorded
   * from real attempts only — never inferred.
   */
  const [devForgeOk, setDevForgeOk] = useState<boolean | null>(null);
  const [mode, setMode] = useState<GatewayMode>('offline');
  const [apiBase, setApiBase] = useState<string>(API_BASE);
  const [health, setHealth] = useState<HealthzInfo | null>(null);
  const [ready, setReady] = useState<Readiness | null>(null);
  const [audit, setAudit] = useState<AuditVerifyResult | null>(null);
  const [catalogItems, setCatalogItems] = useState<CatalogItem[]>([]);
  const [tenant, setTenant] = useState<string | null>(null);
  const [version, setVersion] = useState<VersionInfo | null>(null);
  const [license, setLicense] = useState<LicenseInfo | null>(null);

  const [liveStream, setLiveStream] = useState<StreamEvent[]>([]);
  const [liveSnapshot, setLiveSnapshot] = useState<MetricsSnapshot>(EMPTY_METRICS);
  const [throughput, setThroughput] = useState<number[]>([]);
  const [healthHistory, setHealthHistory] = useState<HealthTick[]>([]);

  const baseRef = useRef<string | null>(null);
  const tokenRef = useRef<string | null>(null);
  const tokenExpRef = useRef<number | null>(null);
  const tenantRef = useRef<string | null>(null);
  const wormRef = useRef(0);
  const latenciesRef = useRef<number[]>([]);
  /** Latest /readyz redis verdict, for the health-history ring. */
  const readyRef = useRef<boolean | null>(null);
  /** Last successful decisions-counter reading, for real per-tick throughput. */
  const rateRef = useRef<{ total: number; atMs: number; perSec: number | null } | null>(null);
  /** True while the probe loop considers the gateway reachable. */
  const liveRef = useRef(false);
  // Admin (CAP_DIRECTORY_ADMIN) token, minted for the company tenant, used for the
  // gateway's admin reads (decision feed, rosters) so they reflect ALL agents.
  const adminTokenRef = useRef<string | null>(null);
  const adminTokenExpRef = useRef<number | null>(null);

  /**
   * Mint the sandbox dev JWT once and cache it; re-mint only when the cached
   * token is about to expire (the sandbox mints ~5-minute tokens). Fails soft.
   */
  const ensureToken = useCallback(async (signal?: AbortSignal): Promise<string | null> => {
    // An operator-pinned bearer always wins: it is a REAL identity from the
    // customer's IdP, and on a production gateway it is the only one available.
    const pinned = readPinnedToken();
    if (pinned) {
      return pinned;
    }
    const cached = tokenRef.current;
    if (cached) {
      const expMs = tokenExpRef.current;
      if (expMs === null || Date.now() < expMs - TOKEN_EXP_SLACK_MS) {
        return cached;
      }
      tokenRef.current = null;
    }
    const base = baseRef.current;
    if (base === null) {
      return null;
    }
    try {
      // Mint the console's identity for the OPERATOR'S company tenant (from the
      // first-run setup), so every live surface — catalog, stream, metrics — reflects
      // the company the operator actually configured, not the sandbox default.
      const company = loadCompanyConfig();
      const claims = company?.tenant ? { tenant_id: company.tenant } : {};
      const jwt = await mintDevToken(claims, { base, signal });
      setDevForgeOk(true);
      const { tenant: decoded, expMs } = decodeClaims(jwt);
      tokenRef.current = jwt;
      tokenExpRef.current = expMs;
      tenantRef.current = decoded;
      setTenant(decoded);
      return jwt;
    } catch {
      // 404 here is the normal production answer, not an error: the sandbox
      // forge is simply not mounted. Record it so the UI can ask for a token.
      setDevForgeOk(false);
      return null;
    }
  }, []);

  /**
   * Mint a CAP_DIRECTORY_ADMIN token for the company tenant (cached, proactively
   * re-minted before expiry). Used for the gateway's admin reads. In production
   * /v1/dev/token is 404 — those reads then stay honestly empty, like every
   * other admin surface without a real admin credential.
   */
  const ensureAdminToken = useCallback(async (signal?: AbortSignal): Promise<string | null> => {
    // Same precedence as ensureToken. Whether the pinned bearer actually carries
    // CAP_DIRECTORY_ADMIN is the gateway's call, not ours — if it does not, the
    // admin reads return 403 and the panels stay empty, which is the honest result.
    const pinned = readPinnedToken();
    if (pinned) {
      return pinned;
    }
    const cached = adminTokenRef.current;
    if (cached) {
      const expMs = adminTokenExpRef.current;
      if (expMs === null || Date.now() < expMs - TOKEN_EXP_SLACK_MS) {
        return cached;
      }
      adminTokenRef.current = null;
    }
    const base = baseRef.current;
    if (base === null) {
      return null;
    }
    try {
      // Tenant comes from the operator's real company profile (or the already-minted
      // console identity); with neither, the sandbox IdP's own default identity is
      // used — the console never hardcodes a tenant.
      const company = loadCompanyConfig();
      const tenantId = company?.tenant || tenantRef.current;
      const claims: DevTokenClaims = {
        agent_id: 'agent-directory-admin',
        capabilities: [CAP_DIRECTORY_ADMIN],
      };
      if (tenantId) {
        claims.tenant_id = tenantId;
      }
      const jwt = await mintDevToken(claims, { base, signal });
      setDevForgeOk(true);
      adminTokenRef.current = jwt;
      adminTokenExpRef.current = decodeClaims(jwt).expMs;
      return jwt;
    } catch {
      setDevForgeOk(false);
      return null;
    }
  }, []);

  /**
   * Pull the gateway's REAL recent decisions for the company tenant into the
   * stream. This is the single source of the stream, so ANY agent's traffic (a
   * Claude MCP client, another service) shows up — not only calls this console
   * makes. Nothing is fabricated: an idle gateway yields an empty stream.
   */
  const refreshDecisions = useCallback(async (signal?: AbortSignal): Promise<void> => {
    const base = baseRef.current;
    if (base === null) {
      return;
    }
    const token = await ensureAdminToken(signal);
    if (!token) {
      return;
    }
    const rows = await recentDecisions(token, { base, signal }, STREAM_LIMIT);
    if (rows === null) {
      return;
    }
    setLiveStream(rows.slice(0, STREAM_LIMIT).map(toStreamEvent));
    // Feed max is a REAL fallback reading of the WORM height (used until the
    // /metrics gauge answers, and to bridge multi-worker gauge lag).
    wormRef.current = rows.reduce((m, r) => Math.max(m, r.worm_sequence), wormRef.current);
  }, [ensureAdminToken]);

  /**
   * Scrape GET /metrics — the gateway's OWN Prometheus counters/histogram —
   * and rebuild the snapshot. Fleet-wide and honest: p50/p95 cover ALL agents'
   * traffic; throughput is the delta of a real cumulative counter. A transient
   * scrape failure keeps the last-known snapshot rather than blanking it.
   */
  const refreshMetrics = useCallback(async (signal?: AbortSignal): Promise<void> => {
    const base = baseRef.current;
    if (base === null) {
      return;
    }
    const scrape = await scrapeMetrics({ base, signal });
    if (scrape === null) {
      return;
    }
    const now = Date.now();
    let perSec: number | null = rateRef.current?.perSec ?? null;
    const total = scrape.decisions?.total ?? null;
    if (total !== null) {
      const prev = rateRef.current;
      if (prev !== null && now > prev.atMs) {
        // Counter-reset handling (gateway restart): the new total IS the increase.
        const delta = total >= prev.total ? total - prev.total : total;
        perSec = Math.round((delta / ((now - prev.atMs) / 1000)) * 10) / 10;
        const point = perSec;
        setThroughput((h) => [...h, point].slice(-HISTORY));
      }
      rateRef.current = { total, atMs: now, perSec };
    }
    const feedWorm = wormRef.current > 0 ? wormRef.current : null;
    const gaugeWorm = scrape.wormSequence;
    setLiveSnapshot((prevSnapshot) => ({
      decisionsTotal: scrape.decisions?.total ?? null,
      allowTotal: scrape.decisions?.allow ?? null,
      denyTotal: scrape.decisions?.deny ?? null,
      stagedTotal: scrape.decisions?.staged ?? null,
      gatewayP50Ms: scrape.latency?.p50Ms ?? null,
      gatewayP95Ms: scrape.latency?.p95Ms ?? null,
      decisionsPerSec: perSec,
      // Both readings are real observations of the same monotonic height.
      wormSequence:
        gaugeWorm !== null ? Math.max(gaugeWorm, feedWorm ?? 0) : feedWorm,
      wormEpoch: scrape.wormEpoch,
      consoleProbeP50Ms: prevSnapshot.consoleProbeP50Ms,
    }));
  }, []);

  /** A console-initiated call folds its latency in and pulls the fresh decision now. */
  const recordOutcome = useCallback(
    (outcome: AuthorizeOutcome, latencyMs: number): void => {
      // Staged (202) responses return before dispatch — only terminal decisions
      // join the probe-latency population.
      if (outcome.kind !== 'staged') {
        latenciesRef.current.push(latencyMs);
        if (latenciesRef.current.length > LATENCY_WINDOW) {
          latenciesRef.current.shift();
        }
        setLiveSnapshot((prev) => ({
          ...prev,
          consoleProbeP50Ms: median(latenciesRef.current),
        }));
      }
      // The decision is already durable in WORM by the time authorize returns, so an
      // immediate refresh surfaces it without waiting for the next poll tick.
      void refreshDecisions();
    },
    [refreshDecisions],
  );

  /** One REAL /v1/authorize round-trip with measured latency. Fails soft. */
  const authorizeSkill = useCallback(
    async (alias: string, signal?: AbortSignal): Promise<LiveAuthResult | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureToken(signal);
      if (!token) {
        return null;
      }
      const started = performance.now();
      try {
        const outcome = await authorize(probeRequest(alias), { token, base, signal });
        const latencyMs = Math.round((performance.now() - started) * 10) / 10;
        recordOutcome(outcome, latencyMs);
        return { outcome, latencyMs };
      } catch {
        return null;
      }
    },
    [ensureToken, recordOutcome],
  );

  /**
   * Complete a staged step-up: fetch the one-time code from the SANDBOX
   * authenticator stand-in, then resubmit the byte-identical probe request
   * with pin + challenge_id (the atomic consume-and-compare). Returns null
   * when the authenticator is unavailable — production delivers the code
   * out-of-band, so the console cannot (and must not pretend to) complete it.
   */
  const completeStepUp = useCallback(
    async (alias: string, challengeId: string, signal?: AbortSignal): Promise<LiveAuthResult | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureToken(signal);
      if (!token) {
        return null;
      }
      const otp = await authenticatorOtp(token, challengeId, { base, signal });
      if (otp === null) {
        return null;
      }
      const started = performance.now();
      try {
        const outcome = await authorize(
          { ...probeRequest(alias), pin: otp, challenge_id: challengeId },
          { token, base, signal },
        );
        const latencyMs = Math.round((performance.now() - started) * 10) / 10;
        recordOutcome(outcome, latencyMs);
        return { outcome, latencyMs };
      } catch {
        return null;
      }
    },
    [ensureToken, recordOutcome],
  );

  /** Own-poll ledger read: /v1/admin/decisions/recent at up to the server max. */
  const fetchDecisions = useCallback(
    async (limit = 200, signal?: AbortSignal): Promise<RecentDecision[] | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureAdminToken(signal);
      if (!token) {
        return null;
      }
      return recentDecisions(token, { base, signal }, limit);
    },
    [ensureAdminToken],
  );

  /** Per-event inclusion proof (sandbox-only endpoint; honest states otherwise). */
  const fetchProof = useCallback(
    async (eventId: string, signal?: AbortSignal): Promise<ProofResult> => {
      const base = baseRef.current;
      if (base === null) {
        return { status: 'unavailable', proof: null, detail: 'no gateway connected' };
      }
      const token = await ensureToken(signal);
      if (!token) {
        return { status: 'unavailable', proof: null, detail: 'no verified identity for the proof read' };
      }
      return auditProof(token, eventId, { base, signal });
    },
    [ensureToken],
  );

  /** Portable signed audit attestation (plain-JWT-gated; production-available). Fails soft. */
  const fetchAuditAttestation = useCallback(
    async (signal?: AbortSignal): Promise<AuditAttestation | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureToken(signal);
      if (!token) {
        return null;
      }
      return auditAttestation(token, { base, signal });
    },
    [ensureToken],
  );

  /** Portable compliance-evidence bundle (CAP_DIRECTORY_ADMIN; evidence, never a cert). Fails soft. */
  const fetchComplianceEvidence = useCallback(
    async (signal?: AbortSignal): Promise<ComplianceEvidence | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureAdminToken(signal);
      if (!token) {
        return null;
      }
      return complianceEvidence(token, { base, signal });
    },
    [ensureAdminToken],
  );

  /** LOCAL live deployment/license/usage numbers (CAP_DIRECTORY_ADMIN). Fails soft. */
  const fetchDeploymentStats = useCallback(
    async (signal?: AbortSignal): Promise<DeploymentStats | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureAdminToken(signal);
      if (!token) {
        return null;
      }
      return deploymentStats(token, { base, signal });
    },
    [ensureAdminToken],
  );

  /** One page of the decision-history query (date range + multi-filter + cursor). */
  const fetchDecisionsPage = useCallback(
    async (query: DecisionQuery, signal?: AbortSignal): Promise<DecisionPage | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureAdminToken(signal);
      if (!token) {
        return null;
      }
      return queryDecisions(token, { base, signal }, query);
    },
    [ensureAdminToken],
  );

  const fetchRevokedPrincipals = useCallback(
    async (signal?: AbortSignal): Promise<string[] | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureAdminToken(signal);
      if (!token) {
        return null;
      }
      return revokedPrincipals(token, { base, signal });
    },
    [ensureAdminToken],
  );

  const fetchQuarantine = useCallback(
    async (signal?: AbortSignal): Promise<QuarantinedAgent[] | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureAdminToken(signal);
      if (!token) {
        return null;
      }
      return quarantineRoster(token, { base, signal });
    },
    [ensureAdminToken],
  );

  const fetchCanaries = useCallback(
    async (signal?: AbortSignal): Promise<CanaryDecoy[] | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureAdminToken(signal);
      if (!token) {
        return null;
      }
      return canaryRoster(token, { base, signal });
    },
    [ensureAdminToken],
  );

  const fetchDirectoryRelations = useCallback(
    async (
      filters: RelationFilters = {},
      signal?: AbortSignal,
    ): Promise<RelationRoster | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureAdminToken(signal);
      if (!token) {
        return null;
      }
      return directoryRelations(token, filters, { base, signal });
    },
    [ensureAdminToken],
  );

  /** Force an immediate /v1/version re-check on demand. Fails soft (null). */
  const checkForUpdate = useCallback(
    async (signal?: AbortSignal): Promise<VersionInfo | null> => {
      const base = baseRef.current;
      if (base === null) {
        return null;
      }
      const token = await ensureToken(signal);
      if (!token) {
        return null;
      }
      const info = await fetchVersion(token, { base, signal });
      if (info) {
        setVersion(info);
      }
      return info;
    },
    [ensureToken],
  );

  /** Record one REAL probe observation into the session health ring. */
  const recordTick = useCallback((live: boolean): void => {
    const tick: HealthTick = { t: Date.now(), live, redis: live ? readyRef.current : null };
    setHealthHistory((prev) => [...prev.slice(-(HEALTH_TICKS - 1)), tick]);
  }, []);

  /** Drop all per-connection state (tokens, stream, metrics) — a clean, honest offline. */
  const resetConnectionState = useCallback((): void => {
    baseRef.current = null;
    tokenRef.current = null;
    tokenExpRef.current = null;
    adminTokenRef.current = null;
    adminTokenExpRef.current = null;
    readyRef.current = null;
    rateRef.current = null;
    if (liveRef.current) {
      liveRef.current = false;
      latenciesRef.current = [];
      wormRef.current = 0;
      setLiveStream([]);
      setLiveSnapshot(EMPTY_METRICS);
      setThroughput([]);
      setReady(null);
    }
    setMode('offline');
    setHealth(null);
  }, []);

  // --- Probe loop: /healthz every PROBE_MS; resolves the working base and
  // records one health-history tick per probe. ------------------------------
  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();

    const probe = async (): Promise<void> => {
      // Plug-and-play: when the operator has pinned an endpoint, that endpoint is
      // authoritative — try ONLY it (a bad URL shows offline, never silently falls
      // back to a different gateway). Otherwise auto-detect the usual candidates.
      let candidates: string[];
      if (configuredBase !== null) {
        candidates = [configuredBase];
      } else {
        const known = baseRef.current;
        const fallbacks = [...new Set([API_BASE, ''])];
        candidates =
          known !== null ? [known, ...fallbacks.filter((b) => b !== known)] : fallbacks;
      }
      for (const base of candidates) {
        const info = await healthz({ base, signal: controller.signal });
        if (cancelled) {
          return;
        }
        if (info) {
          baseRef.current = base;
          liveRef.current = true;
          setApiBase(base);
          setHealth(info);
          setMode('live');
          recordTick(true);
          return;
        }
      }
      // Single failed probe flips to offline (clearing per-connection state);
      // the interval keeps retrying quietly.
      resetConnectionState();
      recordTick(false);
    };

    void probe();
    const id = window.setInterval(() => {
      void probe();
    }, PROBE_MS);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
    // Re-run (re-probe immediately) whenever the operator pins/clears an endpoint.
  }, [configuredBase, recordTick, resetConnectionState]);

  /**
   * Plug-and-play: probe an endpoint DIRECTLY; pin it (persisted) only if it answers.
   * No proxy fallback — the pinned base is exactly the address the operator entered,
   * so a failure is real and actionable (node down, wrong host/port, or the gateway
   * hasn't allowed this console's origin — sandbox allows all; production lists them
   * via MCPIP_CONSOLE_ORIGINS).
   */
  const connect = useCallback(async (base: string): Promise<boolean> => {
    const normalized = base.trim().replace(/\/+$/, '');
    const info = await healthz({ base: normalized });
    if (!info) {
      return false;
    }
    try {
      localStorage.setItem(GATEWAY_KEY, normalized);
    } catch {
      /* private mode / storage disabled — session-only pin still works */
    }
    baseRef.current = normalized;
    setConfiguredBase(normalized);
    return true;
  }, []);

  /**
   * Pin (or clear) an operator-supplied bearer. Cached forge-minted tokens are
   * dropped so the next read uses the new identity immediately.
   */
  const setOperatorToken = useCallback((token: string | null): void => {
    const normalized = token && token.trim() ? token.trim() : null;
    try {
      if (normalized === null) {
        localStorage.removeItem(OPERATOR_TOKEN_KEY);
      } else {
        localStorage.setItem(OPERATOR_TOKEN_KEY, normalized);
      }
    } catch {
      /* private mode / storage disabled — session-only pin still works */
    }
    tokenRef.current = null;
    tokenExpRef.current = null;
    adminTokenRef.current = null;
    adminTokenExpRef.current = null;
    setOperatorTokenState(normalized);
  }, []);

  /** Unpin the endpoint and drop to offline / auto-detect. */
  const disconnect = useCallback((): void => {
    try {
      localStorage.removeItem(GATEWAY_KEY);
    } catch {
      /* ignore */
    }
    resetConnectionState();
    setConfiguredBase(null);
  }, [resetConnectionState]);

  // --- Refresh loop: catalog + audit + readyz every REFRESH_MS while live. -
  useEffect(() => {
    if (mode !== 'live') {
      return;
    }
    let cancelled = false;
    const controller = new AbortController();

    const refresh = async (): Promise<void> => {
      const base = baseRef.current;
      if (base === null) {
        return;
      }
      const opts = { base, signal: controller.signal };
      const token = await ensureToken(controller.signal);
      if (cancelled) {
        return;
      }
      if (token) {
        const [cat, aud, rdy, ver, lic] = await Promise.all([
          fetchCatalog(token, opts),
          auditVerify(token, opts),
          readyz(opts),
          fetchVersion(token, opts),
          fetchLicense(token, opts),
        ]);
        if (cancelled) {
          return;
        }
        // catalog() returns null on failure (vs [] for a genuine empty view);
        // a failed refresh keeps the last-known catalog rather than blanking it.
        if (cat !== null) {
          setCatalogItems(cat);
        }
        setAudit(aud);
        setReady(rdy);
        readyRef.current = rdy.redis === 'up';
        // Version/license likewise keep last-known on a transient failure.
        if (ver !== null) {
          setVersion(ver);
        }
        if (lic !== null) {
          setLicense(lic);
        }
      } else {
        const rdy = await readyz(opts);
        if (cancelled) {
          return;
        }
        setReady(rdy);
        readyRef.current = rdy.redis === 'up';
      }
    };

    void refresh();
    const id = window.setInterval(() => {
      void refresh();
    }, REFRESH_MS);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [mode, ensureToken]);

  // --- Decision feed + metrics scrape: every DECISIONS_POLL_MS while live.
  // The feed is the ONLY source of the stream — the console never manufactures
  // traffic — and /metrics is the ONLY source of fleet-wide numbers. Idle →
  // empty stream and zero counters, honestly. --------------------------------
  useEffect(() => {
    if (mode !== 'live') {
      return;
    }
    const controller = new AbortController();
    const tick = (): void => {
      void refreshDecisions(controller.signal);
      void refreshMetrics(controller.signal);
    };
    tick();
    const id = window.setInterval(tick, DECISIONS_POLL_MS);
    return () => {
      controller.abort();
      window.clearInterval(id);
    };
  }, [mode, refreshDecisions, refreshMetrics]);

  const apiHost = useMemo(() => hostOf(apiBase), [apiBase]);

  /** Identity provenance, derived from real observations only (never guessed). */
  const identitySource: GatewayLive['identitySource'] = operatorToken
    ? 'operator-token'
    : devForgeOk === true
      ? 'sandbox-forge'
      : 'none';
  /**
   * A production gateway is connected (the forge answered 404) and no operator
   * token is pinned — so the live panels cannot populate. The UI shows this as a
   * prompt for a token instead of an unexplained empty console.
   */
  const needsOperatorToken = devForgeOk === false && operatorToken === null;

  if (mode === 'live') {
    return {
      mode,
      apiBase,
      apiHost,
      tenant,
      health,
      ready,
      audit,
      catalog: catalogItems,
      stream: liveStream,
      metrics: liveSnapshot,
      healthHistory,
      throughputHistory: throughput,
      version,
      license,
      authorizeSkill,
      completeStepUp,
      fetchDecisions,
      fetchDecisionsPage,
      fetchProof,
      fetchAuditAttestation,
      fetchComplianceEvidence,
      fetchDeploymentStats,
      ensureAdminToken,
      fetchRevokedPrincipals,
      fetchQuarantine,
      fetchCanaries,
      fetchDirectoryRelations,
      checkForUpdate,
      configuredBase,
      connect,
      disconnect,
      identitySource,
      setOperatorToken,
      needsOperatorToken,
    };
  }

  return {
    mode,
    apiBase,
    apiHost,
    tenant: null,
    health: null,
    ready: null,
    audit: null,
    catalog: [],
    // Offline is honestly EMPTY — no fabricated telemetry. Panels render their
    // real "no gateway connected" empty states; only the health ring keeps its
    // REAL (offline) probe observations.
    stream: [],
    metrics: EMPTY_METRICS,
    healthHistory,
    throughputHistory: [],
    version: null,
    license: null,
    authorizeSkill,
    completeStepUp,
    fetchDecisions,
    fetchDecisionsPage,
    fetchProof,
    fetchAuditAttestation,
    fetchComplianceEvidence,
    fetchDeploymentStats,
    ensureAdminToken,
    fetchRevokedPrincipals,
    fetchQuarantine,
    fetchCanaries,
    fetchDirectoryRelations,
    checkForUpdate,
    configuredBase,
    connect,
    disconnect,
    identitySource,
    setOperatorToken,
    needsOperatorToken,
  };
}
