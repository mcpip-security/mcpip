/* ---------------------------------------------------------------------------
   WORM Audit Ledger — data layer.

   • SESSION RING BUFFER. The ledger runs its OWN poll of the operator feed
     (/v1/admin/decisions/recent at the server's 200-row cap — not the Command
     Center's short ticker) and accumulates rows in a module-level buffer keyed
     by correlation_id, so an event that rotates out of the gateway's bounded
     tail stays inspectable for the rest of the console session (and across
     view remounts). This is honestly a CONSOLE PROJECTION: it holds what this
     session OBSERVED — seeded with the newest ≤200 rows at connect — never
     the full ledger. The authoritative record is the gateway's signed
     Merkle-epoch chain (`mcpip export-audit`). Offline or on a gateway switch
     the buffer resets to honestly empty; nothing is fabricated, ever.

   • REAL PER-EVENT PROOFS. Feed rows carry the WORM `event_id`, which keys
     GET /v1/audit/proof/{event_id}. The returned proof is then RE-VERIFIED IN
     THIS BROWSER: WebCrypto SHA-256 over the sealed record and the sibling
     path — using the engine's domain-separation prefixes, pinned byte-for-byte
     from audit/merkle.py — must reproduce the signed epoch root. The console
     cannot check the Ed25519 chain signature itself (it holds no audit public
     key); that stays with /v1/audit/verify (sandbox) or the external verifier
     (production), and the UI says exactly that.
--------------------------------------------------------------------------- */

import { useCallback, useEffect, useMemo, useState, useSyncExternalStore } from 'react';
import { auditVerify, forensicRead, mintDevToken } from './api';
import type { AuditVerifyResult, DevTokenClaims, RecentDecision } from './api';
import type { ForensicRecord, InclusionProof } from './types';
import type { GatewayLive } from './useGatewayLive';
import { CAP_FORENSIC_READ } from './protocol';

/* --------------------------------------------------------------------------
   Row model — a thin wrapper over the VERBATIM wire projection. The inspector
   and the export render `projection` untouched, so "only real fields" is
   structural, not a convention.
-------------------------------------------------------------------------- */

/**
 * Coarse display status derived from REAL enum values only: `decision` plus
 * the deny reasons the tripwire pipeline emits (interfaces.py DenyReason).
 */
export type LedgerStatus = 'allow' | 'deny' | 'stepup' | 'canary' | 'quarantine';

export const STATUS_META: Record<
  LedgerStatus,
  { label: string; tone: 'verified' | 'denied' | 'staged' }
> = {
  allow: { label: 'ALLOW', tone: 'verified' },
  deny: { label: 'DENY', tone: 'denied' },
  stepup: { label: 'STEP-UP', tone: 'staged' },
  canary: { label: 'CANARY TRIP', tone: 'denied' },
  quarantine: { label: 'QUARANTINED', tone: 'denied' },
};

/** Chip display order — a complete, disjoint partition of the feed rows. */
export const ALL_STATUSES: ReadonlyArray<LedgerStatus> = [
  'allow',
  'deny',
  'stepup',
  'canary',
  'quarantine',
];

export interface LedgerRow {
  /** Buffer key — the decision's correlation id (unique per authorize call). */
  key: string;
  /** The VERBATIM whitelist projection as served by the gateway. */
  projection: RecentDecision;
  /** Epoch ms derived from the projection's timestamp_ns (sort/display only). */
  ts: number;
  status: LedgerStatus;
}

function statusOf(d: RecentDecision): LedgerStatus {
  if (d.decision === 'allow') return 'allow';
  if (d.deny_reason === 'pin_required') return 'stepup';
  if (d.deny_reason === 'canary_tripped') return 'canary';
  if (d.deny_reason === 'agent_quarantined') return 'quarantine';
  return 'deny';
}

function toRow(d: RecentDecision): LedgerRow {
  return {
    key: d.correlation_id,
    projection: d,
    ts: Math.round(d.timestamp_ns / 1_000_000),
    status: statusOf(d),
  };
}

/* --------------------------------------------------------------------------
   Module-level session store. Lives OUTSIDE React so the accumulated buffer
   survives view/subtab remounts (App remounts the view per navigation); it is
   still strictly session-scoped — a reload starts empty, offline resets it.
-------------------------------------------------------------------------- */

/** Deep-read poll: the server clamps limit to 1..200 — ask for the max. */
const FEED_LIMIT = 200;
const LEDGER_POLL_MS = 3000;
/** Buffer cap — evicts the LOWEST worm_sequence rows once exceeded. */
const RING_CAPACITY = 5000;

export type FeedState = 'waiting' | 'ok' | 'unavailable';

export interface LedgerSnapshot {
  /** All session-observed rows, worm_sequence DESC (the real total order). */
  rows: ReadonlyArray<LedgerRow>;
  /** When this connection's accumulation began (epoch ms), or null. */
  observedSince: number | null;
  feedState: FeedState;
}

const EMPTY_SNAPSHOT: LedgerSnapshot = { rows: [], observedSince: null, feedState: 'waiting' };

const store: {
  /** The gateway base the buffer belongs to — a switch must never mix ledgers. */
  base: string | null;
  buffer: Map<string, LedgerRow>;
  snapshot: LedgerSnapshot;
  listeners: Set<() => void>;
} = { base: null, buffer: new Map(), snapshot: EMPTY_SNAPSHOT, listeners: new Set() };

function notify(): void {
  for (const listener of store.listeners) listener();
}

function resetStore(base: string | null): void {
  store.base = base;
  store.buffer = new Map();
  store.snapshot = EMPTY_SNAPSHOT;
  notify();
}

function setFeedState(feedState: FeedState): void {
  if (store.snapshot.feedState === feedState) return;
  store.snapshot = { ...store.snapshot, feedState };
  notify();
}

/** Fold one poll into the buffer; publishes a new snapshot only on change. */
function mergeFetched(fetched: ReadonlyArray<RecentDecision>): void {
  const observedSince = store.snapshot.observedSince ?? Date.now();
  let changed =
    store.snapshot.feedState !== 'ok' || store.snapshot.observedSince === null;
  for (const d of fetched) {
    const prev = store.buffer.get(d.correlation_id);
    // Same seq + event id ⇒ the identical WORM row; skip to avoid churn.
    if (
      prev &&
      prev.projection.worm_sequence === d.worm_sequence &&
      prev.projection.event_id === d.event_id
    ) {
      continue;
    }
    store.buffer.set(d.correlation_id, toRow(d));
    changed = true;
  }
  if (store.buffer.size > RING_CAPACITY) {
    const oldest = [...store.buffer.values()]
      .sort((a, b) => a.projection.worm_sequence - b.projection.worm_sequence)
      .slice(0, store.buffer.size - RING_CAPACITY);
    for (const row of oldest) store.buffer.delete(row.key);
    changed = true;
  }
  if (!changed) return;
  const rows = [...store.buffer.values()].sort(
    (a, b) => b.projection.worm_sequence - a.projection.worm_sequence,
  );
  store.snapshot = { rows, observedSince, feedState: 'ok' };
  notify();
}

function subscribe(listener: () => void): () => void {
  store.listeners.add(listener);
  return () => {
    store.listeners.delete(listener);
  };
}

function getSnapshot(): LedgerSnapshot {
  return store.snapshot;
}

/* --------------------------------------------------------------------------
   The ledger hook — polling, filtering, export.
-------------------------------------------------------------------------- */

export interface LedgerFilters {
  query: string;
  statuses: ReadonlySet<LedgerStatus>;
  alias: string; // '' = all
  agent: string; // '' = all
  reason: string; // '' = all deny reasons
}

export interface UseWormLedger {
  /** Filtered rows, newest-first by worm_sequence. */
  rows: ReadonlyArray<LedgerRow>;
  /** Total rows in the session buffer (pre-filter). */
  observedCount: number;
  observedSince: number | null;
  feedState: FeedState;
  /** Distinct values OBSERVED this session — filter options, never invented. */
  aliases: ReadonlyArray<string>;
  agents: ReadonlyArray<string>;
  reasons: ReadonlyArray<{ reason: string; count: number }>;
  filters: LedgerFilters;
  hasActiveFilters: boolean;
  setQuery: (q: string) => void;
  setAlias: (alias: string) => void;
  setAgent: (agent: string) => void;
  setReason: (reason: string) => void;
  toggleStatus: (s: LedgerStatus) => void;
  clearFilters: () => void;
  /** Download the WHOLE session buffer as JSONL (see header line for provenance). */
  exportJsonl: () => void;
}

function downloadBlob(filename: string, mime: string, content: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function useWormLedger(gateway: GatewayLive): UseWormLedger {
  const { mode, apiBase, apiHost, fetchDecisions } = gateway;
  const snapshot = useSyncExternalStore(subscribe, getSnapshot);

  const [query, setQuery] = useState('');
  const [alias, setAlias] = useState('');
  const [agent, setAgent] = useState('');
  const [reason, setReason] = useState('');
  const [statuses, setStatuses] = useState<ReadonlySet<LedgerStatus>>(
    () => new Set(ALL_STATUSES),
  );

  // Own poll loop. Offline (or a base switch) resets the buffer FIRST — the
  // empty state must be honest, and two gateways' ledgers must never mix.
  useEffect(() => {
    if (mode !== 'live') {
      if (store.base !== null || store.snapshot !== EMPTY_SNAPSHOT) {
        resetStore(null);
      }
      return;
    }
    if (store.base !== apiBase) {
      resetStore(apiBase);
    }
    let cancelled = false;
    const controller = new AbortController();
    const poll = async (): Promise<void> => {
      const fetched = await fetchDecisions(FEED_LIMIT, controller.signal);
      if (cancelled) return;
      if (fetched === null) {
        // Feed read failed (prod without an admin credential, or transient):
        // flag it but KEEP the already-observed buffer — those reads were real.
        setFeedState('unavailable');
        return;
      }
      mergeFetched(fetched);
    };
    void poll();
    const id = window.setInterval(() => {
      void poll();
    }, LEDGER_POLL_MS);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [mode, apiBase, fetchDecisions]);

  const aliases = useMemo(() => {
    const set = new Set<string>();
    for (const r of snapshot.rows) {
      if (r.projection.alias) set.add(r.projection.alias);
    }
    return [...set].sort();
  }, [snapshot.rows]);

  const agents = useMemo(() => {
    const set = new Set<string>();
    for (const r of snapshot.rows) {
      if (r.projection.agent_id) set.add(r.projection.agent_id);
    }
    return [...set].sort();
  }, [snapshot.rows]);

  const reasons = useMemo(() => {
    const counts = new Map<string, number>();
    for (const r of snapshot.rows) {
      const dr = r.projection.deny_reason;
      if (dr) counts.set(dr, (counts.get(dr) ?? 0) + 1);
    }
    return [...counts.entries()]
      .map(([value, count]) => ({ reason: value, count }))
      .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason));
  }, [snapshot.rows]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return snapshot.rows.filter((r) => {
      if (!statuses.has(r.status)) return false;
      const p = r.projection;
      if (alias && p.alias !== alias) return false;
      if (agent && p.agent_id !== agent) return false;
      if (reason && p.deny_reason !== reason) return false;
      if (q) {
        const hay = `${p.correlation_id} ${p.event_id ?? ''} ${p.alias ?? ''} ${
          p.agent_id ?? ''
        } ${p.deny_reason ?? ''} ${p.transaction_ref ?? ''}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [snapshot.rows, statuses, alias, agent, reason, query]);

  const toggleStatus = useCallback((s: LedgerStatus) => {
    setStatuses((prev) => {
      const next = new Set(prev);
      if (next.has(s)) {
        next.delete(s);
      } else {
        next.add(s);
      }
      return next;
    });
  }, []);

  const clearFilters = useCallback(() => {
    setQuery('');
    setAlias('');
    setAgent('');
    setReason('');
    setStatuses(new Set(ALL_STATUSES));
  }, []);

  // ONE honest export: the session-observed projection rows VERBATIM (ledger
  // order), prefixed by a self-describing provenance line — explicitly a
  // console projection, never a substitute for `mcpip export-audit`.
  const exportJsonl = useCallback(() => {
    const ordered = [...snapshot.rows].sort(
      (a, b) => a.projection.worm_sequence - b.projection.worm_sequence,
    );
    const header = {
      kind: 'mcpip.console.session_projection',
      generated_at: new Date().toISOString(),
      gateway: mode === 'live' ? apiHost : 'offline',
      source: 'GET /v1/admin/decisions/recent (whitelist projection)',
      observed_since:
        snapshot.observedSince !== null
          ? new Date(snapshot.observedSince).toISOString()
          : null,
      rows: ordered.length,
      note:
        'Rows this console session observed from the operator feed — a bounded ' +
        'projection, NOT the ledger (timestamp_ns is at IEEE-754 precision). ' +
        'The authoritative record is the signed WORM epoch chain; export it ' +
        'with `mcpip export-audit`.',
    };
    const lines = [
      JSON.stringify(header),
      ...ordered.map((r) => JSON.stringify(r.projection)),
    ];
    downloadBlob(
      `mcpip-session-projection-${ordered.length}.jsonl`,
      'application/x-ndjson',
      lines.join('\n') + '\n',
    );
  }, [snapshot.rows, snapshot.observedSince, mode, apiHost]);

  const hasActiveFilters =
    query.trim() !== '' ||
    alias !== '' ||
    agent !== '' ||
    reason !== '' ||
    statuses.size !== ALL_STATUSES.length;

  return {
    rows,
    observedCount: snapshot.rows.length,
    observedSince: snapshot.observedSince,
    feedState: snapshot.feedState,
    aliases,
    agents,
    reasons,
    filters: { query, statuses, alias, agent, reason },
    hasActiveFilters,
    setQuery,
    setAlias,
    setAgent,
    setReason,
    toggleStatus,
    clearFilters,
    exportJsonl,
  };
}

/* --------------------------------------------------------------------------
   Inclusion proofs — fetch + INDEPENDENT in-browser recomputation.
-------------------------------------------------------------------------- */

/*
 * Domain-separation prefixes, pinned byte-for-byte from audit/merkle.py:
 *   _DOMAIN_LEAF = b"MCPIP:WORM:LEAF:v1\x00"
 *   _DOMAIN_NODE = b"MCPIP:WORM:NODE:v1\x01"
 * leaf  = SHA-256(DOMAIN_LEAF ‖ utf8(record))
 * fold  = SHA-256(DOMAIN_NODE ‖ left ‖ right)   (side 'L' ⇒ sibling is left)
 * A drifted byte here silently turns every real proof into a "mismatch", so
 * the backend file is authoritative — never this mirror.
 */
function domainPrefix(tag: string, separator: number): Uint8Array {
  const text = new TextEncoder().encode(tag);
  const out = new Uint8Array(text.length + 1);
  out.set(text, 0);
  out[text.length] = separator;
  return out;
}

const DOMAIN_LEAF = domainPrefix('MCPIP:WORM:LEAF:v1', 0x00);
const DOMAIN_NODE = domainPrefix('MCPIP:WORM:NODE:v1', 0x01);

function concatBytes(...parts: ReadonlyArray<Uint8Array>): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

const DIGEST_HEX_RE = /^[0-9a-f]{64}$/i;

/** Strict 32-byte digest parse — a malformed sibling FAILS the proof (closed). */
function digestBytes(hex: string): Uint8Array {
  if (!DIGEST_HEX_RE.test(hex)) {
    throw new TypeError('malformed 32-byte digest hex');
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

export interface LocalProofCheck {
  /**
   * 'match'        — this browser reproduced the signed epoch root.
   * 'mismatch'     — recomputation FAILED (wrong root or malformed path):
   *                  the proof does not verify. Fail closed.
   * 'unverifiable' — environment only (no WebCrypto): nothing recomputed,
   *                  no verdict claimed.
   */
  verdict: 'match' | 'mismatch' | 'unverifiable';
  /** Lowercase hex root recomputed here, or null when nothing was computed. */
  computedRoot: string | null;
  detail: string;
}

/**
 * Recompute the Merkle path locally: leaf-hash the sealed record, fold the
 * sibling path, compare against the signed epoch root. This is a REAL
 * independent check of the gateway's proof — the only trusted inputs are the
 * pinned public domain constants.
 */
export async function recomputeInclusionProof(
  proof: InclusionProof,
): Promise<LocalProofCheck> {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    return {
      verdict: 'unverifiable',
      computedRoot: null,
      detail:
        'WebCrypto is unavailable in this context (insecure origin?) — the path was not recomputed',
    };
  }
  try {
    let h = await sha256(
      concatBytes(DOMAIN_LEAF, new TextEncoder().encode(proof.record)),
    );
    for (const hop of proof.proof) {
      const side = hop[0];
      const sibling = digestBytes(hop[1]);
      if (side === 'L') {
        h = await sha256(concatBytes(DOMAIN_NODE, sibling, h));
      } else if (side === 'R') {
        h = await sha256(concatBytes(DOMAIN_NODE, h, sibling));
      } else {
        throw new TypeError('malformed path side');
      }
    }
    const computedRoot = bytesToHex(h);
    if (computedRoot === proof.merkle_root.toLowerCase()) {
      return {
        verdict: 'match',
        computedRoot,
        detail: `root reconstructed from the sealed record and the ${proof.proof.length}-hop sibling path`,
      };
    }
    return {
      verdict: 'mismatch',
      computedRoot,
      detail: 'the recomputed root does not equal the signed epoch root',
    };
  } catch {
    return {
      verdict: 'mismatch',
      computedRoot: null,
      detail: 'the proof path could not be recomputed (malformed sibling data)',
    };
  }
}

/** One per-event proof attempt, as the inspector renders it. */
export type ProofRun =
  | { phase: 'fetching' }
  | { phase: 'proved'; proof: InclusionProof; local: LocalProofCheck }
  | { phase: 'unsealed'; detail: string }
  | { phase: 'unavailable'; detail: string };

/**
 * Fetch the inclusion proof for one WORM event id and locally re-verify it.
 * 'unsealed' means the gateway answered 404 — on a sandbox node the event is
 * not yet sealed into a signed epoch; a production node never mounts the
 * endpoint at all (the view renders the external-verifier explanation).
 */
export async function runInclusionProof(
  gateway: GatewayLive,
  eventId: string,
): Promise<ProofRun> {
  const result = await gateway.fetchProof(eventId);
  if (result.status === 'verified' && result.proof) {
    return {
      phase: 'proved',
      proof: result.proof,
      local: await recomputeInclusionProof(result.proof),
    };
  }
  if (result.status === 'unsealed') {
    return { phase: 'unsealed', detail: result.detail };
  }
  return { phase: 'unavailable', detail: result.detail };
}

/* --------------------------------------------------------------------------
   Forensic reconstruction — the CAP_FORENSIC_READ investigator side-channel.

   Distinct from the inclusion proof above: that proves a decision was recorded;
   this reconstructs the REAL QUERY the agent sent (alias + normalized, secret-
   scrubbed arguments + non-secret identity context) that the opaque agent wire
   and the arguments-omitting decision feed never surface. It is an ADMIN /
   investigator affordance ONLY — the console mints a dedicated credential
   carrying CAP_FORENSIC_READ (which is DISTINCT from CAP_DIRECTORY_ADMIN and
   which no agent token holds), and the gateway WORM-audits every read before it
   discloses anything. Nothing here is fabricated: a gateway with capture off, or
   an expired/never-captured correlation id, resolves to an HONEST 'absent'
   state, never a synthesized payload.
-------------------------------------------------------------------------- */

/** One per-event forensic reconstruction attempt, as the inspector renders it. */
export type ForensicRun =
  | { phase: 'fetching' }
  | { phase: 'found'; record: ForensicRecord }
  | { phase: 'absent' }
  | { phase: 'denied' }
  | { phase: 'unavailable'; detail: string };

/**
 * Mint a short-lived investigator credential carrying CAP_FORENSIC_READ (scoped
 * to the gateway's tenant so the tenant-bound store namespace + AAD line up) and
 * fetch the reconstructed payload for one correlation id. In production the
 * sandbox minter 404s — there is no CAP_FORENSIC_READ credential to mint over
 * HTTP — so the attempt lands honestly on 'unavailable', exactly like the
 * chain-verify and proof runners when the sandbox affordances are absent.
 */
export async function runForensicRead(
  gateway: GatewayLive,
  correlationId: string,
): Promise<ForensicRun> {
  if (gateway.mode !== 'live') {
    return { phase: 'unavailable', detail: 'no gateway connected' };
  }
  let token: string;
  try {
    // A dedicated forensic identity — NOT the CAP_DIRECTORY_ADMIN feed token —
    // so the console exercises the exact least-privilege separation the gateway
    // enforces (directory admin does not confer raw-payload read).
    const claims: DevTokenClaims = {
      agent_id: 'agent-forensic-investigator',
      capabilities: [CAP_FORENSIC_READ],
    };
    if (gateway.tenant) {
      claims.tenant_id = gateway.tenant;
    }
    token = await mintDevToken(claims, { base: gateway.apiBase });
  } catch {
    return {
      phase: 'unavailable',
      detail:
        'this gateway will not mint a CAP_FORENSIC_READ credential over HTTP ' +
        '(production mints none — an investigator uses a real granted token there)',
    };
  }
  const result = await forensicRead(token, correlationId, { base: gateway.apiBase });
  switch (result.status) {
    case 'found':
      return { phase: 'found', record: result.record };
    case 'absent':
      return { phase: 'absent' };
    case 'denied':
      return { phase: 'denied' };
    default:
      return { phase: 'unavailable', detail: result.detail };
  }
}

/* --------------------------------------------------------------------------
   Chain verification — the on-demand /v1/audit/verify runner.
-------------------------------------------------------------------------- */

export interface ChainRun {
  state: 'idle' | 'running' | 'done' | 'unavailable';
  result: AuditVerifyResult | null;
  /** Wall clock of the last completed attempt (epoch ms). */
  checkedAt: number | null;
}

export interface UseChainVerify {
  chain: ChainRun;
  run: () => Promise<void>;
}

/**
 * Manual chain check. Beyond explicitness it has one REAL side effect the 5s
 * auto-poll shares: the endpoint force-closes the open tail epoch before
 * verifying, so a decision made moments ago becomes provable right after.
 * Mints a FRESH sandbox token per run (never a cached, possibly-stale one);
 * in production the minter 404s and the state lands on 'unavailable' — the
 * honest answer, rendered as the external-verifier explanation.
 */
export function useChainVerify(gateway: GatewayLive): UseChainVerify {
  const { mode, apiBase } = gateway;
  const [chain, setChain] = useState<ChainRun>({
    state: 'idle',
    result: null,
    checkedAt: null,
  });

  const run = useCallback(async (): Promise<void> => {
    if (mode !== 'live') {
      setChain({ state: 'unavailable', result: null, checkedAt: Date.now() });
      return;
    }
    setChain((prev) => ({ ...prev, state: 'running' }));
    try {
      const token = await mintDevToken({}, { base: apiBase });
      const result = await auditVerify(token, { base: apiBase });
      setChain(
        result === null
          ? { state: 'unavailable', result: null, checkedAt: Date.now() }
          : { state: 'done', result, checkedAt: Date.now() },
      );
    } catch {
      setChain({ state: 'unavailable', result: null, checkedAt: Date.now() });
    }
  }, [mode, apiBase]);

  return { chain, run };
}
