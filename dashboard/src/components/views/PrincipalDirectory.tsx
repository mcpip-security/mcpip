import {
  Fragment,
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
  useSyncExternalStore,
} from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Ban,
  Bot,
  Building2,
  Check,
  ChevronRight,
  Clock,
  Copy,
  Fingerprint,
  GripVertical,
  KeyRound,
  Loader2,
  MousePointerClick,
  Network,
  Pencil,
  Plus,
  PlugZap,
  RotateCcw,
  ScrollText,
  ShieldAlert,
  ShieldCheck,
  Timer,
  Trash2,
  UserRound,
  Users,
  X,
} from 'lucide-react';
import type { GatewayLive } from '../../lib/useGatewayLive';
import { issueCompartmentGrant } from '../../lib/grantCeremony';
import { setPrincipalRevocation } from '../../lib/revokeCeremony';
import { catalog, mintDevToken } from '../../lib/api';
import type { DevTokenClaims, LicenseInfo, RelationEdge } from '../../lib/api';
import { loadDirectory, saveDirectory } from '../../lib/directorySync';
import {
  CAP_COMPARTMENT_GRANT,
  CAP_COMPARTMENT_REVOKE,
  CAP_DIRECTORY_ADMIN,
} from '../../lib/protocol';
import { grantCapabilityFor, isUuid } from '../../lib/uuidv5';
import { newCompartmentUuid, slugifyTenant, useCompanyConfig } from '../../lib/companyConfig';
import type { CompanyConfig, CompanyTeam } from '../../lib/companyConfig';
import { formatDateTime, prefersReducedMotion, truncateId } from '../../lib/format';
import { LicenseTerminal } from '../LicenseTerminal';
import { Badge, Detail, EmptyState, Field, Input, Panel, PanelHeader, Select } from '../ui';

/* ---------------------------------------------------------------------------
   Directory — truthful, company-scoped IAM over the gateway's REAL surfaces.

     hierarchy    — the operator's org chart (OU → Team → Principal), persisted
                    via GET/PUT /v1/directory under the operator's REAL tenant.
                    Per-principal revocation state is RECONCILED from
                    GET /v1/admin/principals/revoked (the gateway is
                    authoritative — local state is never trusted); revoke /
                    reactivate ride the real kill-switch endpoints. Temporary
                    access runs the REAL skill_compartment_grant step-up
                    ceremony for any resolvable compartment — a failed ceremony
                    reports its denial, never a fake countdown.
     licensing    — mint a REAL principal via the sandbox IdP, prove its blast
                    radius by enumerating /v1/catalog with ITS token, revoke it
                    live. Production mints offline (the terminal's `ceremony`).
     entitlements — the real entitlement surface: the boot-verified license
                    document (/v1/license) with what each entitlement actually
                    gates, and the engine-pinned governance capability UUIDs
                    (protocol.ts) with the surfaces they unlock.

   Nothing here fabricates identity data: no invented key bindings, no
   hardcoded PoP badges, no client-only grants. The directory holds metadata;
   credentials are the IdP's alone; every displayed status traces to a gateway
   response or an engine-pinned constant.
--------------------------------------------------------------------------- */

/** House curve — slow, expensive, never bouncy (charter EASE). */
const EASE = [0.32, 0.72, 0, 1] as const;

const LABEL = 'text-[10.5px] font-medium uppercase tracking-[0.1em] text-slate-500';

function navigateToConnection(): void {
  window.dispatchEvent(
    new CustomEvent('mcpip:navigate', { detail: { view: 'gateway', subtab: 'connection' } }),
  );
}

function ConnectCta(): JSX.Element {
  return (
    <button type="button" onClick={navigateToConnection} className="btn-primary">
      <PlugZap size={13} /> Connect a gateway
    </button>
  );
}

/** Local wall-clock HH:MM:SS — grant-expiry stamps and reconcile times. */
function fmtClock(ms: number): string {
  const d = new Date(ms);
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** Compact TTL: 900 → "15m", 3600 → "1h". */
function fmtTtl(seconds: number): string {
  if (seconds % 3600 === 0) return `${seconds / 3600}h`;
  if (seconds % 60 === 0) return `${seconds / 60}m`;
  return `${seconds}s`;
}

/**
 * Decode a JWT's payload claims — display truth for licensed principals comes
 * from the REAL minted token, never from form state. Returns null on any
 * malformed input (no partial guesses).
 */
function decodeJwtClaims(jwt: string): Record<string, unknown> | null {
  try {
    const payload = jwt.split('.')[1];
    if (!payload) return null;
    const parsed: unknown = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------ session stores */

/**
 * Module-scoped session records — the console's only memory of ceremonies it
 * ran. The gateway serves no grant/license roster to read back (grants live in
 * Redis with EX=ttl; identities live in the IdP), so these survive subtab
 * remounts (the shell keys the view wrapper by subtab) but NOT a reload — and
 * the UI says so instead of pretending they are server state.
 */
interface SessionStore<T> {
  get: () => T;
  set: (updater: (prev: T) => T) => void;
  subscribe: (onChange: () => void) => () => void;
}

function createSessionStore<T>(initial: T): SessionStore<T> {
  let state = initial;
  const listeners = new Set<() => void>();
  return {
    get: () => state,
    set: (updater) => {
      state = updater(state);
      for (const l of listeners) l();
    },
    subscribe: (onChange) => {
      listeners.add(onChange);
      return () => {
        listeners.delete(onChange);
      };
    },
  };
}

function useSessionStore<T>(store: SessionStore<T>): T {
  return useSyncExternalStore(store.subscribe, store.get);
}

/** One committed compartment grant — every field is from the real ceremony. */
interface SessionGrant {
  id: string;
  granteeAgentId: string;
  compartmentUuid: string;
  compartmentLabel: string;
  ttlSeconds: number;
  /** Console clock at commit; expiry ≈ issuedAtMs + ttl (Redis is authoritative). */
  issuedAtMs: number;
  /** Committing transaction_ref of the consuming /v1/authorize (200). */
  reference: string;
  wormSequence: number;
}

/** One principal licensed this session — token + claims are the REAL mint. */
interface SessionLicense {
  agentId: string;
  tenant: string;
  compartmentUuid: string | null;
  compartmentLabel: string;
  grantOfficer: boolean;
  /** The REAL minted JWT (sandbox IdP) — shown once in full, then its tail. */
  token: string;
  /** Claims decoded from that token — never re-stated from form inputs. */
  claims: Record<string, unknown> | null;
  /** Aliases the new identity actually enumerates (real /v1/catalog), null = read failed. */
  visibleAliases: string[] | null;
  mintedAtMs: number;
  status: 'active' | 'revoked';
}

const grantStore = createSessionStore<ReadonlyArray<SessionGrant>>([]);
const licenseStore = createSessionStore<ReadonlyArray<SessionLicense>>([]);

/* -------------------------------------------------------------- descriptors */

/** JWT `role` claim options — DESCRIPTIVE ONLY; the gateway authorizes nothing on it. */
type RoleId = 'orchestrator' | 'operator' | 'analyst' | 'auditor' | 'service';

const ROLE_LABEL: Record<RoleId, string> = {
  orchestrator: 'Orchestrator',
  operator: 'Operator',
  analyst: 'Analyst',
  auditor: 'Auditor',
  service: 'Service',
};

/** The agent's vendor/framework — becomes a prefix of the licensed agent id so
 *  every WORM decision attributes the call to its framework. */
const VENDORS = [
  { value: 'openai', label: 'OpenAI' },
  { value: 'anthropic', label: 'Anthropic' },
  { value: 'gemini', label: 'Gemini' },
  { value: 'bedrock', label: 'Bedrock' },
  { value: 'mcp', label: 'MCP' },
  { value: 'raw', label: 'raw' },
] as const;
type VendorId = (typeof VENDORS)[number]['value'];

/* ---------------------------------------------------------------- org model */

/**
 * A directory principal — ONLY real fields. The fabricated key-binding /
 * sender-constrained metadata of the old console is gone: the directory never
 * holds credential material, so it must not display any.
 */
interface AgentPrincipal {
  id: string;
  /** The (tenant, agent_id) the gateway's kill-switch and WORM records key on. */
  agentId: string;
  /** Reconciled from GET /v1/admin/principals/revoked while live. */
  status: 'active' | 'revoked';
  /** 'agent' = licensed software agent; 'user' = human principal. Absent = 'agent'. */
  kind?: 'agent' | 'user';
}
interface Team {
  id: string;
  label: string;
  /** Compartment UUID (blast radius). Full UUIDs are grantable; legacy docs may
   *  hold truncated display forms — rendered as-is, excluded from ceremonies. */
  compartment: string;
  agents: AgentPrincipal[];
}
interface OrgUnit {
  id: string;
  label: string;
  /** Gateway tenant this org unit maps to — the scope of a real revocation. */
  tenant: string;
  teams: Team[];
}

let _seq = 1000;
const uid = (p: string): string => `${p}-${(_seq += 1).toString(36)}`;

/**
 * Normalize a loaded /v1/directory document into the REAL-fields-only shape.
 * Older docs carried fabricated per-principal fields (random key ids, hardcoded
 * PoP flags) — this deliberately drops them, so the next debounced save scrubs
 * the persisted doc too. Malformed nodes are skipped, never guessed at.
 */
function sanitizeOrg(raw: unknown[], fallbackTenant: string): OrgUnit[] {
  const str = (v: unknown, fb: string): string => (typeof v === 'string' && v ? v : fb);
  const out: OrgUnit[] = [];
  for (const u of raw) {
    if (typeof u !== 'object' || u === null) continue;
    const ou = u as Record<string, unknown>;
    const teams: Team[] = [];
    if (Array.isArray(ou.teams)) {
      for (const t of ou.teams) {
        if (typeof t !== 'object' || t === null) continue;
        const team = t as Record<string, unknown>;
        const agents: AgentPrincipal[] = [];
        if (Array.isArray(team.agents)) {
          for (const a of team.agents) {
            if (typeof a !== 'object' || a === null) continue;
            const ag = a as Record<string, unknown>;
            const agentId = str(ag.agentId, '');
            if (!agentId) continue;
            agents.push({
              id: str(ag.id, uid('a')),
              agentId,
              status: ag.status === 'revoked' ? 'revoked' : 'active',
              kind: ag.kind === 'user' ? 'user' : 'agent',
            });
          }
        }
        teams.push({
          id: str(team.id, uid('team')),
          label: str(team.label, 'Team'),
          compartment: str(team.compartment, ''),
          agents,
        });
      }
    }
    out.push({
      id: str(ou.id, uid('ou')),
      label: str(ou.label, 'Org Unit'),
      tenant: str(ou.tenant, fallbackTenant),
      teams,
    });
  }
  return out;
}

/**
 * Seed the org tree from the operator's REAL company config (written by the
 * first-run setup) — no mock data. Teams keep their FULL compartment UUIDs so
 * the grant ceremony can resolve them; rows truncate only at render time.
 * With no config at all, the tree starts blank.
 */
function seedOrgFromCompany(config: CompanyConfig | null): OrgUnit[] {
  if (!config) return [];
  return [
    {
      id: slugifyTenant(config.name) || 'company',
      label: config.name || 'My Company',
      tenant: config.tenant,
      teams: config.teams.map((t) => ({
        id: t.id,
        label: t.name,
        compartment: t.compartment,
        agents: [],
      })),
    },
  ];
}

/* --------------------------------------------------------------- org reducer */

type OrgAction =
  | { type: 'ADD_OU'; tenant: string }
  | { type: 'ADD_TEAM'; ouId: string }
  | { type: 'ADD_AGENT'; teamId: string; kind?: 'agent' | 'user' }
  | { type: 'DELETE_OU'; ouId: string }
  | { type: 'DELETE_TEAM'; teamId: string }
  | { type: 'DELETE_AGENT'; agentId: string }
  | { type: 'MOVE_AGENT'; agentId: string; toTeamId: string }
  | { type: 'SET_STATUS'; agentId: string; status: 'active' | 'revoked' }
  | { type: 'RECONCILE_REVOCATIONS'; revoked: ReadonlyArray<string>; tenant: string }
  | { type: 'RENAME_OU'; ouId: string; label: string }
  | { type: 'RENAME_TEAM'; teamId: string; label: string }
  | { type: 'RENAME_AGENT'; agentId: string; agentIdLabel: string }
  | { type: 'HYDRATE'; org: OrgUnit[] };

function orgReducer(org: OrgUnit[], action: OrgAction): OrgUnit[] {
  switch (action.type) {
    case 'HYDRATE':
      return action.org;
    case 'ADD_OU':
      // Tenant comes from the caller (the operator's company profile) — the old
      // 'tenant-acme' hardcode made revocations from new OUs target a fixture.
      return [...org, { id: uid('ou'), label: 'New Org Unit', tenant: action.tenant, teams: [] }];
    case 'ADD_TEAM':
      // A REAL fresh compartment UUID — resolvable by the grant ceremony and
      // persisted with the doc (never a fake short id).
      return org.map((ou) =>
        ou.id === action.ouId
          ? { ...ou, teams: [...ou.teams, { id: uid('team'), label: 'New Team', compartment: newCompartmentUuid(), agents: [] }] }
          : ou,
      );
    case 'ADD_AGENT': {
      const kind = action.kind ?? 'agent';
      const prefix = kind === 'user' ? 'user' : 'agent';
      return org.map((ou) => ({
        ...ou,
        teams: ou.teams.map((t) =>
          t.id === action.teamId
            ? { ...t, agents: [...t.agents, { id: uid('a'), agentId: `${prefix}-${uid('x').slice(-4)}`, status: 'active' as const, kind }] }
            : t,
        ),
      }));
    }
    case 'DELETE_OU':
      return org.filter((ou) => ou.id !== action.ouId);
    case 'DELETE_TEAM':
      return org.map((ou) => ({ ...ou, teams: ou.teams.filter((t) => t.id !== action.teamId) }));
    case 'DELETE_AGENT':
      return org.map((ou) => ({ ...ou, teams: ou.teams.map((t) => ({ ...t, agents: t.agents.filter((a) => a.id !== action.agentId) })) }));
    case 'SET_STATUS':
      return org.map((ou) => ({ ...ou, teams: ou.teams.map((t) => ({ ...t, agents: t.agents.map((a) => (a.id === action.agentId ? { ...a, status: action.status } : a)) })) }));
    case 'RECONCILE_REVOCATIONS': {
      // The gateway's revoked list is authoritative for the operator's tenant:
      // present ⇒ revoked, absent ⇒ active — regardless of what this document
      // remembers. Returns the SAME reference when nothing changed so the
      // debounced save never churns on a no-op poll.
      const revoked = new Set(action.revoked);
      let changed = false;
      const next = org.map((ou) => {
        if (ou.tenant !== action.tenant) return ou;
        let ouChanged = false;
        const teams = ou.teams.map((t) => {
          let teamChanged = false;
          const agents = t.agents.map((a) => {
            const status: AgentPrincipal['status'] = revoked.has(a.agentId) ? 'revoked' : 'active';
            if (a.status === status) return a;
            teamChanged = true;
            return { ...a, status };
          });
          if (!teamChanged) return t;
          ouChanged = true;
          return { ...t, agents };
        });
        if (!ouChanged) return ou;
        changed = true;
        return { ...ou, teams };
      });
      return changed ? next : org;
    }
    case 'RENAME_OU':
      return org.map((ou) => (ou.id === action.ouId ? { ...ou, label: action.label } : ou));
    case 'RENAME_TEAM':
      return org.map((ou) => ({ ...ou, teams: ou.teams.map((t) => (t.id === action.teamId ? { ...t, label: action.label } : t)) }));
    case 'RENAME_AGENT':
      return org.map((ou) => ({ ...ou, teams: ou.teams.map((t) => ({ ...t, agents: t.agents.map((a) => (a.id === action.agentId ? { ...a, agentId: action.agentIdLabel } : a)) })) }));
    case 'MOVE_AGENT': {
      let moved: AgentPrincipal | null = null;
      const stripped = org.map((ou) => ({
        ...ou,
        teams: ou.teams.map((t) => ({
          ...t,
          agents: t.agents.filter((a) => {
            if (a.id === action.agentId) {
              moved = a;
              return false;
            }
            return true;
          }),
        })),
      }));
      if (!moved) return org;
      const movedAgent: AgentPrincipal = moved;
      return stripped.map((ou) => ({
        ...ou,
        teams: ou.teams.map((t) => (t.id === action.toTeamId ? { ...t, agents: [...t.agents, movedAgent] } : t)),
      }));
    }
    default:
      return org;
  }
}

/* ------------------------------------------------------------ directory sync */

type SyncStatus = 'offline' | 'loading' | 'synced' | 'saving' | 'error';

/**
 * Persist the org tree via GET/PUT /v1/directory when live: load once on
 * connect (sanitized to real fields only), debounce-save on every edit.
 * Non-authoritative metadata — survives sessions/nodes but never mints
 * identity. Offline stays purely local.
 */
function useDirectorySync(
  gateway: GatewayLive,
  org: OrgUnit[],
  dispatch: React.Dispatch<OrgAction>,
  fallbackTenant: string,
): SyncStatus {
  const [status, setStatus] = useState<SyncStatus>('offline');
  const [ready, setReady] = useState(false);
  // The last org state that is known-persisted (loaded doc, or the seed baseline).
  // A save fires only when the live org diverges from this snapshot.
  const lastSavedRef = useRef<string | null>(null);

  // Load once per live session; establish the persisted baseline.
  useEffect(() => {
    if (gateway.mode !== 'live') {
      setReady(false);
      setStatus('offline');
      lastSavedRef.current = null;
      return;
    }
    if (ready) return;
    let cancelled = false;
    const controller = new AbortController();
    setStatus('loading');
    void (async () => {
      const loaded = await loadDirectory(gateway.apiBase, controller.signal);
      if (cancelled) return;
      if (loaded && loaded.orgUnits.length > 0) {
        // Baseline is the RAW stored doc: if sanitizing changed anything (e.g.
        // scrubbing the old fabricated key-binding fields), the very next
        // debounced save persists the cleaned document — a deliberate migration.
        lastSavedRef.current = JSON.stringify(loaded.orgUnits);
        dispatch({ type: 'HYDRATE', org: sanitizeOrg(loaded.orgUnits, fallbackTenant) });
      } else {
        // No saved doc yet — the current tree is the baseline; only edits persist.
        lastSavedRef.current = JSON.stringify(org);
      }
      setReady(true);
      setStatus('synced');
    })();
    return () => {
      cancelled = true;
      controller.abort();
    };
    // `org` intentionally excluded — the baseline is captured once at load.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [gateway.mode, gateway.apiBase, ready, dispatch, fallbackTenant]);

  // Debounced save whenever the tree diverges from the persisted baseline.
  useEffect(() => {
    if (gateway.mode !== 'live' || !ready) return;
    const serialized = JSON.stringify(org);
    if (serialized === lastSavedRef.current) return;
    setStatus('saving');
    const controller = new AbortController();
    const t = window.setTimeout(() => {
      void (async () => {
        // rbac deliberately omitted: the old fixture matrix is gone, so saves
        // also scrub any stored rbac blob (the document is rebuilt whole).
        const ok = await saveDirectory(gateway.apiBase, org, undefined, controller.signal);
        if (ok) {
          lastSavedRef.current = serialized;
        }
        setStatus(ok ? 'synced' : 'error');
      })();
    }, 700);
    return () => {
      controller.abort();
      window.clearTimeout(t);
    };
  }, [org, gateway.mode, gateway.apiBase, ready]);

  return status;
}

/* ---------------------------------------------------- revocation reconciler */

const RECONCILE_MS = 10_000;

interface ReconcileState {
  /** 'none' = first read in flight (or offline); 'ok' = list applied; 'unavailable' = read failing. */
  status: 'none' | 'ok' | 'unavailable';
  atMs: number | null;
}

/**
 * Poll GET /v1/admin/principals/revoked (authoritative, admin-tenant-scoped)
 * and reconcile the tree's per-principal status against it — revocations made
 * out-of-band (API, another console, a lost session) surface here instead of
 * silently rendering as 'active'.
 */
function useRevocationReconcile(
  gateway: GatewayLive,
  tenant: string,
  dispatch: React.Dispatch<OrgAction>,
): { rec: ReconcileState; refresh: () => void } {
  const [rec, setRec] = useState<ReconcileState>({ status: 'none', atMs: null });
  const [nonce, setNonce] = useState(0);
  const { mode, fetchRevokedPrincipals } = gateway;

  useEffect(() => {
    if (mode !== 'live' || tenant === '') {
      setRec({ status: 'none', atMs: null });
      return;
    }
    let cancelled = false;
    const controller = new AbortController();
    const tick = async (): Promise<void> => {
      const revoked = await fetchRevokedPrincipals(controller.signal);
      if (cancelled) return;
      if (revoked === null) {
        setRec({ status: 'unavailable', atMs: Date.now() });
        return;
      }
      dispatch({ type: 'RECONCILE_REVOCATIONS', revoked, tenant });
      setRec({ status: 'ok', atMs: Date.now() });
    };
    void tick();
    const id = window.setInterval(() => {
      void tick();
    }, RECONCILE_MS);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [mode, fetchRevokedPrincipals, tenant, dispatch, nonce]);

  // Bumping the nonce restarts the effect → an immediate re-read (used right
  // after a successful revoke/reactivate so the tree reflects the gateway now).
  const refresh = useCallback((): void => setNonce((n) => n + 1), []);
  return { rec, refresh };
}

/* ---------------------------------------------------------------- root switch */

export function PrincipalDirectory({ gateway, subtab }: { gateway: GatewayLive; subtab: string }): JSX.Element {
  if (subtab === 'licensing') return <Licensing gateway={gateway} />;
  if (subtab === 'entitlements') return <Entitlements gateway={gateway} />;
  return <Hierarchy gateway={gateway} />;
}

/* ------------------------------------------------------------------ hierarchy */

function SyncBadge({ sync }: { sync: SyncStatus }): JSX.Element {
  if (sync === 'offline') {
    return <span className="chip">Local only</span>;
  }
  const map: Record<Exclude<SyncStatus, 'offline'>, { text: string; cls: string; dot: string }> = {
    loading: { text: 'Loading…', cls: 'text-slate-500', dot: 'bg-slate-500' },
    saving: { text: 'Saving…', cls: 'text-staged', dot: 'bg-staged' },
    synced: { text: 'Synced', cls: 'text-verified', dot: 'bg-verified' },
    error: { text: 'Save failed', cls: 'text-denied', dot: 'bg-denied' },
  };
  const m = map[sync];
  return (
    <span className={`inline-flex items-center gap-1.5 text-[11px] font-medium ${m.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.text}
    </span>
  );
}

function ReconcileBadge({ rec, live }: { rec: ReconcileState; live: boolean }): JSX.Element | null {
  if (!live) return null;
  if (rec.status === 'none') {
    return <span className="text-[11px] font-medium text-slate-500">reconciling revocations…</span>;
  }
  if (rec.status === 'unavailable') {
    return (
      <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-staged" title="GET /v1/admin/principals/revoked is not answering — statuses shown are the document's last knowledge, not the gateway's.">
        <ShieldAlert size={11} /> revocation read unavailable
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-500" title="Per-principal status is reconciled from GET /v1/admin/principals/revoked — the gateway is authoritative.">
      <ShieldCheck size={11} className="text-verified" />
      revocations reconciled{' '}
      <span className="tabular font-mono text-[10.5px] text-slate-400">{rec.atMs !== null ? fmtClock(rec.atMs) : ''}</span>
    </span>
  );
}

/** One stat tile — the charter's .metric recipe (19px tabular value). */
function StatTile({
  label,
  value,
  tone = 'ink',
  sub,
}: {
  label: string;
  value: string;
  tone?: 'ink' | 'verified' | 'staged' | 'denied';
  sub?: string;
}): JSX.Element {
  const t =
    tone === 'verified' ? 'text-verified' : tone === 'staged' ? 'text-staged' : tone === 'denied' ? 'text-denied' : 'text-ink';
  return (
    <div className="metric">
      <span className="metric-label">{label}</span>
      <span className={`metric-value truncate ${t}`}>{value}</span>
      {sub !== undefined ? <span className="truncate text-[10.5px] text-slate-500">{sub}</span> : null}
    </div>
  );
}

/** Inline rename field — commits on Enter/blur, cancels on Escape. */
function RenameInput({ value, onSave, onCancel }: { value: string; onSave: (v: string) => void; onCancel: () => void }): JSX.Element {
  const [draft, setDraft] = useState(value);
  return (
    <input
      autoFocus
      value={draft}
      onClick={(e) => e.stopPropagation()}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => {
        const v = draft.trim();
        v ? onSave(v) : onCancel();
      }}
      onKeyDown={(e) => {
        e.stopPropagation();
        if (e.key === 'Enter') {
          const v = draft.trim();
          v ? onSave(v) : onCancel();
        }
        if (e.key === 'Escape') onCancel();
      }}
      className="min-w-0 flex-1 rounded-md border border-ink/30 bg-canvas px-1.5 py-0.5 text-[13px] font-medium text-ink outline-none"
    />
  );
}

function IconBtn({ title, onClick, danger, children }: { title: string; onClick: () => void; danger?: boolean; children: React.ReactNode }): JSX.Element {
  return (
    <button
      type="button"
      title={title}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      className={`inline-flex h-7 w-7 items-center justify-center rounded-lg border border-hairline bg-surface text-slate-400 shadow-card transition-colors hover:bg-canvas ${danger ? 'hover:border-denied/30 hover:text-denied' : 'hover:border-ink/20 hover:text-ink'}`}
    >
      {children}
    </button>
  );
}

function Row({
  depth,
  open,
  expandable,
  onClick,
  icon,
  title,
  meta,
  actions,
}: {
  depth: number;
  open?: boolean;
  expandable?: boolean;
  onClick?: () => void;
  icon: JSX.Element;
  title: React.ReactNode;
  meta?: React.ReactNode;
  actions?: React.ReactNode;
}): JSX.Element {
  return (
    <div className="group flex items-center rounded-md transition-colors hover:bg-canvas" style={{ paddingLeft: `${8 + depth * 20}px` }}>
      <button type="button" onClick={onClick} className="flex min-w-0 flex-1 items-center gap-2 px-2 py-1.5 text-left">
        {expandable ? (
          <ChevronRight className={`h-3.5 w-3.5 shrink-0 text-slate-500 transition-transform ${open ? 'rotate-90' : ''}`} />
        ) : (
          <span className="h-3.5 w-3.5 shrink-0" />
        )}
        {icon}
        <span className="min-w-0 truncate text-[13px] text-ink">{title}</span>
        <span className="ml-auto flex shrink-0 items-center gap-2 pl-3">{meta}</span>
      </button>
      {actions && <span className="flex items-center gap-0.5 pr-2 opacity-0 transition-opacity group-hover:opacity-100">{actions}</span>}
    </div>
  );
}

function AgentRow({
  a,
  grant,
  now,
  live,
  dragging,
  selected,
  editing,
  onSelect,
  onDragStart,
  onDragEnd,
  onDelete,
  onToggleStatus,
  onGrant,
  onStartRename,
  onRename,
  onCancelRename,
}: {
  a: AgentPrincipal;
  grant: SessionGrant | undefined;
  now: number;
  live: boolean;
  dragging: boolean;
  selected: boolean;
  editing: boolean;
  onSelect: () => void;
  onDragStart: () => void;
  onDragEnd: () => void;
  onDelete: () => void;
  onToggleStatus: () => void;
  onGrant: () => void;
  onStartRename: () => void;
  onRename: (v: string) => void;
  onCancelRename: () => void;
}): JSX.Element {
  const expiresAt = grant !== undefined ? grant.issuedAtMs + grant.ttlSeconds * 1000 : 0;
  const grantActive = grant !== undefined && expiresAt > now;
  const revoked = a.status === 'revoked';
  return (
    <div
      draggable
      onClick={onSelect}
      onDragStart={onDragStart}
      onDragEnd={onDragEnd}
      className={`group flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 transition-colors ${selected ? 'bg-canvas ring-1 ring-inset ring-ink/15' : 'hover:bg-canvas'} ${dragging ? 'opacity-40' : ''}`}
      style={{ paddingLeft: '48px' }}
    >
      <GripVertical className="h-3.5 w-3.5 shrink-0 cursor-grab text-slate-600 opacity-0 group-hover:opacity-100" />
      {a.kind === 'user' ? (
        <UserRound className="h-4 w-4 shrink-0 text-slate-400" />
      ) : (
        <Bot className="h-4 w-4 shrink-0 text-slate-400" />
      )}
      {editing ? (
        <RenameInput value={a.agentId} onSave={onRename} onCancel={onCancelRename} />
      ) : (
        <span className={`truncate font-mono text-[12px] ${revoked ? 'text-slate-400' : 'text-ink'}`}>{a.agentId}</span>
      )}
      <span className="ml-auto flex items-center gap-2 pl-3">
        {grantActive && grant !== undefined ? (
          <span
            className="hidden items-center gap-1 rounded-full border border-staged/25 bg-staged/8 px-2 py-0.5 text-[10px] font-medium text-staged md:inline-flex"
            title={`live gateway grant → ${grant.compartmentLabel} (${truncateId(grant.compartmentUuid, 8, 5)}) · txn ${grant.reference} · Redis TTL is authoritative`}
          >
            <ShieldCheck className="h-3 w-3" />
            until {fmtClock(expiresAt)}
          </span>
        ) : null}
        <span className={`rounded-full border border-hairline bg-canvas px-2 py-0.5 text-[10px] font-medium ${revoked ? 'text-denied' : 'text-verified'}`}>
          {a.status}
        </span>
        <span className="flex items-center gap-0.5 opacity-0 transition-opacity group-hover:opacity-100">
          <IconBtn title="Rename principal" onClick={onStartRename}><Pencil className="h-3.5 w-3.5" /></IconBtn>
          {live && !grantActive && <IconBtn title="Grant temporary access (real ceremony)" onClick={onGrant}><Clock className="h-3.5 w-3.5" /></IconBtn>}
          <IconBtn title={revoked ? 'Reactivate principal' : 'Revoke principal (gateway kill-switch)'} danger={!revoked} onClick={onToggleStatus}>
            {revoked ? <RotateCcw className="h-3.5 w-3.5" /> : <Ban className="h-3.5 w-3.5" />}
          </IconBtn>
          <IconBtn title="Remove from directory" danger onClick={onDelete}><Trash2 className="h-3.5 w-3.5" /></IconBtn>
        </span>
      </span>
    </div>
  );
}

/* ------------------------------------------------------------ temp grants UI */

/** A grantable compartment: full UUID (ceremony-resolvable) + display label. */
interface GrantTarget {
  uuid: string;
  label: string;
}

const TTL_OPTIONS = [
  { label: '15m', seconds: 15 * 60 },
  { label: '1h', seconds: 3600 },
  { label: '8h', seconds: 8 * 3600 },
  { label: '24h', seconds: 86_400 },
] as const;

/**
 * The grant dialog runs ONLY the real ceremony: mint a compartment-scoped
 * officer → POST /v1/authorize (202 staged) → sandbox one-time code → consume.
 * Success records the committing receipt; a gateway deny is reported verbatim.
 * There is no local-staging fallback and no fake countdown — offline, this
 * dialog is simply not offered.
 */
function TempGrantDialog({
  agent,
  targets,
  apiBase,
  tenant,
  onClose,
  onIssued,
}: {
  agent: AgentPrincipal;
  targets: ReadonlyArray<GrantTarget>;
  apiBase: string;
  tenant: string;
  onClose: () => void;
  onIssued: () => void;
}): JSX.Element {
  const reduced = prefersReducedMotion();
  const [compartmentUuid, setCompartmentUuid] = useState(targets[0]?.uuid ?? '');
  const [ttlSeconds, setTtlSeconds] = useState<number>(TTL_OPTIONS[1].seconds);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const target = targets.find((t) => t.uuid === compartmentUuid) ?? null;

  const submit = async (): Promise<void> => {
    if (busy || target === null) return;
    setBusy(true);
    setError(null);
    const res = await issueCompartmentGrant({
      apiBase,
      granteeAgentId: agent.agentId,
      compartmentDisplay: target.uuid,
      ttlSeconds,
      // Omit an empty tenant so the ceremony's own company-config fallback (and
      // its honest no-tenant failure) applies instead of a blank tenant claim.
      ...(tenant ? { tenantId: tenant } : {}),
    });
    if (!res.ok) {
      // Honest failure: the gateway denied (or the ceremony broke) — report why
      // and leave NO grant artifact behind.
      setError(res.reason);
      setBusy(false);
      return;
    }
    grantStore.set((prev) => [
      {
        id: uid('grant'),
        granteeAgentId: agent.agentId,
        compartmentUuid: res.compartmentUuid,
        compartmentLabel: target.label,
        ttlSeconds,
        issuedAtMs: Date.now(),
        reference: res.reference,
        wormSequence: res.wormSequence,
      },
      ...prev,
    ]);
    onIssued();
    onClose();
  };

  return (
    <motion.div
      initial={reduced ? false : { opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.3, ease: EASE }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/20 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={reduced ? false : { scale: 0.97, y: 8 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.97, y: 8 }}
        transition={{ duration: 0.3, ease: EASE }}
        onClick={(e) => e.stopPropagation()}
        className="panel w-full max-w-sm p-4"
      >
        <div className="mb-3 flex items-center gap-2 text-ink">
          <Timer className="h-4 w-4 text-staged" />
          <h3 className="text-[13px] font-semibold">Grant temporary access</h3>
          <button type="button" onClick={onClose} className="ml-auto text-slate-500 transition-colors hover:text-ink" aria-label="Close">
            <X className="h-4 w-4" />
          </button>
        </div>
        <p className="mb-3 text-[11px] leading-relaxed text-slate-500">
          Runs the real <span className="font-mono">skill_compartment_grant</span> ceremony for{' '}
          <span className="font-mono text-ink">{agent.agentId}</span>: stage (202) → one-time code →
          consume. A committed grant lands in the gateway&apos;s Redis GrantStore with{' '}
          <span className="font-mono">EX=ttl</span> and expires there.
        </p>

        {targets.length === 0 ? (
          <p className="rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-500">
            No resolvable compartments: the ceremony needs a team with a full compartment UUID.
            Add a team in the tree (new teams get a real UUID) or complete the company setup.
          </p>
        ) : (
          <>
            <Field label="Compartment (blast radius)">
              <Select mono value={compartmentUuid} onChange={(e) => setCompartmentUuid(e.target.value)}>
                {targets.map((t) => (
                  <option key={t.uuid} value={t.uuid}>
                    {t.label} · {truncateId(t.uuid, 8, 5)}
                  </option>
                ))}
              </Select>
            </Field>
            <div className="mt-3">
              <span className={LABEL}>time-to-live</span>
              <div className="mt-1 flex gap-1.5">
                {TTL_OPTIONS.map((o) => (
                  <button
                    key={o.label}
                    type="button"
                    onClick={() => setTtlSeconds(o.seconds)}
                    className={`flex-1 rounded-md border px-2 py-1.5 text-[12px] transition-colors ${ttlSeconds === o.seconds ? 'border-ink bg-ink text-surface' : 'border-hairline bg-canvas text-slate-400 hover:text-ink'}`}
                  >
                    {o.label}
                  </button>
                ))}
              </div>
            </div>
          </>
        )}

        {error !== null ? (
          <div className="mt-3 rounded-lg border border-denied/25 bg-denied/5 px-2.5 py-1.5">
            <p className="font-mono text-[10.5px] leading-relaxed text-denied">ceremony failed · {error}</p>
            <p className="mt-0.5 text-[10.5px] leading-relaxed text-slate-500">
              The concrete deny reason is WORM-only — find this attempt in the Audit Ledger.
            </p>
          </div>
        ) : null}

        <button
          type="button"
          onClick={() => void submit()}
          disabled={busy || target === null}
          className="btn-primary mt-4 w-full"
        >
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Timer className="h-3.5 w-3.5" />}
          {busy ? 'running step-up ceremony…' : 'Issue grant · auto-expires'}
        </button>
      </motion.div>
    </motion.div>
  );
}

/* ----------------------------------------------------------- principal inspector */

function PrincipalInspector({
  agent,
  team,
  ou,
  grants,
  now,
  live,
  onGrant,
  onToggleStatus,
  onDelete,
}: {
  agent: AgentPrincipal;
  team: Team;
  ou: OrgUnit;
  grants: ReadonlyArray<SessionGrant>;
  now: number;
  live: boolean;
  onGrant: () => void;
  onToggleStatus: () => void;
  onDelete: () => void;
}): JSX.Element {
  const isUser = agent.kind === 'user';
  const active = agent.status === 'active';
  // The real decoded JWT for principals licensed THIS session — the only
  // credential-shaped data the directory may show, because it is real.
  const licenses = useSessionStore(licenseStore);
  const license = licenses.find((l) => l.agentId === agent.agentId) ?? null;
  const hasActiveGrant = grants.some((g) => g.issuedAtMs + g.ttlSeconds * 1000 > now);

  return (
    <div className="flex h-full flex-col">
      <div className="flex shrink-0 items-center gap-2.5 border-b border-hairline px-4 py-3">
        {isUser ? <UserRound className="h-4 w-4 text-slate-500" /> : <Bot className="h-4 w-4 text-slate-500" />}
        <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-ink">{agent.agentId}</span>
        <Badge tone={active ? 'verified' : 'denied'}>{agent.status}</Badge>
      </div>

      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <Detail label="Kind">{isUser ? 'User · human principal' : 'Agent · licensed workload'}</Detail>
          <Detail label="Org unit">{ou.label}</Detail>
          <Detail label="Team">{team.label}</Detail>
          <Detail label="Tenant" mono>{ou.tenant || '—'}</Detail>
          <Detail label="Compartment" mono span>
            {team.compartment ? (isUuid(team.compartment) ? team.compartment : `${team.compartment} · legacy short form`) : '—'}
          </Detail>
        </dl>

        <div>
          <div className="mb-1.5 flex items-center gap-1.5">
            <KeyRound className="h-3 w-3 text-slate-500" />
            <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
              License claims · this session
            </span>
          </div>
          {license !== null && license.claims !== null ? (
            <details className="group">
              <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[11px] font-medium text-slate-400 transition-colors hover:text-ink">
                <ChevronRight className="h-3 w-3 shrink-0 text-slate-500 transition-transform group-open:rotate-90" />
                View claims
                <span className="ml-auto font-mono text-[10px] text-slate-500">minted {fmtClock(license.mintedAtMs)}</span>
              </summary>
              <pre className="mt-1.5 max-h-44 overflow-y-auto whitespace-pre-wrap break-all rounded-lg border border-hairline bg-canvas p-2.5 font-mono text-[10.5px] leading-relaxed text-ink">
                {JSON.stringify(license.claims, null, 2)}
              </pre>
              <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">
                Decoded verbatim from the JWT minted at {fmtClock(license.mintedAtMs)} — never
                re-stated from form inputs.
              </p>
            </details>
          ) : (
            <p className="rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-500">
              No license minted for this principal this session. The directory holds metadata only —
              credentials exist solely where your IdP minted them.
            </p>
          )}
        </div>

        <div>
          <div className="mb-1.5 flex items-center gap-1.5">
            <Clock className="h-3 w-3 text-slate-500" />
            <span className="text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
              Delegated access · this session
            </span>
          </div>
          {grants.length === 0 ? (
            <p className="rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-500">
              No grants issued this session. Temporary access is TTL-bounded and auto-expires — no
              standing entitlement.
            </p>
          ) : (
            <>
              <div className="overflow-hidden rounded-lg border border-hairline">
                {grants.map((g) => {
                  const expiresAt = g.issuedAtMs + g.ttlSeconds * 1000;
                  const grantLive = expiresAt > now;
                  return (
                    <div key={g.id} className="border-b border-hairline/60 bg-canvas px-2.5 py-1.5 last:border-0">
                      <div className="flex items-center gap-2">
                        <ShieldCheck className={`h-3 w-3 shrink-0 ${grantLive ? 'text-staged' : 'text-slate-500'}`} />
                        <span className="truncate font-mono text-[11px] text-ink">{g.compartmentLabel}</span>
                        <span className={`ml-auto shrink-0 text-[10.5px] font-medium ${grantLive ? 'text-staged' : 'text-slate-500'}`}>
                          {grantLive ? `until ${fmtClock(expiresAt)}` : 'expired'}
                        </span>
                      </div>
                      <p className="mt-0.5 pl-[20px] font-mono text-[10px] text-slate-500">
                        ttl {fmtTtl(g.ttlSeconds)} · txn {truncateId(g.reference, 10, 4)} · WORM #{g.wormSequence}
                      </p>
                    </div>
                  );
                })}
              </div>
              <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">
                Committed by the gateway — Redis <span className="font-mono">EX=ttl</span> enforces
                expiry. This build wires no grant-revoke mandate (
                <span className="font-mono">CAP_COMPARTMENT_REVOKE</span> is reserved), so a live
                grant cannot be cut early here; to block the principal now, revoke it below.
              </p>
            </>
          )}
        </div>

        <p className="text-[10.5px] leading-relaxed text-slate-500">
          Revocation state reconciles from{' '}
          <span className="font-mono">/v1/admin/principals/revoked</span> — the gateway is
          authoritative, never this document. Revocation is enforced on the hot path.
        </p>
      </div>

      <div className="space-y-2 border-t border-hairline px-4 py-3">
        {live && !hasActiveGrant ? (
          <button type="button" onClick={onGrant} className="btn-ghost w-full">
            <Clock size={13} /> Grant temporary access
          </button>
        ) : null}
        {!live ? (
          <p className="text-center text-[10.5px] text-slate-500">
            Grant and revocation ceremonies are live-only — connect a gateway.
          </p>
        ) : null}
        <button
          type="button"
          onClick={onToggleStatus}
          disabled={!live}
          className={`flex w-full items-center justify-center gap-1.5 rounded-lg border px-3 py-2 text-[12.5px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${
            active
              ? 'border-hairline bg-surface text-ink hover:border-denied/40 hover:text-denied'
              : 'border-verified/25 bg-verified/5 text-verified hover:bg-verified/10'
          }`}
        >
          {active ? <Ban size={13} /> : <RotateCcw size={13} />}
          {active ? 'Revoke principal' : 'Reactivate principal'}
        </button>
        <button type="button" onClick={onDelete} className="btn-ghost w-full hover:border-denied/40 hover:text-denied">
          <Trash2 size={13} /> Remove from directory
        </button>
      </div>
    </div>
  );
}

/* ------------------------------------------------ ReBAC relation projection */

/** Poll cadence for the best-effort relation projection (matches the reconcile feel). */
const RELATION_POLL_MS = 15_000;

type RelationFetchState =
  | { status: 'offline' }
  | { status: 'loading' }
  | { status: 'unavailable' }
  | { status: 'ok'; edges: RelationEdge[]; atMs: number };

/**
 * Knowledge-Graph edge source. Reads GET /v1/admin/directory/relations — the
 * gateway-served projection of committed compartment grants — so the console
 * finally has an AUTHORITATIVE relation roster (previously grants lived only in
 * Redis with EX=ttl and were never read back). It is a BEST-EFFORT PROJECTION:
 * a missing edge under-reports access (fail-safe), never over-reports, and the
 * copy says so — an operator must never read a missing edge as proof of no
 * access (the gateway/Redis grant state is authoritative). Honest empty states
 * offline / when the admin read is unavailable / when there are genuinely no
 * live grants — nothing is ever fabricated.
 */
function KnowledgeGraphPanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { config } = useCompanyConfig();
  const live = gateway.mode === 'live';
  const { mode, fetchDirectoryRelations } = gateway;
  const [state, setState] = useState<RelationFetchState>({ status: live ? 'loading' : 'offline' });

  useEffect(() => {
    if (mode !== 'live') {
      setState({ status: 'offline' });
      return;
    }
    let cancelled = false;
    const controller = new AbortController();
    const tick = async (): Promise<void> => {
      const roster = await fetchDirectoryRelations({}, controller.signal);
      if (cancelled) return;
      if (roster === null) {
        setState({ status: 'unavailable' });
        return;
      }
      setState({ status: 'ok', edges: roster.relations, atMs: Date.now() });
    };
    void tick();
    const id = window.setInterval(() => void tick(), RELATION_POLL_MS);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [mode, fetchDirectoryRelations]);

  /** compartment UUID → operator-friendly label (best-effort, from the company profile). */
  const compartmentLabel = useMemo(() => {
    const m = new Map<string, string>();
    for (const t of config?.teams ?? []) {
      if (isUuid(t.compartment)) m.set(t.compartment, t.name);
    }
    return m;
  }, [config]);

  /** Group the projected edges by compartment (object) for a readable roster. */
  const grouped = useMemo(() => {
    if (state.status !== 'ok') return [];
    const byObject = new Map<string, RelationEdge[]>();
    for (const edge of state.edges) {
      const list = byObject.get(edge.object) ?? [];
      list.push(edge);
      byObject.set(edge.object, list);
    }
    return [...byObject.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [state]);

  const right =
    state.status === 'ok'
      ? `${state.edges.length} edge${state.edges.length === 1 ? '' : 's'} · projection`
      : state.status === 'loading'
        ? 'reading…'
        : state.status === 'unavailable'
          ? 'admin read unavailable'
          : 'offline';

  return (
    <Panel className="shrink-0">
      <PanelHeader title="Knowledge graph · relation projection" icon={Network} right={right} />
      <div className="min-h-0 max-h-[42vh] overflow-y-auto p-3">
        {state.status === 'ok' && grouped.length > 0 ? (
          <div className="flex flex-col gap-3">
            {grouped.map(([object, edges]) => (
              <div key={object} className="rounded-lg border border-hairline bg-canvas p-2.5">
                <div className="mb-1.5 flex items-center gap-2">
                  <Building2 className="h-3.5 w-3.5 text-slate-500" />
                  <span className="text-[12px] font-semibold text-ink">
                    {compartmentLabel.get(object) ?? 'compartment'}
                  </span>
                  <span className="font-mono text-[10.5px] text-slate-500" title={object}>
                    {isUuid(object) ? truncateId(object, 8, 5) : object}
                  </span>
                </div>
                <div className="flex flex-col gap-1">
                  {edges
                    .slice()
                    .sort((a, b) => a.relation.localeCompare(b.relation) || a.subject.localeCompare(b.subject))
                    .map((edge, i) => (
                      <div
                        key={`${edge.relation}@${edge.subject}#${i}`}
                        className="flex items-center gap-2 text-[11.5px]"
                      >
                        <Badge tone={edge.relation === 'member' ? 'verified' : 'muted'}>{edge.relation}</Badge>
                        <span className="truncate font-mono text-slate-300" title={edge.subject}>
                          {edge.subject}
                        </span>
                        {edge.issued_at_ns != null ? (
                          <span className="ml-auto shrink-0 font-mono text-[10px] text-slate-500">
                            {formatDateTime(new Date(Math.floor(edge.issued_at_ns / 1_000_000)).toISOString())}
                          </span>
                        ) : null}
                      </div>
                    ))}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <EmptyState
            icon={Network}
            title={
              state.status === 'offline'
                ? 'Connect a gateway to project relations'
                : state.status === 'unavailable'
                  ? 'Relation read unavailable'
                  : state.status === 'loading'
                    ? 'Reading live grant projection…'
                    : 'No live grant edges'
            }
            detail={
              state.status === 'offline'
                ? 'Once connected, the Knowledge graph reads GET /v1/admin/directory/relations — the gateway-served projection of committed compartment grants.'
                : state.status === 'unavailable'
                  ? 'The connected gateway did not serve the relation projection (a pre-endpoint build, or the admin read failed). The gateway/Redis grant state remains authoritative.'
                  : state.status === 'loading'
                    ? 'Fetching the projected relation tuples for your tenant.'
                    : 'No committed compartment grants are live right now. Issue a grant from a principal to see its member and grantor edges appear here.'
            }
          />
        )}
      </div>
      <div className="border-t border-hairline px-3 py-2">
        <p className="text-[10.5px] leading-relaxed text-slate-500">
          Best-effort projection of live grants — auto-expires in lockstep with each grant&apos;s Redis
          TTL. The gateway/Redis grant state is authoritative; a missing edge under-reports access, never
          over-reports it. Operator-facing identifiers only — never a target, secret, or alias mapping.
        </p>
      </div>
    </Panel>
  );
}

function Hierarchy({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { config } = useCompanyConfig();
  const tenant = config?.tenant ?? '';
  const live = gateway.mode === 'live';
  const [org, dispatch] = useReducer(orgReducer, config, seedOrgFromCompany);
  const sync = useDirectorySync(gateway, org, dispatch, tenant);
  const { rec, refresh: refreshRevocations } = useRevocationReconcile(gateway, tenant, dispatch);
  const grants = useSessionStore(grantStore);

  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [dragId, setDragId] = useState<string | null>(null);
  const [dropTeam, setDropTeam] = useState<string | null>(null);
  const [grantFor, setGrantFor] = useState<AgentPrincipal | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [showGraph, setShowGraph] = useState(false);
  const [note, setNote] = useState<{ tone: 'verified' | 'denied'; text: string } | null>(null);
  // Expiry stamps are static facts (Redis EX set at commit); this slow tick only
  // flips active → expired at half-minute granularity — no per-second theater.
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 30_000);
    return () => window.clearInterval(t);
  }, []);

  const toggle = (id: string): void => setOpen((o) => ({ ...o, [id]: !(o[id] ?? true) }));
  const isOpen = (id: string): boolean => open[id] ?? true;

  /** Newest ACTIVE session grant per grantee (rows show one chip; the inspector shows all). */
  const activeGrantByAgent = useMemo(() => {
    const m = new Map<string, SessionGrant>();
    for (const g of grants) {
      if (g.issuedAtMs + g.ttlSeconds * 1000 > now && !m.has(g.granteeAgentId)) {
        m.set(g.granteeAgentId, g);
      }
    }
    return m;
  }, [grants, now]);

  const counts = useMemo(() => {
    let teams = 0;
    let agents = 0;
    let revoked = 0;
    for (const ou of org) {
      teams += ou.teams.length;
      for (const t of ou.teams) {
        agents += t.agents.length;
        revoked += t.agents.filter((a) => a.status === 'revoked').length;
      }
    }
    return { ous: org.length, teams, agents, revoked };
  }, [org]);

  /**
   * Compartments the grant ceremony can actually resolve: full UUIDs from the
   * company profile plus any org-tree team carrying one. Legacy truncated forms
   * are excluded — the derivation needs the full UUID, and the dialog never
   * pretends otherwise.
   */
  const grantTargets = useMemo<GrantTarget[]>(() => {
    const seen = new Set<string>();
    const out: GrantTarget[] = [];
    for (const t of config?.teams ?? []) {
      if (isUuid(t.compartment) && !seen.has(t.compartment)) {
        seen.add(t.compartment);
        out.push({ uuid: t.compartment, label: t.name });
      }
    }
    for (const ou of org) {
      for (const t of ou.teams) {
        if (isUuid(t.compartment) && !seen.has(t.compartment)) {
          seen.add(t.compartment);
          out.push({ uuid: t.compartment, label: t.label });
        }
      }
    }
    return out;
  }, [config, org]);

  const onDrop = (teamId: string): void => {
    if (dragId) dispatch({ type: 'MOVE_AGENT', agentId: dragId, toTeamId: teamId });
    setDragId(null);
    setDropTeam(null);
  };

  /**
   * Revoke / reactivate a principal. LIVE only: call the real
   * CAP_DIRECTORY_ADMIN kill-switch, flip local status on success, then force a
   * reconcile so the tree reflects the gateway's own list. A failure leaves the
   * status unchanged and surfaces the reason.
   */
  const toggleStatus = async (agent: AgentPrincipal, ouTenant: string): Promise<void> => {
    if (!live) return;
    const revoke = agent.status === 'active';
    const res = await setPrincipalRevocation({
      apiBase: gateway.apiBase,
      tenantId: ouTenant,
      agentId: agent.agentId,
      revoke,
      ...(revoke ? { reason: 'revoked from operator console' } : {}),
    });
    if (!res.ok) {
      setNote({ tone: 'denied', text: `${revoke ? 'revoke' : 'reactivate'} failed · ${res.reason ?? ''}` });
      return;
    }
    setNote({
      tone: 'verified',
      text: revoke
        ? `${agent.agentId} revoked · gateway now denies it (PRINCIPAL_REVOKED), WORM-logged`
        : `${agent.agentId} reactivated · gateway block lifted`,
    });
    dispatch({ type: 'SET_STATUS', agentId: agent.id, status: revoke ? 'revoked' : 'active' });
    refreshRevocations();
  };

  // Resolve the selected principal (with its team/OU context) for the inspector.
  const selected = useMemo(() => {
    if (!selectedId) return null;
    for (const ou of org) {
      for (const team of ou.teams) {
        const agent = team.agents.find((a) => a.id === selectedId);
        if (agent) return { agent, team, ou };
      }
    }
    return null;
  }, [org, selectedId]);

  const inspector =
    selected !== null ? (
      <PrincipalInspector
        agent={selected.agent}
        team={selected.team}
        ou={selected.ou}
        grants={grants.filter((g) => g.granteeAgentId === selected.agent.agentId)}
        now={now}
        live={live}
        onGrant={() => setGrantFor(selected.agent)}
        onToggleStatus={() => void toggleStatus(selected.agent, selected.ou.tenant)}
        onDelete={() => {
          dispatch({ type: 'DELETE_AGENT', agentId: selected.agent.id });
          setSelectedId(null);
        }}
      />
    ) : (
      <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-12 text-center">
        <MousePointerClick size={22} className="text-slate-600" />
        <p className="text-[12.5px] font-medium text-slate-400">Select a principal</p>
        <p className="max-w-[230px] text-[11.5px] leading-relaxed text-slate-500">
          Inspect its real fields, session license claims, and delegated grants.
        </p>
      </div>
    );

  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <div className="grid shrink-0 grid-cols-2 gap-3 sm:grid-cols-4">
        <StatTile label="Org units" value={String(counts.ous)} />
        <StatTile label="Teams" value={String(counts.teams)} sub="compartments · blast radii" />
        <StatTile label="Principals" value={String(counts.agents)} sub="agents + users" />
        <StatTile
          label="Revoked"
          value={String(counts.revoked)}
          tone={counts.revoked > 0 ? 'denied' : 'ink'}
          sub={rec.status === 'ok' ? 'gateway-reconciled' : 'document state'}
        />
      </div>

      <div className="flex shrink-0 flex-wrap items-center gap-3">
        <p className="text-[11px] text-slate-500">
          Click a principal to inspect · drag onto a team to reassign · hover a row for actions.
        </p>
        {note ? (
          <span className={`truncate font-mono text-[10.5px] ${note.tone === 'denied' ? 'text-denied' : 'text-verified'}`}>
            {note.text}
          </span>
        ) : null}
        <div className="ml-auto flex items-center gap-3">
          <ReconcileBadge rec={rec} live={live} />
          <SyncBadge sync={sync} />
          <button
            type="button"
            onClick={() => setShowGraph((v) => !v)}
            className="btn-ghost"
            aria-pressed={showGraph}
          >
            <Network size={13} /> {showGraph ? 'Hide graph' : 'Knowledge graph'}
          </button>
          <button type="button" onClick={() => dispatch({ type: 'ADD_OU', tenant })} className="btn-ghost">
            <Plus size={13} /> Org unit
          </button>
        </div>
      </div>

      {/* Master (tree) + Detail (principal inspector) */}
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel>
          <div className="min-h-0 flex-1 overflow-y-auto p-2">
            {org.length === 0 ? (
              <EmptyState
                icon={Building2}
                title="No org units yet"
                detail="Add an org unit to begin, or run the first-time setup to seed your company and teams. The chart persists via /v1/directory under your real tenant."
                action={
                  <button type="button" onClick={() => dispatch({ type: 'ADD_OU', tenant })} className="btn-ghost">
                    <Plus size={13} /> Add org unit
                  </button>
                }
              />
            ) : (
              org.map((ou) => (
                <div key={ou.id} className="select-none">
                  <Row
                    depth={0}
                    open={isOpen(ou.id)}
                    onClick={() => toggle(ou.id)}
                    icon={<Building2 className="h-4 w-4 text-slate-400" />}
                    title={
                      editingId === ou.id ? (
                        <RenameInput
                          value={ou.label}
                          onSave={(v) => {
                            dispatch({ type: 'RENAME_OU', ouId: ou.id, label: v });
                            setEditingId(null);
                          }}
                          onCancel={() => setEditingId(null)}
                        />
                      ) : (
                        ou.label
                      )
                    }
                    meta={<span className="text-[10.5px] text-slate-500">{ou.teams.length} teams</span>}
                    expandable
                    actions={
                      <>
                        <IconBtn title="Rename org unit" onClick={() => setEditingId(ou.id)}><Pencil className="h-3.5 w-3.5" /></IconBtn>
                        <IconBtn title="Add team (mints a fresh compartment UUID)" onClick={() => { dispatch({ type: 'ADD_TEAM', ouId: ou.id }); setOpen((o) => ({ ...o, [ou.id]: true })); }}><Plus className="h-3.5 w-3.5" /></IconBtn>
                        <IconBtn title="Delete org unit" danger onClick={() => dispatch({ type: 'DELETE_OU', ouId: ou.id })}><Trash2 className="h-3.5 w-3.5" /></IconBtn>
                      </>
                    }
                  />
                  {isOpen(ou.id) &&
                    ou.teams.map((team) => (
                      <div
                        key={team.id}
                        onDragOver={(e) => {
                          e.preventDefault();
                          setDropTeam(team.id);
                        }}
                        onDragLeave={() => setDropTeam((d) => (d === team.id ? null : d))}
                        onDrop={() => onDrop(team.id)}
                        className={`rounded-md ${dropTeam === team.id ? 'bg-canvas ring-1 ring-inset ring-ink/40' : ''}`}
                      >
                        <Row
                          depth={1}
                          open={isOpen(team.id)}
                          onClick={() => toggle(team.id)}
                          icon={<Users className="h-4 w-4 text-slate-400" />}
                          title={
                            editingId === team.id ? (
                              <RenameInput
                                value={team.label}
                                onSave={(v) => {
                                  dispatch({ type: 'RENAME_TEAM', teamId: team.id, label: v });
                                  setEditingId(null);
                                }}
                                onCancel={() => setEditingId(null)}
                              />
                            ) : (
                              team.label
                            )
                          }
                          meta={
                            <span className="font-mono text-[10.5px] text-slate-500" title={team.compartment}>
                              {isUuid(team.compartment) ? truncateId(team.compartment, 8, 5) : team.compartment || '—'}
                            </span>
                          }
                          expandable
                          actions={
                            <>
                              <IconBtn title="Rename team" onClick={() => setEditingId(team.id)}><Pencil className="h-3.5 w-3.5" /></IconBtn>
                              <IconBtn title="Add agent" onClick={() => { dispatch({ type: 'ADD_AGENT', teamId: team.id, kind: 'agent' }); setOpen((o) => ({ ...o, [team.id]: true })); }}><Bot className="h-3.5 w-3.5" /></IconBtn>
                              <IconBtn title="Add user (human principal)" onClick={() => { dispatch({ type: 'ADD_AGENT', teamId: team.id, kind: 'user' }); setOpen((o) => ({ ...o, [team.id]: true })); }}><UserRound className="h-3.5 w-3.5" /></IconBtn>
                              <IconBtn title="Delete team" danger onClick={() => dispatch({ type: 'DELETE_TEAM', teamId: team.id })}><Trash2 className="h-3.5 w-3.5" /></IconBtn>
                            </>
                          }
                        />
                        {isOpen(team.id) &&
                          team.agents.map((a) => (
                            <AgentRow
                              key={a.id}
                              a={a}
                              grant={activeGrantByAgent.get(a.agentId)}
                              now={now}
                              live={live}
                              dragging={dragId === a.id}
                              selected={selectedId === a.id}
                              editing={editingId === a.id}
                              onSelect={() => setSelectedId(a.id)}
                              onDragStart={() => setDragId(a.id)}
                              onDragEnd={() => setDragId(null)}
                              onDelete={() => {
                                dispatch({ type: 'DELETE_AGENT', agentId: a.id });
                                if (selectedId === a.id) setSelectedId(null);
                              }}
                              onToggleStatus={() => void toggleStatus(a, ou.tenant)}
                              onGrant={() => setGrantFor(a)}
                              onStartRename={() => setEditingId(a.id)}
                              onRename={(v) => {
                                dispatch({ type: 'RENAME_AGENT', agentId: a.id, agentIdLabel: v });
                                setEditingId(null);
                              }}
                              onCancelRename={() => setEditingId(null)}
                            />
                          ))}
                      </div>
                    ))}
                </div>
              ))
            )}
          </div>
        </Panel>

        <Panel className="hidden xl:flex">{inspector}</Panel>
      </div>

      {/* Below xl the inspector stacks under the tree when a row is selected. */}
      {selected !== null ? <Panel className="max-h-[55vh] shrink-0 xl:hidden">{inspector}</Panel> : null}

      {/* Knowledge graph: the AUTHORITATIVE relation edges projected from committed
          grants (best-effort). Hidden by default for density — toggled from the
          toolbar; still real edges + honest empty state when shown. */}
      {showGraph ? <KnowledgeGraphPanel gateway={gateway} /> : null}

      <AnimatePresence>
        {grantFor && live && (
          <TempGrantDialog
            agent={grantFor}
            targets={grantTargets}
            apiBase={gateway.apiBase}
            tenant={tenant}
            onClose={() => setGrantFor(null)}
            onIssued={() => setNote({ tone: 'verified', text: `grant committed for ${grantFor.agentId} · WORM-logged` })}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

/* ---------------------------------------------------------- agent licensing */

interface CompartmentOption {
  id: string;
  label: string;
  uuid: string | null;
}

/**
 * Agent Licensing — register ANY agent like adding a person. MCPIP is
 * agent-agnostic (the Bridge normalizes every major dialect): the company does
 * not restrict WHICH agent runs — it LICENSES the agent: an IdP-signed
 * principal (identity), a team/compartment (blast radius), capability UUIDs
 * (entitlements). LIVE: mints a REAL principal via the sandbox IdP, then
 * proves the license by enumerating what the new identity can actually see
 * (/v1/catalog with ITS token). A grant-officer license derives the scoped
 * grant_capability_for(X) for the CHOSEN team at runtime — any compartment,
 * not just showcase seeds. Production mints offline (`ceremony` in the
 * terminal); offline this page is its honest connect state.
 */
function Licensing({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const { config } = useCompanyConfig();
  const companyTenant = config?.tenant ?? gateway.tenant ?? '';
  const issued = useSessionStore(licenseStore);

  const compartmentOptions: ReadonlyArray<CompartmentOption> = useMemo(
    () => [
      { id: 'none', label: 'Company-wide (no team)', uuid: null },
      ...(config?.teams ?? []).map((t) => ({ id: t.id, label: t.name, uuid: t.compartment })),
    ],
    [config],
  );

  const [vendor, setVendor] = useState<VendorId>('anthropic');
  const [agentId, setAgentId] = useState('orchestrator-1');
  const [tenant, setTenant] = useState(companyTenant);
  const [compartmentId, setCompartmentId] = useState('none');
  const [role, setRole] = useState<RoleId>('operator');
  const [grantOfficer, setGrantOfficer] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokingId, setRevokingId] = useState<string | null>(null);
  // Which roster rows are expanded to reveal the minted JWT + proven blast radius.
  // Absent entry ⇒ the newest license (latest) is open by default, the rest closed.
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [showConsole, setShowConsole] = useState(false);

  // Keep the tenant field synced to the company until the operator edits it.
  const tenantTouched = useRef(false);
  useEffect(() => {
    if (!tenantTouched.current) setTenant(companyTenant);
  }, [companyTenant]);

  const compartment = compartmentOptions.find((c) => c.id === compartmentId) ?? compartmentOptions[0]!;
  const latest = issued[0] ?? null;
  const isRowOpen = (id: string): boolean => expanded[id] ?? id === latest?.agentId;
  const toggleRow = (id: string): void =>
    setExpanded((e) => ({ ...e, [id]: !(e[id] ?? id === latest?.agentId) }));

  // The vendor is part of the identity: it prefixes the agent id the gateway
  // records, so every WORM decision attributes the call to its framework.
  const effectiveAgentId = `${vendor}-${agentId.trim()}`;

  const issue = async (): Promise<void> => {
    const base = agentId.trim();
    if (!base || busy) return;
    const id = effectiveAgentId;
    const tenantId = tenant.trim();
    if (!tenantId) {
      setError('tenant required — complete the company setup or type one');
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const capabilities: string[] = [];
      if (grantOfficer) {
        capabilities.push(CAP_COMPARTMENT_GRANT);
        // The scoped issuing authority is DERIVED at runtime for whatever team
        // was chosen — uuid5(CAP_COMPARTMENT_GRANT, X), byte-identical to the
        // engine — so officers work for company teams, not only showcase seeds.
        if (compartment.uuid) capabilities.push(await grantCapabilityFor(compartment.uuid));
      }
      const claims: DevTokenClaims = { tenant_id: tenantId, agent_id: id, role };
      if (compartment.uuid) claims.compartment = compartment.uuid;
      if (capabilities.length > 0) claims.capabilities = capabilities;
      // REAL mint via the sandbox IdP (production: the offline ceremony in the terminal).
      const token = await mintDevToken(claims, { base: gateway.apiBase });
      // Prove the license: enumerate what THIS new identity can actually see.
      const visible = await catalog(token, { base: gateway.apiBase });
      licenseStore.set((prev) => [
        {
          agentId: id,
          tenant: tenantId,
          compartmentUuid: compartment.uuid,
          compartmentLabel: compartment.label,
          grantOfficer,
          token,
          claims: decodeJwtClaims(token),
          visibleAliases: visible === null ? null : visible.map((v) => v.alias),
          mintedAtMs: Date.now(),
          status: 'active' as const,
        },
        ...prev.filter((p) => p.agentId !== id),
      ]);
      setCopied(false);
    } catch {
      setError('license mint failed — /v1/dev/token is sandbox-only (production mints offline via scripts/mint_principal.py; see the terminal’s `ceremony`)');
    } finally {
      setBusy(false);
    }
  };

  const revokeLicense = async (l: SessionLicense): Promise<void> => {
    if (!live || revokingId !== null) return;
    setRevokingId(l.agentId);
    const res = await setPrincipalRevocation({
      apiBase: gateway.apiBase,
      tenantId: l.tenant,
      agentId: l.agentId,
      revoke: true,
      reason: 'license revoked from console',
    });
    setRevokingId(null);
    if (!res.ok) return;
    licenseStore.set((prev) => prev.map((p) => (p.agentId === l.agentId ? { ...p, status: 'revoked' as const } : p)));
  };

  const copyToken = async (token: string): Promise<void> => {
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  if (!live) {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={Fingerprint}
          title="No gateway connected"
          detail="Licensing is live-only: the sandbox IdP mints a real principal and the catalog proves its blast radius. Nothing is simulated offline — production licenses are minted offline by your IdP (scripts/mint_principal.py)."
          action={<ConnectCta />}
        />
      </Panel>
    );
  }

  return (
    <div className="grid h-full min-h-0 grid-cols-1 gap-3 xl:grid-cols-[400px_minmax(0,1fr)]">
      {/* --- License form (the "add an agent like a person" flow) ------------ */}
      <Panel>
        <div className="flex min-h-0 flex-1 flex-col gap-3.5 overflow-y-auto p-4">
          <div>
            <div className="flex items-center gap-2 text-ink">
              <Fingerprint className="h-4 w-4 text-slate-400" />
              <h3 className="text-[13.5px] font-semibold tracking-tightest">License an agent</h3>
            </div>
            <p className="mt-1.5 text-[11.5px] leading-relaxed text-slate-500">
              Bring <span className="font-medium text-ink">any</span> agent — MCPIP never restricts
              the framework or model. Licensing binds an identity, a blast radius, and entitlements;
              every action is then authorized per-call.
            </p>
          </div>

          <Field label="Agent id">
            <Input mono value={agentId} onChange={(e) => setAgentId(e.target.value)} spellCheck={false} />
          </Field>
          <p className="-mt-1.5 text-[10.5px] text-slate-500">
            Licensed as <span className="font-mono text-ink">{effectiveAgentId}</span>
          </p>
          <Field label="Tenant (your company)">
            <Input
              mono
              value={tenant}
              onChange={(e) => {
                tenantTouched.current = true;
                setTenant(e.target.value);
              }}
              spellCheck={false}
            />
          </Field>
          <Field label="Team / compartment (blast radius)">
            <Select value={compartmentId} onChange={(e) => setCompartmentId(e.target.value)}>
              {compartmentOptions.map((c) => (
                <option key={c.id} value={c.id}>{c.label}</option>
              ))}
            </Select>
          </Field>

          <details className="group">
            <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[11px] font-medium text-slate-400 transition-colors hover:text-ink">
              <ChevronRight className="h-3 w-3 shrink-0 text-slate-500 transition-transform group-open:rotate-90" />
              Advanced
              <span className="ml-auto text-[10px] text-slate-500">vendor · role · grant officer</span>
            </summary>
            <div className="mt-3 flex flex-col gap-3.5">
              <Field label="Vendor (part of the agent id)">
                <Select value={vendor} onChange={(e) => setVendor(e.target.value as VendorId)}>
                  {VENDORS.map((v) => (
                    <option key={v.value} value={v.value}>{v.label}</option>
                  ))}
                </Select>
              </Field>
              <Field label="Role (descriptive only — authorizes nothing)">
                <Select value={role} onChange={(e) => setRole(e.target.value as RoleId)}>
                  {(Object.keys(ROLE_LABEL) as RoleId[]).map((r) => (
                    <option key={r} value={r}>{ROLE_LABEL[r]}</option>
                  ))}
                </Select>
              </Field>
              <label className="flex items-start gap-2 text-[12px] text-slate-400">
                <input
                  type="checkbox"
                  checked={grantOfficer}
                  onChange={(e) => setGrantOfficer(e.target.checked)}
                  className="mt-0.5 accent-ink"
                />
                <span>
                  Grant-issuing officer{' '}
                  <span className="text-slate-500">
                    (coarse capability + the scoped <span className="font-mono">grant_capability_for</span> of the chosen team, derived at mint)
                  </span>
                </span>
              </label>
              {grantOfficer && compartment.uuid === null ? (
                <p className="-mt-1 text-[10.5px] leading-relaxed text-staged">
                  Company-wide officer mints the coarse capability only — scoped issuing authority is
                  per-team; pick a team to derive it into the JWT.
                </p>
              ) : null}
            </div>
          </details>

          {error !== null ? (
            <p className="rounded-lg border border-denied/25 bg-denied/5 px-2.5 py-1.5 text-[11px] leading-relaxed text-denied">{error}</p>
          ) : null}

          <button type="button" onClick={() => void issue()} disabled={busy} className="btn-primary w-full py-2">
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Plus className="h-3.5 w-3.5" />}
            {busy ? 'issuing license…' : 'Issue license (live)'}
          </button>

          <p className="text-[10.5px] leading-relaxed text-slate-500">
            The sandbox IdP mints bearer tokens; production licenses are sender-constrained via the
            offline PoP key ceremony (<span className="font-mono">--cnf-jkt</span>) — run{' '}
            <span className="font-mono">ceremony</span> in the console below for the exact command.
          </p>
        </div>
      </Panel>

      {/* --- Roster (expandable rows) + live console ------------------------- */}
      <div className="flex min-h-0 flex-col gap-3">
        <Panel className="min-h-0 flex-1">
          <PanelHeader
            title="Licensed this session"
            icon={ScrollText}
            right={<span className="tabular">{issued.length}</span>}
          />
          <div className="min-h-0 flex-1 overflow-y-auto">
            {issued.length === 0 ? (
              <p className="px-4 py-6 text-center text-[11.5px] text-slate-500">
                Issued licenses appear here with live revocation. Session record only — a reload
                clears it; identities live in your IdP, never in this console.
              </p>
            ) : (
              <table className="w-full border-collapse text-left">
                <thead className="sticky top-0 bg-surface">
                  <tr className="border-b border-hairline">
                    <th className={`px-3 py-2 ${LABEL}`}>Agent</th>
                    <th className={`px-3 py-2 ${LABEL}`}>Scope</th>
                    <th className={`px-3 py-2 ${LABEL}`}>Sees</th>
                    <th className={`px-3 py-2 ${LABEL}`}>Status</th>
                    <th className={`px-3 py-2 text-right ${LABEL}`}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {issued.map((l) => (
                    <Fragment key={l.agentId}>
                      <tr className="border-b border-hairline/60 last:border-0 hover:bg-canvas">
                        <td className="px-3 py-2">
                          <button
                            type="button"
                            onClick={() => toggleRow(l.agentId)}
                            className="flex items-center gap-1.5 text-left"
                            aria-expanded={isRowOpen(l.agentId)}
                          >
                            <ChevronRight className={`h-3 w-3 shrink-0 text-slate-500 transition-transform ${isRowOpen(l.agentId) ? 'rotate-90' : ''}`} />
                            <span className="font-mono text-[12px] text-ink">{l.agentId}</span>
                          </button>
                        </td>
                        <td className="px-3 py-2 text-[11.5px] text-slate-400">
                          {l.compartmentUuid ? l.compartmentLabel : 'tenant-wide'}
                          {l.grantOfficer ? ' · officer' : ''}
                        </td>
                        <td className="tabular px-3 py-2 font-mono text-[11px] text-slate-400">
                          {l.visibleAliases === null ? '—' : `${l.visibleAliases.length} aliases`}
                        </td>
                        <td className="px-3 py-2">
                          <span className={`text-[11px] font-medium ${l.status === 'active' ? 'text-verified' : 'text-denied'}`}>
                            {l.status}
                          </span>
                        </td>
                        <td className="px-3 py-2 text-right">
                          <button
                            type="button"
                            disabled={l.status === 'revoked' || revokingId !== null}
                            onClick={() => void revokeLicense(l)}
                            className="inline-flex items-center gap-1 rounded-md border border-hairline px-2 py-1 text-[11px] text-slate-400 transition-colors hover:border-denied/30 hover:text-denied disabled:opacity-40"
                          >
                            {revokingId === l.agentId ? <Loader2 className="h-3 w-3 animate-spin" /> : <Ban className="h-3 w-3" />}
                            Revoke
                          </button>
                        </td>
                      </tr>
                      {isRowOpen(l.agentId) ? (
                        <tr className="border-b border-hairline/60 last:border-0">
                          <td colSpan={5} className="px-3 pb-3 pt-0">
                            <div className="rounded-lg border border-hairline bg-canvas p-3">
                              <div className="flex items-center gap-2">
                                <ShieldCheck className="h-3.5 w-3.5 shrink-0 text-verified" />
                                <code className="min-w-0 flex-1 truncate rounded-md border border-hairline bg-surface px-2.5 py-1.5 font-mono text-[10.5px] text-slate-400">
                                  {l.token.slice(0, 28)}…{l.token.slice(-10)}
                                </code>
                                <button type="button" onClick={() => void copyToken(l.token)} className="btn-ghost shrink-0">
                                  {copied ? 'Copied' : 'Copy JWT'}
                                </button>
                              </div>
                              <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">
                                Drop this into the agent&apos;s environment (e.g.{' '}
                                <span className="font-mono">MCPIP_TOKEN</span>) — any framework, any model.
                                Short-lived by design; re-mint on expiry.
                              </p>
                              <div className="mt-3 border-t border-hairline pt-3">
                                <p className={`mb-1.5 ${LABEL}`}>
                                  Proven blast radius — what this license actually sees (live /v1/catalog)
                                </p>
                                {l.visibleAliases === null ? (
                                  <p className="text-[11.5px] text-slate-500">catalog check unavailable</p>
                                ) : l.visibleAliases.length === 0 ? (
                                  <p className="text-[11.5px] text-slate-500">this identity enumerates nothing</p>
                                ) : (
                                  <div className="flex flex-wrap gap-1">
                                    {l.visibleAliases.map((a) => (
                                      <span key={a} className="rounded-md border border-hairline bg-surface px-1.5 py-0.5 font-mono text-[10.5px] text-slate-400">
                                        {a}
                                      </span>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      ) : null}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Panel>

        {/* Live ceremony console — behind a toggle for density. Real mint/tools/call
            round-trips against the gateway; `ceremony` prints the offline equivalent. */}
        <div className="shrink-0">
          <button
            type="button"
            onClick={() => setShowConsole((v) => !v)}
            className="flex w-full items-center gap-1.5 rounded-lg border border-hairline bg-surface px-3 py-2 text-[12px] font-medium text-slate-400 transition-colors hover:text-ink"
            aria-expanded={showConsole}
          >
            <ChevronRight className={`h-3.5 w-3.5 shrink-0 text-slate-500 transition-transform ${showConsole ? 'rotate-90' : ''}`} />
            Live ceremony console
            <span className="ml-auto text-[10.5px] text-slate-500">real mint · tools · call — offline equivalent via `ceremony`</span>
          </button>
          {showConsole ? <LicenseTerminal gateway={gateway} className="mt-3 h-[250px]" /> : null}
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------- entitlements */

/** Copy-to-clipboard affordance for a protocol id — brief ✓ flash, no toast. */
function CopyId({ value, label }: { value: string; label: string }): JSX.Element {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(t);
  }, [copied]);
  return (
    <button
      type="button"
      title={`Copy ${label}`}
      onClick={() => {
        navigator.clipboard
          .writeText(value)
          .then(() => setCopied(true))
          .catch(() => {
            /* clipboard unavailable (permissions / insecure context) — nothing to fake */
          });
      }}
      className="shrink-0 text-slate-500 transition-colors hover:text-ink focus:outline-none focus-visible:shadow-focus-ring"
    >
      {copied ? <Check size={12} className="text-verified" /> : <Copy size={12} />}
    </button>
  );
}

/**
 * What each license entitlement actually gates — real product surfaces, quoted
 * from the engine: scripts/gen_license.py `_DEFAULT_ENTITLEMENTS`, the /v1/mcp
 * edge in app/main.py, the mcpip-verify export CLI, and GET /metrics.
 */
const ENTITLEMENT_SURFACES: ReadonlyArray<{ id: string; surface: string; gates: string }> = [
  {
    id: 'authorize',
    surface: 'POST /v1/authorize',
    gates: 'The REST authorization choke point — every agent tool call flows through it.',
  },
  {
    id: 'mcp_edge',
    surface: 'POST /v1/mcp',
    gates: 'The MCP JSON-RPC 2.0 edge (initialize · tools/list · tools/call), Streamable-HTTP single-request mode.',
  },
  {
    id: 'audit_export',
    surface: 'mcpip export-audit',
    gates: 'Sealed-ledger export for the external verifier — epoch roots and the Ed25519 chain.',
  },
  {
    id: 'metrics',
    surface: 'GET /metrics',
    gates: 'Prometheus exposition — closed-enum labels only, never tenant or agent data.',
  },
];

/** One entitlement row: name · state badge · the surface it names. */
function EntitlementRow({
  id,
  state,
}: {
  id: string;
  state: 'entitled' | 'not licensed' | 'reference';
}): JSX.Element {
  const known = ENTITLEMENT_SURFACES.find((e) => e.id === id) ?? null;
  return (
    <div className="border-b border-hairline/60 bg-canvas px-3 py-2 last:border-0">
      <div className="flex items-center gap-2">
        <span className="truncate font-mono text-[11.5px] text-ink">{id}</span>
        <Badge tone={state === 'entitled' ? 'verified' : 'muted'}>{state}</Badge>
        <span className="ml-auto hidden shrink-0 font-mono text-[10.5px] text-slate-400 sm:block">
          {known?.surface ?? '—'}
        </span>
      </div>
      <p className="mt-1 text-[10.5px] leading-relaxed text-slate-500">
        {known?.gates ?? 'Not in this console’s surface registry — the signed license document is the authority on its meaning.'}
      </p>
    </div>
  );
}

/** The boot-verified license document, rendered without invention. */
function LicensePanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const lic: LicenseInfo | null = gateway.license;

  let body: JSX.Element;
  if (!live) {
    // Wrapped so EmptyState's h-full resolves against the flex-sized remainder
    // (the panel also carries a footer, unlike the single-child empty panels).
    body = (
      <div className="min-h-0 flex-1">
        <EmptyState
          icon={ScrollText}
          title="No gateway connected"
          detail="Entitlements come from the gateway's boot-verified license document (/v1/license). Nothing is shown that a gateway did not answer."
          action={<ConnectCta />}
        />
      </div>
    );
  } else if (lic === null) {
    body = (
      <div className="min-h-0 flex-1">
        <EmptyState
          icon={ShieldAlert}
          title="License surface unavailable"
          detail="GET /v1/license is not answering for this console's identity. The read is JWT-gated and fails soft — nothing is assumed in its place."
        />
      </div>
    );
  } else if (!lic.licensed) {
    body = (
      <div className="min-h-0 flex-1 space-y-3 overflow-y-auto px-4 py-4">
        <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11.5px] leading-relaxed text-slate-400">
          <ShieldAlert size={14} className="mt-0.5 shrink-0" />
          <span>
            <span className="font-semibold">Sandbox boot — no entitlement document.</span> A
            production gateway refuses to boot without a valid Ed25519-signed license (fail-closed);
            the sandbox skips the gate and holds no entitlements.
          </span>
        </div>
        <div>
          <p className={`mb-1.5 ${LABEL}`}>Standard entitlements · reference</p>
          <div className="overflow-hidden rounded-lg border border-hairline">
            {ENTITLEMENT_SURFACES.map((e) => (
              <EntitlementRow key={e.id} id={e.id} state="reference" />
            ))}
          </div>
          <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">
            The four defaults <span className="font-mono">scripts/gen_license.py</span> mints —
            shown as reference only; this gateway holds none of them.
          </p>
        </div>
      </div>
    );
  } else {
    const held = lic.entitlements ?? [];
    const missing = ENTITLEMENT_SURFACES.map((e) => e.id).filter((id) => !held.includes(id));
    body = (
      <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <Detail label="License id" mono span>{lic.license_id ?? '—'}</Detail>
          <Detail label="Customer">{lic.customer ?? '—'}</Detail>
          <Detail label="Tier" mono>{lic.tier ?? '—'}</Detail>
          <Detail label="Issued" mono>{formatDateTime(lic.issued_at)}</Detail>
          <Detail label="Expires" mono>{formatDateTime(lic.expires_at)}</Detail>
        </dl>
        <div>
          <p className={`mb-1.5 ${LABEL}`}>Entitlements · {held.length}</p>
          {held.length === 0 ? (
            <p className="rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] text-slate-500">
              The verified document names no entitlements.
            </p>
          ) : (
            <div className="overflow-hidden rounded-lg border border-hairline">
              {held.map((id) => (
                <EntitlementRow key={id} id={id} state="entitled" />
              ))}
            </div>
          )}
        </div>
        {missing.length > 0 ? (
          <details className="group">
            <summary className="flex cursor-pointer list-none items-center gap-1.5 text-slate-400 transition-colors hover:text-ink">
              <ChevronRight className="h-3 w-3 shrink-0 text-slate-500 transition-transform group-open:rotate-90" />
              <span className={LABEL}>Not in this license</span>
              <span className="ml-auto font-mono text-[10.5px] text-slate-500">{missing.length}</span>
            </summary>
            <div className="mt-1.5 overflow-hidden rounded-lg border border-hairline">
              {missing.map((id) => (
                <EntitlementRow key={id} id={id} state="not licensed" />
              ))}
            </div>
          </details>
        ) : null}
      </div>
    );
  }

  return (
    <Panel className="min-h-0">
      <PanelHeader
        title="License entitlements"
        icon={ScrollText}
        right={<span className="font-mono text-[10.5px]">/v1/license · boot-verified</span>}
      />
      {body}
      <div className="shrink-0 border-t border-hairline px-4 py-2.5">
        <p className="text-[10.5px] leading-relaxed text-slate-500">
          Entitlements gate <span className="font-medium text-ink">process boot only</span> —
          verified fail-closed at start, never consulted by the per-request pipeline. That
          separation keeps commercial state out of the security decision path
          (<span className="font-mono">core/licensing.py</span>).
        </p>
      </div>
    </Panel>
  );
}

/** One engine-pinned governance capability + the surfaces it unlocks. */
interface CapabilityRow {
  name: string;
  uuid: string;
  authority: string;
  unlocks: ReadonlyArray<string>;
  note?: string;
}

const CAPABILITY_ROWS: ReadonlyArray<CapabilityRow> = [
  {
    name: 'CAP_DIRECTORY_ADMIN',
    uuid: CAP_DIRECTORY_ADMIN,
    authority:
      'Operator kill-switch + directory authority. DENY-only: it can block a principal’s requests, never mint one — IdP sovereignty stands.',
    unlocks: [
      '/v1/admin/principals/{agent}/revoke · /reactivate · /revoked',
      '/v1/admin/decisions/recent — the Audit Ledger + Decision Stream feed',
      '/v1/admin/quarantine · /v1/admin/canaries — tripwire rosters',
      '/v1/admin/skills/* — register · deregister · disable · enable',
      '/v1/admin/cloud/environments · /v1/admin/vault/secrets',
      '/v1/directory — this org chart’s persistence',
    ],
  },
  {
    name: 'CAP_COMPARTMENT_GRANT',
    uuid: CAP_COMPARTMENT_GRANT,
    authority:
      'Marks a grant-issuing authority: admits the holder to the skill_compartment_grant EXECUTE mandate (PIN step-up, payload-locked, WORM-logged).',
    unlocks: ['skill_compartment_grant — stage (202) → one-time code → consume'],
    note: 'Issuing for compartment X additionally requires the scoped grant_capability_for(X) below — the coarse capability alone is never a tenant-wide master key.',
  },
  {
    name: 'CAP_COMPARTMENT_REVOKE',
    uuid: CAP_COMPARTMENT_REVOKE,
    authority: 'Delegated-grant revocation authority — reserved by the engine.',
    unlocks: [],
    note: 'No revoke mandate is wired in this build: a delegated grant expires by Redis TTL only. The immediate cut is the principal kill-switch (Org Hierarchy).',
  },
];

/**
 * Live scoped-capability derivation — uuid5(CAP_COMPARTMENT_GRANT, X), computed
 * in this browser with WebCrypto, byte-identical to interfaces.py
 * `grant_capability_for` (verified derivation — see lib/uuidv5.ts). Real
 * cryptography over the operator's own compartments, not a lookup table.
 */
function DeriveScopedCap({ teams }: { teams: ReadonlyArray<CompanyTeam> }): JSX.Element {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<{ compartment: string; capability: string } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const derive = async (value: string): Promise<void> => {
    const v = value.trim();
    if (!isUuid(v)) {
      setErr('not a well-formed UUID — the engine fails closed on malformed compartments');
      setResult(null);
      return;
    }
    setErr(null);
    setResult({ compartment: v, capability: await grantCapabilityFor(v) });
  };

  return (
    <div className="shrink-0 border-t border-hairline px-4 py-3">
      <p className={`mb-1.5 ${LABEL}`}>Derive a scoped grant capability</p>
      <div className="flex items-center gap-2">
        <Input
          mono
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="compartment UUID"
          spellCheck={false}
          aria-label="Compartment UUID to derive the scoped grant capability for"
        />
        <button type="button" onClick={() => void derive(input)} className="btn-ghost shrink-0">
          Derive
        </button>
      </div>
      {teams.length > 0 ? (
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {teams.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => {
                setInput(t.compartment);
                void derive(t.compartment);
              }}
              className="rounded-full border border-hairline bg-surface px-2.5 py-1 text-[10.5px] text-slate-500 transition-colors hover:border-ink/20 hover:text-ink"
            >
              {t.name}
            </button>
          ))}
        </div>
      ) : null}
      {err !== null ? <p className="mt-2 text-[11px] leading-relaxed text-denied">{err}</p> : null}
      {result !== null ? (
        <div className="mt-2 overflow-hidden rounded-lg border border-hairline">
          <div className="flex items-center gap-2 border-b border-hairline/60 bg-canvas px-2.5 py-1.5">
            <span className="shrink-0 text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">for</span>
            <span className="truncate font-mono text-[11px] text-slate-400">{result.compartment}</span>
          </div>
          <div className="flex items-center gap-2 bg-canvas px-2.5 py-1.5">
            <span className="shrink-0 text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">scoped cap</span>
            <span className="truncate font-mono text-[11px] text-ink">{result.capability}</span>
            <span className="ml-auto">
              <CopyId value={result.capability} label="scoped grant capability" />
            </span>
          </div>
        </div>
      ) : null}
      <p className="mt-2 text-[10.5px] leading-relaxed text-slate-500">
        <span className="font-mono">uuid5(CAP_COMPARTMENT_GRANT, X)</span> — derived here with
        WebCrypto, byte-identical to <span className="font-mono">interfaces.py grant_capability_for</span>.
        Put it (plus the coarse capability) in an officer&apos;s JWT{' '}
        <span className="font-mono">capabilities</span> claim to authorize grant issuance for exactly
        that compartment.
      </p>
    </div>
  );
}

/**
 * Entitlements — the REAL entitlement surface, replacing the old fixture RBAC
 * matrix (a role-keyed grid the gateway never read, contradicting the
 * product's own invariant). Left: the boot-verified license document. Right:
 * the engine-pinned governance capability registry with live derivation.
 */
function Entitlements({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { config } = useCompanyConfig();
  return (
    <div className="flex h-full min-h-0 flex-col gap-3">
      <p className="shrink-0 text-[12.5px] leading-relaxed text-slate-500">
        <span className="font-medium text-ink">The role claim authorizes nothing.</span> A principal
        may perform a privileged action iff it holds the required{' '}
        <span className="font-medium text-ink">capability UUID</span> — carried in the JWT{' '}
        <span className="font-mono text-[11.5px]">capabilities</span> claim and/or a Redis-held
        grant (<span className="font-mono text-[11.5px]">interfaces.py §1.1b</span>). There is no
        role × permission matrix to edit, because the gateway never consults one.
      </p>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-2">
        <LicensePanel gateway={gateway} />

        <Panel className="min-h-0">
          <PanelHeader
            title="Governance capabilities"
            icon={KeyRound}
            right={<span className="font-mono text-[10.5px]">engine-pinned · interfaces.py</span>}
          />
          <div className="min-h-0 flex-1 overflow-y-auto">
            {CAPABILITY_ROWS.map((cap) => (
              <div key={cap.uuid} className="border-b border-hairline/60 px-4 py-3 last:border-0">
                <p className="text-[12px] font-semibold text-ink">{cap.name}</p>
                <div className="mt-1 flex items-center gap-2">
                  <span className="truncate font-mono text-[11px] text-slate-400">{cap.uuid}</span>
                  <CopyId value={cap.uuid} label={cap.name} />
                </div>
                <p className="mt-1.5 text-[11px] leading-relaxed text-slate-500">{cap.authority}</p>
                {cap.unlocks.length > 0 ? (
                  <details className="group mt-1.5">
                    <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[10.5px] font-medium uppercase tracking-[0.08em] text-slate-500 transition-colors hover:text-ink">
                      <ChevronRight className="h-3 w-3 shrink-0 transition-transform group-open:rotate-90" />
                      Unlocks {cap.unlocks.length} surface{cap.unlocks.length === 1 ? '' : 's'}
                    </summary>
                    <ul className="mt-1.5 space-y-0.5">
                      {cap.unlocks.map((u) => (
                        <li key={u} className="flex items-baseline gap-1.5 text-[10.5px] leading-relaxed text-slate-500">
                          <span className="select-none text-slate-600">·</span>
                          <span className="font-mono">{u}</span>
                        </li>
                      ))}
                    </ul>
                  </details>
                ) : null}
                {cap.note !== undefined ? (
                  <p className="mt-1.5 text-[10.5px] leading-relaxed text-slate-500">{cap.note}</p>
                ) : null}
              </div>
            ))}
          </div>
          <DeriveScopedCap teams={config?.teams ?? []} />
        </Panel>
      </div>
    </div>
  );
}
