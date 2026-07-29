import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  Play,
  PlugZap,
  Square,
  Plus,
  Trash2,
  Loader2,
  ShieldAlert,
  Boxes,
  Bug,
  Info,
  X,
  Search,
  Package,
  MousePointerClick,
  ChevronRight,
} from 'lucide-react';
import { truncateId, formatRelative, formatDateTime } from '../lib/format';
import {
  loadDisabledSkills,
  loadRegisteredSkills,
  setSkillDisabled,
  registerSkill,
  deregisterSkill,
} from '../lib/skillGate';
import { catalog as fetchCatalog, mintDevToken } from '../lib/api';
import { DEFENSE_TENANT, SEED_COMPARTMENT_LIST } from '../lib/protocol';
import { useCompanyConfig } from '../lib/companyConfig';
import type { CompanyTeam } from '../lib/companyConfig';
import { Panel, Badge, Field, Input, Select, EmptyState, Detail } from './ui';
import type {
  RiskTier,
  TransportClass,
  Classification,
  CatalogItem,
  Compartment,
  SkillAccess,
} from '../lib/types';
import type { GatewayLive } from '../lib/useGatewayLive';

/** Turn a plain-language description into a safe alias/target slug. */
function slugify(text: string, sep: '_' | '.'): string {
  const s = text.toLowerCase().replace(/[^a-z0-9]+/g, sep);
  return s.replace(new RegExp(`^\\${sep}+|\\${sep}+$`, 'g'), '');
}

/**
 * Client mirror of obfuscator.alias_registry.display_service — the fallback service
 * label for an alias with no stored label: strip the leading "skill_", underscores
 * become spaces.
 */
export function displayService(alias: string): string {
  const stripped = alias.startsWith('skill_') ? alias.slice('skill_'.length) : alias;
  return stripped.replace(/_/g, ' ');
}

/**
 * Skills — the operator's permission table for the obfuscator catalog, in the shape of
 * an API-token permission list: each SERVICE is listed once with a Read and a Write
 * control. A checked box means agents may call the alias behind it; unchecking denies
 * it (SKILL_DISABLED) until re-checked — the same hot-path kill-switch as before, it
 * never edits the alias→target mapping. A box is present only when an alias with that
 * access level exists for the service.
 *
 * Expanding a service lists its underlying aliases; the inspector shows the per-alias
 * detail (transport, risk tier, compartment) and holds the per-alias controls,
 * including deregister for operator-added skills. Canary decoys are badged from the
 * operator-only GET /v1/admin/canaries roster (the agent-facing catalog keeps hiding
 * the flag), and unchecking one asks for confirmation — a stopped decoy is a disarmed
 * tripwire.
 *
 * "View as" re-reads GET /v1/catalog under a per-team identity, so the rows shown are
 * exactly what that team's agents can enumerate. Agents only ever see the alias.
 * Offline is honestly empty — no fabricated catalog.
 */

/* ---------------------------------------------------------------------------
   Compartment sources — the "view as" universe. Operator teams come from the
   persisted company config (first-run setup / Company Settings); on the two
   sandbox showcase tenants the server-seeded compartments are appended so the
   seeded separation is inspectable. Seeds are shown ONLY for the tenant that
   actually owns them server-side — offering project-falcon on a company tenant
   would claim a view the gateway cannot serve.
--------------------------------------------------------------------------- */

export interface CompartmentSource {
  /** Stable list key. */
  key: string;
  /** Human label (team name / seed compartment label). */
  label: string;
  /** The compartment UUID carried in probe JWTs and catalog rows. */
  uuid: string;
  /** 'team' = operator company config · 'seed' = sandbox-seeded showcase compartment. */
  origin: 'team' | 'seed';
}

/**
 * obfuscator/tenant_catalog.py `MCPIP_ENGINEERING` / `MCPIP_FINANCE` +
 * INDUSTRY_COMPARTMENTS['mcpip-inc'] labels/classifications, verbatim — the
 * demo company's two seeded compartments (the runnable A→Z walkthrough). Same
 * pinning discipline as protocol.ts: the backend file is authoritative.
 */
const MCPIP_INC_TENANT = 'mcpip-inc';
const MCPIP_SEED_COMPARTMENTS: ReadonlyArray<Compartment> = [
  {
    compartment_uuid: 'e0900000-0000-4000-8000-e0900000e090',
    label: 'team-engineering',
    classification: 'restricted',
  },
  {
    compartment_uuid: 'f1a00000-0000-4000-8000-f1a00000f1a0',
    label: 'team-finance',
    classification: 'restricted',
  },
];

/**
 * The compartments an operator can "view as" / separation-check: their own
 * teams first, then any server-seeded compartments of the connected tenant.
 * De-duplicated by UUID (a team deliberately mapped onto a seed wins).
 */
export function compartmentSources(
  teams: ReadonlyArray<CompanyTeam>,
  liveTenant: string | null,
): CompartmentSource[] {
  const out: CompartmentSource[] = [];
  const seen = new Set<string>();
  for (const t of teams) {
    if (!t.compartment || seen.has(t.compartment)) continue;
    seen.add(t.compartment);
    out.push({ key: `team:${t.id}`, label: t.name, uuid: t.compartment, origin: 'team' });
  }
  const seeds: ReadonlyArray<Compartment> =
    liveTenant === DEFENSE_TENANT
      ? SEED_COMPARTMENT_LIST
      : liveTenant === MCPIP_INC_TENANT
        ? MCPIP_SEED_COMPARTMENTS
        : [];
  for (const c of seeds) {
    if (seen.has(c.compartment_uuid)) continue;
    seen.add(c.compartment_uuid);
    out.push({ key: `seed:${c.label}`, label: c.label, uuid: c.compartment_uuid, origin: 'seed' });
  }
  return out;
}

/* ---------------------------------------------------------------------------
   Per-compartment live catalog — the "view as" data. Mints a (tenant,
   compartment) identity and reads GET /v1/catalog under it on the standard 5s
   cadence, so enable/disable/register reconcile in a team view exactly like the
   company-wide one. Fails honest: `failed` (never a silent fallback to the
   tenant-wide rows) when the mint or read cannot complete.
--------------------------------------------------------------------------- */

interface CompartmentViewState {
  /** Rows the scoped identity enumerated; null until the first successful read. */
  items: CatalogItem[] | null;
  /** First read in flight (no cached rows yet). */
  loading: boolean;
  /** The last read failed AND nothing was ever cached — render the honest failure. */
  failed: boolean;
}

const VIEW_POLL_MS = 5000;

function useCompartmentView(
  gateway: GatewayLive,
  tenantId: string | null,
  compartment: string | null,
): CompartmentViewState {
  const { mode, apiBase } = gateway;
  const [state, setState] = useState<CompartmentViewState>({
    items: null,
    loading: false,
    failed: false,
  });
  // Per-(base, tenant, compartment) cache so re-selecting a view is instant.
  const cacheRef = useRef<Map<string, CatalogItem[]>>(new Map());

  useEffect(() => {
    if (mode !== 'live' || !tenantId || !compartment) {
      setState({ items: null, loading: false, failed: false });
      return;
    }
    const key = `${apiBase}|${tenantId}|${compartment}`;
    const cached = cacheRef.current.get(key) ?? null;
    setState({ items: cached, loading: cached === null, failed: false });

    let cancelled = false;
    const controller = new AbortController();
    const load = async (): Promise<void> => {
      const opts = { base: apiBase, signal: controller.signal };
      try {
        const token = await mintDevToken({ tenant_id: tenantId, compartment }, opts);
        if (cancelled) return;
        const items = await fetchCatalog(token, opts);
        if (cancelled) return;
        if (items === null) {
          // Read failed — keep last-known rows if any, otherwise fail honest.
          setState((prev) => ({ items: prev.items, loading: false, failed: prev.items === null }));
          return;
        }
        cacheRef.current.set(key, items);
        setState({ items, loading: false, failed: false });
      } catch {
        if (!cancelled) {
          setState((prev) => ({ items: prev.items, loading: false, failed: prev.items === null }));
        }
      }
    };
    void load();
    const id = window.setInterval(() => {
      void load();
    }, VIEW_POLL_MS);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [mode, apiBase, tenantId, compartment]);

  return state;
}

/* --------------------------------------------------------------------------- */

interface SkillRow {
  alias: string;
  transport: TransportClass;
  risk: RiskTier;
  classification: Classification;
  compartment?: string | null;
  /** Permission-table group — the human service label. */
  service: string;
  /** Structured access level (display metadata; risk-derived when unannotated). */
  access: SkillAccess;
  /** operator-registered (deregisterable) vs config (immutable). */
  operator: boolean;
  /** running = agents may invoke it; stopped = disabled (denied SKILL_DISABLED). */
  running: boolean;
  /** Canary decoy (from the operator-only roster) — stopping it disarms a tripwire. */
  canary: boolean;
  /** When the operator registered this skill (ISO-8601); null for config skills. */
  registeredAt?: string | null;
}

/** One permission-table row: a service with its read and write aliases. */
interface ServiceGroup {
  service: string;
  rows: SkillRow[];
  reads: SkillRow[];
  writes: SkillRow[];
}

/** A stop request awaiting confirmation because it would disarm canary decoys. */
interface PendingStop {
  aliases: string[];
  canaryAliases: string[];
}

interface AliasRegistryProps {
  gateway: GatewayLive;
}

export function AliasRegistry({ gateway }: AliasRegistryProps): JSX.Element {
  const { mode, catalog, tenant, apiBase, fetchCanaries } = gateway;
  const { config } = useCompanyConfig();
  // Tenant for admin mutations: the live JWT's tenant, else the operator's company
  // profile — never a hardcoded demo tenant.
  const skillTenant = tenant ?? config?.tenant ?? null;
  const live = mode === 'live';

  const [query, setQuery] = useState('');
  const [disabled, setDisabled] = useState<Set<string>>(new Set());
  const [registered, setRegistered] = useState<Set<string>>(new Set());
  // alias → registration timestamp (ISO-8601), for operator-registered skills.
  const [registeredAt, setRegisteredAt] = useState<Map<string, string>>(new Map());
  // alias → stored service label (operator surface; config rows use the client fallback).
  const [serviceByAlias, setServiceByAlias] = useState<Map<string, string>>(new Map());
  const [busy, setBusy] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [showRegister, setShowRegister] = useState(false);
  const [bulkBusy, setBulkBusy] = useState(false);
  // Expanded permission-table groups (service labels).
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  // Optimistic overlays so register / deregister feel instant before the 5s catalog refresh.
  const [pendingAdds, setPendingAdds] = useState<SkillRow[]>([]);
  const [pendingRemoves, setPendingRemoves] = useState<Set<string>>(new Set());
  // The kill-switch is a safety control: a failed toggle must be VISIBLE, never a
  // silently-cleared spinner. One calm line, replaced by the next action.
  const [actionError, setActionError] = useState<string | null>(null);
  // Canary decoy aliases for this tenant (operator-only admin read).
  const [canaries, setCanaries] = useState<ReadonlySet<string>>(new Set());
  const [pendingStop, setPendingStop] = useState<PendingStop | null>(null);
  // "View as" — null = company-wide, else a compartment UUID from `sources`.
  const [viewAs, setViewAs] = useState<string | null>(null);

  const sources = useMemo(
    () => compartmentSources(config?.teams ?? [], live ? tenant : null),
    [config, live, tenant],
  );
  const activeSource = useMemo(
    () => sources.find((s) => s.uuid === viewAs) ?? null,
    [sources, viewAs],
  );
  // A team deleted elsewhere (or a tenant switch) must not leave a phantom view.
  useEffect(() => {
    if (viewAs !== null && !sources.some((s) => s.uuid === viewAs)) setViewAs(null);
  }, [viewAs, sources]);

  /** Resolve a compartment UUID to its team/seed label (row + inspector display). */
  const labelOf = useCallback(
    (uuid: string | null | undefined): string => {
      if (!uuid) return 'tenant-wide';
      const src = sources.find((s) => s.uuid === uuid);
      return src ? src.label : truncateId(uuid, 8, 4);
    },
    [sources],
  );

  const scopedView = useCompartmentView(gateway, skillTenant, viewAs);

  // Load the operator disable-set + registered-set for the tenant while live.
  useEffect(() => {
    if (!live || !skillTenant) {
      setDisabled(new Set());
      setRegistered(new Set());
      return;
    }
    let cancelled = false;
    const controller = new AbortController();
    void (async () => {
      const [off, reg] = await Promise.all([
        loadDisabledSkills(apiBase, skillTenant, controller.signal),
        loadRegisteredSkills(apiBase, skillTenant, controller.signal),
      ]);
      if (!cancelled) {
        setDisabled(new Set(off));
        setRegistered(new Set(reg.map((r) => r.alias)));
        setRegisteredAt((prev) => {
          const next = new Map(prev);
          for (const r of reg) if (r.registered_at) next.set(r.alias, r.registered_at);
          return next;
        });
        setServiceByAlias((prev) => {
          const next = new Map(prev);
          for (const r of reg) if (r.service) next.set(r.alias, r.service);
          return next;
        });
      }
    })();
    return () => {
      cancelled = true;
      controller.abort();
    };
  }, [live, apiBase, skillTenant]);

  // Canary roster (admin-only) — badges decoy rows and arms the stop warning.
  // Null (offline / endpoint unsupported / no admin read) leaves the set empty:
  // rows just render unbadged, never a guessed flag.
  useEffect(() => {
    if (!live) {
      setCanaries(new Set());
      return;
    }
    let cancelled = false;
    const controller = new AbortController();
    const load = async (): Promise<void> => {
      const roster = await fetchCanaries(controller.signal);
      if (!cancelled && roster !== null) setCanaries(new Set(roster.map((c) => c.alias)));
    };
    void load();
    const id = window.setInterval(() => {
      void load();
    }, 15000);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [live, apiBase, fetchCanaries]);

  const rows: SkillRow[] = useMemo(() => {
    if (!live) return [];
    // Company-wide = the gateway's own tenant-scoped poll; a team view = the rows
    // the scoped identity enumerated (still [] while loading/failed — the body
    // branches below render those states, never a silent fallback).
    const source: CatalogItem[] = viewAs === null ? catalog : scopedView.items ?? [];
    const byAlias = new Map<string, SkillRow>();
    for (const c of source) {
      if (pendingRemoves.has(c.alias)) continue;
      byAlias.set(c.alias, {
        alias: c.alias,
        transport: c.transport_class,
        risk: c.risk_tier,
        classification: (c.classification ?? 'unclassified') as Classification,
        compartment: c.compartment,
        // Service label: the stored operator label when one exists, else the alias
        // humanized (the same fallback the gateway's display helper uses).
        service: serviceByAlias.get(c.alias) ?? displayService(c.alias),
        // Access: the gateway's advisory projection; older gateways fall back to risk.
        access:
          c.access === 'read' || c.access === 'write'
            ? c.access
            : c.risk_tier === 'pin_required'
              ? 'write'
              : 'read',
        operator: registered.has(c.alias),
        running: !disabled.has(c.alias),
        canary: canaries.has(c.alias),
        registeredAt: registeredAt.get(c.alias) ?? null,
      });
    }
    // Merge optimistic adds the catalog hasn't surfaced yet (tenant-wide rows are
    // visible in every compartment view, so they belong in a team view too).
    for (const p of pendingAdds) {
      if (pendingRemoves.has(p.alias) || byAlias.has(p.alias)) continue;
      byAlias.set(p.alias, { ...p, running: !disabled.has(p.alias) });
    }
    const q = query.trim().toLowerCase();
    return [...byAlias.values()]
      .filter((r) =>
        q ? r.alias.toLowerCase().includes(q) || r.service.toLowerCase().includes(q) : true,
      )
      .sort((a, b) => a.alias.localeCompare(b.alias));
  }, [live, viewAs, catalog, scopedView.items, disabled, registered, registeredAt, serviceByAlias, canaries, pendingAdds, pendingRemoves, query]);

  // The permission table: one row per service, Read/Write as controls.
  const groups: ServiceGroup[] = useMemo(() => {
    const byService = new Map<string, SkillRow[]>();
    for (const r of rows) {
      const list = byService.get(r.service);
      if (list) list.push(r);
      else byService.set(r.service, [r]);
    }
    return [...byService.entries()]
      .map(([service, list]) => ({
        service,
        rows: list,
        reads: list.filter((r) => r.access === 'read'),
        writes: list.filter((r) => r.access === 'write'),
      }))
      .sort((a, b) => a.service.localeCompare(b.service));
  }, [rows]);

  const selectedRow = useMemo(() => rows.find((r) => r.alias === selected) ?? null, [rows, selected]);

  /** The actual kill-switch calls — shared by checkbox toggles and the canary confirm. */
  const doSetRunning = useCallback(
    async (aliases: string[], run: boolean): Promise<void> => {
      if (!skillTenant || aliases.length === 0) return;
      const single = aliases.length === 1 ? aliases[0] ?? null : null;
      if (single !== null) setBusy(single);
      else setBulkBusy(true);
      const ok: string[] = [];
      const failed: string[] = [];
      for (const alias of aliases) {
        if (await setSkillDisabled(apiBase, skillTenant, alias, !run)) ok.push(alias);
        else failed.push(alias);
      }
      setDisabled((prev) => {
        const next = new Set(prev);
        ok.forEach((a) => (run ? next.delete(a) : next.add(a)));
        return next;
      });
      setActionError(
        failed.length > 0
          ? `${run ? 'Enable' : 'Disable'} failed for ${failed.join(', ')} — the gateway refused the change or is unreachable.`
          : null,
      );
      setBusy(null);
      setBulkBusy(false);
    },
    [apiBase, skillTenant],
  );

  /** Route an enable/disable through the canary confirmation when it would disarm decoys. */
  const requestSetRunning = useCallback(
    (aliases: string[], run: boolean): void => {
      if (!run) {
        const canaryHits = aliases.filter((a) => canaries.has(a));
        if (canaryHits.length > 0) {
          setPendingStop({ aliases, canaryAliases: canaryHits });
          return;
        }
      }
      void doSetRunning(aliases, run);
    },
    [canaries, doSetRunning],
  );

  const removeSkill = useCallback(
    async (alias: string): Promise<void> => {
      if (!skillTenant) return;
      setBusy(alias);
      const res = await deregisterSkill(apiBase, skillTenant, alias);
      if (res.ok) {
        setActionError(null);
        setPendingRemoves((prev) => new Set(prev).add(alias));
        setPendingAdds((prev) => prev.filter((p) => p.alias !== alias));
        setRegistered((prev) => {
          const next = new Set(prev);
          next.delete(alias);
          return next;
        });
        if (selected === alias) setSelected(null);
      } else {
        setActionError(`Deregister failed for ${alias} — the gateway refused the change or is unreachable.`);
      }
      setBusy(null);
    },
    [apiBase, skillTenant, selected],
  );

  const onRegistered = useCallback((newRows: SkillRow[]): void => {
    if (newRows.length === 0) return;
    const aliases = new Set(newRows.map((r) => r.alias));
    setPendingRemoves((prev) => {
      const next = new Set(prev);
      newRows.forEach((r) => next.delete(r.alias));
      return next;
    });
    setPendingAdds((prev) => [...prev.filter((p) => !aliases.has(p.alias)), ...newRows]);
    setRegistered((prev) => {
      const next = new Set(prev);
      newRows.forEach((r) => next.add(r.alias));
      return next;
    });
    setRegisteredAt((prev) => {
      const next = new Map(prev);
      newRows.forEach((r) => { if (r.registeredAt) next.set(r.alias, r.registeredAt); });
      return next;
    });
    setServiceByAlias((prev) => {
      const next = new Map(prev);
      newRows.forEach((r) => next.set(r.alias, r.service));
      return next;
    });
    setShowRegister(false);
    const last = newRows[newRows.length - 1];
    if (last) {
      setSelected(last.alias);
      setExpanded((prev) => new Set(prev).add(last.service));
    }
  }, []);

  const toggleExpanded = useCallback((service: string): void => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(service)) next.delete(service);
      else next.add(service);
      return next;
    });
  }, []);

  const running = rows.filter((r) => r.running).length;
  const operatorCount = rows.filter((r) => r.operator).length;
  const anyBusy = busy !== null || bulkBusy;

  const teamViewPending = viewAs !== null && scopedView.loading;
  const teamViewFailed = viewAs !== null && scopedView.failed;

  const inspector = selectedRow ? (
    <Inspector
      row={selectedRow}
      compartmentLabel={labelOf}
      busy={busy === selectedRow.alias}
      onToggle={() => requestSetRunning([selectedRow.alias], !selectedRow.running)}
      onRemove={() => void removeSkill(selectedRow.alias)}
    />
  ) : (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 text-center">
      <MousePointerClick size={22} className="text-slate-600" />
      <p className="text-[12.5px] font-medium text-slate-400">Select a skill</p>
      <p className="max-w-[220px] text-[11.5px] leading-relaxed text-slate-500">
        Expand a service and pick an alias to inspect its transport, risk tier, and
        status — or to deregister one you added.
      </p>
    </div>
  );

  return (
    <div className="flex h-full flex-col gap-3">
      {/* Toolbar */}
      <div className="panel">
        <div className="flex flex-wrap items-center gap-2.5 px-3.5 py-2.5">
          <div className="flex items-center gap-2">
            <Boxes size={15} className="text-slate-500" />
            <span className="text-[13.5px] font-semibold tracking-tightest text-ink">Skills &amp; Tools</span>
          </div>
          {/* View-as — one dropdown re-scopes the catalog read to a team's real
              identity (the gateway applies the compartment filter, not the console). */}
          {live && sources.length > 0 ? (
            <div className="w-[200px]">
              <Select
                value={viewAs ?? ''}
                onChange={(e) => setViewAs(e.target.value || null)}
                title="View the catalog exactly as a team's agents enumerate it — the gateway applies the filter"
              >
                <option value="">company-wide</option>
                {sources.map((s) => (
                  <option key={s.key} value={s.uuid}>
                    view as {s.label}
                  </option>
                ))}
              </Select>
            </div>
          ) : null}

          <div className="ml-auto flex flex-wrap items-center gap-2">
            {live ? (
              <div className="relative">
                <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Filter services"
                  className="w-[160px] rounded-lg border border-hairline bg-canvas py-1.5 pl-8 pr-3 text-[12.5px] text-ink placeholder:text-slate-500 focus:border-ink/30 focus:outline-none focus:shadow-focus-ring"
                />
              </div>
            ) : null}
            <button
              type="button"
              onClick={() => setShowRegister(true)}
              disabled={!live}
              className="btn-primary h-[34px]"
              title={live ? 'Register a new skill' : 'Connect a gateway to register a skill'}
            >
              <Plus size={14} /> Register skill
            </button>
          </div>
        </div>
      </div>

      {/* Master-Detail */}
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-[1fr_380px]">
        <Panel>
          <div className="flex shrink-0 items-center justify-between gap-2 border-b border-hairline px-4 py-2 min-h-[45px]">
            <span className="text-[13px] font-semibold text-ink">Permissions</span>
            <span className="tabular text-[11px] text-slate-500">
              {teamViewPending || teamViewFailed
                ? '—'
                : `${groups.length} services · ${rows.length} skills · ${running} enabled${operatorCount > 0 ? ` · ${operatorCount} operator` : ''}${activeSource ? ` · as ${activeSource.label}` : ''}`}
            </span>
          </div>

          {actionError !== null ? (
            <div className="flex items-start gap-2 border-b border-hairline/60 bg-denied/5 px-4 py-2 text-[11px] leading-relaxed text-denied">
              <ShieldAlert size={13} className="mt-0.5 shrink-0" />
              <span className="min-w-0 flex-1">{actionError}</span>
              <button type="button" onClick={() => setActionError(null)} title="Dismiss" className="shrink-0 text-denied/70 transition-colors hover:text-denied">
                <X size={13} />
              </button>
            </div>
          ) : null}

          {!live ? (
            <EmptyState
              icon={Package}
              title="No gateway connected"
              detail="The permission table is live-only: every checkbox, registration, and inspection acts on the real catalog the gateway serves — nothing is fabricated offline."
              action={
                <button
                  type="button"
                  onClick={() =>
                    window.dispatchEvent(
                      new CustomEvent('mcpip:navigate', { detail: { view: 'gateway', subtab: 'connection' } }),
                    )
                  }
                  className="btn-primary"
                >
                  <PlugZap size={13} /> Connect a gateway
                </button>
              }
            />
          ) : teamViewPending ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-12 text-center">
              <Loader2 size={20} className="animate-spin text-slate-500" />
              <p className="text-[12.5px] font-medium text-slate-400">
                Reading the catalog as {activeSource?.label ?? 'this team'}
              </p>
              <p className="max-w-sm text-[11.5px] leading-relaxed text-slate-500">
                A per-team identity is being minted so the gateway itself applies the compartment filter.
              </p>
            </div>
          ) : teamViewFailed ? (
            <EmptyState
              icon={ShieldAlert}
              title="Team view unavailable"
              detail="The per-team identity could not be minted — switch back to the company-wide view."
              action={
                <button type="button" onClick={() => setViewAs(null)} className="btn-ghost">
                  Back to company-wide
                </button>
              }
            />
          ) : groups.length === 0 ? (
            <EmptyState
              icon={Package}
              title={
                query
                  ? 'No services match your filter'
                  : activeSource
                    ? `No skills visible to ${activeSource.label} agents`
                    : 'No skills visible for this identity'
              }
              detail={
                query
                  ? undefined
                  : activeSource
                    ? 'Un-compartmented skills are visible to every team; rows scoped to other compartments are not even enumerable here.'
                    : 'Register a skill to make a new alias→target authorizable for this tenant.'
              }
            />
          ) : (
            <div className="min-h-0 flex-1 overflow-y-auto">
              {/* Column headers — the token-permission shape: service once, two controls. */}
              <div className="flex items-center gap-3 border-b border-hairline bg-canvas px-4 py-1.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
                <span className="w-[15px]" />
                <span className="min-w-0 flex-1">Service</span>
                <span className="w-14 text-center">Read</span>
                <span className="w-14 text-center">Write</span>
              </div>
              {groups.map((g) => (
                <ServiceGroupRow
                  key={g.service}
                  group={g}
                  expanded={expanded.has(g.service)}
                  selected={selected}
                  disabledAll={anyBusy}
                  compartmentLabel={labelOf}
                  onToggleExpand={() => toggleExpanded(g.service)}
                  onSelect={(alias) => setSelected(alias)}
                  onSetRunning={requestSetRunning}
                />
              ))}
            </div>
          )}
        </Panel>

        {/* Inspector (side pane at xl and up) */}
        <Panel className="hidden xl:flex">{inspector}</Panel>
      </div>

      {/* Below xl the inspector stacks under the list when a row is selected. */}
      {selectedRow ? <Panel className="max-h-[55vh] shrink-0 xl:hidden">{inspector}</Panel> : null}

      <AnimatePresence>
        {showRegister && skillTenant ? (
          <RegisterDialog
            apiBase={apiBase}
            tenant={skillTenant}
            existing={new Set([...catalog.map((c) => c.alias), ...rows.map((r) => r.alias)])}
            onClose={() => setShowRegister(false)}
            onRegistered={onRegistered}
          />
        ) : null}
        {pendingStop !== null ? (
          <StopCanaryDialog
            pending={pendingStop}
            onCancel={() => setPendingStop(null)}
            onConfirm={() => {
              const p = pendingStop;
              setPendingStop(null);
              void doSetRunning(p.aliases, false);
            }}
          />
        ) : null}
      </AnimatePresence>
    </div>
  );
}

/* --- status dot ------------------------------------------------------------ */

function StatusDot({ running, size = 8 }: { running: boolean; size?: number }): JSX.Element {
  return (
    <span
      className={`inline-block shrink-0 rounded-full ${running ? 'bg-verified' : 'bg-denied'}`}
      style={{ width: size, height: size, boxShadow: running ? '0 0 0 3px rgba(5,150,105,0.12)' : '0 0 0 3px rgba(220,38,38,0.10)' }}
    />
  );
}

/* --- one permission checkbox ------------------------------------------------
   Present only when the service has an alias with that access level. Checked =
   every such alias is enabled; a mixed set renders indeterminate. Toggling calls
   the same enable/disable endpoints as ever — a deny-only availability control.
--------------------------------------------------------------------------- */

function AccessCheckbox({
  aliases,
  disabled,
  label,
  service,
  onSetRunning,
}: {
  aliases: SkillRow[];
  disabled: boolean;
  label: 'Read' | 'Write';
  service: string;
  onSetRunning: (aliases: string[], run: boolean) => void;
}): JSX.Element {
  const allOn = aliases.length > 0 && aliases.every((r) => r.running);
  const someOn = aliases.some((r) => r.running);
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) ref.current.indeterminate = someOn && !allOn;
  }, [someOn, allOn]);
  if (aliases.length === 0) {
    return <span className="w-14 text-center text-[11px] text-slate-500">—</span>;
  }
  const hasCanary = aliases.some((r) => r.canary);
  return (
    <span className="flex w-14 justify-center" onClick={(e) => e.stopPropagation()}>
      <input
        ref={ref}
        type="checkbox"
        checked={allOn}
        disabled={disabled}
        onChange={() => onSetRunning(aliases.map((r) => r.alias), !allOn)}
        title={
          allOn
            ? `${label} enabled for ${service} — uncheck to deny${hasCanary ? ' (disarms a decoy — asks first)' : ''}`
            : `${label} disabled for ${service} — check to allow`
        }
        className="h-4 w-4 cursor-pointer accent-ink disabled:cursor-not-allowed"
      />
    </span>
  );
}

/* --- one service group row (Cloudflare-token style) ------------------------- */

function ServiceGroupRow({
  group,
  expanded,
  selected,
  disabledAll,
  compartmentLabel,
  onToggleExpand,
  onSelect,
  onSetRunning,
}: {
  group: ServiceGroup;
  expanded: boolean;
  selected: string | null;
  disabledAll: boolean;
  compartmentLabel: (uuid: string | null | undefined) => string;
  onToggleExpand: () => void;
  onSelect: (alias: string) => void;
  onSetRunning: (aliases: string[], run: boolean) => void;
}): JSX.Element {
  const anyCanary = group.rows.some((r) => r.canary);
  const anyOperator = group.rows.some((r) => r.operator);
  const stopped = group.rows.filter((r) => !r.running).length;
  return (
    <div className="border-b border-hairline/50 last:border-0">
      <div
        onClick={onToggleExpand}
        className="group flex cursor-pointer items-center gap-3 px-4 py-2.5 transition-colors hover:bg-canvas"
      >
        <ChevronRight
          size={13}
          className={`shrink-0 text-slate-500 transition-transform ${expanded ? 'rotate-90' : ''}`}
        />
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="truncate text-[12.5px] font-medium text-ink">{group.service}</span>
            {anyCanary ? (
              <Badge tone="muted">
                <Bug size={10} /> decoy
              </Badge>
            ) : null}
            {anyOperator ? <Badge tone="muted">operator</Badge> : null}
            {stopped > 0 ? <Badge tone="denied">{stopped} disabled</Badge> : null}
          </div>
        </div>
        <AccessCheckbox
          aliases={group.reads}
          disabled={disabledAll}
          label="Read"
          service={group.service}
          onSetRunning={onSetRunning}
        />
        <AccessCheckbox
          aliases={group.writes}
          disabled={disabledAll}
          label="Write"
          service={group.service}
          onSetRunning={onSetRunning}
        />
      </div>

      {expanded ? (
        <div className="border-t border-hairline/40 bg-canvas/60">
          {group.rows.map((r) => (
            <div
              key={r.alias}
              onClick={() => onSelect(r.alias)}
              className={`flex cursor-pointer items-center gap-2.5 py-2 pl-[42px] pr-4 transition-colors ${
                selected === r.alias ? 'bg-canvas' : 'hover:bg-canvas'
              } ${r.running ? '' : 'opacity-70'}`}
            >
              <StatusDot running={r.running} size={6} />
              <span className="truncate font-mono text-[11.5px] text-ink">{r.alias}</span>
              <Badge tone="muted">{r.access}</Badge>
              {r.risk === 'pin_required' ? <Badge tone="staged">PIN</Badge> : null}
              {r.canary ? (
                <Badge tone="muted">
                  <Bug size={10} /> decoy
                </Badge>
              ) : null}
              <span className="ml-auto hidden truncate text-[10.5px] text-slate-500 sm:block">
                {compartmentLabel(r.compartment)}
              </span>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  onSelect(r.alias);
                }}
                title="Inspect this alias"
                className="shrink-0 text-slate-500 transition-colors hover:text-ink"
              >
                <Info size={13} />
              </button>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

/* --- inspector (right pane) ------------------------------------------------ */

function Inspector({
  row,
  compartmentLabel,
  busy,
  onToggle,
  onRemove,
}: {
  row: SkillRow;
  compartmentLabel: (uuid: string | null | undefined) => string;
  busy: boolean;
  onToggle: () => void;
  onRemove: () => void;
}): JSX.Element {
  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2.5 border-b border-hairline px-4 py-3">
        <StatusDot running={row.running} size={10} />
        <span className="min-w-0 flex-1 truncate font-mono text-[13px] text-ink">{row.alias}</span>
        {row.canary ? (
          <Badge tone="muted">
            <Bug size={10} /> decoy
          </Badge>
        ) : null}
        <Badge tone={row.running ? 'verified' : 'denied'}>{row.running ? 'enabled' : 'disabled'}</Badge>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto px-4 py-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <Detail label="Alias · agent-visible" mono span>
            {row.alias}
          </Detail>
          <Detail label="Service">{row.service}</Detail>
          <Detail label="Access" tone={row.access === 'write' ? 'staged' : 'verified'}>
            {row.access}
          </Detail>
          <Detail label="Transport">{row.transport}</Detail>
          <Detail label="Risk tier" tone={row.risk === 'pin_required' ? 'staged' : 'verified'}>
            {row.risk}
          </Detail>
          <Detail label="Classification">{row.classification}</Detail>
          <Detail label="Origin" tone={row.operator ? 'ink' : 'muted'}>
            {row.operator ? 'operator-registered' : 'config (immutable)'}
          </Detail>
          {row.canary ? (
            <Detail label="Tripwire" span>
              Decoy — calling it denies CANARY_TRIPPED and quarantines the caller.
            </Detail>
          ) : null}
          {row.compartment ? (
            <Detail label="Compartment" mono span>
              {compartmentLabel(row.compartment)} · {truncateId(row.compartment, 10, 6)}
            </Detail>
          ) : null}
          {row.operator ? (
            <Detail label="Registered" span>
              {row.registeredAt ? (
                <span title={row.registeredAt}>{formatDateTime(row.registeredAt)} · {formatRelative(row.registeredAt)}</span>
              ) : (
                '—'
              )}
            </Detail>
          ) : null}
        </dl>

        <div className="rounded-lg border border-hairline bg-canvas px-3 py-2.5 text-[11px] leading-relaxed text-slate-500">
          Disabling a skill denies every call (<span className="font-mono">SKILL_DISABLED</span>)
          until enabled again — the real target stays gateway-internal, and the access
          level is a display label, never the enforcement.
        </div>
      </div>

      <div className="space-y-2 border-t border-hairline px-4 py-3">
        <button
          type="button"
          onClick={onToggle}
          disabled={busy}
          className={`flex w-full items-center justify-center gap-2 rounded-lg border px-3 py-2 text-[12.5px] font-medium transition-colors disabled:opacity-50 ${
            row.running
              ? 'border-hairline bg-surface text-ink hover:border-denied/40 hover:text-denied'
              : 'border-verified/40 bg-verified/5 text-verified hover:bg-verified/10'
          }`}
        >
          {busy ? <Loader2 size={14} className="animate-spin" /> : row.running ? <Square size={14} /> : <Play size={14} />}
          {row.running ? (row.canary ? 'Disable decoy…' : 'Disable skill') : row.canary ? 'Enable decoy' : 'Enable skill'}
        </button>
        {row.operator ? (
          <button
            type="button"
            onClick={onRemove}
            disabled={busy}
            className="flex w-full items-center justify-center gap-2 rounded-lg border border-hairline bg-surface px-3 py-2 text-[12.5px] font-medium text-slate-500 transition-colors hover:border-denied/40 hover:text-denied disabled:opacity-50"
          >
            <Trash2 size={14} /> Deregister skill
          </button>
        ) : null}
      </div>
    </div>
  );
}

/* --- stop-canary confirmation ----------------------------------------------
   Decoys look like ordinary rows to agents ON PURPOSE — but the operator must
   never disarm a tripwire by accident. Disabling one swaps CANARY_TRIPPED (+
   quarantine) for a plain SKILL_DISABLED deny: the tenant loses the
   early-warning signal until the decoy is enabled again.
--------------------------------------------------------------------------- */

function StopCanaryDialog({
  pending,
  onCancel,
  onConfirm,
}: {
  pending: PendingStop;
  onCancel: () => void;
  onConfirm: () => void;
}): JSX.Element {
  const others = pending.aliases.length - pending.canaryAliases.length;
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/25 p-4"
      onClick={onCancel}
    >
      <motion.div
        initial={{ scale: 0.97, y: 8 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.97, y: 8 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-xl border border-hairline bg-surface shadow-panel"
      >
        <div className="flex items-center gap-2 border-b border-hairline px-4 py-3">
          <Bug size={15} className="text-staged" />
          <h3 className="text-[13.5px] font-semibold text-ink">
            {pending.canaryAliases.length === 1 ? 'Disable a canary decoy?' : `Disable ${pending.canaryAliases.length} canary decoys?`}
          </h3>
          <button type="button" onClick={onCancel} className="ml-auto text-slate-500 hover:text-ink">
            <X size={16} />
          </button>
        </div>

        <div className="space-y-3 px-4 py-4">
          <p className="text-[11.5px] leading-relaxed text-slate-500">
            {pending.canaryAliases.length === 1 ? 'This row is a tripwire, not a real skill.' : 'These rows are tripwires, not real skills.'}{' '}
            While disabled, a hijacked agent that selects one is denied a plain{' '}
            <span className="font-mono text-[10.5px]">SKILL_DISABLED</span> instead of tripping{' '}
            <span className="font-mono text-[10.5px]">CANARY_TRIPPED</span> — the tenant loses that
            early-warning quarantine until you enable it again.
          </p>
          <div className="overflow-hidden rounded-lg border border-hairline">
            {pending.canaryAliases.map((a) => (
              <div key={a} className="flex items-center gap-2 border-b border-hairline/60 bg-canvas px-2.5 py-1.5 last:border-0">
                <Bug size={11} className="shrink-0 text-staged" />
                <span className="truncate font-mono text-[11px] text-ink">{a}</span>
              </div>
            ))}
          </div>
          {others > 0 ? (
            <p className="text-[10.5px] leading-relaxed text-slate-500">
              {others} non-decoy {others === 1 ? 'skill in the selection is disabled' : 'skills in the selection are disabled'} as usual.
            </p>
          ) : null}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-hairline px-4 py-3">
          <button type="button" onClick={onCancel} className="btn-ghost">
            Cancel
          </button>
          <button
            type="button"
            onClick={onConfirm}
            className="btn border border-denied/30 bg-denied/5 text-denied hover:bg-denied/10"
          >
            <Square size={13} /> Disable anyway
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

/* --- register modal ---------------------------------------------------------
   Permission-model registration: name the SERVICE, choose the access level, and
   the console suggests the alias as skill_{service-slug} — editable, never a
   _read/_write suffix. The access level is sent as the structured `access` field.
--------------------------------------------------------------------------- */

function RegisterDialog({
  apiBase,
  tenant,
  existing,
  onClose,
  onRegistered,
}: {
  apiBase: string;
  tenant: string;
  existing: Set<string>;
  onClose: () => void;
  onRegistered: (rows: SkillRow[]) => void;
}): JSX.Element {
  // Service-first: the operator names the service ("AWS DynamoDB", "General ledger")
  // and picks Read or Write; the console derives the alias and the internal target.
  // Raw alias/target stay editable under "Advanced". "Several" registers a list —
  // one service per line, all with the chosen access level.
  const [mode, setMode] = useState<'one' | 'many'>('one');
  const [service, setService] = useState('');
  const [access, setAccess] = useState<SkillAccess>('read');
  const [bulk, setBulk] = useState('');
  const [alias, setAlias] = useState('');
  const [target, setTarget] = useState('');
  const [aliasTouched, setAliasTouched] = useState(false);
  const [targetTouched, setTargetTouched] = useState(false);
  const [sensitive, setSensitive] = useState(false);
  const [sensitiveTouched, setSensitiveTouched] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const trimmedService = service.trim();
  const derivedAlias = trimmedService ? `skill_${slugify(trimmedService, '_')}` : '';
  const derivedTarget = trimmedService ? `rest.${slugify(trimmedService, '.')}` : '';
  const effectiveAlias = aliasTouched ? alias : derivedAlias;
  const effectiveTarget = targetTouched ? target : derivedTarget;
  const risk: RiskTier = sensitive ? 'pin_required' : 'auto';
  const classification: Classification = sensitive ? 'restricted' : 'unclassified';

  const pickAccess = (m: SkillAccess): void => {
    setAccess(m);
    setError(null);
    // A write defaults to the PIN step-up until the operator says otherwise.
    if (!sensitiveTouched) setSensitive(m === 'write');
  };

  const trimmedAlias = effectiveAlias.trim();
  const trimmedTarget = effectiveTarget.trim();
  const collides = existing.has(trimmedAlias);
  const valid =
    trimmedService.length > 0 &&
    trimmedService.length <= 64 &&
    trimmedAlias.length > 1 &&
    trimmedTarget.length > 0 &&
    !collides;

  // Batch: each non-empty line is one service; derive + flag collisions and dupes.
  const bulkItems = useMemo(() => {
    const seen = new Set<string>();
    return bulk
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean)
      .map((line) => {
        const slug = slugify(line, '_');
        const aliasName = `skill_${slug}`;
        const dup = seen.has(aliasName);
        seen.add(aliasName);
        return {
          service: line.slice(0, 64),
          alias: aliasName,
          target: `rest.${slugify(line, '.')}`,
          bad: !slug || existing.has(aliasName) || dup,
        };
      });
  }, [bulk, existing]);
  const bulkValid = bulkItems.filter((it) => !it.bad);

  const rowOf = (aliasName: string, serviceLabel: string): SkillRow => ({
    alias: aliasName,
    transport: 'cloud_rest',
    risk,
    classification,
    compartment: null,
    service: serviceLabel || displayService(aliasName),
    access,
    operator: true,
    running: true,
    canary: false,
    registeredAt: new Date().toISOString(),
  });

  const submit = async (): Promise<void> => {
    if (!valid || busy) return;
    setBusy(true);
    setError(null);
    const ok = await registerSkill(apiBase, tenant, {
      alias: trimmedAlias,
      target: trimmedTarget,
      risk_tier: risk,
      classification: classification === 'unclassified' ? 'unclassified' : 'restricted',
      service: trimmedService,
      access,
    });
    if (ok) {
      onRegistered([rowOf(trimmedAlias, trimmedService)]);
      return;
    }
    setError('Registration denied. The alias may already resolve (config skills can never be shadowed), or the gateway rejected the request.');
    setBusy(false);
  };

  const submitMany = async (): Promise<void> => {
    if (bulkValid.length === 0 || busy) return;
    setBusy(true);
    setError(null);
    const succeeded: SkillRow[] = [];
    for (const it of bulkValid) {
      const ok = await registerSkill(apiBase, tenant, {
        alias: it.alias,
        target: it.target,
        risk_tier: risk,
        classification: classification === 'unclassified' ? 'unclassified' : 'restricted',
        service: it.service,
        access,
      });
      if (ok) succeeded.push(rowOf(it.alias, it.service));
    }
    if (succeeded.length > 0) {
      onRegistered(succeeded);
      return;
    }
    setError('No skills were registered — the names may already resolve, or the gateway rejected the request.');
    setBusy(false);
  };

  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center bg-ink/25 p-4"
      onClick={onClose}
    >
      <motion.div
        initial={{ scale: 0.97, y: 8 }}
        animate={{ scale: 1, y: 0 }}
        exit={{ scale: 0.97, y: 8 }}
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-md rounded-xl border border-hairline bg-surface shadow-panel"
      >
        <div className="flex items-center gap-2 border-b border-hairline px-4 py-3">
          <Plus size={15} className="text-slate-500" />
          <h3 className="text-[13.5px] font-semibold text-ink">Register a skill</h3>
          <button type="button" onClick={onClose} className="ml-auto text-slate-500 hover:text-ink">
            <X size={16} />
          </button>
        </div>

        <div className="space-y-3.5 px-4 py-4">
          {/* One vs Several — register a single service or a whole list at once. */}
          <div className="inline-flex items-center gap-0.5 rounded-lg border border-hairline bg-elevated p-0.5">
            {(['one', 'many'] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => { setMode(m); setError(null); }}
                className={`rounded-[7px] px-3 py-1 text-[12px] font-medium transition-all ${
                  mode === m ? 'bg-surface text-ink shadow-card' : 'text-slate-500 hover:text-ink'
                }`}
              >
                {m === 'one' ? 'One' : 'Several'}
              </button>
            ))}
          </div>

          {mode === 'one' ? (
            <>
              <p className="text-[11.5px] leading-relaxed text-slate-500">
                Name the service and choose what agents may do with it — the console
                names the skill and wires it up for{' '}
                <span className="font-mono text-ink">{tenant}</span>. Every registration is WORM-logged.
              </p>

              <Field label="Service">
                <Input
                  value={service}
                  onChange={(e) => { setService(e.target.value); setError(null); }}
                  placeholder="e.g. AWS DynamoDB"
                  maxLength={64}
                  autoFocus
                />
              </Field>
            </>
          ) : (
            <>
              <p className="text-[11.5px] leading-relaxed text-slate-500">
                List your services — <span className="text-ink">one per line</span>. The console names and wires up each one
                for <span className="font-mono text-ink">{tenant}</span>. Every registration is WORM-logged.
              </p>

              <Field label="Services">
                <textarea
                  value={bulk}
                  onChange={(e) => { setBulk(e.target.value); setError(null); }}
                  rows={5}
                  autoFocus
                  spellCheck={false}
                  placeholder={'Payroll ledger\nCustomer records\nSales pipeline'}
                  className="w-full resize-y rounded-lg border border-hairline bg-canvas px-3 py-2 text-[12.5px] leading-relaxed text-ink placeholder:text-slate-500 focus:border-ink/30 focus:outline-none focus:shadow-focus-ring"
                />
              </Field>
            </>
          )}

          {/* Access — the structured read/write level (display metadata; the PIN
              checkbox below is the enforcement choice). */}
          <Field label="Access">
            <div className="inline-flex items-center gap-0.5 rounded-lg border border-hairline bg-elevated p-0.5">
              {(['read', 'write'] as const).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => pickAccess(m)}
                  className={`rounded-[7px] px-4 py-1 text-[12px] font-medium capitalize transition-all ${
                    access === m ? 'bg-surface text-ink shadow-card' : 'text-slate-500 hover:text-ink'
                  }`}
                >
                  {m}
                </button>
              ))}
            </div>
          </Field>

          {mode === 'one' ? (
            <Field label="Alias · what the agent calls">
              <Input
                mono
                value={effectiveAlias}
                onChange={(e) => { setAliasTouched(true); setAlias(e.target.value); setError(null); }}
                placeholder="skill_aws_dynamodb"
                spellCheck={false}
              />
              {collides ? (
                <p className="mt-1 text-[10.5px] text-denied">That alias already exists — pick another name.</p>
              ) : null}
            </Field>
          ) : bulkItems.length > 0 ? (
            <div className="rounded-lg border border-hairline bg-canvas px-3 py-2.5">
              <div className="mb-1.5 flex items-center justify-between text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
                <span>The agent will call</span>
                <span>{bulkValid.length}/{bulkItems.length} ready</span>
              </div>
              <div className="max-h-40 space-y-1 overflow-y-auto">
                {bulkItems.map((it, i) => (
                  <div key={i} className="flex items-center gap-2 text-[11.5px]">
                    {it.bad ? (
                      <ShieldAlert size={11} className="shrink-0 text-slate-500" />
                    ) : (
                      <span className="h-1.5 w-1.5 shrink-0 rounded-full bg-verified" />
                    )}
                    <span className={`break-all font-mono ${it.bad ? 'text-slate-500 line-through' : 'text-ink'}`}>{it.alias}</span>
                  </div>
                ))}
              </div>
              {bulkItems.some((it) => it.bad) ? (
                <p className="mt-1.5 text-[10px] leading-relaxed text-slate-500">Greyed names already exist or repeat — they&apos;ll be skipped.</p>
              ) : null}
            </div>
          ) : null}

          <label className="flex items-start gap-2.5 rounded-lg border border-hairline bg-canvas px-3 py-2.5">
            <input
              type="checkbox"
              checked={sensitive}
              onChange={(e) => { setSensitive(e.target.checked); setSensitiveTouched(true); }}
              className="mt-0.5 accent-ink"
            />
            <span className="text-[11.5px] leading-relaxed text-slate-500">
              <span className="font-medium text-ink">Sensitive action</span> — require a human one-time PIN before it runs
              (for writes, payments, anything you&apos;d want a second check on){mode === 'many' ? ', applied to every service in the list' : ''}.
            </span>
          </label>

          {/* Advanced — the raw target for power users; single-skill only. */}
          {mode === 'one' ? (
            <>
              <button
                type="button"
                onClick={() => setAdvanced((v) => !v)}
                className="flex items-center gap-1.5 text-[10.5px] font-medium uppercase tracking-[0.08em] text-slate-500 transition-colors hover:text-ink"
              >
                <ChevronRight size={11} className={`transition-transform ${advanced ? 'rotate-90' : ''}`} /> Advanced
              </button>
              {advanced ? (
                <div className="space-y-3 rounded-lg border border-hairline bg-canvas p-3">
                  <Field label="Target · the internal system it reaches">
                    <Input mono value={effectiveTarget} onChange={(e) => { setTargetTouched(true); setTarget(e.target.value); setError(null); }} placeholder="rest.aws.dynamodb" spellCheck={false} />
                  </Field>
                  <p className="text-[10.5px] leading-relaxed text-slate-500">
                    Transport is <span className="font-mono">cloud_rest</span>; additive only — you can introduce a new name,
                    never repoint an existing skill. The real target never leaves the gateway.
                  </p>
                </div>
              ) : null}
            </>
          ) : null}

          {error ? (
            <p className="rounded-lg border border-denied/30 bg-denied/5 px-2.5 py-1.5 text-[11px] leading-relaxed text-denied">
              {error}
            </p>
          ) : null}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-hairline px-4 py-3">
          <button type="button" onClick={onClose} className="btn-ghost">
            Cancel
          </button>
          {mode === 'one' ? (
            <button type="button" onClick={() => void submit()} disabled={!valid || busy} className="btn-primary">
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              {busy ? 'Registering…' : 'Register skill'}
            </button>
          ) : (
            <button type="button" onClick={() => void submitMany()} disabled={bulkValid.length === 0 || busy} className="btn-primary">
              {busy ? <Loader2 size={14} className="animate-spin" /> : <Plus size={14} />}
              {busy ? 'Registering…' : `Register ${bulkValid.length || ''} ${bulkValid.length === 1 ? 'skill' : 'skills'}`.replace('  ', ' ')}
            </button>
          )}
        </div>
      </motion.div>
    </motion.div>
  );
}
