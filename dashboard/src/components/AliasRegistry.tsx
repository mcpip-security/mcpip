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
} from '../lib/types';
import type { GatewayLive } from '../lib/useGatewayLive';

/** Turn a plain-language description into a safe alias/target slug. */
function slugify(text: string, sep: '_' | '.'): string {
  const s = text.toLowerCase().replace(/[^a-z0-9]+/g, sep);
  return s.replace(new RegExp(`^\\${sep}+|\\${sep}+$`, 'g'), '');
}

/**
 * Skills & Tools — the operator's Docker-Desktop-style control surface for the
 * obfuscator catalog. Every row is a skill the gateway can authorize; the operator
 * can:
 *   • ▶ Play / ■ Stop it (the hot-path kill-switch — a DENY-only control that never
 *     edits the alias→target mapping; a stopped skill is denied SKILL_DISABLED),
 *   • ⓘ inspect it (metadata only — the real target never leaves the gateway),
 *   • + Register a NEW skill (additive-only alias→target, cloud_rest, WORM-logged),
 *   • 🗑 Deregister one the operator added (config skills are immutable),
 *   • "View as" a team compartment — the console mints a per-(tenant, compartment)
 *     identity and re-reads GET /v1/catalog under it, so the rows shown are EXACTLY
 *     what that team's agents can enumerate (the gateway itself applies the filter;
 *     nothing is filtered client-side).
 *
 * Canary decoys are badged from the operator-only GET /v1/admin/canaries roster
 * (the agent-facing catalog keeps hiding the flag), and stopping one asks for
 * confirmation — a stopped decoy is a disarmed tripwire.
 *
 * Agents only ever see the alias. Offline is honestly empty — no fabricated catalog.
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
   cadence, so play/stop/register reconcile in a team view exactly like the
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
  /** operator-registered (deregisterable) vs config (immutable). */
  operator: boolean;
  /** running = agents may invoke it; stopped = disabled (denied SKILL_DISABLED). */
  running: boolean;
  /** Canary decoy (from the operator-only roster) — stopping it disarms a tripwire. */
  canary: boolean;
  /** When the operator registered this skill (ISO-8601); null for config skills. */
  registeredAt?: string | null;
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
  const [busy, setBusy] = useState<string | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [showRegister, setShowRegister] = useState(false);
  // Multi-select for bulk play / stop / deregister across many skills at once.
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
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
      .filter((r) => (q ? r.alias.toLowerCase().includes(q) : true))
      .sort((a, b) => a.alias.localeCompare(b.alias));
  }, [live, viewAs, catalog, scopedView.items, disabled, registered, registeredAt, canaries, pendingAdds, pendingRemoves, query]);

  const selectedRow = useMemo(() => rows.find((r) => r.alias === selected) ?? null, [rows, selected]);

  /** The actual kill-switch calls — shared by single toggles, bulk, and the confirm. */
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
          ? `${run ? 'Play' : 'Stop'} failed for ${failed.join(', ')} — the gateway refused the change or is unreachable.`
          : null,
      );
      setBusy(null);
      setBulkBusy(false);
    },
    [apiBase, skillTenant],
  );

  /** Route a play/stop through the canary confirmation when it would disarm decoys. */
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
    setShowRegister(false);
    setSelected(newRows[newRows.length - 1]!.alias);
  }, []);

  const toggleChecked = useCallback((alias: string): void => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (next.has(alias)) next.delete(alias);
      else next.add(alias);
      return next;
    });
  }, []);

  // Bulk play/stop across every checked, visible skill (skips ones already in that state).
  const bulkSetRunning = useCallback(
    (run: boolean): void => {
      const targets = rows.filter((r) => checked.has(r.alias) && r.running !== run).map((r) => r.alias);
      if (targets.length === 0) return;
      requestSetRunning(targets, run);
    },
    [rows, checked, requestSetRunning],
  );

  // Bulk deregister — operator-added skills only (config skills are immutable).
  const bulkDeregister = useCallback(async (): Promise<void> => {
    if (!skillTenant) return;
    const targets = rows.filter((r) => checked.has(r.alias) && r.operator).map((r) => r.alias);
    if (targets.length === 0) return;
    setBulkBusy(true);
    const removed: string[] = [];
    const failed: string[] = [];
    for (const alias of targets) {
      const res = await deregisterSkill(apiBase, skillTenant, alias);
      if (res.ok) removed.push(alias);
      else failed.push(alias);
    }
    setPendingRemoves((prev) => {
      const next = new Set(prev);
      removed.forEach((a) => next.add(a));
      return next;
    });
    setPendingAdds((prev) => prev.filter((p) => !removed.includes(p.alias)));
    setRegistered((prev) => {
      const next = new Set(prev);
      removed.forEach((a) => next.delete(a));
      return next;
    });
    setChecked((prev) => {
      const next = new Set(prev);
      removed.forEach((a) => next.delete(a));
      return next;
    });
    setActionError(
      failed.length > 0
        ? `Deregister failed for ${failed.join(', ')} — the gateway refused the change or is unreachable.`
        : null,
    );
    if (selected && removed.includes(selected)) setSelected(null);
    setBulkBusy(false);
  }, [rows, checked, apiBase, skillTenant, selected]);

  const running = rows.filter((r) => r.running).length;
  const operatorCount = rows.filter((r) => r.operator).length;

  // Selection is over the currently VISIBLE rows (filter-aware).
  const checkedVisible = rows.filter((r) => checked.has(r.alias));
  const checkedCount = checkedVisible.length;
  const checkedOperator = checkedVisible.filter((r) => r.operator).length;
  const allChecked = rows.length > 0 && rows.every((r) => checked.has(r.alias));
  const toggleAll = (): void =>
    setChecked((prev) => {
      const next = new Set(prev);
      if (rows.every((r) => next.has(r.alias))) rows.forEach((r) => next.delete(r.alias));
      else rows.forEach((r) => next.add(r.alias));
      return next;
    });
  const clearChecked = (): void => setChecked(new Set());

  const teamViewPending = viewAs !== null && scopedView.loading;
  const teamViewFailed = viewAs !== null && scopedView.failed;

  const inspector = selectedRow ? (
    <Inspector
      row={selectedRow}
      tenant={skillTenant ?? '—'}
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
        Inspect its transport, risk tier, and status — and play, stop, or deregister it.
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
                  placeholder="Filter skills"
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
            {checkedCount > 0 ? (
              <>
                <div className="flex items-center gap-2.5">
                  <button type="button" onClick={clearChecked} title="Clear selection" className="text-slate-500 transition-colors hover:text-ink">
                    <X size={15} />
                  </button>
                  <span className="text-[12.5px] font-semibold text-ink">{checkedCount} selected</span>
                </div>
                <div className="flex items-center gap-1.5">
                  {bulkBusy ? <Loader2 size={13} className="animate-spin text-slate-500" /> : null}
                  <button type="button" disabled={bulkBusy} onClick={() => bulkSetRunning(true)} className="btn-ghost h-[30px] hover:border-verified/40 hover:text-verified">
                    <Play size={12} /> Play all
                  </button>
                  <button type="button" disabled={bulkBusy} onClick={() => bulkSetRunning(false)} className="btn-ghost h-[30px] hover:border-denied/40 hover:text-denied">
                    <Square size={12} /> Stop all
                  </button>
                  {checkedOperator > 0 ? (
                    <button type="button" disabled={bulkBusy} onClick={() => void bulkDeregister()} className="btn-ghost h-[30px] hover:border-denied/40 hover:text-denied">
                      <Trash2 size={12} /> Deregister {checkedOperator}
                    </button>
                  ) : null}
                </div>
              </>
            ) : (
              <>
                <div className="flex items-center gap-2.5">
                  {live && rows.length > 0 ? (
                    <input
                      type="checkbox"
                      checked={allChecked}
                      onChange={toggleAll}
                      title="Select all"
                      className="h-3.5 w-3.5 accent-ink"
                    />
                  ) : null}
                  <span className="text-[13px] font-semibold text-ink">Skill catalog</span>
                </div>
                <span className="tabular text-[11px] text-slate-500">
                  {teamViewPending || teamViewFailed
                    ? '—'
                    : `${rows.length} skills · ${running} running${operatorCount > 0 ? ` · ${operatorCount} operator` : ''}${activeSource ? ` · as ${activeSource.label}` : ''}`}
                </span>
              </>
            )}
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
              detail="The skill manager is live-only: ▶ play / ■ stop, register and inspect act on the real catalog the gateway serves — nothing is fabricated offline."
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
              detail="The per-team identity could not be minted or its catalog read failed. Per-team views need the sandbox token minter (/v1/dev/token); on a production gateway, enumerate with a real team-scoped credential instead."
              action={
                <button type="button" onClick={() => setViewAs(null)} className="btn-ghost">
                  Back to company-wide
                </button>
              }
            />
          ) : rows.length === 0 ? (
            <EmptyState
              icon={Package}
              title={
                query
                  ? 'No skills match your filter'
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
              {rows.map((r) => (
                <SkillRowItem
                  key={r.alias}
                  row={r}
                  selected={selected === r.alias}
                  checked={checked.has(r.alias)}
                  busy={busy === r.alias}
                  onCheck={() => toggleChecked(r.alias)}
                  onSelect={() => setSelected(r.alias)}
                  onToggle={() => requestSetRunning([r.alias], !r.running)}
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

/* --- one skill row (Docker-container style) -------------------------------- */

function SkillRowItem({
  row,
  selected,
  checked,
  busy,
  onCheck,
  onSelect,
  onToggle,
}: {
  row: SkillRow;
  selected: boolean;
  checked: boolean;
  busy: boolean;
  onCheck: () => void;
  onSelect: () => void;
  onToggle: () => void;
}): JSX.Element {
  return (
    <div
      onClick={onSelect}
      className={`group flex cursor-pointer items-center gap-3 border-b border-hairline/50 px-4 py-2.5 transition-colors last:border-0 ${
        selected ? 'bg-canvas' : 'hover:bg-canvas'
      } ${row.running ? '' : 'opacity-70'}`}
    >
      <input
        type="checkbox"
        checked={checked}
        onClick={(e) => e.stopPropagation()}
        onChange={onCheck}
        title="Select for bulk actions"
        className={`h-3.5 w-3.5 shrink-0 accent-ink transition-opacity ${checked ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'}`}
      />
      <StatusDot running={row.running} />
      <div className="min-w-0 flex-1">
        {/* Essentials only — transport / risk / classification / compartment / added-date
            live in the Inspector, revealed per-selection rather than on every row. */}
        <div className="flex items-center gap-2">
          <span className="truncate font-mono text-[12.5px] text-ink">{row.alias}</span>
          <Badge tone={row.running ? 'verified' : 'denied'}>{row.running ? 'running' : 'stopped'}</Badge>
          {row.operator ? <Badge tone="muted">operator</Badge> : null}
          {row.canary ? (
            <Badge tone="muted">
              <Bug size={10} /> decoy
            </Badge>
          ) : null}
        </div>
      </div>

      <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
        <button
          type="button"
          onClick={onToggle}
          disabled={busy}
          title={
            row.running
              ? row.canary
                ? 'Stop — disarms this canary tripwire (asks first)'
                : 'Stop — deny this skill for the tenant'
              : 'Play — allow this skill'
          }
          className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-lg border transition-colors disabled:opacity-50 ${
            row.running
              ? 'border-hairline bg-surface text-slate-500 hover:border-denied/40 hover:text-denied'
              : 'border-verified/30 bg-verified/5 text-verified hover:border-verified/50'
          }`}
        >
          {busy ? <Loader2 size={13} className="animate-spin" /> : row.running ? <Square size={13} /> : <Play size={13} />}
        </button>
      </div>
    </div>
  );
}

/* --- inspector (right pane) ------------------------------------------------ */

function Inspector({
  row,
  tenant,
  compartmentLabel,
  busy,
  onToggle,
  onRemove,
}: {
  row: SkillRow;
  tenant: string;
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
        <Badge tone={row.running ? 'verified' : 'denied'}>{row.running ? 'running' : 'stopped'}</Badge>
      </div>

      <div className="flex-1 space-y-4 overflow-y-auto px-4 py-4">
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <Detail label="Alias · agent-visible" mono span>
            {row.alias}
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
              Canary decoy — selecting it denies CANARY_TRIPPED and quarantines the caller. It is never
              backed by a real system.
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

        {/* Operator-only metadata — revealed per-selection here, not on every row. */}
        {row.compartment ? (
          <details className="group rounded-lg border border-hairline bg-canvas">
            <summary className="flex cursor-pointer items-center gap-1.5 px-3 py-2 text-[10.5px] font-semibold uppercase tracking-[0.1em] text-slate-500 transition-colors hover:text-ink">
              <ChevronRight size={11} className="shrink-0 transition-transform group-open:rotate-90" />
              Operator-only metadata
            </summary>
            <div className="border-t border-hairline px-3 py-2.5">
              <Detail label="Compartment" mono span>
                {compartmentLabel(row.compartment)} · {truncateId(row.compartment, 10, 6)}
              </Detail>
            </div>
          </details>
        ) : null}

        <div className="rounded-lg border border-hairline bg-canvas px-3 py-2.5 text-[11px] leading-relaxed text-slate-500">
          The real target is gateway-internal (topology hygiene) — only the coarse transport class is
          operator-visible. Stopping a skill is a <span className="text-ink">DENY-only</span> control: every
          invocation is denied <span className="font-mono">SKILL_DISABLED</span> for the whole{' '}
          <span className="font-mono">{tenant}</span> tenant until played again. It never edits the alias→target map.
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
          {row.running ? (row.canary ? 'Stop decoy…' : 'Stop skill') : row.canary ? 'Play decoy' : 'Play skill'}
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
   never disarm a tripwire by accident. Stopping one swaps CANARY_TRIPPED (+
   quarantine) for a plain SKILL_DISABLED deny: the tenant loses the
   early-warning signal until the decoy is played again.
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
            {pending.canaryAliases.length === 1 ? 'Stop a canary decoy?' : `Stop ${pending.canaryAliases.length} canary decoys?`}
          </h3>
          <button type="button" onClick={onCancel} className="ml-auto text-slate-500 hover:text-ink">
            <X size={16} />
          </button>
        </div>

        <div className="space-y-3 px-4 py-4">
          <p className="text-[11.5px] leading-relaxed text-slate-500">
            {pending.canaryAliases.length === 1 ? 'This row is a tripwire, not a real skill.' : 'These rows are tripwires, not real skills.'}{' '}
            While stopped, a hijacked agent that selects one is denied a plain{' '}
            <span className="font-mono text-[10.5px]">SKILL_DISABLED</span> instead of tripping{' '}
            <span className="font-mono text-[10.5px]">CANARY_TRIPPED</span> — the tenant loses that
            early-warning quarantine until you play it again.
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
              {others} non-decoy {others === 1 ? 'skill in the selection stops' : 'skills in the selection stop'} as usual.
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
            <Square size={13} /> Stop anyway
          </button>
        </div>
      </motion.div>
    </motion.div>
  );
}

/* --- register modal -------------------------------------------------------- */

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
  // Description-first: a non-technical operator describes the skill in plain words and
  // the console derives the alias (what the agent calls) and the internal target. The
  // raw fields stay available under "Advanced" for anyone who wants to override them.
  // "Several" mode registers a whole list at once — one tool per line.
  const [mode, setMode] = useState<'one' | 'many'>('one');
  const [description, setDescription] = useState('');
  const [bulk, setBulk] = useState('');
  const [alias, setAlias] = useState('');
  const [target, setTarget] = useState('');
  const [aliasTouched, setAliasTouched] = useState(false);
  const [targetTouched, setTargetTouched] = useState(false);
  const [sensitive, setSensitive] = useState(false);
  const [advanced, setAdvanced] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const derivedAlias = description.trim() ? `skill_${slugify(description, '_')}` : '';
  const derivedTarget = description.trim() ? `rest.${slugify(description, '.')}` : '';
  const effectiveAlias = aliasTouched ? alias : derivedAlias;
  const effectiveTarget = targetTouched ? target : derivedTarget;
  const risk: RiskTier = sensitive ? 'pin_required' : 'auto';
  const classification: Classification = sensitive ? 'restricted' : 'unclassified';

  const trimmedAlias = effectiveAlias.trim();
  const trimmedTarget = effectiveTarget.trim();
  const collides = existing.has(trimmedAlias);
  const valid = trimmedAlias.length > 1 && trimmedTarget.length > 0 && !collides;

  // Batch: each non-empty line becomes one skill; derive + flag collisions and in-list dupes.
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
        return { line, alias: aliasName, target: `rest.${slugify(line, '.')}`, bad: !slug || existing.has(aliasName) || dup };
      });
  }, [bulk, existing]);
  const bulkValid = bulkItems.filter((it) => !it.bad);

  const rowOf = (aliasName: string): SkillRow => ({
    alias: aliasName,
    transport: 'cloud_rest',
    risk,
    classification,
    compartment: null,
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
    });
    if (ok) {
      onRegistered([rowOf(trimmedAlias)]);
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
      });
      if (ok) succeeded.push(rowOf(it.alias));
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
          {/* One vs Several — register a single tool or a whole list at once. */}
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
                Describe what the tool does — the console names it and wires it up for{' '}
                <span className="font-mono text-ink">{tenant}</span>. Every registration is WORM-logged.
              </p>

              <Field label="What should this tool do?">
                <Input
                  value={description}
                  onChange={(e) => { setDescription(e.target.value); setError(null); }}
                  placeholder="e.g. Read the payroll ledger"
                  autoFocus
                />
              </Field>

              {/* Live preview of the derived names — reassuring, not editable here. */}
              {trimmedAlias ? (
                <div className="rounded-lg border border-hairline bg-canvas px-3 py-2.5 text-[11px]">
                  <p className="text-slate-500">The agent will call</p>
                  <p className="mt-0.5 break-all font-mono text-[12px] text-ink">{trimmedAlias}</p>
                  {collides ? (
                    <p className="mt-1 text-[10.5px] text-denied">That name already exists — tweak the description.</p>
                  ) : null}
                </div>
              ) : null}
            </>
          ) : (
            <>
              <p className="text-[11.5px] leading-relaxed text-slate-500">
                List your tools — <span className="text-ink">one per line</span>. The console names and wires up each one
                for <span className="font-mono text-ink">{tenant}</span>. Every registration is WORM-logged.
              </p>

              <Field label="What should these tools do?">
                <textarea
                  value={bulk}
                  onChange={(e) => { setBulk(e.target.value); setError(null); }}
                  rows={5}
                  autoFocus
                  spellCheck={false}
                  placeholder={'Read the payroll ledger\nLook up a customer record\nRead the sales pipeline'}
                  className="w-full resize-y rounded-lg border border-hairline bg-canvas px-3 py-2 text-[12.5px] leading-relaxed text-ink placeholder:text-slate-500 focus:border-ink/30 focus:outline-none focus:shadow-focus-ring"
                />
              </Field>

              {bulkItems.length > 0 ? (
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
            </>
          )}

          <label className="flex items-start gap-2.5 rounded-lg border border-hairline bg-canvas px-3 py-2.5">
            <input type="checkbox" checked={sensitive} onChange={(e) => setSensitive(e.target.checked)} className="mt-0.5 accent-ink" />
            <span className="text-[11.5px] leading-relaxed text-slate-500">
              <span className="font-medium text-ink">Sensitive action</span> — require a human one-time PIN before it runs
              (for writes, payments, anything you&apos;d want a second check on){mode === 'many' ? ', applied to every tool in the list' : ''}.
            </span>
          </label>

          {/* Advanced — the raw alias/target for power users; single-skill only. */}
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
                  <Field label="Alias · what the agent calls">
                    <Input mono value={effectiveAlias} onChange={(e) => { setAliasTouched(true); setAlias(e.target.value); setError(null); }} placeholder="skill_payroll_read" spellCheck={false} />
                  </Field>
                  <Field label="Target · the internal system it reaches">
                    <Input mono value={effectiveTarget} onChange={(e) => { setTargetTouched(true); setTarget(e.target.value); setError(null); }} placeholder="rest.payroll.read" spellCheck={false} />
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
