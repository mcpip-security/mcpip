/* ---------------------------------------------------------------------------
   Activity History — the decision feed AT SCALE.

   The live Decision Stream shows only the newest ~50 rows. This view is the
   operator's answer to "show me everything, by date, filtered, and let me
   export it": it drives GET /v1/admin/decisions — the date-ranged,
   multi-filtered, cursor-paged history over the SAME strict whitelist
   projection the live feed serves (no target, no payload, no secret — just the
   tenant's own WORM decision tail, walkable by time).

   Honest by construction: every row is a REAL projected WORM field; offline or
   an unavailable admin read renders the standard empty state, never a mock row;
   "Load more" pages by the server's opaque cursor; Export walks the WHOLE
   window (following the cursor to the end) and streams a CSV/JSON the operator
   can hand to an auditor. It is NOT the authoritative record — that stays the
   signed epoch chain (Audit Ledger → Chain Integrity).
--------------------------------------------------------------------------- */

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  ChevronRight,
  Download,
  FileJson,
  Filter,
  History,
  Inbox,
  Loader2,
  PlugZap,
  RotateCcw,
  Search,
} from 'lucide-react';
import { Badge, EmptyState, Field, Input, Panel, PanelHeader, Select } from '../ui';
import type { DecisionFacet, DecisionQuery, RecentDecision } from '../../lib/api';
import type { GatewayLive } from '../../lib/useGatewayLive';

/** Page size for a single "Load more" fetch (server clamps to MAX_DECISIONS_PAGE=200). */
const PAGE_LIMIT = 100;
/** Export backstops — a whole-window walk is bounded so a hostile range can't run forever. */
const MAX_EXPORT_ROWS = 50000;
const MAX_EXPORT_PAGES = 2000;

interface FilterState {
  from: string; // datetime-local value (local wall clock) or ''
  to: string;
  decision: '' | 'allow' | 'deny';
  alias: string; // comma-separated → OR
  denyReason: string;
  riskTier: string;
  agentId: string;
}

const EMPTY_FILTERS: FilterState = {
  from: '',
  to: '',
  decision: '',
  alias: '',
  denyReason: '',
  riskTier: '',
  agentId: '',
};

/** datetime-local string → epoch ms (or undefined when blank/invalid). */
function toMs(value: string): number | undefined {
  if (!value) return undefined;
  const ms = new Date(value).getTime();
  return Number.isFinite(ms) ? ms : undefined;
}

/** Comma-separated facet input → deduped value list (OR within the facet). */
function facetValues(raw: string): string[] {
  return Array.from(
    new Set(
      raw
        .split(',')
        .map((v) => v.trim())
        .filter(Boolean),
    ),
  );
}

/** Assemble the wire query from the filter UI (only non-empty facets are sent). */
function buildQuery(f: FilterState, cursor?: string): DecisionQuery {
  const filters: Partial<Record<DecisionFacet, string[]>> = {};
  if (f.decision) filters.decision = [f.decision];
  const alias = facetValues(f.alias);
  if (alias.length) filters.alias = alias;
  const deny = facetValues(f.denyReason);
  if (deny.length) filters.deny_reason = deny;
  const risk = facetValues(f.riskTier);
  if (risk.length) filters.risk_tier = risk;
  const agent = facetValues(f.agentId);
  if (agent.length) filters.agent_id = agent;
  const query: DecisionQuery = { limit: PAGE_LIMIT, filters };
  const fromMs = toMs(f.from);
  const toMsV = toMs(f.to);
  if (fromMs !== undefined) query.fromMs = fromMs;
  if (toMsV !== undefined) query.toMs = toMsV;
  if (cursor) query.cursor = cursor;
  return query;
}

/** ns → local wall-clock string (ms floor — the ns stamp exceeds JS float precision). */
function fmtTs(ns: number): string {
  const d = new Date(Math.floor(ns / 1e6));
  const p = (n: number, w = 2): string => String(n).padStart(w, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(
    d.getMinutes(),
  )}:${p(d.getSeconds())}`;
}

function isoFromNs(ns: number): string {
  const ms = Math.floor(ns / 1e6);
  const d = new Date(ms);
  return Number.isFinite(ms) ? d.toISOString() : '';
}

const EXPORT_COLUMNS: ReadonlyArray<readonly [string, (r: RecentDecision) => string]> = [
  ['timestamp', (r) => isoFromNs(r.timestamp_ns)],
  ['decision', (r) => r.decision],
  ['alias', (r) => r.alias ?? ''],
  ['deny_reason', (r) => r.deny_reason ?? ''],
  ['risk_tier', (r) => r.risk_tier ?? ''],
  ['transport', (r) => r.transport ?? ''],
  ['classification', (r) => r.classification ?? ''],
  ['source_format', (r) => r.source_format ?? ''],
  ['agent_id', (r) => r.agent_id ?? ''],
  ['transaction_ref', (r) => r.transaction_ref ?? ''],
  ['worm_sequence', (r) => String(r.worm_sequence)],
  ['correlation_id', (r) => r.correlation_id],
  ['event_id', (r) => r.event_id ?? ''],
  ['tenant_id', (r) => r.tenant_id],
];

function csvCell(value: string): string {
  return /["\n,]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value;
}

function toCsv(rows: RecentDecision[]): string {
  const header = EXPORT_COLUMNS.map(([name]) => name).join(',');
  const body = rows
    .map((r) => EXPORT_COLUMNS.map(([, get]) => csvCell(get(r))).join(','))
    .join('\n');
  return `${header}\n${body}\n`;
}

function download(name: string, mime: string, data: string): void {
  const blob = new Blob([data], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

type LoadState = 'idle' | 'loading' | 'unavailable';

export function ActivityHistory({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const [draft, setDraft] = useState<FilterState>(EMPTY_FILTERS);
  const [applied, setApplied] = useState<FilterState>(EMPTY_FILTERS);
  const [rows, setRows] = useState<RecentDecision[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [state, setState] = useState<LoadState>('idle');
  const [scanned, setScanned] = useState(0);
  const [exporting, setExporting] = useState<null | { done: number; capped: boolean }>(null);
  const live = gateway.mode === 'live';
  const runId = useRef(0);
  // Bind the STABLE fetcher (a useCallback), not the whole `gateway` object.
  // useGatewayLive returns a fresh object every render; depending on `gateway`
  // made `load` change identity each render, so the effect below re-fired every
  // render — resetting rows to [] and refetching forever (the "0 rows" bug).
  const { fetchDecisionsPage } = gateway;

  const load = useCallback(
    async (filters: FilterState, resume: string | null): Promise<void> => {
      const id = ++runId.current;
      setState('loading');
      const page = await fetchDecisionsPage(buildQuery(filters, resume ?? undefined));
      if (id !== runId.current) return; // a newer request superseded this one
      if (page === null) {
        setState('unavailable');
        return;
      }
      setRows((prev) => (resume ? [...prev, ...page.decisions] : page.decisions));
      setScanned((prev) => (resume ? prev + page.scanned : page.scanned));
      setCursor(page.next_cursor);
      setState('idle');
    },
    [fetchDecisionsPage],
  );

  // First render (and whenever the applied filter set changes): fresh page 1.
  useEffect(() => {
    if (!live) return;
    setRows([]);
    setScanned(0);
    setCursor(null);
    void load(applied, null);
  }, [applied, live, load]);

  const apply = (): void => setApplied(draft);
  const reset = (): void => {
    setDraft(EMPTY_FILTERS);
    setApplied(EMPTY_FILTERS);
  };

  const exportAll = useCallback(
    async (format: 'csv' | 'json'): Promise<void> => {
      setExporting({ done: 0, capped: false });
      const collected: RecentDecision[] = [];
      let resume: string | undefined;
      let capped = false;
      for (let page = 0; page < MAX_EXPORT_PAGES; page += 1) {
        const q = buildQuery(applied, resume);
        q.limit = 200; // widest page for a bulk walk
        const res = await fetchDecisionsPage(q);
        if (res === null) break; // transport blip — export what we have, honestly
        collected.push(...res.decisions);
        setExporting({ done: collected.length, capped: false });
        if (collected.length >= MAX_EXPORT_ROWS) {
          capped = true;
          break;
        }
        if (res.next_cursor === null) break;
        resume = res.next_cursor;
      }
      const stamp = new Date().toISOString().replace(/[:.]/g, '-');
      if (format === 'csv') {
        download(`mcpip-decisions-${stamp}.csv`, 'text/csv;charset=utf-8', toCsv(collected));
      } else {
        download(
          `mcpip-decisions-${stamp}.json`,
          'application/json',
          JSON.stringify(collected, null, 2),
        );
      }
      setExporting({ done: collected.length, capped });
      window.setTimeout(() => setExporting(null), 4000);
    },
    [applied, fetchDecisionsPage],
  );

  if (!live) {
    return (
      <Panel className="h-full">
        <PanelHeader title="Activity History" icon={History} />
        <EmptyState
          icon={PlugZap}
          title="Connect a gateway to browse decision history"
          detail="The history query reads the tenant's own signed WORM decision tail (date range · multi-filter · export). It needs a live, admin-authorized gateway — offline shows nothing rather than a fabricated timeline."
        />
      </Panel>
    );
  }

  const busy = state === 'loading';
  const exportBusy = exporting !== null;
  // Count of the rare, disclosure-hidden facets that carry a value — surfaced as
  // a chip on the "More filters" summary so a collapsed active facet stays visible.
  const moreActive = [draft.denyReason, draft.riskTier, draft.agentId].filter(
    (v) => v.trim() !== '',
  ).length;

  return (
    <Panel className="h-full">
      <PanelHeader
        title="Activity History"
        icon={History}
        right={
          <span className="tabular">
            {rows.length} row{rows.length === 1 ? '' : 's'}
            {scanned > 0 ? ` · scanned ${scanned.toLocaleString()}` : ''}
          </span>
        }
      />

      {/* Filter bar */}
      <div className="shrink-0 border-b border-hairline bg-surface/60 px-4 py-3">
        {/* Common facets — always visible. */}
        <div className="grid grid-cols-2 gap-2.5 md:grid-cols-4">
          <Field label="From">
            <Input
              type="datetime-local"
              value={draft.from}
              onChange={(e) => setDraft({ ...draft, from: e.target.value })}
            />
          </Field>
          <Field label="To">
            <Input
              type="datetime-local"
              value={draft.to}
              onChange={(e) => setDraft({ ...draft, to: e.target.value })}
            />
          </Field>
          <Field label="Decision">
            <Select
              value={draft.decision}
              onChange={(e) =>
                setDraft({ ...draft, decision: e.target.value as FilterState['decision'] })
              }
            >
              <option value="">Any</option>
              <option value="allow">Allow</option>
              <option value="deny">Deny</option>
            </Select>
          </Field>
          <Field label="Alias">
            <Input
              mono
              placeholder="skill_a, skill_b"
              value={draft.alias}
              onChange={(e) => setDraft({ ...draft, alias: e.target.value })}
            />
          </Field>
        </div>

        {/* Rare facets — disclosed on demand; an active count keeps a collapsed
            filter visible so it never silently narrows the result set. */}
        <details className="group mt-2.5">
          <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[11px] font-medium text-slate-400 transition hover:text-ink">
            <ChevronRight size={13} className="transition-transform group-open:rotate-90" />
            More filters
            {moreActive > 0 ? (
              <span className="chip text-ink">
                {moreActive} active
              </span>
            ) : null}
          </summary>
          <div className="mt-2.5 grid grid-cols-2 gap-2.5 md:grid-cols-3">
            <Field label="Deny reason">
              <Input
                mono
                placeholder="canary_tripped, …"
                value={draft.denyReason}
                onChange={(e) => setDraft({ ...draft, denyReason: e.target.value })}
              />
            </Field>
            <Field label="Risk tier">
              <Input
                mono
                placeholder="high, critical"
                value={draft.riskTier}
                onChange={(e) => setDraft({ ...draft, riskTier: e.target.value })}
              />
            </Field>
            <Field label="Agent id">
              <Input
                mono
                placeholder="agent-…"
                value={draft.agentId}
                onChange={(e) => setDraft({ ...draft, agentId: e.target.value })}
              />
            </Field>
          </div>
        </details>
        <div className="mt-2.5 flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={apply}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg border border-ink/20 bg-ink px-3 py-1.5 text-[12px] font-semibold text-surface transition hover:opacity-90 disabled:opacity-50"
          >
            <Search size={13} />
            Apply filters
          </button>
          <button
            type="button"
            onClick={reset}
            className="inline-flex items-center gap-1.5 rounded-lg border border-hairline bg-canvas px-3 py-1.5 text-[12px] font-medium text-slate-400 transition hover:text-ink"
          >
            <RotateCcw size={13} />
            Reset
          </button>
          {/* One Export control — a split button whose menu holds both formats;
              each still walks the WHOLE window and streams the auditor CSV/JSON. */}
          <details className="group relative ml-auto">
            <summary className="inline-flex cursor-pointer list-none items-center gap-1.5 rounded-lg border border-hairline bg-canvas px-3 py-1.5 text-[12px] font-medium text-ink transition hover:border-ink/30">
              {exportBusy ? <Loader2 size={13} className="animate-spin" /> : <Download size={13} />}
              Export
              <ChevronRight size={13} className="transition-transform group-open:rotate-90" />
            </summary>
            <div className="absolute right-0 z-20 mt-1.5 flex w-44 flex-col overflow-hidden rounded-lg border border-hairline bg-surface shadow-panel">
              <button
                type="button"
                onClick={(e) => {
                  e.currentTarget.closest('details')?.removeAttribute('open');
                  void exportAll('csv');
                }}
                disabled={exportBusy}
                className="flex items-center gap-2 px-3 py-2 text-left text-[12px] text-ink transition hover:bg-canvas disabled:opacity-50"
              >
                <Download size={13} />
                Export CSV
              </button>
              <button
                type="button"
                onClick={(e) => {
                  e.currentTarget.closest('details')?.removeAttribute('open');
                  void exportAll('json');
                }}
                disabled={exportBusy}
                className="flex items-center gap-2 border-t border-hairline px-3 py-2 text-left text-[12px] text-ink transition hover:bg-canvas disabled:opacity-50"
              >
                <FileJson size={13} />
                Export JSON
              </button>
            </div>
          </details>
        </div>
        {exporting ? (
          <p className="mt-2 text-[11px] text-slate-500">
            {exporting.capped
              ? `Exported ${exporting.done.toLocaleString()} rows (capped at ${MAX_EXPORT_ROWS.toLocaleString()} — narrow the window for the full set).`
              : `Exporting… ${exporting.done.toLocaleString()} rows.`}
          </p>
        ) : null}
      </div>

      {/* Results */}
      <div className="min-h-0 flex-1 overflow-auto">
        {rows.length === 0 && state === 'unavailable' ? (
          <EmptyState
            icon={Filter}
            title="Decision history is unavailable"
            detail="The admin read did not answer — the gateway may lack a CAP_DIRECTORY_ADMIN token in this mode, or the endpoint is not reachable. Nothing is shown rather than an invented row."
          />
        ) : rows.length === 0 && !busy ? (
          <EmptyState
            icon={Inbox}
            title="No decisions in this window"
            detail="No allow/deny decisions match the current date range and filters. Widen the window or clear a facet."
          />
        ) : (
          <table className="w-full border-collapse text-[12px]">
            <thead className="sticky top-0 z-10 bg-surface">
              <tr className="border-b border-hairline text-left text-[10.5px] font-semibold uppercase tracking-wide text-slate-500">
                <th className="px-4 py-2 font-semibold">Time</th>
                <th className="px-3 py-2 font-semibold">Decision</th>
                <th className="px-3 py-2 font-semibold">Alias</th>
                <th className="px-3 py-2 font-semibold">Reason</th>
                <th className="px-3 py-2 font-semibold">Risk</th>
                <th className="px-3 py-2 font-semibold">Transport</th>
                <th className="px-3 py-2 text-right font-semibold">WORM #</th>
                <th className="px-3 py-2 font-semibold">Correlation</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr
                  key={`${r.worm_sequence}:${r.correlation_id}`}
                  className="border-b border-hairline/60 hover:bg-elevated/40"
                >
                  <td className="whitespace-nowrap px-4 py-1.5 tabular text-slate-400">
                    {fmtTs(r.timestamp_ns)}
                  </td>
                  <td className="px-3 py-1.5">
                    <Badge tone={r.decision === 'allow' ? 'verified' : 'denied'}>{r.decision}</Badge>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[11.5px] text-ink">{r.alias ?? '—'}</td>
                  <td className="px-3 py-1.5 font-mono text-[11.5px] text-slate-400">
                    {r.deny_reason ?? '—'}
                  </td>
                  <td className="px-3 py-1.5 text-slate-400">{r.risk_tier ?? '—'}</td>
                  <td className="px-3 py-1.5 text-slate-400">{r.transport ?? '—'}</td>
                  <td className="px-3 py-1.5 text-right tabular text-slate-400">
                    {r.worm_sequence}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-[11px] text-slate-500">
                    {r.correlation_id.slice(0, 12)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Footer: load-more / terminal state */}
      {rows.length > 0 ? (
        <div className="flex shrink-0 items-center justify-center gap-3 border-t border-hairline px-4 py-2.5">
          {cursor !== null ? (
            <button
              type="button"
              onClick={() => void load(applied, cursor)}
              disabled={busy}
              className="inline-flex items-center gap-1.5 rounded-lg border border-hairline bg-canvas px-3 py-1.5 text-[12px] font-medium text-ink transition hover:border-ink/30 disabled:opacity-50"
            >
              {busy ? <Loader2 size={13} className="animate-spin" /> : null}
              Load more
            </button>
          ) : (
            <span className="text-[11px] text-slate-500">End of window · {rows.length} rows loaded</span>
          )}
        </div>
      ) : null}
    </Panel>
  );
}
