/* ---------------------------------------------------------------------------
   Analytics — the tenant's decision posture, at a glance, on LIVE data only.

   Two honest sources, no mock anywhere:
     • GET /v1/admin/stats (DeploymentStats) — the authoritative all-time
       allow/deny/staged totals, governed-identity cardinality (HyperLogLog),
       and the live latency/throughput metrics the console already scrapes.
     • GET /v1/admin/decisions (a bounded recent window over the SAME whitelist
       projection the feed serves) — aggregated IN THE BROWSER into the top
       aliases and the deny-reason breakdown. Labeled "last N decisions" so the
       sample is never mistaken for the all-time totals.

   Forms follow the data's job (dataviz): hero stat tiles for the headline
   numbers, a composition bar for the allow/deny/staged mix (reserved status
   colors, always label-paired), a sparkline for throughput-over-time, and
   single-hue magnitude bar lists for the rankings. Offline / an unavailable
   admin read render the standard empty state, never a fabricated chart.
--------------------------------------------------------------------------- */

import { useCallback, useEffect, useState } from 'react';
import {
  Activity,
  BarChart3,
  Layers,
  Loader2,
  PlugZap,
  RefreshCw,
  ShieldAlert,
  Users,
} from 'lucide-react';
import { Badge, EmptyState, Panel, PanelHeader } from '../ui';
import { AnimatedNumber } from '../AnimatedNumber';
import { Sparkline } from '../Sparkline';
import type { DeploymentStats, RecentDecision } from '../../lib/api';
import type { GatewayLive } from '../../lib/useGatewayLive';

/** How deep the in-browser aggregation walks the recent decision window. */
const AGG_PAGE = 200;
const AGG_MAX_PAGES = 15; // up to ~3000 recent decisions — bounded, honest sample.
const TOP_N = 8;

interface Aggregate {
  sampled: number;
  aliases: Array<{ label: string; value: number }>;
  denyReasons: Array<{ label: string; value: number }>;
}

/** Tally a field across rows → the TOP_N descending, with the rest folded away. */
function topCounts(
  rows: RecentDecision[],
  pick: (r: RecentDecision) => string | null,
): Array<{ label: string; value: number }> {
  const counts = new Map<string, number>();
  for (const r of rows) {
    const key = pick(r);
    if (!key) continue;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([label, value]) => ({ label, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, TOP_N);
}

/* --- Chart primitives (dataviz mark specs, MCPIP tokens) ------------------ */

function StatTile({
  icon: Icon,
  label,
  value,
  decimals = 0,
  suffix,
  sub,
}: {
  icon: typeof Users;
  label: string;
  value: number | null;
  decimals?: number;
  suffix?: string;
  sub?: string;
}): JSX.Element {
  return (
    <div className="panel flex flex-col gap-1 px-4 py-3">
      <div className="flex items-center gap-1.5 text-[10.5px] font-medium uppercase tracking-[0.1em] text-slate-500">
        <Icon size={13} className="text-slate-500" />
        {label}
      </div>
      <div className="flex items-baseline gap-1">
        {value === null ? (
          <span className="text-[22px] font-semibold text-slate-600">—</span>
        ) : (
          <AnimatedNumber
            value={value}
            decimals={decimals}
            className="tabular text-[22px] font-semibold text-ink"
          />
        )}
        {suffix && value !== null ? (
          <span className="text-[12px] font-medium text-slate-500">{suffix}</span>
        ) : null}
      </div>
      {sub ? <div className="text-[11px] text-slate-500">{sub}</div> : null}
    </div>
  );
}

function DecisionMix({
  allow,
  deny,
  staged,
}: {
  allow: number;
  deny: number;
  staged: number;
}): JSX.Element {
  const total = allow + deny + staged;
  const segments = [
    { label: 'Allow', cls: 'bg-verified', value: allow },
    { label: 'Deny', cls: 'bg-denied', value: deny },
    { label: 'Staged', cls: 'bg-staged', value: staged },
  ];
  const pct = (n: number): number => (total > 0 ? (n / total) * 100 : 0);
  return (
    <div className="flex flex-col gap-3">
      {/* Composition bar — 2px surface gaps between fills, rounded outer ends. */}
      <div className="flex h-3 w-full gap-0.5 overflow-hidden rounded-full bg-elevated">
        {total === 0
          ? null
          : segments.map((s) => {
              const w = pct(s.value);
              if (w <= 0) return null;
              return (
                <div
                  key={s.label}
                  className={`${s.cls} h-full first:rounded-l-full last:rounded-r-full`}
                  style={{ width: `${w}%` }}
                  title={`${s.label}: ${s.value.toLocaleString()} (${w.toFixed(1)}%)`}
                />
              );
            })}
      </div>
      {/* Legend — swatch + label + count + pct; identity is never color-alone. */}
      <div className="flex flex-wrap gap-x-6 gap-y-2">
        {segments.map((s) => (
          <div key={s.label} className="flex items-center gap-2">
            <span className={`h-2.5 w-2.5 rounded-sm ${s.cls}`} aria-hidden="true" />
            <span className="text-[12px] font-medium text-ink">{s.label}</span>
            <span className="tabular text-[12px] text-slate-500">{s.value.toLocaleString()}</span>
            <span className="tabular text-[11px] text-slate-600">{pct(s.value).toFixed(1)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function BarList({
  rows,
  tone,
  empty,
}: {
  rows: Array<{ label: string; value: number }>;
  tone: 'ink' | 'denied';
  empty: string;
}): JSX.Element {
  if (rows.length === 0) {
    return <div className="px-1 py-4 text-[12px] text-slate-500">{empty}</div>;
  }
  const max = Math.max(...rows.map((r) => r.value), 1);
  const fill = tone === 'denied' ? 'bg-denied/70' : 'bg-ink/70';
  return (
    <div className="flex flex-col gap-2">
      {rows.map((r) => (
        <div key={r.label} className="flex items-center gap-3" title={`${r.label}: ${r.value}`}>
          <span className="w-40 shrink-0 truncate font-mono text-[11.5px] text-ink" title={r.label}>
            {r.label}
          </span>
          <div className="h-2.5 flex-1 overflow-hidden rounded-full bg-elevated">
            <div
              className={`h-full rounded-full ${fill}`}
              style={{ width: `${Math.max((r.value / max) * 100, 2)}%` }}
            />
          </div>
          <span className="tabular w-10 shrink-0 text-right text-[11.5px] text-slate-500">
            {r.value.toLocaleString()}
          </span>
        </div>
      ))}
    </div>
  );
}

export function Analytics({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const [stats, setStats] = useState<DeploymentStats | null>(null);
  const [agg, setAgg] = useState<Aggregate | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadedOnce, setLoadedOnce] = useState(false);
  const live = gateway.mode === 'live';
  // Bind the STABLE fetchers (useCallbacks), not the whole `gateway` object —
  // useGatewayLive returns a fresh object every render, so depending on `gateway`
  // makes `refresh` change identity each render and the effect below re-fire in a
  // tight loop (re-pulling stats and re-walking the decision window every render).
  const { fetchDeploymentStats, fetchDecisionsPage } = gateway;

  const refresh = useCallback(async (): Promise<void> => {
    setLoading(true);
    const s = await fetchDeploymentStats();
    setStats(s);
    // Aggregate a bounded recent window for the rankings (client-side, honest sample).
    const rows: RecentDecision[] = [];
    let cursor: string | undefined;
    for (let page = 0; page < AGG_MAX_PAGES; page += 1) {
      const res = await fetchDecisionsPage({ limit: AGG_PAGE, cursor });
      if (res === null) break;
      rows.push(...res.decisions);
      if (res.next_cursor === null) break;
      cursor = res.next_cursor;
    }
    setAgg({
      sampled: rows.length,
      aliases: topCounts(rows, (r) => r.alias),
      denyReasons: topCounts(
        rows.filter((r) => r.decision === 'deny'),
        (r) => r.deny_reason,
      ),
    });
    setLoading(false);
    setLoadedOnce(true);
  }, [fetchDeploymentStats, fetchDecisionsPage]);

  useEffect(() => {
    if (live) void refresh();
  }, [live, refresh]);

  if (!live) {
    return (
      <Panel className="h-full">
        <PanelHeader title="Analytics" icon={BarChart3} />
        <EmptyState
          icon={PlugZap}
          title="Connect a gateway to see analytics"
          detail="Analytics reads the tenant's own live decision totals, governed-identity count, latency, and a recent-window breakdown of aliases and deny reasons — all from the running gateway. Offline shows nothing rather than a fabricated dashboard."
        />
      </Panel>
    );
  }

  const d = stats?.decisions;
  const total = d ? d.allow + d.deny + d.staged : null;
  const denyRate = d && total && total > 0 ? (d.deny / total) * 100 : null;
  const m = gateway.metrics;

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto pb-2">
      {/* Header row with a manual refresh (the numbers are live-scraped elsewhere;
          this re-pulls the stats + re-aggregates the ranking window on demand). */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <BarChart3 size={15} className="text-slate-500" />
          <h2 className="text-[14px] font-semibold text-ink">Analytics</h2>
          {stats ? <Badge tone="muted">v{stats.version}</Badge> : null}
        </div>
        <button
          type="button"
          onClick={() => void refresh()}
          disabled={loading}
          className="inline-flex items-center gap-1.5 rounded-lg border border-hairline bg-canvas px-3 py-1.5 text-[12px] font-medium text-ink transition hover:border-ink/30 disabled:opacity-50"
        >
          {loading ? (
            <Loader2 size={13} className="animate-spin" />
          ) : (
            <RefreshCw size={13} />
          )}
          Refresh
        </button>
      </div>

      {!loadedOnce && loading ? (
        <div className="flex flex-1 items-center justify-center text-slate-500">
          <Loader2 size={20} className="animate-spin" />
        </div>
      ) : !stats ? (
        <Panel className="flex-1">
          <EmptyState
            icon={BarChart3}
            title="Analytics is unavailable"
            detail="The admin stats read did not answer — the gateway may lack a CAP_DIRECTORY_ADMIN token in this mode, or the endpoint is not reachable. Nothing is shown rather than an invented number."
          />
        </Panel>
      ) : (
        <>
          {/* KPI tiles — headline numbers only. Deny rate now rides the decision-mix
              bar; p95 lives on the Throughput card; WORM height moved to the ledger. */}
          <div className="grid grid-cols-2 gap-3">
            <StatTile
              icon={Users}
              label="Governed identities"
              value={stats.governed_agent_identity_count}
              sub="unique agent ids (HLL)"
            />
            <StatTile icon={Activity} label="Total decisions" value={total} sub="allow + deny + staged" />
          </div>

          {/* Decision mix + throughput */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Panel>
              <PanelHeader
                title="Decision mix"
                icon={Layers}
                right={
                  <span className="flex items-center gap-2">
                    <span>all-time</span>
                    {denyRate !== null ? (
                      <span className="tabular font-semibold text-denied">
                        <ShieldAlert size={11} className="mr-1 inline align-[-1px]" />
                        deny {denyRate.toFixed(1)}%
                      </span>
                    ) : null}
                  </span>
                }
              />
              <div className="px-4 py-4">
                {d ? <DecisionMix allow={d.allow} deny={d.deny} staged={d.staged} /> : null}
              </div>
            </Panel>
            <Panel>
              <PanelHeader
                title="Throughput"
                icon={Activity}
                right={m.decisionsPerSec !== null ? `${m.decisionsPerSec.toFixed(2)}/s now` : 'idle'}
              />
              <div className="flex flex-col gap-3 px-4 py-4">
                <div className="text-verified">
                  <Sparkline data={gateway.throughputHistory} width={520} height={44} className="w-full" />
                </div>
                <div className="flex gap-6 text-[11.5px] text-slate-500">
                  <span>
                    decisions/sec · {gateway.throughputHistory.length} live points
                  </span>
                  {m.gatewayP50Ms !== null ? (
                    <span className="tabular">p50 {m.gatewayP50Ms.toFixed(1)} ms</span>
                  ) : null}
                  {m.gatewayP95Ms !== null ? (
                    <span className="tabular">p95 {m.gatewayP95Ms.toFixed(1)} ms</span>
                  ) : null}
                </div>
              </div>
            </Panel>
          </div>

          {/* Rankings from the recent-window sample */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Panel>
              <PanelHeader
                title="Top aliases"
                icon={BarChart3}
                right={agg ? `last ${agg.sampled.toLocaleString()}` : ''}
              />
              <div className="px-4 py-4">
                <BarList
                  rows={agg?.aliases ?? []}
                  tone="ink"
                  empty="No decisions in the recent window yet."
                />
              </div>
            </Panel>
            <Panel>
              <PanelHeader
                title="Top deny reasons"
                icon={ShieldAlert}
                right={agg ? `last ${agg.sampled.toLocaleString()}` : ''}
              />
              <div className="px-4 py-4">
                <BarList
                  rows={agg?.denyReasons ?? []}
                  tone="denied"
                  empty="No denials in the recent window — clean traffic."
                />
              </div>
            </Panel>
          </div>

          <p className="px-1 text-[11px] text-slate-500">
            Totals and identity count are authoritative (all-time, from the gateway); the
            alias and deny-reason rankings are aggregated in-browser from the last
            {agg ? ` ${agg.sampled.toLocaleString()}` : ''} decisions — a bounded, honest
            sample, not the all-time distribution.
          </p>
        </>
      )}
    </div>
  );
}
