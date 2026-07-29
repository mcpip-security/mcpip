/* ---------------------------------------------------------------------------
   Canary Tripwires — the deception layer as a LIVE instrument, not a brochure.

   Three real sources, nothing hardcoded:
     • decoy roster    — GET /v1/admin/canaries (the ONLY surface where the
                         canary flag may cross the wire; agents never see it),
       cross-referenced with the tenant's disable-set so a stopped (disarmed)
       decoy is visible as such;
     • trips           — the session-observed decision feed (lib/ledger ring
                         buffer over /v1/admin/decisions/recent), filtered on
                         the real deny reasons canary_tripped /
                         agent_quarantined;
     • quarantine      — GET /v1/admin/quarantine, the agents currently frozen
                         by a trip, each with its remaining Redis TTL.

   Offline renders the standard connect state; a gateway that predates the
   admin rosters (404) gets the honest "unavailable" line — never a seeded
   table standing in for state.
--------------------------------------------------------------------------- */

import { useEffect, useMemo, useState } from 'react';
import { Bug, Inbox, PlugZap, ScrollText, ShieldAlert, Snowflake } from 'lucide-react';
import { Badge, EmptyState, Panel, PanelHeader } from '../ui';
import { formatClock } from '../../lib/format';
import { loadDisabledSkills } from '../../lib/skillGate';
import { useWormLedger } from '../../lib/ledger';
import { useCompanyConfig } from '../../lib/companyConfig';
import type { LedgerRow } from '../../lib/ledger';
import type { CanaryDecoy, QuarantinedAgent } from '../../lib/api';
import type { GatewayLive } from '../../lib/useGatewayLive';

const ROSTER_POLL_MS = 5000;

/** undefined = first read in flight · null = endpoint/admin read unavailable. */
type Roster<T> = T[] | null | undefined;

/** Per-alias trip stats derived from REAL canary_tripped rows. */
interface DecoyStats {
  trips: number;
  lastTs: number | null;
}

/** Per-agent activity derived from the feed + the live quarantine roster. */
interface AgentActivity {
  agent: string;
  trips: number;
  /** Requests denied AGENT_QUARANTINED while frozen. */
  frozenDenies: number;
  lastTs: number | null;
  /** Remaining freeze TTL (s) when currently quarantined; null otherwise. */
  ttlSeconds: number | null;
  quarantined: boolean;
}

function navigateTo(view: string, subtab: string): void {
  window.dispatchEvent(new CustomEvent('mcpip:navigate', { detail: { view, subtab } }));
}

function MetricTile({
  label,
  value,
  tone = 'ink',
  sub,
}: {
  label: string;
  value: string;
  tone?: 'ink' | 'denied' | 'verified';
  sub?: string;
}): JSX.Element {
  const toneClass = tone === 'denied' ? 'text-denied' : tone === 'verified' ? 'text-verified' : 'text-ink';
  return (
    <div className="metric">
      <span className="metric-label">{label}</span>
      <span className={`metric-value truncate ${toneClass}`}>{value}</span>
      {sub !== undefined ? <span className="truncate text-[10.5px] text-slate-500">{sub}</span> : null}
    </div>
  );
}

/** Calm single-line degradation for an admin roster the gateway did not serve. */
function RosterUnavailable({ endpoint }: { endpoint: string }): JSX.Element {
  return (
    <div className="space-y-1.5 px-4 py-3">
      <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11px] leading-relaxed text-slate-400">
        <ShieldAlert size={13} className="mt-0.5 shrink-0" />
        <span>
          <span className="font-semibold">Roster unavailable. </span>
          <span className="font-mono text-[10.5px]">{endpoint}</span> did not answer.
        </span>
      </div>
      <p className="pl-6 text-[10.5px] leading-relaxed text-slate-500">
        The connected gateway predates this admin endpoint, or the console holds no{' '}
        <span className="font-mono text-[10px]">CAP_DIRECTORY_ADMIN</span> credential (production
        mounts no sandbox token minter).
      </p>
    </div>
  );
}

export function CanaryPanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { mode, apiBase, tenant, fetchCanaries, fetchQuarantine } = gateway;
  const { config } = useCompanyConfig();
  const skillTenant = tenant ?? config?.tenant ?? null;
  const live = mode === 'live';

  // Trips come from the same session ring buffer the Audit Ledger accumulates —
  // one shared observation store, no second source of truth.
  const ledger = useWormLedger(gateway);

  const [decoys, setDecoys] = useState<Roster<CanaryDecoy>>(undefined);
  const [quarantine, setQuarantine] = useState<Roster<QuarantinedAgent>>(undefined);
  const [disabled, setDisabled] = useState<ReadonlySet<string>>(new Set());

  useEffect(() => {
    if (!live) {
      setDecoys(undefined);
      setQuarantine(undefined);
      setDisabled(new Set());
      return;
    }
    let cancelled = false;
    const controller = new AbortController();
    const tick = async (): Promise<void> => {
      const [canaryRows, quarantineRows, off] = await Promise.all([
        fetchCanaries(controller.signal),
        fetchQuarantine(controller.signal),
        skillTenant ? loadDisabledSkills(apiBase, skillTenant, controller.signal) : Promise.resolve([]),
      ]);
      if (cancelled) return;
      setDecoys(canaryRows);
      setQuarantine(quarantineRows);
      setDisabled(new Set(off));
    };
    void tick();
    const id = window.setInterval(() => {
      void tick();
    }, ROSTER_POLL_MS);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [live, apiBase, skillTenant, fetchCanaries, fetchQuarantine]);

  // ledger.rows is worm_sequence DESC, so index 0 of a filtered slice is newest.
  const tripRows = useMemo(
    () => ledger.rows.filter((r) => r.projection.deny_reason === 'canary_tripped'),
    [ledger.rows],
  );
  const frozenRows = useMemo(
    () => ledger.rows.filter((r) => r.projection.deny_reason === 'agent_quarantined'),
    [ledger.rows],
  );

  const decoyStats = useMemo(() => {
    const map = new Map<string, DecoyStats>();
    for (const r of tripRows) {
      const alias = r.projection.alias;
      if (!alias) continue;
      const prev = map.get(alias) ?? { trips: 0, lastTs: null };
      map.set(alias, { trips: prev.trips + 1, lastTs: prev.lastTs ?? r.ts });
    }
    return map;
  }, [tripRows]);

  const agents = useMemo((): AgentActivity[] => {
    const map = new Map<string, AgentActivity>();
    const bump = (row: LedgerRow, kind: 'trip' | 'frozen'): void => {
      const agent = row.projection.agent_id ?? '(unknown)';
      const prev = map.get(agent) ?? {
        agent,
        trips: 0,
        frozenDenies: 0,
        lastTs: null,
        ttlSeconds: null,
        quarantined: false,
      };
      map.set(agent, {
        ...prev,
        trips: prev.trips + (kind === 'trip' ? 1 : 0),
        frozenDenies: prev.frozenDenies + (kind === 'frozen' ? 1 : 0),
        lastTs: prev.lastTs === null ? row.ts : Math.max(prev.lastTs, row.ts),
      });
    };
    for (const r of tripRows) bump(r, 'trip');
    for (const r of frozenRows) bump(r, 'frozen');
    for (const q of quarantine ?? []) {
      const prev = map.get(q.agent_id) ?? {
        agent: q.agent_id,
        trips: 0,
        frozenDenies: 0,
        lastTs: null,
        ttlSeconds: null,
        quarantined: false,
      };
      map.set(q.agent_id, { ...prev, quarantined: true, ttlSeconds: q.ttl_seconds });
    }
    return [...map.values()].sort((a, b) => {
      if (a.quarantined !== b.quarantined) return a.quarantined ? -1 : 1;
      return (b.lastTs ?? 0) - (a.lastTs ?? 0);
    });
  }, [tripRows, frozenRows, quarantine]);

  if (!live) {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={Bug}
          title="No gateway connected"
          detail="Connect a gateway to see its decoy roster, trips and quarantine state."
          action={
            <button type="button" className="btn-primary" onClick={() => navigateTo('gateway', 'connection')}>
              <PlugZap size={13} /> Connect a gateway
            </button>
          }
        />
      </Panel>
    );
  }

  const armed = Array.isArray(decoys) ? decoys.filter((d) => !disabled.has(d.alias)).length : null;
  const feedLive = ledger.observedSince !== null;

  return (
    <div className="flex h-full flex-col gap-3">
      <div className="grid shrink-0 grid-cols-2 gap-3">
        <MetricTile
          label="Decoys armed"
          value={armed !== null ? String(armed) : '—'}
          sub={
            Array.isArray(decoys) && armed !== null && decoys.length > armed
              ? `${decoys.length - armed} stopped`
              : undefined
          }
        />
        <MetricTile
          label="Quarantined now"
          value={Array.isArray(quarantine) ? String(quarantine.length) : '—'}
          tone={Array.isArray(quarantine) && quarantine.length > 0 ? 'denied' : 'ink'}
        />
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-2">
        {/* --- Decoy roster ------------------------------------------------- */}
        <Panel>
          <PanelHeader
            icon={Bug}
            title="Tripwires"
            right={<span className="font-mono text-[10.5px]">canary aliases · /v1/admin/canaries</span>}
          />
          {decoys === undefined ? (
            <div className="px-4 py-3 text-[11px] text-slate-500">Reading the decoy roster…</div>
          ) : decoys === null ? (
            <RosterUnavailable endpoint="GET /v1/admin/canaries" />
          ) : decoys.length === 0 ? (
            <EmptyState
              icon={Bug}
              title="No decoys armed for this tenant"
              detail="Canaries are opt-in — none are ever seeded into your catalog uninvited."
            />
          ) : (
            <div className="min-h-0 flex-1 overflow-auto">
              <table className="w-full min-w-[460px] border-collapse text-left">
                <thead className="sticky top-0 z-10 bg-surface">
                  <tr className="border-b border-hairline text-[10.5px] font-semibold uppercase tracking-[0.06em] text-slate-500">
                    <th className="px-4 py-2 font-semibold">Decoy alias</th>
                    <th className="px-4 py-2 font-semibold">State</th>
                    <th className="px-4 py-2 font-semibold">Trips</th>
                    <th className="px-4 py-2 font-semibold">Last trip</th>
                  </tr>
                </thead>
                <tbody>
                  {decoys.map((d) => {
                    const stats = decoyStats.get(d.alias) ?? null;
                    const isArmed = !disabled.has(d.alias);
                    return (
                      <tr key={d.alias} className="border-b border-hairline/60 transition-colors last:border-0 hover:bg-canvas">
                        <td className="px-4 py-2">
                          <span className="block truncate font-mono text-[11.5px] text-ink">{d.alias}</span>
                          <span className="text-[10px] text-slate-500">
                            {d.risk_tier ?? 'auto'} · {d.classification ?? 'unclassified'}
                          </span>
                        </td>
                        <td className="px-4 py-2">
                          {/* verified = live tripwire; staged = attention: the trap is off. */}
                          <Badge tone={isArmed ? 'verified' : 'staged'}>{isArmed ? 'armed' : 'stopped'}</Badge>
                        </td>
                        <td className="tabular px-4 py-2 font-mono text-[11px] text-slate-400">
                          {feedLive ? (stats?.trips ?? 0) : '—'}
                        </td>
                        <td className="tabular px-4 py-2 font-mono text-[11px] text-slate-400">
                          {stats !== null && stats.lastTs !== null ? formatClock(stats.lastTs) : '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-auto shrink-0 border-t border-hairline px-4 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
            Selecting a decoy is denied <span className="font-mono text-[10px]">CANARY_TRIPPED</span>{' '}
            and the caller is frozen for the quarantine TTL.
          </div>
        </Panel>

        {/* --- Trips & quarantine ------------------------------------------- */}
        <Panel>
          <PanelHeader
            icon={Snowflake}
            title="Trips & quarantine"
            right={
              <button
                type="button"
                onClick={() => navigateTo('ledger', 'events')}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 transition-colors hover:text-ink"
              >
                <ScrollText size={11} /> Open audit log
              </button>
            }
          />
          {quarantine === null ? <RosterUnavailable endpoint="GET /v1/admin/quarantine" /> : null}
          {agents.length === 0 ? (
            quarantine === null ? null : (
              <EmptyState
                icon={Inbox}
                title="No trips observed"
                detail="No canary trips or quarantined agents in this session."
              />
            )
          ) : (
            <div className="min-h-0 flex-1 overflow-auto">
              <table className="w-full min-w-[460px] border-collapse text-left">
                <thead className="sticky top-0 z-10 bg-surface">
                  <tr className="border-b border-hairline text-[10.5px] font-semibold uppercase tracking-[0.06em] text-slate-500">
                    <th className="px-4 py-2 font-semibold">Agent</th>
                    <th className="px-4 py-2 font-semibold">Trips</th>
                    <th className="px-4 py-2 font-semibold">Denied frozen</th>
                    <th className="px-4 py-2 font-semibold">Last event</th>
                    <th className="px-4 py-2 font-semibold">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((a) => (
                    <tr key={a.agent} className="border-b border-hairline/60 transition-colors last:border-0 hover:bg-canvas">
                      <td className="max-w-[180px] truncate px-4 py-2 font-mono text-[11.5px] text-ink">{a.agent}</td>
                      <td className="tabular px-4 py-2 font-mono text-[11px] text-slate-400">{a.trips}</td>
                      <td className="tabular px-4 py-2 font-mono text-[11px] text-slate-400">{a.frozenDenies}</td>
                      <td className="tabular px-4 py-2 font-mono text-[11px] text-slate-400">
                        {a.lastTs !== null ? formatClock(a.lastTs) : '—'}
                      </td>
                      <td className="px-4 py-2">
                        {a.quarantined ? (
                          <Badge tone="denied">
                            <Snowflake size={10} />
                            {a.ttlSeconds !== null ? `frozen · ~${a.ttlSeconds}s` : 'frozen'}
                          </Badge>
                        ) : (
                          <span className="text-[10.5px] text-slate-500">released</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          <div className="mt-auto shrink-0 border-t border-hairline px-4 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
            {feedLive ? (
              <>
                Derived from <span className="font-mono text-[10px]">/v1/admin/decisions/recent</span> —{' '}
                <span className="tabular">{ledger.observedCount}</span> decisions observed this session · freeze
                expiry is Redis&apos;s clock; a deliberate persistent block is the Directory revoke.
              </>
            ) : ledger.feedState === 'unavailable' ? (
              <>
                The decision feed read is unavailable — trip counts need{' '}
                <span className="font-mono text-[10px]">/v1/admin/decisions/recent</span>.
              </>
            ) : (
              'Contacting the decision feed…'
            )}
          </div>
        </Panel>
      </div>
    </div>
  );
}
