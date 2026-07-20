import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { ChevronRight } from 'lucide-react';
import { AnimatedNumber } from './AnimatedNumber';
import { Sparkline } from './Sparkline';
import type { AuditVerifyResult } from '../lib/api';
import type { GatewayLive, Readiness } from '../lib/useGatewayLive';
import type { MetricsSnapshot } from '../lib/types';

/* ---------------------------------------------------------------------------
   Overview KPI wall — six tiles, every number a REAL gateway source. The
   `compact` variant keeps the four decision-flow tiles on the wall and tucks
   readiness + catalog behind a native disclosure (Live landing density):

     • Decisions/s + sparkline   — per-scrape deltas of the gateway's own
       mcpip_authorize_decisions_total counter (throughputHistory records one
       real point per scrape; nothing is backfilled).
     • Decisions · since start   — the cumulative counter + allow/deny/staged
       split, straight from GET /metrics.
     • Gateway p50 / p95         — interpolated from the gateway-side
       mcpip_authorize_latency_seconds histogram (ALL agents' traffic — this
       replaced the old console-fed gauge that could never move).
     • Audit chain               — /v1/audit/verify verdict; when that
       sandbox-only endpoint is absent the tile says so instead of faking a
       green check. WORM height/epoch ride along from the /metrics gauges.
     • Readiness                 — /readyz (redis is the fail-closed hinge).
     • Catalog                   — what /v1/catalog enumerates for THIS
       console identity, with the honest compartment count (never "tenants").

   null always renders as "—" (no signal), never as a fabricated zero.
--------------------------------------------------------------------------- */

type ChipTone = 'verified' | 'denied' | 'muted';

const CHIP_TEXT: Record<ChipTone, string> = {
  verified: 'text-verified',
  denied: 'text-denied',
  muted: 'text-slate-400',
};

/** A word-valued tile state (chain / readiness chips). */
interface CellState {
  value: string;
  tone: ChipTone;
  detail: string;
}

function chainCell(audit: AuditVerifyResult | null, m: MetricsSnapshot): CellState {
  if (audit === null) {
    // /v1/audit/verify is sandbox-only; production verifies out-of-band.
    return {
      value: 'Unverified',
      tone: 'muted',
      detail: 'external verifier required · mcpip export-audit',
    };
  }
  if (!audit.intact) {
    return {
      value: 'Tampered',
      tone: 'denied',
      detail: `first bad epoch ${audit.first_bad_epoch ?? 'unknown'}`,
    };
  }
  const parts: string[] = [];
  if (m.wormSequence !== null) {
    parts.push(`seq #${m.wormSequence.toLocaleString('en-US')}`);
  }
  if (m.wormEpoch !== null) {
    parts.push(`epoch ${m.wormEpoch}`);
  }
  return {
    value: 'Intact',
    tone: 'verified',
    detail: parts.length > 0 ? parts.join(' · ') : 'signed chain verified',
  };
}

function readyCell(ready: Readiness | null): CellState {
  if (ready === null) {
    return { value: '—', tone: 'muted', detail: 'no /readyz signal yet' };
  }
  if (ready.ready) {
    return { value: 'Ready', tone: 'verified', detail: `redis ${ready.redis}` };
  }
  return {
    value: 'Not ready',
    tone: 'denied',
    detail: ready.redis === 'down' ? 'redis down · failing closed' : `redis ${ready.redis}`,
  };
}

function Tile({
  label,
  children,
  detail,
}: {
  label: string;
  children: ReactNode;
  detail?: ReactNode;
}): JSX.Element {
  return (
    <div className="metric min-w-0">
      <p className="metric-label">{label}</p>
      <div className="flex min-w-0 items-baseline gap-1">{children}</div>
      {detail !== undefined ? (
        <div className="min-w-0 text-[10.5px] leading-relaxed text-slate-500">{detail}</div>
      ) : null}
    </div>
  );
}

/** Truncating one-line tile detail with the full text on hover. */
function DetailText({ text }: { text: string }): JSX.Element {
  return (
    <span className="block truncate" title={text}>
      {text}
    </span>
  );
}

/** Numeric tile value: the real number, or an honest "—" when there is no signal. */
function Value({
  value,
  decimals = 0,
  unit,
}: {
  value: number | null;
  decimals?: number;
  unit?: string;
}): JSX.Element {
  if (value === null) {
    return <span className="metric-value text-slate-400">—</span>;
  }
  return (
    <>
      <AnimatedNumber value={value} decimals={decimals} className="metric-value" />
      {unit ? <span className="text-[11px] font-medium text-slate-500">{unit}</span> : null}
    </>
  );
}

const fmt = (v: number | null): string => (v === null ? '—' : v.toLocaleString('en-US'));

interface MetricsGridProps {
  /** The live gateway artery — every tile reads a real source off it (see header). */
  gateway: GatewayLive;
  /**
   * Landing-density variant: show only the four decision-relevant tiles
   * (throughput, cumulative split, gateway latency, audit chain) and tuck the
   * two scope/infra tiles (readiness, catalog) behind a native disclosure so
   * nothing is lost — the Live landing wanted less at equal weight, not fewer
   * facts. Default (false) renders the full six-tile wall.
   */
  compact?: boolean;
}

export function MetricsGrid({ gateway, compact = false }: MetricsGridProps): JSX.Element {
  const m = gateway.metrics;

  // Distinct compartment UUIDs across MY catalog — honest scope, never "tenants".
  const compartments = useMemo(() => {
    const set = new Set<string>();
    for (const item of gateway.catalog) {
      if (item.compartment) {
        set.add(item.compartment);
      }
    }
    return set.size;
  }, [gateway.catalog]);

  const chain = chainCell(gateway.audit, m);
  const readiness = readyCell(gateway.ready);

  const latencyDetail =
    m.gatewayP50Ms !== null
      ? `p95 ${m.gatewayP95Ms === null ? '—' : m.gatewayP95Ms.toFixed(1)} ms · all agents`
      : m.decisionsTotal !== null
        ? 'no authorize traffic observed yet'
        : 'no /metrics signal';

  const compartmentDetail =
    compartments === 0
      ? 'no compartments in my catalog'
      : `${compartments} compartment${compartments === 1 ? '' : 's'} in my catalog`;

  // The four decision-flow tiles — throughput, cumulative split, gateway
  // latency, audit-chain integrity. These stay on the wall in every variant.
  const decisionTiles = (
    <>
      <Tile
        label="Decisions / s"
        detail={
          gateway.throughputHistory.length >= 2 ? (
            <Sparkline
              data={gateway.throughputHistory}
              width={200}
              height={22}
              className="w-full text-ink"
            />
          ) : (
            <DetailText text="per-scrape counter deltas" />
          )
        }
      >
        <Value value={m.decisionsPerSec} decimals={1} />
      </Tile>

      <Tile
        label="Decisions · since start"
        detail={
          m.decisionsTotal === null ? (
            <DetailText text="no /metrics signal" />
          ) : (
            <span className="tabular block truncate">
              <span className="text-verified">{fmt(m.allowTotal)} allow</span>
              <span className="text-slate-600"> · </span>
              <span className="text-denied">{fmt(m.denyTotal)} deny</span>
              <span className="text-slate-600"> · </span>
              <span className="text-staged">{fmt(m.stagedTotal)} staged</span>
            </span>
          )
        }
      >
        <Value value={m.decisionsTotal} />
      </Tile>

      <Tile label="Gateway p50" detail={<DetailText text={latencyDetail} />}>
        <Value value={m.gatewayP50Ms} decimals={1} unit="ms" />
      </Tile>

      <Tile label="Audit chain" detail={<DetailText text={chain.detail} />}>
        <span className={`metric-value ${CHIP_TEXT[chain.tone]}`}>{chain.value}</span>
      </Tile>
    </>
  );

  // The two scope/infra tiles — readiness (the fail-closed hinge) and catalog
  // scope. Secondary to the decision flow; disclosed, not dropped, in compact.
  const secondaryTiles = (
    <>
      <Tile label="Readiness" detail={<DetailText text={readiness.detail} />}>
        <span className={`metric-value ${CHIP_TEXT[readiness.tone]}`}>{readiness.value}</span>
      </Tile>

      <Tile label="Catalog skills" detail={<DetailText text={compartmentDetail} />}>
        <Value value={gateway.catalog.length} />
      </Tile>
    </>
  );

  if (compact) {
    return (
      <div className="shrink-0 space-y-2.5">
        <section aria-label="Gateway telemetry" className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {decisionTiles}
        </section>
        <details className="group">
          <summary className="eyebrow flex cursor-pointer list-none items-center gap-1.5 py-0.5 text-slate-500 transition-colors hover:text-slate-400">
            <ChevronRight
              size={13}
              className="shrink-0 transition-transform group-open:rotate-90"
              aria-hidden="true"
            />
            Readiness &amp; catalog
          </summary>
          <section
            aria-label="Gateway readiness and catalog scope"
            className="mt-2.5 grid grid-cols-2 gap-3"
          >
            {secondaryTiles}
          </section>
        </details>
      </div>
    );
  }

  return (
    <section
      aria-label="Gateway telemetry"
      className="grid shrink-0 grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-6"
    >
      {decisionTiles}
      {secondaryTiles}
    </section>
  );
}
