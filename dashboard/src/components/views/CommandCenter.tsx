import { PlugZap, Unplug } from 'lucide-react';
import { AuthorizeProbe } from '../AuthorizeProbe';
import { MetricsGrid } from '../MetricsGrid';
import { StreamPanel } from '../StreamPanel';
import { EmptyState, Panel } from '../ui';
import type { GatewayLive } from '../../lib/useGatewayLive';

/* ---------------------------------------------------------------------------
   Command Center — the landing view, honest and essential:

     • overview — the Live landing: a trimmed KPI wall (MetricsGrid compact:
       the four decision-flow tiles off the /metrics scrape + audit verify,
       readiness/catalog disclosed) ABOVE the live decision tail at full width
       in master-detail mode (row → inspector with every projected WORM field).
       The deny-reason composition lives in Analytics, not doubled here.
     • probe    — the live /v1/authorize instrument, the console's only
       invented-data-free latency source.

   Offline is the standard honest empty state with a connect CTA — no tile
   wall of fabricated zeros, no mock rows, ever.
--------------------------------------------------------------------------- */

function navigateToConnection(): void {
  window.dispatchEvent(
    new CustomEvent('mcpip:navigate', { detail: { view: 'gateway', subtab: 'connection' } }),
  );
}

function OfflineOverview(): JSX.Element {
  return (
    <Panel className="h-full">
      <EmptyState
        icon={Unplug}
        title="No gateway connected"
        detail="The Command Center renders only real telemetry — the /metrics scrape, the decision feed and /readyz. Nothing is fabricated offline."
        action={
          <button type="button" onClick={navigateToConnection} className="btn-primary">
            <PlugZap size={13} /> Connect a gateway
          </button>
        }
      />
    </Panel>
  );
}

export function CommandCenter({
  gateway,
  subtab,
}: {
  gateway: GatewayLive;
  subtab: string;
}): JSX.Element {
  const live = gateway.mode === 'live';

  if (subtab === 'probe') {
    return <AuthorizeProbe gateway={gateway} />;
  }

  // 'overview' — the Live landing.
  if (!live) {
    return <OfflineOverview />;
  }

  return (
    <div className="flex h-full flex-col gap-4">
      <MetricsGrid gateway={gateway} compact />
      {/* The full-width decision tail — the feed that was its own sub-tab now
          lives here in master-detail mode: click a row to pin its WORM
          projection in the inspector. */}
      <div className="min-h-0 flex-1">
        <StreamPanel events={gateway.stream} live inspect />
      </div>
    </div>
  );
}
