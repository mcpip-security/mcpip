/* ---------------------------------------------------------------------------
   Skills & Access — govern what agents can call. Sub-tabs:
     • registry   — the live obfuscator catalog as a permission table (each
                    service listed once with Read/Write checkboxes over the
                    enable/disable kill-switch; register, deregister, per-alias
                    inspector) plus the per-team "view as" compartment filter;
                    canary decoys badged.
     • canaries   — the LIVE tripwire instrument: decoy roster, session trips,
                    per-agent quarantine state (all from real admin endpoints).
     • separation — the compartment-separation self-test over the operator's
                    own teams: real /v1/authorize probes + real feed evidence.
     • community  — the author-your-own-skill/gate workflow: a Contributor
                    submits an mcpip-extension/1 manifest, a CAP_CATALOG_REVIEWER
                    approves/rejects the tenant's PENDING queue (real endpoints).
   Each sub-tab owns its honest offline/degraded states — this is pure routing.
--------------------------------------------------------------------------- */

import { AliasRegistry } from '../AliasRegistry';
import { SeparationCheck } from '../SeparationCheck';
import { CanaryPanel } from './CanaryPanel';
import { CommunityExtensions } from './CommunityExtensions';
import type { GatewayLive } from '../../lib/useGatewayLive';

export function SkillsAccess({
  gateway,
  subtab,
}: {
  gateway: GatewayLive;
  subtab: string;
}): JSX.Element {
  if (subtab === 'canaries') {
    return <CanaryPanel gateway={gateway} />;
  }
  if (subtab === 'separation') {
    return <SeparationCheck gateway={gateway} />;
  }
  if (subtab === 'community') {
    return <CommunityExtensions gateway={gateway} />;
  }

  // 'registry'
  return (
    <div className="h-full">
      <AliasRegistry gateway={gateway} />
    </div>
  );
}
