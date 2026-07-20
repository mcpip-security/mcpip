import { Activity, ChevronRight, UserRound, Menu } from 'lucide-react';
import type { GatewayLive } from '../../lib/useGatewayLive';
import type { Section } from '../../lib/nav';
import { EnvironmentBadge } from './EnvironmentBadge';
import { ThemeToggle } from './ThemeToggle';
import { UpdateNotice } from './UpdateNotice';

/**
 * Fixed top header: contextual breadcrumb (left) and operational status (right).
 * Every readout is a REAL gateway field or an honest unknown — the health dot
 * (which clicks through to Gateway → Connection), an environment chip built
 * from the boot-verified license tier + the /healthz release (hidden entirely
 * when neither is known), the connected host, and the JWT-decoded tenant
 * (em-dash offline). Utilitarian; no marketing, nothing fabricated.
 */

type HealthState = 'down' | 'probing' | 'degraded' | 'healthy';

const HEALTH: Record<HealthState, { dot: string; text: string; label: string }> = {
  down: { dot: 'bg-denied', text: 'text-denied', label: 'Node unreachable' },
  probing: { dot: 'bg-slate-500', text: 'text-slate-500', label: 'Probing readiness' },
  degraded: { dot: 'bg-staged', text: 'text-staged', label: 'Redis degraded' },
  healthy: { dot: 'bg-verified', text: 'text-verified', label: 'Node healthy' },
};

/**
 * Green only when live AND /readyz confirmed Redis; a neutral "probing" state
 * while the first /readyz verdict is still pending (never claimed healthy);
 * amber when live but Redis is degraded; red when no gateway answers.
 */
function healthState(gateway: GatewayLive): HealthState {
  if (gateway.mode !== 'live') return 'down';
  if (gateway.ready === null) return 'probing';
  return gateway.ready.redis === 'up' ? 'healthy' : 'degraded';
}

function HealthDot({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const state = healthState(gateway);
  const { dot, text, label } = HEALTH[state];
  return (
    // The dot is the shell's path to recovery: it deep-links to the Connection
    // sub-tab so a red state is actionable from any screen.
    <button
      type="button"
      onClick={() =>
        window.dispatchEvent(
          new CustomEvent('mcpip:navigate', { detail: { view: 'gateway', subtab: 'connection' } }),
        )
      }
      title="Open Gateway → Connection"
      aria-label={`${label} — open gateway connection`}
      className="-mx-1.5 flex items-center gap-2 rounded-md px-1.5 py-1 transition-colors hover:bg-canvas focus:outline-none focus-visible:shadow-focus-ring"
    >
      <span className="relative flex h-2 w-2">
        <span
          className={`inline-flex h-2 w-2 rounded-full ${dot} ${state !== 'down' ? 'animate-blink' : ''}`}
        />
      </span>
      <span className={`hidden text-[11.5px] font-medium sm:inline ${text}`}>{label}</span>
    </button>
  );
}

export function TopHeader({
  item,
  subtabLabel,
  gateway,
  onOpenMobileNav,
}: {
  item: Section;
  subtabLabel: string;
  gateway: GatewayLive;
  onOpenMobileNav: () => void;
}): JSX.Element {
  const Icon = item.icon;
  // Environment readout — REAL fields only: license tier when a verified license
  // document declares one, and the running release from /healthz. No fabricated
  // "Production"/"Tier-1" labels; with neither field known, the chip is absent.
  const license = gateway.license;
  const tier = license !== null && license.licensed ? license.tier ?? null : null;
  const version = gateway.health?.version ?? null;
  return (
    <header className="sticky top-0 z-20 flex h-16 items-center justify-between gap-4 border-b border-hairline bg-surface/95 px-4 backdrop-blur md:px-6">
      {/* Breadcrumb / context */}
      <div className="flex min-w-0 items-center gap-2.5">
        <button
          type="button"
          onClick={onOpenMobileNav}
          aria-label="Open navigation"
          className="rounded-md border border-hairline p-1.5 text-slate-500 transition-colors hover:text-ink lg:hidden"
        >
          <Menu size={16} />
        </button>
        <Icon size={16} className="hidden shrink-0 text-slate-500 sm:block" />
        <span className="hidden text-[12.5px] font-medium text-slate-500 md:inline">MCPIP</span>
        <ChevronRight size={14} className="hidden text-slate-600 md:inline" />
        <h1 className="truncate text-[15px] font-semibold tracking-tightest text-ink">
          {item.label}
        </h1>
        <ChevronRight size={14} className="hidden shrink-0 text-slate-600 sm:inline" />
        <span className="hidden truncate text-[13px] text-slate-500 sm:inline">
          {subtabLabel}
        </span>
      </div>

      {/* Status cluster */}
      <div className="flex items-center gap-3 sm:gap-4">
        <HealthDot gateway={gateway} />

        {/* Global update-available notice — appears only when a newer signed
            release exists and the operator hasn't dismissed that version. */}
        <UpdateNotice gateway={gateway} />

        <ThemeToggle />

        {/* Build-edition badge — renders only for a non-production console, so a
            staging/internal build is unmistakable (nothing shown in production). */}
        <EnvironmentBadge />

        <span className="hidden h-4 w-px bg-hairline sm:block" />

        {tier !== null || version !== null ? (
          <div className="hidden items-center gap-2 rounded-lg border border-hairline bg-surface px-2.5 py-1 shadow-card md:flex">
            {tier !== null ? (
              <span className="text-[11.5px] font-medium text-ink">{tier}</span>
            ) : null}
            {tier !== null && version !== null ? <span className="h-3 w-px bg-hairline" /> : null}
            {version !== null ? (
              <span className="font-mono text-[11px] text-slate-500">v{version}</span>
            ) : null}
          </div>
        ) : null}

        <div className="hidden items-center gap-1.5 text-[11.5px] text-slate-500 lg:flex">
          <Activity size={12} className="text-slate-500" />
          <span className="font-mono text-[11px] text-slate-400">
            {gateway.mode === 'live' ? gateway.apiHost : 'offline'}
          </span>
        </div>

        <span className="hidden h-4 w-px bg-hairline sm:block" />

        <div className="flex items-center gap-2.5">
          <div className="flex h-8 w-8 items-center justify-center rounded-full border border-hairline bg-elevated">
            <UserRound size={15} className="text-slate-500" />
          </div>
          <div className="hidden leading-tight sm:block">
            <p className="text-[12.5px] font-semibold text-ink">Operator</p>
            <p className="font-mono text-[10px] text-slate-500">
              {gateway.tenant ?? '—'}
            </p>
          </div>
        </div>
      </div>
    </header>
  );
}
