import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  RefreshCw,
  DownloadCloud,
  ShieldCheck,
  BadgeCheck,
  AlertTriangle,
  CheckCircle2,
  KeyRound,
  Loader2,
  PlugZap,
  Users,
  Radio,
  Gauge,
  Camera,
  Waypoints,
  BellRing,
  ListChecks,
  ChevronRight,
} from 'lucide-react';
import { Panel, PanelHeader, Badge, EmptyState } from '../ui';
import type { GatewayLive } from '../../lib/useGatewayLive';
import type { DeploymentStats, FeaturesInfo } from '../../lib/api';
import {
  deriveUpdateStatus,
  howToApply,
  clearDismissal,
  readDismissedKey,
  isDismissed,
  type UpdateStatus,
} from '../../lib/updateStatus';

/** Deep-link to Gateway → Connection (the standard offline-empty-state CTA). */
function navigateToConnection(): void {
  window.dispatchEvent(
    new CustomEvent('mcpip:navigate', { detail: { view: 'gateway', subtab: 'connection' } }),
  );
}

/**
 * Software Updates & License — the operator's provenance and entitlement view.
 *
 * The update surface is a NOTIFIER, never an installer. MCPIP is a Tier-1 zero-trust
 * appliance: it does not download or execute new code. "Check for updates" compares
 * three honest signals — this console's own build version (baked in at build time),
 * the connected gateway's running version, and the signed release manifest — and
 * tells the operator when a signed redeploy is due. It never applies one.
 */

/** A clean label→value row; the value is monospace only when it's a version/id. */
function Row({
  label,
  value,
  tone = 'ink',
  mono = true,
  badge,
}: {
  label: string;
  value: string;
  tone?: 'ink' | 'verified' | 'denied' | 'staged' | 'muted';
  mono?: boolean;
  badge?: React.ReactNode;
}): JSX.Element {
  const t =
    tone === 'verified' ? 'text-verified'
    : tone === 'denied' ? 'text-denied'
    : tone === 'staged' ? 'text-staged'
    : tone === 'muted' ? 'text-slate-400'
    : 'text-ink';
  return (
    <div className="flex items-center justify-between gap-3 border-b border-hairline/60 py-2.5 last:border-0">
      <span className="text-[11.5px] font-medium text-slate-500">{label}</span>
      <span className="flex items-center gap-2">
        {badge}
        <span className={`${mono ? 'font-mono text-[11.5px]' : 'text-[12px] font-medium'} ${t}`}>{value}</span>
      </span>
    </div>
  );
}

function daysUntil(iso: string): number | null {
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return Math.round((t - Date.now()) / 86_400_000);
}

/** The operator's control over the header update notice — shown only when there IS
 *  an update. If it was dismissed for this version, offer to re-enable it. */
function NotificationControl({
  status,
  dismissedKey,
  onChange,
}: {
  status: UpdateStatus;
  dismissedKey: string | null;
  onChange: () => void;
}): JSX.Element | null {
  if (status.severity !== 'update') return null;
  const dismissed = isDismissed(status, dismissedKey);
  return (
    <div className="mt-4 flex items-center justify-between gap-3 rounded-lg border border-hairline bg-canvas px-3.5 py-2.5">
      <div className="flex items-center gap-2">
        <BellRing size={13} className={dismissed ? 'text-slate-400' : 'text-staged'} />
        <span className="text-[11.5px] text-slate-500">
          {dismissed
            ? 'Header notice dismissed for this version.'
            : 'Header notice is showing for this update.'}
        </span>
      </div>
      {dismissed ? (
        <button
          type="button"
          onClick={() => {
            clearDismissal();
            onChange();
          }}
          className="btn-ghost !px-2.5 !py-1 !text-[11.5px]"
        >
          Notify me again
        </button>
      ) : null}
    </div>
  );
}

function UpdatePanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const consoleV = __APP_VERSION__;
  const [checking, setChecking] = useState(false);
  const [checkedAt, setCheckedAt] = useState<string | null>(null);
  const [dismissedKey, setDismissedKey] = useState<string | null>(() => readDismissedKey());

  const status = useMemo(() => deriveUpdateStatus(consoleV, gateway), [consoleV, gateway]);
  const ver = gateway.version;
  const steps = status.severity === 'update' ? howToApply(status) : [];

  const runCheck = async (): Promise<void> => {
    setChecking(true);
    try {
      await gateway.checkForUpdate();
      setCheckedAt(new Date().toLocaleTimeString());
    } finally {
      setChecking(false);
    }
  };

  const banner =
    status.severity === 'update' ? 'border-staged/25 bg-staged/5'
    : status.severity === 'current' ? 'border-verified/25 bg-verified/5'
    : 'border-hairline bg-canvas';
  const BannerIcon =
    status.severity === 'update' ? AlertTriangle
    : status.severity === 'current' ? CheckCircle2
    : DownloadCloud;
  const bannerTone =
    status.severity === 'update' ? 'text-staged'
    : status.severity === 'current' ? 'text-verified'
    : 'text-slate-500';

  const releaseValue = ver?.release.version ?? '—';
  const releaseVerified = ver?.release.verified;

  return (
    <Panel className="h-full">
      <PanelHeader
        title="Software updates"
        icon={DownloadCloud}
        right={<Badge tone="muted">{ver?.channel ? `${ver.channel} channel` : 'notifier'}</Badge>}
      />

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
        <div className={`mb-4 flex items-start gap-3 rounded-lg border px-3.5 py-3 ${banner}`}>
          <BannerIcon size={16} className={`mt-0.5 shrink-0 ${bannerTone}`} />
          <div className="min-w-0">
            <p className={`text-[13px] font-semibold ${bannerTone}`}>{status.headline}</p>
            <p className="mt-0.5 text-[11.5px] leading-relaxed text-slate-500">{status.detail}</p>
          </div>
        </div>

        <Row label="Console build" value={consoleV} tone="verified" />
        <Row label="Connected gateway" value={ver?.running ?? '—'} tone={ver?.running ? 'ink' : 'muted'} />
        <Row
          label="Signed release"
          value={releaseValue}
          tone={releaseVerified === true ? 'verified' : releaseVerified === false ? 'denied' : 'ink'}
          badge={
            releaseVerified === true ? <Badge tone="verified"><ShieldCheck size={9} /> verified</Badge>
            : releaseVerified === false ? <Badge tone="denied"><AlertTriangle size={9} /> unverified</Badge>
            : ver?.release ? <Badge tone="muted">stated</Badge> : undefined
          }
        />
        <Row label="Update policy" value={ver?.update_policy ?? 'redeploy'} tone="staged" mono={false} />
        {ver?.release.signing_key_id ? <Row label="Signing key" value={ver.release.signing_key_id} /> : null}

        {/* How to apply — the operator's own signed redeploy, only when there's an update */}
        {steps.length > 0 ? (
          <div className="mt-4">
            <div className="mb-2 flex items-center gap-1.5">
              <ListChecks size={12} className="text-slate-500" />
              <span className="eyebrow">How to apply</span>
            </div>
            <ol className="space-y-1.5">
              {steps.map((step, i) => (
                <li key={i} className="flex gap-2 text-[11.5px] leading-relaxed text-slate-500">
                  <span className="mt-px flex h-4 w-4 shrink-0 items-center justify-center rounded-full border border-hairline bg-canvas font-mono text-[9px] text-slate-400">
                    {i + 1}
                  </span>
                  <span>{step}</span>
                </li>
              ))}
            </ol>
          </div>
        ) : null}

        {/* Notification control — the operator's full control over the header notice */}
        <NotificationControl
          status={status}
          dismissedKey={dismissedKey}
          onChange={() => setDismissedKey(readDismissedKey())}
        />
      </div>

      <div className="flex shrink-0 items-center justify-between border-t border-hairline px-5 py-3">
        <span className="text-[11px] text-slate-500">
          {checkedAt ? `Last checked ${checkedAt}` : 'Auto-checks while connected'}
        </span>
        <button
          type="button"
          onClick={() => void runCheck()}
          disabled={checking || gateway.mode !== 'live'}
          className="btn-ghost !py-1.5 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {checking ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
          {checking ? 'Checking…' : 'Check for updates'}
        </button>
      </div>

      <p className="flex shrink-0 items-start gap-1.5 border-t border-hairline px-5 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
        <ShieldCheck size={12} className="mt-px shrink-0 text-slate-500" />
        <span>
          MCPIP never auto-installs. Updates are immutable, signed artifacts applied by a{' '}
          <span className="text-ink">redeploy</span> — the console notifies; your change-control applies. No
          auto-updater, no remote code.
        </span>
      </p>
    </Panel>
  );
}

function LicensePanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const lic = gateway.license;
  const noDocument = !live || lic === null;
  const licensed = lic?.licensed === true;
  const days = lic?.expires_at ? daysUntil(lic.expires_at) : null;

  return (
    <Panel className="h-full">
      <PanelHeader
        title="License & entitlements"
        icon={BadgeCheck}
        right={
          <Badge tone={licensed ? 'verified' : 'muted'}>
            {licensed ? lic?.tier ?? 'licensed' : !live ? 'no gateway' : lic === null ? 'unknown' : 'unlicensed'}
          </Badge>
        }
      />

      <div className="min-h-0 flex-1 overflow-y-auto">
        {noDocument ? (
          // Two honest absences: no gateway at all, vs a live gateway whose
          // JWT-gated /v1/license read failed for this console's identity.
          <EmptyState
            icon={BadgeCheck}
            title={live ? 'License unreadable' : 'No gateway connected'}
            detail={
              live
                ? 'The gateway is reachable but did not answer the /v1/license read for this console’s identity — the entitlement state is unknown, not "unlicensed".'
                : 'Connect to a gateway to read its boot-verified entitlement document.'
            }
            action={
              live ? undefined : (
                <button type="button" onClick={navigateToConnection} className="btn-primary">
                  <PlugZap size={13} /> Connect a gateway
                </button>
              )
            }
          />
        ) : !licensed ? (
          <div className="flex items-start gap-2.5 px-5 py-4 text-[11.5px] leading-relaxed text-slate-500">
            <ShieldCheck size={15} className="mt-px shrink-0 text-verified" />
            <span>
              Sandbox boot — no license configured. Set <span className="font-mono text-[10.5px] text-ink">MCPIP_LICENSE_PATH</span>{' '}
              and the license public key to enable the offline Ed25519 entitlement gate.
            </span>
          </div>
        ) : (
          <>
            <div className="px-5 py-4">
              <Row label="License id" value={lic?.license_id ?? '—'} />
              <Row label="Customer" value={lic?.customer ?? '—'} mono={false} />
              <Row label="Tier" value={lic?.tier ?? '—'} tone="verified" mono={false} />
              <Row label="Issued" value={lic?.issued_at?.slice(0, 10) ?? '—'} />
              <Row
                label="Expires"
                value={
                  lic?.expires_at
                    ? `${lic.expires_at.slice(0, 10)}${days != null ? ` · ${days}d left` : ''}`
                    : '—'
                }
                tone={days != null && days < 30 ? 'denied' : days != null && days < 90 ? 'staged' : 'ink'}
              />
            </div>
            {lic?.entitlements && lic.entitlements.length > 0 ? (
              <div className="border-t border-hairline px-5 py-3.5">
                <div className="mb-2 flex items-center gap-1.5">
                  <KeyRound size={11} className="text-slate-500" />
                  <span className="eyebrow">Entitlements</span>
                </div>
                <div className="flex flex-wrap gap-1.5">
                  {lic.entitlements.map((e) => (
                    <span
                      key={e}
                      className="rounded-md border border-hairline bg-canvas px-2 py-0.5 font-mono text-[10.5px] text-slate-400"
                    >
                      {e}
                    </span>
                  ))}
                </div>
              </div>
            ) : null}
          </>
        )}
      </div>

      <p className="flex shrink-0 items-start gap-1.5 border-t border-hairline px-5 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
        <BadgeCheck size={12} className="mt-px shrink-0 text-slate-500" />
        <span>
          Licensing gates process <span className="text-ink">boot only</span> — never the per-request
          authorization pipeline. Verified offline against the signed document; air-gapped enclaves validate
          exactly like connected deployments.
        </span>
      </p>
    </Panel>
  );
}

type StatsState =
  | { phase: 'loading' }
  | { phase: 'unavailable' }
  | { phase: 'ok'; stats: DeploymentStats };

/** A large headline number with a caption — the governed-agent value metric. */
function BigStat({
  label,
  value,
  tone = 'ink',
}: {
  label: string;
  value: string;
  tone?: 'ink' | 'verified' | 'denied' | 'staged';
}): JSX.Element {
  const t =
    tone === 'verified' ? 'text-verified'
    : tone === 'denied' ? 'text-denied'
    : tone === 'staged' ? 'text-staged'
    : 'text-ink';
  return (
    <div className="rounded-lg border border-hairline bg-canvas px-3.5 py-3">
      <div className={`font-mono text-[22px] font-semibold leading-none ${t}`}>{value}</div>
      <div className="mt-1.5 text-[10.5px] font-medium text-slate-500">{label}</div>
    </div>
  );
}

/** Human summary of the honest opt-in telemetry posture — never a fabricated "connected". */
function telemetrySummary(t: DeploymentStats['telemetry']): { tone: 'verified' | 'staged' | 'muted'; label: string; detail: string } {
  if (t.status === 'enabled') {
    const last =
      t.last_sent === null
        ? 'no beacon sent yet'
        : `last beacon ${new Date(t.last_sent * 1000).toLocaleString()} (${t.last_result})`;
    return { tone: 'verified', label: 'enabled', detail: `Opt-in beacon is live — ${last}. Only aggregate integers leave the box.` };
  }
  if (t.status === 'air-gap') {
    return {
      tone: 'muted',
      label: 'air-gap',
      detail: 'Sandbox / air-gapped — the beacon is structurally disabled and no install identity was ever minted. This deployment never phones home.',
    };
  }
  return { tone: 'muted', label: 'disabled', detail: 'Opt-out (default) — no beacon is scheduled. Set MCPIP_TELEMETRY_ENABLED + MCPIP_TELEMETRY_URL to opt in.' };
}

/** Honest forensic-capture posture summary for the deployment panel — mirrors the
 * telemetry row. NEVER fabricates a "live" state: the server-supplied `detail` explains
 * WHY it is off and how to enable it. `undefined` features (a gateway predating the
 * block) reads as an honest unknown posture, not a guessed one. */
function forensicSummary(f: FeaturesInfo['forensic_capture'] | undefined): {
  tone: 'verified' | 'muted';
  label: string;
  detail: string;
} {
  if (!f) {
    return { tone: 'muted', label: 'unknown', detail: 'This gateway does not report forensic-capture posture.' };
  }
  if (f.status === 'enabled') {
    return { tone: 'verified', label: 'enabled', detail: f.detail };
  }
  const label = f.status === 'absent' ? 'absent' : 'disabled';
  return { tone: 'muted', label, detail: f.detail };
}

/** Honest outbound external-PDP posture summary. `enforcing` reads as a live control;
 * `staged`/`off` are muted with the server's own explanation. No URL is ever shown. */
function externalPdpSummary(p: FeaturesInfo['external_pdp'] | undefined): {
  tone: 'verified' | 'staged' | 'muted';
  label: string;
  detail: string;
} {
  if (!p) {
    return { tone: 'muted', label: 'unknown', detail: 'This gateway does not report external-PDP posture.' };
  }
  if (p.status === 'enforcing') {
    return { tone: 'verified', label: 'enforcing', detail: p.detail };
  }
  if (p.status === 'staged') {
    return { tone: 'staged', label: 'staged', detail: p.detail };
  }
  return { tone: 'muted', label: 'off', detail: p.detail };
}

/**
 * Deployment / License & Usage — the LOCAL live-stats panel over GET /v1/admin/stats.
 *
 * The client-side "see the numbers live" surface: the operator's OWN tenant's REAL
 * governed-agent identity CARDINALITY (the per-agent value metric), decision totals,
 * license posture, and the HONEST opt-in vendor-telemetry state — served locally, no
 * beacon, no vendor, no network. Every state is honest: loading, an offline/unauthorized
 * empty state, or REAL numbers (a fresh tenant shows zeros). It NEVER fabricates a
 * client, number, license, or "connected" telemetry activity.
 */
function DeploymentUsagePanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { fetchDeploymentStats } = gateway;
  const live = gateway.mode === 'live';
  const [state, setState] = useState<StatsState>({ phase: 'loading' });

  const load = useCallback(
    async (signal?: AbortSignal): Promise<void> => {
      setState({ phase: 'loading' });
      const stats = await fetchDeploymentStats(signal);
      if (signal?.aborted) return;
      setState(stats === null ? { phase: 'unavailable' } : { phase: 'ok', stats });
    },
    [fetchDeploymentStats],
  );

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);

  const stats = state.phase === 'ok' ? state.stats : null;
  const tel = stats ? telemetrySummary(stats.telemetry) : null;
  const forensic = stats ? forensicSummary(stats.features?.forensic_capture) : null;
  const pdp = stats ? externalPdpSummary(stats.features?.external_pdp) : null;

  return (
    <Panel className="shrink-0">
      <PanelHeader
        title="Usage · this deployment"
        icon={Gauge}
        right={
          <div className="flex items-center gap-2">
            <span className="text-[10.5px] text-slate-500">local · no beacon needed</span>
            <button
              type="button"
              onClick={() => void load()}
              disabled={state.phase === 'loading'}
              className="btn-ghost !px-1.5 !py-1"
              title="Re-read /v1/admin/stats"
            >
              {state.phase === 'loading' ? (
                <Loader2 size={12} className="animate-spin" />
              ) : (
                <RefreshCw size={12} />
              )}
            </button>
          </div>
        }
      />

      <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
        {state.phase === 'loading' ? (
          <div className="flex items-center gap-2 py-6 text-[12px] text-slate-500">
            <Loader2 size={14} className="animate-spin" /> Reading live deployment stats…
          </div>
        ) : state.phase === 'unavailable' || stats === null ? (
          <EmptyState
            icon={Gauge}
            title={live ? 'Stats unreadable' : 'No gateway connected'}
            detail={
              live
                ? 'The gateway is reachable but did not answer the CAP_DIRECTORY_ADMIN /v1/admin/stats read for this console’s identity. No numbers are shown rather than a fabricated one.'
                : 'Connect to a gateway to read its own-tenant live governed-agent count, decision totals, license posture, and telemetry state.'
            }
            action={
              live ? undefined : (
                <button type="button" onClick={navigateToConnection} className="btn-primary">
                  <PlugZap size={13} /> Connect a gateway
                </button>
              )
            }
          />
        ) : (
          <>
            <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
              <BigStat label="Governed agent identities" value={String(stats.governed_agent_identity_count)} tone="ink" />
              <BigStat label="Allowed" value={String(stats.decisions.allow)} tone="verified" />
              <BigStat label="Denied" value={String(stats.decisions.deny)} tone="denied" />
              <BigStat label="Staged (PIN)" value={String(stats.decisions.staged)} tone="staged" />
            </div>

            {/* License + version are shown once, in the Version & License card
                below — this panel is now usage + security posture only. */}
            <div className="mt-4">
              <Row
                label="Vendor telemetry"
                value={tel!.label}
                tone={tel!.tone === 'verified' ? 'verified' : 'muted'}
                mono={false}
                badge={<Radio size={12} className={tel!.tone === 'verified' ? 'text-verified' : 'text-slate-400'} />}
              />
              <Row
                label="Forensic capture"
                value={forensic!.label}
                tone={forensic!.tone === 'verified' ? 'verified' : 'muted'}
                mono={false}
                badge={<Camera size={12} className={forensic!.tone === 'verified' ? 'text-verified' : 'text-slate-400'} />}
              />
              <Row
                label="Outbound PDP consult"
                value={pdp!.label}
                tone={pdp!.tone === 'verified' ? 'verified' : pdp!.tone === 'staged' ? 'staged' : 'muted'}
                mono={false}
                badge={<Waypoints size={12} className={pdp!.tone === 'verified' ? 'text-verified' : pdp!.tone === 'staged' ? 'text-staged' : 'text-slate-400'} />}
              />

              {/* The long "why it's off / how to enable" prose for forensic + PDP
                  is reference material — one disclosure keeps the panel glanceable. */}
              <details className="group mt-2.5">
                <summary className="flex cursor-pointer list-none items-center gap-1.5 text-[10.5px] font-medium text-slate-500 hover:text-ink">
                  <ChevronRight size={12} className="shrink-0 transition-transform group-open:rotate-90" />
                  Posture details
                </summary>
                <div className="mt-2 space-y-1.5">
                  <p className="flex items-start gap-1.5 text-[10.5px] leading-relaxed text-slate-500">
                    <Camera size={12} className="mt-px shrink-0 text-slate-500" />
                    <span>{forensic!.detail}</span>
                  </p>
                  <p className="flex items-start gap-1.5 text-[10.5px] leading-relaxed text-slate-500">
                    <Waypoints size={12} className="mt-px shrink-0 text-slate-500" />
                    <span>{pdp!.detail}</span>
                  </p>
                </div>
              </details>
            </div>

            <p className="mt-3 flex items-start gap-1.5 text-[10.5px] leading-relaxed text-slate-500">
              <Users size={12} className="mt-px shrink-0 text-slate-500" />
              <span>
                The governed-agent count is a <span className="text-ink">cardinality</span> (a HyperLogLog
                PFCOUNT) — the agent ids themselves are never stored or exposed. {tel!.detail}
              </span>
            </p>
          </>
        )}
      </div>

      <p className="flex shrink-0 items-start gap-1.5 border-t border-hairline px-5 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
        <ShieldCheck size={12} className="mt-px shrink-0 text-slate-500" />
        <span>
          These are this deployment’s OWN-tenant numbers, read locally. No tenant/agent/alias/target
          crosses this boundary — only aggregate integers. The opt-in beacon (when enabled) reports the
          same shape to the vendor; an <span className="text-ink">air-gapped</span> deployment never phones home.
        </span>
      </p>
    </Panel>
  );
}

/**
 * Software updates — an independent surface. The update NOTIFIER stands alone:
 * a gateway's software version and "a newer signed release exists" verdict have
 * nothing to do with the entitlement document, so they are no longer stacked
 * with it. Reached via Gateway → Updates.
 */
export function SoftwareUpdatesView({ gateway }: { gateway: GatewayLive }): JSX.Element {
  return (
    <div className="flex h-full flex-col overflow-y-auto">
      <UpdatePanel gateway={gateway} />
    </div>
  );
}

/**
 * License & usage — the entitlement document plus this deployment's own-tenant
 * usage (the governed-agent cardinality IS the per-agent value metric measured
 * against that license, so the two belong together). Reached via Gateway → License.
 */
export function LicenseUsageView({ gateway }: { gateway: GatewayLive }): JSX.Element {
  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto">
      <DeploymentUsagePanel gateway={gateway} />
      <LicensePanel gateway={gateway} />
    </div>
  );
}
