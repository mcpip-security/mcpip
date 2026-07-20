import { useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Activity, ChevronRight, Layers } from 'lucide-react';
import { Badge, Detail, Panel, PanelHeader } from './ui';
import { prefersReducedMotion } from '../lib/format';
import type { GatewayLive } from '../lib/useGatewayLive';

/* ---------------------------------------------------------------------------
   Gateway → Health — the incident-triage page, built ONLY from signals the
   gateway actually emits:

     • Availability — the session's REAL probe ring (useGatewayLive records one
       {live, redis} tick per /healthz probe ≈ every 4 s; nothing is backfilled
       or invented). Before ticks accumulate the page says so instead of
       drawing a history it never observed.
     • Pipeline subsystems — one row per stage with its real signal (/readyz,
       /v1/audit/verify, /v1/catalog, deny events attributed from the live
       feed) and an honest "no signal" state for the stages the gateway does
       not report (jwks keyring, mainframe adapter) — never a defaulted green.
       The audit/WORM row absorbs the old Infrastructure tab's one real datum:
       first_bad_epoch from /v1/audit/verify, as an expanded detail.

   The fabricated 60-minute availability graph, the per-stage invented tick
   bars, the hardcoded AOF durability claim and the decorative heartbeat are
   gone. Latency shown here is the gateway's OWN p50/p95 (the /metrics
   histogram — all agents' traffic), never a console-side estimate.
--------------------------------------------------------------------------- */

/** House curve — slow, expensive, never bouncy. */
const EASE = [0.32, 0.72, 0, 1] as const;

type SubsystemState = 'operational' | 'failed' | 'no_signal';

const STATE_BADGE: Record<SubsystemState, { label: string; tone: 'verified' | 'denied' | 'muted' }> = {
  operational: { label: 'operational', tone: 'verified' },
  failed: { label: 'failed', tone: 'denied' },
  no_signal: { label: 'no signal', tone: 'muted' },
};

type EventSeverity = 'deny' | 'warn';

/** One REAL observed event (a WORM deny row, or the current /readyz outage). */
interface UnusualEvent {
  at: string;
  severity: EventSeverity;
  code: string;
  detail: string;
}

/** Static architecture facts about one pipeline stage — never fabricated telemetry. */
interface SubsystemMeta {
  name: string;
  role: string;
  /** What this stage enforces (shown until a live signal overlays it). */
  note: string;
  /** The REAL signal this row's state derives from; 'none' rows can only ever say "no signal". */
  source: string;
}

interface Subsystem extends SubsystemMeta {
  state: SubsystemState;
  events: UnusualEvent[];
}

const SUBSYSTEM_META: SubsystemMeta[] = [
  { name: 'bridge', role: 'ingress · schema enforcement', note: 'deep-strict · extra=forbid', source: '/healthz · serving process' },
  { name: 'obfuscator', role: 'alias registry · tenant scoping', note: 'aliases resolve in-memory', source: '/v1/catalog' },
  { name: 'auth / pin store', role: 'redis · atomic consume-and-compare', note: 'lua single-round-trip', source: '/readyz · redis' },
  { name: 'audit / worm', role: 'hash chain · Ed25519 signer', note: 'emit before dispatch', source: '/v1/audit/verify · /metrics worm gauges' },
  { name: 'jwks keyring', role: 'issuer keys · rotation watch', note: 'EdDSA · multi-issuer', source: 'none — not reported by the gateway' },
  { name: 'mainframe adapter', role: 'legacy transport · CICS / DB2', note: 'copybook encoder', source: 'none — transport_error denies only' },
];

/** Which pipeline stage produced a given WORM deny reason. */
const REASON_SUBSYSTEM: Record<string, string> = {
  identity_injection: 'bridge',
  unknown_format: 'bridge',
  schema_violation: 'bridge',
  depth_exceeded: 'bridge',
  size_exceeded: 'bridge',
  illegal_character: 'bridge',
  unknown_alias: 'obfuscator',
  cross_tenant: 'obfuscator',
  compartment_denied: 'obfuscator',
  capability_denied: 'obfuscator',
  jwt_invalid: 'auth / pin store',
  jwt_claims_missing: 'auth / pin store',
  pin_required: 'auth / pin store',
  pin_not_found: 'auth / pin store',
  pin_mismatch: 'auth / pin store',
  payload_mismatch: 'auth / pin store',
  lock_error: 'auth / pin store',
  transport_error: 'mainframe adapter',
};

function fmtAt(ts: number): string {
  const d = new Date(ts);
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** Compact duration for the observed-window fact: "42s", "6m 04s". */
function fmtSpan(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) {
    return `${s}s`;
  }
  return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
}

/**
 * Build the subsystem rows from REAL gateway signals only. Live states:
 * bridge/obfuscator ride the answering process (an in-process stage on the
 * /healthz path is serving iff the process is), auth rides /readyz redis,
 * audit rides /v1/audit/verify. jwks keyring and the mainframe adapter have
 * NO reporting endpoint, so they stay "no signal" — the console does not
 * default anything to green. Offline: every row is "no signal", no events.
 */
function buildSubsystems(gateway: GatewayLive): Subsystem[] {
  if (gateway.mode !== 'live') {
    return SUBSYSTEM_META.map((m) => ({ ...m, state: 'no_signal' as SubsystemState, events: [] }));
  }

  // Real deny events from the live stream, attributed to the stage that raised them.
  const eventsByStage = new Map<string, UnusualEvent[]>();
  for (const e of gateway.stream) {
    if (e.decision !== 'deny' || !e.reason) continue;
    const stage = REASON_SUBSYSTEM[e.reason];
    if (!stage) continue;
    const list = eventsByStage.get(stage) ?? [];
    if (list.length >= 6) continue; // keep the panel scannable
    list.push({
      at: fmtAt(e.ts),
      severity: 'deny',
      code: e.reason.toUpperCase(),
      detail: `${e.alias} · ${e.tenant} · correlation ${e.correlationId.slice(0, 12)}…`,
    });
    eventsByStage.set(stage, list);
  }

  return SUBSYSTEM_META.map((m) => {
    let state: SubsystemState = 'no_signal';
    let note = m.note;
    const events = eventsByStage.get(m.name) ?? [];

    if (m.name === 'bridge' || m.name === 'obfuscator') {
      // In-process stages on the answering /healthz path — serving iff the process is.
      state = 'operational';
      if (m.name === 'obfuscator' && gateway.catalog.length > 0) {
        note = `${gateway.catalog.length} aliases · live /v1/catalog`;
      }
    }
    if (m.name === 'auth / pin store') {
      if (gateway.ready === null) {
        note = 'no /readyz signal yet';
      } else if (gateway.ready.redis === 'up') {
        state = 'operational';
        note = 'redis up · lua single-round-trip';
      } else {
        state = 'failed';
        note = 'redis DOWN — failing closed';
        events.unshift({
          at: fmtAt(Date.now()),
          severity: 'warn',
          code: 'REDIS_DOWN',
          detail: 'sync-state store unreachable — decisions fail closed until it returns',
        });
      }
    }
    if (m.name === 'audit / worm') {
      const seq = gateway.metrics.wormSequence;
      if (gateway.audit === null) {
        note = 'no verify signal — external verifier in production';
      } else if (gateway.audit.intact) {
        state = 'operational';
        note = `verify_chain() INTACT${seq !== null ? ` · seq #${seq.toLocaleString('en-US')}` : ''}`;
      } else {
        state = 'failed';
        note = `verify_chain() FAILED @ epoch ${gateway.audit.first_bad_epoch ?? '?'}`;
      }
    }

    return { ...m, state, note, events };
  });
}

const SEVERITY_STYLES: Record<EventSeverity, { dot: string; label: string }> = {
  deny: { dot: 'bg-denied', label: 'text-denied' },
  warn: { dot: 'bg-staged', label: 'text-staged' },
};

/* --- Availability (the REAL probe ring) ------------------------------------ */

type FactTone = 'ink' | 'denied' | 'muted';

/** One cell in the availability facts strip — same language as Connection. */
function Fact({ label, value, tone = 'ink' }: { label: string; value: string; tone?: FactTone }): JSX.Element {
  const t = tone === 'denied' ? 'text-denied' : tone === 'muted' ? 'text-slate-400' : 'text-ink';
  return (
    <div className="flex min-w-0 flex-col gap-1.5 bg-surface px-4 py-3">
      <p className="eyebrow">{label}</p>
      <p className={`tabular truncate text-[14px] font-semibold tracking-tightest ${t}`}>{value}</p>
    </div>
  );
}

interface Tick {
  t: number;
  /** true up · false down · null no reading at that tick. */
  ok: boolean | null;
}

/**
 * One recorded-probe bar row. Every bar is one REAL tick; newest on the right.
 * Bars flex between 3–6px so the ring fills whatever column width it gets;
 * when the ring outgrows the row width the oldest ticks clip on the left —
 * the summary always counts the full recorded window.
 */
function TickRow({ label, endpoint, ticks }: { label: string; endpoint: string; ticks: Tick[] }): JSX.Element {
  const known = ticks.filter((x) => x.ok !== null);
  const up = known.filter((x) => x.ok === true).length;
  const summary =
    known.length === 0
      ? 'no readings yet'
      : `${((up / known.length) * 100).toFixed(1)}% up · ${known.length} of ${ticks.length} ticks`;
  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between gap-3">
        <p className="flex min-w-0 items-baseline gap-2">
          <span className="text-[11px] font-medium text-ink">{label}</span>
          <span className="truncate font-mono text-[10.5px] text-slate-500">{endpoint}</span>
        </p>
        <span className="tabular shrink-0 font-mono text-[10.5px] text-slate-500">{summary}</span>
      </div>
      <div className="flex justify-end gap-[2px] overflow-hidden" aria-hidden="true">
        {ticks.map((tick) => (
          <span
            key={tick.t}
            title={`${fmtAt(tick.t)} · ${tick.ok === null ? 'no reading' : tick.ok ? 'up' : 'down'}`}
            className={`h-3.5 min-w-[3px] max-w-[6px] flex-1 rounded-full ${
              tick.ok === null ? 'bg-ink/10' : tick.ok ? 'bg-ink/25' : 'bg-denied'
            }`}
          />
        ))}
      </div>
    </div>
  );
}

function AvailabilityPanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const history = gateway.healthHistory;
  const first = history.length > 0 ? history[0] : undefined;
  const last = history.length > 0 ? history[history.length - 1] : undefined;
  const liveCount = history.filter((t) => t.live).length;
  const m = gateway.metrics;

  const windowValue = first && last ? fmtSpan(last.t - first.t) : '—';
  const uptimeValue = history.length > 0 ? `${((liveCount / history.length) * 100).toFixed(1)}%` : '—';
  const uptimeTone: FactTone = history.length === 0 ? 'muted' : last && !last.live ? 'denied' : 'ink';

  return (
    <Panel className="h-full">
      <PanelHeader
        title="Availability"
        icon={Activity}
        right={
          <span className="tabular font-mono">
            {live ? `live · ${gateway.apiHost}${gateway.health?.loop ? ` · loop=${gateway.health.loop}` : ''}` : 'no node connected'}
          </span>
        }
      />

      <div className="min-h-0 flex-1 overflow-y-auto">
        {/* Facts — the observed probe ring; the gateway's OWN latency histogram is one row down. */}
        <div className="grid grid-cols-2 gap-px border-b border-hairline bg-hairline">
          <Fact label="Observed window" value={windowValue} tone={first ? 'ink' : 'muted'} />
          <Fact label="Probes answered" value={uptimeValue} tone={uptimeTone} />
        </div>

        {/* Gateway-measured latency (all agents' traffic) — demoted behind a disclosure. */}
        <details className="group border-b border-hairline">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-2.5 [&::-webkit-details-marker]:hidden">
            <span className="flex min-w-0 items-center gap-2">
              <ChevronRight size={13} className="shrink-0 text-slate-400 transition-transform group-open:rotate-90" />
              <span className="eyebrow">Gateway-measured latency</span>
            </span>
            <span className="tabular shrink-0 font-mono text-[10.5px] text-slate-500">
              p50 {m.gatewayP50Ms !== null ? `${m.gatewayP50Ms.toFixed(1)}ms` : '—'} · p95 {m.gatewayP95Ms !== null ? `${m.gatewayP95Ms.toFixed(1)}ms` : '—'}
            </span>
          </summary>
          <div className="grid grid-cols-2 gap-px border-t border-hairline bg-hairline">
            <Fact label="p50 · gateway-measured" value={m.gatewayP50Ms !== null ? `${m.gatewayP50Ms.toFixed(1)} ms` : '—'} tone={m.gatewayP50Ms !== null ? 'ink' : 'muted'} />
            <Fact label="p95 · gateway-measured" value={m.gatewayP95Ms !== null ? `${m.gatewayP95Ms.toFixed(1)} ms` : '—'} tone={m.gatewayP95Ms !== null ? 'ink' : 'muted'} />
          </div>
        </details>

        {history.length === 0 ? (
          <p className="px-6 py-8 text-center text-[11.5px] leading-relaxed text-slate-500">
            No probe ticks recorded yet — the console logs one availability tick per{' '}
            <span className="font-mono text-[10.5px]">/healthz</span> probe (about every 4 s) from the moment it
            opens. Nothing is backfilled.
          </p>
        ) : (
          <div className="space-y-4 px-5 py-4">
            <TickRow label="Gateway" endpoint="/healthz" ticks={history.map((t) => ({ t: t.t, ok: t.live }))} />
            <TickRow label="Redis" endpoint="/readyz" ticks={history.map((t) => ({ t: t.t, ok: t.redis }))} />
          </div>
        )}
      </div>

      <p className="shrink-0 border-t border-hairline px-5 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
        Session-scoped record of this console&apos;s own probes — one tick per round-trip, newest on the right,
        never backfilled. The Redis row reads the <span className="font-mono">/readyz</span> verdict current at
        each tick.
      </p>
    </Panel>
  );
}

/* --- Pipeline subsystems ----------------------------------------------------- */

function Chevron({ open }: { open: boolean }): JSX.Element {
  return (
    <svg
      viewBox="0 0 10 10"
      className={`h-2.5 w-2.5 shrink-0 text-slate-400 transition-transform duration-300 ${
        open ? 'rotate-90' : ''
      }`}
      aria-hidden="true"
    >
      <path d="M3 1.5 6.5 5 3 8.5" fill="none" stroke="currentColor" strokeWidth="1.4" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function EventRows({ events, name, live }: { events: UnusualEvent[]; name: string; live: boolean }): JSX.Element {
  if (events.length === 0) {
    return (
      <p className="pt-1 font-mono text-[11px] text-slate-400">
        {live ? 'no unusual events in the live window' : 'connect a gateway to stream real events — none are fabricated offline'}
      </p>
    );
  }
  return (
    <ul className="space-y-0 pt-1" aria-label={`Unusual events for ${name}`}>
      {events.map((e, i) => {
        const sev = SEVERITY_STYLES[e.severity];
        return (
          <li
            key={`${e.at}-${e.code}-${i}`}
            className="grid grid-cols-[auto_auto_1fr] items-baseline gap-x-3 border-l border-hairline py-1.5 pl-4 sm:grid-cols-[64px_170px_1fr]"
          >
            <span className="tabular font-mono text-[11px] text-slate-400">{e.at}</span>
            <span className={`flex items-center gap-1.5 font-mono text-[11px] font-semibold ${sev.label}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${sev.dot}`} />
              {e.code}
            </span>
            <span className="col-span-3 break-all font-mono text-[10.5px] leading-relaxed text-slate-500 sm:col-span-1">
              {e.detail}
            </span>
          </li>
        );
      })}
    </ul>
  );
}

function SubsystemsPanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const [openRow, setOpenRow] = useState<string | null>(null);
  const reduced = prefersReducedMotion();
  const live = gateway.mode === 'live';
  const subsystems = buildSubsystems(gateway);
  const healthzHref = `${gateway.apiBase}/healthz`;

  // Stages the gateway exposes NO health signal for (jwks keyring, mainframe adapter)
  // collapse to a single muted line — but a stage that carried a real live event
  // (e.g. a transport_error deny) re-materializes as a full row so no deny evidence is lost.
  const collapsed = subsystems.filter((s) => s.source.startsWith('none') && s.events.length === 0);
  const shown = subsystems.filter((s) => !collapsed.includes(s));

  return (
    <Panel className="h-full">
      <PanelHeader
        title="Pipeline subsystems"
        icon={Layers}
        right={live ? 'live signals per stage' : 'no node connected'}
      />

      <div className="min-h-0 flex-1 divide-y divide-hairline/60 overflow-y-auto">
        {shown.map((s) => {
          const open = openRow === s.name;
          const eventCount = s.events.length;
          const badge = STATE_BADGE[s.state];
          return (
            <div key={s.name}>
              <button
                type="button"
                onClick={() => setOpenRow(open ? null : s.name)}
                aria-expanded={open}
                className={`grid w-full grid-cols-[1fr_auto] items-center gap-x-4 gap-y-1 px-5 py-3 text-left transition-colors sm:grid-cols-[210px_1fr_auto] ${
                  open ? 'bg-canvas' : 'hover:bg-canvas'
                }`}
              >
                <div className="flex min-w-0 items-center gap-2.5">
                  <Chevron open={open} />
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[12px] font-semibold tracking-tight text-ink">
                      {s.name}
                      {eventCount > 0 ? (
                        <span className="tabular ml-2 font-mono text-[10px] font-normal text-slate-400">
                          {eventCount} event{eventCount > 1 ? 's' : ''}
                        </span>
                      ) : null}
                    </p>
                    <p className="mt-0.5 truncate text-[11px] text-slate-500">{s.role}</p>
                  </div>
                </div>
                <p className="hidden min-w-0 truncate font-mono text-[11px] text-slate-500 sm:block">{s.note}</p>
                <Badge tone={badge.tone}>{badge.label}</Badge>
              </button>
              <AnimatePresence initial={false}>
                {open ? (
                  <motion.div
                    key="detail"
                    initial={reduced ? false : { height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={reduced ? undefined : { height: 0, opacity: 0 }}
                    transition={{ duration: 0.3, ease: EASE }}
                    className="overflow-hidden bg-canvas"
                  >
                    <div className="border-t border-hairline/60 px-5 pb-4 pt-3.5">
                      <dl className="grid grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-4">
                        <Detail label="signal source" mono span>
                          {s.source}
                        </Detail>
                        {s.name === 'audit / worm' ? (
                          <>
                            <Detail
                              label="chain verify"
                              mono
                              tone={gateway.audit === null ? 'muted' : gateway.audit.intact ? 'verified' : 'denied'}
                            >
                              {gateway.audit === null ? 'no verdict' : gateway.audit.intact ? 'INTACT' : 'TAMPERED'}
                            </Detail>
                            <Detail label="worm height" mono>
                              {gateway.metrics.wormSequence !== null ? `#${gateway.metrics.wormSequence.toLocaleString('en-US')}` : '—'}
                            </Detail>
                            <Detail label="sealed epoch" mono>
                              {gateway.metrics.wormEpoch !== null ? String(gateway.metrics.wormEpoch) : '—'}
                            </Detail>
                            <Detail
                              label="first bad epoch"
                              mono
                              tone={gateway.audit?.first_bad_epoch != null ? 'denied' : 'ink'}
                            >
                              {gateway.audit?.first_bad_epoch != null ? String(gateway.audit.first_bad_epoch) : 'none'}
                            </Detail>
                          </>
                        ) : null}
                      </dl>
                      {s.state === 'no_signal' ? (
                        <p className="mt-3 text-[11px] leading-relaxed text-slate-500">
                          {live
                            ? 'The gateway exposes no health signal for this stage — the console reports none rather than defaulting to green.'
                            : 'No gateway connected — every stage is unreported until a node answers.'}
                        </p>
                      ) : null}
                      <div className="mt-3.5">
                        <p className="text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">
                          events · live window
                        </p>
                        <EventRows events={s.events} name={s.name} live={live} />
                      </div>
                    </div>
                  </motion.div>
                ) : null}
              </AnimatePresence>
            </div>
          );
        })}
        {collapsed.length > 0 ? (
          <p className="px-5 py-3 text-[11px] leading-relaxed text-slate-500">
            <span className="font-mono font-medium text-slate-400">
              {collapsed.length} stage{collapsed.length > 1 ? 's' : ''} not reported
            </span>{' '}
            by the gateway ({collapsed.map((s) => s.name).join(', ')}) — the console shows no signal rather than defaulting to green.
          </p>
        ) : null}
      </div>

      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-t border-hairline px-5 py-2.5">
        <p className="text-[10.5px] leading-relaxed text-slate-500">
          Fail-closed: any subsystem down &rarr; decisions deny, nothing commits.
        </p>
        <a
          href={healthzHref}
          className="font-mono text-[10.5px] text-slate-500 underline decoration-hairline underline-offset-4 transition-colors hover:text-ink"
        >
          {live ? `${gateway.apiHost}/healthz` : '/healthz'}
        </a>
      </div>
    </Panel>
  );
}

interface HealthPanelProps {
  gateway: GatewayLive;
}

export function HealthPanel({ gateway }: HealthPanelProps): JSX.Element {
  return (
    <div className="flex h-full flex-col">
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
        <AvailabilityPanel gateway={gateway} />
        <SubsystemsPanel gateway={gateway} />
      </div>
    </div>
  );
}
