/* ---------------------------------------------------------------------------
   Separation Check — a compartment-separation self-test over the OPERATOR'S
   OWN tenant (no fixed demo scenario).

   Pick two of your compartments; the check then does only real things:
     1. mints one throwaway probe identity per team (sandbox IdP),
     2. reads GET /v1/catalog under each — the gateway itself applies the
        compartment filter, so the row counts and the "not even enumerable"
        facts are the server's, not the console's,
     3. fires real POST /v1/authorize calls at each team's compartment-scoped
        alias from BOTH identities and renders the verdict matrix: own-team
        allow (or step-up), cross-team opaque deny.

   Every probe is WORM-logged; each cell links its correlation id, and a deny's
   concrete reason is only claimed when the live decision feed actually shows
   it (deny reasons never cross the agent wire — that is the product).

   In production the sandbox minter is not mounted: the check states the real
   requirement (mint per-team principals from your IdP) instead of simulating
   an outcome. Offline is the standard connect state. Nothing here is mocked.
--------------------------------------------------------------------------- */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Check,
  Copy,
  EyeOff,
  Inbox,
  Loader2,
  Play,
  PlugZap,
  ScrollText,
  SearchX,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
} from 'lucide-react';
import { authorize, catalog as fetchCatalog, mintDevToken } from '../lib/api';
import { useCompanyConfig } from '../lib/companyConfig';
import { compartmentSources } from './AliasRegistry';
import type { CompartmentSource } from './AliasRegistry';
import { formatClock, truncateId } from '../lib/format';
import { Badge, EmptyState, Field, Panel, PanelHeader, Select } from './ui';
import type { CatalogItem, RiskTier } from '../lib/types';
import type { GatewayLive } from '../lib/useGatewayLive';

/* --- run model --------------------------------------------------------------- */

type CellOutcome = 'allow' | 'staged' | 'deny' | 'error';

interface ProbeCell {
  callerUuid: string;
  ownerUuid: string;
  alias: string;
  outcome: CellOutcome;
  correlationId: string | null;
  /** True when the outcome matches the separation expectation for this pair. */
  expected: boolean;
}

interface ProbeTarget {
  alias: string;
  owner: CompartmentSource;
  risk: RiskTier;
  /** REAL cross-enumerability read: did the OTHER team's catalog list this alias? */
  enumerableFromOther: boolean;
}

interface SideView {
  source: CompartmentSource;
  agentId: string;
  /** Rows this identity could enumerate via its own live GET /v1/catalog. */
  enumerable: number;
}

type Run =
  | { phase: 'idle' }
  | { phase: 'running'; step: string }
  /** The sandbox identity minter is not mounted — production. */
  | { phase: 'unavailable' }
  | { phase: 'failed'; detail: string }
  | { phase: 'done'; a: SideView; b: SideView; targets: ProbeTarget[]; cells: ProbeCell[]; at: number };

/** A probe agent id derived from the team label (feed rows stay legible). */
function probeAgentId(source: CompartmentSource): string {
  const slug = source.label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return `agent-sepcheck-${slug || 'team'}`;
}

/** The team's compartment-scoped probe alias — prefer 'auto' so an in-compartment
    pass completes without a step-up ceremony (a 202 still proves the gate). */
function pickScoped(items: ReadonlyArray<CatalogItem>, uuid: string): CatalogItem | null {
  const scoped = items.filter((i) => i.compartment === uuid);
  return scoped.find((i) => i.risk_tier === 'auto') ?? scoped[0] ?? null;
}

/* --- small pieces ------------------------------------------------------------ */

function CopyCorr({ id }: { id: string }): JSX.Element {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      title={`copy correlation id · ${id}`}
      onClick={() => {
        try {
          void navigator.clipboard.writeText(id);
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        } catch {
          /* clipboard unavailable (insecure context) — the title still shows the id */
        }
      }}
      className="inline-flex items-center gap-1 font-mono text-[10px] text-slate-500 transition-colors hover:text-ink"
    >
      {copied ? <Check size={10} className="text-verified" /> : <Copy size={10} />}
      {copied ? 'copied' : truncateId(id, 8, 4)}
    </button>
  );
}

const OUTCOME_META: Record<CellOutcome, { label: string; tone: 'verified' | 'denied' | 'staged' | 'muted' }> = {
  allow: { label: 'ALLOW', tone: 'verified' },
  staged: { label: 'STEP-UP', tone: 'staged' },
  deny: { label: 'DENIED', tone: 'denied' },
  error: { label: 'NO RESPONSE', tone: 'muted' },
};

function navigateTo(view: string, subtab: string): void {
  window.dispatchEvent(new CustomEvent('mcpip:navigate', { detail: { view, subtab } }));
}

/* --- component ---------------------------------------------------------------- */

export function SeparationCheck({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const { mode, apiBase, tenant, stream } = gateway;
  const { config } = useCompanyConfig();
  const skillTenant = tenant ?? config?.tenant ?? null;
  const live = mode === 'live';

  const sources = useMemo(
    () => compartmentSources(config?.teams ?? [], live ? tenant : null),
    [config, live, tenant],
  );

  // `sources` is declared above, so the lazy initializers can seed real picks
  // on first paint; the repair effects below track later list changes.
  const [pickA, setPickA] = useState<string>(() => sources[0]?.uuid ?? '');
  const [pickB, setPickB] = useState<string>(() => sources[1]?.uuid ?? '');
  const [run, setRun] = useState<Run>({ phase: 'idle' });
  const runningRef = useRef<AbortController | null>(null);

  // Keep the two picks valid and distinct as the source list changes.
  useEffect(() => {
    setPickA((prev) => (sources.some((s) => s.uuid === prev) ? prev : sources[0]?.uuid ?? ''));
  }, [sources]);
  useEffect(() => {
    setPickB((prev) => {
      if (prev !== pickA && sources.some((s) => s.uuid === prev)) return prev;
      return sources.find((s) => s.uuid !== pickA)?.uuid ?? '';
    });
  }, [sources, pickA]);

  // A dropped gateway aborts any in-flight ceremony and clears the stale verdict.
  useEffect(() => {
    if (!live) {
      runningRef.current?.abort();
      setRun({ phase: 'idle' });
    }
  }, [live]);
  useEffect(() => () => runningRef.current?.abort(), []);

  // The live feed rows keyed by correlation id — lets a denied cell show the REAL
  // WORM deny reason once the feed catches up (~2s), instead of asserting one.
  const feedReason = useMemo(() => {
    const map = new Map<string, string | null>();
    for (const e of stream) map.set(e.correlationId, e.reason);
    return map;
  }, [stream]);

  const doRun = useCallback(async (): Promise<void> => {
    const a = sources.find((s) => s.uuid === pickA);
    const b = sources.find((s) => s.uuid === pickB);
    if (!a || !b || a.uuid === b.uuid || !skillTenant || !live) return;
    runningRef.current?.abort();
    const controller = new AbortController();
    runningRef.current = controller;
    const opts = { base: apiBase, signal: controller.signal };
    const agentA = probeAgentId(a);
    const agentB = probeAgentId(b);

    setRun({ phase: 'running', step: 'minting per-team probe identities' });
    let tokenA: string;
    let tokenB: string;
    try {
      [tokenA, tokenB] = await Promise.all([
        mintDevToken({ tenant_id: skillTenant, agent_id: agentA, compartment: a.uuid }, opts),
        mintDevToken({ tenant_id: skillTenant, agent_id: agentB, compartment: b.uuid }, opts),
      ]);
    } catch {
      // The minter 404s in production (identity sovereignty) — say so, simulate nothing.
      if (!controller.signal.aborted) setRun({ phase: 'unavailable' });
      return;
    }

    setRun({ phase: 'running', step: 'reading each team’s live catalog' });
    const [catA, catB] = await Promise.all([fetchCatalog(tokenA, opts), fetchCatalog(tokenB, opts)]);
    if (controller.signal.aborted) return;
    if (catA === null || catB === null) {
      setRun({ phase: 'failed', detail: 'a per-team catalog read failed after the identities minted — retry in a moment' });
      return;
    }

    const scopedA = pickScoped(catA, a.uuid);
    const scopedB = pickScoped(catB, b.uuid);
    const targets: ProbeTarget[] = [];
    if (scopedA !== null) {
      targets.push({ alias: scopedA.alias, owner: a, risk: scopedA.risk_tier, enumerableFromOther: catB.some((i) => i.alias === scopedA.alias) });
    }
    if (scopedB !== null) {
      targets.push({ alias: scopedB.alias, owner: b, risk: scopedB.risk_tier, enumerableFromOther: catA.some((i) => i.alias === scopedB.alias) });
    }
    const sideA: SideView = { source: a, agentId: agentA, enumerable: catA.length };
    const sideB: SideView = { source: b, agentId: agentB, enumerable: catB.length };
    if (targets.length === 0) {
      // Still a REAL result: both catalogs were read live and hold nothing scoped.
      setRun({ phase: 'done', a: sideA, b: sideB, targets, cells: [], at: Date.now() });
      return;
    }

    setRun({ phase: 'running', step: `firing ${targets.length * 2} real /v1/authorize probes` });
    const callers = [
      { src: a, token: tokenA },
      { src: b, token: tokenB },
    ];
    const cells: ProbeCell[] = [];
    for (const t of targets) {
      for (const caller of callers) {
        let outcome: CellOutcome;
        let correlationId: string | null;
        try {
          const res = await authorize(
            { source_format: 'raw_mcp', tool_call: { tool: t.alias, arguments: {} } },
            { token: caller.token, base: apiBase, signal: controller.signal },
          );
          if (res.kind === 'executed') {
            outcome = 'allow';
            correlationId = res.receipt.correlation_id;
          } else if (res.kind === 'staged') {
            outcome = 'staged';
            correlationId = res.challenge.correlation_id;
          } else {
            outcome = 'deny';
            correlationId = res.error.correlation_id;
          }
        } catch {
          if (controller.signal.aborted) return;
          outcome = 'error';
          correlationId = null;
        }
        const own = caller.src.uuid === t.owner.uuid;
        // Own compartment must pass the gate (200, or 202 when pin_required);
        // any other compartment must be denied before a PIN is even in play.
        const expected = own ? outcome === 'allow' || outcome === 'staged' : outcome === 'deny';
        cells.push({ callerUuid: caller.src.uuid, ownerUuid: t.owner.uuid, alias: t.alias, outcome, correlationId, expected });
      }
    }
    if (!controller.signal.aborted) {
      setRun({ phase: 'done', a: sideA, b: sideB, targets, cells, at: Date.now() });
    }
  }, [sources, pickA, pickB, skillTenant, live, apiBase]);

  /* --- gates ----------------------------------------------------------------- */

  if (!live) {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={Shield}
          title="No gateway connected"
          detail="The separation check runs real /v1/authorize probes against the connected gateway — there is nothing to simulate offline."
          action={
            <button type="button" className="btn-primary" onClick={() => navigateTo('gateway', 'connection')}>
              <PlugZap size={13} /> Connect a gateway
            </button>
          }
        />
      </Panel>
    );
  }

  if (sources.length < 2) {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={Users}
          title="Two teams required"
          detail="Create at least two teams in Company Settings, then run the check."
          action={
            <button type="button" className="btn-ghost" onClick={() => navigateTo('gateway', 'company')}>
              Open Company Settings
            </button>
          }
        />
      </Panel>
    );
  }

  const running = run.phase === 'running';
  const canRun = !running && pickA !== '' && pickB !== '' && pickA !== pickB;

  return (
    <div className="flex h-full flex-col gap-3">
      {/* --- control bar -------------------------------------------------------- */}
      <div className="panel flex flex-wrap items-end gap-3 px-3.5 py-3">
        <div className="mr-1 flex items-center gap-2">
          <Shield size={15} className="text-slate-500" />
          <div>
            <div className="text-[13.5px] font-semibold tracking-tightest text-ink">Separation Check</div>
            <div className="text-[10.5px] text-slate-500">
              over <span className="font-mono">{skillTenant ?? '—'}</span> · your own compartments
            </div>
          </div>
        </div>
        <Field label="Team A">
          <Select value={pickA} onChange={(e) => setPickA(e.target.value)} className="!w-[170px]">
            {sources.map((s) => (
              <option key={s.key} value={s.uuid}>
                {s.label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Team B">
          <Select value={pickB} onChange={(e) => setPickB(e.target.value)} className="!w-[170px]">
            {sources
              .filter((s) => s.uuid !== pickA)
              .map((s) => (
                <option key={s.key} value={s.uuid}>
                  {s.label}
                </option>
              ))}
          </Select>
        </Field>
        <button type="button" onClick={() => void doRun()} disabled={!canRun} className="btn-primary h-[34px]">
          {running ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
          {running ? 'Checking…' : run.phase === 'done' ? 'Re-run check' : 'Run check'}
        </button>
        <span className="pb-1.5 text-[10.5px] text-slate-500">
          2–4 real <span className="font-mono text-[10px]">/v1/authorize</span> calls · WORM-logged
        </span>
      </div>

      {/* --- result + evidence --------------------------------------------------- */}
      <div className="grid min-h-0 flex-1 grid-cols-1 gap-3 xl:grid-cols-[minmax(0,1fr)_380px]">
        <Panel>
          <PanelHeader
            icon={ShieldCheck}
            title="Verdict matrix"
            right={run.phase === 'done' ? <span className="font-mono text-[10.5px]">checked {formatClock(run.at)}</span> : undefined}
          />
          {run.phase === 'idle' ? (
            <EmptyState
              icon={ShieldCheck}
              title="No verdict yet"
              detail="Run the check to watch the gateway decide both sides of the team boundary for real."
              action={
                <button type="button" onClick={() => void doRun()} disabled={!canRun} className="btn-primary">
                  <Play size={13} /> Run check
                </button>
              }
            />
          ) : null}

          {run.phase === 'running' ? (
            <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-12 text-center">
              <Loader2 size={20} className="animate-spin text-slate-500" />
              <p className="text-[12.5px] font-medium text-slate-400">{run.step}</p>
              <p className="max-w-sm text-[11.5px] leading-relaxed text-slate-500">
                Every call is a real gateway round-trip — the verdicts land as they return.
              </p>
            </div>
          ) : null}

          {run.phase === 'unavailable' ? (
            <div className="space-y-1.5 px-5 py-4">
              <div className="flex items-start gap-2 rounded-lg border border-staged/25 bg-staged/5 px-3 py-2 text-[11.5px] leading-relaxed text-staged">
                <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                <span>
                  <span className="font-semibold">The self-test needs the sandbox identity minter.</span>{' '}
                  This gateway does not mount <span className="font-mono text-[10.5px]">POST /v1/dev/token</span>.
                </span>
              </div>
              <p className="pl-6 text-[11px] leading-relaxed text-slate-500">
                In production, mint two team-scoped principals from your IdP and fire the same two
                calls through the SDK.
              </p>
            </div>
          ) : null}

          {run.phase === 'failed' ? (
            <div className="space-y-1.5 px-5 py-4">
              <div className="flex items-start gap-2 rounded-lg border border-denied/25 bg-denied/5 px-3 py-2 text-[11.5px] leading-relaxed text-denied">
                <ShieldAlert size={14} className="mt-0.5 shrink-0" />
                <span>
                  <span className="font-semibold">Check did not complete.</span> {run.detail}.
                </span>
              </div>
            </div>
          ) : null}

          {run.phase === 'done' && run.cells.length === 0 ? (
            <EmptyState
              icon={SearchX}
              title="No compartment-scoped skills to test"
              detail={`Both catalogs were read live (${run.a.enumerable} and ${run.b.enumerable} rows) — every enumerable alias is tenant-wide, so there is no boundary to test.`}
            />
          ) : null}

          {run.phase === 'done' && run.cells.length > 0 ? <DoneMatrix run={run} feedReason={feedReason} /> : null}

          <div className="mt-auto shrink-0 border-t border-hairline px-4 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
            The wire carries only an opaque deny + correlation id — look up the id in the audit log
            for the concrete reason.
          </div>
        </Panel>

        {/* --- live evidence from the real feed --------------------------------- */}
        <Panel>
          <PanelHeader
            icon={ScrollText}
            title="Cross-compartment denials"
            right={
              <button
                type="button"
                onClick={() => navigateTo('ledger', 'events')}
                className="inline-flex items-center gap-1 text-[11px] font-medium text-slate-500 transition-colors hover:text-ink"
              >
                Open audit log
              </button>
            }
          />
          <EvidenceList stream={stream} />
          <div className="mt-auto shrink-0 border-t border-hairline px-4 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
            <span className="font-mono text-[10px]">compartment_denied</span> rows from the live
            feed — probe denials appear within ~2 s.
          </div>
        </Panel>
      </div>
    </div>
  );
}

/* --- done-state matrix -------------------------------------------------------- */

function DoneMatrix({
  run,
  feedReason,
}: {
  run: Extract<Run, { phase: 'done' }>;
  feedReason: ReadonlyMap<string, string | null>;
}): JSX.Element {
  const { a, b, targets, cells } = run;
  const unexpected = cells.filter((c) => !c.expected);
  const errors = cells.filter((c) => c.outcome === 'error');
  const crossBreaches = unexpected.filter((c) => c.callerUuid !== c.ownerUuid && c.outcome !== 'error');
  const ownDenied = unexpected.filter((c) => c.callerUuid === c.ownerUuid && c.outcome === 'deny');

  let banner: JSX.Element;
  if (crossBreaches.length > 0) {
    banner = (
      <div className="flex items-start gap-2 rounded-lg border border-staged/25 bg-staged/5 px-3 py-2 text-[11.5px] leading-relaxed text-staged">
        <ShieldAlert size={14} className="mt-0.5 shrink-0" />
        <span>
          <span className="font-semibold">Boundary crossed.</span> A cross-compartment call was not denied. An
          active delegated grant makes that legitimate — verify in the Audit Ledger (and the grant record)
          before treating it as a breach.
        </span>
      </div>
    );
  } else if (ownDenied.length > 0) {
    banner = (
      <div className="flex items-start gap-2 rounded-lg border border-denied/25 bg-denied/5 px-3 py-2 text-[11.5px] leading-relaxed text-denied">
        <ShieldAlert size={14} className="mt-0.5 shrink-0" />
        <span>
          <span className="font-semibold">In-compartment call denied.</span> A team was refused its own scoped
          skill — check whether the skill is stopped (SKILL_DISABLED) or the identity&apos;s compartment claim
          drifted from the gateway&apos;s registry.
        </span>
      </div>
    );
  } else if (errors.length > 0) {
    banner = (
      <div className="flex items-start gap-2 rounded-lg border border-hairline bg-canvas px-3 py-2 text-[11.5px] leading-relaxed text-slate-400">
        <ShieldAlert size={14} className="mt-0.5 shrink-0" />
        <span>
          <span className="font-semibold">Check incomplete.</span> {errors.length}{' '}
          {errors.length === 1 ? 'probe' : 'probes'} got no response — re-run the check.
        </span>
      </div>
    );
  } else {
    banner = (
      <div className="flex items-start gap-2 rounded-lg border border-verified/25 bg-verified/5 px-3 py-2 text-[11.5px] leading-relaxed text-verified">
        <ShieldCheck size={14} className="mt-0.5 shrink-0" />
        <span>
          <span className="font-semibold">Separation holds.</span> In-compartment calls pass the gate;
          cross-compartment calls are denied opaquely before any step-up.
        </span>
      </div>
    );
  }

  const callers: ReadonlyArray<SideView> = [a, b];

  return (
    <div className="min-h-0 flex-1 space-y-4 overflow-y-auto px-4 py-4">
      {banner}

      <div className="overflow-x-auto rounded-lg border border-hairline">
        <table className="w-full min-w-[520px] border-collapse text-left">
          <thead>
            <tr className="border-b border-hairline text-[10.5px] font-semibold uppercase tracking-[0.06em] text-slate-500">
              <th className="px-3 py-2 font-semibold">Caller identity</th>
              {targets.map((t) => (
                <th key={t.alias} className="px-3 py-2 font-semibold">
                  <span className="block truncate font-mono normal-case tracking-normal text-[11px] text-ink">{t.alias}</span>
                  <span className="font-medium normal-case tracking-normal text-slate-500">
                    scoped to {t.owner.label} · {t.risk}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {callers.map((side) => (
              <tr key={side.source.uuid} className="border-b border-hairline/60 last:border-0">
                <td className="px-3 py-2.5 align-top">
                  <span className="block truncate font-mono text-[11.5px] text-ink">{side.agentId}</span>
                  <span className="mt-0.5 inline-flex items-center gap-1 text-[10.5px] text-slate-500">
                    <Users size={10} /> {side.source.label} · {side.enumerable} enumerable
                  </span>
                </td>
                {targets.map((t) => {
                  const cell = cells.find((c) => c.callerUuid === side.source.uuid && c.alias === t.alias);
                  if (!cell) {
                    return (
                      <td key={t.alias} className="px-3 py-2.5 align-top text-[11px] text-slate-500">
                        —
                      </td>
                    );
                  }
                  const meta = OUTCOME_META[cell.outcome];
                  const own = cell.callerUuid === cell.ownerUuid;
                  return (
                    <td key={t.alias} className="px-3 py-2.5 align-top">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <Badge tone={meta.tone}>{meta.label}</Badge>
                        <span className={`text-[10px] font-medium ${cell.expected ? 'text-slate-500' : 'text-denied'}`}>
                          {cell.expected ? (own ? '✓ own compartment' : '✓ cross-team denied') : '✗ unexpected'}
                        </span>
                      </div>
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Evidence — per-cell correlation ids + WORM deny reasons and the catalog
          half of separation. Data, rendered plainly. */}
      <div className="rounded-lg border border-hairline">
        <p className="border-b border-hairline px-3 py-2 text-[10.5px] font-medium uppercase tracking-[0.08em] text-slate-500">
          Evidence
        </p>
        <div className="space-y-3 px-3 py-3">
          <div className="space-y-1.5">
            {cells.map((cell) => {
              const caller = callers.find((s) => s.source.uuid === cell.callerUuid);
              const feedHit = cell.correlationId !== null ? feedReason.get(cell.correlationId) : undefined;
              const meta = OUTCOME_META[cell.outcome];
              return (
                <div
                  key={`${cell.callerUuid}-${cell.alias}`}
                  className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10px] text-slate-500"
                >
                  <span className="font-mono text-[10.5px] text-slate-400">{caller?.source.label ?? cell.callerUuid}</span>
                  <span className="shrink-0 text-slate-500">→</span>
                  <span className="font-mono text-[10.5px] text-ink">{cell.alias}</span>
                  <Badge tone={meta.tone}>{meta.label}</Badge>
                  {cell.outcome === 'deny' ? (
                    typeof feedHit === 'string' ? (
                      <span>
                        WORM: <span className="font-mono text-denied">{feedHit}</span>
                      </span>
                    ) : (
                      <span>reason is WORM-only</span>
                    )
                  ) : null}
                  {cell.correlationId !== null ? <CopyCorr id={cell.correlationId} /> : null}
                </div>
              );
            })}
          </div>

          {/* The catalog half of separation — real cross-enumerability reads. */}
          <div className="space-y-1.5 border-t border-hairline pt-3">
            {targets.map((t) => (
              <div key={t.alias} className="flex items-start gap-2 text-[11px] leading-relaxed text-slate-500">
                <EyeOff size={12} className={`mt-0.5 shrink-0 ${t.enumerableFromOther ? 'text-staged' : 'text-verified'}`} />
                <span>
                  <span className="font-mono text-[10.5px] text-ink">{t.alias}</span> (scoped to {t.owner.label}):{' '}
                  {t.enumerableFromOther ? (
                    <span className="text-staged">visible in the other team&apos;s catalog — check for a live grant</span>
                  ) : (
                    <>hidden from the other team&apos;s catalog</>
                  )}
                  .
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* --- evidence list -------------------------------------------------------------- */

function EvidenceList({ stream }: { stream: GatewayLive['stream'] }): JSX.Element {
  const rows = useMemo(() => stream.filter((e) => e.reason === 'compartment_denied').slice(0, 12), [stream]);
  if (rows.length === 0) {
    return (
      <EmptyState
        icon={Inbox}
        title="No cross-team denials in the recent feed"
        detail="Run the check to generate real cross-team probes."
      />
    );
  }
  return (
    <div className="min-h-0 flex-1 overflow-y-auto">
      {rows.map((e) => (
        <div key={e.id} className="border-b border-hairline/60 px-4 py-2 last:border-0">
          <div className="flex items-center gap-2">
            <span className="tabular shrink-0 font-mono text-[10.5px] text-slate-500">{formatClock(e.ts)}</span>
            <span className="min-w-0 truncate font-mono text-[11px] text-ink">{e.agent ?? '(unknown)'}</span>
            <span className="shrink-0 text-[10px] text-slate-500">→</span>
            <span className="min-w-0 truncate font-mono text-[11px] text-slate-400">{e.alias}</span>
          </div>
          <div className="mt-0.5 flex items-center gap-2 pl-[52px]">
            <Badge tone="denied">compartment_denied</Badge>
            <CopyCorr id={e.correlationId} />
          </div>
        </div>
      ))}
    </div>
  );
}
