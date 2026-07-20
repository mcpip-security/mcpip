import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, Loader2, Play, PlugZap, ShieldAlert, SquareTerminal } from 'lucide-react';
import { authenticatorOtp, authorize, mintDevToken } from '../lib/api';
import { loadCompanyConfig } from '../lib/companyConfig';
import { truncateId } from '../lib/format';
import { EmptyState, Field, Panel, PanelHeader, Select } from './ui';
import type { AuthorizeRequest } from '../lib/types';
import type { GatewayLive, LiveAuthResult } from '../lib/useGatewayLive';

/* ---------------------------------------------------------------------------
   Authorize Probe — the live /v1/authorize instrument, and the console's ONLY
   invented-data-free latency source: every round-trip printed on the tape is
   a wall-clock measurement of a request THIS console just made, and it is
   always labelled console-measured (the gateway-side histogram in Overview is
   the separate, fleet-wide truth).

   Pick a skill from the real /v1/catalog, edit the tool-call arguments, and
   fire: the actual receipt (200), staged challenge (202) or opaque deny
   renders as tape lines the moment the response lands — nothing is scripted,
   typed-out, or delayed for effect. A staged pin_required call can be
   completed end-to-end via the SANDBOX authenticator stand-in; in production
   the one-time code arrives out-of-band, and the probe says so instead of
   pretending.

   Two request paths, one honest reason: the canonical empty-args probe rides
   gateway.authorizeSkill / completeStepUp (so its latency joins
   metrics.consoleProbeP50Ms and the stream refreshes immediately), while
   custom argument payloads go directly through the api client with a per-run
   sandbox token — the hook's probe request is pinned to `arguments: {}`
   because the step-up payload lock is over the arguments' canonical JSON.
   For the same reason a staged challenge freezes its argument snapshot:
   completion must resubmit exactly those bytes.
--------------------------------------------------------------------------- */

type LineKind = 'cmd' | 'info' | 'note' | 'ok' | 'staged' | 'deny';

interface TapeLine {
  id: number;
  kind: LineKind;
  text: string;
}

const BANNER: Record<'ok' | 'staged' | 'deny', string> = {
  ok: 'border-verified/25 bg-verified/5 text-verified',
  staged: 'border-staged/25 bg-staged/5 text-staged',
  deny: 'border-denied/25 bg-denied/5 text-denied',
};

function LineRow({ line }: { line: TapeLine }): JSX.Element {
  if (line.kind === 'cmd') {
    return (
      <div className="flex gap-2">
        <span className="select-none text-slate-500">$</span>
        <span className="min-w-0 break-all text-ink">{line.text}</span>
      </div>
    );
  }
  if (line.kind === 'info') {
    return <div className="break-all pl-4 text-slate-400">{line.text}</div>;
  }
  if (line.kind === 'note') {
    return <div className="break-all pl-4 text-slate-500">{line.text}</div>;
  }
  return (
    <div
      className={`mt-1 flex items-start gap-2 rounded-lg border px-2.5 py-1.5 font-semibold ${BANNER[line.kind]}`}
    >
      <span className="select-none">→</span>
      <span className="min-w-0 break-all">{line.text}</span>
    </div>
  );
}

/** A staged challenge awaiting its one-time code. `args` is frozen at stage
    time — the payload lock is over their canonical JSON, so completion must
    resubmit exactly this snapshot, not whatever the editor holds by then. */
interface PendingChallenge {
  alias: string;
  challengeId: string;
  args: Record<string, unknown>;
}

/** Parse the editor text into the tool-call `arguments` dict (objects only). */
function parseArgs(text: string): { args: Record<string, unknown> } | { error: string } {
  try {
    const parsed: unknown = JSON.parse(text);
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return { error: 'arguments must be a JSON object' };
    }
    return { args: parsed as Record<string, unknown> };
  } catch (err) {
    return { error: err instanceof Error ? err.message : 'invalid JSON' };
  }
}

function median(values: ReadonlyArray<number>): number | null {
  if (values.length === 0) {
    return null;
  }
  const sorted = [...values].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  const v =
    sorted.length % 2 === 1 ? sorted[mid] ?? 0 : ((sorted[mid - 1] ?? 0) + (sorted[mid] ?? 0)) / 2;
  return Math.round(v * 10) / 10;
}

export function AuthorizeProbe({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const idRef = useRef(0);
  const [lines, setLines] = useState<TapeLine[]>([]);
  const [selectedAlias, setSelectedAlias] = useState('');
  const [argsText, setArgsText] = useState('{}');
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<PendingChallenge | null>(null);
  /** Console-measured round-trips of TERMINAL decisions this session (real only). */
  const [trips, setTrips] = useState<number[]>([]);
  const scrollRef = useRef<HTMLDivElement>(null);

  // ONLY what the gateway actually enumerates for this identity — no fallback list.
  const options = gateway.catalog;
  const firstAlias = options[0]?.alias ?? '';
  const alias = options.some((o) => o.alias === selectedAlias) ? selectedAlias : firstAlias;

  const parsed = useMemo(() => parseArgs(argsText), [argsText]);
  const argsError = 'error' in parsed ? parsed.error : null;

  /** Append tape lines INSTANTLY — terminal output never types itself out. */
  const push = (next: ReadonlyArray<{ kind: LineKind; text: string }>): void => {
    const stamped: TapeLine[] = next.map((l) => {
      idRef.current += 1;
      return { ...l, id: idRef.current };
    });
    setLines((prev) => [...prev, ...stamped].slice(-120));
  };

  // Keep the newest line in view.
  useEffect(() => {
    const el = scrollRef.current;
    if (el) {
      el.scrollTop = el.scrollHeight;
    }
  }, [lines]);

  /** Per-run sandbox token for the operator's company tenant (same identity
      recipe as the hook). Null when unmintable — production has no /v1/dev/token. */
  const mintProbeToken = async (): Promise<string | null> => {
    try {
      const company = loadCompanyConfig();
      return await mintDevToken(company?.tenant ? { tenant_id: company.tenant } : {}, {
        base: gateway.apiBase,
      });
    } catch {
      return null;
    }
  };

  /** One direct /v1/authorize round-trip for CUSTOM arguments, wall-clock
      measured around the authorize call only (the mint is excluded). */
  const fireDirect = async (
    token: string,
    forAlias: string,
    args: Record<string, unknown>,
    pin?: { otp: string; challengeId: string },
  ): Promise<LiveAuthResult | null> => {
    const request: AuthorizeRequest = {
      source_format: 'raw_mcp',
      tool_call: { tool: forAlias, arguments: args },
    };
    if (pin) {
      request.pin = pin.otp;
      request.challenge_id = pin.challengeId;
    }
    const started = performance.now();
    try {
      const outcome = await authorize(request, { token, base: gateway.apiBase });
      return { outcome, latencyMs: Math.round((performance.now() - started) * 10) / 10 };
    } catch {
      return null;
    }
  };

  /** Print one REAL outcome; terminal decisions join the session stats. */
  const renderOutcome = (
    forAlias: string,
    args: Record<string, unknown>,
    result: LiveAuthResult,
  ): void => {
    const { outcome, latencyMs } = result;
    if (outcome.kind === 'executed') {
      const r = outcome.receipt;
      setPending(null);
      setTrips((prev) => [...prev, latencyMs].slice(-200));
      push([
        { kind: 'info', text: `allow · committed · ${latencyMs} ms console-measured` },
        { kind: 'info', text: `txn=${r.transaction_ref} · corr=${truncateId(r.correlation_id, 8, 4)}` },
        {
          kind: 'ok',
          text: `200 EXECUTED · target_class=${r.executed_target_class} · worm seq #${r.worm_sequence}`,
        },
      ]);
    } else if (outcome.kind === 'staged') {
      const c = outcome.challenge;
      setPending({ alias: forAlias, challengeId: c.challenge_id, args });
      push([
        { kind: 'info', text: `risk=${c.risk_tier} · step-up required · ${latencyMs} ms console-measured` },
        { kind: 'note', text: c.action_required },
        {
          kind: 'staged',
          text: `202 STAGED · challenge=${truncateId(c.challenge_id, 8, 4)} · corr=${truncateId(c.correlation_id, 8, 4)}`,
        },
      ]);
    } else {
      setPending(null);
      setTrips((prev) => [...prev, latencyMs].slice(-200));
      push([
        { kind: 'info', text: `deny · opaque at the agent boundary · ${latencyMs} ms console-measured` },
        {
          kind: 'deny',
          text: `DENIED · {"error":"${outcome.error.error}"} · corr=${truncateId(outcome.error.correlation_id, 8, 4)}`,
        },
        {
          kind: 'note',
          text: 'the concrete WORM deny reason for this correlation id is operator-visible in the Decision Stream',
        },
      ]);
    }
  };

  const run = async (): Promise<void> => {
    if (busy || alias === '' || 'error' in parsed) {
      return;
    }
    const args = parsed.args;
    setBusy(true);
    setPending(null);
    const cmd: Array<{ kind: LineKind; text: string }> = [
      { kind: 'cmd', text: `POST /v1/authorize · raw_mcp · tool=${alias}` },
    ];
    const compact = JSON.stringify(args);
    if (compact !== '{}') {
      cmd.push({
        kind: 'info',
        text: `arguments ${compact.length > 96 ? `${compact.slice(0, 96)}…` : compact}`,
      });
    }
    push(cmd);

    // Canonical {} probes ride the hook (latency joins consoleProbeP50Ms and
    // the stream refreshes immediately); custom payloads go direct.
    let result: LiveAuthResult | null;
    if (Object.keys(args).length === 0) {
      result = await gateway.authorizeSkill(alias);
    } else {
      const token = await mintProbeToken();
      result = token === null ? null : await fireDirect(token, alias, args);
    }

    if (result === null) {
      push([
        {
          kind: 'deny',
          text: 'no round-trip — the request failed before reaching the gateway (network, or no sandbox identity to sign it)',
        },
      ]);
    } else {
      renderOutcome(alias, args, result);
    }
    setBusy(false);
  };

  /** Complete the staged step-up: sandbox OTP + resubmit of the frozen args. */
  const completePending = async (): Promise<void> => {
    if (busy || pending === null) {
      return;
    }
    setBusy(true);
    push([
      {
        kind: 'cmd',
        text: `POST /v1/authorize · tool=${pending.alias} · pin=<sandbox otp> · challenge=${truncateId(pending.challengeId, 8, 4)}`,
      },
    ]);

    let result: LiveAuthResult | null;
    if (Object.keys(pending.args).length === 0) {
      result = await gateway.completeStepUp(pending.alias, pending.challengeId);
    } else {
      const token = await mintProbeToken();
      const otp =
        token === null
          ? null
          : await authenticatorOtp(token, pending.challengeId, { base: gateway.apiBase });
      result =
        token !== null && otp !== null
          ? await fireDirect(token, pending.alias, pending.args, {
              otp,
              challengeId: pending.challengeId,
            })
          : null;
    }

    if (result === null) {
      // Honest: the sandbox authenticator stand-in 404s in production — the
      // one-time code arrives out-of-band there and the console can't fetch it.
      push([
        {
          kind: 'deny',
          text: 'step-up not completed — the sandbox authenticator is unavailable (in production the one-time code arrives out-of-band on the enrolled device)',
        },
      ]);
    } else {
      renderOutcome(pending.alias, pending.args, result);
    }
    setBusy(false);
  };

  if (gateway.mode !== 'live') {
    return (
      <Panel className="h-full">
        <EmptyState
          icon={SquareTerminal}
          title="No gateway connected"
          detail="The probe is live-only: every line of its tape is a real /v1/authorize round-trip against the connected gateway. Nothing is scripted."
          action={
            <button
              type="button"
              onClick={() =>
                window.dispatchEvent(
                  new CustomEvent('mcpip:navigate', {
                    detail: { view: 'gateway', subtab: 'connection' },
                  }),
                )
              }
              className="btn-primary"
            >
              <PlugZap size={13} /> Connect a gateway
            </button>
          }
        />
      </Panel>
    );
  }

  const p50 = median(trips);
  const last = trips[trips.length - 1] ?? null;
  const runDisabled = busy || alias === '' || argsError !== null;

  return (
    <Panel className="h-full">
      <PanelHeader
        title="Authorize probe"
        icon={SquareTerminal}
        right={
          <span className="font-mono text-[10.5px]">POST /v1/authorize · {gateway.apiHost}</span>
        }
      />

      <div className="grid min-h-0 flex-1 grid-cols-1 md:grid-cols-[320px_minmax(0,1fr)]">
        {/* Request builder */}
        <div className="flex min-h-0 flex-col gap-3 overflow-y-auto border-b border-hairline p-4 md:border-b-0 md:border-r">
          <Field label="Skill alias">
            <Select
              mono
              value={alias}
              onChange={(e) => setSelectedAlias(e.target.value)}
              disabled={options.length === 0}
              aria-label="Skill alias to authorize"
            >
              {options.length === 0 ? (
                <option value="">no skills enumerable for this identity</option>
              ) : (
                options.map((o) => (
                  <option key={o.alias} value={o.alias}>
                    {o.alias} · {o.risk_tier}
                  </option>
                ))
              )}
            </Select>
          </Field>

          <Field label="Arguments · JSON object">
            <textarea
              value={argsText}
              onChange={(e) => setArgsText(e.target.value)}
              rows={6}
              spellCheck={false}
              aria-label="Tool-call arguments as a JSON object"
              className="w-full resize-none rounded-lg border border-hairline bg-canvas px-3 py-2.5 font-mono text-[12px] leading-relaxed text-ink outline-none placeholder:text-slate-500 focus:border-ink/30 focus:shadow-focus-ring"
            />
          </Field>
          {argsError !== null ? (
            <p className="flex items-start gap-1.5 text-[11px] leading-relaxed text-denied">
              <ShieldAlert size={12} className="mt-[1px] shrink-0" /> {argsError}
            </p>
          ) : null}

          <button
            type="button"
            onClick={() => {
              void run();
            }}
            disabled={runDisabled}
            className="btn-primary w-full"
          >
            {busy ? <Loader2 size={13} className="animate-spin" /> : <Play size={13} />}
            {busy ? 'Authorizing…' : 'Authorize'}
          </button>

          {pending !== null ? (
            <div className="rounded-lg border border-staged/25 bg-staged/5 px-3 py-2.5">
              <p className="text-[11.5px] font-medium text-staged">Step-up staged</p>
              <p className="mt-0.5 font-mono text-[10.5px] text-slate-500">
                challenge {truncateId(pending.challengeId, 8, 4)}
              </p>
              <button
                type="button"
                onClick={() => {
                  void completePending();
                }}
                disabled={busy}
                className="btn mt-2 w-full border border-staged/25 bg-surface text-staged hover:bg-staged/5"
              >
                Complete step-up · sandbox authenticator
              </button>
            </div>
          ) : null}

          <details className="group mt-auto border-t border-hairline pt-3">
            <summary className="eyebrow flex cursor-pointer list-none items-center gap-1.5 text-slate-500 transition-colors hover:text-slate-400">
              <ChevronRight
                size={13}
                className="shrink-0 transition-transform group-open:rotate-90"
                aria-hidden="true"
              />
              About this probe
            </summary>
            <div className="mt-2 space-y-1.5 text-[10.5px] leading-relaxed text-slate-500">
              <p>
                Identity-shaped argument keys (<span className="font-mono">role</span>,{' '}
                <span className="font-mono">sub</span>, <span className="font-mono">tenant_id</span>,
                …) are a hard deny — identity comes only from the verified JWT. Try one to watch the
                gateway refuse it.
              </p>
              <p>
                Round-trips are wall-clock measured by this console and always labelled
                console-measured; the gateway-side histogram (all agents) lives in Overview.
              </p>
            </div>
          </details>
        </div>

        {/* Response tape */}
        <div className="flex min-h-0 flex-col">
          <div
            ref={scrollRef}
            className="min-h-0 flex-1 space-y-1 overflow-y-auto bg-canvas px-4 py-3 font-mono text-[11.5px] leading-relaxed"
          >
            {lines.length === 0 ? (
              <p className="pt-2 font-sans text-[11.5px] text-slate-500">
                Pick a skill and authorize — every line here is a real gateway response.
              </p>
            ) : (
              lines.map((line) => <LineRow key={line.id} line={line} />)
            )}
            {busy ? (
              /* blink = reserved liveness semantics: a request is genuinely in flight */
              <span className="mt-1 inline-block h-3 w-[7px] animate-blink bg-ink/80" aria-hidden="true" />
            ) : null}
          </div>
          <div className="flex shrink-0 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-t border-hairline px-4 py-2 text-[10.5px] text-slate-500">
            <span>
              agent boundary sees an opaque error + <span className="font-mono">correlation_id</span>{' '}
              only
            </span>
            <span className="tabular font-mono">
              {p50 === null || last === null
                ? 'no decisions yet'
                : `${trips.length} decisions · last ${last} ms · p50 ${p50} ms · console-measured`}
            </span>
          </div>
        </div>
      </div>
    </Panel>
  );
}
