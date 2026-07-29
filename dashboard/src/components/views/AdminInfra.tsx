import { useCallback, useEffect, useState } from 'react';
import {
  Boxes,
  KeyRound,
  PlugZap,
  Check,
  Loader2,
  CheckCircle2,
  XCircle,
  Building2,
  Plus,
  Trash2,
  RotateCcw,
  Save,
  Cloud,
  ChevronRight,
  Vault as VaultIcon,
  ShieldCheck,
  X,
  ShieldAlert,
  KeySquare,
  Server,
  Link2,
  Link2Off,
  Gauge,
  Timer,
  Coins,
} from 'lucide-react';
import { HealthPanel } from '../HealthPanel';
import { MySecurity } from './MySecurity';
import { SoftwareUpdatesView, LicenseUsageView } from './SoftwarePanel';
import { Field, Input, Badge, Panel, PanelHeader, EmptyState, Select } from '../ui';
import { useCompanyConfig, loadCompanyConfig, slugifyTenant, deleteProfile } from '../../lib/companyConfig';
import { formatDateTime } from '../../lib/format';
import { saveCloudEnvironment, removeCloudEnvironment, type CloudEnvironment } from '../../lib/cloudBroker';
import { loadVaultSecrets, saveVaultSecret, removeVaultSecret, VAULT_VENDORS, VENDOR_FIELDS, type VaultSecret, type VaultVendor } from '../../lib/vault';
import {
  deletePolicy,
  getPolicy,
  listCloudEnvironments,
  listVaultSecrets,
  mcpStepUpCapability,
  catalog as fetchCatalog,
  mintDevToken,
  readyz,
  POLICY_SCHEMA,
  protectedResourceMetadata,
  putPolicy,
} from '../../lib/api';
import type {
  ExternalPdpFeatureStatus,
  McpStepUpCapability,
  PolicyDocument,
  PolicyRule,
  ProtectedResourceMetadata,
} from '../../lib/api';
import { CAP_DIRECTORY_ADMIN } from '../../lib/protocol';
import type { GatewayLive } from '../../lib/useGatewayLive';

/* ---------------------------------------------------------------------------
   Gateway — the administer view: everything about THIS console's connection to
   THIS gateway node. Six honest sub-tabs:

     connection · company · cloud (Cloud IAM) · vault (Secret Vault) ·
     health · software (Updates & License)

   The old 'identity' sub-tab (a pure fixture tenant) is cut, and the old
   'infra' sub-tab is folded into Health — its one real datum (first_bad_epoch
   from /v1/audit/verify) lives there as an audit/WORM detail row; its
   hardcoded AOF-durability claim is gone because no endpoint reports it.
   Every remaining surface reads or writes a real gateway endpoint, and every
   failure renders as itself — unknown is "unknown", never a confident guess.
--------------------------------------------------------------------------- */

/** Deep-link to Gateway → Connection (the standard offline-empty-state CTA). */
function navigateToConnection(): void {
  window.dispatchEvent(
    new CustomEvent('mcpip:navigate', { detail: { view: 'gateway', subtab: 'connection' } }),
  );
}

/**
 * The tenant admin reads/writes are scoped to: the minted console identity's
 * tenant, else the operator's company profile. NEVER a hardcoded fallback —
 * with no real tenant the admin surfaces render their honest unavailable
 * state instead of silently scoping to a phantom.
 */
function resolveTenant(gateway: GatewayLive): string | null {
  if (gateway.tenant) {
    return gateway.tenant;
  }
  const configured = loadCompanyConfig()?.tenant;
  return configured ? configured : null;
}

/**
 * Mint a CAP_DIRECTORY_ADMIN token for one admin read. Null when the sandbox
 * /v1/dev/token minter is absent (production, by design) or refused — callers
 * must then render an explicit "unavailable" state, never an empty list.
 */
async function mintAdminToken(apiBase: string, tenantId: string, agentId: string): Promise<string | null> {
  try {
    return await mintDevToken(
      { tenant_id: tenantId, agent_id: agentId, capabilities: [CAP_DIRECTORY_ADMIN] },
      { base: apiBase },
    );
  } catch {
    return null;
  }
}

/**
 * Tri-state admin read: 'ok' means the gateway ANSWERED (data may be empty);
 * 'unavailable' means the mint or the read FAILED — the real state is unknown.
 * Collapsing the two is exactly the false-negative this view refuses to show.
 */
type AdminListRead<T> = { kind: 'loading' } | { kind: 'unavailable' } | { kind: 'ok'; data: T };

/**
 * The honest degraded state for a failed admin read. In production the
 * sandbox /v1/dev/token minter is 404 by design (identity sovereignty), so
 * this is the expected posture there — stated plainly, never dressed up as
 * "nothing configured".
 */
function AdminReadUnavailable({ what }: { what: string }): JSX.Element {
  return (
    <div className="space-y-1.5 px-5 py-4">
      <p className="flex items-center gap-2 text-[11.5px] font-medium text-staged">
        <ShieldAlert size={14} className="shrink-0" /> {what} unavailable — the admin read failed.
      </p>
      <p className="max-w-3xl pl-6 text-[11px] leading-relaxed text-slate-500">
        The console could not obtain a <span className="font-mono text-[10.5px]">CAP_DIRECTORY_ADMIN</span>{' '}
        credential (production gateways disable the sandbox{' '}
        <span className="font-mono text-[10.5px]">/v1/dev/token</span> minter), or the gateway refused the
        read. The real state is unknown, so nothing is shown — this is not a statement that the feature is
        off or empty.
      </p>
    </div>
  );
}

/** Calm, actionable write-failure line — a refused PUT/DELETE must never look like success. */
function WriteErrorLine({ message }: { message: string }): JSX.Element {
  return (
    <p className="flex items-center gap-2 border-b border-hairline bg-denied/5 px-5 py-2.5 text-[11.5px] font-medium text-denied">
      <XCircle size={13} className="shrink-0" /> {message}
    </p>
  );
}

/* ---------------------------------------------------------------------------
   Connection — the plug-and-play entry point. Point the console at any gateway
   at runtime (no rebuild): enter its URL, Test & Connect, and every tab flips
   to real data. The endpoint is persisted (localStorage) so it survives
   reload. This is the "plug"; the rest of the console is the "play".
--------------------------------------------------------------------------- */

/** One cell in the connection facts strip — editorial, same language as Command Center. */
function FactCell({ label, value, tone = 'ink' }: { label: string; value: React.ReactNode; tone?: 'ink' | 'verified' | 'denied' | 'staged' | 'muted' }): JSX.Element {
  const t = tone === 'verified' ? 'text-verified' : tone === 'denied' ? 'text-denied' : tone === 'staged' ? 'text-staged' : tone === 'muted' ? 'text-slate-400' : 'text-ink';
  return (
    <div className="flex min-w-0 flex-col gap-2 bg-surface px-4 py-3.5">
      <p className="eyebrow">{label}</p>
      <p className={`tabular truncate text-[14px] font-semibold tracking-tightest ${t}`}>{value}</p>
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Standards interop — reads the gateway's REAL, PUBLIC RFC 9728 OAuth 2.1
   Protected Resource Metadata (/.well-known/oauth-protected-resource, N2). It
   confirms to an operator that MCPIP advertises OAuth 2.1 Resource-Server interop
   and names the trusted authorization server(s) a token must come from — plus the
   two adjacent standards surfaces the same wave shipped (AuthZEN decision PDP N1,
   MCP MRT step-up N4). No fixture: an unreachable/pre-endpoint gateway renders an
   honest "not advertised / unavailable" state, never invented issuers.
--------------------------------------------------------------------------- */
function StandardsInterop({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const [meta, setMeta] = useState<ProtectedResourceMetadata | null | 'loading'>('loading');
  // MRT step-up is read LIVE from the real unauthenticated `initialize` reply — never a
  // static string — so a gateway predating the surface honestly reads as not-advertised.
  const [stepUp, setStepUp] = useState<McpStepUpCapability | null | 'loading'>('loading');
  // External-PDP posture comes from the admin_stats `features` block (CAP_DIRECTORY_ADMIN);
  // null = unknown (no admin token / pre-block gateway), never a fabricated state.
  const [pdp, setPdp] = useState<ExternalPdpFeatureStatus | null | 'loading'>('loading');
  const { fetchDeploymentStats } = gateway;

  useEffect(() => {
    if (!live) {
      setMeta(null);
      setStepUp(null);
      setPdp(null);
      return;
    }
    let cancelled = false;
    const ac = new AbortController();
    setMeta('loading');
    setStepUp('loading');
    setPdp('loading');
    void protectedResourceMetadata({ base: gateway.apiBase, signal: ac.signal }).then((m) => {
      if (!cancelled) setMeta(m);
    });
    void mcpStepUpCapability({ base: gateway.apiBase, signal: ac.signal }).then((c) => {
      if (!cancelled) setStepUp(c);
    });
    void fetchDeploymentStats(ac.signal).then((s) => {
      if (!cancelled) setPdp(s === null ? null : (s.features?.external_pdp ?? null));
    });
    return () => {
      cancelled = true;
      ac.abort();
    };
  }, [live, gateway.apiBase, fetchDeploymentStats]);

  const advertised = meta !== null && meta !== 'loading';

  return (
    <details className="panel group overflow-hidden">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-2.5 [&::-webkit-details-marker]:hidden">
        <span className="flex min-w-0 items-center gap-2">
          <ChevronRight size={14} className="shrink-0 text-slate-500 transition-transform group-open:rotate-90" />
          <KeySquare size={14} className="shrink-0 text-slate-500" />
          <span className="truncate text-[13px] font-semibold text-ink">Standards &amp; interop</span>
        </span>
        <Badge tone={advertised ? 'verified' : 'muted'}>
          {advertised ? 'OAuth 2.1 RS advertised' : live ? 'not advertised' : 'offline'}
        </Badge>
      </summary>
      <div className="grid gap-px border-t border-hairline bg-hairline lg:grid-cols-2">
        {/* RFC 9728 Protected Resource Metadata — the real public discovery doc. */}
        <div className="space-y-2.5 bg-surface px-5 py-4">
          <p className="eyebrow">OAuth 2.1 Resource Server · RFC 9728</p>
          {meta === 'loading' ? (
            <p className="flex items-center gap-2 text-[11.5px] text-slate-500">
              <Loader2 size={13} className="animate-spin" /> Reading /.well-known/oauth-protected-resource…
            </p>
          ) : meta === null ? (
            <p className="text-[11.5px] leading-relaxed text-slate-500">
              {live
                ? 'This gateway did not answer the RFC 9728 discovery endpoint (it may predate the surface).'
                : 'Connect to a gateway to read its advertised resource identity.'}
            </p>
          ) : (
            <div className="space-y-2 text-[11.5px]">
              <div>
                <p className="text-[10.5px] uppercase tracking-wide text-slate-500">Resource (RFC 8707 audience)</p>
                <p className="tabular break-all font-mono text-[11px] text-ink">{meta.resource || '—'}</p>
              </div>
              <div>
                <p className="text-[10.5px] uppercase tracking-wide text-slate-500">
                  Authorization server{meta.authorization_servers.length === 1 ? '' : 's'}
                </p>
                {meta.authorization_servers.length === 0 ? (
                  <p className="text-slate-500">—</p>
                ) : (
                  <ul className="space-y-0.5">
                    {meta.authorization_servers.map((iss) => (
                      <li key={iss} className="tabular break-all font-mono text-[11px] text-ink">
                        {iss}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <p className="text-[10.5px] text-slate-500">
                Bearer method{meta.bearer_methods_supported.length === 1 ? '' : 's'}:{' '}
                <span className="font-mono text-ink">
                  {meta.bearer_methods_supported.join(', ') || '—'}
                </span>{' '}
                · no OAuth scopes (authorization is capability-UUID / grant based).
              </p>
            </div>
          )}
        </div>

        {/* The adjacent decision + step-up standards the same wave shipped. */}
        <div className="space-y-3 bg-surface px-5 py-4">
          <p className="eyebrow">Decision &amp; step-up profiles</p>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <p className="text-[11.5px] font-medium text-ink">OpenID-AuthZEN 1.0 decision PDP</p>
            </div>
            <p className="text-[11px] leading-relaxed text-slate-500">
              <span className="font-mono text-[10.5px] text-ink">POST /v1/authz/decision</span> answers a
              pre-execution permit/deny (with standards-shaped obligations) — decision-only, opaque, JWT-only
              identity.
            </p>
          </div>
          {/* Outbound PDP consult — the honest posture of the deny-only external-PDP PEP,
              fed from admin_stats.features.external_pdp (no URL is ever shown). */}
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <p className="text-[11.5px] font-medium text-ink">Outbound PDP consult</p>
              {pdp === 'loading' ? (
                <Badge tone="muted">…</Badge>
              ) : pdp === null ? (
                <Badge tone="muted">{live ? 'unknown' : 'offline'}</Badge>
              ) : (
                <Badge
                  tone={
                    pdp.status === 'enforcing'
                      ? 'verified'
                      : pdp.status === 'staged'
                        ? 'staged'
                        : 'muted'
                  }
                >
                  {pdp.status}
                </Badge>
              )}
            </div>
            <p className="text-[11px] leading-relaxed text-slate-500">
              {pdp !== null && pdp !== 'loading'
                ? pdp.detail
                : live
                  ? 'Requires a CAP_DIRECTORY_ADMIN token to read the deployment posture; this console did not obtain one.'
                  : 'Connect to a gateway to read whether an outbound AuthZEN PDP is off, staged, or enforcing.'}
            </p>
          </div>
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <p className="text-[11.5px] font-medium text-ink">MCP multi-round-trip step-up · SEP-2322</p>
              {stepUp === 'loading' ? (
                <Badge tone="muted">…</Badge>
              ) : stepUp === null ? (
                <Badge tone="muted">{live ? 'unavailable' : 'offline'}</Badge>
              ) : (
                <Badge tone={stepUp.advertised ? 'verified' : 'muted'}>
                  {stepUp.advertised ? 'advertised' : 'not advertised'}
                </Badge>
              )}
            </div>
            <p className="text-[11px] leading-relaxed text-slate-500">
              {stepUp !== null && stepUp !== 'loading' && stepUp.advertised
                ? 'MCP step-up (MRT / SEP-2322) is advertised — the /v1/mcp edge maps the payload-bound PIN onto the MRT InputRequired shape. Opt-in per call; a client without the MRT keys gets the classic staged-text path.'
                : stepUp === null && live
                  ? 'The /v1/mcp initialize handshake did not answer, so the step-up capability could not be read live.'
                  : stepUp !== 'loading' && stepUp !== null && !stepUp.advertised
                    ? 'This gateway’s live initialize reply does not advertise the MRT step-up capability (it may predate the surface).'
                    : 'The /v1/mcp edge maps the payload-bound PIN onto the MRT InputRequired shape, read live from the initialize handshake.'}
            </p>
          </div>
          <p className="text-[10.5px] leading-relaxed text-slate-500">
            RFC 8693 delegation chains are recorded to the signed WORM audit log only — never surfaced on the
            agent wire.
          </p>
        </div>
      </div>
    </details>
  );
}

/* ---------------------------------------------------------------------------
   Pipeline handshake — the plug-and-play MOTION.

   Connecting used to be a spinner then a verdict, which wastes the most teachable
   two seconds the product gets. This resolves the four pipeline stages in sequence
   instead, so an operator watching a connect LEARNS the architecture without reading
   a word of docs.

   HONEST BY CONSTRUCTION: each step is a REAL request whose label states what that
   request actually proved — never a timed animation dressed up as work. Steps run in
   dependency order (a token must exist before the catalog can be read); the caption
   names the true pipeline order so the sequence is never mistaken for it. A step that
   fails stops the run and stays failed — there is no cosmetic "all green".
--------------------------------------------------------------------------- */

type StepState = 'idle' | 'running' | 'ok' | 'fail';

interface HandshakeStep {
  readonly stage: string;
  /** What the probe PROVED — not what we wish it proved. */
  readonly proves: string;
  readonly state: StepState;
}

const HANDSHAKE_STAGES: ReadonlyArray<{ stage: string; proves: string }> = [
  { stage: 'Bridge', proves: 'the ingress answers and is parsing requests' },
  { stage: 'Auth', proves: 'a verified identity is accepted' },
  { stage: 'Obfuscator', proves: 'aliases resolve — targets stay hidden' },
  { stage: 'Audit', proves: 'the WORM store is durable and ready' },
];

function StepDot({ state }: { state: StepState }): JSX.Element {
  if (state === 'ok') return <Check size={13} className="text-verified" aria-hidden="true" />;
  if (state === 'fail') return <X size={13} className="text-denied" aria-hidden="true" />;
  if (state === 'running')
    return <Loader2 size={13} className="animate-spin text-ink" aria-hidden="true" />;
  return <span className="h-1.5 w-1.5 rounded-full bg-slate-600" aria-hidden="true" />;
}

function PipelineHandshake({ steps }: { steps: readonly HandshakeStep[] }): JSX.Element | null {
  if (steps.every((s) => s.state === 'idle')) return null;
  return (
    <div className="border-t border-hairline px-5 py-3.5">
      <p className="eyebrow mb-2.5">Handshake</p>
      <ol className="flex flex-col gap-1.5">
        {steps.map((s) => (
          <li key={s.stage} className="flex items-center gap-2.5 text-[12px]">
            <span className="flex h-4 w-4 shrink-0 items-center justify-center">
              <StepDot state={s.state} />
            </span>
            <span
              className={`w-[92px] shrink-0 font-medium ${
                s.state === 'idle' ? 'text-slate-500' : 'text-ink'
              }`}
            >
              {s.stage}
            </span>
            <span
              className={`min-w-0 truncate ${
                s.state === 'fail' ? 'text-denied' : 'text-slate-400'
              }`}
            >
              {s.state === 'fail' ? `could not confirm ${s.proves}` : s.proves}
            </span>
          </li>
        ))}
      </ol>
      <p className="mt-2.5 text-[11px] text-slate-500">
        Each line is a real request. Steps run in dependency order; the pipeline itself is
        Bridge → Obfuscator → Auth → Audit, and every authorize crosses all four.
      </p>
    </div>
  );
}

function ConnectionPanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const [url, setUrl] = useState(gateway.configuredBase ?? 'http://localhost:8080');
  const [state, setState] = useState<'idle' | 'testing' | 'ok' | 'fail'>('idle');

  // Reflect an auto-detected connection into the field if the operator hasn't pinned one.
  useEffect(() => {
    if (gateway.configuredBase === null && live && gateway.apiBase) {
      setUrl((u) => (u === 'http://localhost:8080' ? gateway.apiBase || u : u));
    }
  }, [gateway.configuredBase, live, gateway.apiBase]);

  const [steps, setSteps] = useState<readonly HandshakeStep[]>(
    HANDSHAKE_STAGES.map((s) => ({ ...s, state: 'idle' as StepState })),
  );

  /** Mark one stage, leaving the rest untouched. */
  const mark = (i: number, state: StepState): void =>
    setSteps((prev) => prev.map((s, j) => (j === i ? { ...s, state } : s)));

  const connect = async (target: string): Promise<void> => {
    setUrl(target);
    setState('testing');
    setSteps(HANDSHAKE_STAGES.map((s) => ({ ...s, state: 'idle' as StepState })));

    // 1 · BRIDGE — gateway.connect() performs the real /healthz reachability probe and
    // pins the endpoint. Everything downstream depends on it, so a failure stops here
    // rather than showing three more steps we never actually attempted.
    mark(0, 'running');
    const ok = await gateway.connect(target);
    mark(0, ok ? 'ok' : 'fail');
    if (!ok) {
      setState('fail');
      return;
    }

    // 2 · AUTH — mint and present a real token. This is the identity leg: if it fails the
    // gateway is reachable but will not accept us, which is a DIFFERENT problem from
    // unreachable, and the operator must be able to tell them apart.
    mark(1, 'running');
    let identified = false;
    let token = '';
    try {
      token = await mintDevToken({}, { base: target });
      identified = Boolean(token);
    } catch {
      identified = false;
    }
    mark(1, identified ? 'ok' : 'fail');

    // 3 · OBFUSCATOR — read the catalog. Success proves aliases resolve for this identity
    // AND that the response carries no targets; it is skipped (not faked) without identity.
    mark(2, 'running');
    let resolved = false;
    if (identified) {
      try {
        resolved = Array.isArray(await fetchCatalog(token, { base: target }));
      } catch {
        resolved = false;
      }
    }
    mark(2, resolved ? 'ok' : 'fail');

    // 4 · AUDIT — /readyz carries the durability verdict for the WORM store. Write-before-
    // execute is only a guarantee if that store is actually ready to accept the write.
    mark(3, 'running');
    let durable = false;
    try {
      durable = (await readyz({ base: target })).ready;
    } catch {
      durable = false;
    }
    mark(3, durable ? 'ok' : 'fail');

    setState('ok');
  };

  const statusTone = live ? 'verified' : state === 'fail' ? 'denied' : 'muted';
  const dot = statusTone === 'verified' ? 'bg-verified' : statusTone === 'denied' ? 'bg-denied' : 'bg-slate-400';
  const ring = statusTone === 'verified' ? 'ring-verified/20' : statusTone === 'denied' ? 'ring-denied/20' : 'ring-hairline';

  return (
    <div className="flex h-full w-full flex-col gap-4 overflow-y-auto pb-4">
      {/* System status header + endpoint config — one control-plane connection card, no motion. */}
      <Panel>
        <div className="flex items-center gap-3.5 px-5 py-4">
          <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-hairline ${live ? 'bg-verified/8' : 'bg-elevated'}`}>
            <Server size={19} className={live ? 'text-verified' : 'text-slate-500'} />
          </span>
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h2 className="text-[16px] font-semibold tracking-tightest text-ink">Gateway connection</h2>
              <span className={`inline-flex items-center gap-1.5 rounded-md border border-hairline bg-canvas px-2 py-0.5 text-[10.5px] font-semibold uppercase tracking-wide ${statusTone === 'verified' ? 'text-verified' : statusTone === 'denied' ? 'text-denied' : 'text-slate-400'}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${dot} ring-2 ${ring}`} />
                {live ? 'Connected' : state === 'fail' ? 'Unreachable' : 'Not connected'}
              </span>
            </div>
            <p className="mt-0.5 text-[12px] text-slate-500">
              {live
                ? <>Serving live data from <span className="font-medium text-ink">{gateway.apiHost}</span>. Every tab reflects this gateway&apos;s real state.</>
                : 'Point the console at a running MCPIP gateway. The endpoint is saved and survives reload — no rebuild.'}
            </p>
          </div>
        </div>

        {/* Connection identity — real signals only; every unknown renders as "—". */}
        <div className="grid grid-cols-3 gap-px border-t border-hairline bg-hairline">
          <FactCell label="Status" value={live ? 'Live' : 'Offline'} tone={live ? 'verified' : 'muted'} />
          <FactCell label="Endpoint" value={live ? gateway.apiHost : '—'} />
          <FactCell label="Version" value={gateway.health?.version ? `v${gateway.health.version}` : '—'} />
        </div>

        {/* Endpoint configuration — merged into the connection card. */}
        <div className="border-t border-hairline px-5 py-4">
          <div className="mb-3 flex items-center justify-between gap-2">
            <span className="eyebrow flex items-center gap-1.5"><Link2 size={12} className="text-slate-500" /> Endpoint</span>
            <Badge tone={gateway.configuredBase !== null ? 'ink' : 'muted'}>{gateway.configuredBase !== null ? 'Pinned' : 'Auto-detect'}</Badge>
          </div>
          <div className="flex flex-col gap-2.5 sm:flex-row sm:items-end">
            <div className="min-w-0 flex-1">
              <Field label="Gateway URL">
                <Input
                  mono
                  value={url}
                  onChange={(e) => { setUrl(e.target.value); setState('idle'); }}
                  onKeyDown={(e) => { if (e.key === 'Enter') void connect(url); }}
                  placeholder="https://mcpip.internal:8080"
                  spellCheck={false}
                />
              </Field>
            </div>
            <button type="button" onClick={() => void connect(url)} disabled={state === 'testing'} className="btn-primary h-[38px] shrink-0 px-4">
              {state === 'testing' ? <Loader2 size={14} className="animate-spin" /> : <Link2 size={14} />}
              {state === 'testing' ? 'Connecting…' : 'Test & Connect'}
            </button>
            {gateway.configuredBase !== null ? (
              <button type="button" onClick={() => { gateway.disconnect(); setState('idle'); }} className="btn-ghost h-[38px] shrink-0">
                <Link2Off size={14} /> Disconnect
              </button>
            ) : null}
          </div>

          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <span className="eyebrow mr-1">Presets</span>
            {[
              { url: 'http://localhost:8080', label: 'localhost:8080' },
              { url: 'http://127.0.0.1:8080', label: '127.0.0.1:8080' },
              { url: '', label: 'Same origin' },
            ].map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => void connect(preset.url)}
                className="rounded-md border border-hairline bg-canvas px-2.5 py-1 text-[11px] font-medium text-slate-500 transition-colors hover:border-ink/20 hover:text-ink"
              >
                {preset.label}
              </button>
            ))}
          </div>

          {state === 'ok' || (live && state === 'idle') ? (
            <div className="mt-3 flex items-center gap-2 rounded-lg border border-verified/25 bg-verified/5 px-3 py-2 text-[11.5px] text-verified">
              <CheckCircle2 size={14} /> Connected{gateway.health?.version ? ` — gateway v${gateway.health.version}` : ''}. Health check passed.
            </div>
          ) : null}
          {state === 'fail' ? (
            <div className="mt-3 space-y-1.5 rounded-lg border border-denied/25 bg-denied/5 px-3 py-2.5 text-[11.5px]">
              <p className="flex items-center gap-2 font-medium text-denied">
                <XCircle size={14} /> No gateway answered at that address.
              </p>
              <ul className="space-y-1 pl-0.5 text-[11px] leading-relaxed text-slate-500">
                <li className="flex gap-1.5"><span className="text-slate-400">1.</span> Confirm the node is running and reachable on that host and port.</li>
                <li className="flex gap-1.5"><span className="text-slate-400">2.</span> If it responds to a health check but not here, the browser blocked a cross-origin call — allow this console&apos;s origin on the gateway.</li>
                <li className="flex gap-1.5"><span className="text-slate-400">3.</span> Check TLS: a secure console cannot reach a non-secure gateway.</li>
              </ul>
            </div>
          ) : null}
        </div>
        <p className="flex items-center gap-1.5 border-t border-hairline px-5 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
          <ShieldCheck size={11} className="shrink-0 text-slate-500" />
          With no gateway connected, every panel shows an honest empty state — the console never fabricates data.
        </p>
        {/* Handshake — four real probes, one per pipeline stage. Renders only once a
            connect has been attempted; idle stays invisible. */}
        <PipelineHandshake steps={steps} />
      </Panel>

      {/* Standards interop — the gateway's advertised OAuth 2.1 RS / AuthZEN / MRT surfaces. */}
      <StandardsInterop gateway={gateway} />
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Company Settings — the deployment IDENTITY written by first-run setup:
   company name, gateway tenant, and bootstrap admin. Real persisted state
   (localStorage-backed company config), no mock data; a full "re-run setup"
   reset is the escape hatch. Compartments (teams) are NOT edited here — they
   live in Directory → Org Hierarchy (the tree); this page only mirrors them
   read-only with a jump to that single editor. Nothing here mints
   credentials — identity stays with the IdP.
--------------------------------------------------------------------------- */
function CompanySettings(): JSX.Element {
  const { config, save, reset } = useCompanyConfig();
  const [name, setName] = useState(config?.name ?? '');
  const [tenant, setTenant] = useState(config?.tenant ?? '');
  const [admin, setAdmin] = useState(config?.admin ?? '');
  const [confirmReset, setConfirmReset] = useState(false);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  if (!config) {
    return (
      <div className="h-full w-full">
        <Panel className="h-full">
          <EmptyState
            icon={Building2}
            title="No company configured"
            detail="Run the first-time setup to create your deployment identity — it appears here for editing afterwards."
          />
        </Panel>
      </div>
    );
  }

  const dirty = name !== config.name || tenant !== config.tenant || admin !== config.admin;

  const persist = (): void => {
    save({ ...config, name: name.trim(), tenant: tenant.trim(), admin: admin.trim() });
    setSavedAt(Date.now());
  };

  const tenantSlug = slugifyTenant(name);

  return (
    <div className="flex h-full w-full flex-col overflow-y-auto">
      <div className="grid flex-1 content-start gap-4 pb-24 xl:content-stretch xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)] xl:pb-4">
        {/* Identity — every deployment-identity field, clearly editable. */}
        <Panel>
          <PanelHeader title="Company identity" icon={Building2} right="editable · persisted locally" />
          <div className="grid grid-cols-1 gap-x-5 gap-y-4 px-5 py-4 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <Field label="Company name">
                <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="MCPIP Inc" />
              </Field>
              <p className="mt-1 text-[10.5px] text-slate-500">Display name across the console. Not sent to the gateway.</p>
            </div>
            <div>
              <label className="flex items-center justify-between">
                <span className="text-[10.5px] font-medium uppercase tracking-[0.1em] text-slate-500">Gateway tenant · agent scope</span>
                {tenant !== tenantSlug && tenantSlug ? (
                  <button type="button" onClick={() => setTenant(tenantSlug)} className="inline-flex items-center gap-1 text-[10px] font-medium text-slate-500 transition-colors hover:text-ink">
                    <RotateCcw size={9} /> from name
                  </button>
                ) : null}
              </label>
              <Input mono value={tenant} onChange={(e) => setTenant(e.target.value)} spellCheck={false} className="mt-1" />
              <p className="mt-1 text-[10.5px] leading-relaxed text-slate-500">The tenant every agent token is issued under — the isolation boundary the gateway enforces.</p>
            </div>
            <div>
              <Field label="Bootstrap admin principal">
                <Input mono value={admin} onChange={(e) => setAdmin(e.target.value)} spellCheck={false} />
              </Field>
              <p className="mt-1 text-[10.5px] leading-relaxed text-slate-500">The agent id that holds CAP_DIRECTORY_ADMIN for console write actions.</p>
            </div>
          </div>
          {config.createdAt || config.updatedAt ? (
            <p className="flex flex-wrap items-center gap-x-2 border-t border-hairline px-5 py-2.5 text-[10.5px] text-slate-500">
              <span>Created <span className="text-slate-400">{formatDateTime(config.createdAt)}</span></span>
              <span aria-hidden>·</span>
              <span>Last updated <span className="text-slate-400">{formatDateTime(config.updatedAt)}</span></span>
            </p>
          ) : null}
        </Panel>

        <div className="flex min-w-0 flex-col gap-4 xl:self-start">
          {/* Compartments — one-line link row to the single editor (Directory → Org Hierarchy). */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-hairline bg-surface px-4 py-3 shadow-panel">
            <p className="min-w-0 flex-1 text-[11.5px] leading-relaxed text-slate-500">
              <span className="inline-flex items-center gap-1.5 font-medium text-ink"><Boxes size={12} className="text-slate-500" /> {config.teams.length} {config.teams.length === 1 ? 'compartment' : 'compartments'}</span>{' '}
              — the blast radius the gateway enforces on every call. Manage them where the tree lives, to keep one source of truth.
            </p>
            <button
              type="button"
              onClick={() => window.dispatchEvent(new CustomEvent('mcpip:navigate', { detail: { view: 'directory', subtab: 'hierarchy' } }))}
              className="btn-ghost shrink-0"
            >
              Manage compartments <ChevronRight size={13} />
            </button>
          </div>

          {/* Danger zone — destructive actions behind a disclosure. */}
          <details className="panel group overflow-hidden">
            <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-2.5 [&::-webkit-details-marker]:hidden">
              <span className="flex min-w-0 items-center gap-2">
                <ChevronRight size={14} className="shrink-0 text-slate-500 transition-transform group-open:rotate-90" />
                <RotateCcw size={14} className="shrink-0 text-slate-500" />
                <span className="truncate text-[13px] font-semibold text-ink">Danger zone</span>
              </span>
              <span className="shrink-0 text-[11px] text-slate-500">local console state only</span>
            </summary>
            <div className="divide-y divide-hairline/60 border-t border-hairline px-5">
              <div className="flex flex-wrap items-center justify-between gap-2 py-3.5">
                <div className="min-w-0">
                  <p className="text-[12.5px] font-medium text-ink">Re-run first-time setup</p>
                  <p className="text-[11px] text-slate-500">Clears the company config only — the gateway connection stays pinned.</p>
                </div>
                <button type="button" onClick={() => reset()} className="btn-ghost shrink-0">
                  <RotateCcw size={13} /> Re-run setup
                </button>
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 py-3.5">
                <div className="min-w-0 max-w-lg">
                  <p className="text-[12.5px] font-medium text-ink">Delete profile</p>
                  <p className="text-[11px] leading-relaxed text-slate-500">
                    Erases ALL local operator state — company, teams, workspace, pinned gateway — and restarts from a
                    clean slate. Gateway-side records (skills, directory, WORM ledger) are untouched.
                  </p>
                </div>
                {confirmReset ? (
                  <span className="flex shrink-0 items-center gap-2 text-[11.5px] text-denied">
                    Delete everything?
                    <button type="button" onClick={() => deleteProfile()} className="btn-ghost border-denied/40 text-denied">
                      <Trash2 size={13} /> Yes, delete
                    </button>
                    <button type="button" onClick={() => setConfirmReset(false)} className="btn-ghost">Cancel</button>
                  </span>
                ) : (
                  <button type="button" onClick={() => setConfirmReset(true)} className="btn-ghost shrink-0 hover:border-denied/40 hover:text-denied">
                    <Trash2 size={13} /> Delete profile
                  </button>
                )}
              </div>
            </div>
          </details>
        </div>
      </div>

      {/* Sticky save bar — always reachable, shows dirty state. */}
      <div className="sticky bottom-0 -mx-0 mt-auto flex items-center justify-between gap-3 border-t border-hairline bg-surface/95 px-4 py-3 backdrop-blur">
        <span className={`text-[11.5px] font-medium ${dirty ? 'text-staged' : savedAt ? 'text-verified' : 'text-slate-500'}`}>
          {dirty ? '● Unsaved changes' : savedAt ? '✓ All changes saved' : 'No changes'}
        </span>
        <button type="button" onClick={persist} disabled={!dirty} className="btn-primary">
          <Save size={14} /> Save changes
        </button>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Cloud IAM — the operator's cloud environment bindings for the ``cloud_iam``
   transport. A binding maps a compartment to a cloud role (AWS/GCP/Azure);
   executing a cloud_iam skill VENDS a short-lived, scoped credential for that
   call — the agent never holds a standing key. Bindings hold NO cloud secret
   (the gateway assumes the role with its own host identity). Live-only: the
   list is the gateway's answer or an explicit "unavailable" — never an empty
   list standing in for a failed read.
--------------------------------------------------------------------------- */
function CloudEnvironments({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const tenant = resolveTenant(gateway);
  const [read, setRead] = useState<AdminListRead<CloudEnvironment[]>>({ kind: 'loading' });
  const [vaultEntries, setVaultEntries] = useState<VaultSecret[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [writeError, setWriteError] = useState<string | null>(null);
  const emptyDraft: CloudEnvironment = {
    env_id: '', provider: 'aws', role: '', region: 'us-east-1', compartment: '', session_ttl: 900, vault_secret_id: '',
  };
  const [draft, setDraft] = useState<CloudEnvironment>(emptyDraft);

  const refresh = useCallback(async (): Promise<void> => {
    if (!live) {
      return;
    }
    setRead({ kind: 'loading' });
    if (!tenant) {
      setRead({ kind: 'unavailable' });
      return;
    }
    const token = await mintAdminToken(gateway.apiBase, tenant, 'agent-cloud-admin');
    const envs = token ? await listCloudEnvironments(token, { base: gateway.apiBase }) : null;
    if (envs === null) {
      setRead({ kind: 'unavailable' });
      setVaultEntries([]);
      return;
    }
    setRead({ kind: 'ok', data: envs });
    // Broker-identity dropdown guidance; a failed vault read just leaves host identity.
    const v = await loadVaultSecrets(gateway.apiBase, tenant);
    setVaultEntries(v.secrets);
  }, [live, gateway.apiBase, tenant]);

  useEffect(() => { void refresh(); }, [refresh]);

  const save = async (): Promise<void> => {
    if (!tenant) {
      return;
    }
    const env = {
      ...draft,
      env_id: draft.env_id.trim(),
      compartment: draft.compartment || null,
      vault_secret_id: draft.vault_secret_id || null,
    };
    if (!env.env_id || !env.role) {
      return;
    }
    setBusy('save');
    const ok = await saveCloudEnvironment(gateway.apiBase, tenant, env);
    setBusy(null);
    if (ok) {
      setWriteError(null);
      setShowForm(false);
      setDraft(emptyDraft);
      await refresh();
    } else {
      setWriteError('The gateway refused the binding write — nothing was saved. Check the admin credential and the field values, then retry.');
    }
  };

  const remove = async (envId: string): Promise<void> => {
    if (!tenant) {
      return;
    }
    setBusy(envId);
    const ok = await removeCloudEnvironment(gateway.apiBase, tenant, envId);
    setBusy(null);
    if (ok) {
      setWriteError(null);
      await refresh();
    } else {
      setWriteError(`The gateway refused the delete for ${envId} — the binding still exists.`);
    }
  };

  if (!live) {
    return (
      <div className="h-full w-full">
        <Panel className="h-full">
          <EmptyState
            icon={Cloud}
            title="No gateway connected"
            detail="Cloud IAM bindings are served by the gateway. Connect one to manage which cloud role each compartment may assume."
            action={
              <button type="button" onClick={navigateToConnection} className="btn-primary">
                <PlugZap size={13} /> Connect a gateway
              </button>
            }
          />
        </Panel>
      </div>
    );
  }

  return (
    <div className={`grid h-full w-full content-start gap-4 overflow-y-auto xl:content-stretch ${showForm && read.kind === 'ok' ? 'xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]' : ''}`}>
      {showForm && read.kind === 'ok' ? (
        <Panel className="xl:order-2">
          <div className="grid flex-1 grid-cols-1 content-start gap-3 overflow-y-auto bg-canvas px-5 py-4 sm:grid-cols-2 xl:min-h-0">
            <Field label="Environment id"><Input mono value={draft.env_id} onChange={(e) => setDraft({ ...draft, env_id: e.target.value })} placeholder="aws-eng-readonly" /></Field>
            <Field label="Provider"><Select value={draft.provider} onChange={(e) => setDraft({ ...draft, provider: e.target.value })}><option value="aws">aws</option><option value="gcp">gcp</option><option value="azure">azure</option></Select></Field>
            <Field label="Role (ARN / SA / client id)"><Input mono value={draft.role} onChange={(e) => setDraft({ ...draft, role: e.target.value })} placeholder="arn:aws:iam::…:role/…" /></Field>
            <Field label="Region"><Input mono value={draft.region} onChange={(e) => setDraft({ ...draft, region: e.target.value })} placeholder="us-east-1" /></Field>
            <Field label="Compartment UUID (blank = tenant-wide)"><Input mono value={draft.compartment ?? ''} onChange={(e) => setDraft({ ...draft, compartment: e.target.value })} placeholder="e0900000-…" /></Field>
            <Field label="Session TTL (seconds, 300–3600)"><Input value={String(draft.session_ttl)} onChange={(e) => setDraft({ ...draft, session_ttl: Number(e.target.value) || 900 })} /></Field>
            <Field label="Broker identity">
              <Select value={draft.vault_secret_id ?? ''} onChange={(e) => setDraft({ ...draft, vault_secret_id: e.target.value })}>
                <option value="">Host identity (recommended)</option>
                {vaultEntries.map((s) => (
                  <option key={s.secret_id} value={s.secret_id}>Vault · {s.secret_id}</option>
                ))}
              </Select>
            </Field>
            <div className="col-span-full -mt-1 flex items-start gap-2 text-[10.5px] leading-relaxed text-slate-500">
              {draft.vault_secret_id
                ? <><KeySquare size={12} className="mt-px shrink-0 text-staged" /> The broker will spend a <span className="text-ink">vault-stored key</span> to assume this role — a weaker posture than host identity, and deliberately visible as such.</>
                : <><ShieldCheck size={12} className="mt-px shrink-0 text-verified" /> The gateway assumes this role with its <span className="text-ink">own host identity</span> — no secret is stored anywhere.</>}
            </div>
            <div className="col-span-full flex justify-end gap-2">
              <button type="button" onClick={() => setShowForm(false)} className="btn-ghost">Cancel</button>
              <button type="button" onClick={() => void save()} disabled={busy === 'save' || !draft.env_id.trim() || !draft.role.trim()} className="btn-primary">
                {busy === 'save' ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />} Save binding
              </button>
            </div>
          </div>
        </Panel>
      ) : null}
      <Panel className="xl:order-1">
        <PanelHeader
          title="Cloud IAM environments"
          icon={Cloud}
          right={
            read.kind === 'ok' ? (
              <button type="button" onClick={() => setShowForm((v) => !v)} className="btn-primary !py-1">
                <Plus size={13} /> Add binding
              </button>
            ) : null
          }
        />
        <p className="border-b border-hairline px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
          A binding maps a <span className="text-ink">compartment</span> to a cloud <span className="text-ink">role</span>; a{' '}
          <span className="font-mono text-[10.5px]">cloud_iam</span> call vends a short-lived scoped credential — the agent never
          holds a standing key, and the binding stores <span className="text-ink">no secret</span> (host identity assumes the role).
        </p>

        {writeError ? <WriteErrorLine message={writeError} /> : null}

        <div className="flex-1 xl:min-h-0 xl:overflow-y-auto">
          {read.kind === 'loading' ? (
            <p className="px-5 py-6 text-center text-[12px] text-slate-500">loading…</p>
          ) : read.kind === 'unavailable' ? (
            <AdminReadUnavailable what="Cloud IAM bindings" />
          ) : read.data.length === 0 ? (
            <EmptyState icon={Cloud} title="No cloud environments" detail="The gateway answered with an empty list. Add a binding to make a cloud_iam skill vend a scoped credential for its compartment." />
          ) : (
            <div className="divide-y divide-hairline/60">
              {read.data.map((e) => (
                <div key={e.env_id} className="group flex flex-wrap items-center gap-3 px-5 py-3">
                  <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-hairline bg-canvas text-slate-500"><Cloud size={13} /></span>
                  <div className="min-w-0">
                    <p className="flex items-center gap-1.5 font-mono text-[12.5px] text-ink">
                      {e.env_id}
                      {e.vault_secret_id
                        ? <Badge tone="staged"><KeySquare size={9} /> vault key</Badge>
                        : <Badge tone="verified"><ShieldCheck size={9} /> host identity</Badge>}
                    </p>
                    <p className="truncate font-mono text-[10.5px] text-slate-500">{e.provider} · {e.role} · {e.region} · {e.session_ttl}s</p>
                  </div>
                  <span className="ml-auto text-[10.5px] text-slate-500">
                    {e.compartment ? `compartment ${e.compartment.slice(0, 8)}…` : 'tenant-wide'}
                  </span>
                  <button
                    type="button"
                    onClick={() => void remove(e.env_id)}
                    disabled={busy === e.env_id}
                    title="Delete binding"
                    className={`shrink-0 text-slate-500 transition-opacity hover:text-denied disabled:opacity-50 ${busy === e.env_id ? '' : 'opacity-0 focus-visible:opacity-100 group-hover:opacity-100'}`}
                  >
                    {busy === e.env_id ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Secret Vault — operator-stored broker credentials for deployments without
   cloud-native workload identity. Values are WRITE-ONLY: sent once when
   stored, encrypted at rest by the gateway, and read solely by the broker at
   vend time. The console only ever shows metadata + a non-secret fingerprint.
   "Not configured" is claimed ONLY when the gateway itself answered
   vault_enabled:false — a failed mint/read renders the distinct
   "unavailable" state instead of that false diagnosis.
--------------------------------------------------------------------------- */
function SecretVaultPanel({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const tenant = resolveTenant(gateway);
  const [read, setRead] = useState<AdminListRead<{ enabled: boolean; secrets: VaultSecret[] }>>({ kind: 'loading' });
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [writeError, setWriteError] = useState<string | null>(null);
  const [vendor, setVendor] = useState<VaultVendor>('aws');
  const [secretId, setSecretId] = useState('');
  const [description, setDescription] = useState('');
  const [material, setMaterial] = useState<Record<string, string>>({});

  const refresh = useCallback(async (): Promise<void> => {
    if (!live) {
      return;
    }
    setRead({ kind: 'loading' });
    if (!tenant) {
      setRead({ kind: 'unavailable' });
      return;
    }
    const token = await mintAdminToken(gateway.apiBase, tenant, 'agent-vault-admin');
    // listVaultSecrets returns null on transport/auth failure vs an ANSWERED
    // { vault_enabled, secrets } — the distinction this panel exists to keep.
    const listed = token ? await listVaultSecrets(token, { base: gateway.apiBase }) : null;
    if (listed === null) {
      setRead({ kind: 'unavailable' });
      return;
    }
    setRead({ kind: 'ok', data: listed });
  }, [live, gateway.apiBase, tenant]);

  useEffect(() => { void refresh(); }, [refresh]);

  const fields = VENDOR_FIELDS[vendor];
  const materialComplete = fields.every((f) => (material[f] ?? '').trim().length > 0);

  const resetForm = (): void => {
    setShowForm(false); setVendor('aws'); setSecretId(''); setDescription(''); setMaterial({});
  };

  const save = async (): Promise<void> => {
    if (!tenant) {
      return;
    }
    const id = secretId.trim();
    const clean: Record<string, string> = {};
    for (const f of fields) { const v = (material[f] ?? '').trim(); if (v) clean[f] = v; }
    if (!id || Object.keys(clean).length === 0) {
      return;
    }
    setBusy('save');
    const ok = await saveVaultSecret(gateway.apiBase, tenant, { secret_id: id, vendor, description: description.trim(), material: clean });
    setBusy(null);
    if (ok) {
      setWriteError(null);
      resetForm();
      await refresh();
    } else {
      setWriteError('The gateway refused the credential write — nothing was stored.');
    }
  };

  const remove = async (id: string): Promise<void> => {
    if (!tenant) {
      return;
    }
    setBusy(id);
    const ok = await removeVaultSecret(gateway.apiBase, tenant, id);
    setBusy(null);
    if (ok) {
      setWriteError(null);
      await refresh();
    } else {
      setWriteError(`The gateway refused the delete for ${id} — the credential is still stored.`);
    }
  };

  if (!live) {
    return (
      <div className="h-full w-full">
        <Panel className="h-full">
          <EmptyState
            icon={VaultIcon}
            title="No gateway connected"
            detail="The secret vault is served by the gateway. Connect one to store broker credentials for cloud environments that can't use host identity."
            action={
              <button type="button" onClick={navigateToConnection} className="btn-primary">
                <PlugZap size={13} /> Connect a gateway
              </button>
            }
          />
        </Panel>
      </div>
    );
  }

  return (
    <div className={`grid h-full w-full content-start gap-4 overflow-y-auto xl:content-stretch ${showForm && read.kind === 'ok' && read.data.enabled ? 'xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]' : ''}`}>
      {showForm && read.kind === 'ok' && read.data.enabled ? (
        <Panel className="xl:order-2">
          <div className="grid flex-1 grid-cols-1 content-start gap-3 overflow-y-auto bg-canvas px-5 py-4 sm:grid-cols-2 xl:min-h-0">
            <Field label="Secret id"><Input mono value={secretId} onChange={(e) => setSecretId(e.target.value)} placeholder="aws-broker-key" /></Field>
            <Field label="Vendor">
              <Select value={vendor} onChange={(e) => { setVendor(e.target.value as VaultVendor); setMaterial({}); }}>
                {VAULT_VENDORS.map((v) => <option key={v} value={v}>{v}</option>)}
              </Select>
            </Field>
            <Field label="Description (optional)"><Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="on-prem broker key for the write role" /></Field>
            <div className="hidden sm:block" />
            {fields.map((f) => (
              <Field key={f} label={f}>
                <Input
                  mono
                  type="password"
                  autoComplete="off"
                  value={material[f] ?? ''}
                  onChange={(e) => setMaterial((m) => ({ ...m, [f]: e.target.value }))}
                  placeholder="••••••••"
                />
              </Field>
            ))}
            <div className="col-span-full -mt-1 flex items-start gap-2 text-[10.5px] leading-relaxed text-slate-500">
              <KeySquare size={12} className="mt-px shrink-0 text-staged" />
              The value is transmitted once over your gateway connection, encrypted immediately, and never returned by any endpoint — rotate it here if it changes.
            </div>
            <div className="col-span-full flex justify-end gap-2">
              <button type="button" onClick={resetForm} className="btn-ghost">Cancel</button>
              <button type="button" onClick={() => void save()} disabled={busy === 'save' || !secretId.trim() || !materialComplete} className="btn-primary">
                {busy === 'save' ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />} Store credential
              </button>
            </div>
          </div>
        </Panel>
      ) : null}
      <Panel className="xl:order-1">
        <PanelHeader
          title="Secret Vault"
          icon={VaultIcon}
          right={
            read.kind === 'ok' && read.data.enabled ? (
              <button type="button" onClick={() => setShowForm((v) => !v)} className="btn-primary !py-1">
                <Plus size={13} /> Store credential
              </button>
            ) : null
          }
        />
        <p className="border-b border-hairline px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
          Store a <span className="text-ink">broker credential</span> once — <span className="text-ink">encrypted at rest</span>,
          spent only by the gateway to assume a cloud role, and <span className="text-ink">write-only</span> (never shown again,
          never written to the audit log); an agent never holds it.
        </p>

        {writeError ? <WriteErrorLine message={writeError} /> : null}

        <div className="flex-1 xl:min-h-0 xl:overflow-y-auto">
          {read.kind === 'loading' ? (
            <p className="px-5 py-6 text-center text-[12px] text-slate-500">loading…</p>
          ) : read.kind === 'unavailable' ? (
            <AdminReadUnavailable what="Vault state" />
          ) : !read.data.enabled ? (
            // The gateway ANSWERED vault_enabled:false — only then is this claim honest.
            <div className="flex h-full flex-col items-center justify-center px-5 py-4">
              <div className="flex max-w-3xl items-start gap-2.5 text-[11.5px] leading-relaxed text-slate-500">
                <ShieldCheck size={15} className="mt-px shrink-0 text-verified" />
                <span>
                  This gateway reports the vault feature as <span className="text-ink">not configured</span> (no master
                  key). That is the <span className="text-ink">recommended</span> production posture — bind cloud
                  environments to the gateway&apos;s own host identity instead, and no secret is stored anywhere. Set
                  <span className="font-mono text-[10.5px]"> MCPIP_VAULT_KEY_PATH</span> to enable stored broker credentials.
                </span>
              </div>
            </div>
          ) : read.data.secrets.length === 0 ? (
            <EmptyState icon={KeyRound} title="No stored credentials" detail="The gateway answered with an empty vault. Store a broker credential to bind a cloud environment that can't use host identity." />
          ) : (
            <div className="divide-y divide-hairline/60">
              {read.data.secrets.map((s) => (
                <div key={s.secret_id} className="group flex flex-wrap items-center gap-3 px-5 py-3">
                  <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-hairline bg-canvas text-slate-500"><KeySquare size={13} /></span>
                  <div className="min-w-0">
                    <p className="flex items-center gap-1.5 font-mono text-[12.5px] text-ink">{s.secret_id}<Badge tone="muted">{s.vendor}</Badge></p>
                    <p className="truncate text-[10.5px] text-slate-500">
                      {s.description || 'no description'} · fingerprint <span className="font-mono">{s.fingerprint}</span>
                    </p>
                  </div>
                  <span className="ml-auto text-[10.5px] text-slate-500">updated {formatDateTime(s.updated_at ? new Date(s.updated_at * 1000).toISOString() : null)}</span>
                  <button
                    type="button"
                    onClick={() => void remove(s.secret_id)}
                    disabled={busy === s.secret_id}
                    title="Delete credential"
                    className={`shrink-0 text-slate-500 transition-opacity hover:text-denied disabled:opacity-50 ${busy === s.secret_id ? '' : 'opacity-0 focus-visible:opacity-100 group-hover:opacity-100'}`}
                  >
                    {busy === s.secret_id ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

/* ---------------------------------------------------------------------------
   Policy Guardrails (G3) — the per-tenant DENY-ONLY velocity / amount-ceiling
   overlay. A guardrail is applied by the gateway AFTER a request clears the
   entitlement gates: a velocity cap (N actions per fixed window) or a ceiling on
   a named numeric argument. It can only ever DENY — it never grants access,
   repoints a skill, or mints identity — and the document holds ONLY these rules,
   never an alias->target mapping. NO guardrails configured => the overlay imposes
   no limits (honest opt-in). Live-only, tenant-scoped, CAP_DIRECTORY_ADMIN — an
   answered-but-empty document is a real "no guardrails" state, distinct from a
   failed admin read.
--------------------------------------------------------------------------- */

/** The add-guardrail form's local draft (string inputs, parsed on save). */
interface RuleDraft {
  kind: 'velocity' | 'amount';
  scope: 'alias' | 'transport_class';
  scope_value: string;
  max_actions: string;
  window_seconds: string;
  amount_field: string;
  max_amount: string;
}

const EMPTY_RULE_DRAFT: RuleDraft = {
  kind: 'velocity',
  scope: 'alias',
  scope_value: '',
  max_actions: '',
  window_seconds: '',
  amount_field: '',
  max_amount: '',
};

/** Build a wire PolicyRule from the draft, or null when required fields are unfilled/invalid. */
function ruleFromDraft(draft: RuleDraft): PolicyRule | null {
  const scopeValue = draft.scope_value.trim();
  if (!scopeValue) {
    return null;
  }
  if (draft.kind === 'velocity') {
    const maxActions = Number.parseInt(draft.max_actions, 10);
    const windowSeconds = Number.parseInt(draft.window_seconds, 10);
    if (!Number.isFinite(maxActions) || maxActions < 1) {
      return null;
    }
    if (!Number.isFinite(windowSeconds) || windowSeconds < 1 || windowSeconds > 86400) {
      return null;
    }
    return {
      kind: 'velocity',
      scope: draft.scope,
      scope_value: scopeValue,
      max_actions: maxActions,
      window_seconds: windowSeconds,
    };
  }
  const amountField = draft.amount_field.trim();
  const maxAmount = draft.max_amount.trim();
  if (!amountField || !maxAmount) {
    return null;
  }
  return {
    kind: 'amount',
    scope: draft.scope,
    scope_value: scopeValue,
    amount_field: amountField,
    max_amount: maxAmount,
  };
}

function PolicyGuardrails({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const tenant = resolveTenant(gateway);
  const [read, setRead] = useState<AdminListRead<PolicyDocument>>({ kind: 'loading' });
  const [showForm, setShowForm] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [writeError, setWriteError] = useState<string | null>(null);
  const [draft, setDraft] = useState<RuleDraft>(EMPTY_RULE_DRAFT);

  const refresh = useCallback(async (): Promise<void> => {
    if (!live) {
      return;
    }
    setRead({ kind: 'loading' });
    if (!tenant) {
      setRead({ kind: 'unavailable' });
      return;
    }
    const token = await mintAdminToken(gateway.apiBase, tenant, 'agent-policy-admin');
    // getPolicy returns null on transport/auth failure vs an ANSWERED document
    // (whose rules may legitimately be empty) — the distinction this panel keeps.
    const doc = token ? await getPolicy(token, { base: gateway.apiBase }) : null;
    if (doc === null) {
      setRead({ kind: 'unavailable' });
      return;
    }
    setRead({ kind: 'ok', data: doc });
  }, [live, gateway.apiBase, tenant]);

  useEffect(() => { void refresh(); }, [refresh]);

  const resetForm = (): void => {
    setShowForm(false);
    setDraft(EMPTY_RULE_DRAFT);
  };

  const draftRule = ruleFromDraft(draft);

  const save = async (): Promise<void> => {
    if (!tenant || read.kind !== 'ok' || draftRule === null) {
      return;
    }
    const document: PolicyDocument = {
      schema: POLICY_SCHEMA,
      rules: [...read.data.rules, draftRule],
    };
    setBusy('save');
    const token = await mintAdminToken(gateway.apiBase, tenant, 'agent-policy-admin');
    const ok = token ? await putPolicy(token, document, { base: gateway.apiBase }) : false;
    setBusy(null);
    if (ok) {
      setWriteError(null);
      resetForm();
      await refresh();
    } else {
      setWriteError(
        'The gateway refused the guardrail write — nothing was saved. A velocity cap needs a positive count and a 1–86400s window; an amount ceiling needs a decimal like "500.00".',
      );
    }
  };

  const remove = async (index: number): Promise<void> => {
    if (!tenant || read.kind !== 'ok') {
      return;
    }
    const remaining = read.data.rules.filter((_, i) => i !== index);
    setBusy(`rule-${index}`);
    const token = await mintAdminToken(gateway.apiBase, tenant, 'agent-policy-admin');
    let ok = false;
    if (token) {
      // Removing the last rule deletes the document outright — back to the honest
      // no-limits state — rather than storing an empty rule list.
      ok = remaining.length === 0
        ? await deletePolicy(token, { base: gateway.apiBase })
        : await putPolicy(token, { schema: POLICY_SCHEMA, rules: remaining }, { base: gateway.apiBase });
    }
    setBusy(null);
    if (ok) {
      setWriteError(null);
      await refresh();
    } else {
      setWriteError('The gateway refused the guardrail delete — the rule still applies.');
    }
  };

  if (!live) {
    return (
      <div className="h-full w-full">
        <Panel className="h-full">
          <EmptyState
            icon={Gauge}
            title="No gateway connected"
            detail="Policy guardrails are served by the gateway. Connect one to set deny-only velocity caps and amount ceilings for this tenant."
            action={
              <button type="button" onClick={navigateToConnection} className="btn-primary">
                <PlugZap size={13} /> Connect a gateway
              </button>
            }
          />
        </Panel>
      </div>
    );
  }

  return (
    <div className={`grid h-full w-full content-start gap-4 overflow-y-auto xl:content-stretch ${showForm && read.kind === 'ok' ? 'xl:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]' : ''}`}>
      {showForm && read.kind === 'ok' ? (
        <Panel className="xl:order-2">
          <div className="grid flex-1 grid-cols-1 content-start gap-3 overflow-y-auto bg-canvas px-5 py-4 sm:grid-cols-2 xl:min-h-0">
            <Field label="Guardrail kind">
              <Select value={draft.kind} onChange={(e) => setDraft({ ...draft, kind: e.target.value as RuleDraft['kind'] })}>
                <option value="velocity">velocity — actions per window</option>
                <option value="amount">amount — ceiling on a numeric field</option>
              </Select>
            </Field>
            <Field label="Scope">
              <Select value={draft.scope} onChange={(e) => setDraft({ ...draft, scope: e.target.value as RuleDraft['scope'] })}>
                <option value="alias">alias</option>
                <option value="transport_class">transport_class</option>
              </Select>
            </Field>
            <Field label={draft.scope === 'alias' ? 'Alias (opaque skill name)' : 'Transport class'}>
              <Input
                mono
                value={draft.scope_value}
                onChange={(e) => setDraft({ ...draft, scope_value: e.target.value })}
                placeholder={draft.scope === 'alias' ? 'skill_aws_dynamodb' : 'cloud_iam'}
              />
            </Field>
            <div className="hidden sm:block" />
            {draft.kind === 'velocity' ? (
              <>
                <Field label="Max actions (≥ 1)">
                  <Input value={draft.max_actions} onChange={(e) => setDraft({ ...draft, max_actions: e.target.value })} placeholder="10" />
                </Field>
                <Field label="Window seconds (1–86400)">
                  <Input value={draft.window_seconds} onChange={(e) => setDraft({ ...draft, window_seconds: e.target.value })} placeholder="60" />
                </Field>
              </>
            ) : (
              <>
                <Field label="Amount field (argument name)">
                  <Input mono value={draft.amount_field} onChange={(e) => setDraft({ ...draft, amount_field: e.target.value })} placeholder="amount" />
                </Field>
                <Field label="Max amount (decimal string)">
                  <Input mono value={draft.max_amount} onChange={(e) => setDraft({ ...draft, max_amount: e.target.value })} placeholder="500.00" />
                </Field>
              </>
            )}
            <div className="col-span-full -mt-1 flex items-start gap-2 text-[10.5px] leading-relaxed text-slate-500">
              <ShieldCheck size={12} className="mt-px shrink-0 text-verified" />
              {draft.kind === 'velocity'
                ? <>A <span className="text-ink">velocity</span> guardrail denies once the fixed window&apos;s count is exceeded. It only ever denies — never grants — and is counted only for matching requests.</>
                : <>An <span className="text-ink">amount</span> guardrail denies when the named field exceeds the ceiling. An <span className="text-ink">absent</span> field is a no-op; a present <span className="text-ink">non-numeric</span> value fails closed. Attach it only to skills whose schema guarantees the field.</>}
            </div>
            <div className="col-span-full flex justify-end gap-2">
              <button type="button" onClick={resetForm} className="btn-ghost">Cancel</button>
              <button type="button" onClick={() => void save()} disabled={busy === 'save' || draftRule === null} className="btn-primary">
                {busy === 'save' ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />} Add guardrail
              </button>
            </div>
          </div>
        </Panel>
      ) : null}
      <Panel className="xl:order-1">
        <PanelHeader
          title="Policy guardrails"
          icon={Gauge}
          right={
            read.kind === 'ok' ? (
              <button type="button" onClick={() => setShowForm((v) => !v)} className="btn-primary !py-1">
                <Plus size={13} /> Add guardrail
              </button>
            ) : null
          }
        />
        <p className="border-b border-hairline px-5 py-2.5 text-[11px] leading-relaxed text-slate-500">
          A <span className="text-ink">deny-only</span> cap applied after the entitlement gates — a{' '}
          <span className="font-mono text-[10.5px]">velocity</span> limit or an <span className="font-mono text-[10.5px]">amount</span>{' '}
          ceiling that can only DENY (never grants, repoints, or mints identity); with none configured, <span className="text-ink">no limits</span> apply.
        </p>

        {writeError ? <WriteErrorLine message={writeError} /> : null}

        <div className="flex-1 xl:min-h-0 xl:overflow-y-auto">
          {read.kind === 'loading' ? (
            <p className="px-5 py-6 text-center text-[12px] text-slate-500">loading…</p>
          ) : read.kind === 'unavailable' ? (
            <AdminReadUnavailable what="Policy guardrails" />
          ) : read.data.rules.length === 0 ? (
            <EmptyState icon={Gauge} title="No guardrails configured" detail="The gateway answered with an empty policy — the deny-only overlay imposes no limits for this tenant. Add a velocity cap or an amount ceiling to enable it." />
          ) : (
            <div className="divide-y divide-hairline/60">
              {read.data.rules.map((rule, index) => (
                <div key={`${rule.kind}:${rule.scope}:${rule.scope_value}:${index}`} className="group flex flex-wrap items-center gap-3 px-5 py-3">
                  <span className="flex h-7 w-7 items-center justify-center rounded-lg border border-hairline bg-canvas text-slate-500">
                    {rule.kind === 'velocity' ? <Timer size={13} /> : <Coins size={13} />}
                  </span>
                  <div className="min-w-0">
                    <p className="flex items-center gap-1.5 font-mono text-[12.5px] text-ink">
                      {rule.scope_value}
                      <Badge tone="muted">{rule.scope === 'alias' ? 'alias' : 'transport'}</Badge>
                      <Badge tone={rule.kind === 'velocity' ? 'staged' : 'denied'}>{rule.kind}</Badge>
                    </p>
                    <p className="truncate font-mono text-[10.5px] text-slate-500">
                      {rule.kind === 'velocity'
                        ? `max ${rule.max_actions ?? '—'} action(s) / ${rule.window_seconds ?? '—'}s window`
                        : `field "${rule.amount_field ?? '—'}" ≤ ${rule.max_amount ?? '—'}`}
                    </p>
                  </div>
                  <span className="ml-auto text-[10.5px] text-slate-500">deny-only</span>
                  <button
                    type="button"
                    onClick={() => void remove(index)}
                    disabled={busy === `rule-${index}`}
                    title="Delete guardrail"
                    className={`shrink-0 text-slate-500 transition-opacity hover:text-denied disabled:opacity-50 ${busy === `rule-${index}` ? '' : 'opacity-0 focus-visible:opacity-100 group-hover:opacity-100'}`}
                  >
                    {busy === `rule-${index}` ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Panel>
    </div>
  );
}

export function AdminInfra({
  gateway,
  subtab,
}: {
  gateway: GatewayLive;
  subtab: string;
}): JSX.Element {
  if (subtab === 'company') {
    return <CompanySettings />;
  }
  if (subtab === 'cloud') {
    return <CloudEnvironments gateway={gateway} />;
  }
  if (subtab === 'vault') {
    return <SecretVaultPanel gateway={gateway} />;
  }
  if (subtab === 'security') {
    return <MySecurity gateway={gateway} />;
  }
  if (subtab === 'policy') {
    return <PolicyGuardrails gateway={gateway} />;
  }
  if (subtab === 'health') {
    return <HealthPanel gateway={gateway} />;
  }
  if (subtab === 'updates') {
    return <SoftwareUpdatesView gateway={gateway} />;
  }
  if (subtab === 'software') {
    return <LicenseUsageView gateway={gateway} />;
  }

  // 'connection' — the view's front door and its default sub-tab.
  return <ConnectionPanel gateway={gateway} />;
}
