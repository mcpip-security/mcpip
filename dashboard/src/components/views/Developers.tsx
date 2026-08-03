/* ---------------------------------------------------------------------------
   Developers — the console side of the SDK story: everything a developer
   needs to wire an agent to THIS gateway, SDK quickstarts included.

   Two subtabs. `connect`: the MCP endpoint (protocol 2025-06-18) with a
   ready-to-paste .mcp.json and the REST choke point with a curl snippet as
   the visible screen; a collapsed "Protocol reference" accordion folds in
   the JWT contract (8 required claims, EdDSA/RS256 only), the PIN step-up
   ceremony, the two shipped SDKs (sdk/python · sdk/typescript, one snippet
   toggle sharing one fact list), and the {host}/openapi.json + {host}/docs
   references. `console`: the interactive API console. The opaque-deny
   envelope is explained once, folded into the REST panel's responses. A
   real live round-trip lives in the Authorize Probe (one deep-link here).

   Honesty rules: the operator's REAL host, first catalog alias, and tenant
   are substituted into every snippet while live; offline they become
   explicit <angle-bracket> placeholders — never a fabricated endpoint.
   Every protocol fact on this page is quoted from the wire contract
   (app/main.py · models/schemas.py · interfaces.py), not invented.
--------------------------------------------------------------------------- */

import { useState } from 'react';
import {
  ArrowUpRight,
  BookOpen,
  Braces,
  Fingerprint,
  KeyRound,
  Package,
  Play,
  PlugZap,
  ScrollText,
  ShieldAlert,
  SquareTerminal,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Badge, Panel, PanelHeader } from '../ui';
import { CodeSnippet } from '../CodeSnippet';
import { TabbedCommand } from '../TabbedCommand';
import { ApiConsole } from './DeveloperConsole';
import type { GatewayLive } from '../../lib/useGatewayLive';

/** Deep-link into another console view (the standard cross-view CTA). */
function navigateTo(view: string, subtab: string): void {
  window.dispatchEvent(new CustomEvent('mcpip:navigate', { detail: { view, subtab } }));
}

type Tone = 'verified' | 'denied' | 'staged' | 'muted';

const TONE_TEXT: Record<Tone, string> = {
  verified: 'text-verified',
  denied: 'text-denied',
  staged: 'text-staged',
  muted: 'text-slate-400',
};

/* ---------------------------------------------------------------------------
   Snippet substitution — the real host / alias / tenant while live, explicit
   placeholders offline. `apiBase === ''` means the console reaches the
   gateway through its own origin's proxy (vite.config.ts forwards /v1/*), so
   the origin is a REAL working base for these snippets, not a guess.
--------------------------------------------------------------------------- */

interface SnippetContext {
  live: boolean;
  /** Absolute gateway base, or the honest placeholder when offline. */
  base: string;
  /** First alias this gateway actually enumerates, or the placeholder. */
  alias: string;
  /** The console identity's decoded tenant, or the placeholder. */
  tenant: string;
}

function snippetContext(gateway: GatewayLive): SnippetContext {
  if (gateway.mode !== 'live') {
    return {
      live: false,
      base: 'https://<gateway-host>',
      alias: '<alias>',
      tenant: '<tenant-id>',
    };
  }
  return {
    live: true,
    base: gateway.apiBase === '' ? window.location.origin : gateway.apiBase,
    alias: gateway.catalog[0]?.alias ?? '<alias>',
    tenant: gateway.tenant ?? '<tenant-id>',
  };
}

/* ------------------------------------------------------------ snippet text */

function mcpJsonSnippet(ctx: SnippetContext): string {
  return `{
  "mcpServers": {
    "mcpip": {
      "type": "http",
      "url": "${ctx.base}/v1/mcp",
      "headers": { "Authorization": "Bearer <jwt>" }
    }
  }
}`;
}

function curlSnippet(ctx: SnippetContext): string {
  return `# Sandbox identity — in production your IdP mints the JWT (gateway is verify-only)
TOKEN=$(curl -s -X POST ${ctx.base}/v1/dev/token \\
  -H 'Content-Type: application/json' -d '{"tenant_id":"${ctx.tenant}"}' | jq -r .jwt)

# One tool call through the authorization choke point
curl -s -X POST ${ctx.base}/v1/authorize \\
  -H "Authorization: Bearer $TOKEN" \\
  -H 'Content-Type: application/json' \\
  -d '{"source_format":"raw_mcp","tool_call":{"tool":"${ctx.alias}","arguments":{}}}'`;
}

/** The exact wire shape of every deny — two keys, no cause, header echoed. */
const DENY_SNIPPET = `HTTP/1.1 403 Forbidden
X-MCPIP-Correlation-Id: <correlation_id>

{"error": "MCPIP: request denied by policy.", "correlation_id": "<correlation_id>"}`;

function pythonSnippet(ctx: SnippetContext): string {
  return `from mcpip_sdk import Allowed, MCPIPDenied, SandboxClient, Staged

# SandboxClient mints demo identities; in production use
# MCPIPClient(base, token=<IdP JWT or refresh callback>).
with SandboxClient("${ctx.base}") as client:
    client.set_token(lambda: client.dev_token(tenant_id="${ctx.tenant}"))
    try:
        outcome = client.authorize("${ctx.alias}", {})
        if isinstance(outcome, Staged):          # 202 — PIN step-up required
            pin = client.authenticator_code(outcome.challenge_id)
            outcome = client.complete(outcome, pin)   # byte-identical consume
        print(outcome.transaction_ref, outcome.worm_sequence)
    except MCPIPDenied as deny:
        print("opaque deny - correlate in the Audit Ledger:", deny.correlation_id)`;
}

function typescriptSnippet(ctx: SnippetContext): string {
  return `import { McpipClient, McpipSandboxClient, McpipDenied, rawMcp } from '@mcpip/sdk';

// Sandbox identity — in production pass your IdP JWT or an async callback.
const sandbox = new McpipSandboxClient({ baseUrl: '${ctx.base}' });
const token = sandbox.devTokenSource({ tenant_id: '${ctx.tenant}' });
const client = new McpipClient({ baseUrl: '${ctx.base}', token });

try {
  let outcome = await client.authorize({
    source_format: 'raw_mcp',
    tool_call: rawMcp('${ctx.alias}', {}),
  });
  if (outcome.status === 'staged') {           // 202 — PIN step-up required
    const pin = await sandbox.authenticatorCode(outcome.challengeId);
    outcome = await client.complete(outcome, pin);  // byte-identical consume
  }
  console.log(outcome.transactionRef, outcome.wormSequence);
} catch (err) {
  if (err instanceof McpipDenied) console.error('denied', err.correlationId);
}`;
}

/* ------------------------------------------------ quick-start (tabbed card) */

/** Minimal Python block — the essential lines of `pythonSnippet`, nothing new. */
function pythonQuickstart(ctx: SnippetContext): string {
  return `from mcpip_sdk import SandboxClient

with SandboxClient("${ctx.base}") as client:
    client.set_token(lambda: client.dev_token(tenant_id="${ctx.tenant}"))
    outcome = client.authorize("${ctx.alias}", {})
    print(outcome.transaction_ref, outcome.worm_sequence)`;
}

/** Minimal TypeScript block — the essential lines of `typescriptSnippet`. */
function typescriptQuickstart(ctx: SnippetContext): string {
  return `import { McpipClient, McpipSandboxClient, rawMcp } from '@mcpip/sdk';

const sandbox = new McpipSandboxClient({ baseUrl: '${ctx.base}' });
const client = new McpipClient({
  baseUrl: '${ctx.base}',
  token: sandbox.devTokenSource({ tenant_id: '${ctx.tenant}' }),
});
const outcome = await client.authorize({
  source_format: 'raw_mcp',
  tool_call: rawMcp('${ctx.alias}', {}),
});`;
}

/* ------------------------------------------------------------- static facts */

/** interfaces.py SourceFormat — the six normalized provider dialects. */
const SOURCE_FORMATS: ReadonlyArray<string> = [
  'openai_tool_call',
  'anthropic_tool_use',
  'gemini_function_call',
  'bedrock_tool_use',
  'mcp_jsonrpc',
  'raw_mcp',
];

const MCP_METHODS: ReadonlyArray<{ method: string; bearer: boolean; detail: string }> = [
  {
    method: 'initialize',
    bearer: false,
    detail: 'Returns protocolVersion 2025-06-18, capabilities.tools and serverInfo "mcpip".',
  },
  {
    method: 'notifications/initialized',
    bearer: false,
    detail: 'Acknowledged with HTTP 202 and an empty body.',
  },
  {
    method: 'tools/list',
    bearer: true,
    detail:
      'Your aliases with risk_tier + classification in the description — exactly the /v1/catalog visibility, never a target.',
  },
  {
    method: 'tools/call',
    bearer: true,
    detail:
      'allow → receipt JSON as text content · pin_required → isError:true challenge · deny → JSON-RPC error -32000 with data.correlation_id (HTTP 200).',
  },
];

const AUTHORIZE_RESPONSES: ReadonlyArray<{
  status: string;
  tone: Tone;
  shape: string;
  meaning: string;
}> = [
  {
    status: '200',
    tone: 'verified',
    shape: 'ExecutionReceipt',
    meaning:
      'Committed: correlation_id, transaction_ref, executed_target_class (a coarse class, never a target), worm_sequence.',
  },
  {
    status: '202',
    tone: 'staged',
    shape: 'StagedChallenge',
    meaning:
      'pin_required step-up: challenge_id + action_required. Complete by resubmitting the byte-identical tool_call with pin + challenge_id.',
  },
  {
    status: '403',
    tone: 'denied',
    shape: '{ error, correlation_id }',
    meaning:
      'Opaque deny — exactly these two keys for every cause; the concrete reason exists only in the WORM ledger.',
  },
  {
    status: '422',
    tone: 'denied',
    shape: "{ error: 'invalid request', correlation_id }",
    meaning:
      'Malformed envelope: unknown keys (strict schema), batch arrays, or pin without challenge_id (the pair travels together or not at all).',
  },
];

const REQUIRED_CLAIMS: ReadonlyArray<{ claim: string; meaning: string }> = [
  {
    claim: 'iss',
    meaning: 'Issuer — must equal the gateway’s MCPIP_JWT_ISSUER (sandbox IdP: mcpip-demo-idp).',
  },
  {
    claim: 'aud',
    meaning: 'Audience — must equal MCPIP_JWT_AUDIENCE (sandbox: mcpip-gateway).',
  },
  {
    claim: 'tenant_id',
    meaning: 'The tenant every decision is scoped to — cross-tenant references are a hard deny.',
  },
  {
    claim: 'agent_id',
    meaning:
      'The calling principal (vendor-prefixed by convention) — decision attribution in the WORM ledger.',
  },
  {
    claim: 'role',
    meaning: 'Descriptive ONLY — the role claim authorizes nothing anywhere in the pipeline.',
  },
  {
    claim: 'exp',
    meaning:
      'Expiry — sandbox tokens live ~5 minutes; re-mint proactively (~30 s early) rather than reacting to denies.',
  },
  { claim: 'iat', meaning: 'Issued-at.' },
  { claim: 'nbf', meaning: 'Not-before.' },
];

const OPTIONAL_CLAIMS: ReadonlyArray<{ claim: string; meaning: string }> = [
  {
    claim: 'compartment',
    meaning: 'Compartment UUID — required to reach compartmented aliases.',
  },
  {
    claim: 'capabilities',
    meaning:
      'Capability UUID list — e.g. CAP_DIRECTORY_ADMIN gates every /v1/admin/* surface (registry in Directory → Entitlements).',
  },
  {
    claim: 'cnf.jkt',
    meaning:
      'RFC 7638 key thumbprint — makes the token sender-constrained; every call then needs a per-request DPoP proof.',
  },
  { claim: 'act.sub', meaning: 'Delegation actor for on-behalf-of chains.' },
  { claim: 'kid', meaning: 'Key id for JWKS-backed gateways.' },
];

const PIN_STEPS: ReadonlyArray<{ title: string; body: string }> = [
  {
    title: 'Stage',
    body:
      'POST /v1/authorize on a pin_required alias → HTTP 202 with challenge_id. The one-time code is NEVER in the response; the staging itself is WORM-logged as a pin_required deny.',
  },
  {
    title: 'Obtain the code out-of-band',
    body:
      'Production: the enrolled authenticator delivers it. Sandbox stand-in: GET /v1/authenticator/{challenge_id} with the same Bearer token (404 in production).',
  },
  {
    title: 'Consume',
    body:
      'Resubmit the byte-identical tool_call plus pin + challenge_id (both or neither — 422). The lock binds tenant, agent, alias and canonical arguments; any drift is a payload_mismatch deny, but the lock survives for a correct retry.',
  },
  {
    title: 'Terminal',
    body:
      'Match → 200 ExecutionReceipt, with the WORM allow written before dispatch. Wrong code, expired, or replayed → the same opaque 403 as any other deny.',
  },
];

/* -------------------------------------------------------------- shared bits */

/** Offline notice: docs render with placeholders; the CTA restores live hosts. */
function OfflineBanner(): JSX.Element {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-hairline bg-surface px-3.5 py-2.5 shadow-panel">
      <p className="flex min-w-0 items-start gap-2 text-[11.5px] leading-relaxed text-slate-500">
        <PlugZap size={14} className="mt-px shrink-0 text-slate-500" />
        <span>
          No gateway connected — snippets show{' '}
          <span className="font-mono text-[10.5px] text-ink">&lt;placeholder&gt;</span> values.
        </span>
      </p>
      <button
        type="button"
        className="btn-primary shrink-0"
        onClick={() => navigateTo('gateway', 'connection')}
      >
        <PlugZap size={13} /> Connect gateway
      </button>
    </div>
  );
}

/** Bottom-of-panel footnote, matching the SoftwarePanel hint recipe. */
function Footnote({ icon: Icon, children }: { icon: LucideIcon; children: React.ReactNode }): JSX.Element {
  return (
    <p className="flex items-start gap-1.5 border-t border-hairline px-5 py-2.5 text-[10.5px] leading-relaxed text-slate-500">
      <Icon size={12} className="mt-px shrink-0 text-slate-500" />
      <span>{children}</span>
    </p>
  );
}

/* ------------------------------------------------------------- connect tab */

function McpPanel({ ctx }: { ctx: SnippetContext }): JSX.Element {
  return (
    <Panel>
      <PanelHeader
        title="MCP endpoint"
        icon={Braces}
        right={<span className="font-mono text-[10.5px]">protocol 2025-06-18</span>}
      />
      <div className="space-y-3 px-5 py-4">
        <p className="text-[11.5px] leading-relaxed text-slate-500">
          One JSON-RPC 2.0 object per POST; identity is the{' '}
          <span className="font-mono text-[10.5px] text-ink">Authorization: Bearer</span> header.
        </p>
        <CodeSnippet label="POST · streamable http" code={`${ctx.base}/v1/mcp`} />

        <div className="overflow-hidden rounded-lg border border-hairline">
          {MCP_METHODS.map((m) => (
            <div
              key={m.method}
              className="flex items-start gap-2.5 border-b border-hairline/60 bg-canvas px-2.5 py-2 last:border-0"
            >
              <span className="w-48 shrink-0 truncate pt-px font-mono text-[11px] text-ink">
                {m.method}
              </span>
              <span className="shrink-0">
                <Badge tone={m.bearer ? 'ink' : 'muted'}>{m.bearer ? 'bearer' : 'no auth'}</Badge>
              </span>
              <p className="min-w-0 text-[10.5px] leading-relaxed text-slate-500">{m.detail}</p>
            </div>
          ))}
        </div>

        <CodeSnippet label=".mcp.json — Claude Code project registration" code={mcpJsonSnippet(ctx)} />
      </div>
      <Footnote icon={KeyRound}>
        Sandbox tokens expire in ~5 minutes — for long sessions use the SDK&apos;s re-minting token
        source or a long-lived IdP JWT.
      </Footnote>
    </Panel>
  );
}

function RestPanel({ ctx }: { ctx: SnippetContext }): JSX.Element {
  return (
    <Panel>
      <PanelHeader
        title="REST authorization"
        icon={SquareTerminal}
        right={<span className="font-mono text-[10.5px]">POST {ctx.base}/v1/authorize</span>}
      />
      <div className="space-y-3 px-5 py-4">
        <p className="text-[11.5px] leading-relaxed text-slate-500">
          Send one of <span className="font-mono text-[10.5px] text-ink">source_format</span> or{' '}
          <span className="font-mono text-[10.5px] text-ink">vendor</span> plus the raw provider{' '}
          <span className="font-mono text-[10.5px] text-ink">tool_call</span> — one tool call per
          request.
        </p>

        <div className="flex flex-wrap gap-1.5">
          {SOURCE_FORMATS.map((f) => (
            <span
              key={f}
              className="rounded-md border border-hairline bg-canvas px-2 py-0.5 font-mono text-[10.5px] text-slate-400"
            >
              {f}
            </span>
          ))}
        </div>

        <CodeSnippet label="bash" code={curlSnippet(ctx)} />

        <div>
          <p className="eyebrow mb-1">Responses</p>
          {AUTHORIZE_RESPONSES.map((r) => (
            <div
              key={r.status}
              className="flex items-start gap-2.5 border-b border-hairline/60 py-2 last:border-0"
            >
              <span
                className={`tabular w-7 shrink-0 pt-px font-mono text-[11px] font-semibold ${TONE_TEXT[r.tone]}`}
              >
                {r.status}
              </span>
              <div className="min-w-0">
                <p className="font-mono text-[11px] text-ink">{r.shape}</p>
                <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">{r.meaning}</p>
              </div>
            </div>
          ))}
          <p className="pt-2 text-[10.5px] leading-relaxed text-slate-500">
            Every response echoes the{' '}
            <span className="font-mono text-ink">X-MCPIP-Correlation-Id</span> header.
          </p>
        </div>

        <div>
          <p className="eyebrow mb-1">Every deny — one opaque envelope</p>
          <p className="text-[11px] leading-relaxed text-slate-500">
            Every deny carries exactly these two keys — search the correlation id in the audit log
            for the real reason.
          </p>
          <CodeSnippet label="http" code={DENY_SNIPPET} className="mt-2" />
          <button
            type="button"
            className="btn-ghost mt-2"
            onClick={() => navigateTo('ledger', 'events')}
          >
            <ScrollText size={13} /> Correlate in the audit log
          </button>
        </div>
      </div>
      <Footnote icon={ShieldAlert}>
        Never auto-retry this POST — every retry is a fresh, WORM-logged decision.
      </Footnote>
    </Panel>
  );
}

function JwtPanel(): JSX.Element {
  return (
    <Panel>
      <PanelHeader
        title="JWT contract"
        icon={KeyRound}
        right={<span className="font-mono text-[10.5px]">EdDSA · RS256 only</span>}
      />
      <div className="space-y-4 px-5 py-4">
        <div className="grid gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-hairline bg-canvas px-3 py-2.5">
            <p className="text-[11.5px] font-semibold text-ink">Production — IdP-sovereign</p>
            <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
              Your IdP mints every agent JWT; the gateway only verifies (it holds the IdP public
              key and can never mint an identity). Reference minter:{' '}
              <span className="font-mono text-[10.5px] text-ink">scripts/mint_principal.py</span>.
            </p>
          </div>
          <div className="rounded-lg border border-hairline bg-canvas px-3 py-2.5">
            <p className="text-[11.5px] font-semibold text-ink">Sandbox — dev minter</p>
            <p className="mt-1 text-[11px] leading-relaxed text-slate-500">
              <span className="font-mono text-[10.5px] text-ink">POST /v1/dev/token</span> (no
              auth) mints ~5-minute EdDSA tokens for quick wiring. The endpoint is a 404 in
              production — identity sovereignty is the point.
            </p>
          </div>
        </div>

        <div>
          <p className="eyebrow mb-1">Required claims — all 8, or jwt_claims_missing</p>
          {REQUIRED_CLAIMS.map((c) => (
            <div
              key={c.claim}
              className="flex items-start gap-3 border-b border-hairline/60 py-2 last:border-0"
            >
              <span className="w-24 shrink-0 pt-px font-mono text-[11px] text-ink">{c.claim}</span>
              <p className="min-w-0 text-[11px] leading-relaxed text-slate-500">{c.meaning}</p>
            </div>
          ))}
        </div>

        <div>
          <p className="eyebrow mb-1">Optional claims</p>
          {OPTIONAL_CLAIMS.map((c) => (
            <div
              key={c.claim}
              className="flex items-start gap-3 border-b border-hairline/60 py-2 last:border-0"
            >
              <span className="w-24 shrink-0 pt-px font-mono text-[11px] text-ink">{c.claim}</span>
              <p className="min-w-0 text-[11px] leading-relaxed text-slate-500">{c.meaning}</p>
            </div>
          ))}
        </div>
      </div>
      <Footnote icon={ShieldAlert}>
        <span className="font-mono">alg=none</span> and HS* are rejected; identity-shaped keys
        inside arguments are a hard deny.
      </Footnote>
    </Panel>
  );
}

function PinPanel(): JSX.Element {
  return (
    <Panel>
      <PanelHeader
        title="PIN step-up ceremony"
        icon={Fingerprint}
        right={<span className="font-mono text-[10.5px]">risk_tier=pin_required</span>}
      />
      <div className="px-5 py-2.5">
        {PIN_STEPS.map((s, i) => (
          <div key={s.title} className="flex gap-3 border-b border-hairline/60 py-2.5 last:border-0">
            <span className="tabular flex h-5 w-5 shrink-0 items-center justify-center rounded-md border border-hairline bg-elevated font-mono text-[10.5px] text-slate-400">
              {i + 1}
            </span>
            <div className="min-w-0">
              <p className="text-[12px] font-semibold text-ink">{s.title}</p>
              <p className="mt-0.5 text-[11px] leading-relaxed text-slate-500">{s.body}</p>
            </div>
          </div>
        ))}
      </div>
      <Footnote icon={Fingerprint}>
        6-digit code · 300 s TTL · 5 attempts · single-use consume.
      </Footnote>
    </Panel>
  );
}

/** Deep-link to Build's single live tester — the Authorize Probe fires a real
    round-trip (mint + one authorize) through the choke point; no duplicate here. */
function ProbeNote(): JSX.Element {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-hairline bg-surface px-3.5 py-2.5 shadow-panel">
      <p className="flex min-w-0 items-start gap-2 text-[11.5px] leading-relaxed text-slate-500">
        <Play size={14} className="mt-px shrink-0 text-slate-500" />
        <span>Fire a real authorize round-trip with the Authorize Probe.</span>
      </p>
      <button
        type="button"
        className="btn-ghost shrink-0"
        onClick={() => navigateTo('command', 'probe')}
      >
        <ArrowUpRight size={13} /> Open Authorize Probe
      </button>
    </div>
  );
}

function ConnectTab({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const ctx = snippetContext(gateway);
  // ONE job: get an agent talking to this gateway. The quick start comes
  // first; the deep contract lives on the sibling Protocol child tab.
  return (
    <div className="flex min-h-full flex-col gap-4">
      {!ctx.live ? <OfflineBanner /> : null}
      <TabbedCommand
        tabs={[
          { id: 'curl', label: 'curl', code: curlSnippet(ctx), prompt: true },
          { id: 'python', label: 'Python', code: pythonQuickstart(ctx) },
          { id: 'typescript', label: 'TypeScript', code: typescriptQuickstart(ctx) },
          { id: 'mcp-json', label: '.mcp.json', code: mcpJsonSnippet(ctx) },
        ]}
      />
      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
        <McpPanel ctx={ctx} />
        <RestPanel ctx={ctx} />
      </div>
      <ProbeNote />
    </div>
  );
}

/** The Protocol child tab — the deep contract (JWT · PIN step-up · SDK ·
 *  OpenAPI) promoted from a collapsed accordion to its own screen. */
function ProtocolTab({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const ctx = snippetContext(gateway);
  return (
    <div className="flex min-h-full flex-col gap-4">
      <div className="grid grid-cols-1 items-start gap-4 xl:grid-cols-2">
        <JwtPanel />
        <PinPanel />
      </div>
      <SdkBlock ctx={ctx} />
      <ReferencePanel ctx={ctx} />
    </div>
  );
}

/* --------------------------------------------------------------- sdk block */

/** One terse SDK capability row: mono keyword + sans meaning. */
function FactRow({ keyword, children }: { keyword: string; children: React.ReactNode }): JSX.Element {
  return (
    <div className="flex items-start gap-3 border-b border-hairline/60 py-2 last:border-0">
      <span className="w-44 shrink-0 break-all pt-px font-mono text-[10.5px] text-ink">
        {keyword}
      </span>
      <p className="min-w-0 text-[11px] leading-relaxed text-slate-500">{children}</p>
    </div>
  );
}

/** Both SDKs expose the same shape; one shared fact list, language on the snippet. */
const SDK_FACTS: ReadonlyArray<{ keyword: string; body: string }> = [
  {
    keyword: 'authorize(alias, args)',
    body:
      'Returns Allowed | Staged (a 202 is a result, not an error); every denial raises MCPIPDenied / McpipDenied carrying only the correlation_id — the SDK never guesses the reason.',
  },
  {
    keyword: 'complete(staged, pin)',
    body:
      'The consume half of the PIN ceremony — resubmits the byte-identical payload with the one-time code; the sandbox authenticator (authenticator_code / authenticatorCode) stands in for the enrolled device.',
  },
  {
    keyword: 'envelopes',
    body:
      'Typed builders for every dialect — openai_tool_call, anthropic_tool_use, gemini_function_call, bedrock_tool_use, mcp_jsonrpc, raw_mcp, a2a_task — so you never hand-roll a strict ingress shape.',
  },
  {
    keyword: 'token providers',
    body:
      'A static string, an async refresh callback, or the sandbox dev-token source — cached and re-minted ~30 s before exp; a deny is never a refresh trigger.',
  },
  {
    keyword: 'admin client · mcp_call()',
    body:
      'The full admin surface (skills, principals, directory, workspace, cloud IAM, vault, quarantine + canary rosters) behind a CAP_DIRECTORY_ADMIN JWT, plus JSON-RPC 2.0 against /v1/mcp — initialize unauthenticated, tools/* bearer-gated, -32000 mapped to the opaque deny.',
  },
];

/** The two shipped SDKs merged: shared facts, a Python|TypeScript snippet toggle. */
function SdkBlock({ ctx }: { ctx: SnippetContext }): JSX.Element {
  const [lang, setLang] = useState<'python' | 'typescript'>('python');
  const isPy = lang === 'python';
  return (
    <Panel>
      <PanelHeader
        title="SDK"
        icon={Package}
        right={
          <div className="inline-flex overflow-hidden rounded-md border border-hairline">
            {(['python', 'typescript'] as const).map((l) => (
              <button
                key={l}
                type="button"
                onClick={() => setLang(l)}
                className={`px-2 py-0.5 font-mono text-[10.5px] transition-colors ${
                  lang === l ? 'bg-elevated text-ink' : 'text-slate-500 hover:text-ink'
                }`}
              >
                {l === 'python' ? 'Python' : 'TypeScript'}
              </button>
            ))}
          </div>
        }
      />
      <div className="space-y-3 px-5 py-4">
        <p className="text-[11px] leading-relaxed text-slate-500">
          Two first-party SDKs, one shape:{' '}
          <span className="font-mono text-[10.5px] text-ink">mcpip-sdk</span> (Python) and{' '}
          <span className="font-mono text-[10.5px] text-ink">@mcpip/sdk</span> (TypeScript).
        </p>
        <CodeSnippet label="bash" code={isPy ? 'pip install mcpip-sdk' : 'npm install @mcpip/sdk'} />
        <CodeSnippet
          label={isPy ? 'python' : 'typescript'}
          code={isPy ? pythonSnippet(ctx) : typescriptSnippet(ctx)}
        />
        <div>
          {SDK_FACTS.map((f) => (
            <FactRow key={f.keyword} keyword={f.keyword}>
              {f.body}
            </FactRow>
          ))}
        </div>
      </div>
      <Footnote icon={Package}>
        Neither SDK logs tokens or PINs, and neither auto-retries an authorize.
      </Footnote>
    </Panel>
  );
}

function ReferencePanel({ ctx }: { ctx: SnippetContext }): JSX.Element {
  const links: ReadonlyArray<{ path: string; note: string }> = [
    { path: '/openapi.json', note: 'machine-readable route + request-body inventory' },
    { path: '/docs', note: 'interactive Swagger UI for the same routes' },
  ];
  return (
    <Panel>
      <PanelHeader title="API reference" icon={BookOpen} />
      <div className="space-y-3 px-5 py-4">
        <div className="overflow-hidden rounded-lg border border-hairline">
          {links.map((l) =>
            ctx.live ? (
              <a
                key={l.path}
                href={`${ctx.base}${l.path}`}
                target="_blank"
                rel="noreferrer"
                className="group flex items-center gap-2 border-b border-hairline/60 bg-canvas px-2.5 py-2 last:border-0"
              >
                <span className="truncate font-mono text-[11px] text-ink">
                  {ctx.base}
                  {l.path}
                </span>
                <ArrowUpRight
                  size={12}
                  className="shrink-0 text-slate-500 transition-colors group-hover:text-ink"
                />
                <span className="ml-auto hidden shrink-0 text-[10.5px] text-slate-500 sm:block">
                  {l.note}
                </span>
              </a>
            ) : (
              <div
                key={l.path}
                className="flex items-center gap-2 border-b border-hairline/60 bg-canvas px-2.5 py-2 last:border-0"
              >
                <span className="truncate font-mono text-[11px] text-slate-400">
                  {ctx.base}
                  {l.path}
                </span>
                <span className="ml-auto shrink-0 text-[10.5px] text-slate-500">
                  connect to open
                </span>
              </div>
            ),
          )}
        </div>
      </div>
      <Footnote icon={BookOpen}>
        Both SDKs live in the gateway repository under{' '}
        <span className="font-mono text-ink">sdk/python</span> and{' '}
        <span className="font-mono text-ink">sdk/typescript</span>.
      </Footnote>
    </Panel>
  );
}

/* -------------------------------------------------------------------- view */

export function Developers({
  gateway,
  subtab,
}: {
  gateway: GatewayLive;
  subtab: string;
}): JSX.Element {
  if (subtab === 'console') return <ApiConsole gateway={gateway} />;
  if (subtab === 'protocol') return <ProtocolTab gateway={gateway} />;
  return <ConnectTab gateway={gateway} />;
}
