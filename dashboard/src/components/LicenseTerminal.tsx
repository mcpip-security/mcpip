import { useEffect, useRef, useState } from 'react';
import { SquareTerminal } from 'lucide-react';
import { authorize, catalog, mintDevToken } from '../lib/api';
import { useCompanyConfig } from '../lib/companyConfig';
import { Panel, PanelHeader } from './ui';
import type { GatewayLive } from '../lib/useGatewayLive';

/* ---------------------------------------------------------------------------
   License ceremony terminal — a REAL interactive console, not a mock transcript.

   Every command is an actual round-trip against the connected gateway:

     mint <agent-id> [team]   mint a license via the sandbox IdP (team names come
                              from YOUR company config and resolve to compartments)
     tools                    what the minted license can actually see (/v1/catalog)
     call <alias>             one real /v1/authorize as the minted identity
     ceremony                 the equivalent offline production ceremony (IdP-side)
     clear · help

   Production never mints in-band — `ceremony` prints the exact scripts/
   mint_principal.py invocation for the current identity instead. The frame is
   the charter's terminal: mono data on porcelain, decision-palette tones,
   output landing instantly (never typed out), a blink cursor only while a
   request is genuinely in flight.
--------------------------------------------------------------------------- */

type Tone = 'cmd' | 'ok' | 'deny' | 'note' | 'out';

interface Line {
  tone: Tone;
  text: string;
}

const TONE_CLS: Record<Tone, string> = {
  cmd: 'text-ink',
  ok: 'text-verified',
  deny: 'text-denied',
  note: 'text-slate-500',
  out: 'text-slate-400',
};

const BANNER: Line[] = [
  { tone: 'note', text: 'MCPIP license console — every command is a real gateway round-trip.' },
  { tone: 'note', text: "type 'help' for commands." },
];

interface MintedIdentity {
  agentId: string;
  /** tenant_id decoded from the REAL minted JWT (never a hardcoded fallback). */
  tenant: string | null;
  team: string | null;
  compartment: string | null;
  token: string;
}

/** tenant_id out of a JWT payload — display truth comes from the token itself. */
function decodeTenant(jwt: string): string | null {
  try {
    const payload = jwt.split('.')[1];
    if (!payload) return null;
    const claims = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/'))) as {
      tenant_id?: unknown;
    };
    return typeof claims.tenant_id === 'string' ? claims.tenant_id : null;
  } catch {
    return null;
  }
}

export function LicenseTerminal({
  gateway,
  className = '',
}: {
  gateway: GatewayLive;
  className?: string;
}): JSX.Element {
  const { config } = useCompanyConfig();
  const [lines, setLines] = useState<Line[]>(BANNER);
  const [input, setInput] = useState('');
  const [busy, setBusy] = useState(false);
  const [minted, setMinted] = useState<MintedIdentity | null>(null);
  const scrollRef = useRef<HTMLDivElement | null>(null);
  const live = gateway.mode === 'live';
  // The operator's real tenant, when known — with neither a company profile nor
  // a live console identity, mint claims omit tenant_id (the sandbox IdP's own
  // default applies) rather than inventing one.
  const tenant = config?.tenant || gateway.tenant || null;
  const teams = config?.teams ?? [];

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight });
  }, [lines]);

  const print = (...added: Line[]): void => setLines((prev) => [...prev, ...added]);

  const run = async (raw: string): Promise<void> => {
    const cmd = raw.trim();
    if (!cmd) return;
    print({ tone: 'cmd', text: `$ ${cmd}` });
    setInput('');
    const [verb, ...args] = cmd.split(/\s+/);

    if (verb === 'clear') {
      setLines(BANNER);
      return;
    }
    if (verb === 'help') {
      print(
        { tone: 'out', text: 'mint <agent-id> [team]   mint a license (sandbox IdP) — teams: ' + (teams.map((t) => t.name.toLowerCase()).join(' · ') || 'none configured') },
        { tone: 'out', text: 'tools                    list what the minted license can see' },
        { tone: 'out', text: 'call <alias>             one real /v1/authorize as that identity' },
        { tone: 'out', text: 'ceremony                 the offline production mint for this identity' },
        { tone: 'out', text: 'clear                    reset the console' },
      );
      return;
    }
    if (verb === 'ceremony') {
      const agent = minted?.agentId ?? '<agent-id>';
      const comp = minted?.compartment;
      print(
        { tone: 'note', text: '# production licenses are minted OFFLINE by your IdP — the gateway only verifies:' },
        { tone: 'out', text: 'python scripts/mint_principal.py --idp-key /secure/idp_ed25519.pem \\' },
        { tone: 'out', text: `  --tenant ${minted?.tenant ?? tenant ?? '<tenant-id>'} --agent ${agent} \\` },
        ...(comp ? [{ tone: 'out' as Tone, text: `  --compartment ${comp} \\` }] : []),
        { tone: 'out', text: '  --issuer $MCPIP_JWT_ISSUER --audience $MCPIP_JWT_AUDIENCE \\' },
        { tone: 'out', text: '  --cnf-jkt <agent-key RFC-7638 thumbprint> --ttl 3600 --out ./license.jwt' },
      );
      return;
    }

    if (!live) {
      print({ tone: 'deny', text: 'no gateway connected — connect one (Gateway → Connection) to run live ceremonies.' });
      return;
    }

    if (verb === 'mint') {
      const agentId = args[0];
      if (!agentId) {
        print({ tone: 'deny', text: 'usage: mint <agent-id> [team]' });
        return;
      }
      const teamName = args[1]?.toLowerCase() ?? null;
      const team = teamName ? teams.find((t) => t.name.toLowerCase() === teamName) : undefined;
      if (teamName && !team) {
        print({ tone: 'deny', text: `unknown team '${teamName}' — configured: ${teams.map((t) => t.name.toLowerCase()).join(' · ') || '(none)'}` });
        return;
      }
      setBusy(true);
      try {
        const claims: Parameters<typeof mintDevToken>[0] = { agent_id: agentId };
        if (tenant) claims.tenant_id = tenant;
        if (team) claims.compartment = team.compartment;
        const token = await mintDevToken(claims, { base: gateway.apiBase });
        // The token is the truth of what got minted — decode, don't assume.
        const mintedTenant = decodeTenant(token) ?? tenant;
        setMinted({ agentId, tenant: mintedTenant, team: team?.name ?? null, compartment: team?.compartment ?? null, token });
        print(
          { tone: 'ok', text: `✓ license minted — ${agentId} @ ${mintedTenant ?? '(sandbox default tenant)'}${team ? ` · team ${team.name} (compartment ${team.compartment.slice(0, 8)}…)` : ' · no team (company-wide only)'}` },
          { tone: 'out', text: `  jwt ${token.slice(0, 24)}…${token.slice(-10)}` },
          { tone: 'note', text: "  next: 'tools' to see its blast radius, 'call <alias>' to authorize." },
        );
      } catch {
        print({ tone: 'deny', text: 'mint failed — /v1/dev/token is sandbox-only (production mints offline; see `ceremony`).' });
      } finally {
        setBusy(false);
      }
      return;
    }

    if (verb === 'tools') {
      if (!minted) {
        print({ tone: 'deny', text: "no license minted yet — 'mint <agent-id> [team]' first." });
        return;
      }
      setBusy(true);
      const visible = await catalog(minted.token, { base: gateway.apiBase });
      setBusy(false);
      if (visible === null) {
        print({ tone: 'deny', text: 'catalog unavailable (token expired? mint again).' });
        return;
      }
      print(
        { tone: 'ok', text: `✓ ${minted.agentId} enumerates ${visible.length} skill(s):` },
        ...visible.map((v) => ({
          tone: 'out' as Tone,
          text: `  ${v.alias}  ·  ${v.risk_tier}${v.compartment ? '  ·  compartmented' : ''}`,
        })),
        { tone: 'note', text: '  anything not listed is invisible to this identity — not merely forbidden.' },
      );
      return;
    }

    if (verb === 'call') {
      const alias = args[0];
      if (!alias) {
        print({ tone: 'deny', text: 'usage: call <alias>' });
        return;
      }
      if (!minted) {
        print({ tone: 'deny', text: "no license minted yet — 'mint <agent-id> [team]' first." });
        return;
      }
      setBusy(true);
      try {
        const started = performance.now();
        const outcome = await authorize(
          { source_format: 'raw_mcp', tool_call: { tool: alias, arguments: {} } },
          { token: minted.token, base: gateway.apiBase },
        );
        const ms = (performance.now() - started).toFixed(1);
        if (outcome.kind === 'executed') {
          print({
            tone: 'ok',
            text: `✓ ALLOW — committed · txn ${outcome.receipt.transaction_ref.slice(0, 18)}… · WORM #${outcome.receipt.worm_sequence} · ${ms} ms`,
          });
        } else if (outcome.kind === 'staged') {
          print(
            { tone: 'out', text: `▲ STAGED (202) — human step-up required · challenge ${outcome.challenge.challenge_id.slice(0, 12)}…` },
            { tone: 'note', text: '  a payload-bound one-time PIN must approve this exact payload.' },
          );
        } else {
          print(
            { tone: 'deny', text: `✕ DENY — "${outcome.error.error}"` },
            { tone: 'note', text: `  correlation ${outcome.error.correlation_id} · the real reason lives only in the WORM ledger.` },
          );
        }
      } catch {
        print({ tone: 'deny', text: 'request failed — gateway unreachable.' });
      } finally {
        setBusy(false);
      }
      return;
    }

    print({ tone: 'deny', text: `unknown command '${verb ?? ''}' — try 'help'.` });
  };

  const quick: string[] = [
    `mint agent-demo-1${teams[0] ? ` ${teams[0].name.toLowerCase()}` : ''}`,
    'tools',
    'ceremony',
  ];

  return (
    <Panel className={className}>
      <PanelHeader
        title="License console"
        icon={SquareTerminal}
        right={
          <span className={`font-mono text-[10.5px] ${live ? 'text-verified' : ''}`}>
            {live ? `live · ${gateway.apiHost}` : 'offline'}
          </span>
        }
      />

      <div
        ref={scrollRef}
        className="min-h-[160px] flex-1 space-y-0.5 overflow-y-auto bg-canvas px-3.5 py-3"
      >
        {lines.map((l, i) => (
          <p key={i} className={`whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed ${TONE_CLS[l.tone]}`}>
            {l.text}
          </p>
        ))}
        {busy ? (
          /* blink = reserved liveness semantics: a request is genuinely in flight */
          <span className="mt-1 inline-block h-3 w-[7px] animate-blink bg-ink/80" aria-hidden="true" />
        ) : null}
      </div>

      <div className="shrink-0 border-t border-hairline px-3.5 py-2">
        <div className="flex items-center gap-2">
          <span className="select-none font-mono text-[12px] text-slate-500">$</span>
          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !busy) void run(input);
            }}
            placeholder={live ? 'mint agent-demo-1 …' : 'connect a gateway to run live ceremonies'}
            spellCheck={false}
            aria-label="License console command"
            className="min-w-0 flex-1 bg-transparent font-mono text-[12px] text-ink outline-none placeholder:text-slate-500"
          />
        </div>
        <div className="mt-1.5 flex flex-wrap gap-1.5">
          {quick.map((q) => (
            <button
              key={q}
              type="button"
              onClick={() => void run(q)}
              disabled={busy}
              className="rounded-full border border-hairline bg-surface px-2.5 py-1 font-mono text-[10.5px] text-slate-500 transition-colors hover:border-ink/20 hover:text-ink disabled:opacity-50"
            >
              {q}
            </button>
          ))}
        </div>
      </div>
    </Panel>
  );
}
