import { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  PlugZap,
  Building2,
  Users,
  Rocket,
  ArrowRight,
  ArrowLeft,
  Loader2,
  CheckCircle2,
  XCircle,
  Trash2,
  Sparkles,
  ShieldAlert,
  RotateCcw,
} from 'lucide-react';
import { Logomark } from './Logo';
import { ThemeToggle } from './shell/ThemeToggle';
import { Field, Input } from './ui';
import { prefersReducedMotion } from '../lib/format';
import {
  EMPTY_COMPANY,
  slugifyTenant,
  type CompanyConfig,
  type CompanyTeam,
} from '../lib/companyConfig';
import { generateStarter, type Starter } from '../lib/starterKit';
import { applyPlan, type WorkspacePlan } from '../lib/workspace';
import type { GatewayLive } from '../lib/useGatewayLive';

/**
 * Project the drafted starter into a WorkspacePlan the gateway can apply through the
 * authoritative, WORM-audited ``/v1/admin/workspace/plan/apply`` endpoint. Skills become
 * tenant-wide cloud_rest catalog entries (unclassified — the starter never marks a read
 * RESTRICTED); teams become the org chart. The gateway re-validates before applying.
 */
function starterToPlan(name: string, tenant: string, starter: Starter | null): WorkspacePlan {
  const tn = tenant.trim() || 'my-company';
  const label = name.trim() || 'My Company';
  const teams = (starter?.teams ?? []).map((t) => ({ id: slugifyTenant(t) || t, label: t, compartment: '' }));
  const skills = (starter?.skills ?? []).map((s) => ({
    alias: s.alias,
    target: s.target,
    risk_tier: s.risk,
    classification: 'unclassified',
  }));
  return { company: label, tenant: tn, org_units: [{ id: tn, label, tenant: tn, teams }], skills };
}

/** Apple-like decelerating ease — slow, expensive, never bouncy. */
const EASE = [0.32, 0.72, 0, 1] as const;

type StepId = 'welcome' | 'connect' | 'company' | 'workspace' | 'launch';
const STEPS: ReadonlyArray<{ id: StepId; label: string }> = [
  { id: 'welcome', label: 'Welcome' },
  { id: 'connect', label: 'Connect' },
  { id: 'company', label: 'Company' },
  { id: 'workspace', label: 'Workspace' },
  { id: 'launch', label: 'Launch' },
];

/** A stable-ish compartment UUID for a new team (browser crypto; Math fallback). */
function newCompartment(): string {
  try {
    if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  } catch {
    /* fall through */
  }
  const hex = (n: number): string =>
    Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  return `${hex(8)}-${hex(4)}-4${hex(3)}-8${hex(3)}-${hex(12)}`;
}

/**
 * First-run setup — the animated "landing" the operator sees the first time they open
 * the console for a fresh deployment. It initializes REAL state: it connects a gateway
 * (plug-and-play, persisted) and writes the company identity + teams to the persisted
 * company config. Nothing is mocked; nothing is minted (the gateway stays
 * identity-sovereign — real principals come from the IdP ceremony afterwards).
 */
export function Onboarding({
  gateway,
  onComplete,
}: {
  gateway: GatewayLive;
  onComplete: (config: CompanyConfig) => void;
}): JSX.Element {
  const reduced = prefersReducedMotion();
  const [stepIdx, setStepIdx] = useState(0);
  const [dir, setDir] = useState<1 | -1>(1);

  const [name, setName] = useState('');
  const [tenant, setTenant] = useState('');
  const [tenantTouched, setTenantTouched] = useState(false);
  const [admin, setAdmin] = useState('agent-admin');
  const [brief, setBrief] = useState('');
  const [starter, setStarter] = useState<Starter | null>(null);
  const [launching, setLaunching] = useState(false);

  const step = STEPS[stepIdx]!;
  const live = gateway.mode === 'live';

  // Auto-derive the tenant slug from the company name until the operator edits it.
  useEffect(() => {
    if (!tenantTouched) setTenant(slugifyTenant(name));
  }, [name, tenantTouched]);

  const go = (delta: 1 | -1): void => {
    setDir(delta);
    setStepIdx((i) => Math.min(STEPS.length - 1, Math.max(0, i + delta)));
  };

  const canNext = useMemo(() => {
    if (step.id === 'company') return name.trim().length > 1 && tenant.trim().length > 1;
    if (step.id === 'workspace') return starter !== null;
    return true;
  }, [step.id, name, tenant, starter]);

  const finish = (): void => {
    const teams: CompanyTeam[] = (starter?.teams ?? []).map((t) => ({
      id: slugifyTenant(t) || t,
      name: t,
      compartment: newCompartment(),
    }));
    onComplete({
      ...EMPTY_COMPANY,
      name: name.trim() || 'My Company',
      tenant: tenant.trim() || 'my-company',
      admin: admin.trim() || 'agent-admin',
      teams,
      skills: starter?.skills ?? [],
      brief: brief.trim(),
      setupComplete: true,
    });
  };

  // Launch = PROVISION the generated workspace to the gateway (authoritative + WORM-
  // audited apply of the org chart + skills), THEN persist the local company config and
  // enter the console. A connected gateway gets a real, validated workspace out of the
  // box; offline, we just persist the config and the operator applies later. Idempotent.
  const launchNow = async (): Promise<void> => {
    setLaunching(true);
    try {
      if (live && starter) {
        await applyPlan(gateway.apiBase, tenant.trim() || 'my-company', starterToPlan(name, tenant, starter));
      }
    } catch {
      // A provisioning hiccup never blocks entering the console — the config is saved and
      // the operator can refine tools anytime in Skills & Access (or re-run setup).
    } finally {
      finish();
    }
  };

  // Vertical blur-fade between steps — soft, decelerating, never a slide-show.
  const variants = {
    enter: { opacity: 0, y: reduced ? 0 : 18, filter: reduced ? 'none' : 'blur(6px)' },
    center: { opacity: 1, y: 0, filter: 'blur(0px)' },
    exit: { opacity: 0, y: reduced ? 0 : -14, filter: reduced ? 'none' : 'blur(6px)' },
  };
  void dir; // direction no longer drives motion — kept for state symmetry.

  return (
    <div className="relative flex h-screen flex-col items-center justify-center overflow-hidden bg-canvas px-6">
      {/* Theme toggle is reachable from the very first screen — dark mode should
          never be a setting you can only find after connecting. */}
      <div className="absolute right-5 top-5 z-10">
        <ThemeToggle />
      </div>
      <div className="w-full max-w-[420px]">
        <AnimatePresence mode="wait">
          <motion.div
            key={step.id}
            variants={variants}
            initial="enter"
            animate="center"
            exit="exit"
            transition={{ duration: 0.55, ease: EASE }}
          >
            {step.id === 'welcome' ? <WelcomeStep /> : null}
            {step.id === 'connect' ? <ConnectStep gateway={gateway} /> : null}
            {step.id === 'company' ? (
              <CompanyStep
                name={name}
                tenant={tenant}
                admin={admin}
                onName={setName}
                onTenant={(v) => {
                  setTenant(v);
                  setTenantTouched(true);
                }}
                onAdmin={setAdmin}
              />
            ) : null}
            {step.id === 'workspace' ? (
              <WorkspaceStep brief={brief} onBrief={setBrief} starter={starter} onStarter={setStarter} />
            ) : null}
            {step.id === 'launch' ? (
              <LaunchStep name={name} tenant={tenant} admin={admin} starter={starter} live={live} host={gateway.apiHost} />
            ) : null}
          </motion.div>
        </AnimatePresence>

        {/* Nav — back · dots · continue. No chrome, no counters. */}
        <div className="mt-12 flex items-center justify-between">
          <button
            type="button"
            onClick={() => go(-1)}
            disabled={stepIdx === 0}
            className="inline-flex items-center gap-1 text-[13px] font-medium text-slate-400 transition-colors hover:text-ink disabled:invisible"
          >
            <ArrowLeft size={14} /> Back
          </button>

          <div className="flex items-center gap-1.5" aria-hidden="true">
            {STEPS.map((s, i) => (
              <span
                key={s.id}
                className={`h-1.5 rounded-full transition-all duration-500 ${
                  i === stepIdx ? 'w-5 bg-ink' : i < stepIdx ? 'w-1.5 bg-ink/40' : 'w-1.5 bg-ink/15'
                }`}
              />
            ))}
          </div>

          {step.id === 'launch' ? (
            <motion.button
              type="button"
              onClick={() => void launchNow()}
              disabled={launching}
              whileTap={reduced ? undefined : { scale: 0.97 }}
              className="inline-flex items-center gap-1.5 rounded-full bg-ink px-6 py-2.5 text-[13px] font-medium text-surface transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              {launching ? <Loader2 size={14} className="animate-spin" /> : null}
              {launching ? (live && starter ? 'Provisioning…' : 'Entering…') : 'Enter console'}
            </motion.button>
          ) : (
            <motion.button
              type="button"
              onClick={() => go(1)}
              disabled={!canNext}
              whileTap={reduced ? undefined : { scale: 0.97 }}
              className="inline-flex items-center gap-1.5 rounded-full bg-ink px-6 py-2.5 text-[13px] font-medium text-surface transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-30"
            >
              {step.id === 'welcome' ? 'Get started' : 'Continue'} <ArrowRight size={14} />
            </motion.button>
          )}
        </div>
      </div>

      <motion.p
        initial={reduced ? false : { opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 1, delay: 0.9, ease: EASE }}
        className="absolute bottom-7 left-0 right-0 mx-auto max-w-md px-6 text-center text-[10.5px] leading-relaxed text-slate-400"
      >
        MCPIP never mints credentials — teams map to gateway compartments; real agent
        licenses are issued by your IdP afterwards.
      </motion.p>
    </div>
  );
}

/** Staggered content reveal — soft rise + fade on the Apple ease. */
function Reveal({ delay = 0, children }: { delay?: number; children: React.ReactNode }): JSX.Element {
  const reduced = prefersReducedMotion();
  return (
    <motion.div
      initial={reduced ? false : { opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.6, delay: reduced ? 0 : delay, ease: EASE }}
    >
      {children}
    </motion.div>
  );
}

/* --- steps ----------------------------------------------------------------- */

function StepHead({ icon, title, sub }: { icon: React.ReactNode; title: string; sub: string }): JSX.Element {
  return (
    <Reveal>
      <div className="mb-8 flex flex-col items-center text-center">
        <div className="text-slate-400">{icon}</div>
        <h2 className="mt-4 text-[22px] font-semibold leading-tight tracking-tightest text-ink">{title}</h2>
        <p className="mt-2 max-w-[340px] text-[13px] font-normal leading-relaxed text-slate-500">{sub}</p>
      </div>
    </Reveal>
  );
}

function WelcomeStep(): JSX.Element {
  return (
    <div className="flex flex-col items-center py-8 text-center">
      <Reveal>
        <Logomark size={76} animated />
      </Reveal>
      <Reveal delay={0.35}>
        <h1 className="mt-9 text-[42px] font-light leading-none tracking-tight text-ink">
          MCP<span className="font-semibold">IP</span>
        </h1>
      </Reveal>
      <Reveal delay={0.65}>
        <p className="mt-5 max-w-[280px] text-[14px] font-light leading-relaxed text-slate-500">
          The authorization plane for your agents.
        </p>
      </Reveal>
      <Reveal delay={0.95}>
        {/* The whole product in three words — the concept diet: everything else
            (tenants, compartments, canaries) waits until it's needed. */}
        <p className="mt-3 text-[12px] font-medium tracking-[0.08em] text-slate-400">
          Connect · Protect · Approve
        </p>
      </Reveal>
    </div>
  );
}

function ConnectStep({ gateway }: { gateway: GatewayLive }): JSX.Element {
  const live = gateway.mode === 'live';
  const [url, setUrl] = useState(gateway.configuredBase ?? 'http://localhost:8080');
  const [state, setState] = useState<'idle' | 'testing' | 'ok' | 'fail'>(live ? 'ok' : 'idle');

  const connect = async (): Promise<void> => {
    setState('testing');
    const ok = await gateway.connect(url);
    setState(ok ? 'ok' : 'fail');
  };

  return (
    <div>
      <StepHead
        icon={<PlugZap size={24} strokeWidth={1.6} className={live ? 'text-verified' : 'text-slate-400'} />}
        title="Connect your gateway"
        sub="Point the console at a running MCPIP gateway. Plug-and-play — the endpoint is saved so every tab runs on real data."
      />
      <Field label="Gateway endpoint">
        <Input
          mono
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            setState('idle');
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter') void connect();
          }}
          placeholder="http://localhost:8080"
          spellCheck={false}
        />
      </Field>
      <div className="mt-3 flex items-center gap-2">
        <button type="button" onClick={() => void connect()} disabled={state === 'testing'} className="btn-primary">
          {state === 'testing' ? <Loader2 size={14} className="animate-spin" /> : <PlugZap size={14} />}
          {state === 'testing' ? 'Testing…' : 'Test & Connect'}
        </button>
        <span className="text-[11px] text-slate-500">or continue offline and connect later</span>
      </div>
      {state === 'ok' || (live && state !== 'fail') ? (
        <div className="mt-3 flex items-center gap-2 rounded-lg border border-verified/25 bg-verified/5 px-3 py-2 text-[11.5px] text-verified">
          <CheckCircle2 size={14} /> Connected — {gateway.apiHost} answered.
        </div>
      ) : null}
      {state === 'fail' ? (
        <div className="mt-3 space-y-1 rounded-lg border border-denied/25 bg-denied/5 px-3 py-2 text-[11.5px]">
          <p className="flex items-center gap-2 text-denied">
            <XCircle size={14} /> No gateway answered.
          </p>
          <p className="pl-6 text-[11px] leading-relaxed text-slate-500">
            Check the node is running (<span className="font-mono text-[10.5px]">curl …/healthz</span>) and the host/port. If
            curl answers but this doesn&apos;t, the browser blocked a cross-origin call — run the gateway with{' '}
            <span className="font-mono text-[10.5px]">MCPIP_SANDBOX_MODE=true</span> or set{' '}
            <span className="font-mono text-[10.5px]">MCPIP_CONSOLE_ORIGINS</span> to this console&apos;s origin.
          </p>
        </div>
      ) : null}
    </div>
  );
}

function CompanyStep({
  name,
  tenant,
  admin,
  onName,
  onTenant,
  onAdmin,
}: {
  name: string;
  tenant: string;
  admin: string;
  onName: (v: string) => void;
  onTenant: (v: string) => void;
  onAdmin: (v: string) => void;
}): JSX.Element {
  return (
    <div>
      <StepHead
        icon={<Building2 size={24} strokeWidth={1.6} className="text-slate-400" />}
        title="Your company"
        sub="Name your organization and the gateway tenant this console administers. All editable later in Settings."
      />
      <div className="space-y-3">
        <Field label="Company name">
          <Input value={name} onChange={(e) => onName(e.target.value)} placeholder="MCPIP Inc" autoFocus />
        </Field>
        <Field label="Gateway tenant · agent scope">
          <Input mono value={tenant} onChange={(e) => onTenant(e.target.value)} placeholder="mcpip-inc" spellCheck={false} />
        </Field>
        <Field label="Bootstrap admin principal">
          <Input mono value={admin} onChange={(e) => onAdmin(e.target.value)} placeholder="agent-admin" spellCheck={false} />
        </Field>
      </div>
    </div>
  );
}

/* --- workspace: describe → design → review --------------------------------- */

const BRIEF_EXAMPLES = [
  'Fintech startup — engineering, finance, support',
  'Hospital network — clinical data, billing, IT ops',
  'E-commerce — sales, support, logistics, analytics',
];

function WorkspaceStep({
  brief,
  onBrief,
  starter,
  onStarter,
}: {
  brief: string;
  onBrief: (v: string) => void;
  starter: Starter | null;
  onStarter: (s: Starter | null) => void;
}): JSX.Element {
  const reduced = prefersReducedMotion();

  // The draft is deterministic and returns synchronously — reveal it at once
  // with the review list's own staggered rise. No staged "designing" ticker:
  // liveness signals never run without a real process behind them.
  const design = (input: string): void => {
    onStarter(generateStarter(input));
  };

  if (starter !== null) {
    const byTeam = new Map<string, typeof starter.skills>();
    for (const s of starter.skills) {
      const key = s.team;
      byTeam.set(key, [...(byTeam.get(key) ?? []), s]);
    }
    const removeSkill = (alias: string): void => {
      const skills = starter.skills.filter((s) => s.alias !== alias);
      const teams = starter.teams.filter((t) => skills.some((s) => s.team === t));
      onStarter({ teams, skills });
    };
    return (
      <div>
        <StepHead
          icon={<Sparkles size={24} strokeWidth={1.6} className="text-slate-400" />}
          title="Your starter workspace"
          sub="A general starting point drafted from your brief — approve it now, refine it anytime in Skills & Access."
        />
        <div className="max-h-[300px] space-y-3 overflow-y-auto pr-1">
          {['company', ...starter.teams].map((team, ti) =>
            byTeam.has(team) ? (
              <motion.div
                key={team}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.3, delay: reduced ? 0 : ti * 0.07, ease: EASE }}
              >
                <div className="mb-1 flex items-center gap-1.5">
                  <Users size={11} className="text-slate-500" />
                  <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-slate-500">
                    {team === 'company' ? 'Company-wide' : team}
                  </span>
                </div>
                <div className="overflow-hidden rounded-lg border border-hairline">
                  {(byTeam.get(team) ?? []).map((s) => (
                    <div
                      key={s.alias}
                      className="group flex items-center gap-2 border-b border-hairline/60 bg-canvas px-2.5 py-1.5 last:border-0"
                    >
                      <span className="truncate font-mono text-[11px] text-ink">{s.alias}</span>
                      {s.risk === 'pin_required' ? (
                        <span title="requires a payload-bound one-time PIN">
                          <ShieldAlert size={11} className="shrink-0 text-staged" />
                        </span>
                      ) : null}
                      <span className="ml-auto hidden truncate text-[10.5px] text-slate-500 sm:block">{s.description}</span>
                      <button
                        type="button"
                        onClick={() => removeSkill(s.alias)}
                        title="Remove"
                        className="shrink-0 text-slate-500 opacity-0 transition-opacity hover:text-denied group-hover:opacity-100"
                      >
                        <Trash2 size={12} />
                      </button>
                    </div>
                  ))}
                </div>
              </motion.div>
            ) : null,
          )}
        </div>
        <button
          type="button"
          onClick={() => onStarter(null)}
          className="mt-3 inline-flex items-center gap-1.5 text-[11px] font-medium text-slate-500 transition-colors hover:text-ink"
        >
          <RotateCcw size={11} /> Start over with a new brief
        </button>
      </div>
    );
  }

  return (
    <div>
      <StepHead
        icon={<Sparkles size={24} strokeWidth={1.6} className="text-slate-400" />}
        title="Describe your company"
        sub="A sentence is enough — teams and disciplines matter most. MCPIP drafts a general starter workspace (teams + tools) you approve and refine."
      />
      <textarea
        value={brief}
        onChange={(e) => onBrief(e.target.value)}
        rows={3}
        placeholder="e.g. A fintech startup with engineering, finance and customer-support teams"
        className="w-full resize-none rounded-lg border border-hairline bg-canvas px-3 py-2.5 text-[12.5px] leading-relaxed text-ink outline-none placeholder:text-slate-500 focus:border-ink/30 focus:shadow-focus-ring"
      />
      <div className="mt-2 flex flex-wrap gap-1.5">
        {BRIEF_EXAMPLES.map((ex) => (
          <button
            key={ex}
            type="button"
            onClick={() => onBrief(ex)}
            className="rounded-full border border-hairline bg-surface px-2.5 py-1 text-[10.5px] text-slate-500 transition-colors hover:border-ink/20 hover:text-ink"
          >
            {ex}
          </button>
        ))}
      </div>
      <div className="mt-4 flex items-center gap-3">
        <button type="button" onClick={() => design(brief)} disabled={brief.trim().length < 3} className="btn-primary">
          <Sparkles size={14} /> Design my workspace
        </button>
        <button
          type="button"
          onClick={() => design('')}
          className="text-[11px] font-medium text-slate-500 transition-colors hover:text-ink"
        >
          Skip — start with a general template
        </button>
      </div>
    </div>
  );
}

function LaunchStep({
  name,
  tenant,
  admin,
  starter,
  live,
  host,
}: {
  name: string;
  tenant: string;
  admin: string;
  starter: Starter | null;
  live: boolean;
  host: string;
}): JSX.Element {
  return (
    <div>
      <StepHead
        icon={<Rocket size={24} strokeWidth={1.6} className="text-slate-400" />}
        title="Ready to launch"
        sub="Review your deployment. You can change any of this later in Settings."
      />
      <dl className="space-y-2.5">
        <Summary label="Company" value={name.trim() || '—'} />
        <Summary label="Gateway tenant" value={tenant.trim() || '—'} mono />
        <Summary label="Admin principal" value={admin.trim() || '—'} mono />
        <Summary
          label="Teams"
          value={starter && starter.teams.length ? starter.teams.join(' · ') : 'none yet'}
        />
        <Summary
          label="Starter tools"
          value={
            starter
              ? live
                ? `${starter.skills.length} — provisioned to the gateway on launch`
                : `${starter.skills.length} drafted — applied once a gateway is connected`
              : '—'
          }
          tone={starter && live ? 'verified' : 'ink'}
        />
        <Summary
          label="Gateway"
          value={live ? `live · ${host}` : 'offline — connect later'}
          tone={live ? 'verified' : 'muted'}
        />
      </dl>
    </div>
  );
}

function Summary({
  label,
  value,
  mono,
  tone = 'ink',
}: {
  label: string;
  value: string;
  mono?: boolean;
  tone?: 'ink' | 'verified' | 'muted';
}): JSX.Element {
  const cls = tone === 'verified' ? 'text-verified' : tone === 'muted' ? 'text-slate-500' : 'text-ink';
  return (
    <div className="flex items-center justify-between gap-3 border-b border-hairline/60 pb-2 last:border-0">
      <dt className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-slate-500">{label}</dt>
      <dd className={`truncate text-[12.5px] font-medium ${mono ? 'font-mono text-[11.5px]' : ''} ${cls}`}>{value}</dd>
    </div>
  );
}
