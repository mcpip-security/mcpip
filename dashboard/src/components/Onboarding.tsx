import { useEffect, useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import {
  PlugZap,
  Building2,
  Rocket,
  ArrowRight,
  ArrowLeft,
  Loader2,
  CheckCircle2,
  XCircle,
  Sparkles,
} from 'lucide-react';
import { Logomark } from './Logo';
import { ThemeToggle } from './shell/ThemeToggle';
import { Field, Input } from './ui';
import { prefersReducedMotion } from '../lib/format';
import {
  EMPTY_COMPANY,
  slugifyTenant,
  type CompanyConfig,
} from '../lib/companyConfig';
import type { GatewayLive } from '../lib/useGatewayLive';

/** Apple-like decelerating ease — slow, expensive, never bouncy. */
const EASE = [0.32, 0.72, 0, 1] as const;

// Setup captures the operator's IDENTITY only (company, gateway tenant, admin) and
// connects a gateway. The skill catalog + team compartments are no longer generated
// here — they are built by pointing a coding agent at the agent-setup prompt
// (context-driven) and registered to the gateway, so the old "Workspace" step is gone.
type StepId = 'welcome' | 'connect' | 'company' | 'launch';
const STEPS: ReadonlyArray<{ id: StepId; label: string }> = [
  { id: 'welcome', label: 'Welcome' },
  { id: 'connect', label: 'Connect' },
  { id: 'company', label: 'Company' },
  { id: 'launch', label: 'Launch' },
];

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
    return true;
  }, [step.id, name, tenant]);

  const finish = (): void => {
    // Persist the company IDENTITY only. Teams (compartments) and the skill catalog are
    // built afterwards by the operator's coding agent (the agent-setup prompt) and
    // registered to the gateway — setup neither generates nor provisions them.
    onComplete({
      ...EMPTY_COMPANY,
      name: name.trim() || 'My Company',
      tenant: tenant.trim() || 'my-company',
      admin: admin.trim() || 'agent-admin',
      teams: [],
      skills: [],
      setupComplete: true,
    });
  };

  // Launch just persists the company identity and enters the console — there is no
  // catalog to provision here anymore. The console populates as the operator's coding
  // agent registers skills to the gateway (see Skills & Access / the agent-setup prompt).
  const launchNow = (): void => {
    setLaunching(true);
    finish();
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
            {step.id === 'launch' ? (
              <LaunchStep name={name} tenant={tenant} admin={admin} live={live} host={gateway.apiHost} />
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
              {launching ? 'Entering…' : 'Enter console'}
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

function LaunchStep({
  name,
  tenant,
  admin,
  live,
  host,
}: {
  name: string;
  tenant: string;
  admin: string;
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
          label="Gateway"
          value={live ? `live · ${host}` : 'offline — connect later'}
          tone={live ? 'verified' : 'muted'}
        />
      </dl>
      <div className="mt-5 rounded-lg border border-hairline bg-canvas p-3.5">
        <div className="mb-1 flex items-center gap-1.5">
          <Sparkles size={12} className="text-slate-500" />
          <span className="text-[10.5px] font-semibold uppercase tracking-[0.1em] text-slate-500">
            Next: build your catalog
          </span>
        </div>
        <p className="text-[12px] leading-relaxed text-slate-500">
          Your teams and skills are built by pointing a coding agent (Claude Code, Cursor, …) at the
          agent-setup prompt — it interviews you and registers a catalog tailored to your systems.
          Panels stay empty until it does.
        </p>
        <code className="mt-2 block rounded bg-surface px-2 py-1.5 font-mono text-[10.5px] text-ink">
          Fetch https://mcpip.ai/agent-setup/prompt.md and follow it.
        </code>
      </div>
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
