/* ---------------------------------------------------------------------------
   MCPIP console — shared UI primitives.

   The design language lives in TWO cooperating layers: the @layer components
   classes in index.css (.panel / .panel-header / .eyebrow / .metric / .btn /
   .chip / .id), which views apply directly to dense markup, and the React
   primitives below for the recurring composites (panels, badges, fields,
   selects, empty states, inspector rows). Views mix both freely — same
   charter either way (do not diverge per-view):
     • SANS (Inter) for all chrome — titles, labels, controls, headers.
     • MONO for data cells only — hashes, JWTs, IDs, timestamps, UUIDs.
     • Panels: rounded-xl · hairline border · shadow-panel. Header: sans-semibold
       title + optional icon (left) and a muted meta (right).
     • Tables: sans uppercase headers, mono data, row hover = bg-canvas.
     • Empty over fake: when there is no data, render <EmptyState>, never a mock.
--------------------------------------------------------------------------- */

import { ChevronDown } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

type Tone = 'ink' | 'verified' | 'denied' | 'staged' | 'muted';

const TONE_TEXT: Record<Tone, string> = {
  ink: 'text-ink',
  verified: 'text-verified',
  denied: 'text-denied',
  staged: 'text-staged',
  muted: 'text-slate-500',
};

/* --- Panel + header -------------------------------------------------------- */

export function Panel({
  children,
  className = '',
}: {
  children: React.ReactNode;
  className?: string;
}): JSX.Element {
  return <div className={`panel flex min-h-0 flex-col overflow-hidden ${className}`}>{children}</div>;
}

export function PanelHeader({
  title,
  icon: Icon,
  right,
}: {
  title: string;
  icon?: LucideIcon;
  right?: React.ReactNode;
}): JSX.Element {
  return (
    <div className="flex shrink-0 items-center justify-between gap-3 border-b border-hairline px-4 py-2.5">
      <div className="flex min-w-0 items-center gap-2">
        {Icon ? <Icon size={14} className="shrink-0 text-slate-500" /> : null}
        <span className="truncate text-[13px] font-semibold text-ink">{title}</span>
      </div>
      {right != null ? <div className="shrink-0 text-[11px] text-slate-500">{right}</div> : null}
    </div>
  );
}

/* --- Badges ---------------------------------------------------------------- */

export function Badge({
  children,
  tone = 'muted',
}: {
  children: React.ReactNode;
  tone?: Tone;
}): JSX.Element {
  const map: Record<Tone, string> = {
    ink: 'border-hairline bg-elevated text-ink',
    muted: 'border-hairline bg-elevated text-slate-400',
    verified: 'border-verified/25 bg-verified/8 text-verified',
    denied: 'border-denied/25 bg-denied/8 text-denied',
    staged: 'border-staged/25 bg-staged/8 text-staged',
  };
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[10.5px] font-semibold uppercase tracking-wide ${map[tone]}`}>
      {children}
    </span>
  );
}

/* --- Field / inputs -------------------------------------------------------- */

const FIELD_LABEL = 'text-[10.5px] font-medium uppercase tracking-[0.1em] text-slate-500';
const CONTROL =
  'w-full rounded-lg border border-hairline bg-canvas px-2.5 py-1.5 text-[12.5px] text-ink outline-none focus:border-ink/30 focus:shadow-focus-ring';

export function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}): JSX.Element {
  return (
    <label className="flex flex-col gap-1">
      <span className={FIELD_LABEL}>{label}</span>
      {children}
    </label>
  );
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement> & { mono?: boolean }): JSX.Element {
  const { mono, className = '', ...rest } = props;
  return <input {...rest} className={`${CONTROL} ${mono ? 'font-mono text-[12px]' : 'font-medium'} ${className}`} />;
}

/**
 * The ONE dropdown. `appearance-none` + our own chevron so every select across the
 * system renders identically (no per-browser default arrow), sized and toned exactly
 * like Input. Pass `mono` for value-is-data selects (tenants, compartments).
 */
export function Select(
  props: React.SelectHTMLAttributes<HTMLSelectElement> & { mono?: boolean },
): JSX.Element {
  const { className = '', mono, children, ...rest } = props;
  return (
    <span className={`relative inline-flex w-full ${className}`}>
      <select
        {...rest}
        className={`${CONTROL} cursor-pointer appearance-none pr-8 ${mono ? 'font-mono text-[12px]' : 'font-medium'} disabled:cursor-not-allowed disabled:opacity-50`}
      >
        {children}
      </select>
      <ChevronDown
        size={14}
        className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500"
        aria-hidden="true"
      />
    </span>
  );
}

/* --- Empty state ----------------------------------------------------------- */

export function EmptyState({
  icon: Icon,
  title,
  detail,
  action,
}: {
  icon: LucideIcon;
  title: string;
  detail?: string;
  /** Optional call-to-action rendered under the detail (e.g. a "Connect" button). */
  action?: React.ReactNode;
}): JSX.Element {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2 px-6 py-12 text-center">
      {/* slate-500, not -600: this icon is meaningful non-text content (1.4.11),
          and slate-600 is the ramp's decorative step (2.40:1 light / 2.78:1 dark
          on elevated). Only the ramp's USE moves; the ramp itself stays. */}
      <Icon size={24} className="text-slate-500" />
      <p className="text-[13px] font-medium text-slate-400">{title}</p>
      {detail ? <p className="max-w-sm text-[11.5px] leading-relaxed text-slate-500">{detail}</p> : null}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

/* --- Definition list (inspector detail rows) ------------------------------- */

export function Detail({
  label,
  children,
  mono,
  span,
  tone = 'ink',
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
  span?: boolean;
  tone?: Tone;
}): JSX.Element {
  return (
    <div className={span ? 'col-span-2' : ''}>
      <dt className="mb-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] text-slate-500">{label}</dt>
      <dd className={`text-[11.5px] ${mono ? 'break-all font-mono' : 'font-medium'} ${TONE_TEXT[tone]}`}>{children}</dd>
    </div>
  );
}
