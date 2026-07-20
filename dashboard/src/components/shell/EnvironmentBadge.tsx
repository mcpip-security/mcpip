import { EDITION } from '../../lib/consoleConfig';
import type { Edition } from '../../lib/consoleConfig';

/**
 * The build-edition badge. Borrows Stripe's rule that a non-production
 * environment must be ALWAYS visible and visually unmistakable, so an operator
 * can never confuse a staging/internal console for production.
 *
 * Renders NOTHING in a production build — production is the unmarked default, so
 * the badge only ever adds a warning, never a reassuring "you're safe" chip that
 * could be faked. The edition is a compile-time constant (`import.meta.env`), so
 * the whole component collapses to `null` in the production bundle.
 */
const STYLE: Record<Exclude<Edition, 'production'>, { label: string; cls: string; dot: string }> = {
  staging: {
    label: 'STAGING',
    // Amber = the house "staged" token; the tokens now carry an alpha channel
    // (rgb(var(--c-staged) / <alpha>)), so a /10 tint reads on both themes.
    cls: 'border-staged text-staged bg-staged/10',
    dot: 'bg-staged',
  },
  internal: {
    label: 'INTERNAL',
    // Neutral + dashed to read as distinct from staging without a second accent.
    cls: 'border-dashed border-slate-400 text-slate-400 bg-canvas',
    dot: 'bg-slate-400',
  },
};

export function EnvironmentBadge(): JSX.Element | null {
  if (EDITION === 'production') return null;
  const { label, cls, dot } = STYLE[EDITION];
  return (
    <span
      title={`This console is a ${label.toLowerCase()} build — not production.`}
      className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-[10.5px] font-semibold uppercase tracking-wide ${cls}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
      {label}
    </span>
  );
}
