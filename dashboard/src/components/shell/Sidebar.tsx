import { Lock } from 'lucide-react';
import { Logomark } from '../Logo';
import { SECTIONS, sectionGateState } from '../../lib/nav';
import type { Section, SectionId } from '../../lib/nav';
import type { FeaturePosture, GateState } from '../../lib/consoleConfig';

/**
 * Persistent left-hand navigation — a FLAT rail of the four sections (Monitor /
 * Governance / Gateway / Developers), one scannable level. Sub-tabs live in the
 * top segmented bar; the group-label layer is gone, so the rail is four items,
 * not eight-under-four (the Vercel / Linear shape).
 *
 * Responsive: a static 248px rail at `lg`+, and a slide-over drawer below `lg`
 * (toggled from the header hamburger, dismissed by the backdrop or any selection).
 */

interface SidebarProps {
  section: SectionId;
  /** True while the /healthz probe loop has a real gateway answering. */
  live: boolean;
  /** Live feature posture — resolves each section's edition·tier·feature gate. */
  posture: FeaturePosture;
  onSelectSection: (id: SectionId) => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}

function SectionButton({
  item,
  active,
  state,
  onSelect,
}: {
  item: Section;
  active: boolean;
  state: GateState;
  onSelect: () => void;
}): JSX.Element {
  const Icon = item.icon;
  const locked = state === 'lock';
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-current={active ? 'page' : undefined}
      title={locked ? `${item.label} — requires a higher plan or an enabled feature` : undefined}
      className={`group relative flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left transition-colors ${
        active ? 'bg-canvas text-ink' : 'text-slate-400 hover:bg-canvas hover:text-ink'
      }`}
    >
      <span
        className={`absolute left-0 top-1/2 h-5 w-[3px] -translate-y-1/2 rounded-full transition-colors ${
          active ? 'bg-ink' : 'bg-transparent'
        }`}
        aria-hidden="true"
      />
      <Icon
        size={16}
        strokeWidth={active ? 2.25 : 2}
        className={active ? 'text-ink' : 'text-slate-500 group-hover:text-ink'}
      />
      <span className="flex-1 text-[13px] font-medium tracking-tight">{item.label}</span>
      {locked ? <Lock size={12} className="shrink-0 text-slate-600" aria-label="locked" /> : null}
    </button>
  );
}

export function Sidebar({
  section,
  live,
  posture,
  onSelectSection,
  mobileOpen,
  onCloseMobile,
}: SidebarProps): JSX.Element {
  return (
    <>
      {/* Mobile backdrop */}
      {mobileOpen ? (
        <div
          className="fixed inset-0 z-30 bg-ink/25 lg:hidden"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      ) : null}

      <aside
        className={`fixed inset-y-0 left-0 z-40 flex h-screen w-[248px] shrink-0 flex-col border-r border-hairline bg-surface transition-transform duration-200 ease-out lg:static lg:z-auto lg:translate-x-0 ${
          mobileOpen ? 'translate-x-0 shadow-xl' : '-translate-x-full lg:shadow-none'
        }`}
      >
        {/* Brand */}
        <div className="flex h-16 shrink-0 items-center gap-2.5 border-b border-hairline px-5">
          <Logomark size={22} />
          <div className="leading-tight">
            <p className="text-[14px] font-semibold tracking-tightest text-ink">MCPIP</p>
            <p className="text-[10px] font-medium uppercase tracking-[0.14em] text-slate-500">
              Authorization Plane
            </p>
          </div>
        </div>

        {/* Flat section rail — four items, one level. A `hide` gate removes a
            section entirely; a `lock` gate keeps it visible-but-disabled. */}
        <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-3">
          {SECTIONS.map((s) => ({ s, state: sectionGateState(s, posture) }))
            .filter((x) => x.state !== 'hide')
            .map(({ s, state }) => (
              <SectionButton
                key={s.id}
                item={s}
                active={s.id === section}
                state={state}
                onSelect={() => onSelectSection(s.id)}
              />
            ))}
        </nav>

        {/* Enforcement-posture footer — the dot is BOUND to the live probe:
            green only while a real gateway answers; offline states the fact. */}
        <div className="shrink-0 border-t border-hairline px-5 py-3">
          <p className="eyebrow">Enforcement posture</p>
          <p className="mt-1.5 flex items-center gap-2 text-[11.5px] font-medium text-slate-400">
            <span
              className={`h-1.5 w-1.5 shrink-0 rounded-full ${live ? 'bg-verified' : 'bg-denied'}`}
            />
            {live ? 'Fail-closed · opaque · WORM-first' : 'No gateway connected'}
          </p>
        </div>
      </aside>
    </>
  );
}
