import type { SubTab } from '../../lib/nav';

/**
 * Horizontal sub-tab switcher rendered at the top of each view — the responsive
 * counterpart to the sidebar tree (always visible, scrolls horizontally on narrow
 * screens). Kept in sync with the sidebar via shared state.
 *
 * Styled as a macOS-style segmented control: a single recessed track with a raised
 * white pill under the selected segment — one consistent tab treatment everywhere.
 */
export function SubTabBar({
  subtabs,
  active,
  onSelect,
}: {
  subtabs: ReadonlyArray<SubTab>;
  active: string;
  onSelect: (id: string) => void;
}): JSX.Element {
  return (
    <div
      role="tablist"
      className="inline-flex max-w-full items-center gap-0.5 overflow-x-auto rounded-xl border border-hairline bg-elevated p-0.5"
    >
      {subtabs.map((s) => {
        const on = s.id === active;
        return (
          <button
            key={s.id}
            type="button"
            role="tab"
            onClick={() => onSelect(s.id)}
            aria-selected={on}
            className={`shrink-0 whitespace-nowrap rounded-[9px] px-3 py-1.5 text-[13px] font-medium transition-all ${
              on
                ? 'bg-surface text-ink shadow-card'
                : 'text-slate-500 hover:text-ink'
            }`}
          >
            {s.label}
          </button>
        );
      })}
    </div>
  );
}
