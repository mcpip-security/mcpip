import { useEffect, useState } from 'react';
import { Moon, Sun } from 'lucide-react';
import {
  getResolvedTheme,
  initTheme,
  toggleTheme,
  type ResolvedTheme,
} from '../../lib/theme';

/**
 * A single control that flips the console between light and dark. The palette
 * lives entirely in CSS variables (see lib/theme.ts + index.css), so this button
 * only ever toggles one attribute — the whole design re-themes for free.
 *
 * It seeds from whatever the pre-paint script already applied (no flash), then
 * stays in sync with live OS changes while the operator is on the system default.
 */
export function ThemeToggle(): JSX.Element {
  const [theme, setTheme] = useState<ResolvedTheme>(() => getResolvedTheme());

  useEffect(() => initTheme(setTheme), []);

  const isDark = theme === 'dark';
  return (
    <button
      type="button"
      onClick={() => setTheme(toggleTheme())}
      title={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      aria-label={isDark ? 'Switch to light theme' : 'Switch to dark theme'}
      aria-pressed={isDark}
      className="flex h-8 w-8 items-center justify-center rounded-full border border-hairline bg-surface text-slate-500 transition-colors hover:text-ink focus:outline-none focus-visible:shadow-focus-ring"
    >
      {isDark ? <Sun size={15} /> : <Moon size={15} />}
    </button>
  );
}
