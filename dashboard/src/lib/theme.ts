/**
 * Theme controller for the operator console.
 *
 * A single `data-theme` attribute on <html> drives the entire palette: every
 * color token in tailwind.config.js resolves to a CSS variable whose value is
 * keyed on `:root` (light) vs `:root[data-theme='dark']` (dark) in index.css.
 * Flipping this one attribute re-themes every component at once — no `dark:`
 * variants, no per-component work.
 *
 * Preference resolution:
 *   - An explicit operator choice ('light' | 'dark') is persisted in
 *     localStorage and always wins.
 *   - With no stored choice we follow the OS ('system'), tracking live changes
 *     to `prefers-color-scheme` until the operator picks a side.
 *
 * The very first paint is handled by an inline script in index.html (see
 * applyPrePaint's twin there) so there is never a light-flash before React
 * mounts; this module is the source of truth once the app is running.
 */

export type ThemeChoice = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'light' | 'dark';

const STORAGE_KEY = 'mcpip:theme';

// Canvas colors per theme, kept byte-identical to index.css so the browser
// chrome (address bar / status bar tint) matches the console surface exactly.
const THEME_COLOR: Record<ResolvedTheme, string> = {
  light: '#f9f9f9',
  dark: '#0c0c0e',
};

function systemPrefersDark(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  );
}

/** The operator's stored choice, or 'system' when they haven't picked a side. */
export function getThemeChoice(): ThemeChoice {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw === 'light' || raw === 'dark') return raw;
  } catch {
    /* localStorage can throw in private-mode / sandboxed frames — fall through. */
  }
  return 'system';
}

/** The theme actually in effect right now (choice resolved against the OS). */
export function getResolvedTheme(): ResolvedTheme {
  const choice = getThemeChoice();
  if (choice === 'system') return systemPrefersDark() ? 'dark' : 'light';
  return choice;
}

/** Paint the resolved theme onto <html> and sync the browser-chrome meta. */
export function applyTheme(theme: ResolvedTheme): void {
  const root = document.documentElement;
  if (theme === 'dark') root.setAttribute('data-theme', 'dark');
  else root.removeAttribute('data-theme');

  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute('content', THEME_COLOR[theme]);
  const scheme = document.querySelector('meta[name="color-scheme"]');
  if (scheme) scheme.setAttribute('content', theme);
}

/** Persist an explicit choice (or clear it back to 'system') and repaint. */
export function setThemeChoice(choice: ThemeChoice): void {
  try {
    if (choice === 'system') localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, choice);
  } catch {
    /* Best-effort persistence; the in-memory paint below still applies. */
  }
  applyTheme(getResolvedTheme());
}

/** Flip between light and dark from whatever is currently resolved. */
export function toggleTheme(): ResolvedTheme {
  const next: ResolvedTheme = getResolvedTheme() === 'dark' ? 'light' : 'dark';
  setThemeChoice(next);
  return next;
}

/**
 * Start the theme controller: paint the current resolution and, while the
 * operator is still on 'system', track live OS changes. Returns a disposer.
 */
export function initTheme(onChange?: (t: ResolvedTheme) => void): () => void {
  applyTheme(getResolvedTheme());

  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') {
    return () => undefined;
  }
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const handler = (): void => {
    // Only OS-follow while no explicit choice is stored.
    if (getThemeChoice() !== 'system') return;
    const resolved = getResolvedTheme();
    applyTheme(resolved);
    onChange?.(resolved);
  };
  mq.addEventListener('change', handler);
  return () => mq.removeEventListener('change', handler);
}
