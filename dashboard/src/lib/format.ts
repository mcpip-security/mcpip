/* Small formatting + environment helpers. */

/** Detect the OS reduced-motion preference (SSR-safe, defaults to false). */
export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) {
    return false;
  }
  return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
}

/** hh:mm:ss.mmm in local time. */
export function formatClock(ts: number): string {
  const d = new Date(ts);
  const pad = (v: number, w = 2): string => String(v).padStart(w, '0');
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(
    d.getMilliseconds(),
    3,
  )}`;
}

/** Abbreviate a long id: 9f2c41a7…81a3c */
export function truncateId(id: string, head = 8, tail = 5): string {
  if (id.length <= head + tail + 1) {
    return id;
  }
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}

/** Parse an ISO-8601 timestamp to epoch ms, or null if unparseable/absent. */
function parseIso(iso: string | null | undefined): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

/** Compact relative time: "just now", "3m ago", "2h ago", "5d ago", or a date. */
export function formatRelative(iso: string | null | undefined): string {
  const t = parseIso(iso);
  if (t === null) return '—';
  const s = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (s < 45) return 'just now';
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

/** Absolute local timestamp: "Jul 15, 2026 · 19:25". Empty-safe. */
export function formatDateTime(iso: string | null | undefined): string {
  const t = parseIso(iso);
  if (t === null) return '—';
  const d = new Date(t);
  const date = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
  const time = `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
  return `${date} · ${time}`;
}
