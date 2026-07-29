/**
 * The design system's two silent-failure modes, closed.
 *
 * Both were found by reviewing the theme pass, and neither is caught by `tsc` or
 * `vite build` — which is exactly why they need a test:
 *
 *  1. A DELETED Tailwind utility. The theme pass removed `shadow-raised`,
 *     `shadow-popover` and `shadow-glow`. Tailwind emits nothing for a class it
 *     does not recognise: no error, no warning, just an element that silently
 *     loses its shadow. Today there are zero orphans; nothing stopped tomorrow's
 *     `shadow-raised` from rendering as nothing.
 *
 *  2. A muted-text step that stops being readable. `--c-slate-500` carries the
 *     captions, the 10.5–11px prose and the inactive sub-tab labels — real text
 *     that owes 4.5:1. It has to clear that on its WORST ground, and which ground
 *     is worst FLIPS between themes: in light the text is dark, so the darkest
 *     background (canvas) is worst; in dark the text is light, so the LIGHTEST
 *     background (elevated) is worst. Checking only one, or only one theme, is
 *     how 115/115/115 shipped at 4.39 on canvas while passing on surface.
 *
 * Both parse the real files, so they fail on the source of truth rather than on a
 * copy of it.
 */

import { describe, expect, it } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'

const ROOT = join(__dirname, '..')
const SRC = join(ROOT, 'src')

function walk(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) walk(p, out)
    else if (/\.(tsx?|css)$/.test(entry)) out.push(p)
  }
  return out
}

const SOURCES = walk(SRC).map((p) => ({ path: p, text: readFileSync(p, 'utf8') }))
const TAILWIND = readFileSync(join(ROOT, 'tailwind.config.js'), 'utf8')
const INDEX_CSS = readFileSync(join(SRC, 'index.css'), 'utf8')

/** Shadow keys the Tailwind config actually defines. */
function definedShadows(): Set<string> {
  const block = TAILWIND.slice(TAILWIND.indexOf('boxShadow:'))
  const body = block.slice(0, block.indexOf('\n      }'))
  const keys = new Set<string>()
  for (const m of body.matchAll(/^\s{8}'?([a-z-]+)'?:/gm)) keys.add(m[1])
  return keys
}

describe('no orphaned Tailwind utilities', () => {
  it('every shadow-* class used in src/ is defined in tailwind.config.js', () => {
    const defined = definedShadows()
    // Tailwind's own built-ins stay legal — only the project's custom ramp is checked.
    const builtin = new Set(['sm', 'md', 'lg', 'xl', '2xl', 'inner', 'none'])
    const orphans: string[] = []
    for (const { path, text } of SOURCES) {
      // Only class-bearing sources. .css is skipped because `--c-shadow-key` is a
      // custom PROPERTY, not a utility class, and this test's own prose names the
      // deleted utilities on purpose.
      if (!/\.tsx?$/.test(path) || path.endsWith('.test.ts') || path.endsWith('.test.tsx')) continue
      // The lookbehind keeps `--c-shadow-*` and `drop-shadow-*` out: a real utility
      // is never preceded by a hyphen or a word character.
      for (const m of text.matchAll(/(?<![-\w])shadow-([a-z][a-z0-9-]*)\b/g)) {
        const name = m[1]
        if (builtin.has(name) || defined.has(name)) continue
        orphans.push(`${path.replace(ROOT + '/', '')}: shadow-${name}`)
      }
    }
    expect(
      orphans,
      `these classes render NOTHING — Tailwind silently drops unknown utilities:\n${orphans.join('\n')}`,
    ).toEqual([])
  })

  it('defines the shadows the app actually uses', () => {
    // Guards the reverse direction: a config rewrite that dropped `panel` would
    // otherwise only show up as a flat UI nobody notices in review.
    const defined = definedShadows()
    for (const required of ['panel', 'card', 'focus-ring']) {
      expect(defined.has(required), `boxShadow.${required} is missing`).toBe(true)
    }
  })
})

// --- contrast ---------------------------------------------------------------

/** An sRGB triple. A fixed-length tuple so strict index checks stay satisfied. */
type Rgb = readonly [number, number, number]

function channel(c: number): number {
  const s = c / 255
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
}
function luminance([r, g, b]: Rgb): number {
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}
function contrast(a: Rgb, b: Rgb): number {
  const la = luminance(a)
  const lb = luminance(b)
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05)
}

/** Read one `--c-*: r g b;` triple out of a theme block in index.css. */
function token(theme: 'light' | 'dark', name: string): Rgb {
  const start =
    theme === 'light' ? INDEX_CSS.indexOf(':root {') : INDEX_CSS.indexOf(":root[data-theme='dark']")
  expect(start, `${theme} theme block not found`).toBeGreaterThan(-1)
  const block = INDEX_CSS.slice(start, INDEX_CSS.indexOf('}', INDEX_CSS.indexOf('--c-focus', start)))
  const m = block.match(new RegExp(`--c-${name}:\\s*(\\d+)\\s+(\\d+)\\s+(\\d+)`))
  if (!m) throw new Error(`--c-${name} not found in the ${theme} block of index.css`)
  return [Number(m[1]), Number(m[2]), Number(m[3])] as const
}

const GROUNDS = ['canvas', 'surface', 'elevated'] as const

describe('muted body text is readable on every ground, in both themes', () => {
  for (const theme of ['light', 'dark'] as const) {
    it(`${theme}: slate-500 clears 4.5:1 on canvas, surface AND elevated`, () => {
      const fg = token(theme, 'slate-500')
      for (const ground of GROUNDS) {
        const bg = token(theme, ground)
        const ratio = contrast(fg, bg)
        expect(
          ratio,
          `${theme} slate-500 on ${ground} is ${ratio.toFixed(2)}:1 — below the 4.5 floor for ` +
            `the 10.5–13px text this step carries`,
        ).toBeGreaterThanOrEqual(4.5)
      }
    })
  }

  it('the decorative step never carries interpolated data', () => {
    // slate-600 is deliberately BELOW 4.5:1 — it exists for inert marks (·, chevrons,
    // empty-state icons). The review found it rendering a percentage, a latency and a
    // transport name: real values a reader has to read, at 11px, at 2.52:1 on white.
    // A `{...}` interpolation inside a slate-600 element is the signature of that
    // mistake, so it is refused here rather than re-discovered in a browser.
    const offenders: string[] = []
    for (const { path, text } of SOURCES) {
      if (!/\.tsx$/.test(path)) continue
      for (const m of text.matchAll(/<(\w+)[^>]*\btext-slate-600\b[^>]*>([^<]*)</g)) {
        if (/\{[^}]+\}/.test(m[2] ?? '')) {
          offenders.push(`${path.replace(ROOT + '/', '')}: <${m[1]}>${(m[2] ?? '').trim().slice(0, 40)}`)
        }
      }
    }
    expect(
      offenders,
      `slate-600 is the DECORATIVE step (below 4.5:1 by design) and these render real ` +
        `values with it — move them to slate-500:\n${offenders.join('\n')}`,
    ).toEqual([])
  })

  it('the ramp stays monotonic so the hierarchy still reads', () => {
    // Fixing contrast by dragging 500 toward 400 would satisfy the floor while
    // destroying the muted/emphasis distinction the ramp exists to express.
    for (const theme of ['light', 'dark'] as const) {
      const l400 = luminance(token(theme, 'slate-400'))
      const l500 = luminance(token(theme, 'slate-500'))
      const l600 = luminance(token(theme, 'slate-600'))
      if (theme === 'light') {
        // Inverted ramp: higher step = lighter = less emphasis.
        expect(l400, 'light 400 must stay darker than 500').toBeLessThan(l500)
        expect(l500, 'light 500 must stay darker than 600').toBeLessThan(l600)
      } else {
        expect(l400, 'dark 400 must stay lighter than 500').toBeGreaterThan(l500)
        expect(l500, 'dark 500 must stay lighter than 600').toBeGreaterThan(l600)
      }
    }
  })

  it('status tokens clear 4.5:1 as Badge text over a /8 wash of themselves', () => {
    // The Badge renders the token as text over an 8% tint of the SAME token; the
    // composite is what a reader sees, and it is what the 600→700 move fixed.
    for (const theme of ['light', 'dark'] as const) {
      for (const name of ['verified', 'denied', 'staged']) {
        const fg = token(theme, name)
        for (const ground of GROUNDS) {
          const bg = token(theme, ground)
          const wash: Rgb = [
            fg[0] * 0.08 + bg[0] * 0.92,
            fg[1] * 0.08 + bg[1] * 0.92,
            fg[2] * 0.08 + bg[2] * 0.92,
          ]
          const ratio = contrast(fg, wash)
          expect(
            ratio,
            `${theme} ${name} badge on ${ground} is ${ratio.toFixed(2)}:1`,
          ).toBeGreaterThanOrEqual(4.5)
        }
      }
    }
  })
})
