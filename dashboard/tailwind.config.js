/** @type {import('tailwindcss').Config} */
export default {
  // The palette is driven entirely by CSS variables keyed on the `data-theme`
  // attribute (see src/index.css), so components never need `dark:` variants.
  // Aligning `darkMode` to that same selector keeps any future `dark:` utility
  // consistent with the attribute the theme controller actually sets.
  darkMode: ['selector', '[data-theme="dark"]'],
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  theme: {
    extend: {
      colors: {
        // Semantic tokens driven by CSS variables so a single `data-theme` on
        // <html> flips the ENTIRE design between light and dark without touching
        // any component. `rgb(var(--x) / <alpha-value>)` keeps every opacity
        // modifier working (bg-ink/90, border-verified/25, …). Values live in
        // src/index.css (`:root` = light, `:root[data-theme="dark"]` = dark).
        canvas: 'rgb(var(--c-canvas) / <alpha-value>)',
        surface: 'rgb(var(--c-surface) / <alpha-value>)',
        elevated: 'rgb(var(--c-elevated) / <alpha-value>)',
        hairline: 'rgb(var(--c-hairline) / <alpha-value>)',
        ink: 'rgb(var(--c-ink) / <alpha-value>)',
        porcelain: 'rgb(var(--c-canvas) / <alpha-value>)',
        // Decision states — tuned per theme for contrast on each surface.
        verified: 'rgb(var(--c-verified) / <alpha-value>)',
        denied: 'rgb(var(--c-denied) / <alpha-value>)',
        staged: 'rgb(var(--c-staged) / <alpha-value>)',
        glow: 'rgb(var(--c-ink) / <alpha-value>)',
        // Semantic "slate" ramp (secondary/muted ink → dividers). In light it is
        // the inverted scale that reads on porcelain; in dark it re-steps to read
        // on the ink canvas. Same class names, opposite direction — one variable.
        slate: {
          50: 'rgb(var(--c-slate-50) / <alpha-value>)',
          100: 'rgb(var(--c-slate-100) / <alpha-value>)',
          200: 'rgb(var(--c-slate-200) / <alpha-value>)',
          300: 'rgb(var(--c-slate-300) / <alpha-value>)',
          400: 'rgb(var(--c-slate-400) / <alpha-value>)',
          500: 'rgb(var(--c-slate-500) / <alpha-value>)',
          600: 'rgb(var(--c-slate-600) / <alpha-value>)',
          700: 'rgb(var(--c-slate-700) / <alpha-value>)',
          800: 'rgb(var(--c-slate-800) / <alpha-value>)',
          900: 'rgb(var(--c-slate-900) / <alpha-value>)',
        },
      },
      fontFamily: {
        sans: [
          'Inter Variable',
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          'Segoe UI',
          'Roboto',
          'sans-serif',
        ],
        mono: [
          'SF Mono',
          'ui-monospace',
          'SFMono-Regular',
          'Menlo',
          'Consolas',
          'monospace',
        ],
      },
      letterSpacing: {
        tightest: '-0.02em',
      },
      keyframes: {
        'mcpip-blink': {
          '0%,49%': { opacity: '1' },
          '50%,100%': { opacity: '0' },
        },
        'mcpip-pulse': {
          '0%': { transform: 'scale(0.85)', opacity: '0.9' },
          '70%': { transform: 'scale(2.4)', opacity: '0' },
          '100%': { transform: 'scale(2.4)', opacity: '0' },
        },
        'mcpip-scan': {
          '0%': { transform: 'translateX(-100%)' },
          '100%': { transform: 'translateX(220%)' },
        },
        'mcpip-shimmer': {
          '0%': { backgroundPosition: '-200% 0' },
          '100%': { backgroundPosition: '200% 0' },
        },
      },
      animation: {
        blink: 'mcpip-blink 1.1s step-end infinite',
        pulse: 'mcpip-pulse 2.4s ease-out infinite',
        scan: 'mcpip-scan 2.6s linear infinite',
        shimmer: 'mcpip-shimmer 3s linear infinite',
      },
      boxShadow: {
        // Layered, low-opacity elevation — a considered enterprise ramp.
        // `panel` carries a soft ambient float so cards lift off the canvas
        // instead of relying on the hairline alone. Colour AND alpha come from
        // src/index.css so each theme gets an elevation that is actually
        // visible on its own canvas (a hardcoded near-black is not).
        panel:
          '0 1px 2px 0 rgb(var(--c-shadow) / var(--c-shadow-key)), 0 4px 12px -4px rgb(var(--c-shadow) / var(--c-shadow-ambient))',
        card: '0 1px 2px 0 rgb(var(--c-shadow) / var(--c-shadow-key))',
        // Two-tone focus ring. The inner band is the surface colour, so the
        // accent band never merges into the control it wraps; the accent band
        // is the ink token, which clears 3:1 on canvas, surface and elevated in
        // BOTH themes. Every call site pairs this with `outline-none`, so this
        // shadow IS the indicator — it has to carry WCAG 2.4.7 / 1.4.11 alone.
        'focus-ring': '0 0 0 2px rgb(var(--c-surface)), 0 0 0 4px rgb(var(--c-focus))',
      },
    },
  },
  plugins: [],
};
