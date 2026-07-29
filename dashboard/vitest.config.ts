import { defineConfig } from 'vitest/config';

// Minimal test runner for the operator console. jsdom gives the store tests a
// real `localStorage` + `window` so they exercise the same-tab reactivity path
// (the config-island bug shipped precisely because there was no frontend suite).
export default defineConfig({
  test: {
    environment: 'jsdom',
    // src/** = browser-logic tests (jsdom). tests/** = build-artifact assertions
    // that READ the real config/CSS files, so they live outside the hermetic
    // `types: []` app graph and are typechecked by tsconfig.node.json instead.
    include: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'tests/**/*.test.ts'],
  },
});
