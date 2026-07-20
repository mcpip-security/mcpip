import { readFileSync } from 'node:fs';
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Bake the console's own build version (package.json) into the bundle so the
// Software Updates panel can compare the running build against the gateway's
// reported version and against the signed release manifest — the honest,
// no-phone-home "check for updates" signal (an upgrade is a signed redeploy).
const APP_VERSION: string = JSON.parse(
  readFileSync(new URL('./package.json', import.meta.url), 'utf-8'),
).version;

// Bake the repository CHANGELOG (repo root) into the bundle so the in-app
// Docs → Release Notes surface renders the REAL, shipped release history — no
// second copy to drift, no fabricated entries. The running/release version is
// still read live from the gateway (/v1/version) at display time; this is only
// the notes text. Same build-time `define` discipline as __APP_VERSION__.
let CHANGELOG = '';
try {
  CHANGELOG = readFileSync(new URL('../CHANGELOG.md', import.meta.url), 'utf-8');
} catch {
  // Absent changelog ⇒ empty string ⇒ the Docs view shows an honest empty state.
  CHANGELOG = '';
}

/**
 * The sandbox gateway does not send CORS headers, so the dashboard cannot
 * fetch it cross-origin from the dev server. These proxy rules forward the
 * gateway routes same-origin; useGatewayLive falls back to them automatically
 * when a direct fetch to VITE_API_BASE is blocked.
 */
const GATEWAY_PROXY = {
  '/healthz': 'http://127.0.0.1:8080',
  '/readyz': 'http://127.0.0.1:8080',
  '/v1': 'http://127.0.0.1:8080',
} as const;

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(APP_VERSION),
    __CHANGELOG__: JSON.stringify(CHANGELOG),
  },
  server: {
    port: 5173,
    strictPort: false,
    proxy: { ...GATEWAY_PROXY },
  },
  preview: {
    proxy: { ...GATEWAY_PROXY },
  },
  build: {
    target: 'es2020',
    sourcemap: false,
  },
});
