/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_BASE?: string;
  /** The build edition — 'production' | 'staging' | 'internal'. Set per Vite mode
   * via `.env.<mode>` and read through `resolveEdition()` in `lib/consoleConfig.ts`.
   * Absent or unrecognized ⇒ resolves to 'production' (the safe, leanest surface). */
  readonly VITE_MCPIP_EDITION?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}

/** The console's own build version (package.json), injected by Vite `define`. */
declare const __APP_VERSION__: string;

/** The repository CHANGELOG.md (repo root), injected by Vite `define` at build so
 * the in-app Docs → Release Notes surface renders the REAL shipped history. Empty
 * string if the changelog was absent at build (Docs shows an honest empty state). */
declare const __CHANGELOG__: string;
