/* ---------------------------------------------------------------------------
   Company configuration — the operator's first-run identity for THIS deployment.

   This is real, persisted state (localStorage), NOT mock data: the setup flow writes
   it once on first launch and every tab reads the company name / tenant from it. It is
   metadata about the deployment (company name, the gateway tenant it administers, the
   admin principal, and the team compartments) — it never mints credentials; the gateway
   stays identity-sovereign. Teams created here map to gateway compartments (blast radius);
   real principals are still minted by the IdP ceremony (scripts/mint_principal.py).
--------------------------------------------------------------------------- */

import { useCallback, useEffect, useState } from 'react';
import type { StarterSkill } from './starterKit';

const KEY = 'mcpip.company.v1';

/**
 * Delete the WHOLE local operator profile — company config, the pinned gateway
 * endpoint, and any other console-local state — then reload so the app lands on
 * the first-run setup. Built for repeatable demos: run the full A→Z flow again
 * from a clean slate. Gateway-side state (registered skills, directory doc,
 * WORM ledger) is intentionally untouched — this deletes the operator's local
 * profile, never the audit record.
 */
export function deleteProfile(): void {
  try {
    for (const k of Object.keys(localStorage)) {
      if (k.startsWith('mcpip.')) localStorage.removeItem(k);
    }
  } catch {
    /* storage disabled — reload still resets in-memory state */
  }
  window.location.reload();
}

export interface CompanyTeam {
  id: string;
  /** Human label, e.g. "Finance". */
  name: string;
  /** Gateway compartment UUID (blast radius) this team maps to. */
  compartment: string;
  /** When this compartment was created in the console (ISO-8601). Optional (legacy). */
  createdAt?: string;
}

export interface CompanyConfig {
  /** Display name, e.g. "MCPIP Inc". */
  name: string;
  /** The gateway tenant this console administers. */
  tenant: string;
  /** The bootstrap admin principal (an IdP-minted identity; not created here). */
  admin: string;
  teams: CompanyTeam[];
  /** The AI-generated starter tools the operator approved (editable later). */
  skills?: StarterSkill[];
  /** The free-text description the operator gave the setup assistant. */
  brief?: string;
  /** True once the first-run setup flow has been completed. */
  setupComplete: boolean;
  /** When this deployment profile was first created (ISO-8601). Optional (legacy). */
  createdAt?: string;
  /** When this deployment profile was last saved (ISO-8601). Optional (legacy). */
  updatedAt?: string;
}

/** Current wall-clock as an ISO-8601 string (console-local creation/update stamps). */
export function nowIso(): string {
  return new Date().toISOString();
}

export const EMPTY_COMPANY: CompanyConfig = {
  name: '',
  tenant: '',
  admin: '',
  teams: [],
  skills: [],
  setupComplete: false,
};

function isConfig(v: unknown): v is CompanyConfig {
  if (typeof v !== 'object' || v === null) return false;
  const c = v as Record<string, unknown>;
  return (
    typeof c.name === 'string' &&
    typeof c.tenant === 'string' &&
    typeof c.setupComplete === 'boolean' &&
    Array.isArray(c.teams)
  );
}

export function loadCompanyConfig(): CompanyConfig | null {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    return isConfig(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function saveCompanyConfig(config: CompanyConfig): CompanyConfig {
  // Stamp creation once (first save) and bump the updated time on every save, so the
  // console can show honest "created / last updated" times for the deployment profile.
  const stamped: CompanyConfig = { ...config, createdAt: config.createdAt ?? nowIso(), updatedAt: nowIso() };
  try {
    localStorage.setItem(KEY, JSON.stringify(stamped));
  } catch {
    /* private mode / storage disabled — session-only config still works in memory */
  }
  return stamped;
}

export function clearCompanyConfig(): void {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

/** A fresh compartment UUID for a new team (browser crypto; deterministic-free fallback). */
export function newCompartmentUuid(): string {
  try {
    if (typeof crypto !== 'undefined' && 'randomUUID' in crypto) return crypto.randomUUID();
  } catch {
    /* fall through */
  }
  const hex = (n: number): string =>
    Array.from({ length: n }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  return `${hex(8)}-${hex(4)}-4${hex(3)}-8${hex(3)}-${hex(12)}`;
}

/** A slug safe to use as a gateway tenant id, derived from a company name. */
export function slugifyTenant(name: string): string {
  return name
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 48);
}

/**
 * Company-config store. Returns the current config (or null until the first-run setup
 * flow completes), plus setters. Persists synchronously to localStorage on every write.
 */
export function useCompanyConfig(): {
  config: CompanyConfig | null;
  setupComplete: boolean;
  save: (config: CompanyConfig) => void;
  reset: () => void;
} {
  const [config, setConfig] = useState<CompanyConfig | null>(() => loadCompanyConfig());

  // Reflect edits made in another tab.
  useEffect(() => {
    const onStorage = (e: StorageEvent): void => {
      if (e.key === KEY) setConfig(loadCompanyConfig());
    };
    window.addEventListener('storage', onStorage);
    return () => window.removeEventListener('storage', onStorage);
  }, []);

  const save = useCallback((next: CompanyConfig): void => {
    setConfig(saveCompanyConfig(next));
  }, []);

  const reset = useCallback((): void => {
    clearCompanyConfig();
    setConfig(null);
  }, []);

  return { config, setupComplete: config?.setupComplete === true, save, reset };
}
