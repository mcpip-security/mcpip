/* ---------------------------------------------------------------------------
   Operator directory persistence — the console side of GET/PUT /v1/directory.

   The org chart the operator edits (Org Units → Teams → principal references) is
   NON-authoritative metadata: persisting it lets the directory survive across
   sessions and nodes, but it never mints identity and the gateway never consults
   it for authorization (that stays JWT + grants + the revocation kill-switch).

   Both calls run under a CAP_DIRECTORY_ADMIN token minted for the OPERATOR'S
   REAL company tenant (the first-run profile). Before setup completes there is
   no tenant, so persistence fails soft — nothing is ever written under a
   fixture tenant.
--------------------------------------------------------------------------- */

import { getDirectory, putDirectory, mintDevToken } from './api';
import type { DirectoryDocument } from './api';
import { CAP_DIRECTORY_ADMIN } from './protocol';
import { loadCompanyConfig } from './companyConfig';

const SCHEMA = 'mcpip-directory/1' as const;

/**
 * The tenant the console persists its directory under: the operator's real
 * company tenant from the setup profile, or null when setup hasn't completed.
 */
export function directoryTenant(): string | null {
  const tenant = loadCompanyConfig()?.tenant.trim();
  return tenant ? tenant : null;
}

async function adminToken(apiBase: string, signal?: AbortSignal): Promise<string | null> {
  const tenantId = directoryTenant();
  if (tenantId === null) {
    return null;
  }
  try {
    return await mintDevToken(
      {
        tenant_id: tenantId,
        agent_id: 'agent-directory-admin',
        capabilities: [CAP_DIRECTORY_ADMIN],
      },
      { base: apiBase, signal },
    );
  } catch {
    return null;
  }
}

/** Load the persisted org units, or null when none saved / unavailable. */
export async function loadDirectory(
  apiBase: string,
  signal?: AbortSignal,
): Promise<{ orgUnits: unknown[]; rbac?: Record<string, string[]> } | null> {
  const token = await adminToken(apiBase, signal);
  if (!token) return null;
  const doc = await getDirectory(token, { base: apiBase, signal });
  if (!doc || !Array.isArray(doc.org_units)) return null;
  return { orgUnits: doc.org_units, ...(doc.rbac ? { rbac: doc.rbac } : {}) };
}

/** Persist the org units (+ optional RBAC). Returns true on a durable save. */
export async function saveDirectory(
  apiBase: string,
  orgUnits: unknown[],
  rbac?: Record<string, string[]>,
  signal?: AbortSignal,
): Promise<boolean> {
  const token = await adminToken(apiBase, signal);
  if (!token) return false;
  const document: DirectoryDocument = { schema: SCHEMA, org_units: orgUnits, ...(rbac ? { rbac } : {}) };
  return putDirectory(token, document, { base: apiBase, signal });
}
