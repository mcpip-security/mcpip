/* ---------------------------------------------------------------------------
   Cloud IAM environments — the console side of /v1/admin/cloud/environments.

   A CloudEnvironment is a BINDING: which cloud role a compartment may assume, in
   which region, for how long. It holds NO cloud secret — in production the gateway
   assumes the role with its own host identity and vends a short-lived scoped
   credential per authorized call. Managed under a CAP_DIRECTORY_ADMIN token minted
   for the operator's own tenant.
--------------------------------------------------------------------------- */

import {
  listCloudEnvironments,
  putCloudEnvironment,
  deleteCloudEnvironment,
  mintDevToken,
  type CloudEnvironment,
} from './api';
import { CAP_DIRECTORY_ADMIN } from './protocol';

export type { CloudEnvironment } from './api';

async function adminToken(apiBase: string, tenantId: string, signal?: AbortSignal): Promise<string | null> {
  try {
    return await mintDevToken(
      { tenant_id: tenantId, agent_id: 'agent-cloud-admin', capabilities: [CAP_DIRECTORY_ADMIN] },
      { base: apiBase, signal },
    );
  } catch {
    return null;
  }
}

/** Load the tenant's cloud environment bindings (empty on any failure). */
export async function loadCloudEnvironments(
  apiBase: string,
  tenantId: string,
  signal?: AbortSignal,
): Promise<CloudEnvironment[]> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return [];
  return (await listCloudEnvironments(token, { base: apiBase, signal })) ?? [];
}

/** Create or update one binding. Returns true on a durable change. */
export async function saveCloudEnvironment(
  apiBase: string,
  tenantId: string,
  env: CloudEnvironment,
  signal?: AbortSignal,
): Promise<boolean> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return false;
  return putCloudEnvironment(token, env, { base: apiBase, signal });
}

/** Remove one binding. Returns true on a durable change. */
export async function removeCloudEnvironment(
  apiBase: string,
  tenantId: string,
  envId: string,
  signal?: AbortSignal,
): Promise<boolean> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return false;
  return deleteCloudEnvironment(token, envId, { base: apiBase, signal });
}
