/* ---------------------------------------------------------------------------
   Environment secret vault — the console side of /v1/admin/vault/secrets.

   A VaultSecret is an operator-stored broker credential (an AWS key, a GCP service
   account, an Azure client secret, an API token, a DB password), encrypted at rest by
   the gateway. The console only ever sees METADATA + a non-secret fingerprint: the
   value is write-only (sent once when stored) and is read solely by the broker at vend
   time. Managed under a CAP_DIRECTORY_ADMIN token minted for the operator's own tenant.

   Trust tiers a cloud environment can carry:
     • host identity   — no stored secret; the cloud injects rotating credentials.
     • vault broker key — a stored, encrypted, gateway-only secret (this module).
--------------------------------------------------------------------------- */

import {
  listVaultSecrets,
  putVaultSecret,
  deleteVaultSecret,
  mintDevToken,
  type VaultSecret,
} from './api';
import { CAP_DIRECTORY_ADMIN } from './protocol';

export type { VaultSecret } from './api';

/** Vendors the vault understands. Cloud trio backs cloud_iam brokers; the rest are
 *  generic server-side credentials a downstream target authenticates with. */
export const VAULT_VENDORS = ['aws', 'gcp', 'azure', 'api_key', 'database'] as const;
export type VaultVendor = (typeof VAULT_VENDORS)[number];

/** The material field labels a given vendor expects (guidance only; any flat map works).
 *  These are the broker credentials the gateway spends to authenticate ITSELF to the
 *  cloud when a binding uses the vault tier — never anything the agent sees. */
export const VENDOR_FIELDS: Record<VaultVendor, string[]> = {
  aws: ['access_key_id', 'secret_access_key'],
  gcp: ['service_account_json'],
  azure: ['tenant_id', 'client_id', 'client_secret'],
  api_key: ['api_key'],
  database: ['connection_string'],
};

async function adminToken(apiBase: string, tenantId: string, signal?: AbortSignal): Promise<string | null> {
  try {
    return await mintDevToken(
      { tenant_id: tenantId, agent_id: 'agent-vault-admin', capabilities: [CAP_DIRECTORY_ADMIN] },
      { base: apiBase, signal },
    );
  } catch {
    return null;
  }
}

/** Load the tenant's vault entries (metadata only). `enabled` is false when the gateway
 *  has no vault master key configured — the whole feature is then absent. */
export async function loadVaultSecrets(
  apiBase: string,
  tenantId: string,
  signal?: AbortSignal,
): Promise<{ enabled: boolean; secrets: VaultSecret[] }> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return { enabled: false, secrets: [] };
  return (await listVaultSecrets(token, { base: apiBase, signal })) ?? { enabled: false, secrets: [] };
}

/** Store (create/rotate) one broker credential. The value is transmitted once. */
export async function saveVaultSecret(
  apiBase: string,
  tenantId: string,
  secret: { secret_id: string; vendor: string; description: string; material: Record<string, string> },
  signal?: AbortSignal,
): Promise<boolean> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return false;
  return putVaultSecret(token, secret, { base: apiBase, signal });
}

/** Remove one stored credential. */
export async function removeVaultSecret(
  apiBase: string,
  tenantId: string,
  secretId: string,
  signal?: AbortSignal,
): Promise<boolean> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return false;
  return deleteVaultSecret(token, secretId, { base: apiBase, signal });
}
