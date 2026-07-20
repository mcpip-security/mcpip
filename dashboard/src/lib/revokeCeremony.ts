/* ---------------------------------------------------------------------------
   Operator principal kill-switch — the console side of the gateway's admin
   revocation endpoints.

   Revoking a principal is a DENY-only control: it blocks every request from a
   (tenant, agent) until an admin reactivates it. It NEVER mints or edits a
   credential — identity stays the IdP's to issue; the gateway's job is only to
   refuse a request bearing an otherwise-valid token.

   The action is capability-gated: it runs under a JWT holding
   CAP_DIRECTORY_ADMIN, minted for the target principal's OWN tenant (revocation
   is tenant-scoped — an admin can only ever block within its own tenant).
--------------------------------------------------------------------------- */

import { mintDevToken, reactivatePrincipal, revokePrincipal } from './api';
import { CAP_DIRECTORY_ADMIN } from './protocol';

/**
 * Revoke or reactivate a principal against a live gateway. Returns a soft result
 * (never throws) so the caller can surface a failure reason inline.
 */
export async function setPrincipalRevocation(opts: {
  apiBase: string;
  tenantId: string;
  agentId: string;
  revoke: boolean;
  reason?: string;
  signal?: AbortSignal;
}): Promise<{ ok: boolean; reason?: string }> {
  const reqOpts = { base: opts.apiBase, signal: opts.signal };
  try {
    const admin = await mintDevToken(
      {
        tenant_id: opts.tenantId,
        agent_id: 'agent-directory-admin',
        capabilities: [CAP_DIRECTORY_ADMIN],
      },
      reqOpts,
    );
    const ok = opts.revoke
      ? await revokePrincipal(admin, opts.agentId, opts.reason ?? null, reqOpts)
      : await reactivatePrincipal(admin, opts.agentId, reqOpts);
    if (ok) {
      return { ok: true };
    }
    return { ok: false, reason: opts.revoke ? 'gateway refused the revoke' : 'gateway refused the reactivate' };
  } catch {
    return { ok: false, reason: 'admin ceremony failed (gateway unreachable?)' };
  }
}
