/* ---------------------------------------------------------------------------
   Operator skill kill-switch — the console side of the /v1/admin/skills endpoints.

   Disabling a skill is a DENY-only control: while disabled, an alias is denied
   SKILL_DISABLED for every caller in the tenant, regardless of capability. It
   NEVER edits the alias→target mapping — the obfuscation layer stays immutable;
   the operator can only toggle availability.

   Runs under a CAP_DIRECTORY_ADMIN token minted for the catalog's own tenant
   (disable is tenant-scoped).
--------------------------------------------------------------------------- */

import {
  listDisabledSkills,
  listRegisteredSkills,
  setSkillDisabled as apiSetSkillDisabled,
  registerSkill as apiRegisterSkill,
  deregisterSkill as apiDeregisterSkill,
  mintDevToken,
  type RegisterSkillBody,
  type RegisteredSkill,
} from './api';
import { CAP_DIRECTORY_ADMIN } from './protocol';

async function adminToken(apiBase: string, tenantId: string, signal?: AbortSignal): Promise<string | null> {
  try {
    return await mintDevToken(
      { tenant_id: tenantId, agent_id: 'agent-directory-admin', capabilities: [CAP_DIRECTORY_ADMIN] },
      { base: apiBase, signal },
    );
  } catch {
    return null;
  }
}

/** Load the set of disabled alias names for the tenant. */
export async function loadDisabledSkills(apiBase: string, tenantId: string, signal?: AbortSignal): Promise<string[]> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return [];
  return (await listDisabledSkills(token, { base: apiBase, signal })) ?? [];
}

/** Load the operator-registered (deregisterable) skills — alias + creation timestamp. */
export async function loadRegisteredSkills(apiBase: string, tenantId: string, signal?: AbortSignal): Promise<RegisteredSkill[]> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return [];
  return (await listRegisteredSkills(token, { base: apiBase, signal })) ?? [];
}

/** Disable or enable one alias for the tenant. Returns true on a durable change. */
export async function setSkillDisabled(
  apiBase: string,
  tenantId: string,
  alias: string,
  disabled: boolean,
  signal?: AbortSignal,
): Promise<boolean> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return false;
  return apiSetSkillDisabled(token, alias, disabled, { base: apiBase, signal });
}

/**
 * Register a NEW operator skill (a new alias→target) for the tenant. Additive only —
 * the gateway refuses to shadow a config alias. Returns true on a durable 200.
 */
export async function registerSkill(
  apiBase: string,
  tenantId: string,
  body: RegisterSkillBody,
  signal?: AbortSignal,
): Promise<boolean> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return false;
  return apiRegisterSkill(token, body, { base: apiBase, signal });
}

/**
 * Deregister an OPERATOR-registered skill. `removed` is true only when an overlay row
 * was actually dropped (config aliases are a no-op success). Returns { ok, removed }.
 */
export async function deregisterSkill(
  apiBase: string,
  tenantId: string,
  alias: string,
  signal?: AbortSignal,
): Promise<{ ok: boolean; removed: boolean }> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return { ok: false, removed: false };
  return apiDeregisterSkill(token, alias, { base: apiBase, signal });
}
