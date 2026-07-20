/* ---------------------------------------------------------------------------
   Workspace generation — the console client for /v1/admin/workspace/*.

   Brief → a reviewable plan (org chart + a governed starter skill catalog) → apply
   through the SAME hardened admin endpoints (register_skill + directory). Used by the
   first-run setup/onboarding flow, whose launch step provisions the drafted workspace
   via applyPlan; there is no separate console tab. The gateway draft is deterministic
   and inference-free; a richer LLM draft (the packaged local-model toolchain) produces
   the identical plan shape and would flow through the same validate → review → apply
   path. Nothing is applied without the operator's action. Managed under a
   CAP_DIRECTORY_ADMIN token minted for the operator's own tenant.
--------------------------------------------------------------------------- */

import {
  draftWorkspace,
  validateWorkspacePlan,
  applyWorkspacePlan,
  mintDevToken,
  type WorkspacePlan,
  type PlanValidation,
} from './api';
import { CAP_DIRECTORY_ADMIN } from './protocol';

export type { WorkspacePlan, PlanSkill, PlanValidation } from './api';

async function adminToken(apiBase: string, tenantId: string, signal?: AbortSignal): Promise<string | null> {
  try {
    return await mintDevToken(
      { tenant_id: tenantId, agent_id: 'agent-workspace-admin', capabilities: [CAP_DIRECTORY_ADMIN] },
      { base: apiBase, signal },
    );
  } catch {
    return null;
  }
}

/** Deterministic draft from a brief (empty on failure). */
export async function draftWorkspacePlan(
  apiBase: string,
  tenantId: string,
  brief: string,
  company: string,
  signal?: AbortSignal,
): Promise<WorkspacePlan | null> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return null;
  return draftWorkspace(token, { brief, company, tenant: tenantId }, { base: apiBase, signal });
}

/** Dry-run validate a (possibly hand-edited) plan. */
export async function validatePlan(
  apiBase: string,
  tenantId: string,
  plan: WorkspacePlan,
  signal?: AbortSignal,
): Promise<PlanValidation | null> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return null;
  return validateWorkspacePlan(token, plan, { base: apiBase, signal });
}

/** Apply a reviewed plan. Returns the created/skipped aliases, or null on refusal. */
export async function applyPlan(
  apiBase: string,
  tenantId: string,
  plan: WorkspacePlan,
  signal?: AbortSignal,
): Promise<{ applied: boolean; created: string[]; skipped: string[] } | null> {
  const token = await adminToken(apiBase, tenantId, signal);
  if (!token) return null;
  return applyWorkspacePlan(token, plan, { base: apiBase, signal });
}
