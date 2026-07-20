/* ---------------------------------------------------------------------------
   Real compartment-grant ceremony — the operator-facing side of the gateway's
   `skill_compartment_grant` EXECUTE mandate.

   Issuing a delegated compartment grant is NOT a directory write; it is a
   payload-bound, step-up-gated authorization that flows through the SAME
   /v1/authorize choke point as every other privileged action:

     mint a compartment-scoped officer  →  POST /v1/authorize (202 staged)
       →  fetch the one-time code out-of-band  →  POST /v1/authorize (pin + challenge_id)
       →  200: the grant is durably in the Redis GrantStore with EX=ttl.

   The officer must hold BOTH the coarse `compartment_grant` capability AND the
   per-compartment `grant_capability_for(X)` scope — holding one without the
   other is denied, which is exactly what stops a grant capability from being a
   tenant-wide master key. The ceremony works for ANY compartment UUID: the
   scoped capability is derived at runtime (lib/uuidv5.ts, byte-identical to
   interfaces.py grant_capability_for), with the pinned sandbox-seed values as
   a fast path. Only a well-formed compartment UUID can be resolved; anything
   else fails closed to a local-only staging grant.
--------------------------------------------------------------------------- */

import { authenticatorOtp, authorize, mintDevToken } from './api';
import {
  CAP_COMPARTMENT_GRANT,
  DEFENSE_TENANT,
  GRANT_CAP_FOR,
  SEED_COMPARTMENTS,
} from './protocol';
import type { SeedCompartmentKey } from './protocol';
import { grantCapabilityFor, isUuid } from './uuidv5';
import { loadCompanyConfig } from './companyConfig';

/** A resolved grant target: compartment + its scoped grant-issuing capability. */
export interface ResolvedCompartment {
  uuid: string;
  grantCap: string;
  /** The seed tenant that owns a sandbox-seed compartment; null = operator compartment. */
  seedTenant: string | null;
}

/** The truncated form the org tree renders (e.g. `f4100000…fa1c0`). */
function shortForm(full: string): string {
  return `${full.slice(0, 8)}…${full.slice(-5)}`;
}

/**
 * Resolve a compartment display string to a grantable compartment. Sandbox
 * seeds match by full UUID or the truncated org-tree form and use the PINNED
 * scoped capability (sync-verified against the engine); any other well-formed
 * UUID gets its scoped capability DERIVED at runtime. A truncated non-seed
 * form cannot be resolved (the derivation needs the full UUID) → null, and the
 * caller falls back to a local staging grant — never a fabricated live one.
 */
export async function resolveCompartment(display: string): Promise<ResolvedCompartment | null> {
  const d = display.trim();
  for (const key of Object.keys(SEED_COMPARTMENTS) as SeedCompartmentKey[]) {
    const uuid = SEED_COMPARTMENTS[key].compartment_uuid;
    if (uuid === d || shortForm(uuid) === d) {
      return { uuid, grantCap: GRANT_CAP_FOR[key], seedTenant: DEFENSE_TENANT };
    }
  }
  if (!isUuid(d)) {
    return null;
  }
  try {
    return { uuid: d, grantCap: await grantCapabilityFor(d), seedTenant: null };
  } catch {
    return null;
  }
}

export type GrantResult =
  | { ok: true; reference: string; wormSequence: number; compartmentUuid: string }
  | { ok: false; reason: string };

/**
 * Run the full step-up grant ceremony against a live gateway. Returns the
 * committing transaction reference on success (the grant is now in Redis with
 * EX=ttl), or a soft failure reason — never throws.
 *
 * The officer is minted for the tenant that OWNS the compartment: the seed
 * defense tenant for sandbox seeds, otherwise `tenantId` (defaulting to the
 * operator's company tenant) — compartments are tenant-scoped, so a mismatched
 * tenant would be denied by the gateway anyway.
 */
export async function issueCompartmentGrant(opts: {
  apiBase: string;
  granteeAgentId: string;
  compartmentDisplay: string;
  ttlSeconds: number;
  /** Tenant that owns the compartment (ignored for sandbox seeds). */
  tenantId?: string;
  signal?: AbortSignal;
}): Promise<GrantResult> {
  const known = await resolveCompartment(opts.compartmentDisplay);
  if (!known) {
    return { ok: false, reason: 'not a resolvable compartment UUID — staged locally only' };
  }
  const tenantId = known.seedTenant ?? opts.tenantId ?? loadCompanyConfig()?.tenant ?? null;
  if (!tenantId) {
    return { ok: false, reason: 'no tenant owns this compartment — complete the company setup first' };
  }
  const base = opts.apiBase;
  const reqOpts = { base, signal: opts.signal };
  const officerClaims = {
    tenant_id: tenantId,
    agent_id: 'agent-directory-officer',
    capabilities: [CAP_COMPARTMENT_GRANT, known.grantCap],
  };
  // Byte-identical args across stage + consume — the payload lock is over them.
  const grantArgs = {
    grantee: opts.granteeAgentId,
    compartment: known.uuid,
    ttl_seconds: opts.ttlSeconds,
  };
  const request = {
    source_format: 'raw_mcp' as const,
    tool_call: { tool: 'skill_compartment_grant', arguments: grantArgs },
  };
  try {
    const officer = await mintDevToken(officerClaims, reqOpts);
    const staged = await authorize(request, { token: officer, base, signal: opts.signal });
    if (staged.kind === 'denied') {
      // Opaque on the wire, honest to the operator: the mandate gate denies e.g.
      // a compartment the gateway doesn't know — WORM holds the concrete reason.
      return { ok: false, reason: 'gateway denied the grant mandate (see the WORM ledger)' };
    }
    if (staged.kind !== 'staged') {
      return { ok: false, reason: 'gateway did not require step-up (grant not staged)' };
    }
    const otp = await authenticatorOtp(officer, staged.challenge.challenge_id, reqOpts);
    if (!otp) {
      return { ok: false, reason: 'authenticator code unavailable' };
    }
    const committed = await authorize(
      { ...request, pin: otp, challenge_id: staged.challenge.challenge_id },
      { token: officer, base, signal: opts.signal },
    );
    if (committed.kind !== 'executed') {
      return { ok: false, reason: 'grant not committed by the gateway' };
    }
    return {
      ok: true,
      reference: committed.receipt.transaction_ref,
      wormSequence: committed.receipt.worm_sequence,
      compartmentUuid: known.uuid,
    };
  } catch {
    return { ok: false, reason: 'ceremony failed (gateway unreachable?)' };
  }
}
