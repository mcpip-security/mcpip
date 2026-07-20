/* ---------------------------------------------------------------------------
   Real protocol constants — the console's mirror of engine-pinned identifiers.

   Every value in this module is quoted byte-for-byte from a backend source of
   truth, pinned in a comment next to each constant. Nothing here is display
   copy or fixture data: these are the UUIDs the gateway actually authorizes
   against, so a drifted value silently breaks live ceremonies (grants, admin
   reads, compartment probes). On change, the pinned backend file is
   authoritative — never this mirror. The old lib/demo.ts fixtures are gone;
   only real protocol values survived into this file.
--------------------------------------------------------------------------- */

import type { Compartment } from './types';

/* ---------------------------------------------------------------------------
   Well-known capability UUIDs — UUID-identified authorization, never a role
   string. Source of truth: interfaces.py §1.1b (CAPABILITY / COMPARTMENT
   CONSTANTS). Carried in the JWT `capabilities` claim minted for admin
   ceremonies; the gateway compares these exact byte sequences.
--------------------------------------------------------------------------- */

/**
 * interfaces.py `CAP_COMPARTMENT_GRANT` — marks a principal as a grant-issuing
 * authority (gates USE of the `skill_compartment_grant` governance alias).
 * Issuing a grant for compartment X additionally requires the scoped
 * `grant_capability_for(X)` (see GRANT_CAP_FOR / lib/uuidv5.ts).
 */
export const CAP_COMPARTMENT_GRANT = '9c2b6f14-7a3d-4e8b-b1c0-2f5a9d3e4c71';

/** interfaces.py `CAP_COMPARTMENT_REVOKE` — the delegated-grant revocation authority. */
export const CAP_COMPARTMENT_REVOKE = '3e7d1a95-6c4b-42f0-8a9e-1b2c3d4e5f60';

/**
 * interfaces.py `CAP_DIRECTORY_ADMIN` — the operator kill-switch / directory
 * authority gating every `/v1/admin/*` surface plus `/v1/directory`. A
 * DENY-only authority: holding it lets an operator BLOCK a principal's
 * requests, never mint one (IdP sovereignty stands).
 */
export const CAP_DIRECTORY_ADMIN = 'b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20';

/**
 * interfaces.py `CAP_FORENSIC_READ` — the SOLE authority that unlocks raw-payload
 * reconstruction via `GET /v1/admin/forensic/{correlation_id}`. It is DELIBERATELY
 * DISTINCT from CAP_DIRECTORY_ADMIN: holding directory-admin does NOT confer
 * forensic read — reconstructing the real query an agent sent is a separately-
 * grantable, higher-sensitivity investigator authority (least privilege). No
 * agent token ever carries it, and every read it authorizes is WORM-audited
 * (`admin_action='forensic_read'`) before the payload is disclosed.
 */
export const CAP_FORENSIC_READ = 'd5f0c9a2-4b71-4e6a-9c83-1a7f2e6b4d90';

/**
 * interfaces.py `CAP_CATALOG_REVIEWER` — the reviewer half of the
 * author-your-own-skill/gate workflow: read the pending queue and approve/reject a
 * community-extension manifest (GET /v1/admin/extensions/pending,
 * POST /v1/admin/extensions/{id}/{approve,reject}). DELIBERATELY DISTINCT from
 * CAP_DIRECTORY_ADMIN and CAP_FORENSIC_READ — "can approve community extensions"
 * is separable from "can revoke a principal" and "can read raw forensic payloads";
 * holding either sibling does NOT confer it. SUBMITTING a manifest needs no
 * capability at all (any authenticated principal). Pinned to interfaces.py.
 */
export const CAP_CATALOG_REVIEWER = '7a1f9c34-2e58-4b6d-9f01-3c7a5e2b8d46';

/**
 * interfaces.py `MAX_GATE_COST` — the ceiling a community-GATE manifest's declared
 * `max_cost` must satisfy (1..MAX_GATE_COST). The console pre-validates against it so
 * an over-budget gate is caught before the fail-closed submit; the gateway remains
 * authoritative. The STATIC cost prover that would confirm the real AST cost is part
 * of the DEFERRED CEL runtime (docs/EXTENSIBILITY.md §8).
 */
export const MAX_GATE_COST = 1_000_000;

/**
 * interfaces.py `GATE_CONTEXT_FIELDS` — the fixed, topology-free whitelist a gate's
 * `referenced_context_fields` must be a subset of. It is EXACTLY the coarse,
 * non-secret projection a gate is handed (opaque alias + coarse transport class +
 * risk tier + classification) — never the real `target`, a secret, or identity.
 */
export const GATE_CONTEXT_FIELDS: ReadonlyArray<string> = [
  'alias',
  'risk_tier',
  'transport_class',
  'classification',
];

/* ---------------------------------------------------------------------------
   SANDBOX SEEDS — the compartmented showcase tenant the sandbox gateway boots
   with. Source of truth: obfuscator/tenant_catalog.py (FALCON / AEGIS /
   SENTINEL + INDUSTRY_COMPARTMENTS['aegis-dynamics']). These are seed data of
   the DEMO defense tenant, NOT universal protocol ids: an operator's own
   compartments come from their company profile / live catalog, never from
   here. They stay pinned because live ceremonies against the seeded tenant
   (JWT `compartment` claims, grant payloads) must match the server seed
   byte-for-byte.
--------------------------------------------------------------------------- */

/** obfuscator/tenant_catalog.py — the one seeded tenant whose teams are compartment-separated. */
export const DEFENSE_TENANT = 'aegis-dynamics';

/**
 * obfuscator/tenant_catalog.py `FALCON` / `AEGIS` / `SENTINEL` +
 * `INDUSTRY_COMPARTMENTS['aegis-dynamics']` labels/classifications, verbatim.
 */
export const SEED_COMPARTMENTS = {
  falcon: {
    compartment_uuid: 'f4100000-0000-4000-8000-0000000fa1c0',
    label: 'project-falcon',
    classification: 'classified',
  },
  aegis: {
    compartment_uuid: 'ae610000-0000-4000-8000-0000000ae615',
    label: 'project-aegis',
    classification: 'classified',
  },
  sentinel: {
    compartment_uuid: '5e470000-0000-4000-8000-0000005e4715',
    label: 'project-sentinel',
    classification: 'restricted',
  },
} as const satisfies Record<string, Compartment>;

export type SeedCompartmentKey = keyof typeof SEED_COMPARTMENTS;

/** The seed compartments as rows (derived — SEED_COMPARTMENTS stays the source). */
export const SEED_COMPARTMENT_LIST: ReadonlyArray<Compartment> =
  Object.values(SEED_COMPARTMENTS);

/**
 * Per-compartment, SCOPED grant-issuing capabilities for the sandbox seeds —
 * the engine's `grant_capability_for(X) = uuid5(CAP_COMPARTMENT_GRANT, X)`
 * (interfaces.py). Pinned byte-for-byte (re-derived and verified against
 * python3 `uuid.uuid5`; see lib/uuidv5.ts for the derivation + check) so seed
 * ceremonies have a sync fast path — WebCrypto SHA-1 is async-only. For ANY
 * other compartment derive at runtime via `grantCapabilityFor()` in
 * lib/uuidv5.ts. Holding the coarse CAP_COMPARTMENT_GRANT alone is NOT
 * enough: the mandate gate additionally requires this per-compartment scope,
 * which is exactly what closes cross-compartment delegation.
 */
export const GRANT_CAP_FOR: Readonly<Record<SeedCompartmentKey, string>> = {
  falcon: 'ad10b1b2-9a5c-5291-a3f9-0adaf9cf1f87',
  aegis: '241ad49a-9f3c-54f2-9e52-3819e08a8d04',
  sentinel: 'd0be8613-9b46-50c9-904a-1c8173e58b38',
};
