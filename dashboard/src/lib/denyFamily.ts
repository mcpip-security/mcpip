/**
 * Deny-reason TRIAGE families — the console's coarsening of the 29-member deny taxonomy
 * into the seven questions an operator actually acts on.
 *
 * A 29-member taxonomy is right for the WORM record (an auditor needs the precise cause)
 * and wrong for a console (an operator mid-incident needs to sort by WHAT TO DO NEXT).
 * This module is that second view. The precise reason is never replaced — it stays on
 * every row; the family is only how rows group, filter, and count.
 *
 * MIRRORS `interfaces.py` (`DenyFamily` / `DENY_FAMILY`) EXACTLY. The mapping is pinned
 * on the Python side by `tests/test_deny_family.py::test_typescript_mirror_matches`, so
 * these two cannot drift: adding a DenyReason without adding it in BOTH places fails CI.
 *
 * The family is DERIVED from the projection's `deny_reason`, never served by the gateway
 * and never stored — so it cannot disagree with the record it summarizes.
 */

export type DenyFamily =
  | 'tripwire'
  | 'not_permitted'
  | 'identity'
  | 'needs_human'
  | 'malformed'
  | 'catalog'
  | 'infrastructure';

/** Families in OPERATOR-URGENCY order — the order the console lists buckets in. */
export const DENY_FAMILY_ORDER: readonly DenyFamily[] = [
  'tripwire',
  'not_permitted',
  'identity',
  'needs_human',
  'malformed',
  'catalog',
  'infrastructure',
];

interface FamilyMeta {
  /** Bucket name as an operator reads it. */
  readonly label: string;
  /** The next action this bucket implies — the whole reason the grouping exists. */
  readonly action: string;
  /**
   * Semantic tone. `denied` is reserved for the two buckets that mean "something is
   * wrong with the CALLER or with US"; permission outcomes are `staged` (amber) because
   * a compartment deny is the system working correctly, not an incident.
   */
  readonly tone: 'denied' | 'staged' | 'muted';
}

export const DENY_FAMILY_META: Readonly<Record<DenyFamily, FamilyMeta>> = {
  tripwire: {
    label: 'Tripwire',
    action: 'Investigate now — a decoy alias was touched, or a tripped agent is frozen.',
    tone: 'denied',
  },
  not_permitted: {
    label: 'Not permitted',
    action: 'Identity is good; authority is missing. Grant it, or leave it denied.',
    tone: 'staged',
  },
  identity: {
    label: 'Identity',
    action: 'The token or principal failed. Fix it in the IdP, not in MCPIP grants.',
    tone: 'denied',
  },
  needs_human: {
    label: 'Needs a human',
    action: 'Someone has to approve — or find out why the approver was never asked.',
    tone: 'staged',
  },
  malformed: {
    label: 'Malformed',
    action: 'The call was never well-formed. Fix the calling integration.',
    tone: 'muted',
  },
  catalog: {
    label: 'Catalog',
    action: 'The alias is unknown here or switched off. A catalog problem, not a caller one.',
    tone: 'muted',
  },
  infrastructure: {
    label: 'Ours',
    action: 'OUR failure, not the caller’s. Page someone; do not debug their integration.',
    tone: 'denied',
  },
};

/**
 * reason -> family. Mirrors `interfaces.DENY_FAMILY` key-for-key.
 *
 * Grouping is keyed on the OPERATOR'S NEXT ACTION, not on which subsystem raised the
 * deny — which is why `identity_injection` sits under `identity` (mechanically it is a
 * malformed-input rejection, but the operator's next move is an identity investigation)
 * and why `otp_delivery_failed` sits under `needs_human` rather than `infrastructure`
 * (the fix is finding out why the approver was never asked).
 */
const REASON_TO_FAMILY: Readonly<Record<string, DenyFamily>> = {
  canary_tripped: 'tripwire',
  agent_quarantined: 'tripwire',

  cross_tenant: 'not_permitted',
  compartment_denied: 'not_permitted',
  capability_denied: 'not_permitted',
  policy_denied: 'not_permitted',
  policy_gate_denied: 'not_permitted',

  jwt_invalid: 'identity',
  jwt_claims_missing: 'identity',
  sender_constraint_required: 'identity',
  principal_revoked: 'identity',
  delegation_invalid: 'identity',
  identity_injection: 'identity',

  pin_required: 'needs_human',
  pin_not_found: 'needs_human',
  pin_mismatch: 'needs_human',
  payload_mismatch: 'needs_human',
  otp_delivery_failed: 'needs_human',

  unknown_format: 'malformed',
  unknown_vendor: 'malformed',
  schema_violation: 'malformed',
  depth_exceeded: 'malformed',
  size_exceeded: 'malformed',
  illegal_character: 'malformed',

  unknown_alias: 'catalog',
  alias_disabled: 'catalog',

  lock_error: 'infrastructure',
  transport_error: 'infrastructure',
  rate_limited: 'infrastructure',
  internal: 'infrastructure',
};

/**
 * Coarsen a deny reason to its triage family.
 *
 * Returns `null` for an allow (no reason) and for any reason this build does not know —
 * an unknown reason renders UNGROUPED rather than guessed, because a wrong family tells
 * an operator to take the wrong next action. A console one version behind the gateway
 * therefore degrades to "ungrouped", never to "confidently mis-bucketed".
 */
export function denyFamilyOf(reason: string | null | undefined): DenyFamily | null {
  if (!reason) return null;
  return REASON_TO_FAMILY[reason] ?? null;
}

/** Every reason in a family — used to expand a family filter into reason filters. */
export function reasonsInFamily(family: DenyFamily): string[] {
  return Object.keys(REASON_TO_FAMILY)
    .filter((r) => REASON_TO_FAMILY[r] === family)
    .sort();
}

/** Count rows per family, in urgency order, dropping empty buckets. */
export function tallyFamilies(
  reasons: readonly (string | null)[],
): { family: DenyFamily; count: number }[] {
  const counts = new Map<DenyFamily, number>();
  for (const r of reasons) {
    const f = denyFamilyOf(r);
    if (f) counts.set(f, (counts.get(f) ?? 0) + 1);
  }
  return DENY_FAMILY_ORDER.filter((f) => counts.has(f)).map((f) => ({
    family: f,
    count: counts.get(f) as number,
  }));
}
