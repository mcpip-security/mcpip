/**
 * Console configuration spine — the single typed source of truth for WHICH
 * sections exist in a build and WHEN each one is allowed to render.
 *
 * Three independent layers gate every section, and all three must agree before
 * it appears (see {@link sectionState}):
 *
 *   1. BUILD EDITION  — which sections are compiled into this release at all.
 *      Fed at build time by `VITE_MCPIP_EDITION` (Vite `--mode` → `.env.<mode>`).
 *      A section whose `editions` omits the active edition is `hide` — and,
 *      because the manifest is consulted statically, its view can be tree-shaken
 *      out of the bundle entirely. This is how "ship a staging version and a
 *      production version" is expressed: one codebase, two editions.
 *
 *   2. LICENSE TIER   — the entitlement floor. Read from the boot-verified,
 *      offline-signed license the gateway reports (`/v1/admin/stats.license.tier`)
 *      — works fully air-gapped, no SaaS call. A section with `minTier` above the
 *      deployment's tier is `whenGated` (lock, to advertise the upgrade, or hide).
 *
 *   3. LIVE FEATURE POSTURE — is the backing gateway feature actually ON, on THIS
 *      box? Read from the honest `features` / `telemetry` posture the gateway
 *      already serves. A section with `requires` whose feature is off is
 *      `whenGated`. Unknown posture fails CLOSED (treated as off) — the console
 *      never fabricates an "on" state it can't confirm.
 *
 * The honest rule (MCPIP's zero-mock invariant, extended from data to navigation):
 * a `requires` key MUST be a real member of {@link FeatureKey}, and every
 * `FeatureKey` MUST be produced by `deriveFeaturePosture` from a field the gateway
 * genuinely emits (`posture.ts`). No posture field ⇒ no `FeatureKey` ⇒ a section
 * can't claim it. There is no "shown but dead" state.
 *
 * This module is pure data + pure predicates — no React, no I/O — so it is
 * trivially testable and safe to import anywhere (including the edition badge and,
 * in the next increment, the flat navigation).
 */

/** The build "edition" this bundle was compiled as. */
export type Edition = 'production' | 'staging' | 'internal';

/** License tiers, in ascending order of entitlement. Mirrors the closed tier set
 * the signed license carries; `null` (unlicensed / unknown) is below all of them. */
export type Tier = 'community' | 'team' | 'enterprise';

/**
 * The gateway features a section can be backed by. Each MUST map to a real field
 * `deriveFeaturePosture` reads from the gateway's honest posture — this union is
 * the contract that keeps the manifest and the backend from silently diverging.
 * Grows only as sections that gate on a new (already-emitted) posture field ship.
 */
export type FeatureKey = 'forensic' | 'external_pdp' | 'telemetry';

/** The resolved visibility of a section under the three-layer gate. */
export type GateState = 'show' | 'lock' | 'hide';

/** Every gate-able destination in the console. Top-level sections plus the
 * pinned utility surfaces; sub-surface gates (e.g. the forensic reconstruct
 * inspector) reuse the same {@link SectionGate} shape inside their section. */
export type SectionId =
  | 'overview'
  | 'activity'
  | 'analytics'
  | 'access'
  | 'agents'
  | 'license'
  | 'settings'
  | 'developers'
  | 'docs'
  // Internal-only surfaces — present in staging/internal editions, tree-shaken
  // out of production. They demonstrate (and exercise) the edition mechanism.
  | 'canaryLab'
  | 'pipelineReplay';

export interface SectionGate {
  /** Build editions this section is compiled into. Omit the active edition ⇒ hidden. */
  readonly editions: ReadonlyArray<Edition>;
  /** Entitlement floor. Omit ⇒ available to every tier (including unlicensed). */
  readonly minTier?: Tier;
  /** Backing live feature. Omit ⇒ always-live (no runtime feature dependency). */
  readonly requires?: FeatureKey;
  /** What to do when the edition includes it but tier/feature gate it out. */
  readonly whenGated: 'hide' | 'lock';
}

export interface SectionDef extends SectionGate {
  readonly id: SectionId;
  readonly label: string;
  /** Grouping in the flat sidebar (consumed by the nav-flatten increment). */
  readonly group: 'monitor' | 'govern' | 'account' | 'pinned';
}

export const ALL_EDITIONS: ReadonlyArray<Edition> = ['production', 'staging', 'internal'];
export const NON_PROD: ReadonlyArray<Edition> = ['staging', 'internal'];

/**
 * The section manifest — the redesign's flat information architecture. Ordered
 * by group. This is the contract the navigation increment renders from; here it
 * already carries every gate so editions/tiers/posture are wired from day one.
 *
 * Note the honest calls baked in:
 *  - `analytics` is ALWAYS shown (no `requires`) — when telemetry is off it renders
 *    its own honest empty / air-gap state rather than being hidden, so the section
 *    that explains "no analytics are collected here" is always reachable.
 *  - `license` is ALWAYS shown — it is how a deployment sees and upgrades its plan.
 *  - the two internal surfaces are edition-gated OUT of production.
 */
export const SECTIONS: ReadonlyArray<SectionDef> = [
  { id: 'overview',      label: 'Overview',        group: 'monitor', editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'activity',      label: 'Activity',        group: 'monitor', editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'analytics',     label: 'Analytics',       group: 'monitor', editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'access',        label: 'Access',          group: 'govern',  editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'agents',        label: 'Agents & Users',  group: 'govern',  editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'license',       label: 'License & Usage', group: 'account', editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'settings',      label: 'Settings',        group: 'account', editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'developers',    label: 'Developers',      group: 'pinned',  editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'docs',          label: 'Docs',            group: 'pinned',  editions: ALL_EDITIONS, whenGated: 'hide' },
  { id: 'canaryLab',     label: 'Canary Lab',      group: 'monitor', editions: NON_PROD,     whenGated: 'hide' },
  { id: 'pipelineReplay',label: 'Pipeline Replay', group: 'monitor', editions: NON_PROD,     whenGated: 'hide' },
];

/**
 * Gates for sub-surfaces that live INSIDE a section rather than as a top-level
 * entry — the dark-feature affordances the redesign must gate honestly. Consumed
 * by the section increments; declared here so the whole gating contract lives in
 * one file. Keyed by a stable id the owning view references.
 */
export const SUBFEATURE_GATES: Readonly<Record<string, SectionGate>> = {
  // A payload-reconstruction affordance must NEVER be advertised when forensic
  // capture is off on this deployment — hide it outright, don't lock it.
  'activity.reconstruct': { editions: ALL_EDITIONS, requires: 'forensic', whenGated: 'hide' },
  // The external-PDP consult surface only appears where a PDP is actually enforcing.
  'access.externalPdp':   { editions: ALL_EDITIONS, requires: 'external_pdp', whenGated: 'hide' },
  // Compliance-evidence export: the endpoint exists in every production build, so
  // this is a PRODUCT gate, not a feature-availability one — lock (advertise the
  // upgrade) below enterprise rather than pretending the capability is missing.
  'license.compliance':   { editions: ALL_EDITIONS, minTier: 'enterprise', whenGated: 'lock' },
};

const TIER_RANK: Record<Tier, number> = { community: 0, team: 1, enterprise: 2 };

/** Is `have` at least `need`? A `null` (unlicensed/unknown) tier meets no floor. */
export function tierMeets(have: Tier | null, need: Tier | undefined): boolean {
  if (need === undefined) return true;
  if (have === null) return false;
  return TIER_RANK[have] >= TIER_RANK[need];
}

/** The live posture a section's gate is resolved against (produced by `posture.ts`). */
export interface FeaturePosture {
  readonly tier: Tier | null;
  /** Every `FeatureKey` is present — the type guarantees the honest contract that
   * a gate can only require a feature the posture actually reports. Unknown ⇒ false. */
  readonly features: Readonly<Record<FeatureKey, boolean>>;
}

/**
 * The three-layer visibility predicate. `show` only when the edition includes the
 * section AND the tier meets its floor AND the backing feature is live; otherwise
 * the section's declared `whenGated` (`lock` to advertise, `hide` to remove). An
 * edition miss is always `hide` — a build simply does not contain that section.
 */
export function sectionState(
  gate: SectionGate,
  edition: Edition,
  posture: FeaturePosture,
): GateState {
  if (!gate.editions.includes(edition)) return 'hide';
  const tierOk = tierMeets(posture.tier, gate.minTier);
  const liveOk = gate.requires === undefined || posture.features[gate.requires] === true;
  if (tierOk && liveOk) return 'show';
  return gate.whenGated;
}

const EDITIONS = new Set<Edition>(ALL_EDITIONS);

/**
 * The active build edition, resolved once from `VITE_MCPIP_EDITION` (set per Vite
 * mode). Defaults to `production` — the safe, leanest surface — for any unset or
 * unrecognized value, so a mis-set env can only ever REMOVE non-production
 * sections, never smuggle one into a production build.
 */
export function resolveEdition(): Edition {
  const raw = import.meta.env.VITE_MCPIP_EDITION;
  return raw !== undefined && EDITIONS.has(raw as Edition) ? (raw as Edition) : 'production';
}

/** The edition this bundle was compiled as. */
export const EDITION: Edition = resolveEdition();

/** True when running a non-production edition — the signal the environment badge
 * uses to make a staging/internal console unmistakable (the Stripe rule). */
export const IS_NON_PRODUCTION: boolean = EDITION !== 'production';
