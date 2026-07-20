/**
 * Derives the console's {@link FeaturePosture} — the live half of the section
 * gate — from the honest posture the gateway already serves at
 * `GET /v1/admin/stats` (`DeploymentStats`). This is the ONLY place a
 * {@link FeatureKey} is mapped to a real wire field, so the honest contract
 * ("a gate can only require a feature the gateway genuinely reports") is
 * enforceable in exactly one spot.
 *
 * Fail-closed discipline: an absent / unknown / pre-block gateway posture yields
 * `false` for every feature and `null` for the tier. The console then HIDES or
 * LOCKS the gated surface rather than fabricating an "on" state it cannot confirm
 * — the same fail-closed, zero-mock posture as the rest of the product.
 */
import type { DeploymentStats } from './api';
import type { FeatureKey, FeaturePosture, Tier } from './consoleConfig';

const TIERS: ReadonlyArray<Tier> = ['community', 'team', 'enterprise'];

/** Normalize the license tier the gateway reports to the closed {@link Tier} set,
 * or `null` for unlicensed / unknown / anything outside the set (fail closed). */
export function normalizeTier(raw: string | null | undefined): Tier | null {
  if (typeof raw !== 'string') return null;
  const t = raw.toLowerCase();
  return (TIERS as ReadonlyArray<string>).includes(t) ? (t as Tier) : null;
}

/**
 * Map the gateway's honest posture to per-feature booleans. Each mapping reads the
 * SAME coarse status string the gateway emits and treats only the genuinely-live
 * value as `true`:
 *   - `forensic`     — `features.forensic_capture.status === 'enabled'`
 *                      ('absent' / 'disabled' are NOT live).
 *   - `external_pdp` — `features.external_pdp.status === 'enforcing'`
 *                      ('off' / 'staged' do not consult a decision).
 *   - `telemetry`    — `telemetry.status === 'enabled'`
 *                      ('air-gap' / 'disabled' collect nothing).
 * A `null` stats (offline / unauthorized / pre-block) ⇒ all `false`.
 */
export function deriveFeaturePosture(stats: DeploymentStats | null): FeaturePosture {
  const feats = stats?.features;
  const features: Record<FeatureKey, boolean> = {
    forensic: feats?.forensic_capture?.status === 'enabled',
    external_pdp: feats?.external_pdp?.status === 'enforcing',
    telemetry: stats?.telemetry?.status === 'enabled',
  };
  const tier =
    stats?.license && stats.license.licensed ? normalizeTier(stats.license.tier) : null;
  return { tier, features };
}

/** The safe fail-closed posture used before any stats have loaded: unlicensed,
 * every feature off. Identical to `deriveFeaturePosture(null)`, named for intent. */
export const UNKNOWN_POSTURE: FeaturePosture = deriveFeaturePosture(null);
