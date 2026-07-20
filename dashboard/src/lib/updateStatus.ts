/* ---------------------------------------------------------------------------
   Update status — the ONE source of truth for "is a newer MCPIP available?".

   MCPIP is a Tier-1 zero-trust appliance: the console is a NOTIFIER, never an
   installer. It downloads and executes nothing. This module compares three
   honest signals —
     • the console's own build version (`__APP_VERSION__`, baked in at build),
     • the connected gateway's running version (`/v1/version` → running),
     • the signed release feed's newest APPROVED release (`/v1/version` → latest),
   — and produces a single verdict the whole UI renders identically: the global
   header notice (a Claude-style "update available" popover) AND the License &
   Updates page. Both read THIS, so they never disagree.

   The operator keeps full control: an update is applied only by a deliberate,
   signed redeploy (`update_policy` is always "redeploy"), and the header notice
   can be dismissed per target version (a NEWER version re-surfaces it).
--------------------------------------------------------------------------- */

import type { GatewayLive } from './useGatewayLive';
import { loadReleaseHistory, type ReleaseEntry } from './changelog';

export type UpdateSeverity = 'current' | 'update' | 'neutral';

/** Which of the three-signal comparisons produced the verdict. */
export type UpdateKind =
  | 'feed' // the signed feed advertises a newer approved release than the gateway runs
  | 'redeploy-pending' // this console build is ahead of the gateway (redeploy the gateway)
  | 'console-behind' // the gateway is ahead of this console build (reinstall the console)
  | 'up-to-date'
  | 'unknown';

export interface UpdateStatus {
  severity: UpdateSeverity;
  kind: UpdateKind;
  /** The single most-important one-line statement. */
  headline: string;
  /** The supporting sentence (what it means + how to act). */
  detail: string;
  /** The version the operator should move TO, when known (feed/skew); else null. */
  targetVersion: string | null;
  consoleVersion: string;
  gatewayVersion: string | null;
  /** Entitlement/update channel, or null when unknown. */
  channel: string | null;
  /** Always "redeploy" for a healthy gateway — surfaced so the UI never implies auto-install. */
  updatePolicy: string;
  /** Signed-release provenance: true = verified by the release-root key, false = advertised
   *  but unverified, null = merely stated (or unknown). */
  releaseVerified: boolean | null;
  signingKeyId: string | null;
}

/** Parse a strict MAJOR.MINOR.PATCH into a comparable tuple, or null if malformed. */
function parseSemver(raw: string): [number, number, number] | null {
  const m = /^(\d+)\.(\d+)\.(\d+)$/.exec(raw.trim());
  if (!m) return null;
  return [Number(m[1]), Number(m[2]), Number(m[3])];
}

/** -1 / 0 / 1 (a<b / a==b / a>b), or null when either side is not strict semver. */
export function compareSemver(a: string, b: string): number | null {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa || !pb) return null;
  for (let i = 0; i < 3; i += 1) {
    if (pa[i]! !== pb[i]!) return pa[i]! < pb[i]! ? -1 : 1;
  }
  return 0;
}

/**
 * The single update verdict, derived from the three honest signals. Pure: no I/O,
 * no React, no clock — so it is trivially testable and both consumers share it.
 */
export function deriveUpdateStatus(consoleV: string, gateway: GatewayLive): UpdateStatus {
  const ver = gateway.version;
  const base = {
    targetVersion: null as string | null,
    consoleVersion: consoleV,
    gatewayVersion: ver?.running ?? null,
    channel: ver?.channel ?? null,
    updatePolicy: ver?.update_policy ?? 'redeploy',
    releaseVerified: ver?.release.verified ?? null,
    signingKeyId: ver?.release.signing_key_id ?? null,
  };

  if (gateway.mode !== 'live') {
    return {
      ...base,
      severity: 'neutral',
      kind: 'unknown',
      headline: 'Gateway not reachable',
      detail: `Running console build ${consoleV}. Connect to a gateway to check for a newer signed release.`,
    };
  }
  if (!ver) {
    // Live, but the JWT-gated /v1/version read failed (no verified identity —
    // production disables the sandbox minter). Unknown, not "unreachable".
    return {
      ...base,
      severity: 'neutral',
      kind: 'unknown',
      headline: 'Gateway version unknown',
      detail: `Running console build ${consoleV}. The gateway is reachable but did not answer the /v1/version read for this console's identity.`,
    };
  }

  // A signed update feed is the authoritative "newer approved release" signal.
  if (ver.update_available && ver.latest !== ver.running) {
    return {
      ...base,
      severity: 'update',
      kind: 'feed',
      headline: `Update available — ${ver.latest}`,
      detail: `A newer approved release (${ver.latest}) is published; the gateway runs ${ver.running}. Apply it by redeploying the signed artifact — MCPIP never auto-installs.`,
      targetVersion: ver.latest,
    };
  }

  // Otherwise fall back to console↔gateway build skew (the redeploy-pending case).
  const cmp = compareSemver(consoleV, ver.running);
  if (cmp === null) {
    return {
      ...base,
      severity: 'neutral',
      kind: 'unknown',
      headline: 'Version check inconclusive',
      detail: `Console build ${consoleV} · gateway ${ver.running}.`,
    };
  }
  if (cmp > 0) {
    return {
      ...base,
      severity: 'update',
      kind: 'redeploy-pending',
      headline: 'Redeploy pending',
      detail: `This console build (${consoleV}) is ahead of the gateway (${ver.running}). Redeploy the gateway to the signed ${consoleV} artifact to match.`,
      targetVersion: consoleV,
    };
  }
  if (cmp < 0) {
    return {
      ...base,
      severity: 'update',
      kind: 'console-behind',
      headline: 'Console behind',
      detail: `The gateway (${ver.running}) is ahead of this console build (${consoleV}). Reinstall the ${ver.running} desktop/web build to match.`,
      targetVersion: ver.running,
    };
  }
  return {
    ...base,
    severity: 'current',
    kind: 'up-to-date',
    headline: 'Up to date',
    detail: `Console and gateway are both on the latest signed release (${ver.running}).`,
  };
}

/** Concise, honest "how to apply" steps for the verdict — a signed redeploy of the
 *  gateway, or a console reinstall when the console is the one behind. Shared by the
 *  header notice and the License & Updates page so they never diverge. */
export function howToApply(status: UpdateStatus): string[] {
  if (status.kind === 'console-behind') {
    const v = status.targetVersion ?? status.gatewayVersion ?? 'latest';
    return [
      `Download the signed v${v} console build (desktop or web).`,
      'Reinstall it — the console reconnects to the gateway automatically.',
    ];
  }
  const v = status.targetVersion ?? 'latest';
  return [
    `Pull the signed v${v} gateway artifact from your release channel.`,
    'Verify its signature against the offline release-root key.',
    'Redeploy on your own change-control window (e.g. docker compose up -d).',
    'The gateway restarts on the new version; the console reconnects.',
  ];
}

/* --- Per-version dismissal (header notice only) ---------------------------- */

const DISMISS_KEY = 'mcpip.update.dismissed';

/** The stable identity of a dismissable update — `kind:targetVersion`. Only a
 *  genuine 'update' verdict with a known target can be dismissed; everything else
 *  returns null so it is never suppressible. A new target ⇒ a new key ⇒ re-surfaces. */
export function updateKey(status: UpdateStatus): string | null {
  return status.severity === 'update' && status.targetVersion
    ? `${status.kind}:${status.targetVersion}`
    : null;
}

/** The currently-dismissed update key (localStorage), or null. Fails soft. */
export function readDismissedKey(): string | null {
  try {
    return localStorage.getItem(DISMISS_KEY);
  } catch {
    return null;
  }
}

/** Dismiss THIS update (persist its key). No-op for a non-dismissable verdict. */
export function dismissUpdate(status: UpdateStatus): void {
  const key = updateKey(status);
  if (!key) return;
  try {
    localStorage.setItem(DISMISS_KEY, key);
  } catch {
    /* storage unavailable — dismissal simply doesn't persist */
  }
}

/** Clear any dismissal so the notice can show again (the "notify me again" control). */
export function clearDismissal(): void {
  try {
    localStorage.removeItem(DISMISS_KEY);
  } catch {
    /* no-op */
  }
}

/** Whether this verdict is currently dismissed for the given stored key. */
export function isDismissed(status: UpdateStatus, dismissedKey: string | null): boolean {
  const key = updateKey(status);
  return key !== null && key === dismissedKey;
}

/* --- "What's new" highlights ----------------------------------------------- */

/** The changelog entry for a version (from the bundled CHANGELOG), or null.
 *  A feed target newer than this build won't be in the bundled changelog — that's
 *  fine, the caller falls back to the verdict's own detail sentence. */
export function releaseNotesFor(version: string | null): ReleaseEntry | null {
  if (!version) return null;
  return loadReleaseHistory().find((e) => e.version === version) ?? null;
}

/** Up to `max` flattened highlight bullets for a version, in changelog order. */
export function releaseHighlights(version: string | null, max = 5): string[] {
  const entry = releaseNotesFor(version);
  if (!entry) return [];
  const items: string[] = [];
  for (const section of entry.sections) {
    for (const item of section.items) {
      items.push(item);
      if (items.length >= max) return items;
    }
  }
  return items;
}
