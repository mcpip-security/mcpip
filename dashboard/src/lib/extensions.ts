/* ---------------------------------------------------------------------------
   Community extensions — the console side of the author-your-own-skill/gate flow.

   Two actors, two distinct identities (separation of duties, mirrored from
   docs/integrate/EXTENSIBILITY.md §3):
     • Contributor — ANY authenticated principal, NO capability. Submits a
       manifest via POST /v1/extensions/submit (deliberately OFF /v1/admin/*).
     • Reviewer    — the DISTINCT CAP_CATALOG_REVIEWER. Reads the pending queue
       and approves/rejects via /v1/admin/extensions/*.

   Both identities are minted for the SAME tenant (the reviewer only ever sees
   its own tenant's submissions — cross-tenant approve is structurally
   impossible). In the sandbox the tokens come from /v1/dev/token; in production
   that route 404s, so every wrapper here fails soft (null / false) and the view
   renders its honest "review unavailable" state — never a fabricated queue.

   The manifest carries a `sha256` SELF-PIN the AUTHOR computes over the canonical
   manifest bytes; the gateway re-derives + compares it fail-closed at submit,
   re-verifies it at approve, and re-checks it on every boot-load (rug-pull
   defense). So this module recomputes that digest BYTE-IDENTICALLY to
   `core.integrity.canonical_manifest_bytes`: JSON with sorted keys + compact
   separators + Python's ensure_ascii escaping, over the manifest fields with
   `sha256` and the reserved `signature` dropped, SHA-256 → lowercase hex. This
   is DISTINCT from the payload-lock `canonical_json`; no gate/lock hash is ever
   recomputed here.
--------------------------------------------------------------------------- */

import {
  extensionApprove as apiApprove,
  extensionReject as apiReject,
  extensionsPending as apiPending,
  submitExtension as apiSubmit,
  mintDevToken,
} from './api';
import { CAP_CATALOG_REVIEWER } from './protocol';
import type {
  ExtensionGateManifest,
  ExtensionSkillManifest,
  PendingExtension,
} from './types';

/** The identity the console submits AS (a plain authenticated principal, no capability). */
export const CONTRIBUTOR_AGENT_ID = 'agent-contributor';
/** The identity the console reviews AS (carries CAP_CATALOG_REVIEWER). Distinct from the submitter. */
export const REVIEWER_AGENT_ID = 'agent-catalog-reviewer';

/* --- canonical manifest self-pin (byte-identical to the gateway) ----------- */

/**
 * Serialize one string exactly as Python's `json.dumps` does with the default
 * `ensure_ascii=True`: `"`/`\` and the short C-escapes, every control char and
 * every non-ASCII UTF-16 code unit as `\uXXXX`, everything else verbatim. Matches
 * `core.integrity._canonical_json_bytes` for the ASCII-safe fields a manifest
 * carries (all human fields are NFC + control/bidi/zero-width-rejected server-side).
 */
function pyJsonString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code === 0x22) out += '\\"'; // "
    else if (code === 0x5c) out += '\\\\'; // \
    else if (code === 0x08) out += '\\b';
    else if (code === 0x09) out += '\\t';
    else if (code === 0x0a) out += '\\n';
    else if (code === 0x0c) out += '\\f';
    else if (code === 0x0d) out += '\\r';
    else if (code < 0x20 || code > 0x7e) out += '\\u' + code.toString(16).padStart(4, '0');
    else out += String.fromCharCode(code);
  }
  return out + '"';
}

type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | CanonicalValue[]
  | { [key: string]: CanonicalValue };

/** `json.dumps(value, sort_keys=True, separators=(",",":"))`, ensure_ascii. */
function canonicalSerialize(value: CanonicalValue): string {
  if (typeof value === 'string') return pyJsonString(value);
  if (typeof value === 'number') return String(value); // manifest numbers are integers
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (value === null) return 'null';
  if (Array.isArray(value)) return '[' + value.map(canonicalSerialize).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => pyJsonString(k) + ':' + canonicalSerialize(value[k]!)).join(',') + '}';
}

/** SHA-256 → lowercase hex, over the UTF-8 bytes of `text` (SubtleCrypto). */
async function sha256Hex(text: string): Promise<string> {
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Recompute a manifest's `sha256` self-pin over its canonical bytes. `digestSource`
 * is the manifest WITHOUT `sha256`/`signature` (exactly what
 * `canonical_manifest_bytes` digests); the gateway re-derives the same value and
 * compares constant-time, so this MUST stay byte-identical.
 */
export async function computeManifestPin(
  digestSource: Record<string, CanonicalValue>,
): Promise<string> {
  return sha256Hex(canonicalSerialize(digestSource));
}

/* --- manifest builders (self-pin filled in) -------------------------------- */

export interface SkillManifestFields {
  id: string;
  author: string;
  alias: string;
  target: string;
  risk_tier: 'auto' | 'pin_required';
  classification: 'unclassified' | 'restricted';
}

/** Build a fully-pinned community-SKILL manifest ready to submit. */
export async function buildSkillManifest(
  fields: SkillManifestFields,
): Promise<ExtensionSkillManifest> {
  const digestSource: Record<string, CanonicalValue> = {
    schema: 'mcpip-extension/1',
    kind: 'skill',
    id: fields.id,
    author: fields.author,
    alias: fields.alias,
    target: fields.target,
    transport: 'cloud_rest',
    risk_tier: fields.risk_tier,
    classification: fields.classification,
  };
  const sha256 = await computeManifestPin(digestSource);
  return { ...(digestSource as unknown as ExtensionSkillManifest), sha256 };
}

export interface GateManifestFields {
  id: string;
  author: string;
  source: string;
  referenced_context_fields: string[];
  max_cost: number;
}

/** Build a fully-pinned community-GATE manifest ready to submit (schema-only; runtime deferred). */
export async function buildGateManifest(
  fields: GateManifestFields,
): Promise<ExtensionGateManifest> {
  const digestSource: Record<string, CanonicalValue> = {
    schema: 'mcpip-extension/1',
    kind: 'gate',
    id: fields.id,
    author: fields.author,
    language: 'cel',
    source: fields.source,
    referenced_context_fields: fields.referenced_context_fields,
    max_cost: fields.max_cost,
  };
  const sha256 = await computeManifestPin(digestSource);
  return { ...(digestSource as unknown as ExtensionGateManifest), sha256 };
}

/* --- token minting (fails soft when the dev minter is absent) -------------- */

async function contributorToken(
  apiBase: string,
  tenantId: string,
  signal?: AbortSignal,
): Promise<string | null> {
  try {
    return await mintDevToken(
      { tenant_id: tenantId, agent_id: CONTRIBUTOR_AGENT_ID },
      { base: apiBase, signal },
    );
  } catch {
    return null;
  }
}

async function reviewerToken(
  apiBase: string,
  tenantId: string,
  signal?: AbortSignal,
): Promise<string | null> {
  try {
    return await mintDevToken(
      { tenant_id: tenantId, agent_id: REVIEWER_AGENT_ID, capabilities: [CAP_CATALOG_REVIEWER] },
      { base: apiBase, signal },
    );
  } catch {
    return null;
  }
}

/* --- flow wrappers --------------------------------------------------------- */

/**
 * Submit a fully-pinned manifest AS the contributor identity. Returns the minted
 * submission id, or null when the manifest was refused (opaque deny) or the
 * contributor identity could not be minted (production has no dev minter).
 */
export async function submitCommunityExtension(
  apiBase: string,
  tenantId: string,
  manifest: ExtensionSkillManifest | ExtensionGateManifest,
  signal?: AbortSignal,
): Promise<{ submission_id: string } | null> {
  const token = await contributorToken(apiBase, tenantId, signal);
  if (!token) return null;
  return apiSubmit(token, manifest, { base: apiBase, signal });
}

/**
 * Read the tenant's PENDING submissions AS the reviewer identity. Returns null on
 * any failure (offline / no reviewer credential / opaque 403 / unsupported) — the
 * view renders its honest "review unavailable" state; [] means a genuinely empty
 * queue.
 */
export async function listPendingExtensions(
  apiBase: string,
  tenantId: string,
  signal?: AbortSignal,
): Promise<PendingExtension[] | null> {
  const token = await reviewerToken(apiBase, tenantId, signal);
  if (!token) return null;
  return apiPending(token, { base: apiBase, signal });
}

/** Approve a pending submission AS the reviewer. Returns the approved alias, or null on refusal. */
export async function approveExtension(
  apiBase: string,
  tenantId: string,
  submissionId: string,
  signal?: AbortSignal,
): Promise<{ approved: string } | null> {
  const token = await reviewerToken(apiBase, tenantId, signal);
  if (!token) return null;
  return apiApprove(token, submissionId, { base: apiBase, signal });
}

/** Reject a pending submission AS the reviewer. Returns true on a durable 200. */
export async function rejectExtension(
  apiBase: string,
  tenantId: string,
  submissionId: string,
  signal?: AbortSignal,
): Promise<boolean> {
  const token = await reviewerToken(apiBase, tenantId, signal);
  if (!token) return false;
  return apiReject(token, submissionId, { base: apiBase, signal });
}
