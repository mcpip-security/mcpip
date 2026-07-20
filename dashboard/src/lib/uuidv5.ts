/* ---------------------------------------------------------------------------
   RFC-4122 v5 (SHA-1 name-based) UUIDs — async via crypto.subtle.

   Exists for ONE protocol derivation: the engine's per-compartment, SCOPED
   grant-issuing capability (interfaces.py `grant_capability_for`):

       grant_capability_for(X) = uuid5(CAP_COMPARTMENT_GRANT, X)

   Byte-identity notes (must match python3 `uuid.uuid5` exactly):
     • The digest input is namespace-UUID BYTES (16, big-endian field order)
       followed by the name encoded as UTF-8.
     • The engine passes the compartment-UUID STRING verbatim as the name —
       it validates but does NOT case-normalize — so neither do we. A
       differently-cased input is a DIFFERENT name and derives a different
       capability; callers pass the canonical lowercase form the gateway seeds
       and mints.
     • Version bits: byte 6 = (b & 0x0f) | 0x50; variant: byte 8 = (b & 0x3f) | 0x80.

   WebCrypto has no synchronous SHA-1, hence the async signatures (and why
   protocol.ts pins GRANT_CAP_FOR for the three sandbox seeds as a sync fast
   path). crypto.subtle requires a secure context — localhost and https both
   qualify, which covers every supported console deployment.

   Derivation check (no TS test framework exists — verified 2026-07-16 against
   the engine via `python3 -c "import uuid; print(uuid.uuid5(uuid.UUID('9c2b6f14-7a3d-4e8b-b1c0-2f5a9d3e4c71'), '<compartment>'))"`,
   and this implementation reproduces the same values under node's webcrypto):
     grantCapabilityFor('f4100000-0000-4000-8000-0000000fa1c0')   // falcon
       → 'ad10b1b2-9a5c-5291-a3f9-0adaf9cf1f87'  == GRANT_CAP_FOR.falcon
     grantCapabilityFor('ae610000-0000-4000-8000-0000000ae615')   // aegis
       → '241ad49a-9f3c-54f2-9e52-3819e08a8d04'  == GRANT_CAP_FOR.aegis
     grantCapabilityFor('5e470000-0000-4000-8000-0000005e4715')   // sentinel
       → 'd0be8613-9b46-50c9-904a-1c8173e58b38'  == GRANT_CAP_FOR.sentinel
--------------------------------------------------------------------------- */

import { CAP_COMPARTMENT_GRANT } from './protocol';

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;

/** True when `value` is a well-formed RFC-4122-shaped UUID string. */
export function isUuid(value: string): boolean {
  return UUID_RE.test(value);
}

/** The 16 namespace bytes of a UUID string (big-endian field order, per RFC-4122). */
function uuidBytes(value: string): Uint8Array {
  if (!isUuid(value)) {
    throw new TypeError('malformed UUID');
  }
  const hex = value.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** Canonical lowercase 8-4-4-4-12 formatting of 16 UUID bytes. */
function formatUuid(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * RFC-4122 v5 UUID: SHA-1 over (namespace bytes ‖ UTF-8 name), first 16 digest
 * bytes with version/variant bits stamped. Throws TypeError on a malformed
 * namespace (fail closed — never derive from a bogus namespace).
 */
export async function uuidv5(namespace: string, name: string): Promise<string> {
  const ns = uuidBytes(namespace);
  const nameBytes = new TextEncoder().encode(name);
  const input = new Uint8Array(ns.length + nameBytes.length);
  input.set(ns, 0);
  input.set(nameBytes, ns.length);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-1', input));
  const out = digest.slice(0, 16);
  // Stamp version 5 + RFC-4122 variant exactly like python's uuid5.
  out[6] = ((out[6] ?? 0) & 0x0f) | 0x50;
  out[8] = ((out[8] ?? 0) & 0x3f) | 0x80;
  return formatUuid(out);
}

/**
 * The engine's `grant_capability_for(compartment_uuid)` (interfaces.py):
 * uuid5 over the fixed grant namespace (CAP_COMPARTMENT_GRANT) with the
 * compartment-UUID string as the name. Works for ANY compartment — including
 * operator-created company teams — not only the pinned sandbox seeds. Throws
 * TypeError on a non-UUID input, mirroring the engine's fail-closed
 * validation (never derive a bogus capability from malformed input).
 */
export async function grantCapabilityFor(compartmentUuid: string): Promise<string> {
  if (!isUuid(compartmentUuid)) {
    throw new TypeError('compartment must be a well-formed UUID string');
  }
  return uuidv5(CAP_COMPARTMENT_GRANT, compartmentUuid);
}
