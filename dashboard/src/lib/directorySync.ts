/* ---------------------------------------------------------------------------
   Operator directory persistence — the console side of GET/PUT /v1/directory.

   The org chart the operator edits (Org Units → Teams → principal references) is
   NON-authoritative metadata: persisting it lets the directory survive across
   sessions and nodes, but it never mints identity and the gateway never consults
   it for authorization (that stays JWT + grants + the revocation kill-switch).

   Both calls need a CAP_DIRECTORY_ADMIN credential, and this module never mints
   one itself: the caller passes whatever `gateway.ensureAdminToken()` resolved —
   the operator's pinned bearer on a production gateway, the sandbox dev token
   otherwise. With no credential at all, persistence fails soft and SAYS SO,
   rather than reporting a clean sync it never performed.
--------------------------------------------------------------------------- */

import { getDirectory, putDirectory } from './api';
import type { DirectoryDocument } from './api';

const SCHEMA = 'mcpip-directory/1' as const;

/** What a directory load produced — each state is actionable and distinct. */
export type DirectoryLoad =
  | { kind: 'ok'; orgUnits: unknown[]; rbac?: Record<string, string[]> }
  | { kind: 'absent' }
  | { kind: 'read-failed' }
  | { kind: 'no-credential' };

/** What a directory save produced — a failed write is never reported as saved. */
export type DirectorySave = 'saved' | 'write-failed' | 'no-credential';

/**
 * Read the persisted org units.
 *
 * `credential` is the resolved admin bearer (see `gateway.ensureAdminToken`).
 * A null credential is its OWN state — not "nothing saved yet": on a production
 * gateway the dev forge is a deliberate 404, so this is the ordinary answer
 * there until an operator bearer is pinned.
 */
export async function loadDirectory(
  credential: string | null,
  apiBase: string,
  signal?: AbortSignal,
): Promise<DirectoryLoad> {
  if (!credential) return { kind: 'no-credential' };
  const read = await getDirectory(credential, { base: apiBase, signal });
  if (read.kind !== 'ok') return read;
  if (!Array.isArray(read.document.org_units)) return { kind: 'absent' };
  return {
    kind: 'ok',
    orgUnits: read.document.org_units,
    ...(read.document.rbac ? { rbac: read.document.rbac } : {}),
  };
}

/** Persist the org units (+ optional RBAC) under the caller's admin credential. */
export async function saveDirectory(
  credential: string | null,
  apiBase: string,
  orgUnits: unknown[],
  rbac?: Record<string, string[]>,
  signal?: AbortSignal,
): Promise<DirectorySave> {
  if (!credential) return 'no-credential';
  const document: DirectoryDocument = {
    schema: SCHEMA,
    org_units: orgUnits,
    ...(rbac ? { rbac } : {}),
  };
  const ok = await putDirectory(credential, document, { base: apiBase, signal });
  return ok ? 'saved' : 'write-failed';
}
