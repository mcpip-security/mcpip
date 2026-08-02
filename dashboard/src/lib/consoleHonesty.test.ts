import { afterEach, describe, expect, it, vi } from 'vitest';
import { extensionsPending } from './api';
import { loadDirectory, saveDirectory } from './directorySync';

/**
 * Regressions for the console-honesty audit. Every case here is a state the
 * console previously COLLAPSED into a cheerier neighbouring state — a failed
 * read rendered as "nothing saved yet", a governed registry-server submission
 * rendered as a hand-authored skill. Each collapse is individually small and
 * each one lies to the operator about what the gateway actually said, so they
 * are pinned as tests rather than left to code review.
 */

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

/** Stub `fetch` with a single canned response. */
function stubFetch(status: number, body: unknown): void {
  globalThis.fetch = vi.fn(async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    }),
  ) as unknown as typeof fetch;
}

describe('directory load states stay distinct', () => {
  it('reports no-credential WITHOUT touching the network', async () => {
    const spy = vi.fn();
    globalThis.fetch = spy as unknown as typeof fetch;
    await expect(loadDirectory(null, '')).resolves.toEqual({ kind: 'no-credential' });
    // The point of the state: there is nothing to ask the gateway.
    expect(spy).not.toHaveBeenCalled();
  });

  it('distinguishes a refused read from an empty directory', async () => {
    stubFetch(403, {});
    await expect(loadDirectory('tok', '')).resolves.toEqual({ kind: 'read-failed' });

    stubFetch(200, { document: null });
    await expect(loadDirectory('tok', '')).resolves.toEqual({ kind: 'absent' });
  });

  it('returns the stored org units on a real read', async () => {
    stubFetch(200, { document: { schema: 'mcpip-directory/1', org_units: [{ id: 'ou-1' }] } });
    const loaded = await loadDirectory('tok', '');
    expect(loaded.kind).toBe('ok');
    expect(loaded.kind === 'ok' && loaded.orgUnits).toEqual([{ id: 'ou-1' }]);
  });

  it('never reports a save it did not perform', async () => {
    const spy = vi.fn();
    globalThis.fetch = spy as unknown as typeof fetch;
    await expect(saveDirectory(null, '', [])).resolves.toBe('no-credential');
    expect(spy).not.toHaveBeenCalled();

    stubFetch(403, {});
    await expect(saveDirectory('tok', '', [])).resolves.toBe('write-failed');
  });
});

describe('pending-extension rows keep their kind', () => {
  const registryRow = {
    submission_id: 'sub-1',
    kind: 'registry_server',
    alias: 'skill_weather',
    target: 'https://api.example.com/mcp',
    transport: 'cloud_rest',
    risk_tier: 'pin_required',
    classification: 'restricted',
    publisher_namespace: 'com.example',
    server_name: 'com.example/weather',
    server_version: '1.4.0',
    provenance: { 'io.modelcontextprotocol.registry/official': { id: 'x' } },
    author: 'Example Corp',
    submitter_agent_id: 'agent-contributor',
    manifest_sha256: 'a'.repeat(64),
    created_at: '2026-01-01T00:00:00Z',
    verified: false,
    conflicts_existing_alias: false,
    submitter_is_reviewer: false,
  };

  it('projects a registry-server row instead of flattening it to a skill', async () => {
    stubFetch(200, { pending: [registryRow] });
    const rows = await extensionsPending('tok', { base: '' });
    expect(rows).toHaveLength(1);
    const row = rows?.[0];
    // Mislabelling the kind is the whole bug: it drove the badge, the field
    // grid, and whether the approve button was blocked.
    expect(row?.kind).toBe('registry_server');
    if (row?.kind !== 'registry_server') throw new Error('kind narrowing failed');
    // The two fields a reviewer's decision actually turns on — both were
    // silently dropped by the skill projection.
    expect(row.publisher_namespace).toBe('com.example');
    expect(row.verified).toBe(false);
    expect(row.server_version).toBe('1.4.0');
    expect(row.provenance).toEqual(registryRow.provenance);
  });

  it('defaults a null/array provenance to null rather than a bogus object', async () => {
    stubFetch(200, { pending: [{ ...registryRow, provenance: ['not', 'an', 'object'] }] });
    const rows = await extensionsPending('tok', { base: '' });
    const row = rows?.[0];
    expect(row?.kind === 'registry_server' && row.provenance).toBeNull();
  });

  it('still projects skill and gate rows', async () => {
    stubFetch(200, {
      pending: [
        { submission_id: 's', kind: 'skill', alias: 'skill_a', target: 'https://a' },
        { submission_id: 'g', kind: 'gate', gate_id: 'gate_a', language: 'cel', approvable: false },
      ],
    });
    const rows = await extensionsPending('tok', { base: '' });
    expect(rows?.map((r) => r.kind)).toEqual(['skill', 'gate']);
  });
});
