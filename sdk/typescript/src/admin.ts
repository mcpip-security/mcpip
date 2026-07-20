/* ---------------------------------------------------------------------------
   @mcpip/sdk — the operator admin surface (/v1/admin/* + /v1/directory + the
   community-extension review flow).

   MOST routes here demand a JWT whose `capabilities` claim carries
   CAP_DIRECTORY_ADMIN; the exceptions gate on their OWN distinct capability —
   `forensicGet` on CAP_FORENSIC_READ, the community-extension REVIEW routes
   (`extensionsPending`/`extensionApprove`/`extensionReject`) on
   CAP_CATALOG_REVIEWER — while `submitExtension` needs only a valid, non-revoked,
   non-quarantined principal (no capability at all). Every mutation is WORM-logged
   server-side as an admin_action BEFORE it takes effect. Tenant scope is always
   the caller JWT's own tenant — there is no cross-tenant administration. Any auth
   or validation failure is the same opaque McpipDenied an agent would see.
   Deletes use the API's POST .../delete convention (no HTTP DELETE exists).
--------------------------------------------------------------------------- */

import { GatewayHttp, type CallOptions, type McpipClientOptions } from './client.js';
import type {
  CanaryDecoy,
  CloudEnvironment,
  CloudEnvironmentInput,
  ComplianceEvidence,
  DecisionPage,
  DecisionQuery,
  DeploymentStats,
  OperatorInvite,
  OperatorRole,
  OperatorStatus,
  OperatorUser,
  OperatorUserPage,
  DirectoryDocument,
  ExtensionManifest,
  ForensicPayload,
  PendingExtension,
  PlanValidation,
  PolicyDocument,
  QuarantinedAgent,
  RecentDecision,
  RegisterSkillBody,
  RegisteredSkill,
  RelationEdge,
  RelationList,
  VaultSecret,
  VaultSecretInput,
  VaultSecretList,
  VerifiedPublishers,
  WorkspaceApplyResult,
  WorkspaceDraft,
  WorkspaceDraftBody,
  WorkspacePlan,
} from './types.js';
import { PUBLISHERS_SCHEMA } from './types.js';

export class McpipAdminClient {
  private readonly http: GatewayHttp;

  constructor(options: McpipClientOptions = {}) {
    this.http = new GatewayHttp(options);
  }

  /** The resolved gateway origin this client talks to. */
  get baseUrl(): string {
    return this.http.baseUrl;
  }

  // -------------------------------------------------------------------------
  // Skills — alias registration overlay + kill-switch.
  // -------------------------------------------------------------------------

  /**
   * POST /v1/admin/skills/register — register a NEW alias->target for the
   * tenant. ADDITIVE ONLY: an alias that already resolves (config or overlay)
   * is an opaque deny. cloud_rest transport is forced; 'restricted' requires
   * risk_tier 'pin_required'.
   */
  async skillsRegister(body: RegisterSkillBody, opts: CallOptions = {}): Promise<{ registered: string }> {
    return this.http.json<{ registered: string }>({
      method: 'POST',
      path: '/v1/admin/skills/register',
      auth: true,
      body,
      signal: opts.signal,
    });
  }

  /**
   * POST /v1/admin/skills/{alias}/deregister — remove an OPERATOR-registered
   * skill. Config-file aliases are never removable: requesting one is a no-op
   * success with removed=false.
   */
  async skillsDeregister(
    alias: string,
    opts: CallOptions = {},
  ): Promise<{ deregistered: string; removed: boolean }> {
    return this.http.json<{ deregistered: string; removed: boolean }>({
      method: 'POST',
      path: `/v1/admin/skills/${encodeURIComponent(alias)}/deregister`,
      auth: true,
      signal: opts.signal,
    });
  }

  /** POST /v1/admin/skills/{alias}/disable — deny the alias for everyone until re-enabled. */
  async skillsDisable(alias: string, opts: CallOptions = {}): Promise<{ disabled: string }> {
    return this.http.json<{ disabled: string }>({
      method: 'POST',
      path: `/v1/admin/skills/${encodeURIComponent(alias)}/disable`,
      auth: true,
      signal: opts.signal,
    });
  }

  /** POST /v1/admin/skills/{alias}/enable — lift the kill-switch (removed = was disabled). */
  async skillsEnable(
    alias: string,
    opts: CallOptions = {},
  ): Promise<{ enabled: string; removed: boolean }> {
    return this.http.json<{ enabled: string; removed: boolean }>({
      method: 'POST',
      path: `/v1/admin/skills/${encodeURIComponent(alias)}/enable`,
      auth: true,
      signal: opts.signal,
    });
  }

  /** GET /v1/admin/skills/disabled — aliases currently disabled in the tenant. */
  async skillsDisabled(opts: CallOptions = {}): Promise<string[]> {
    const body = await this.http.json<{ disabled?: unknown }>({
      method: 'GET',
      path: '/v1/admin/skills/disabled',
      auth: true,
      signal: opts.signal,
    });
    return Array.isArray(body.disabled)
      ? body.disabled.filter((a): a is string => typeof a === 'string')
      : [];
  }

  /**
   * GET /v1/admin/skills/registered — operator-registered (deregisterable)
   * skills. Reads the `entries` field; falls back to the legacy `registered`
   * names list (null timestamps) on older gateways.
   */
  async skillsRegistered(opts: CallOptions = {}): Promise<RegisteredSkill[]> {
    const body = await this.http.json<{ registered?: unknown; entries?: unknown }>({
      method: 'GET',
      path: '/v1/admin/skills/registered',
      auth: true,
      signal: opts.signal,
    });
    if (Array.isArray(body.entries)) {
      return body.entries
        .filter(
          (e): e is { alias: string; registered_at?: unknown } =>
            typeof e === 'object' && e !== null && typeof (e as { alias?: unknown }).alias === 'string',
        )
        .map((e) => ({
          alias: e.alias,
          registered_at: typeof e.registered_at === 'string' ? e.registered_at : null,
        }));
    }
    return Array.isArray(body.registered)
      ? body.registered
          .filter((a): a is string => typeof a === 'string')
          .map((alias) => ({ alias, registered_at: null }))
      : [];
  }

  // -------------------------------------------------------------------------
  // Community extensions (author-your-own SKILLS + GATES). Submit is a
  // Contributor action (any authenticated principal, NO capability, OFF the
  // /v1/admin/* prefix); review is the DISTINCT CAP_CATALOG_REVIEWER. All four
  // are opaque-deny + WORM-audited (every mutation logs BEFORE it takes effect).
  // -------------------------------------------------------------------------

  /**
   * POST /v1/extensions/submit — submit a community extension MANIFEST for
   * review. Contributor surface: ANY authenticated principal (a revoked or
   * quarantined one is still denied); NO capability required, and deliberately
   * OUTSIDE the /v1/admin/* prefix. Routes on the manifest `kind`: a `skill` mints
   * a new alias->target on approval; a `gate` (Phase 2) is stored PENDING but can
   * never be approved/enforced until the deferred CEL engine is registered. The
   * manifest carries its own `sha256` self-pin (the author computes it over the
   * canonical manifest bytes); the gateway re-derives + compares fail-closed, so a
   * mismatch — like any validation failure — is the opaque McpipDenied. Returns
   * the server-minted submission id.
   */
  async submitExtension(
    manifest: ExtensionManifest,
    opts: CallOptions = {},
  ): Promise<{ submission_id: string }> {
    return this.http.json<{ submission_id: string }>({
      method: 'POST',
      path: '/v1/extensions/submit',
      auth: true,
      body: { manifest },
      signal: opts.signal,
    });
  }

  /**
   * GET /v1/admin/extensions/pending — the tenant's PENDING submissions awaiting
   * review. Reviewer surface (CAP_CATALOG_REVIEWER — DISTINCT from
   * CAP_DIRECTORY_ADMIN), read-only, tenant-scoped. A strict whitelist projection
   * discriminated by `kind`: a skill row carries the reviewer-only `target` + a
   * `conflicts_existing_alias` additive-only diff; a gate row carries `approvable`
   * (false until a CEL prover/engine is registered). The declared target is a
   * reviewer surface only — it NEVER crosses the agent wire.
   */
  async extensionsPending(opts: CallOptions = {}): Promise<PendingExtension[]> {
    const body = await this.http.json<{ pending?: unknown }>({
      method: 'GET',
      path: '/v1/admin/extensions/pending',
      auth: true,
      signal: opts.signal,
    });
    return Array.isArray(body.pending) ? (body.pending as PendingExtension[]) : [];
  }

  /**
   * POST /v1/admin/extensions/{submission_id}/approve — approve a PENDING
   * submission. Reviewer surface (CAP_CATALOG_REVIEWER), tenant-scoped, opaque
   * deny. Re-runs the AUTHORITATIVE checks fail-closed (re-parse + re-pin,
   * `_overlay_skill_invalid`, additive-only, overlay ceiling), WORM-records the
   * approval BEFORE apply, then mints the skill through the SAME hardened overlay
   * path as `skillsRegister`. A GATE approval is REFUSED — no approve-without-proof
   * — until the deferred CEL engine is registered. Returns the approved alias.
   */
  async extensionApprove(
    submissionId: string,
    opts: CallOptions = {},
  ): Promise<{ approved: string }> {
    return this.http.json<{ approved: string }>({
      method: 'POST',
      path: `/v1/admin/extensions/${encodeURIComponent(submissionId)}/approve`,
      auth: true,
      signal: opts.signal,
    });
  }

  /**
   * POST /v1/admin/extensions/{submission_id}/reject — reject a PENDING
   * submission. Reviewer surface (CAP_CATALOG_REVIEWER), tenant-scoped, opaque
   * deny. WORM-records the rejection BEFORE marking the submission terminal;
   * NOTHING is applied to the catalog. Works uniformly for a skill or a gate.
   * Returns the rejected submission id.
   */
  async extensionReject(
    submissionId: string,
    opts: CallOptions = {},
  ): Promise<{ rejected: string }> {
    return this.http.json<{ rejected: string }>({
      method: 'POST',
      path: `/v1/admin/extensions/${encodeURIComponent(submissionId)}/reject`,
      auth: true,
      signal: opts.signal,
    });
  }

  // -------------------------------------------------------------------------
  // Registry governance — the verified-publisher allow-list (X3). Reviewer
  // surface (CAP_CATALOG_REVIEWER). PUT is WORM-logged emit-before-mutate.
  // -------------------------------------------------------------------------

  /**
   * GET /v1/admin/extensions/publishers — the tenant's verified-publisher
   * allow-list: the reviewer-PINNED set of publisher NAMESPACES (reverse-DNS
   * prefixes such as `io.github.owner`) a registry-sourced skill must belong to
   * before it can be approved or re-verified at boot. Reviewer surface
   * (CAP_CATALOG_REVIEWER), read-only, tenant-scoped, opaque deny. ALWAYS resolves
   * to a document: an honest empty `{ schema, namespaces: [] }` when nothing is
   * pinned (this admin read is fail-soft; the authoritative fail-closed membership
   * check runs server-side at approve/boot). Only namespaces — never a target/identity.
   */
  async verifiedPublishers(opts: CallOptions = {}): Promise<VerifiedPublishers> {
    const body = await this.http.json<{ publishers?: { schema?: unknown; namespaces?: unknown } }>({
      method: 'GET',
      path: '/v1/admin/extensions/publishers',
      auth: true,
      signal: opts.signal,
    });
    const doc = body.publishers ?? {};
    return {
      schema: PUBLISHERS_SCHEMA,
      namespaces: Array.isArray(doc.namespaces)
        ? doc.namespaces.filter((n): n is string => typeof n === 'string')
        : [],
    };
  }

  /**
   * PUT /v1/admin/extensions/publishers — replace the tenant's verified-publisher
   * allow-list with `namespaces`. Reviewer surface (CAP_CATALOG_REVIEWER),
   * tenant-scoped, opaque deny. Strict-validated server-side (schema
   * `mcpip-registry-publishers/1`, <= 256 charset-safe / identity-safe /
   * de-duplicated namespaces) and stored canonically; WORM-logged
   * emit-before-mutate. A malformed list is the same opaque McpipDenied.
   */
  async verifiedPublishersPut(namespaces: string[], opts: CallOptions = {}): Promise<void> {
    await this.http.json<{ ok: boolean }>({
      method: 'PUT',
      path: '/v1/admin/extensions/publishers',
      auth: true,
      body: { schema: PUBLISHERS_SCHEMA, namespaces },
      signal: opts.signal,
    });
  }

  // -------------------------------------------------------------------------
  // Compliance evidence — the portable bundle (X1). CAP_DIRECTORY_ADMIN.
  // -------------------------------------------------------------------------

  /**
   * GET /v1/admin/compliance/evidence — export a portable COMPLIANCE-EVIDENCE
   * bundle (CAP_DIRECTORY_ADMIN-gated, read-only). Assembled from REAL running
   * gateway state ONLY: the existing signed WORM attestation (latest sealed epoch
   * header + a fresh verify_chain verdict + the public signing_key_id), the running
   * version + signed release provenance, and a STATIC control-mapping manifest
   * (which MCPIP mechanism PROVIDES EVIDENCE FOR which control clause across EU AI
   * Act, SEC 17a-4/FINRA, DORA, NIST 800-53, SOC 2, ISO 42001).
   *
   * Reuses the SAME signed commitments `auditAttestation` surfaces — it mints no
   * key, signs nothing new, and never runs on / blocks the write-before-execute
   * emit path. EVIDENCE, NOT a CERTIFICATION: the `disclaimer` (and each
   * framework's `certification_note`) restates that the bundle asserts no SOC 2
   * report, FedRAMP authorization, ISO/DORA/EU-AI-Act certificate, named customer,
   * or auditor sign-off. Epoch fields are null before the first seal (honest empty
   * state). No target/payload/PIN/OTP/secret ever crosses the boundary. Any auth OR
   * engine/transport failure is the same opaque McpipDenied.
   */
  async complianceEvidence(opts: CallOptions = {}): Promise<ComplianceEvidence> {
    return this.http.json<ComplianceEvidence>({
      method: 'GET',
      path: '/v1/admin/compliance/evidence',
      auth: true,
      signal: opts.signal,
    });
  }

  // -------------------------------------------------------------------------
  // Deployment / License & Usage stats — the LOCAL live numbers.
  // -------------------------------------------------------------------------

  /**
   * GET /v1/admin/stats — the LOCAL live-stats read: this admin's OWN tenant's
   * REAL running numbers, served locally with NO beacon, NO vendor, and NO network:
   * the client-side "see the numbers live" surface (CAP_DIRECTORY_ADMIN-gated,
   * tenant-scoped, opaque deny).
   *
   * Returns the REAL governed-agent identity CARDINALITY (a HyperLogLog PFCOUNT —
   * the agent_ids are never stored or exposed), the tenant's {allow, deny, staged}
   * decision totals, the boot-verified license tier/status (honest `licensed:false`
   * when absent — never a fabricated customer/tier/date), the HONEST opt-in
   * vendor-telemetry posture (enabled / disabled / air-gap + coarse last-sent — an
   * air-gapped/sandbox deployment reports "air-gap" and never phones home), and the
   * running version. This is the SAME aggregate the opt-in beacon would report, but
   * scoped to the caller's own tenant; a fresh tenant gets honest zeros. NO
   * tenant/agent/alias/target ever crosses this boundary — only aggregate integers.
   * Any auth OR engine failure is the same opaque McpipDenied.
   */
  async stats(opts: CallOptions = {}): Promise<DeploymentStats> {
    return this.http.json<DeploymentStats>({
      method: 'GET',
      path: '/v1/admin/stats',
      auth: true,
      signal: opts.signal,
    });
  }

  // -------------------------------------------------------------------------
  // Operator/team USER management — the email-keyed console roster.
  // CAP_DIRECTORY_ADMIN. The `role` is a management label (authorizes nothing).
  // -------------------------------------------------------------------------

  /**
   * GET /v1/admin/users — a cursor page of the operator/team roster
   * (CAP_DIRECTORY_ADMIN, tenant-scoped). Paginated by cursor for SCALE (HSCAN,
   * never an offset): follow `next_cursor` until it is `'0'`. An honest empty
   * roster is `{ users: [], ... }`; the secret invite-token hash is never sent.
   */
  async usersList(cursor = '0', limit = 200, opts: CallOptions = {}): Promise<OperatorUserPage> {
    const q = `?cursor=${encodeURIComponent(cursor)}&limit=${encodeURIComponent(String(limit))}`;
    return this.http.json<OperatorUserPage>({
      method: 'GET',
      path: `/v1/admin/users${q}`,
      auth: true,
      signal: opts.signal,
    });
  }

  /**
   * POST /v1/admin/users/invite — invite a NEW member by email + role. WORM
   * emit-before-mutate (`operator_user_invite`; the email + role are recorded,
   * never the token). Additive-only — an existing email / invalid input / full
   * roster is the same opaque McpipDenied. Returns the record + the ONE-TIME
   * invite reference token to send (a reference, not a credential).
   */
  async usersInvite(
    email: string,
    role: OperatorRole = 'member',
    opts: CallOptions = {},
  ): Promise<OperatorInvite> {
    // The invite route replies 201 Created (the record is created + the one-time
    // token minted). `http.json` accepts ONLY 200, so it would throw McpipDenied and
    // DISCARD the token while the record already exists — a one-shot loss. Go through
    // the raw request and accept 200/201 (mirrors the console + Python SDK, which both
    // treat the 201 as success), so the caller reliably receives the invite token.
    const res = await this.http.request({
      method: 'POST',
      path: '/v1/admin/users/invite',
      auth: true,
      body: { email, role },
      signal: opts.signal,
    });
    if (res.status !== 200 && res.status !== 201) {
      return this.http.deny(res);
    }
    return (await res.json().catch(() => ({}))) as OperatorInvite;
  }

  /**
   * PUT /v1/admin/users/{email} — update a member's role and/or status
   * (enable/disable, activate). WORM emit-before-mutate (`operator_user_update`).
   * A non-member / malformed field is the same opaque McpipDenied.
   */
  async usersUpdate(
    email: string,
    patch: { role?: OperatorRole; status?: OperatorStatus },
    opts: CallOptions = {},
  ): Promise<OperatorUser> {
    const body = await this.http.json<{ user: OperatorUser }>({
      method: 'PUT',
      path: `/v1/admin/users/${encodeURIComponent(email)}`,
      auth: true,
      body: patch,
      signal: opts.signal,
    });
    return body.user;
  }

  /**
   * DELETE /v1/admin/users/{email} — remove a member (WORM emit-before-mutate,
   * `operator_user_remove`). Returns whether a record was actually deleted.
   */
  async usersRemove(email: string, opts: CallOptions = {}): Promise<boolean> {
    const body = await this.http.json<{ removed?: boolean }>({
      method: 'DELETE',
      path: `/v1/admin/users/${encodeURIComponent(email)}`,
      auth: true,
      signal: opts.signal,
    });
    return body.removed === true;
  }

  // -------------------------------------------------------------------------
  // Decision feed.
  // -------------------------------------------------------------------------

  /**
   * GET /v1/admin/decisions/recent — the live decision stream for the tenant
   * (all agents' traffic), newest first, whitelist projection only. `limit`
   * is clamped to the server's 1..200 range.
   */
  async decisionsRecent(limit = 50, opts: CallOptions = {}): Promise<RecentDecision[]> {
    const clamped = Math.min(200, Math.max(1, Math.floor(limit)));
    const body = await this.http.json<{ decisions?: unknown }>({
      method: 'GET',
      path: `/v1/admin/decisions/recent?limit=${clamped}`,
      auth: true,
      signal: opts.signal,
    });
    return Array.isArray(body.decisions) ? (body.decisions as RecentDecision[]) : [];
  }

  /**
   * GET /v1/admin/decisions — the date-ranged, multi-filtered, cursor-paged
   * decision HISTORY (at scale) over the SAME whitelist projection the live feed
   * serves. One page per call; pass the returned `next_cursor` back as
   * `query.cursor` for the next page (`null` = window fully walked).
   */
  async decisionsQuery(query: DecisionQuery = {}, opts: CallOptions = {}): Promise<DecisionPage> {
    const params = new URLSearchParams();
    if (query.fromMs !== undefined) params.set('from_ms', String(Math.floor(query.fromMs)));
    if (query.toMs !== undefined) params.set('to_ms', String(Math.floor(query.toMs)));
    if (query.cursor) params.set('cursor', query.cursor);
    params.set('limit', String(Math.floor(query.limit ?? 100)));
    for (const [facet, value] of Object.entries(query.filters ?? {})) {
      if (value === undefined) continue;
      const joined = Array.isArray(value) ? value.join(',') : value;
      if (joined) params.set(facet, joined);
    }
    const body = await this.http.json<Partial<DecisionPage>>({
      method: 'GET',
      path: `/v1/admin/decisions?${params.toString()}`,
      auth: true,
      signal: opts.signal,
    });
    return {
      decisions: Array.isArray(body.decisions) ? body.decisions : [],
      next_cursor: typeof body.next_cursor === 'string' ? body.next_cursor : null,
      scanned: typeof body.scanned === 'number' ? body.scanned : 0,
      exhausted: body.exhausted === true,
    };
  }

  /**
   * Stream EVERY matching decision across the whole window (newest first),
   * following `next_cursor` transparently — the "export all" primitive over
   * {@link decisionsQuery}. `pageLimit` sizes each underlying page; `maxPages`
   * is a runaway backstop.
   */
  async *decisionsAll(
    query: Omit<DecisionQuery, 'cursor' | 'limit'> = {},
    opts: CallOptions & { pageLimit?: number; maxPages?: number } = {},
  ): AsyncGenerator<RecentDecision> {
    const pageLimit = opts.pageLimit ?? 200;
    const maxPages = opts.maxPages ?? 100000;
    let cursor: string | undefined;
    for (let i = 0; i < maxPages; i += 1) {
      const page = await this.decisionsQuery(
        { ...query, cursor, limit: pageLimit },
        { signal: opts.signal },
      );
      for (const row of page.decisions) yield row;
      if (page.next_cursor === null) break;
      cursor = page.next_cursor;
    }
  }

  // -------------------------------------------------------------------------
  // Forensic reconstruction — investigator-only, access-audited.
  // -------------------------------------------------------------------------

  /**
   * GET /v1/admin/forensic/{correlation_id} — reconstruct the REAL query behind
   * one correlation id (the opaque alias, the already-canonicalized and
   * secret-redacted arguments, and non-secret identity context).
   *
   * ADMIN/INVESTIGATOR-ONLY and a HIGHER bar than the rest of this client: the
   * Bearer JWT must carry CAP_FORENSIC_READ, which is DISTINCT from
   * CAP_DIRECTORY_ADMIN — holding directory-admin does NOT grant raw-payload
   * read. The gateway WORM-logs an admin_action='forensic_read' (who read whose
   * payload) BEFORE disclosing anything, so every access is audited. Scope is
   * always the admin JWT's own tenant.
   *
   * Resolves to `null` for an honest, OPAQUE miss: the feature is off on this
   * gateway, or the correlation id is unknown, expired past its TTL, or owned by
   * another tenant (an indistinguishable not-found — no cross-tenant existence
   * oracle). A missing/insufficient capability stays the opaque McpipDenied,
   * never a `null`.
   */
  async forensicGet(
    correlationId: string,
    opts: CallOptions = {},
  ): Promise<ForensicPayload | null> {
    const res = await this.http.request({
      method: 'GET',
      path: `/v1/admin/forensic/${encodeURIComponent(correlationId)}`,
      auth: true,
      signal: opts.signal,
    });
    if (res.status === 404) {
      return null; // opaque miss: feature off, or unknown/expired/cross-tenant.
    }
    if (res.status !== 200) {
      return this.http.deny(res);
    }
    const body = (await res.json().catch(() => ({}))) as { found?: unknown; forensic?: unknown };
    if (body.found !== true || typeof body.forensic !== 'object' || body.forensic === null) {
      return null;
    }
    return body.forensic as ForensicPayload;
  }

  // -------------------------------------------------------------------------
  // Principals — the persistent kill-switch (distinct from canary quarantine).
  // -------------------------------------------------------------------------

  /**
   * POST /v1/admin/principals/{agent_id}/revoke — deny EVERY request from
   * (tenant, agent_id) until reactivated. Deny-only: never mints identity.
   */
  async principalsRevoke(
    agentId: string,
    reason: string | null = null,
    opts: CallOptions = {},
  ): Promise<{ revoked: string }> {
    return this.http.json<{ revoked: string }>({
      method: 'POST',
      path: `/v1/admin/principals/${encodeURIComponent(agentId)}/revoke`,
      auth: true,
      body: { reason },
      signal: opts.signal,
    });
  }

  /** POST /v1/admin/principals/{agent_id}/reactivate — lift a revocation. */
  async principalsReactivate(
    agentId: string,
    opts: CallOptions = {},
  ): Promise<{ reactivated: string; removed: boolean }> {
    return this.http.json<{ reactivated: string; removed: boolean }>({
      method: 'POST',
      path: `/v1/admin/principals/${encodeURIComponent(agentId)}/reactivate`,
      auth: true,
      signal: opts.signal,
    });
  }

  /** GET /v1/admin/principals/revoked — the authoritative revoked agent_ids, sorted. */
  async principalsRevoked(opts: CallOptions = {}): Promise<string[]> {
    const body = await this.http.json<{ revoked?: unknown }>({
      method: 'GET',
      path: '/v1/admin/principals/revoked',
      auth: true,
      signal: opts.signal,
    });
    return Array.isArray(body.revoked)
      ? body.revoked.filter((a): a is string => typeof a === 'string')
      : [];
  }

  // -------------------------------------------------------------------------
  // Tripwire rosters.
  // -------------------------------------------------------------------------

  /**
   * GET /v1/admin/quarantine — agents currently frozen by the canary
   * tripwire, each with its remaining TTL. Read-only: a false trip self-heals
   * at TTL; a deliberate persistent block is principalsRevoke.
   */
  async quarantine(opts: CallOptions = {}): Promise<QuarantinedAgent[]> {
    const body = await this.http.json<{ quarantined?: unknown }>({
      method: 'GET',
      path: '/v1/admin/quarantine',
      auth: true,
      signal: opts.signal,
    });
    return Array.isArray(body.quarantined) ? (body.quarantined as QuarantinedAgent[]) : [];
  }

  /**
   * GET /v1/admin/canaries — the tenant's decoy-alias roster. The ONLY
   * surface where the canary flag crosses the wire (the agent-facing catalog
   * keeps hiding it); metadata only — never the tripwire sink or a target.
   */
  async canaries(opts: CallOptions = {}): Promise<CanaryDecoy[]> {
    const body = await this.http.json<{ canaries?: unknown }>({
      method: 'GET',
      path: '/v1/admin/canaries',
      auth: true,
      signal: opts.signal,
    });
    return Array.isArray(body.canaries) ? (body.canaries as CanaryDecoy[]) : [];
  }

  // -------------------------------------------------------------------------
  // Operator directory (org chart + RBAC) — non-authoritative metadata.
  // -------------------------------------------------------------------------

  /** GET /v1/directory — the persisted document, or null when nothing was saved. */
  async directoryGet(opts: CallOptions = {}): Promise<DirectoryDocument | null> {
    const body = await this.http.json<{ document?: DirectoryDocument | null }>({
      method: 'GET',
      path: '/v1/directory',
      auth: true,
      signal: opts.signal,
    });
    return body.document ?? null;
  }

  /** PUT /v1/directory — persist the document for the admin's tenant. */
  async directoryPut(document: DirectoryDocument, opts: CallOptions = {}): Promise<void> {
    await this.http.json<{ ok: boolean }>({
      method: 'PUT',
      path: '/v1/directory',
      auth: true,
      body: document,
      signal: opts.signal,
    });
  }

  /**
   * GET /v1/admin/directory/relations — the ReBAC relation edges projected from
   * this tenant's committed grants (the operator Knowledge-Graph edge source). A
   * best-effort PROJECTION, tenant-scoped to the caller JWT; the gateway/Redis
   * grant state stays authoritative. Read-only — like `quarantine` / `canaries`
   * it emits no WORM record.
   *
   * Each committed grant projects a `member` edge (subject -> compartment) and a
   * read-time-derived `grantor` edge (issuing principal -> compartment). The
   * optional `subject`/`relation`/`object` filters narrow the emitted edges (a
   * malformed filter is an opaque McpipDenied); a FULL (subject, relation, object)
   * triple additionally returns `allowed` — the BOUNDED, fail-closed
   * transitive-closure check (only `member` is traversable in v1; `grantor` is a
   * derived display edge). READ/VISUALIZATION ONLY: the authorization pipeline
   * NEVER consults it. A transport error yields an honest empty roster (fail-soft
   * — the projection under-reports during a blip, never over-reports).
   */
  async directoryRelations(
    filter: { subject?: string; relation?: string; object?: string } = {},
    opts: CallOptions = {},
  ): Promise<RelationList> {
    const query = new URLSearchParams();
    if (filter.subject !== undefined) query.set('subject', filter.subject);
    if (filter.relation !== undefined) query.set('relation', filter.relation);
    if (filter.object !== undefined) query.set('object', filter.object);
    const suffix = query.toString();
    const body = await this.http.json<{ relations?: unknown; allowed?: unknown }>({
      method: 'GET',
      path: `/v1/admin/directory/relations${suffix ? `?${suffix}` : ''}`,
      auth: true,
      signal: opts.signal,
    });
    return {
      relations: Array.isArray(body.relations) ? (body.relations as RelationEdge[]) : [],
      ...(typeof body.allowed === 'boolean' ? { allowed: body.allowed } : {}),
    };
  }

  // -------------------------------------------------------------------------
  // Deny-only policy overlay (velocity cap + amount ceiling) — per tenant.
  // -------------------------------------------------------------------------

  /**
   * GET /v1/admin/policy — the tenant's deny-only policy document (schema
   * `mcpip-policy/1`). ALWAYS resolves to a document: when nothing is stored the
   * gateway returns the honest empty `{ schema: 'mcpip-policy/1', rules: [] }`
   * (no limits — opt-in), never null. The document holds ONLY velocity/amount
   * rules — never an alias->target mapping or identity.
   */
  async policyGet(opts: CallOptions = {}): Promise<PolicyDocument> {
    const body = await this.http.json<{ policy?: PolicyDocument }>({
      method: 'GET',
      path: '/v1/admin/policy',
      auth: true,
      signal: opts.signal,
    });
    return body.policy ?? { schema: 'mcpip-policy/1', rules: [] };
  }

  /**
   * PUT /v1/admin/policy — persist the tenant's deny-only policy document. The
   * body IS the document (`{ schema, rules }`); it is strict-validated
   * server-side (<= 64 well-formed velocity/amount rules, size-bounded) and a
   * malformed document is the same opaque McpipDenied that never leaks its
   * cause. WORM-logged emit-before-mutate.
   */
  async policyPut(document: PolicyDocument, opts: CallOptions = {}): Promise<void> {
    await this.http.json<{ ok: boolean }>({
      method: 'PUT',
      path: '/v1/admin/policy',
      auth: true,
      body: document,
      signal: opts.signal,
    });
  }

  /**
   * POST /v1/admin/policy/delete — remove the tenant's policy document, back to
   * the honest no-limits state. Idempotent (deleting an absent document still
   * acknowledges); returns the server's `ok`.
   */
  async policyDelete(opts: CallOptions = {}): Promise<boolean> {
    const body = await this.http.json<{ ok?: unknown }>({
      method: 'POST',
      path: '/v1/admin/policy/delete',
      auth: true,
      signal: opts.signal,
    });
    return body.ok === true;
  }

  // -------------------------------------------------------------------------
  // Workspace scaffolding — draft (pure) -> validate (dry-run) -> apply.
  // -------------------------------------------------------------------------

  /** POST /v1/admin/workspace/draft — deterministic brief -> plan proposal. No mutation. */
  async workspaceDraft(body: WorkspaceDraftBody = {}, opts: CallOptions = {}): Promise<WorkspaceDraft> {
    return this.http.json<WorkspaceDraft>({
      method: 'POST',
      path: '/v1/admin/workspace/draft',
      auth: true,
      body,
      signal: opts.signal,
    });
  }

  /** POST /v1/admin/workspace/plan/validate — fail-closed dry run. */
  async workspaceValidate(plan: WorkspacePlan, opts: CallOptions = {}): Promise<PlanValidation> {
    return this.http.json<PlanValidation>({
      method: 'POST',
      path: '/v1/admin/workspace/plan/validate',
      auth: true,
      body: { plan },
      signal: opts.signal,
    });
  }

  /**
   * POST /v1/admin/workspace/plan/apply — re-validates fail-closed, registers
   * each new skill through the hardened register path, persists the org
   * chart. Idempotent: existing aliases land in `skipped`.
   */
  async workspaceApply(plan: WorkspacePlan, opts: CallOptions = {}): Promise<WorkspaceApplyResult> {
    return this.http.json<WorkspaceApplyResult>({
      method: 'POST',
      path: '/v1/admin/workspace/plan/apply',
      auth: true,
      body: { plan },
      signal: opts.signal,
    });
  }

  // -------------------------------------------------------------------------
  // Cloud IAM environment bindings (role->compartment mappings; no secrets).
  // -------------------------------------------------------------------------

  /** GET /v1/admin/cloud/environments — the tenant's bindings (public view). */
  async cloudEnvironmentsList(opts: CallOptions = {}): Promise<CloudEnvironment[]> {
    const body = await this.http.json<{ environments?: unknown }>({
      method: 'GET',
      path: '/v1/admin/cloud/environments',
      auth: true,
      signal: opts.signal,
    });
    return Array.isArray(body.environments) ? (body.environments as CloudEnvironment[]) : [];
  }

  /** PUT /v1/admin/cloud/environments — create/update one binding; returns the public view. */
  async cloudEnvironmentsPut(
    env: CloudEnvironmentInput,
    opts: CallOptions = {},
  ): Promise<CloudEnvironment> {
    const body = await this.http.json<{ environment: CloudEnvironment }>({
      method: 'PUT',
      path: '/v1/admin/cloud/environments',
      auth: true,
      body: env,
      signal: opts.signal,
    });
    return body.environment;
  }

  /** POST /v1/admin/cloud/environments/{env_id}/delete — remove one binding. */
  async cloudEnvironmentsDelete(
    envId: string,
    opts: CallOptions = {},
  ): Promise<{ deleted: string; removed: boolean }> {
    return this.http.json<{ deleted: string; removed: boolean }>({
      method: 'POST',
      path: `/v1/admin/cloud/environments/${encodeURIComponent(envId)}/delete`,
      auth: true,
      signal: opts.signal,
    });
  }

  // -------------------------------------------------------------------------
  // Secret vault — values are write-only; every read returns metadata only.
  // -------------------------------------------------------------------------

  /** GET /v1/admin/vault/secrets — metadata roster + whether a vault is configured. */
  async vaultSecretsList(opts: CallOptions = {}): Promise<VaultSecretList> {
    const body = await this.http.json<{ vault_enabled?: unknown; secrets?: unknown }>({
      method: 'GET',
      path: '/v1/admin/vault/secrets',
      auth: true,
      signal: opts.signal,
    });
    return {
      vault_enabled: body.vault_enabled === true,
      secrets: Array.isArray(body.secrets) ? (body.secrets as VaultSecret[]) : [],
    };
  }

  /**
   * PUT /v1/admin/vault/secrets — store/rotate one broker credential. The
   * material is sent exactly once and never returned by any endpoint; the
   * response is the metadata public view (fingerprint included).
   */
  async vaultSecretsPut(secret: VaultSecretInput, opts: CallOptions = {}): Promise<VaultSecret> {
    const body = await this.http.json<{ secret: VaultSecret }>({
      method: 'PUT',
      path: '/v1/admin/vault/secrets',
      auth: true,
      body: secret,
      signal: opts.signal,
    });
    return body.secret;
  }

  /** POST /v1/admin/vault/secrets/{secret_id}/delete — remove one stored credential. */
  async vaultSecretsDelete(
    secretId: string,
    opts: CallOptions = {},
  ): Promise<{ deleted: string; removed: boolean }> {
    return this.http.json<{ deleted: string; removed: boolean }>({
      method: 'POST',
      path: `/v1/admin/vault/secrets/${encodeURIComponent(secretId)}/delete`,
      auth: true,
      signal: opts.signal,
    });
  }
}
