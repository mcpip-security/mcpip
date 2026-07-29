/* ---------------------------------------------------------------------------
   @mcpip/sdk — agent-surface client + the shared HTTP core.

   Design rules carried from the gateway itself:

     * Fail closed, stay opaque. Any non-success maps to ONE typed error
       carrying only the correlation id — the concrete deny reason lives in
       the WORM log and the SDK never guesses it (errors.ts).
     * NEVER auto-retry POST /v1/authorize. A replayed step-up consume is a
       real PIN_NOT_FOUND deny, and every retry double-counts WORM events.
       One method call == one wire call, always.
     * Identity refresh is proactive, never reactive. A callback TokenSource
       is re-invoked ~30s before the cached JWT's own exp (decoded client-side
       without verification — the gateway is the verifier). It is never
       re-invoked in response to a deny, because denies are opaque: an expired
       token and a policy deny are indistinguishable on purpose.
--------------------------------------------------------------------------- */

import {
  AGENT_FACING_DENY_MESSAGE,
  CORRELATION_HEADER,
  type AuditAttestation,
  type AuthorizeAllowed,
  type AuthorizeRequest,
  type AuthorizeResult,
  type AuthorizeStaged,
  type AuthzenDecisionResponse,
  type CatalogItem,
  type ExecutionReceipt,
  type HealthzInfo,
  type LicenseInfo,
  type ProtectedResourceMetadata,
  type ReadyInfo,
  type StagedChallenge,
  type VersionInfo,
} from './types.js';
import {
  McpipDenied,
  McpipInvalidRequest,
  McpipUnavailable,
  McpipSandboxOnly,
} from './errors.js';

// ---------------------------------------------------------------------------
// Tool-call envelope builders — the exact strict ingress shapes the Bridge's
// per-provider validators accept (bridge/connectors/formats.py). Provider ids
// (call/toolUse ids) are parsed then DISCARDED server-side and are NOT part of
// the payload-lock hash, so the deterministic defaults are safe; pass your
// provider's real id when relaying genuine model output.
// ---------------------------------------------------------------------------

/** OpenAI dialect: `arguments` is a JSON *string* on the wire, built here. */
export function openaiToolCall(
  name: string,
  args: Record<string, unknown>,
  id = 'call_1',
): Record<string, unknown> {
  return { id, type: 'function', function: { name, arguments: JSON.stringify(args) } };
}

/** Anthropic dialect: one `tool_use` content block. */
export function anthropicToolUse(
  name: string,
  input: Record<string, unknown>,
  id = 'toolu_1',
): Record<string, unknown> {
  return { type: 'tool_use', id, name, input };
}

/** Gemini/Vertex dialect: the bare `{"functionCall": ...}` PART object (never a wrapper). */
export function geminiFunctionCall(
  name: string,
  args: Record<string, unknown> = {},
): Record<string, unknown> {
  return { functionCall: { name, args } };
}

/** Bedrock Converse dialect: the native `toolUse` block. */
export function bedrockToolUse(
  name: string,
  input: Record<string, unknown>,
  toolUseId = 'tooluse_1',
): Record<string, unknown> {
  return { toolUse: { toolUseId, name, input } };
}

/** MCP dialect: a full JSON-RPC 2.0 `tools/call` request dict (source_format 'mcp_jsonrpc'). */
export function mcpToolsCall(
  name: string,
  args: Record<string, unknown> = {},
  id: string | number = 1,
): Record<string, unknown> {
  return { jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } };
}

/** Legacy canonical raw-MCP shape: `{"tool", "arguments"}` (source_format 'raw_mcp'). */
export function rawMcp(tool: string, args: Record<string, unknown>): Record<string, unknown> {
  return { tool, arguments: args };
}

/**
 * A2A dialect: a `Task` envelope carrying EXACTLY ONE `DataPart` skill
 * invocation (source_format 'a2a_task').
 *
 * MCPIP does not sit on the A2A message bus — it gates the single
 * side-effecting call a governed identity proposes, so the accepted envelope is
 * deliberately narrow: one message, one data part, `{skill, arguments}`. A task
 * carrying zero or several invocations is a hard 422, not a guess.
 */
export function a2aTask(
  skill: string,
  args: Record<string, unknown> = {},
  ids: { taskId?: string; contextId?: string; messageId?: string } = {},
): Record<string, unknown> {
  return {
    kind: 'task',
    id: ids.taskId ?? 'task_1',
    contextId: ids.contextId ?? 'ctx_1',
    status: { state: 'submitted' },
    message: {
      kind: 'message',
      role: 'agent',
      messageId: ids.messageId ?? 'msg_1',
      parts: [{ kind: 'data', data: { skill, arguments: args } }],
    },
  };
}

// ---------------------------------------------------------------------------
// Identity: TokenSource + proactive exp-slack refresh (same constants as
// dashboard useGatewayLive.ts and scripts/claude_mcp_bridge.py).
// ---------------------------------------------------------------------------

/**
 * A verbatim JWT string (used as-is, never refreshed — the production
 * MCPIP_TOKEN pattern), or an async minter integrating your IdP/STS. The
 * minter is called once, cached, and called again only when the cached token
 * is within TOKEN_EXP_SLACK_MS of its own exp claim.
 */
export type TokenSource = string | (() => string | Promise<string>);

/** Re-mint this long before the JWT's exp (sandbox tokens live ~5 min). */
export const TOKEN_EXP_SLACK_MS = 30_000;

/** Best-effort exp (epoch ms) from an UNVERIFIED JWT payload — refresh timing only. */
function decodeExpMs(jwt: string): number | null {
  try {
    const payload = jwt.split('.')[1];
    if (!payload) {
      return null;
    }
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
    const claims = JSON.parse(json) as { exp?: unknown };
    return typeof claims.exp === 'number' ? claims.exp * 1000 : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Shared HTTP core.
// ---------------------------------------------------------------------------

export interface McpipClientOptions {
  /** Gateway origin, e.g. "http://localhost:8080" (default). Trailing slashes stripped. */
  baseUrl?: string;
  /** Bearer identity for JWT-gated routes. Omitted => requests go out unauthenticated
      and the gateway denies opaquely (fail closed — the SDK never invents identity). */
  token?: TokenSource;
  /** Custom fetch (tests, instrumentation). Defaults to the global fetch. */
  fetch?: typeof fetch;
}

/** Per-call options — AbortSignal passthrough on every method. */
export interface CallOptions {
  signal?: AbortSignal;
}

interface RequestSpec {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  auth: boolean;
  body?: unknown;
  signal?: AbortSignal;
}

/**
 * The one wire-protocol implementation all three clients share. Exported so
 * admin.ts / sandbox.ts can compose it; not part of the package's public
 * index surface.
 */
export class GatewayHttp {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly source: TokenSource | null;
  private cachedToken: string | null = null;
  private cachedExpMs: number | null = null;

  constructor(options: McpipClientOptions) {
    this.baseUrl = (options.baseUrl ?? 'http://localhost:8080').replace(/\/+$/, '');
    // Wrap either implementation so the eventual call never carries `this`
    // (browsers throw "Illegal invocation" when fetch is invoked as a method
    // of anything but the global).
    const custom = options.fetch;
    this.fetchImpl = custom
      ? (input: RequestInfo | URL, init?: RequestInit) => custom(input, init)
      : (input: RequestInfo | URL, init?: RequestInit) => fetch(input, init);
    this.source = options.token ?? null;
  }

  /** Resolve the Bearer token: verbatim string, or cached-mint with exp slack. */
  private async bearer(): Promise<string | null> {
    const source = this.source;
    if (source === null) {
      return null;
    }
    if (typeof source === 'string') {
      return source; // used verbatim, never re-minted (externally rotated).
    }
    if (this.cachedToken !== null) {
      const expMs = this.cachedExpMs;
      if (expMs === null || Date.now() < expMs - TOKEN_EXP_SLACK_MS) {
        return this.cachedToken;
      }
      this.cachedToken = null;
    }
    const minted = await source();
    this.cachedToken = minted;
    this.cachedExpMs = decodeExpMs(minted);
    return minted;
  }

  /** One wire call. Network failure => McpipUnavailable; caller aborts pass through. */
  async request(spec: RequestSpec): Promise<Response> {
    const headers: Record<string, string> = {};
    if (spec.body !== undefined) {
      headers['Content-Type'] = 'application/json';
    }
    if (spec.auth) {
      const token = await this.bearer();
      if (token !== null) {
        headers['Authorization'] = `Bearer ${token}`;
      }
    }
    const init: RequestInit = { method: spec.method, headers };
    if (spec.body !== undefined) {
      init.body = JSON.stringify(spec.body);
    }
    if (spec.signal !== undefined) {
      init.signal = spec.signal;
    }
    try {
      return await this.fetchImpl(`${this.baseUrl}${spec.path}`, init);
    } catch (err) {
      if (err instanceof Error && (err.name === 'AbortError' || err.name === 'TimeoutError')) {
        throw err; // caller-driven cancellation is not a gateway failure.
      }
      throw new McpipUnavailable(`gateway unreachable at ${this.baseUrl}`, null, { cause: err });
    }
  }

  /**
   * Map a non-2xx response to its typed error and throw. `sandboxEndpoint`
   * (with optional `sandboxDetail`) turns a 404 into McpipSandboxOnly
   * for the routes that legitimately vanish in production; every other 404
   * stays inside the opaque-deny arm, fail closed.
   */
  async deny(res: Response, sandboxEndpoint?: string, sandboxDetail?: string): Promise<never> {
    const body = (await res.json().catch(() => ({}))) as {
      error?: unknown;
      correlation_id?: unknown;
    };
    const wireError = typeof body.error === 'string' ? body.error : null;
    const correlationId =
      typeof body.correlation_id === 'string'
        ? body.correlation_id
        : res.headers.get(CORRELATION_HEADER) ?? 'unknown';

    if (res.status === 404 && sandboxEndpoint !== undefined) {
      throw new McpipSandboxOnly(sandboxEndpoint, sandboxDetail);
    }
    if (res.status === 422 || res.status === 413) {
      throw new McpipInvalidRequest(wireError ?? 'invalid request', correlationId, res.status);
    }
    if (res.status === 503) {
      const retryAfter = res.headers.get('Retry-After');
      const seconds = retryAfter !== null && /^\d+$/.test(retryAfter) ? Number(retryAfter) : null;
      throw new McpipUnavailable(wireError ?? 'gateway shed the request', seconds);
    }
    // 401 / 403 / 500 / plain 404 / anything else: the opaque deny. The
    // concrete reason exists only in the WORM log — quote the correlation id.
    throw new McpipDenied(correlationId, res.status, wireError ?? AGENT_FACING_DENY_MESSAGE);
  }

  /** request() for endpoints where the only success is a 200 JSON body. */
  async json<T>(spec: RequestSpec, sandboxEndpoint?: string, sandboxDetail?: string): Promise<T> {
    const res = await this.request(spec);
    if (res.status !== 200) {
      return this.deny(res, sandboxEndpoint, sandboxDetail);
    }
    try {
      return (await res.json()) as T;
    } catch (err) {
      // A 200 with a non-JSON body means something other than the gateway
      // answered (SPA fallback, proxy error page) — surface it honestly.
      throw new McpipUnavailable(`gateway answered ${spec.path} with a non-JSON body`, null, {
        cause: err,
      });
    }
  }
}

// ---------------------------------------------------------------------------
// McpipClient — the agent surface.
// ---------------------------------------------------------------------------

interface JsonRpcErrorShape {
  code?: unknown;
  message?: unknown;
  data?: unknown;
}

export class McpipClient {
  private readonly http: GatewayHttp;
  private rpcSeq = 0;

  constructor(options: McpipClientOptions = {}) {
    this.http = new GatewayHttp(options);
  }

  /** The resolved gateway origin this client talks to. */
  get baseUrl(): string {
    return this.http.baseUrl;
  }

  /**
   * POST /v1/authorize — the single authorization choke point. One request
   * authorizes exactly one tool call (batches are denied server-side).
   *
   *   200 -> { status: 'allowed' } with the ExecutionReceipt
   *   202 -> { status: 'staged' } with the challengeId for the PIN ceremony
   *   anything else -> throws (McpipDenied opaque / McpipInvalidRequest 422)
   *
   * NEVER retried by the SDK — see the module header for why.
   */
  async authorize(request: AuthorizeRequest, opts: CallOptions = {}): Promise<AuthorizeResult> {
    const res = await this.http.request({
      method: 'POST',
      path: '/v1/authorize',
      auth: true,
      body: request,
      signal: opts.signal,
    });
    if (res.status === 200) {
      const receipt = (await res.json()) as ExecutionReceipt;
      return {
        status: 'allowed',
        correlationId: receipt.correlation_id,
        transactionRef: receipt.transaction_ref,
        executedTargetClass: receipt.executed_target_class,
        wormSequence: receipt.worm_sequence,
        vendedCredential: receipt.vended_credential ?? null,
        receipt,
      };
    }
    if (res.status === 202) {
      const challenge = (await res.json()) as StagedChallenge;
      return {
        status: 'staged',
        correlationId: challenge.correlation_id,
        challengeId: challenge.challenge_id,
        actionRequired: challenge.action_required,
        riskTier: challenge.risk_tier,
        challenge,
        request,
      };
    }
    return this.http.deny(res);
  }

  /**
   * Step-up completion: resubmit the staged request VERBATIM plus the
   * one-time code obtained out-of-band. The lock is payload-bound — any drift
   * in tenant/agent/alias/arguments is an opaque deny (the lock survives a
   * drifted attempt; a correct retry with the same pin+challenge still
   * consumes, until PIN_TTL_SECONDS elapse or PIN_MAX_ATTEMPTS wrong codes
   * destroy it). A spent challenge is a real deny when replayed, which is why
   * the SDK never resubmits on its own.
   *
   * For a lock staged on the MCP edge (tools/call answering isError staging
   * content), consume via authorize() directly with source_format
   * 'mcp_jsonrpc', the identical JSON-RPC dict, and pin + challenge_id — the
   * lock is format-independent.
   */
  async complete(
    staged: AuthorizeStaged,
    pin: string,
    opts: CallOptions = {},
  ): Promise<AuthorizeAllowed> {
    const consume: AuthorizeRequest = {
      ...staged.request,
      pin,
      challenge_id: staged.challengeId,
    };
    const result = await this.authorize(consume, opts);
    if (result.status !== 'allowed') {
      // Outside the wire contract: a pin+challenge submission cannot re-stage.
      throw new McpipInvalidRequest(
        'gateway re-staged a step-up completion',
        result.correlationId,
        202,
      );
    }
    return result;
  }

  /**
   * GET /v1/catalog — the tenant-scoped, metadata-only skill catalog. An empty
   * array means "this identity enumerates nothing" — a real answer, distinct
   * from the thrown errors of an unreachable/denying gateway.
   */
  async catalog(opts: CallOptions = {}): Promise<CatalogItem[]> {
    const body = await this.http.json<{ catalog?: unknown }>({
      method: 'GET',
      path: '/v1/catalog',
      auth: true,
      signal: opts.signal,
    });
    if (!Array.isArray(body.catalog)) {
      throw new McpipUnavailable('gateway answered /v1/catalog without a catalog array');
    }
    return body.catalog as CatalogItem[];
  }

  /**
   * POST /v1/mcp — one JSON-RPC 2.0 call on the MCP-native edge (one object
   * per POST; batches are rejected server-side). `initialize` and
   * `notifications/*` go unauthenticated per the edge contract; everything
   * else carries the Bearer header (identity is header-only on this edge).
   *
   * Returns the JSON-RPC `result` (undefined for notifications, which the
   * gateway acknowledges with an empty 202). A -32000 error is a policy deny
   * and throws McpipDenied with the correlation id from `error.data`; other
   * JSON-RPC error codes throw McpipInvalidRequest. Note: a `tools/call` on a
   * pin_required alias succeeds with `isError: true` staging content — finish
   * that ceremony via authorize() with source_format 'mcp_jsonrpc', the
   * identical JSON-RPC dict, and pin + challenge_id (the payload lock is
   * format-independent).
   */
  async mcpCall<TResult = unknown>(
    method: string,
    params?: Record<string, unknown>,
    opts: CallOptions = {},
  ): Promise<TResult> {
    const notification = method.startsWith('notifications/');
    const envelope: Record<string, unknown> = { jsonrpc: '2.0', method };
    if (!notification) {
      envelope['id'] = ++this.rpcSeq;
    }
    if (params !== undefined) {
      envelope['params'] = params;
    }
    const res = await this.http.request({
      method: 'POST',
      path: '/v1/mcp',
      auth: !notification && method !== 'initialize',
      body: envelope,
      signal: opts.signal,
    });
    if (res.status === 202) {
      // Notification acknowledged with an empty body.
      return undefined as unknown as TResult;
    }
    if (res.status !== 200) {
      return this.http.deny(res);
    }
    const payload = (await res.json().catch(() => null)) as {
      result?: unknown;
      error?: JsonRpcErrorShape;
    } | null;
    if (payload === null || typeof payload !== 'object') {
      throw new McpipUnavailable('gateway answered /v1/mcp with a non-JSON-RPC body');
    }
    const rpcError = payload.error;
    if (rpcError !== undefined && rpcError !== null && typeof rpcError === 'object') {
      const code = typeof rpcError.code === 'number' ? rpcError.code : 0;
      const message =
        typeof rpcError.message === 'string' ? rpcError.message : AGENT_FACING_DENY_MESSAGE;
      if (code === -32000) {
        const data = rpcError.data as { correlation_id?: unknown } | null | undefined;
        const correlationId =
          data && typeof data.correlation_id === 'string'
            ? data.correlation_id
            : res.headers.get(CORRELATION_HEADER) ?? 'unknown';
        throw new McpipDenied(correlationId, res.status, message);
      }
      throw new McpipInvalidRequest(
        `JSON-RPC ${code}: ${message}`,
        res.headers.get(CORRELATION_HEADER),
        res.status,
      );
    }
    return payload.result as TResult;
  }

  /**
   * POST /v1/authz/decision — the OpenID-AuthZEN / COAZ decision surface (MCPIP
   * as a PDP). Ask for a PRE-EXECUTION authorization verdict on a hypothetical
   * call; DECISION-ONLY (nothing executes, vends, stages/consumes a PIN, or
   * mutates a grant).
   *
   * `alias` is the opaque AuthZEN `resource.id`; `args` the `action.properties`
   * (deep-validated by the SAME bridge walker as a real call — an identity-shaped
   * key is a hard deny). `subject` is advisory/echo ONLY and is NEVER consulted
   * for identity: identity comes solely from this client's Bearer JWT, so it
   * cannot be injected through the subject.
   *
   * Returns `{ decision, obligations? }`. A permit is `decision: true` optionally
   * carrying standards-shaped obligations (`mcpip.step_up.pin` for a PIN_REQUIRED
   * tier, `mcpip.sender_constraint.dpop` for a sender-constrained resource); a deny
   * is the bare opaque `decision: false` — no reason/target/topology (the concrete
   * cause lives only in the WORM log). A verdict is NOT an authorization to act — a
   * subsequent authorize() still runs the full pipeline (including the runtime
   * velocity/amount controls a decision query deliberately does not evaluate). The
   * endpoint is JWT-gated: an invalid/absent token throws McpipDenied, distinct
   * from `decision: false`.
   */
  async authzDecision(
    alias: string,
    args: Record<string, unknown> = {},
    opts: CallOptions & {
      subject?: Record<string, unknown>;
      context?: Record<string, unknown>;
      actionName?: string;
    } = {},
  ): Promise<AuthzenDecisionResponse> {
    const body: Record<string, unknown> = {
      subject: opts.subject ?? {},
      resource: { id: alias, type: 'mcpip.tool' },
      action: { name: opts.actionName ?? 'invoke', properties: args },
    };
    if (opts.context !== undefined) {
      body['context'] = opts.context;
    }
    return this.http.json<AuthzenDecisionResponse>({
      method: 'POST',
      path: '/v1/authz/decision',
      auth: true,
      body,
      signal: opts.signal,
    });
  }

  /**
   * GET /.well-known/oauth-protected-resource — the RFC 9728 OAuth 2.1 Protected
   * Resource Metadata document. PUBLIC and unauthenticated (no Bearer sent),
   * never shed, available in sandbox AND production. A conformant MCP client reads
   * it to discover MCPIP's own resource identifier and the authorization server(s)
   * that issue tokens for it (RFC 8707 audience binding), so it presents a token
   * bound to THIS resource rather than a look-alike endpoint. The document carries
   * only non-secret discovery identifiers — no scopes, no secret, no topology.
   */
  async protectedResourceMetadata(opts: CallOptions = {}): Promise<ProtectedResourceMetadata> {
    return this.http.json<ProtectedResourceMetadata>({
      method: 'GET',
      path: '/.well-known/oauth-protected-resource',
      auth: false,
      signal: opts.signal,
    });
  }

  /** GET /healthz — event-loop liveness (no auth, never shed). */
  async health(opts: CallOptions = {}): Promise<HealthzInfo> {
    const res = await this.http.request({
      method: 'GET',
      path: '/healthz',
      auth: false,
      signal: opts.signal,
    });
    if (res.status !== 200) {
      throw new McpipUnavailable(`gateway /healthz answered ${res.status}`);
    }
    try {
      return (await res.json()) as HealthzInfo;
    } catch (err) {
      throw new McpipUnavailable('gateway answered /healthz with a non-JSON body', null, {
        cause: err,
      });
    }
  }

  /** GET /readyz — Redis-gated readiness. A 503 body is a real not-ready answer. */
  async ready(opts: CallOptions = {}): Promise<ReadyInfo> {
    const res = await this.http.request({
      method: 'GET',
      path: '/readyz',
      auth: false,
      signal: opts.signal,
    });
    if (res.status !== 200 && res.status !== 503) {
      throw new McpipUnavailable(`gateway /readyz answered ${res.status}`);
    }
    const body = (await res.json().catch(() => ({}))) as { redis?: unknown };
    return { ready: res.status === 200, redis: body.redis === 'up' ? 'up' : 'down' };
  }

  /** GET /v1/version — running release, signed provenance, update posture (JWT-gated). */
  async version(opts: CallOptions = {}): Promise<VersionInfo> {
    return this.http.json<VersionInfo>({
      method: 'GET',
      path: '/v1/version',
      auth: true,
      signal: opts.signal,
    });
  }

  /** GET /v1/license — the entitlement document; sandbox answers { licensed: false }. */
  async license(opts: CallOptions = {}): Promise<LicenseInfo> {
    return this.http.json<LicenseInfo>({
      method: 'GET',
      path: '/v1/license',
      auth: true,
      signal: opts.signal,
    });
  }

  /**
   * GET /v1/audit/attestation — a portable, signed snapshot of the CURRENT
   * audit state (CAP_DIRECTORY_ADMIN-gated, read-only). Available in PRODUCTION
   * (unlike the sandbox-only auditVerify/auditProof on McpipSandboxClient). It
   * requires CAP_DIRECTORY_ADMIN (the caller's JWT must carry it): the attestation
   * commits to the GLOBAL, cross-tenant WORM head, so it is not readable by a
   * plain agent token. The epoch fields are null before the first epoch is sealed;
   * the gateway mints no key and signs nothing new, so no target, payload, or
   * secret crosses the wire.
   */
  async auditAttestation(opts: CallOptions = {}): Promise<AuditAttestation> {
    return this.http.json<AuditAttestation>({
      method: 'GET',
      path: '/v1/audit/attestation',
      auth: true,
      signal: opts.signal,
    });
  }
}
