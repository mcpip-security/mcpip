/* ---------------------------------------------------------------------------
   @mcpip/sdk — the sandbox-only surface.

   Every method here targets an endpoint that answers 404 on a production
   gateway BY DESIGN: identity is IdP-sovereign (the gateway never mints it),
   one-time codes arrive only out-of-band from the enrolled authenticator, and
   chain verification belongs to the external verifier. A production 404 is
   surfaced as McpipSandboxOnly — never silently faked.
--------------------------------------------------------------------------- */

import { GatewayHttp, type CallOptions, type McpipClientOptions } from './client.js';
import { McpipUnavailable } from './errors.js';
import type { AuditVerifyResult, DevTokenClaims, InclusionProof } from './types.js';

export class McpipSandboxClient {
  private readonly http: GatewayHttp;

  constructor(options: McpipClientOptions = {}) {
    this.http = new GatewayHttp(options);
  }

  /** The resolved gateway origin this client talks to. */
  get baseUrl(): string {
    return this.http.baseUrl;
  }

  /**
   * POST /v1/dev/token — mint a demo EdDSA JWT via the in-process demo IdP
   * (iss 'mcpip-demo-idp', aud 'mcpip-gateway', exp = iat + ~300s). No auth.
   * An empty claims object mints the default sandbox identity. Production
   * gateways answer 404 — supply a real IdP token there instead.
   */
  async devToken(claims: DevTokenClaims = {}, opts: CallOptions = {}): Promise<string> {
    const body = await this.http.json<{ jwt?: unknown; token?: unknown }>(
      { method: 'POST', path: '/v1/dev/token', auth: false, body: claims, signal: opts.signal },
      'POST /v1/dev/token',
      'production identity is IdP-sovereign — set a real IdP JWT as the token option',
    );
    // Current gateways answer { jwt }; tolerate the legacy { token } key.
    const jwt =
      typeof body.jwt === 'string' ? body.jwt : typeof body.token === 'string' ? body.token : null;
    if (jwt === null) {
      throw new McpipUnavailable('dev token response carried no jwt');
    }
    return jwt;
  }

  /**
   * A TokenSource for McpipClientOptions.token that re-mints these claims
   * ~30s before each token's exp (sandbox tokens live ~5 minutes). SANDBOX
   * ONLY — a long-running client should use this instead of one static mint.
   */
  devTokenSource(claims: DevTokenClaims = {}): () => Promise<string> {
    return () => this.devToken(claims);
  }

  /**
   * GET /v1/authenticator/{challenge_id} — the sandbox stand-in for the
   * enrolled authenticator device delivering the one-time code. JWT-gated:
   * the OTP is tenant-scoped, so call with the SAME identity that staged the
   * challenge. In production the code arrives only out-of-band and this
   * endpoint 404s, exactly like the real delivery channel it stands in for.
   */
  async authenticatorCode(challengeId: string, opts: CallOptions = {}): Promise<string> {
    const body = await this.http.json<{ otp?: unknown }>(
      {
        method: 'GET',
        path: `/v1/authenticator/${encodeURIComponent(challengeId)}`,
        auth: true,
        signal: opts.signal,
      },
      'GET /v1/authenticator/{challenge_id}',
      'on a sandbox gateway a 404 also means the challenge is unknown or its code expired',
    );
    if (typeof body.otp !== 'string') {
      throw new McpipUnavailable('authenticator response carried no otp');
    }
    return body.otp;
  }

  /**
   * GET /v1/audit/verify — force an epoch close, then verify the signed
   * Merkle-epoch chain end-to-end. JWT-gated. Production gateways 404 (run
   * the external `mcpip` verifier against the exported WORM file instead).
   */
  async auditVerify(opts: CallOptions = {}): Promise<AuditVerifyResult> {
    return this.http.json<AuditVerifyResult>(
      { method: 'GET', path: '/v1/audit/verify', auth: true, signal: opts.signal },
      'GET /v1/audit/verify',
      'production chains are verified externally with the mcpip console verifier',
    );
  }

  /**
   * GET /v1/audit/proof/{event_id} — the O(log n) inclusion proof binding one
   * WORM event to a signed epoch root. JWT-gated.
   */
  async auditProof(eventId: string, opts: CallOptions = {}): Promise<InclusionProof> {
    return this.http.json<InclusionProof>(
      {
        method: 'GET',
        path: `/v1/audit/proof/${encodeURIComponent(eventId)}`,
        auth: true,
        signal: opts.signal,
      },
      'GET /v1/audit/proof/{event_id}',
      'on a sandbox gateway a 404 also means the event is unknown or not yet sealed into an epoch',
    );
  }
}
