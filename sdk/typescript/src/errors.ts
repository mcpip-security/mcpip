/* ---------------------------------------------------------------------------
   @mcpip/sdk — the typed error family.

   Mirrors the gateway's fail-closed voice: a denial carries ONLY the opaque
   wire message and a correlation id. The SDK never guesses, parses, or
   attaches a deny reason — the concrete cause exists solely in the WORM log,
   where an operator can look it up by the correlation id the agent quotes.
--------------------------------------------------------------------------- */

import { AGENT_FACING_DENY_MESSAGE } from './types.js';

/** Base class for every error the SDK throws (instanceof-able as a family). */
export abstract class McpipError extends Error {}

/**
 * A policy denial (403), pre-parse rejection (401), unexpected server failure
 * (500), or any other opaque non-2xx. `message` is the wire's generic text —
 * never a reason. `correlationId` is the only handle worth quoting to a human
 * operator; `httpStatus` is the raw status for callers that must branch.
 *
 * On the MCP edge a deny arrives as JSON-RPC error -32000 over HTTP 200; it
 * is normalized into this same class (correlation id from `error.data`).
 */
export class McpipDenied extends McpipError {
  readonly correlationId: string;
  readonly httpStatus: number;

  constructor(correlationId: string, httpStatus: number, message: string = AGENT_FACING_DENY_MESSAGE) {
    super(message);
    this.name = 'McpipDenied';
    this.correlationId = correlationId;
    this.httpStatus = httpStatus;
  }
}

/**
 * The envelope itself was malformed (422 strict-ingress rejection, 413 body
 * too large) or a JSON-RPC protocol error (-32700/-32600/-32601/-32602) came
 * back from the MCP edge. Fix the request; retrying the same bytes cannot
 * succeed.
 */
export class McpipInvalidRequest extends McpipError {
  readonly correlationId: string | null;
  readonly httpStatus: number;

  constructor(message: string, correlationId: string | null, httpStatus: number) {
    super(message);
    this.name = 'McpipInvalidRequest';
    this.correlationId = correlationId;
    this.httpStatus = httpStatus;
  }
}

/**
 * The gateway could not be reached, answered with a non-JSON body (something
 * that is not the gateway is listening), or shed the request (503 admission
 * control / timeout). `retryAfterSeconds` mirrors the Retry-After header when
 * the gateway sent one. Note: the SDK itself NEVER retries POST /v1/authorize
 * — honoring Retry-After is the caller's decision, and only for reads.
 */
export class McpipUnavailable extends McpipError {
  readonly retryAfterSeconds: number | null;

  constructor(message: string, retryAfterSeconds: number | null = null, options?: ErrorOptions) {
    super(message, options);
    this.name = 'McpipUnavailable';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * A sandbox-only endpoint answered 404. In production these routes refuse to
 * exist by design: identity is IdP-sovereign (/v1/dev/token), one-time codes
 * arrive only out-of-band (/v1/authenticator), and audit verification runs in
 * the external verifier (/v1/audit/*). On a sandbox gateway a 404 from the
 * authenticator/proof routes can also mean the specific resource is unknown,
 * expired, or not yet sealed — `detail` says which reading applies.
 */
export class McpipSandboxOnly extends McpipError {
  readonly endpoint: string;

  constructor(endpoint: string, detail?: string) {
    super(
      `${endpoint} answered 404 — this endpoint exists only on a sandbox gateway ` +
        `(MCPIP_SANDBOX_MODE=true)${detail ? `; ${detail}` : ''}`,
    );
    this.name = 'McpipSandboxOnly';
    this.endpoint = endpoint;
  }
}
