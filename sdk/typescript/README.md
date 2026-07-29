# @mcpip/sdk

Zero-dependency TypeScript client for the MCPIP authorization gateway — the
policy boundary between an autonomous agent's tool calls and the systems that
execute them.

- **ESM only, no runtime dependencies.** Global `fetch` (Node >= 18, browsers,
  workers, Deno, Bun). Ships `.js` + `.d.ts`, strict-typed.
- **Opaque by design.** A denial is a thrown `McpipDenied` carrying only the
  gateway's generic message and a `correlationId`. The SDK never guesses,
  parses, or invents a deny reason — the concrete cause exists solely in the
  gateway's WORM audit log, where an operator looks it up by that id.
- **Never retries an authorize.** A replayed step-up consume is a real
  `PIN_NOT_FOUND` deny, and every retry double-counts WORM events. One method
  call is exactly one wire call.

```bash
npm install @mcpip/sdk
```

## Quickstart (sandbox)

Start a sandbox gateway (`MCPIP_SANDBOX_MODE=true uvicorn app.main:app --port 8080`),
then:

```ts
import { McpipClient, McpipSandboxClient, McpipDenied, openaiToolCall } from '@mcpip/sdk';

const base = 'http://localhost:8080';

// SANDBOX ONLY — mints a short-lived demo JWT and re-mints ~30s before expiry.
// This endpoint answers 404 on a production gateway (see "Tokens in production").
const sandbox = new McpipSandboxClient({ baseUrl: base });
const token = sandbox.devTokenSource({ tenant_id: 'tenant-acme', agent_id: 'agent-1', role: 'ops' });

const client = new McpipClient({ baseUrl: base, token });

// The tenant-scoped catalog: aliases + metadata only, never real targets.
const catalog = await client.catalog();

// One tool call -> one authorization decision.
const result = await client.authorize({
  source_format: 'openai_tool_call',
  tool_call: openaiToolCall('skill_customer_lookup', { customer_id: 'C-1042' }),
});

if (result.status === 'allowed') {
  console.log(result.transactionRef, result.executedTargetClass, result.wormSequence);
}
```

`authorize()` resolves to a discriminated union:

| HTTP | Result                                                        |
| ---- | ------------------------------------------------------------- |
| 200  | `{ status: 'allowed', transactionRef, wormSequence, receipt, ... }` |
| 202  | `{ status: 'staged', challengeId, actionRequired, ... }` — see the PIN ceremony |
| 4xx/5xx | throws — `McpipDenied` (opaque), `McpipInvalidRequest` (422/413), `McpipUnavailable` (503/network) |

Envelope builders for every dialect: `openaiToolCall`, `anthropicToolUse`,
`geminiFunctionCall`, `bedrockToolUse`, `mcpToolsCall`, `rawMcp`, `a2aTask`. Exactly one
of `source_format` / `vendor` goes in the request (the type enforces it).

## The PIN ceremony (pin_required aliases)

High-risk aliases stage a **payload-bound, exactly-once lock** instead of
executing. Three steps, two wire calls:

```ts
// 1. STAGE — same authorize() call; a pin_required alias answers 202.
const staged = await client.authorize({
  source_format: 'openai_tool_call',
  tool_call: openaiToolCall('skill_wire_transfer', { amount: '125.00', currency: 'USD' }),
});
if (staged.status === 'staged') {
  // 2. OBTAIN THE CODE OUT-OF-BAND. Production: the enrolled authenticator
  //    device delivers it. Sandbox: this endpoint stands in for the device
  //    (same Bearer identity that staged the challenge).
  const pin = await sandbox2.authenticatorCode(staged.challengeId); // sandbox2 = McpipSandboxClient with the agent token

  // 3. CONSUME — complete() resubmits the staged request verbatim plus the code.
  const receipt = await client.complete(staged, pin);
}
```

Rules the gateway enforces (and the SDK respects):

- **Identical payload.** The lock binds tenant, agent, alias, and canonical
  arguments. Any drift is an opaque deny — but the lock survives it, so a
  correct resubmission with the same `pin` + `challengeId` still consumes.
  `staged.request` carries the exact staged request and `complete()` resubmits
  it verbatim, so the rule is structural.
- **Exactly once.** A consumed challenge is gone; replaying it is a real deny.
  This is why the SDK never auto-retries `authorize()`/`complete()`.
- **Bounded.** 6-digit code, 300-second lock TTL, 5 wrong-PIN attempts
  (`PIN_LENGTH`, `PIN_TTL_SECONDS`, `PIN_MAX_ATTEMPTS` are exported).
- **The code never crosses this channel.** The 202 carries only the
  `challengeId`; the OTP arrives out-of-band.

A lock staged on the MCP edge (`tools/call` answering `isError: true` staging
content) consumes through `authorize()` directly — `source_format:
'mcp_jsonrpc'`, the identical JSON-RPC dict as `tool_call`, plus `pin` +
`challenge_id` in the same request. The lock is format-independent.

## Denials are opaque

```ts
try {
  await client.authorize(/* ... */);
} catch (err) {
  if (err instanceof McpipDenied) {
    // err.message        -> "MCPIP: request denied by policy."  (always; never a reason)
    // err.correlationId  -> quote this to a human operator
    // err.httpStatus     -> 403 (policy), 401 (pre-parse), 500 (fail-closed), ...
  }
}
```

Expired token, unknown alias, cross-tenant reach, canary trip, quarantine,
revocation — all indistinguishable at this boundary, on purpose. Do not branch
on a deny; report the `correlationId`.

## Tokens in production

The gateway **verifies** identity; it never mints it. `POST /v1/dev/token`
does not exist outside the sandbox (404).

Your IdP/STS issues the JWT — signed **EdDSA or RS256 only**, with the eight
required claims `exp, iat, nbf, iss, aud, tenant_id, agent_id, role` (`iss` /
`aud` must match the gateway's `MCPIP_JWT_ISSUER` / `MCPIP_JWT_AUDIENCE`; the
`role` claim is descriptive and authorizes nothing). Optional authorization
claims: `compartment` (UUID), `capabilities` (UUID list — admin clients need
`CAP_DIRECTORY_ADMIN`, exported by this package), `cnf.jkt` (sender-constrained
tokens demand a DPoP proof per request — not yet implemented client-side; use
unconstrained tokens with this SDK version). `scripts/mint_principal.py` in the
gateway repo is the reference minter.

`token` accepts either form of `TokenSource`:

```ts
// (a) A verbatim string — used as-is, never refreshed (externally rotated).
new McpipClient({ baseUrl, token: process.env.MCPIP_TOKEN });

// (b) An async minter — called once, cached, and called again only when the
//     cached JWT is within 30s of its own exp claim (decoded, not verified).
//     Never called in reaction to a deny: denies are opaque, and reactive
//     re-auth would double-count every legitimate deny in the audit log.
new McpipClient({ baseUrl, token: async () => fetchJwtFromYourSts() });
```

## The MCP edge

`mcpCall()` speaks JSON-RPC 2.0 to `POST /v1/mcp` (one object per POST;
`initialize` and `notifications/*` go unauthenticated, everything else carries
the Bearer header):

```ts
await client.mcpCall('initialize', { protocolVersion: '2025-06-18', capabilities: {} });
await client.mcpCall('notifications/initialized');            // 202, resolves undefined
const { tools } = await client.mcpCall<{ tools: unknown[] }>('tools/list');
const outcome = await client.mcpCall('tools/call', { name: 'skill_customer_lookup', arguments: {} });
```

A JSON-RPC `-32000` error is a policy deny and throws the same `McpipDenied`
(correlation id from `error.data`); protocol errors throw `McpipInvalidRequest`.

## Surfaces

**`McpipClient`** — agent surface: `authorize`, `complete`, `catalog`,
`mcpCall`, `health`, `ready`, `version`, `license`, `auditAttestation` (the
production-available signed audit snapshot), `authzDecision` (OpenID-AuthZEN /
COAZ pre-execution PDP verdict), `protectedResourceMetadata` (public OAuth 2.1
RS discovery, RFC 9728 — no token).

**`McpipSandboxClient`** — sandbox-only (each route answers 404 in
production, surfaced as `McpipSandboxOnly`): `devToken`,
`devTokenSource`, `authenticatorCode`, `auditVerify`, `auditProof`.

**`McpipAdminClient`** — operator surface; the JWT's `capabilities` claim
must carry `CAP_DIRECTORY_ADMIN`, scope is always the admin's own tenant:

| Group | Methods |
| ----- | ------- |
| Skills | `skillsRegister`, `skillsDeregister`, `skillsDisable`, `skillsEnable`, `skillsDisabled`, `skillsRegistered` |
| Extensions¹ | `submitExtension`, `extensionsPending`, `extensionApprove`, `extensionReject` |
| Registry governance¹ | `verifiedPublishers`, `verifiedPublishersPut` (the reviewer-pinned publisher-namespace allow-list, X3) |
| Compliance | `complianceEvidence` (portable evidence bundle assembled from the real signed WORM attestation — **evidence, never a certification**) |
| Decisions | `decisionsRecent(limit)` |
| Principals | `principalsRevoke`, `principalsReactivate`, `principalsRevoked` |
| Tripwire | `canaries`, `quarantine` |
| Directory | `directoryGet`, `directoryPut`, `directoryRelations` (ReBAC Knowledge-Graph read) |
| Policy | `policyGet`, `policyPut`, `policyDelete` |
| Workspace | `workspaceDraft`, `workspaceValidate`, `workspaceApply` |
| Cloud IAM | `cloudEnvironmentsList`, `cloudEnvironmentsPut`, `cloudEnvironmentsDelete` |
| Vault | `vaultSecretsList`, `vaultSecretsPut`, `vaultSecretsDelete` |

All methods take a trailing `{ signal }` for `AbortSignal` cancellation.

¹ The community-extension routes gate differently from the rest of this client:
`submitExtension` (Contributor) needs only a valid, non-revoked, non-quarantined
principal — no capability; the review routes (`extensionsPending`,
`extensionApprove`, `extensionReject`) and the registry-governance routes
(`verifiedPublishers`, `verifiedPublishersPut`) demand `CAP_CATALOG_REVIEWER` (DISTINCT
from `CAP_DIRECTORY_ADMIN`, exported by this package). A `gate` manifest can be
submitted and stored PENDING but never approved/enforced until the deferred CEL
engine is registered — a pending gate row reports `approvable: false`.

## Errors

| Class | Meaning | Carries |
| ----- | ------- | ------- |
| `McpipDenied` | Opaque policy/auth/internal denial (403/401/500, JSON-RPC -32000) | `correlationId`, `httpStatus` |
| `McpipInvalidRequest` | Malformed envelope (422), body too large (413), JSON-RPC protocol error | `correlationId`, `httpStatus` |
| `McpipUnavailable` | Unreachable, non-gateway answer, or 503 shed | `retryAfterSeconds` |
| `McpipSandboxOnly` | Sandbox-only route answered 404 (production, or unknown/expired resource) | `endpoint` |

All extend `McpipError`.

## Smoke test

`smoke.mjs` runs the whole lifecycle against a live sandbox gateway and exits
nonzero on any failure — dev-token mint, catalog, auto-tier authorize, the
full PIN ceremony through the sandbox authenticator, opaque-deny assertions,
and the admin canary/quarantine rosters:

```bash
npx tsc -p tsconfig.json          # build dist/
MCPIP_BASE=http://localhost:8080 node smoke.mjs
```

## Build

```bash
npm install        # dev dependency: typescript only
npm run build      # tsc -> dist/
npm run typecheck
```
