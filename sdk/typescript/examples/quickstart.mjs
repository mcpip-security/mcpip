/* ---------------------------------------------------------------------------
   @mcpip/sdk quickstart — the full agent lifecycle against a sandbox gateway.

   Prereq:  MCPIP_SANDBOX_MODE=true uvicorn app.main:app --port 8080
   Run:     node examples/quickstart.mjs        (after: npx tsc -p tsconfig.json)

   Installed usage imports from the package instead:
     import { McpipClient, McpipSandboxClient, McpipDenied, openaiToolCall } from '@mcpip/sdk';
--------------------------------------------------------------------------- */

import {
  McpipClient,
  McpipSandboxClient,
  McpipDenied,
  openaiToolCall,
} from '../dist/index.js';

const BASE = (process.env.MCPIP_BASE ?? 'http://localhost:8080').replace(/\/+$/, '');

// SANDBOX ONLY: /v1/dev/token answers 404 on a production gateway, where your
// own IdP mints the JWT — pass that token (or an async minter hitting your
// STS) as the `token` option instead. devTokenSource re-mints ~30s before
// each short-lived sandbox token expires.
const sandbox = new McpipSandboxClient({ baseUrl: BASE });
const token = sandbox.devTokenSource({
  tenant_id: 'tenant-acme',
  agent_id: 'agent-quickstart',
  role: 'ops',
});

const client = new McpipClient({ baseUrl: BASE, token });
const authenticator = new McpipSandboxClient({ baseUrl: BASE, token });

// 1. What may this identity even name? Metadata only — real targets never
//    cross this boundary.
const catalog = await client.catalog();
console.log('catalog:');
for (const item of catalog) {
  console.log(`  ${item.alias}  [${item.risk_tier}]`);
}

// 2. An auto-tier call: one POST /v1/authorize -> committed receipt.
//    skill_customer_lookup is a default sandbox-catalog row. (Don't pick
//    blindly by tier in the sandbox: some rows are canary decoys, and
//    touching one quarantines the caller — that is the point of them.)
const lookup = await client.authorize({
  source_format: 'openai_tool_call',
  tool_call: openaiToolCall('skill_customer_lookup', { customer_id: 'C-1042' }),
});
if (lookup.status === 'allowed') {
  console.log(`\nallowed: ${lookup.transactionRef} via ${lookup.executedTargetClass}`);
}

// 3. The PIN ceremony on a pin_required alias. The staged result carries the
//    request, and complete() resubmits it verbatim — the payload-bound lock
//    demands an identical consume.
const staged = await client.authorize({
  source_format: 'openai_tool_call',
  tool_call: openaiToolCall('skill_wire_transfer', { amount: '125.00', currency: 'USD' }),
});
if (staged.status === 'staged') {
  console.log(`\nstaged: challenge ${staged.challengeId}`);
  // Out-of-band in production (enrolled authenticator); in the sandbox this
  // endpoint stands in for the device.
  const pin = await authenticator.authenticatorCode(staged.challengeId);
  const committed = await client.complete(staged, pin);
  console.log(`committed after step-up: ${committed.transactionRef}`);
}

// 4. Denials are opaque BY DESIGN: a typed error with a correlation id and
//    the generic message — never a reason. The reason lives in the WORM log,
//    where an operator can look it up by this id.
try {
  await client.authorize({
    source_format: 'openai_tool_call',
    tool_call: openaiToolCall('skill_no_such_alias', {}),
  });
} catch (err) {
  if (err instanceof McpipDenied) {
    console.log(`\ndenied (opaque): "${err.message}" correlation_id=${err.correlationId}`);
  } else {
    throw err;
  }
}
