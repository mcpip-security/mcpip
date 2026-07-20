#!/usr/bin/env node
/* ---------------------------------------------------------------------------
   @mcpip/sdk — end-to-end smoke against a LIVE sandbox gateway.

   Run:   node smoke.mjs                     (gateway on http://localhost:8080)
          MCPIP_BASE=http://host:port node smoke.mjs
   Prereq: dist/ built (npx tsc -p tsconfig.json) and a sandbox gateway up
          (MCPIP_SANDBOX_MODE=true uvicorn app.main:app --port 8080).

   Every step is a REAL wire call — nothing mocked: dev-token mint -> catalog
   -> auto-tier authorize -> full PIN ceremony via the sandbox authenticator
   -> opaque-deny assertions -> admin canary/quarantine rosters. Exits nonzero
   on the first failure. Each run mints fresh agent ids so a previous run's
   state can never bleed in, and the admin canary roster is fetched BEFORE any
   alias pick so the smoke never trips the tripwire on its own tenant.
--------------------------------------------------------------------------- */

import { randomUUID } from 'node:crypto';

let sdk;
try {
  sdk = await import(new URL('./dist/index.js', import.meta.url).href);
} catch (err) {
  console.error('dist/ is not built — run `npx tsc -p tsconfig.json` first.');
  console.error(String(err instanceof Error ? err.message : err));
  process.exit(1);
}

const {
  AGENT_FACING_DENY_MESSAGE,
  CAP_DIRECTORY_ADMIN,
  McpipAdminClient,
  McpipClient,
  McpipDenied,
  McpipSandboxClient,
  McpipUnavailable,
  McpipSandboxOnly,
  openaiToolCall,
} = sdk;

const BASE = (process.env.MCPIP_BASE ?? 'http://localhost:8080').replace(/\/+$/, '');

let checks = 0;
function assert(cond, label) {
  if (!cond) {
    throw new Error(`assertion failed: ${label}`);
  }
  checks += 1;
  console.log(`  ok  ${label}`);
}
function section(title) {
  console.log(`\n${title}`);
}

async function main() {
  console.log(`@mcpip/sdk smoke — gateway ${BASE}`);

  section('reachability');
  const probe = new McpipClient({ baseUrl: BASE });
  let live;
  try {
    live = await probe.health();
  } catch (err) {
    if (err instanceof McpipUnavailable) {
      console.error(`no gateway answered ${BASE}/healthz`);
      console.error('start a sandbox gateway first:');
      console.error('  MCPIP_SANDBOX_MODE=true uvicorn app.main:app --port 8080');
      console.error('then re-run (MCPIP_BASE overrides the target).');
    }
    throw err;
  }
  assert(live.status === 'live', '/healthz answers status=live');
  const readiness = await probe.ready();
  assert(readiness.ready === true && readiness.redis === 'up', '/readyz reports ready (redis up)');

  section('sandbox identity mint');
  const run = randomUUID().replace(/-/g, '').slice(0, 8);
  const agentId = `agent-sdk-smoke-${run}`;
  const anon = new McpipSandboxClient({ baseUrl: BASE });
  const agentJwt = await anon.devToken({ tenant_id: 'tenant-acme', agent_id: agentId, role: 'ops' });
  assert(agentJwt.split('.').length === 3, 'dev token minted for the agent identity');
  const adminJwt = await anon.devToken({
    tenant_id: 'tenant-acme',
    agent_id: `agent-sdk-smoke-admin-${run}`,
    role: 'ops',
    capabilities: [CAP_DIRECTORY_ADMIN],
  });
  assert(adminJwt.split('.').length === 3, 'dev token minted with CAP_DIRECTORY_ADMIN');

  const client = new McpipClient({ baseUrl: BASE, token: agentJwt });
  const sandbox = new McpipSandboxClient({ baseUrl: BASE, token: agentJwt });
  const admin = new McpipAdminClient({ baseUrl: BASE, token: adminJwt });

  section('admin canary roster (fetched first so alias picks never touch bait)');
  const canaries = await admin.canaries();
  assert(
    Array.isArray(canaries) && canaries.every((c) => typeof c.alias === 'string'),
    'GET /v1/admin/canaries answers the decoy roster',
  );
  assert(canaries.length >= 1, 'sandbox tenant has at least one seeded canary decoy');
  const bait = new Set(canaries.map((c) => c.alias));

  section('catalog');
  const items = await client.catalog();
  assert(items.length > 0, 'catalog enumerates aliases for the minted identity');
  assert(
    items.every((i) => typeof i.alias === 'string' && typeof i.risk_tier === 'string'),
    'catalog rows carry alias + risk_tier metadata',
  );
  assert(
    items.every((i) => !('target' in i) && !('canary' in i)),
    'catalog leaks neither targets nor the canary flag',
  );

  section('authorize — auto tier');
  const autoItem = items.find((i) => i.risk_tier === 'auto' && !bait.has(i.alias));
  assert(autoItem !== undefined, 'an auto-tier non-canary alias exists to call');
  const happy = await client.authorize({
    source_format: 'openai_tool_call',
    tool_call: openaiToolCall(autoItem.alias, { query: 'sdk-smoke', run_id: run }),
  });
  assert(happy.status === 'allowed', `authorize(${autoItem.alias}) is allowed`);
  assert(happy.receipt.status === 'committed', 'receipt status is committed');
  assert(happy.transactionRef.startsWith('txn_'), 'receipt carries a transaction ref');
  assert(
    Number.isInteger(happy.wormSequence) && happy.wormSequence > 0,
    'receipt anchors a WORM sequence',
  );

  section('PIN ceremony — stage, sandbox authenticator, identical-payload consume');
  const pinItem = items.find((i) => i.risk_tier === 'pin_required' && !bait.has(i.alias));
  assert(pinItem !== undefined, 'a pin_required non-canary alias exists to stage');
  // The staged result carries the request; complete() resubmits it verbatim —
  // the payload-bound lock demands identical tenant/agent/alias/arguments.
  const staged = await client.authorize({
    source_format: 'openai_tool_call',
    tool_call: openaiToolCall(pinItem.alias, { amount: '125.00', memo: `sdk-smoke-${run}` }),
  });
  assert(staged.status === 'staged', `authorize(${pinItem.alias}) stages a challenge (202)`);
  assert(staged.challengeId.length > 0, '202 carries a challenge id');
  assert(staged.riskTier === 'pin_required', '202 carries risk_tier pin_required');
  assert(staged.actionRequired.length > 0, '202 instructs the step-up');
  const pin = await sandbox.authenticatorCode(staged.challengeId);
  assert(/^\d{6}$/.test(pin), 'sandbox authenticator delivers a 6-digit one-time code');
  const receipt = await client.complete(staged, pin);
  assert(receipt.status === 'allowed', 'identical-payload consume commits the call');
  assert(receipt.wormSequence > happy.wormSequence, 'WORM sequence advanced monotonically');

  section('opaque deny — unknown alias');
  let denied = null;
  try {
    await client.authorize({
      source_format: 'openai_tool_call',
      tool_call: openaiToolCall(`skill_does_not_exist_${run}`, {}),
    });
  } catch (err) {
    denied = err;
  }
  assert(denied instanceof McpipDenied, 'unknown alias throws McpipDenied');
  assert(denied.httpStatus === 403, 'deny is HTTP 403');
  assert(
    typeof denied.correlationId === 'string' &&
      denied.correlationId.length > 0 &&
      denied.correlationId !== 'unknown',
    'deny carries a real correlation id',
  );
  assert(denied.message === AGENT_FACING_DENY_MESSAGE, 'deny message is the byte-exact opaque text');
  assert(
    Object.keys(denied).every((k) => !k.toLowerCase().includes('reason')),
    'deny object exposes no reason field',
  );

  section('admin quarantine roster');
  const frozen = await admin.quarantine();
  assert(Array.isArray(frozen), 'GET /v1/admin/quarantine answers the freeze roster');
  assert(
    frozen.every(
      (q) => typeof q.agent_id === 'string' && (q.ttl_seconds === null || typeof q.ttl_seconds === 'number'),
    ),
    'quarantine rows carry agent_id + ttl_seconds',
  );
  assert(
    !frozen.some((q) => q.agent_id === agentId),
    'the smoke agent never tripped a canary (not quarantined)',
  );

  section('admin deployment / license & usage stats (local live numbers)');
  const stats = await admin.stats();
  assert(
    typeof stats.governed_agent_identity_count === 'number' && stats.governed_agent_identity_count >= 0,
    'GET /v1/admin/stats answers a governed-agent identity cardinality (an integer)',
  );
  assert(
    typeof stats.decisions.allow === 'number' &&
      typeof stats.decisions.deny === 'number' &&
      typeof stats.decisions.staged === 'number',
    'stats carry the closed {allow,deny,staged} decision totals',
  );
  assert(typeof stats.license.licensed === 'boolean', 'stats carry the honest license posture');
  assert(
    stats.telemetry.status === 'air-gap' ||
      stats.telemetry.status === 'enabled' ||
      stats.telemetry.status === 'disabled',
    'stats carry the honest opt-in telemetry status (air-gap/enabled/disabled — never a fabricated "connected")',
  );
  // The privacy boundary at the read edge: only aggregate integers cross it.
  assert(
    !Object.prototype.hasOwnProperty.call(stats, 'tenant_id') &&
      !Object.prototype.hasOwnProperty.call(stats, 'agent_id'),
    'stats expose no tenant/agent identifier — only the caller-tenant aggregates',
  );
  // Honest dark-feature posture: sandbox defaults forensic capture ON, external PDP off.
  assert(
    stats.features?.forensic_capture.status === 'enabled' &&
      stats.features?.external_pdp.status === 'off',
    'stats carry the honest features posture (forensic_capture + external_pdp) — never a fabricated live state',
  );
  const featBlob = JSON.stringify(stats.features);
  assert(
    !featBlob.includes('http://') && !featBlob.includes('https://') && !featBlob.includes('.key'),
    'features posture carries no url/key-path — coarse, deployment-wide posture only',
  );

  console.log(`\nSMOKE PASSED — ${checks} checks against ${BASE}`);
}

main().catch((err) => {
  console.error(`\nSMOKE FAILED after ${checks} passing checks`);
  console.error(err instanceof Error ? `${err.name}: ${err.message}` : String(err));
  if (err instanceof McpipDenied) {
    console.error(
      `correlation_id=${err.correlationId} — the concrete reason is in the gateway's WORM log`,
    );
  }
  if (err instanceof McpipSandboxOnly) {
    console.error(`the gateway at ${BASE} is not in sandbox mode; the smoke needs one:`);
    console.error('  MCPIP_SANDBOX_MODE=true uvicorn app.main:app --port 8080');
  }
  process.exit(1);
});
