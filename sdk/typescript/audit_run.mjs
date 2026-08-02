import { McpipClient, McpipSandboxClient, McpipAdminClient, McpipDenied,
         CAP_DIRECTORY_ADMIN, openaiToolCall, rawMcp } from './dist/index.js';
const base = 'http://127.0.0.1:8080';

const sandbox = new McpipSandboxClient({ baseUrl: base });
const token = sandbox.devTokenSource({ tenant_id: 'tenant-acme', agent_id: 'agent-ts', role: 'ops' });
const client = new McpipClient({ baseUrl: base, token });

console.log('catalog:', (await client.catalog()).map(c => c.alias).join(','));

// SDK.md section 3 shows: client.authorize("skill_spend_summary", {"period":"2026-Q2"})
// SDK.md line 16: "expose the same surface with the same method names". Try it in TS:
try {
  const r = await client.authorize('skill_spend_summary', { period: '2026-Q2' });
  console.log('positional authorize:', r.status);
} catch (e) {
  console.log('positional authorize (SDK.md section 3 form) ->', e.constructor.name + ':', e.message);
}

// The form that actually works (per sdk/typescript/README.md):
const ok = await client.authorize({ source_format: 'raw_mcp', tool_call: rawMcp('skill_spend_summary', { period: '2026-Q2' }) });
console.log('object authorize:', ok.status, ok.transactionRef, ok.executedTargetClass, ok.wormSequence);

// section 6 auditAttestation: SDK.md says Auth = "JWT"
try { console.log('auditAttestation(agent token):', await client.auditAttestation()); }
catch (e) { console.log('auditAttestation(agent token) ->', e.constructor.name, e.httpStatus, e.message); }

// MCP edge + PIN ceremony
console.log('initialize:', JSON.stringify(await client.mcpCall('initialize')));
const staged = await client.authorize({ source_format: 'raw_mcp', tool_call: rawMcp('skill_payroll_run', { run_id: 'PR-9' }) });
console.log('staged:', staged.status, staged.challengeId, staged.expiresIn ?? staged.expires_in);
const sb2 = new McpipSandboxClient({ baseUrl: base, token });
const pin = await sb2.authenticatorCode(staged.challengeId);
const receipt = await client.complete(staged, pin);
console.log('complete:', receipt.status, receipt.wormSequence);

// admin
const adminTok = await sandbox.devToken({ agent_id: 'agent-admin-ts', role: 'admin', capabilities: [CAP_DIRECTORY_ADMIN] });
const admin = new McpipAdminClient({ baseUrl: base, token: adminTok });
console.log('skillsRegistered:', JSON.stringify(await admin.skillsRegistered()));
console.log('canaries:', (await admin.canaries()).map(c => c.alias).join(','));
