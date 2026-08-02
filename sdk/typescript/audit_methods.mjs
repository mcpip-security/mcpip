import { McpipClient, McpipSandboxClient, McpipAdminClient } from './dist/index.js';

const proto = (C) => {
  const out = new Set();
  let p = C.prototype;
  while (p && p !== Object.prototype) { Object.getOwnPropertyNames(p).forEach(n => n !== 'constructor' && out.add(n)); p = Object.getPrototypeOf(p); }
  return out;
};
const all = new Set([...proto(McpipClient), ...proto(McpipSandboxClient), ...proto(McpipAdminClient)]);

// SDK.md section 10, verbatim list
const doc = ['authorize','complete','catalog','mcpCall','health','ready','version','license',
  'auditAttestation','authzDecision','protectedResourceMetadata',
  'devToken','authenticatorCode','auditVerify','auditProof',
  'registerSkill','deregisterSkill','disableSkill','enableSkill','registeredSkills',
  'disabledSkills','decisionsRecent','forensicGet','revokePrincipal','reactivatePrincipal',
  'revokedPrincipals','quarantine','canaries','directoryGet','directoryPut','directoryRelations',
  'workspaceDraft','workspaceValidate','workspaceApply','cloudEnvironments','cloudEnvironmentPut',
  'cloudEnvironmentDelete','vaultSecrets','vaultSecretPut','vaultSecretDelete'];

const missing = doc.filter(m => !all.has(m));
console.log(`SDK.md section 10 lists ${doc.length} TS methods; ${missing.length} DO NOT EXIST:`);
missing.forEach(m => console.log('  MISSING:', m));
console.log('\nActual admin methods:', [...proto(McpipAdminClient)].sort().join(', '));
