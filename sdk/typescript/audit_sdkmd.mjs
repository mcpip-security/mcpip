// Exactly the names docs/start/SDK.md gives for TypeScript.
import * as sdk from './dist/index.js';

const documented = {
  'section 1 clients': ['MCPIPClient', 'SandboxClient', 'MCPIPAdminClient'],
  'section 9 errors': ['MCPIPDeniedError', 'MCPIPInvalidRequestError',
                       'MCPIPUnavailableError', 'MCPIPNotFoundError',
                       'MCPIPSandboxOnlyError'],
};
for (const [where, names] of Object.entries(documented)) {
  for (const n of names) {
    console.log(`${where}: ${n} -> ${typeof sdk[n] === 'undefined' ? 'UNDEFINED (not exported)' : 'ok'}`);
  }
}
console.log('\nACTUAL top-level exports:');
console.log(Object.keys(sdk).sort().join(', '));
