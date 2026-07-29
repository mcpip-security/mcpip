/* ---------------------------------------------------------------------------
   @mcpip/sdk — public surface.

   Three clients over one wire-protocol core:
     McpipClient        — agent surface (authorize/complete/catalog/mcpCall/
                          health/ready/version/license/auditAttestation)
     McpipSandboxClient — sandbox-only affordances (devToken/authenticatorCode/
                          auditVerify/auditProof); each 404s in production
     McpipAdminClient   — CAP_DIRECTORY_ADMIN operator surface

   Denials are thrown, never returned: McpipDenied carries only the opaque
   wire message and a correlation id, mirroring the gateway's boundary.
--------------------------------------------------------------------------- */

export {
  McpipClient,
  TOKEN_EXP_SLACK_MS,
  openaiToolCall,
  anthropicToolUse,
  geminiFunctionCall,
  bedrockToolUse,
  mcpToolsCall,
  rawMcp,
  a2aTask,
} from './client.js';
export type { CallOptions, McpipClientOptions, TokenSource } from './client.js';

export { McpipSandboxClient } from './sandbox.js';
export { McpipAdminClient } from './admin.js';

export {
  McpipError,
  McpipDenied,
  McpipInvalidRequest,
  McpipUnavailable,
  McpipSandboxOnly,
} from './errors.js';

export * from './types.js';
