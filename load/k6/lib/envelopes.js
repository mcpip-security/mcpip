/* ---------------------------------------------------------------------------
   Wire envelopes, per client type.

   MCPIP takes the dialect as a DECLARED field and never sniffs it from the bytes,
   so a load test has to declare it too. These builders produce the same shapes a
   real client emits, which is the point: a synthetic body that skips the bridge's
   deep validation would measure a path production never takes.
--------------------------------------------------------------------------- */

let seq = 0;
function nextId() {
  seq += 1;
  return seq;
}

/** MCP JSON-RPC 2.0 tools/call — what an MCP host (Claude Code, Cursor, …) sends. */
export function mcpToolCall(alias, args = {}) {
  return {
    vendor: 'claude_code',
    tool_call: {
      jsonrpc: '2.0',
      id: nextId(),
      method: 'tools/call',
      params: { name: alias, arguments: args },
    },
  };
}

/** The MCP-native edge: the gateway itself answering as an MCP server. */
export function mcpNative(method, params = {}) {
  return { jsonrpc: '2.0', id: nextId(), method, params };
}

/**
 * AuthZEN decision request — MCPIP as a PDP.
 *
 * `subject` is echo-only and NEVER consulted for identity (that comes from the JWT),
 * so this deliberately sends a subject the gateway must ignore: if identity injection
 * were ever possible, this scenario would surface it as an attribution mismatch.
 */
export function authzenDecision(alias, args = {}) {
  return {
    subject: { type: 'agent', id: 'load-harness-should-be-ignored' },
    resource: { type: 'skill', id: alias },
    action: { name: 'invoke', properties: args },
  };
}
