/* ---------------------------------------------------------------------------
   Shared configuration for the MCPIP k6 load suite.

   Every scenario in this directory is organised BY CLIENT TYPE, because that is
   the axis along which MCPIP's behaviour actually differs: an agent proposes tool
   calls, a developer integrates through one of five surfaces, an operator reads
   the admin plane, an auditor reads signed evidence, and a PDP consumer asks for
   a verdict that executes nothing. Mixing them into one "requests/sec" number
   hides the thing you need to know — which surface degrades first, and whether
   attribution stays clean when they run together.

   Tokens are supplied by the harness, never minted here: MCPIP never issues
   identity, so a load test must not either. Point BASE at a gateway you own.
--------------------------------------------------------------------------- */

export const BASE = __ENV.MCPIP_BASE || 'http://127.0.0.1:8080';

/** Bearer per client type. All are required by the scenarios that use them. */
export const TOKENS = {
  agent: __ENV.MCPIP_AGENT_TOKEN || '',
  developer: __ENV.MCPIP_DEV_TOKEN || '',
  operator: __ENV.MCPIP_ADMIN_TOKEN || '',
  auditor: __ENV.MCPIP_AUDITOR_TOKEN || '',
};

/** Aliases the suite exercises, by the outcome each is expected to produce. */
export const ALIASES = {
  // auto-tier reads: the only calls that should return 200
  allow: (__ENV.MCPIP_ALLOW_ALIASES || 'cf.d1.databases.list,gh.branches.list,gh.pr.list').split(','),
  // pin_required: must NEVER return 200 without a completed step-up
  staged: (__ENV.MCPIP_STAGED_ALIASES || 'cf.d1.query,gh.repo.delete').split(','),
  // never registered: must always deny
  unknown: (__ENV.MCPIP_UNKNOWN_ALIASES || 'gh.secrets.exfiltrate,cf.kv.nuke').split(','),
};

export function authHeaders(token) {
  return { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' };
}

/**
 * Thresholds are CORRECTNESS-FIRST on purpose.
 *
 * A load test for an authorization gateway that only measures latency is measuring
 * the wrong thing: a gateway that gets fast by letting a pin_required call through
 * has failed, not improved. So the hard gates are behavioural — no unauthorized
 * allow, ever — and latency is a budget on top.
 */
export const THRESHOLDS = {
  // Behavioural invariants — any breach fails the run.
  'checks{kind:invariant}': ['rate==1.0'],
  // Latency budget. Generous by default; tighten per environment.
  http_req_duration: ['p(95)<1500'],
  // A transport error is not a deny — it is the harness failing to ask the question.
  http_req_failed: ['rate<0.05'],
};
