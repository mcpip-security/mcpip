/* ---------------------------------------------------------------------------
   MCPIP load profile — BY CLIENT TYPE, all types concurrently.

     k6 run load/k6/by-client-type.js

   Five client types share one gateway, each with its own arrival rate, so the
   result answers the question a single aggregate number cannot: which surface
   degrades first, and does correctness hold while they contend?

     agent      MCP JSON-RPC tools/call  -> POST /v1/authorize
     developer  raw HTTP + MCP-native    -> POST /v1/authorize, POST /v1/mcp
     operator   admin plane              -> GET  /v1/admin/decisions/recent, /v1/admin/stats
     auditor    signed evidence          -> GET  /v1/audit/attestation
     pdp        AuthZEN verdict          -> POST /v1/authz/decision  (executes nothing)

   THE HARD GATES ARE BEHAVIOURAL. Latency is a budget; correctness is a wall. A
   pin_required alias returning 200 under load, or an unregistered alias being
   allowed, fails the run no matter how fast it was — a gateway that gets quick by
   skipping the risk gate has not improved, it has broken. Those checks are tagged
   {kind:invariant} and thresholded at rate==1.0.
--------------------------------------------------------------------------- */

import http from 'k6/http';
import { check } from 'k6';
import { Counter, Trend } from 'k6/metrics';
import { BASE, TOKENS, ALIASES, authHeaders, THRESHOLDS } from './lib/config.js';
import { mcpToolCall, mcpNative, authzenDecision } from './lib/envelopes.js';

/**
 * A DENY IS A CORRECT ANSWER, AND SO IS A SHED — NEITHER IS A FAILED REQUEST.
 *
 * By default k6 counts any non-2xx as `http_req_failed`, which for an authorization
 * gateway is exactly backwards: most of this suite deliberately asks questions whose
 * right answer is 403 (unregistered alias) or 202 (staged for step-up). Left alone,
 * `http_req_failed` measures how much policy the gateway enforced and reports it as
 * breakage.
 *
 * 503 belongs in this set too, and omitting it produced a materially wrong result the
 * first time this suite ran. MCPIP has a DESIGNED load shedder: past
 * `MCPIP_MAX_IN_FLIGHT` a new arrival gets an opaque 503 + Retry-After, and the limiter
 * "only ever REJECTS or TIMES OUT — it never lets a request skip a gate"
 * (app/main.py:2457-2464). Counting that as failure reported a gateway shedding load
 * exactly as specified as a gateway falling over. Measured directly at 250 concurrent
 * clients against max_in_flight=64: 98.5% allowed, 1.5% shed with 503 + Retry-After: 1,
 * ZERO timeouts, ZERO refused connections.
 *
 * What is left in `http_req_failed` is what should be there: the harness never got an
 * answer at all.
 */
http.setResponseCallback(http.expectedStatuses(200, 202, 403, 409, 503));

/** Shed responses, counted separately so "correctly shed" never hides inside "failed". */
const shedCounter = new Counter('mcpip_shed_503');

/** Per-client-type latency, so one slow surface cannot hide inside the aggregate. */
const lat = {
  agent: new Trend('mcpip_latency_agent', true),
  developer: new Trend('mcpip_latency_developer', true),
  operator: new Trend('mcpip_latency_operator', true),
  auditor: new Trend('mcpip_latency_auditor', true),
  pdp: new Trend('mcpip_latency_pdp', true),
};
const decisions = new Counter('mcpip_decisions');
const staged = new Counter('mcpip_staged');
const denied = new Counter('mcpip_denied');

const RATE = Number(__ENV.MCPIP_RATE || 50); // per-second base, scaled per type
const DUR = __ENV.MCPIP_DURATION || '30s';

function scenario(exec, rate, extra = {}) {
  return {
    executor: 'constant-arrival-rate',
    rate,
    timeUnit: '1s',
    duration: DUR,
    preAllocatedVUs: Math.max(5, Math.ceil(rate / 2)),
    maxVUs: Math.max(20, rate * 4),
    exec,
    ...extra,
  };
}

export const options = {
  scenarios: {
    // Agents are the bulk of real traffic.
    agent: scenario('agentClient', RATE),
    developer: scenario('developerClient', Math.ceil(RATE / 2)),
    // Humans and evidence readers are comparatively rare but must not starve.
    operator: scenario('operatorClient', Math.max(1, Math.ceil(RATE / 10))),
    auditor: scenario('auditorClient', Math.max(1, Math.ceil(RATE / 20))),
    pdp: scenario('pdpClient', Math.ceil(RATE / 5)),
  },
  thresholds: {
    ...THRESHOLDS,
    'mcpip_latency_agent': ['p(95)<1500'],
    'mcpip_latency_operator': ['p(95)<2000'],
  },
  summaryTrendStats: ['avg', 'min', 'med', 'p(90)', 'p(95)', 'p(99)', 'max'],
};

function pick(list) {
  return list[Math.floor(Math.random() * list.length)];
}

// --- agent: proposes tool calls through the choke point ---------------------
export function agentClient() {
  const roll = Math.random();
  let alias;
  let expect;
  if (roll < 0.7) {
    alias = pick(ALIASES.allow);
    expect = 'allow';
  } else if (roll < 0.9) {
    alias = pick(ALIASES.staged);
    expect = 'staged';
  } else {
    alias = pick(ALIASES.unknown);
    expect = 'deny';
  }

  const res = http.post(`${BASE}/v1/authorize`, JSON.stringify(mcpToolCall(alias, { n: __ITER })), {
    headers: authHeaders(TOKENS.agent),
    tags: { client_type: 'agent', expect },
  });
  lat.agent.add(res.timings.duration);

  // A shed is the limiter working, not a decision. Count it and stop: asserting a
  // decision outcome on a request the gateway deliberately never evaluated would
  // score correct back-pressure as a policy failure.
  if (res.status === 503) {
    shedCounter.add(1);
    return;
  }

  if (expect === 'allow') {
    decisions.add(1);
    check(res, { 'agent: auto-tier read allowed': (r) => r.status === 200 }, { client_type: 'agent' });
  } else if (expect === 'staged') {
    staged.add(1);
    // THE invariant. A pin_required alias must never be allowed outright, at any
    // load. 202 = staged for step-up, 403 = refused (e.g. no OTP sink). 200 is a
    // policy failure and fails the whole run.
    check(
      res,
      { 'agent: pin_required is NEVER allowed without step-up': (r) => r.status !== 200 },
      { kind: 'invariant', client_type: 'agent' },
    );
  } else {
    denied.add(1);
    // SAFETY, asserted as an invariant: never ALLOWED. Deliberately `!== 200` and not
    // `=== 403`, because those are different properties and conflating them makes the
    // suite lie in both directions. Under saturation a request can time out (k6 reports
    // status 0); `=== 403` fails on that and reads as a policy breach when the gateway
    // in fact answered nothing at all — a fail-CLOSED outcome scored as a fail-OPEN one.
    // Liveness is measured separately below, where a timeout is honestly a timeout.
    check(
      res,
      { 'agent: unregistered alias is never allowed': (r) => r.status !== 200 },
      { kind: 'invariant', client_type: 'agent' },
    );
    check(
      res,
      { 'agent: unregistered alias answered (liveness)': (r) => r.status === 403 },
      { client_type: 'agent' },
    );
    // The deny body must stay opaque under load — no reason, no target, no topology.
    check(
      res,
      { 'agent: deny stays opaque': (r) => !/target|reason|http|risk_tier/i.test(r.body || '') },
      { kind: 'invariant', client_type: 'agent' },
    );
  }
}

// --- developer: raw HTTP plus the MCP-native edge ---------------------------
export function developerClient() {
  if (Math.random() < 0.5) {
    const res = http.post(
      `${BASE}/v1/authorize`,
      JSON.stringify(mcpToolCall(pick(ALIASES.allow), { n: __ITER })),
      { headers: authHeaders(TOKENS.developer), tags: { client_type: 'developer', surface: 'http' } },
    );
    lat.developer.add(res.timings.duration);
    check(res, { 'developer: authorize ok': (r) => r.status === 200 }, { client_type: 'developer' });
  } else {
    const res = http.post(`${BASE}/v1/mcp`, JSON.stringify(mcpNative('tools/list')), {
      headers: authHeaders(TOKENS.developer),
      tags: { client_type: 'developer', surface: 'mcp' },
    });
    lat.developer.add(res.timings.duration);
    check(res, { 'developer: tools/list ok': (r) => r.status === 200 }, { client_type: 'developer' });
    // The catalog an agent can see must never carry the real target.
    check(
      res,
      { 'developer: tools/list hides targets': (r) => !/https?:\/\//i.test(r.body || '') },
      { kind: 'invariant', client_type: 'developer' },
    );
  }
}

// --- operator: the admin plane ----------------------------------------------
export function operatorClient() {
  const path = Math.random() < 0.5 ? '/v1/admin/decisions/recent?limit=25' : '/v1/admin/stats';
  const res = http.get(`${BASE}${path}`, {
    headers: authHeaders(TOKENS.operator),
    tags: { client_type: 'operator' },
  });
  lat.operator.add(res.timings.duration);
  check(res, { 'operator: admin read ok': (r) => r.status === 200 }, { client_type: 'operator' });
}

// --- auditor: signed evidence ------------------------------------------------
//
// NOTE, and it is not obvious: /v1/audit/attestation is CAP_DIRECTORY_ADMIN-gated,
// NOT CAP_FORENSIC_READ. The attestation commits to the GLOBAL WORM head — a
// fleet-wide ledger height, not a per-tenant view — so a narrower principal reading
// it would leak cross-tenant activity volume and could force a full verify_chain.
// An "auditor" who needs the signed attestation therefore needs the directory-admin
// capability; CAP_FORENSIC_READ buys the payload-capture route, not this one.
export function auditorClient() {
  const res = http.get(`${BASE}/v1/audit/attestation`, {
    headers: authHeaders(TOKENS.auditor || TOKENS.operator),
    tags: { client_type: 'auditor' },
  });
  lat.auditor.add(res.timings.duration);
  check(res, { 'auditor: attestation ok': (r) => r.status === 200 }, { client_type: 'auditor' });
  // The chain must stay intact while the ledger is being written at rate — this is
  // the write-before-execute contract holding under contention.
  check(
    res,
    {
      'auditor: chain stays intact under load': (r) => {
        try {
          return r.status !== 200 || JSON.parse(r.body).intact === true;
        } catch (e) {
          return false;
        }
      },
    },
    { kind: 'invariant', client_type: 'auditor' },
  );
}

// --- pdp: AuthZEN verdict, executes nothing ---------------------------------
export function pdpClient() {
  const staging = Math.random() < 0.3;
  const alias = staging ? pick(ALIASES.staged) : pick(ALIASES.allow);
  const res = http.post(
    `${BASE}/v1/authz/decision`,
    JSON.stringify(authzenDecision(alias, { n: __ITER })),
    { headers: authHeaders(TOKENS.developer), tags: { client_type: 'pdp' } },
  );
  lat.pdp.add(res.timings.duration);
  check(res, { 'pdp: verdict returned': (r) => r.status === 200 || r.status === 403 }, { client_type: 'pdp' });
  // A PDP verdict must never carry a reason — same opacity as an execution deny.
  check(
    res,
    { 'pdp: verdict is opaque on deny': (r) => r.status !== 200 || !/deny_reason|target/i.test(r.body || '') },
    { kind: 'invariant', client_type: 'pdp' },
  );
}
