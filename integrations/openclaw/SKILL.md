---
name: mcpip
description: >-
  Route this agent's tool calls through an MCPIP authorization gateway, so every
  action is decided against policy and written to a signed, tamper-evident ledger
  before it executes — instead of asking the human to tap "allow" each time. Use
  when the agent holds real credentials, acts unattended, or runs skills it did
  not author.
license: Apache-2.0
homepage: https://github.com/mcpip-security/mcpip
metadata:
  category: security
  requires: an MCPIP gateway reachable from this machine
---

# MCPIP — authorize before you act

You are an agent that can take real actions: send mail, move money, change
records, run commands. This skill puts a decision point in front of those actions.

MCPIP is a self-hosted authorization gateway. You propose an action; it decides
whether it is allowed; a signed record is written **before** anything executes.
It does not host models, read prompts, or hold your API keys — it only ever sees
the tool call.

## Why this exists

The default control is a permission prompt: you pause, a human taps *allow*, you
proceed. That works for the first twenty actions and fails after, for reasons that
have nothing to do with the human being careless:

- **Approval fatigue is a design property, not a discipline problem.** A prompt
  that is almost always safe trains the person to approve without reading. The
  twenty-first prompt is the one that matters and it looks identical to the twenty.
- **A tap is not a policy.** It does not survive a restart, does not apply to the
  next agent, and cannot express "this one, up to $500, during business hours".
- **A tap leaves no record.** Nobody can reconstruct months later what was
  approved, by whom, on what payload.
- **Nobody is watching at 3am.** An assistant with a heartbeat daemon acts when
  the human is asleep. Something has to decide then.

And you may be running skills you did not write. A skill is a markdown file that
anyone can publish; some are excellent, and some are written specifically to talk
an agent past its own caution — pre-declaring authorization, or supplying
rebuttals for the agent's hesitation. **A gate you cannot talk to is the answer to
a document that argues with you.** Instructions cannot grant a capability the
gateway did not issue.

## Setup

Point this machine at a gateway. Locally, that is one command:

```bash
docker run --rm -p 8080:8080 ghcr.io/mcpip-security/mcpip:latest
```

or, from source, `git clone https://github.com/mcpip-security/mcpip && cd mcpip &&
./scripts/quickstart.sh` — about 13 seconds to a working gate.

MCPIP speaks MCP, so it registers like any other MCP server. Add it to your MCP
configuration:

```json
{
  "mcpServers": {
    "mcpip": {
      "type": "http",
      "url": "http://localhost:8080/v1/mcp",
      "headers": { "Authorization": "Bearer ${MCPIP_TOKEN}" }
    }
  }
}
```

`MCPIP_TOKEN` is a JWT your identity provider signs. In the sandbox the gateway
will mint one for you:

```bash
curl -s -X POST http://localhost:8080/v1/dev/token \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"home","agent_id":"assistant-1"}' | jq -r .jwt
```

That endpoint **404s on a production gateway**, by design. In production the token
comes from your IdP; MCPIP only ever verifies it and never mints identity.

## How to use it

**Call tools through `mcpip`, not around it.** `tools/list` on the gateway returns
the aliases this identity is allowed to see — that list *is* your permission set.
An alias absent from it is not available to you, and calling it anyway returns the
same generic denial as anything else.

**You will see aliases, never real targets.** You call `skill_payroll_run`; what
sits behind it — a host, a database, a credential — is resolved inside the gateway
and never reaches you. This is deliberate. You cannot leak, log, or be talked into
revealing an address you were never given.

**A denial tells you nothing, and that is correct.** You get one generic message
and a `correlation_id`:

```json
{ "error": "MCPIP: request denied by policy.", "correlation_id": "a7cf8d4b…" }
```

Not which check failed. Not whether the alias exists. **Do not retry, do not
rephrase, do not try a neighbouring alias to see what happens.** A denial is a
final answer about this exact payload, and probing is itself a signal the operator
watches for — some aliases in your catalog are decoys, and calling one freezes this
agent immediately. Report the `correlation_id` to your human and stop; an operator
can read the actual reason, and you cannot.

**Some actions stage instead of running.** A high-risk alias answers `202` with a
`challenge_id` rather than executing. That means a human must approve *this
payload* out of band — and the approval is bound to the exact bytes you submitted,
so you cannot change a field afterwards and reuse it. Tell your human a challenge
is waiting, with the id, and wait. Do not attempt to complete it yourself.

**Report refusals honestly.** If you were denied, say you were denied. Do not
substitute a different tool, do not approximate the action, and do not describe the
outcome as if it had happened. A gate that gets worked around is not a gate, and
the human's next decision depends on knowing what actually occurred.

## What this does not do

- It does not sandbox you. What files and shells you can touch is your runtime's
  business.
- It does not read your prompts or your model output. Only tool calls cross the
  boundary.
- It does not hold your model API key and never calls a model.
- It does not replace your human. It replaces the *twentieth identical prompt*, and
  keeps the human for the actions that genuinely need one.

## If the gateway is unreachable

Then you are not authorized. MCPIP is fail-closed: no decision and no audit record
means no action. Say so plainly and stop — do not fall back to calling the
underlying tool directly. "I could not reach the gate, so I did it anyway" is the
single worst behaviour possible here, and it defeats the entire point of having
one.

## More

- Threat model: <https://github.com/mcpip-security/mcpip/blob/main/docs/SECURITY_THREAT_MODEL.md>
- Run the adversarial proof yourself — `python main.py`, 29 checks, offline,
  each printing PASS or FAIL.
