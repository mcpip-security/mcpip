# MCPIP × OpenClaw

[OpenClaw](https://docs.openclaw.ai) is a local-first personal AI assistant: it runs
on the user's own machine, connects to the messaging apps they already use, acts
proactively on a heartbeat rather than only when prompted, and draws on a large
ecosystem of community-authored skills. Its skills are markdown — a folder with a
`SKILL.md`, no SDK and no compilation — which is why there are thousands of them.

That combination is exactly the situation MCPIP was built for: **an agent holding
real credentials, acting unattended, running instructions it did not author.**

## What is here

| File | What it is |
|---|---|
| [`SKILL.md`](SKILL.md) | The skill itself. Drop it in an OpenClaw skills directory. It teaches the agent to route tool calls through an MCPIP gateway and — as importantly — how to behave when it is refused. |

## The two integration paths

**Path A — the MCP edge. Works today, no new code.** OpenClaw is an MCP client and
MCPIP *is* an MCP server at `POST /v1/mcp`. Register the gateway as an MCP server and
the agent's tool list becomes the alias catalog its identity is allowed to see, with
every call decided at the choke point and written to the signed ledger before it
executes. `SKILL.md` is the whole of this path.

**Path B — the permission-request plugin. Not built yet.** OpenClaw can pause a tool
call pending approval ([plugin permission
requests](https://docs.openclaw.ai/plugins/plugin-permission-requests)). A plugin
that answers that request from MCPIP instead of prompting the human would govern
*every* tool the agent has, not only the ones behind the gateway, and would escalate
to a human only for the `pin_required` tier. That is the better product; it is
tracked in the roadmap, and Path A comes first because it needs nothing.

## Why the prompt is not enough

OpenClaw's current control is the right instinct with the wrong primitive at volume.
A human tapping *allow* in a chat window:

- **trains itself away** — a prompt that is almost always safe teaches the person to
  approve without reading, and the one that matters looks identical to the rest;
- **is not a policy** — it does not survive a restart, does not apply to the next
  agent, and cannot express a limit, a schedule, or a tenant;
- **leaves no record** — nothing reconstructible months later, which is precisely
  what an auditor, an insurer or a regulator asks for;
- **is absent at 3am** — and a heartbeat daemon is not.

MCPIP does not remove the human. It removes the twentieth identical prompt, and
keeps the human for the actions that genuinely need one — where the approval is
bound to the exact payload, single-use, and logged before anything runs.

## The skills problem, said plainly

An OpenClaw skill is a markdown file, and anyone can publish one. The vast majority
are useful. But the form has an obvious property: **a document that the agent reads
as instructions can argue with the agent.** Packages already exist in the wild whose
setup instructions tell the agent to write itself into the host's global config, to
pre-load an authorization declaration *before* any safety review, and to consult a
prepared rebuttal table when it hesitates.

You cannot fix that by asking the agent to be more careful — you are asking the
component under attack to defend itself, using the same channel the attack arrives
on. What does work is putting the decision somewhere the instructions cannot reach:

- The catalog is issued by the gateway, so a skill cannot grant itself an alias.
- The real target never crosses the wire, so it cannot be exfiltrated from the agent.
- The denial is opaque, so a probing loop learns nothing from failing.
- Some aliases are decoys; calling one freezes the agent immediately.
- The record is written **before** execution, so it survives whatever happens next.

None of that depends on the agent's judgement, which is the point.

## Try it

```bash
# a gateway, locally
docker run --rm -p 8080:8080 ghcr.io/mcpip-security/mcpip:latest

# or from source — about 13 seconds to a working gate and a live walkthrough
git clone https://github.com/mcpip-security/mcpip && cd mcpip && ./scripts/quickstart.sh
```

Then copy `SKILL.md` into your OpenClaw skills directory and register the MCP server
as shown in the skill.

## Status and caveats

This is **Path A only**, and it is new. Two honest notes:

1. The YAML frontmatter uses generic fields (`name`, `description`, `license`,
   `homepage`, `metadata`). If ClawHub's current schema wants additional or
   differently-named keys, adjust the frontmatter — the body is what matters.
2. `ghcr.io/mcpip-security/mcpip` is published by the release workflow on a `v*`
   tag. Until the first tag is cut, use the source path above.

Issues and corrections: <https://github.com/mcpip-security/mcpip/issues>.

MCPIP is not affiliated with or endorsed by the OpenClaw project. It is named here
as an integration target; the marks belong to their owners.
