# HTTP API Reference

The gateway speaks one protocol over 63 endpoints, but you only need the first section to
integrate. Everything an **agent** does goes through `POST /v1/authorize` (or its MCP-native
equivalent `POST /v1/mcp`). Everything else is an operator, auditor, or platform surface.

The live, machine-readable contract is served by the gateway itself:

```bash
curl -s http://localhost:8080/openapi.json | jq '.paths | keys'
```

Interactive docs are at `http://localhost:8080/docs`.

## Conventions

Every response carries `X-MCPIP-Correlation-Id`. Every denial returns the same generic body:

```json
{ "error": "MCPIP: request denied by policy.", "correlation_id": "9f2c41a7e83b4d15a0c6f7b2e5d81a3c" }
```

That opacity is deliberate and load-bearing. An agent learns only *that* it was denied — never
*why*, never which check fired, never whether the alias exists. Concrete reasons live in the
WORM audit log, readable by an operator through the forensic surface. If you are debugging an
integration, read the audit log; do not expect the wire to explain itself.

Identity comes only from a verified JWT, supplied as `Authorization: Bearer <jwt>`. The gateway
never mints identity in production and the `role` claim authorizes nothing — entitlements come
from the `capabilities` claim (UUIDs) and Redis-held grants.

**Status codes**

| Code | Meaning |
|---|---|
| `200` | Executed, or a read succeeded |
| `202` | Staged — a high-risk action needs step-up approval before it runs |
| `403` | Denied by policy (opaque) |
| `404` | Not found — also the honest answer for a sandbox-only endpoint in production |
| `422` | Malformed request body |
| `503` | Not ready (readiness probe only) |

## The agent surface

This is the whole integration. Five endpoints, and most agents use one.

| Method · Path | Purpose |
|---|---|
| `POST /v1/authorize` | Authorize — and on ALLOW, execute — one tool call. |
| `POST /v1/mcp` | The MCP-native edge: JSON-RPC 2.0 `initialize` / `tools/list` / `tools/call`. |
| `GET /v1/catalog` | The skills this caller may *see*. Metadata only — never the target. |
| `GET /v1/whoami` | The verified identity behind the presented token. |
| `POST /v1/authz/decision` | Decision-only mode: get the verdict, enforce it yourself (PDP pattern). |

### `POST /v1/authorize`

Exactly one of `source_format` or `vendor` must be present — the dialect is **declared, never
guessed**. `tool_call` is the raw provider envelope in that dialect, passed through as-is
because the Bridge is the authoritative deep validator. `trace` is optional; a single-hop trace
is synthesized from the verified `agent_id` when omitted. `pin` and `challenge_id` are supplied
together or not at all.

```json
{
  "source_format": "openai_tool_call",
  "tool_call": {
    "id": "call_1",
    "type": "function",
    "function": {
      "name": "skill_wire_transfer",
      "arguments": "{\"payee\":\"enrolled:ACME_PAYROLL\",\"amount_cents\":2418000}"
    }
  },
  "trace": {
    "trace_id": "6f1c0f9e-4d1a-4a5b-9c2e-7a1b3c5d9e02",
    "hops": [{ "hop_index": 0, "agent_id": "agent-orchestrator-1", "parent_agent_id": null, "purpose": "pay run" }]
  },
  "pin": null,
  "challenge_id": null
}
```

**`200` — ExecutionReceipt.** An AUTO-tier alias, or a completed step-up. `executed_target_class`
is the coarse transport class only; the real target never crosses the boundary.

```json
{
  "correlation_id": "9f2c41a7e83b4d15a0c6f7b2e5d81a3c",
  "decision": "allow",
  "status": "committed",
  "transaction_ref": "txn_4c8a1e0b7d2f4906",
  "executed_target_class": "cloud_rest",
  "worm_sequence": 42
}
```

**`202` — StagedChallenge.** A `pin_required` alias submitted without a PIN. No ALLOW is emitted.
The one-time code is delivered out of band; it is never in this body.

```json
{
  "correlation_id": "9f2c41a7e83b4d15a0c6f7b2e5d81a3c",
  "action_required": "Step-up required: approve in your enrolled authenticator to obtain a one-time code, then resubmit with pin + challenge_id.",
  "challenge_id": "b7e14d92c3a04f6685d1097fae2b3c48",
  "risk_tier": "pin_required"
}
```

**`403`** — any denial: replay, tamper, bad JWT, cross-tenant, identity injection, unknown alias,
PIN mismatch, `compartment_denied`, `capability_denied`, `policy_denied`. All identical on the wire.

### The declared wire formats

Seven parsers, selected by `source_format`, plus 82 named vendor ids that resolve to one of them
through a hash-pinned registry (`vendor: "gemini"` → `gemini_function_call`).

| `source_format` | Shape |
|---|---|
| `openai_tool_call` | OpenAI / Azure OpenAI `tool_calls[]` function envelope |
| `anthropic_tool_use` | Anthropic `tool_use` content block |
| `gemini_function_call` | Gemini `functionCall` part object |
| `bedrock_tool_use` | Bedrock Converse `toolUse` block |
| `mcp_jsonrpc` | MCP JSON-RPC 2.0 `tools/call` |
| `raw_mcp` | The direct `{tool, arguments}` form |
| `a2a_task` | A2A task envelope |

An unknown `vendor` is an opaque `403`. Neither field is a `422`. The format is never inferred
from payload bytes — sniffing is what lets a caller choose the parser that validates least.

### The step-up flow

High-risk aliases are `pin_required` and consume a payload-bound, exactly-once lock.

1. **Stage** — `POST /v1/authorize`, no `pin` → `202` with a `challenge_id`.
2. **Approve** — the code reaches the enrolled authenticator out of band.
3. **Complete** — resubmit the *same* payload with `pin` + `challenge_id` → `200`. The lock is
   spent atomically in one Redis Lua consume.
4. **Replay** — the same triple again → `403` (`pin_not_found`; the lock is gone).
5. **Tamper** — one byte of the payload drifts after staging → `403` (`payload_mismatch`). The
   lock survives, so a correct-payload retry still consumes it.

Delivery of the code is a pluggable seam, and it is fail-closed: with no channel configured, or a
channel whose delivery raises, the gateway denies `otp_delivery_failed` **before** any `202` is
produced. A `pin_required` action can never stage a challenge nobody can answer. See
[Operations](../operate/OPERATIONS.md) for wiring `MCPIP_AUTHN_WEBHOOK_URL`.

### End to end, copy-paste (sandbox)

```bash
API=http://localhost:8080

# 1) Mint a sandbox identity. Sandbox only — 404 in production, where your IdP does this.
JWT=$(curl -s -X POST $API/v1/dev/token \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-acme","agent_id":"agent-orchestrator-1"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')

# 2) An AUTO alias executes immediately.
curl -s -X POST $API/v1/authorize -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d '{
    "source_format":"openai_tool_call",
    "tool_call":{"id":"call_1","type":"function","function":{"name":"skill_spend_summary","arguments":"{\"period\":\"2026-Q2\"}"}}
  }'

# 3) A high-risk alias with no PIN stages a challenge.
CH=$(curl -s -X POST $API/v1/authorize -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d '{
    "source_format":"openai_tool_call",
    "tool_call":{"id":"call_2","type":"function","function":{"name":"skill_wire_transfer","arguments":"{\"payee\":\"enrolled:ACME_PAYROLL\",\"amount_cents\":2418000}"}}
  }' | python3 -c 'import sys,json; print(json.load(sys.stdin)["challenge_id"])')

# 4) Read the code from the sandbox authenticator stand-in. Sandbox only.
OTP=$(curl -s -H "authorization: Bearer $JWT" $API/v1/authenticator/$CH \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["otp"])')

# 5) Same payload + pin + challenge_id executes.
curl -s -X POST $API/v1/authorize -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d "{
    \"source_format\":\"openai_tool_call\",
    \"tool_call\":{\"id\":\"call_3\",\"type\":\"function\",\"function\":{\"name\":\"skill_wire_transfer\",\"arguments\":\"{\\\"payee\\\":\\\"enrolled:ACME_PAYROLL\\\",\\\"amount_cents\\\":2418000}\"}},
    \"pin\":\"$OTP\",\"challenge_id\":\"$CH\"
  }"

# 6) Replaying step 5 now denies — the lock was spent.
```

### `POST /v1/mcp` — the MCP-native edge

The gateway *is* an MCP server. Point any MCP client at it and every `tools/call` walks the same
four stages. It is an authorization boundary, not a proxy: the gateway does not forward to another
MCP server, it resolves the alias and executes through its own transport table.

```json
{ "mcpServers": { "mcpip": {
    "type": "http",
    "url": "http://localhost:8080/v1/mcp",
    "headers": { "Authorization": "Bearer <jwt>" } } } }
```

Supported methods: `initialize`, `tools/list`, `tools/call`. `tools/list` returns the same
compartment-filtered view as `GET /v1/catalog`.

## The approval surface

Enrolling and using the authenticator that answers a step-up.

| Method · Path | Purpose |
|---|---|
| `POST /v1/authenticator/enroll` | Begin enrollment for the calling principal. |
| `POST /v1/authenticator/enroll/confirm` | Confirm enrollment with the delivered code. |
| `GET /v1/authenticator` | Enrollment status for the caller. |
| `POST /v1/authenticator/reveal` | Reveal the enrollment secret to its owner. |
| `POST /v1/authenticator/disable` | Disable the caller's own authenticator. |
| `GET /v1/authenticator/{challenge_id}` | **Sandbox only.** Stands in for out-of-band delivery. |

## The audit surface

| Method · Path | Purpose |
|---|---|
| `GET /v1/audit/attestation` | Portable, signed attestation of current audit state. JWT-gated, available in production. |
| `GET /v1/audit/verify` | **Sandbox only.** Force an epoch close, then `verify_chain()` → `{intact, first_bad_epoch}`. |
| `GET /v1/audit/proof/{event_id}` | **Sandbox only.** O(log n) Merkle inclusion proof. `CAP_DIRECTORY_ADMIN`, tenant-scoped. |
| `GET /v1/admin/forensic/{correlation_id}` | The real arguments behind one decision. `CAP_FORENSIC_READ`. |

For offline verification of an exported log, see `mcpip export-audit --verify` in
[CLI](CLI.md) and [Release](../operate/RELEASE.md).

## The operator surface

All `/v1/admin/*` routes are capability-gated, tenant-scoped, opaque on failure, and
WORM-logged **before** they take effect. The capabilities are UUIDs carried in the JWT
`capabilities` claim; `GET /v1/dev/capabilities` lists the well-known ones in sandbox.

**Skills (the alias catalog)** — `CAP_DIRECTORY_ADMIN`

| Method · Path | Purpose |
|---|---|
| `POST /v1/admin/skills/register` | Register an alias → target mapping. Additive only. |
| `GET /v1/admin/skills/registered` | List registered skills. |
| `POST /v1/admin/skills/{alias}/deregister` | Remove a registered skill. |
| `POST /v1/admin/skills/{alias}/disable` · `/enable` | Toggle a skill without deregistering it. |
| `GET /v1/admin/skills/disabled` | List currently disabled skills. |

**Principals and access** — `CAP_DIRECTORY_ADMIN`

| Method · Path | Purpose |
|---|---|
| `POST /v1/admin/principals/{agent_id}/revoke` · `/reactivate` | The kill switch, and its undo. |
| `GET /v1/admin/principals/revoked` | The authoritative revoked list. |
| `GET /v1/admin/quarantine` | Currently quarantined agents, with TTL. |
| `GET /v1/admin/canaries` | The decoy-alias roster that trips on enumeration. |
| `GET /v1/admin/delegations` · `POST /v1/admin/delegations/revoke` | Delegated-grant lineage and cascading revocation. |
| `GET /v1/admin/directory/relations` | ReBAC relation edges projected from committed grants. |
| `GET` · `PUT /v1/directory` | The operator org directory. Non-authoritative metadata; never consulted for authorization. |

**Policy overlay** — `CAP_DIRECTORY_ADMIN`

| Method · Path | Purpose |
|---|---|
| `GET` · `PUT /v1/admin/policy` | The per-tenant deny-only rule document. |
| `POST /v1/admin/policy/delete` | Remove it. |

The overlay is **deny-only and opt-in**. It can add a `policy_denied`; it can never turn an
earlier deny into an allow, mint identity, or repoint a skill. Two rule kinds: a velocity
fixed-window action cap, and an amount ceiling on a named numeric argument (compared as
`Decimal`, never coerced from a string). With no document for a tenant there are **no limits** —
never a fabricated default. A Redis error or a malformed document fails closed for that tenant.

**Community extensions** — `CAP_CATALOG_REVIEWER` to review, any principal to submit

| Method · Path | Purpose |
|---|---|
| `POST /v1/extensions/submit` | Submit a skill, gate, or registry-server manifest. No capability required. |
| `GET /v1/admin/extensions/pending` | The review queue. |
| `POST /v1/admin/extensions/{id}/approve` · `/reject` | Decide. Both are WORM-recorded before they apply. |
| `GET` · `PUT /v1/admin/extensions/publishers` | The verified-publisher allow-list a registry-server approval is checked against. |

**Operator console support** — `CAP_DIRECTORY_ADMIN`

| Method · Path | Purpose |
|---|---|
| `GET /v1/admin/decisions` · `/recent` | Paged decision history, and the live feed. |
| `GET /v1/admin/stats` | Local deployment, license, and usage counters. |
| `GET /v1/admin/compliance/evidence` | Portable compliance evidence bundle. Evidence, never a certificate. |
| `GET /v1/admin/users` · `POST /users/invite` · `PUT`/`DELETE /users/{email}` | Console team roster. The `role` is a management label; it authorizes nothing. |
| `GET` · `PUT /v1/admin/vault/secrets` · `POST /vault/secrets/{id}/delete` | Secret references for transports. |
| `GET` · `PUT /v1/admin/cloud/environments` · `POST /{id}/delete` | Cloud-broker environment registrations. |
| `GET /v1/admin/authenticator/enrollments` · `DELETE /{agent_id}` | Enrollment roster and admin revocation. |
| `POST /v1/admin/workspace/draft` · `/plan/validate` · `/plan/apply` | Brief → governed workspace scaffold. |

## Delegation

Off by default. Set `MCPIP_DELEGATION_ENABLED=true` to mount it.

| Method · Path | Purpose |
|---|---|
| `POST /v1/delegate` | Grant a child a subset of your own authority. |
| `POST /v1/delegate/revoke` | Revoke a grant; revocation cascades to the whole subtree. |

A child grant is attenuated by construction: capabilities must be a subset, the compartment must
be the same or narrower, expiry must be sooner, and depth is capped. See
[Session delegation](../SESSION_DELEGATION_DESIGN.md).

## Platform

| Method · Path | Purpose |
|---|---|
| `GET /healthz` | Liveness. Does **not** check Redis — a `live` gateway with Redis down denies every call. |
| `GET /readyz` | Readiness. Pings Redis. `{"status":"ready","redis":"up"}` or `503`. |
| `GET /metrics` | Prometheus metrics. |
| `GET /v1/version` | Running version. |
| `GET /v1/license` | License state. |
| `GET /.well-known/oauth-protected-resource` | OAuth 2.1 resource-server metadata. |

If every call is denying, check `/readyz` before anything else. MCPIP cannot authorize what it
cannot audit, so a down audit store denies everything — correctly, and opaquely.

## Sandbox-only endpoints

These five are mounted only when `MCPIP_SANDBOX_MODE=true` and return `404` otherwise. That
`404` is the correct production answer, not a misconfiguration.

| Method · Path | Stands in for |
|---|---|
| `POST /v1/dev/token` | Your identity provider. |
| `GET /v1/dev/capabilities` | Your capability catalog. |
| `GET /v1/authenticator/{challenge_id}` | Out-of-band code delivery. |
| `GET /v1/audit/verify` | Scheduled offline chain verification. |
| `GET /v1/audit/proof/{event_id}` | Offline proof generation from an export. |

Sandbox mode also boots an in-process IdP and an ephemeral WORM signing key, and logs a loud
banner. Run it on loopback, with a single uvicorn worker — the in-process keys are per-process.

## See also

- [Getting Started](GETTING_STARTED.md) — clone to authorized call
- [SDK](SDK.md) — typed Python and TypeScript clients
- [CLI](CLI.md) — the `mcpip` command
- [Threat model](../SECURITY_THREAT_MODEL.md) — the adversary model behind these choices
