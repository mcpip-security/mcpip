# MCPIP SDKs — Python & TypeScript

    ◐  "Authorize every AI action before execution."

MCPIP ships two first-party clients with **full console parity** — everything
the operator console can do against a gateway, an SDK can do too:

| | Python | TypeScript |
| --- | --- | --- |
| Location | `sdk/python` | `sdk/typescript` |
| Package | `mcpip-sdk` (import `mcpip_sdk`) | `@mcpip/sdk` |
| Runtime deps | `httpx` only | none (global `fetch`, Node ≥ 18) |
| Types | `py.typed`, frozen dataclasses, `mypy --strict` | `.d.ts`, `strict: true` |

Both speak the **identical wire protocol**, and the method surfaces are parallel:
snake_case in Python, the same name in camelCase in TypeScript
(`skills_register` ↔ `skillsRegister`). Two things do **not** transliterate — the class
prefix (`MCPIPClient` in Python, `McpipClient` in TypeScript) and three admin methods,
listed in §10. A test checks every identifier on this page against the shipped sources, so
what follows is what actually exists.

This document is the shared contract; examples are Python-first with the TypeScript mirror
in §10.

> **Prefer the command line?** The SDK you *import* also ships the `mcpip`
> command you *run* — a fail-closed, opaque, git/kubectl-style CLI that wraps
> these same clients (no reimplemented wire logic). Zero to authorized in three
> commands: `mcpip login` → `mcpip sandbox dev-token` → `mcpip authorize`. Full
> command reference, config precedence, the token/OTP-never-in-argv model, and
> the exit-code table live in **[`docs/start/CLI.md`](CLI.md)**. The Python bin is
> the flagship; a zero-dependency TypeScript bin mirrors it (`npx @mcpip/sdk
> mcpip <args>` until published).

---

## 1. Clients

| Python | TypeScript | Role |
| --- | --- | --- |
| `MCPIPClient` | `McpipClient` | Agent surface — authorize, catalog, MCP edge, health/version/license |
| `SandboxClient` | `McpipSandboxClient` | Agent surface **plus sandbox-only affordances** (404 in production, by design) |
| `MCPIPAdminClient` | `McpipAdminClient` | `CAP_DIRECTORY_ADMIN` control plane |

Import the class names exactly as written — the prefix is the one thing that does not
transliterate between the two.

**Install**

```bash
npm install @mcpip/sdk              # PUBLISHED — ESM-only, zero runtime dependencies

pip install ./sdk/python            # or: pipx install ./sdk/python (also puts `mcpip` on PATH)
                                    # NOT on PyPI yet — the git/checkout form is the only one
```

The asymmetry is real and deliberate rather than an oversight: `@mcpip/sdk` is on npm, and
`mcpip-sdk` is not yet on PyPI. Until it is, the Python install stays a path or a git URL —
documenting `pip install mcpip-sdk` before the name resolves would send every reader to an
error.

```python
from mcpip_sdk import MCPIPClient

client = MCPIPClient(
    "https://gateway.example",
    token=my_token_or_callback,   # str, or () -> str
    # timeout=..., transport=...  # strict 10s default; any httpx transport
)
# context-manager friendly; or client.close()
```

Construction never issues a request. All clients are context managers and
have `close()`.

## 2. Identity: the token contract

The gateway **verifies** JWTs and never mints them (production identity is
IdP-sovereign — EdDSA/RS256, 8 required claims; see
`scripts/mint_principal.py` for the reference minter, `capabilities` UUIDs
for admin tokens, `compartment` for scoped principals).

The SDK accepts a **static string** (used verbatim; your rotation) or a
**zero-arg callback** (your IdP/STS integration). Callbacks are invoked
lazily, cached, and re-invoked **proactively ~30 seconds before the token's
own `exp`** (parsed best-effort from the JWT payload — no verification
client-side). There is **no reactive refresh**: a deny is opaque, so
refreshing (or retrying) on deny would double-count every legitimate denial
as two WORM audit events. This mirrors `scripts/claude_mcp_bridge.py` and the
operator console.

Sandbox gateways additionally offer `SandboxClient.dev_token(...)` (`POST
/v1/dev/token`) — mint-on-demand sandbox identities that expire in ~5 minutes.
Pair it with a callback for anything long-running:

```python
client.set_token(lambda: client.dev_token(agent_id="agent-x"))
```

## 3. `authorize` — the single choke point

```python
outcome = client.authorize("skill_spend_summary", {"period": "2026-Q2"})
# → Allowed | Staged; raises MCPIPDenied on any policy deny
```

- Default envelope is `raw_mcp`. Pass `source_format=` any of the seven shipped
  dialects — `openai_tool_call`, `anthropic_tool_use`, `gemini_function_call`,
  `bedrock_tool_use`, `mcp_jsonrpc`, `raw_mcp`, `a2a_task` — and the SDK builds that
  provider's exact strict shape (`mcpip_sdk.envelopes` has the builders; the TypeScript
  equivalents are the top-level `openaiToolCall`, `anthropicToolUse`,
  `geminiFunctionCall`, `bedrockToolUse`, `mcpToolsCall`, `rawMcp`, `a2aTask`).
- Or send a raw provider envelope verbatim:
  `client.authorize(tool_call={...}, source_format="anthropic_tool_use")` /
  `client.authorize(tool_call={...}, vendor="openai")` — exactly one of
  `source_format`/`vendor`, mirroring the wire contract.
- ONE tool call per request; batches are rejected server-side.

**`Allowed`** (HTTP 200) — the receipt: `correlation_id`, `decision`,
`status`, `transaction_ref`, `executed_target_class` (coarse transport CLASS,
never a target — topology never crosses the boundary), `worm_sequence` (the
audit anchor), `vended_credential` (cloud_iam transport only: the short-lived
scoped credential for THIS call).

**`Staged`** (HTTP 202) — a `pin_required` alias staged a payload-bound lock:
`challenge_id`, `action_required`, `risk_tier`, `expires_in` (the protocol's
fixed 300s lock TTL), and `envelope` (the exact request, kept so completion
can resubmit it byte-identically).

**`MCPIPDenied`** — opaque **by design**: `correlation_id` + `http_status`,
nothing else, ever. The concrete reason exists only in the gateway's WORM log
(operators: `decisions_recent`). **Never auto-retry** `/v1/authorize` — the
SDKs never do.

## 4. The PIN ceremony (step-up), exactly

1. **Stage** — `authorize(...)` on a `pin_required` alias → `Staged`. The
   gateway minted a 6-digit one-time code, locked it to
   `(tenant, agent, alias, arguments)`, and told the enrolled authenticator.
   The OTP is **never** in the 202.
2. **Obtain the OTP out-of-band** — production: the approver's enrolled
   authenticator device. Sandbox: `SandboxClient.authenticator_code
   (challenge_id)` (`GET /v1/authenticator/{challenge_id}`, Bearer-gated,
   tenant-scoped). Model production acquisition as your own callback with the
   sandbox method as the dev default.
3. **Complete** — `client.complete(staged, pin)` resubmits the **identical**
   envelope plus `pin` + `challenge_id` (the wire demands the pair together).
   → `Allowed`.

Semantics the gateway enforces: the lock is consumed **exactly once**
(replays deny `pin_not_found`-in-WORM, opaque on the wire); five wrong PINs
destroy it; **payload drift denies but does NOT consume** — a correct retry
with the same `pin` + `challenge_id` still succeeds; the lock expires after
`expires_in` (300s). A step-up staged via the MCP edge completes on
`/v1/authorize` with `source_format="mcp_jsonrpc"` and the identical JSON-RPC
dict — the lock is format-independent.

## 5. The MCP edge — `mcp_call`

`client.mcp_call(method, params)` speaks real JSON-RPC 2.0 to `/v1/mcp` (one
request object per POST):

- `initialize` (no auth) → server card (`protocolVersion: "2025-06-18"`).
- `notifications/initialized` (no auth, a true notification) → `None`.
- `tools/list` (Bearer) → same visibility as `/v1/catalog`, metadata only.
- `tools/call` (Bearer) → allow: result whose `content[0].text` is the
  ExecutionReceipt JSON; staged: result with `isError: true` and the
  `challenge_id` payload (complete via `/v1/authorize`, §4); deny: JSON-RPC
  error `-32000` **inside an HTTP 200** — raised as `MCPIPDenied` with
  `data.correlation_id`.

## 6. Reads

| Method | Endpoint | Auth | Returns |
| --- | --- | --- | --- |
| `catalog()` | `GET /v1/catalog` | JWT | `CatalogItem[]` — alias, risk_tier, transport_class, classification, compartment. Empty list = this identity enumerates nothing (a real answer) |
| `health()` | `GET /healthz` | none | `Health` — the connectivity probe, never shed |
| `ready()` | `GET /readyz` | none | `Readiness` — a 503 parses to `ready=False` honestly, no exception |
| `version()` | `GET /v1/version` | JWT | `VersionInfo` — running/latest, `update_policy: "redeploy"` (notifier only), signed release provenance |
| `license()` | `GET /v1/license` | JWT | `LicenseInfo` — `licensed=False` and nothing else on sandbox |
| `audit_attestation()` | `GET /v1/audit/attestation` | JWT | `AuditAttestation` — a portable, signed snapshot of the audit state: the latest SEALED epoch header (epoch/end_seq/merkle_root/epoch_hash/signature — `None` before the first epoch closes), the WORM key's public `signing_key_id`, a fresh `intact`/`first_bad_epoch`, and the anchor low-watermark. **Available in PRODUCTION** (unlike the sandbox-only `audit_verify`/`audit_proof`); mints no key, signs nothing new, discloses no target/payload/secret |
| `protected_resource_metadata()` | `GET /.well-known/oauth-protected-resource` | **none** | `ProtectedResourceMetadata` (N2, RFC 9728) — the PUBLIC OAuth 2.1 Resource-Server discovery doc: `resource` (the RFC 8707 audience), the trusted `authorization_servers`, and `bearer_methods_supported`. NO OAuth scopes (MCPIP has none), no secret, no alias→target topology. Never shed; served in sandbox AND production |
| `authz_decision(alias, arguments)` | `POST /v1/authz/decision` | JWT | `AuthzenDecision` (N1, OpenID-AuthZEN 1.0 / COAZ) — a PRE-EXECUTION permit/deny verdict from MCPIP as a PDP. DECISION-ONLY (nothing executes, vends, stages/consumes a PIN, or mutates a grant). A permit is `decision=True` optionally with standards-shaped `obligations` (`mcpip.step_up.pin` for a PIN tier, `mcpip.sender_constraint.dpop` for a sender-constrained resource); a deny is the bare opaque `decision=False` (no reason/target/topology). Identity is the Bearer JWT only — the AuthZEN `subject` is advisory/echo. A verdict is NOT an authorization to act — `authorize()` still runs the full pipeline (incl. the velocity/amount controls a decision query deliberately skips) |

> **MCP MRT step-up (N4, SEP-2322).** The `/v1/mcp` edge `initialize` result now
> additively advertises `capabilities.experimental.mcpipStepUp = {"mode":"mrt"}`.
> Both SDKs already speak the edge via `mcp_call` / `mcpCall`; the payload-bound
> PIN maps onto the MRT InputRequired shape (opt-in `stepUp:"mrt"`) over the
> unchanged staging/consume path. The classic `/v1/authorize` two-step is
> byte-for-byte unchanged.

## 7. Sandbox-only affordances (`SandboxClient`)

Each targets an endpoint that **exists only** under
`MCPIP_SANDBOX_MODE=true`; production answers 404 and the SDK raises
`MCPIPSandboxOnly`. Do not ship agents that depend on them.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `dev_token(tenant_id, agent_id, role, compartment=, capabilities=)` | `POST /v1/dev/token` | Mint a sandbox EdDSA JWT (~5 min exp) |
| `authenticator_code(challenge_id)` | `GET /v1/authenticator/{id}` | The stand-in enrolled authenticator (OTP tenant-scoped to the caller) |
| `audit_verify()` | `GET /v1/audit/verify` | Force epoch close + verify the signed Merkle-epoch chain |
| `audit_proof(event_id)` | `GET /v1/audit/proof/{id}` | O(log n) inclusion proof for one sealed WORM event (`event_id` comes from the admin decisions feed) |

## 8. Admin surface (`MCPIPAdminClient`)

The Bearer must carry the `CAP_DIRECTORY_ADMIN` capability UUID
(`b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20`, exported as
`mcpip_sdk.CAP_DIRECTORY_ADMIN`) and the admin principal must not be
revoked/quarantined. Everything is **tenant-scoped to the admin's own JWT
tenant**, every mutation is WORM-logged server-side, any failure is the same
opaque `MCPIPDenied`.

| Python (TS mirror in camelCase) | Endpoint | Notes |
| --- | --- | --- |
| `skills_register(alias, target, risk_tier, classification)` | `POST /v1/admin/skills/register` | Additive only — never shadows an existing alias; restricted ⇒ pin_required |
| `skills_deregister(alias) -> bool` | `POST /v1/admin/skills/{alias}/deregister` | Overlay skills only; config aliases immutable (no-op success) |
| `skills_disable(alias)` / `skills_enable(alias) -> bool` | `POST /v1/admin/skills/{alias}/disable\|enable` | Tenant-wide kill-switch; never edits alias→target |
| `skills_registered() -> RegisteredSkill[]` | `GET /v1/admin/skills/registered` | With timestamps (`entries`; legacy name-only fallback) |
| `skills_disabled() -> str[]` | `GET /v1/admin/skills/disabled` | |
| `decisions_recent(limit=50) -> RecentDecision[]` | `GET /v1/admin/decisions/recent?limit=` | Newest first, clamped 1..200; whitelist projection with `deny_reason` (operator-side), `worm_sequence`, `event_id` (the proof handle) |
| `forensic_get(correlation_id) -> ForensicPayload \| None` | `GET /v1/admin/forensic/{correlation_id}` | **Requires the distinct `CAP_FORENSIC_READ` capability, NOT `CAP_DIRECTORY_ADMIN`** (see below). Reconstructs the REAL query (alias + canonicalized, secret-redacted arguments + non-secret identity context) behind a correlation id. `None` is an opaque miss (feature off, or unknown/expired/cross-tenant id); access is WORM-audited before disclosure |
| `principals_revoke(agent_id, reason=)` / `principals_reactivate(agent_id) -> bool` | `POST /v1/admin/principals/{id}/revoke\|reactivate` | Persistent kill-switch; DENY-only, never mints identity |
| `principals_revoked() -> str[]` | `GET /v1/admin/principals/revoked` | The authoritative list |
| `quarantine() -> QuarantinedAgent[]` | `GET /v1/admin/quarantine` | Canary-tripwire freezes + remaining TTL; read-only (expiry is Redis's clock) |
| `canaries() -> CanaryAlias[]` | `GET /v1/admin/canaries` | The decoy roster — the ONLY surface that reveals the canary flag; agent-facing catalogs keep hiding it |
| `directory_get()` / `directory_put(document)` | `GET\|PUT /v1/directory` | Org-chart metadata (schema `mcpip-directory/1`); never consulted by authorization |
| `directory_relations(subject=, relation=, object_uuid=) -> RelationList` | `GET /v1/admin/directory/relations` | ReBAC Knowledge-Graph edges projected from committed grants (`member` + read-time-derived `grantor`). A best-effort PROJECTION, fail-soft (transport blip UNDER-reports, never over-reports); the gateway/Redis grant state is authoritative. Optional filters narrow the edges (malformed ⇒ opaque deny); a FULL (subject, relation, object) triple also returns `allowed` — the bounded, fail-closed transitive-closure check. **READ/VISUALIZATION ONLY — the authorization pipeline NEVER consults it**; tuples hold operator-facing ids + non-secret grant metadata only, never a target or alias→target mapping |
| `policy_get()` / `policy_put(document)` / `policy_delete() -> bool` | `GET\|PUT /v1/admin/policy`, `POST /v1/admin/policy/delete` | Deny-only policy overlay (schema `mcpip-policy/1`): a bounded list of `velocity` (fixed-window action cap) and `amount` (numeric-field ceiling, decimal STRING) rules, each scoped by `alias` or `transport_class`. Strict-validated + emit-before-mutate WORM. NO stored doc ⇒ no limits (honest opt-in). The doc holds ONLY velocity/amount rules — never an alias→target or identity — so it can never repoint a skill or mint a principal. A policy denial surfaces to the agent as the opaque `POLICY_DENIED` (correlation-id only). **v1 does NOT include second-approver / approval routing (deferred to the full PolicyEngine).** |
| `workspace_draft(brief, company, tenant)` | `POST /v1/admin/workspace/draft` | Deterministic, inference-free plan proposal |
| `workspace_validate(plan)` / `workspace_apply(plan)` | `POST /v1/admin/workspace/plan/validate\|apply` | Apply re-validates fail-closed; idempotent (existing aliases skipped) |
| `cloud_environments_list()` / `cloud_environments_put(...)` / `cloud_environments_delete(env_id) -> bool` | `GET\|PUT /v1/admin/cloud/environments`, `POST .../{env_id}/delete` | Bindings hold no secret; `vault_secret_id` must reference an existing vault entry |
| `vault_secrets_list()` / `vault_secrets_put(secret_id, vendor, material, description)` / `vault_secrets_delete(id) -> bool` | `GET\|PUT /v1/admin/vault/secrets`, `POST .../{id}/delete` | `vault_secrets_put` is the ONLY request in the API carrying a secret value; no endpoint ever returns one — reads are metadata + keyed fingerprint |

(Deletes are `POST .../delete` — this API has no HTTP `DELETE`.)

### 8.1 Forensic reconstruction (`forensic_get` / `forensicGet`)

`forensic_get(correlation_id)` (TS: `forensicGet(correlationId)`) is the sole
retrieval for the forensic capture store — the ADMIN/investigator counterpart
to the deliberately opaque agent wire and the arguments-omitting decision feed.
It is held to a **higher bar than every other method on this client**:

- **A separate capability.** The Bearer must carry `CAP_FORENSIC_READ`
  (`d5f0c9a2-4b71-4e6a-9c83-1a7f2e6b4d90`, exported as
  `mcpip_sdk.CAP_FORENSIC_READ` / `CAP_FORENSIC_READ` in `@mcpip/sdk`), which is
  **deliberately DISTINCT from `CAP_DIRECTORY_ADMIN`** — holding directory-admin
  does **not** grant raw-payload read. Forensic read is a separately-grantable,
  higher-sensitivity investigator authority (least privilege). A token lacking
  it is the usual opaque `MCPIPDenied`.
- **Access-audited before disclosure.** Every call emits a WORM
  `admin_action='forensic_read'` (who read whose payload) *before* the payload
  crosses the wire. The reconstructed payload is never re-embedded in that WORM
  record.
- **Redacted, tenant-scoped, opaque miss.** The returned `ForensicPayload`
  carries the opaque `alias`, the already-canonicalized `arguments` run through
  the same WORM redaction discipline (pin/jwt/token/secret material is scrubbed
  even here), and non-secret identity context (`agent_id` / `source_format` /
  `transport_class`) — never a real target or a secret. Scope is always the
  admin JWT's own tenant. A `None` / `null` return is an honest, indistinguishable
  miss: the feature is off on this gateway, or the correlation id is unknown,
  expired past its TTL, or owned by another tenant (no cross-tenant existence
  oracle). No agent-facing surface ever references this store.

## 9. Error semantics (both SDKs)

Both hierarchies root at a base class — `MCPIPError` in Python, `McpipError` in
TypeScript — so `except MCPIPError` / `catch (e) { if (e instanceof McpipError) }` catches
everything the SDK raises.

| Python | TypeScript | Wire trigger |
| --- | --- | --- |
| `MCPIPDenied(correlation_id, http_status)` | `McpipDenied` | 403/401/500 opaque envelope; MCP-edge JSON-RPC `-32000` (HTTP 200) |
| `MCPIPInvalidRequest` | `McpipInvalidRequest` | 422 (malformed envelope), 413 (body > 256 KiB), JSON-RPC `-32700/-32600/-32601` |
| `MCPIPUnavailable(retry_after)` | `McpipUnavailable` | 503 + `Retry-After`, timeouts, transport failures |
| `MCPIPNotFound` | *(none — folds into `McpipDenied`)* | Unknown challenge / unsealed event on a live endpoint |
| `MCPIPSandboxOnly` | `McpipSandboxOnly` | Sandbox-only endpoint on a production gateway (404, no body correlation id) |

The one asymmetry is deliberate. TypeScript raises `McpipSandboxOnly` for a 404 **only**
on the routes that legitimately vanish in production; every other 404 folds into the
opaque `McpipDenied`, so a caller cannot use a 404 to distinguish "does not exist" from
"not permitted". Python keeps `MCPIPNotFound` as a distinct type for the same wire
condition. If you write cross-language code, catch the base class.

Invariants: a **staged step-up is a result, not an error** (`Staged`); denial
bodies are exactly `{error, correlation_id}` and the SDK exposes exactly
that; every response echoes `X-MCPIP-Correlation-Id` (used as fallback when a
body is unparseable); **no automatic retries anywhere** — back-off belongs to
the caller.

## 10. TypeScript mirror

`@mcpip/sdk` (in `sdk/typescript`) exposes the same three clients over the same wire
contract. Every method is the Python name in camelCase, with three exceptions noted below.

**`McpipClient`** — `authorize`, `complete`, `catalog`, `mcpCall`, `authzDecision`,
`health`, `ready`, `version`, `license`, `auditAttestation`,
`protectedResourceMetadata`.

**`McpipSandboxClient`** — everything above, plus `devToken`, `devTokenSource`,
`authenticatorCode`, `auditVerify`, `auditProof`.

**`McpipAdminClient`** — skills: `skillsRegister`, `skillsDeregister`, `skillsDisable`,
`skillsEnable`, `skillsRegistered`, `skillsDisabled`. Principals: `principalsRevoke`,
`principalsReactivate`, `principalsRevoked`, `quarantine`, `canaries`. Decisions and
evidence: `decisionsRecent`, `decisionsQuery`, `forensicGet`, `complianceEvidence`,
`stats`. Directory: `directoryGet`, `directoryPut`, `directoryRelations`. Policy:
`policyGet`, `policyPut`, `policyDelete`. Extensions: `submitExtension`,
`extensionsPending`, `extensionApprove`, `extensionReject`, `verifiedPublishers`,
`verifiedPublishersPut`. Users: `usersList`, `usersInvite`, `usersUpdate`, `usersRemove`.
Workspace: `workspaceDraft`, `workspaceValidate`, `workspaceApply`. Cloud and vault:
`cloudEnvironmentsList`, `cloudEnvironmentsPut`, `cloudEnvironmentsDelete`,
`vaultSecretsList`, `vaultSecretsPut`, `vaultSecretsDelete`.

**The three that are not a straight camelCase conversion:** Python's
`extension_submit` is `submitExtension`; Python's `verified_publishers_get` is
`verifiedPublishers`; and Python's `decisions_iter` (a generator that pages
`decisions_query` for you) has no TypeScript equivalent — page it yourself with
`decisionsQuery` and the returned cursor.

Error classes are `McpipError` and its subclasses `McpipDenied`,
`McpipInvalidRequest`, `McpipUnavailable`, `McpipSandboxOnly` — not the `…Error`-suffixed
names. `tests/test_sdk_docs_parity.py` checks every identifier on this page against the
shipped sources, and pins those three exceptions, so the page fails the build rather than
drifting again.

ESM-only, zero runtime dependencies (global `fetch`), `AbortSignal`
passthrough, and the identical no-retry/opaque-deny/token-slack rules. See
`sdk/typescript/README.md` for install and TS-specific notes.

## 11. Testing your integration

`tests/test_sdk_python.py` drives the Python SDK against the REAL in-process
gateway (`httpx.ASGITransport(app=app.main.app)` + the sandbox Redis fixture)
— use it as the reference for wiring your own contract tests. Both SDK
clients accept a custom transport/fetch for exactly this purpose.

```bash
python -m pytest tests/test_sdk_python.py -q
MYPYPATH=sdk/python/src mypy --strict sdk/python/src/mcpip_sdk tests/test_sdk_python.py
```

A gateway also serves `GET {host}/openapi.json` and `/docs` (FastAPI
defaults). Treat them as a route inventory only — response schemas, the
JSON-RPC dialect, and the opaque-denial envelope are documented here and in
`docs/start/GETTING_STARTED.md`, not there.
