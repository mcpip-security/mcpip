<div align="center">

# ◐ MCPIP

### The Authorization Layer for Autonomous AI

**_Authorize every AI action before execution._**

> ## AI Reasons. MCPIP Authorizes. Systems Execute.

[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Pydantic](https://img.shields.io/badge/Pydantic-v2%20strict-E92063?logo=pydantic&logoColor=white)](https://docs.pydantic.dev/)
[![Redis](https://img.shields.io/badge/Redis-7%20async-DC382D?logo=redis&logoColor=white)](https://redis.io/)
[![JWT](https://img.shields.io/badge/JWT-EdDSA%20%2F%20RS256-000000?logo=jsonwebtokens&logoColor=white)](https://pyjwt.readthedocs.io/)
[![Audit](https://img.shields.io/badge/WORM-Merkle--epoch%20Ed25519-4B32C3)](docs/WHITEPAPER.md)
[![Posture](https://img.shields.io/badge/posture-fail--closed-0E8A16)](#security-invariants)
[![Gates](https://img.shields.io/badge/demo-10%2F10%20gates-0E8A16)](#the-10-gate-demo)
[![CI](https://github.com/mcpip-security/mcpip/actions/workflows/ci.yml/badge.svg)](https://github.com/mcpip-security/mcpip/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/core-BSL%201.1-blue)](#license) [![SDKs](https://img.shields.io/badge/SDKs-Apache--2.0-blue)](#license)

</div>

---

## What is MCPIP?

Autonomous agents are getting very good at **deciding what to do**. They are not, and should not be, the thing that **decides whether it is allowed**. MCPIP is the thin, uncompromising layer that sits between an agent's reasoning and the systems that execute — a **zero-trust authorization gateway** for machine-to-machine tool calls.

An agent proposes an action in whatever dialect its framework speaks. MCPIP **normalizes it, resolves the opaque alias to a real target the agent never sees, proves the caller's identity from a signed token, binds high-risk actions to a one-time payload lock, and records an immutable, signed verdict** — before a single byte reaches production. Anything that fails, fails **closed**, and the agent learns only a generic denial plus an opaque correlation id. The reasons live in the audit log, not on the wire.

| Product | One-liner |
|---|---|
| **MCPIP** | The Authorization Layer for Autonomous AI. |
| **Bridge** | One ingress for every agent framework — 7 wire shapes (`openai_tool_call`, `anthropic_tool_use`, `gemini_function_call`, `bedrock_tool_use`, `mcp_jsonrpc`, `raw_mcp`, `a2a_task`) across **82 named vendor ids** — selected by a **declared** `source_format`, never by sniffing. |
| **Connectors** | Pure tool-call **parsers** plus a hash-pinned vendor→format registry. MCPIP never calls the LLM and holds no vendor keys — [the product model](#connectors). |
| **Obfuscator** | Agents call aliases. Real systems stay invisible. |
| **Auth** | A payload-bound PIN that's spent exactly once, or the action never runs. |
| **Audit** | Per-epoch Merkle root, root-chained and Ed25519-signed once per epoch — O(log n)-verifiable inclusion proofs (bounded generation, no full-epoch rescan), tamper-evident by construction. |

---

## What MCPIP enforces — and what it does not

The most useful thing a security component can tell you is where it stops. MCPIP is a
narrow layer on purpose; everything below is either something we enforce or something we
deliberately leave to a system that owns it better.

**MCPIP enforces**

- **Per-call authorization** on the exact payload — not a session, not a scope granted an
  hour ago. Every call is judged on its own arguments.
- **Alias → target resolution.** The agent names an opaque alias; the real target, host and
  credential never cross the boundary.
- **Payload-bound step-up.** A high-risk action stages a one-time code bound to those exact
  canonical bytes. Change one field and the approval no longer covers it.
- **Write-before-execute audit.** The signed WORM record is committed *before* the side
  effect, so the evidence cannot be lost by the thing it was recording.
- **Compartment and capability separation**, and canary aliases that trip on enumeration.

**Your identity provider owns**

- **Who an agent is.** MCPIP only ever *verifies* JWTs — it never mints identity, and the
  `role` claim authorizes nothing. Hosting the gateway does not put us in your trust path
  for authentication.

**Your runtime owns**

- Which files and shells the agent can touch, model choice and billing, and the sandbox it
  executes in. MCPIP governs what reaches *your systems*, not what happens inside the agent.

**MCPIP does not provide**

- An agent execution environment or sandbox
- Model hosting, inference, or any LLM credential — the gateway never calls a model
- A memory or vector store
- An LLM proxy. Tool calls pass through the authorization boundary; **prompts and completions never do.**

---

## Status

Version 3.0.0. Source-available core (BSL 1.1), SDKs Apache-2.0. We would rather tell you
where the edges are than have you find them.

**Works, and is tested**

- The full pipeline — Bridge → Obfuscator → Auth → Audit — fail-closed and opaque end to end
- 7 wire shapes across 82 vendor ids; the registry is hash-pinned and refuses to boot on drift
- Payload-bound one-time step-up; a changed byte is a different request with no approval behind it
- Ed25519 Merkle WORM written before dispatch, plus offline re-verification (`mcpip export-audit --verify`)
- Compartment + capability separation, canary tripwires, ReBAC projection, the operator console
- 1,400+ tests, `mypy --strict`, and a self-verifying 10-gate demo that exits non-zero if any gate fails

**Being wired up**

- Out-of-band approval delivery. The step-up ceremony is complete; the *transport* that reaches a
  human is a documented integration point, and with none configured the gateway fails closed
  (`OTP_DELIVERY_FAILED`) rather than staging a challenge nobody can answer.
- Long-horizon decision retention. Signed epoch roots are durable; the per-decision rows are a
  bounded hot buffer, and a query now reports its own horizon rather than answering an out-of-range
  window with a confident "nothing happened".
- SSO/SAML/SCIM — planned, not shipped. Named here because it appears on pricing pages.

**Deliberately not built**

- No execution sandbox, model hosting, or LLM credential. The gateway never calls a model.
- No identity minting. We verify JWTs; your IdP stays sovereign, and the `role` claim authorizes nothing.
- No inference in the authorization path. Decisions are deterministic — the same input always yields
  the same verdict, which is what makes them replayable and auditable.

---

## Architecture — the request pipeline

Every request walks the same four stages, in the same order, every time. A failure at any stage denies immediately and emits a signed WORM record; the caller receives only `correlation_id`.

```
                    ┌───────────────────────────────────────────────────────────────┐
    LLM / agent     │   proposes a tool-call in its native dialect + a signed JWT     │
   (any of the      │   { "function": { "name": "skill_payroll_run", ... } }  +  Bearer│
    six declared    └───────────────────────────────┬───────────────────────────────┘
    dialects)                                        │  raw_call, token, trace
                                                     ▼
   ◐ ───────────────────────────────────────────────────────────────────────────────── ◐
   │                             M C P I P   G A T E W A Y                                │
   │                        correlation_id = uuid4()  (assigned FIRST)                    │
   │                                                                                      │
   │   ┌──────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐             │
   │   │  BRIDGE  │──▶│  OBFUSCATOR  │──▶│     AUTH      │──▶│    AUDIT     │──▶ dispatch  │
   │   │ normalize│   │ alias→target │   │ JWT identity │   │ durable buf →│             │
   │   │ + schema │   │ tenant-scope │   │   + payload  │   │ signed Merkle│             │
   │   │ rigidity │   │ + compartment│   │  lock (PIN)  │   │ epoch roots  │             │
   │   └────┬─────┘   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘             │
   │        │                │                  │                  │                     │
   │  deny: SCHEMA_     deny: UNKNOWN_    deny: JWT_INVALID   record: ALLOW /             │
   │   VIOLATION /       ALIAS /           JWT_CLAIMS_          DENY (redacted,           │
   │   DEPTH / SIZE /    CROSS_TENANT      MISSING /            payload_hash,             │
   │   ILLEGAL_CHAR /                      PIN_* /              lock code)                │
   │   IDENTITY_                           PAYLOAD_MISMATCH                               │
   │   INJECTION                                                                          │
   ◐ ───────────────────────────────────────────────────────────────────────────────── ◐
                                                     │  AuthorizedIntent + resolved target
                                                     ▼
                                        ┌────────────────────────┐
                                        │       TRANSPORT        │
                                        │  CloudREST  |  Legacy   │
                                        │  (POST)     |  Mainframe│
                                        │             |  cp500    │
                                        │             |  80B frame│
                                        └────────────────────────┘
                                                     │
                                                     ▼
                                    rest.crm.* · mainframe.cics.PAYR · db2.GLPOST
                                    (real targets the agent never learns)
```

**Canonical stage order:** `◐ Bridge → Obfuscator → Auth → Audit`

| Stage | Module | What it guarantees |
|---|---|---|
| **Bridge** | `bridge/intent_parser.py` · `bridge/connectors/` | Any provider tool-call → one `NormalizedIntent`. The parser is selected by the **declared** `source_format` (or the pinned vendor→format registry) — never by inspecting payload bytes. Deep schema rigidity, size/depth caps, illegal-character rejection, identity-injection hard-deny. |
| **Obfuscator** | `obfuscator/alias_registry.py` | Tenant-scoped `alias → target`. Agents call `skill_payroll_run`; they never see `mainframe.cics.PAYR`. Unknown/cross-tenant → deny. |
| **Auth** | `auth/token_resolver.py` · `auth/pin_validator.py` | Identity comes **only** from a verified JWT (EdDSA/RS256). High-risk actions require a 6-digit PIN bound to the SHA-256 of the canonical payload, consumed **exactly once** via a single Redis Lua `EVAL`. |
| **Audit** | `audit/worm_logger.py`, `audit/merkle.py` | Every decision is durably buffered (Redis Stream, AOF `appendfsync always`) **before** the action is authorized, then sealed into per-epoch Merkle roots that are root-chained and Ed25519-signed **once per epoch**. `verify_chain()` returns `(intact, first_bad_epoch)` and detects any event OR root mutation (every persisted header field, including the stream-id range, is signed), and accepts a trusted `checkpoint=(epoch, epoch_hash)` to re-verify only newer epochs; `inclusion_proof()` gives an O(log n)-verifiable Merkle path whose generation reads a per-epoch precomputed leaf-digest vector plus the single target event (never a full-epoch rescan). Steady-state storage and full-verify cost stay bounded: `compact()` folds fully-verified old epochs into one Ed25519-signed super-checkpoint (trimming their headers and rotating the anchor file), and each close seals a bounded leaf chunk with the Merkle build offloaded off the event loop. Legacy per-event chain remains behind `mode="per_event"` for migration. |

---

## Connectors

### The product model — an interceptor, never a proxy

MCPIP is an **authorization interceptor, not an LLM proxy**. The end user's client application calls its LLM **directly, with its own API keys and its own billing — credits stay with the end user**. MCPIP never sits between the client and the model: it receives only the *resulting tool-call payload*, authorizes it, and (on ALLOW) executes it through the transport table.

That model makes every connector a **pure parser** of a tool-call wire shape:

- **MCPIP never calls any LLM or vendor API** and **holds no LLM/vendor keys** — `bridge/connectors/bedrock.py` parses the Bedrock Converse `toolUse` shape; it does **not** call AWS (no boto3, no credentials, ever).
- **No connector opens any outbound network connection.** This is mechanically enforced: `tests/test_connector_conformance.py` AST-scans every module under `bridge/connectors/` and fails the build on any LLM-SDK, HTTP-client, `socket`, or env-var-credential import. A connector that imports an LLM SDK or dials out is a **defect**, not a feature.
- Connectors do **extraction and shape-mapping only** — no relaxed validation of their own. Every parser feeds a candidate `{alias, arguments, source_format}` into the **single** normalizer, so `NormalizedIntent` stays the one strict internal boundary (`extra="forbid"` + strict, depth ≤ 8, canonical 16 KiB cap, node ceiling, unicode scrubbing, and the identity-injection hard-deny) in **every** format.

### The seven wire formats

| `source_format` | Accepted wire unit | Parser (`bridge/connectors/formats.py`) |
|---|---|---|
| `openai_tool_call` | `{"id","type":"function","function":{"name","arguments":"<JSON string>"}}` — arguments decoded exactly once, behind a pre-parse length cap | `parse_openai` |
| `anthropic_tool_use` | `{"type":"tool_use","id","name","input"}` | `parse_anthropic` |
| `gemini_function_call` | the bare `{"functionCall":{"name","args"}}` **part** object (a `parts` array or full `candidates` response is a schema violation — one call per request) | `parse_gemini` |
| `bedrock_tool_use` | Bedrock Converse `{"toolUse":{"toolUseId","name","input"}}` block — **parse only, never calls AWS** | `parse_bedrock` |
| `mcp_jsonrpc` | JSON-RPC 2.0 `tools/call` request (`{"jsonrpc":"2.0","id",…,"method":"tools/call","params":{…}}`) | `parse_mcp` |
| `raw_mcp` *(legacy)* | canonical `{"tool","arguments"}` — kept for the frozen legacy ingress, **not** vendor-mapped | `parse_raw_mcp` |
| `a2a_task` | A2A `Task` envelope carrying **exactly one** `DataPart` invocation (`data.skill` → alias, `data.arguments` → arguments) — a task with zero or several invocations is a hard schema violation, never a guess | `parse_a2a_task` |

### Format is declared, never guessed

The ingress selects a parser by an **explicit `source_format`** carried in the request envelope — never by inspecting the payload bytes. Content sniffing is a correctness/consistency hazard (two components guessing differently about the same bytes), the same discipline as pinning the JWT algorithm. Exactly **one** of `source_format` / `vendor` must be supplied on `POST /v1/authorize` — never both, never neither (neither → fail-closed `422`). An unknown `source_format` or vendor is a fail-closed deny: the WORM log records `unknown_format` / `unknown_vendor`; the wire sees only the opaque `403`.

A caller declares the format directly:

```json
{
  "source_format": "gemini_function_call",
  "tool_call": {"functionCall": {"name": "skill_spend_summary", "args": {"period": "2026-Q2"}}}
}
```

or declares its **vendor** and lets the pinned registry resolve the format:

```json
{
  "vendor": "gemini",
  "tool_call": {"functionCall": {"name": "skill_spend_summary", "args": {"period": "2026-Q2"}}}
}
```

Copy-paste runnable (sandbox up as in [Quickstart](#quickstart), API on `:8080`):

```bash
API=http://localhost:8080
JWT=$(curl -s -X POST $API/v1/dev/token -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-acme","agent_id":"agent-orchestrator-1","role":"ops"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')

# Declared source_format — Gemini functionCall part object → 200 executed.
curl -s -X POST $API/v1/authorize -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d '{
    "source_format":"gemini_function_call",
    "tool_call":{"functionCall":{"name":"skill_spend_summary","args":{"period":"2026-Q2"}}}
  }'

# Declared vendor — the hash-pinned registry resolves gemini -> gemini_function_call.
curl -s -X POST $API/v1/authorize -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d '{
    "vendor":"gemini",
    "tool_call":{"functionCall":{"name":"skill_spend_summary","args":{"period":"2026-Q2"}}}
  }'

# Unknown vendor → opaque 403 (WORM reason: unknown_vendor). Neither field → 422.
curl -s -o /dev/null -w '%{http_code}\n' -X POST $API/v1/authorize \
  -H "authorization: Bearer $JWT" -H 'content-type: application/json' \
  -d '{"vendor":"totally_unknown","tool_call":{"functionCall":{"name":"x","args":{}}}}'
```

### The vendor → format registry

`bridge/connectors/registry.py` binds each vendor id to exactly one format. The mapping is a Python constant, **hash-pinned at import** (`REGISTRY_VERSION` + a SHA-256 over the canonical JSON of the map): any edit without a deliberate re-pin + version bump refuses to boot — a gateway with an inconsistent connector table fails closed rather than serve. Lookups are exact-string, no casefolding, no aliasing.

82 vendor ids across 6 wire shapes (`REGISTRY_VERSION=4`). Every id beyond the
original providers is a **pure alias onto an existing parser** — new names, no new
parsing code, and no change to any pre-existing binding.

| Vendor id(s) | Resolves to `source_format` |
|---|---|
| **Frontier labs:** `openai` · `azure_openai` · `copilot` · `deepseek` · `qwen` · `ernie` · `kimi` · `moonshot` | `openai_tool_call` |
| **Inference clouds:** `mistral` · `groq` · `together` · `fireworks` · `openrouter` · `xai` · `zhipu` · `glm` · `minimax` · `perplexity` · `cerebras` · `sambanova` · `nvidia_nim` · `deepinfra` · `nebius` | `openai_tool_call` |
| **Self-hosted runtimes:** `ollama` · `vllm` · `sglang` · `llama_cpp` · `lmstudio` · `tgi` · `localai` | `openai_tool_call` |
| **Enterprise platforms:** `databricks` · `watsonx` · `snowflake_cortex` | `openai_tool_call` |
| **Gateways / routers:** `litellm` · `portkey` · `cloudflare_workers_ai` · `vercel_ai_gateway` · `github_models` | `openai_tool_call` |
| `claude` · `claude_bedrock` · `claude_vertex` (Bedrock- and Vertex-hosted Claude emit the identical `tool_use` block) | `anthropic_tool_use` |
| `gemini` · `vertex` | `gemini_function_call` |
| `bedrock` | `bedrock_tool_use` |
| **MCP hosts** — editors/IDEs/terminals/coding agents: `mcp` · `claude_code` · `cursor` · `windsurf` · `zed` · `vscode` · `jetbrains` · `continue` · `cline` · `roo` · `kilocode` · `opencode` · `codex` · `gemini_cli` · `goose` · `openhands` · `amp` · `crush` · `warp` · `openclaw` | `mcp_jsonrpc` |
| **MCP platforms:** `chatgpt` · `copilot_studio` · `librechat` · `openwebui` · `n8n` · `dify` · `langflow` · `flowise` | `mcp_jsonrpc` |
| **MCP-client agent frameworks:** `langgraph` · `crewai` · `autogen` · `openai_agents` · `pydantic_ai` · `llamaindex` · `semantic_kernel` · `mastra` · `strands` | `mcp_jsonrpc` |
| `a2a` (A2A `Task` envelope) | `a2a_task` |

Note the deliberate near-collisions: `claude_bedrock`/`claude_vertex` bind to the
**Anthropic** parser (the host changes, the wire shape does not) while raw
`bedrock`/`vertex` keep their own native dialects. `grok` is *not* a vendor id —
xAI's is `xai`, and an unrecognized string is a fail-closed `UNKNOWN_VENDOR` deny,
never a guess.

### The MCP-native edge — `POST /v1/mcp`

For MCP-speaking clients (Claude Code, Cursor, Windsurf, any MCP host), MCPIP **is the MCP server the client connects to**. The edge is an **authorization boundary, not a proxy**: it never forwards to an external MCP server, opens no outbound connection, and holds no keys — after ALLOW, dispatch goes through the same internal transport table as `/v1/authorize`.

One JSON-RPC 2.0 endpoint (Streamable-HTTP-compatible single-request mode), identity via `Authorization: Bearer` only:

| `method` | Behaviour |
|---|---|
| `initialize` | No auth; static server card (`protocolVersion`, `serverInfo`) — no tenant data. |
| `notifications/initialized` | No auth; HTTP `202`, empty body. |
| `tools/list` | JWT-gated; same visibility filtering as `GET /v1/catalog` — aliases + metadata only, never targets. |
| `tools/call` | JWT-gated; the full JSON-RPC body runs the shared authorize pipeline as `mcp_jsonrpc`. |

```bash
# MCP-native tools/call — same JWT, same pipeline, JSON-RPC framing.
curl -s -X POST $API/v1/mcp -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d '{
    "jsonrpc":"2.0","id":1,"method":"tools/call",
    "params":{"name":"skill_spend_summary","arguments":{"period":"2026-Q2"}}
  }'
```

A deny on this edge is an HTTP `200` JSON-RPC **error** carrying only the generic message + `correlation_id` — the same opacity as the REST `403`; concrete reasons live only in the WORM log. A JSON-RPC batch (top-level array) is rejected: one authorize request authorizes exactly one tool call. A `pin_required` alias stages a challenge whose step-up completes via `POST /v1/authorize` with `source_format="mcp_jsonrpc"` and the identical JSON-RPC dict — the payload lock is format-independent.

---

## Security invariants

These are non-negotiable. They hold on every request, or the request does not run.

| # | Invariant | Mechanism | Enforced in |
|---|---|---|---|
| 1 | **Timing safety** | `secrets.compare_digest` for every token / hash / secret / signature comparison. PIN + payload equality happen server-side inside the Lua `EVAL` (zero Python check-then-act). | `interfaces.py`, `auth/*`, `audit/worm_logger.py` |
| 2 | **TOCTOU payload lock** | 6-digit PIN bound to `sha256(canonical_json(tenant, agent, alias, arguments))`. Fetch + compare + delete in **one atomic Redis Lua `EVAL`**. Only the PIN hash is stored, never the raw PIN. One byte of payload drift → instant `PAYLOAD_MISMATCH`. | `auth/pin_validator.py` |
| 3 | **Deep schema rigidity** | Every ingress model (incl. **all** nested) uses `ConfigDict(extra="forbid", strict=True)`. Depth ≤ 8, ≤ 64 keys/object, ≤ 256 elems/array, ≤ 16 KiB canonical args. Control, bidi-override (`U+202A–202E`, `U+2066–2069`) and zero-width chars rejected. | `interfaces.py`, `bridge/intent_parser.py` |
| 4 | **M2M identity sovereignty** | `tenant_id` / `agent_id` / `role` come **exclusively** from a verified JWT. `alg=none` and HMAC-confusion rejected; `exp/iat/nbf/iss/aud` + the 3 identity claims required. Any identity- or **capability**-shaped key in the tool-call payload (`tenant_id`, `role`, `capabilities`, `entitlement`, …) is a **hard deny**, not a strip. The `role` claim is validated but **descriptive only** — it authorizes nothing; entitlements come only from the JWT `capabilities` claim / Redis grants. | `auth/token_resolver.py`, `bridge/intent_parser.py` |
| 4b | **UUID capabilities & compartments — never roles** | Privileged actions (e.g. issuing a compartment grant) gate on **capability UUIDs** carried in the JWT `capabilities` claim (strict UUID list, size-bounded) and/or Redis-held grants — never a role string. Compartmented aliases (compartment UUID) deny `compartment_denied` unless the caller holds a direct JWT compartment claim or an active, unexpired delegated grant; `GET /v1/catalog` filters so an agent cannot even enumerate another team's classified MCP. Grant issuance is itself an authorization-gated, payload-bound EXECUTE mandate. | `interfaces.py`, `auth/token_resolver.py`, `obfuscator/alias_registry.py`, `services/grant_store.py`, `services/obfuscator.py` |
| 5 | **Fail-closed, opaque errors** | Any parse / validation / lookup / lock failure denies immediately. The caller receives only a generic message + `correlation_id` (uuid4). Full diagnostics go **only** to the WORM log — no stack traces, paths, key names, or topology leak. | `interfaces.py` (`MCPIPDenied`), `main.py` |
| 6 | **Stateless nodes** | All synchronization state (payload locks, WORM event buffer, monotonic seq, signed epoch chain, event-location index, delegated grants, append/epoch locks) lives in Redis via `redis.asyncio`. No module-level mutable auth state. | `main.py`, `auth/pin_validator.py`, `audit/worm_logger.py`, `services/grant_store.py` |
| 7 | **Zero placeholders** | No TODO/FIXME, no stub bodies, no "rest of code". Every line is implemented and production-grade. | *entire codebase* |

---

## Repository layout

```
mcpip-genesis/
│
├── interfaces.py            ◐ Shared primitives: models, enums, limits,
│                              canonical_json, reject_unsafe_string, ABCs, MCPIPDenied
├── main.py                  ◐ MCPIPGateway pipeline + the 10-gate demo  (python main.py)
├── requirements.txt         ◐ Pinned deps: pydantic · redis · PyJWT · cryptography
│                              · fastapi · uvicorn · pydantic-settings
│
├── bridge/                  ── Stage 1 · normalize any provider tool-call
│   ├── __init__.py
│   ├── intent_parser.py         declared-format dispatch → NormalizedIntent;
│   │                            enforce_argument_safety walker + identity hard-deny
│   ├── errors.py                bridge deny taxonomy (UnknownFormat, UnknownVendor, …)
│   ├── fastwalk.py              opt-in Rust fast-walk shim (MCPIP_FAST_WALKER=1;
│   │                            byte- and decision-identical, pure-Python default)
│   └── connectors/              PURE tool-call parsers — no SDKs, no keys, no network
│       ├── base.py                  Candidate + FormatParser protocol (no logic)
│       ├── formats.py               the real parsers: openai / anthropic / gemini /
│       │                            bedrock / mcp_jsonrpc / raw_mcp
│       ├── registry.py              hash-pinned vendor→format registry (fail-closed boot)
│       └── openai.py · claude.py · gemini.py · bedrock.py · mcp_standard.py
│           · copilot.py · deepseek.py · qwen.py · ernie.py    (vendor bindings)
│
├── obfuscator/              ── Stage 2 · resolve tenant-scoped alias → real target
│   ├── __init__.py
│   └── alias_registry.py        bi-directional alias↔target, fail-closed
│
├── auth/                    ── Stage 3 · identity + canonical payload lock
│   ├── __init__.py
│   ├── token_resolver.py        JWT identity sovereignty (EdDSA/RS256, 8 claims)
│   └── pin_validator.py         6-digit payload-bound PIN, exactly-once Redis Lua EVAL
│
├── audit/                   ── Stage 4 · tamper-evident decision ledger
│   ├── __init__.py
│   ├── merkle.py                Pure Merkle primitives (domain-separated leaf/node, root, O(log n) proofs)
│   └── worm_logger.py           Durable Redis-Stream buffer → per-epoch signed Merkle roots; verify_chain / inclusion_proof
│
├── app/                     ◐ HTTP edge · FastAPI service (uvicorn app.main:app)
│   ├── __init__.py
│   └── main.py                  POST /v1/authorize + /healthz + /readyz (+ sandbox)
├── core/                    ── API config + boundary primitives
│   ├── __init__.py
│   ├── config.py                MCPIP_* Settings (pydantic-settings)
│   └── security.py              new_correlation_id, GatewayDeny, map_engine_exception
├── models/                  ── API request/response schemas (strict Pydantic v2)
│   ├── __init__.py
│   └── schemas.py               AuthorizeRequest, StagedChallenge, ExecutionReceipt, …
├── services/                ── Thin engine adapters (reuse, never reimplement)
│   ├── __init__.py
│   ├── auth_engine.py           TokenResolver + PinValidator + sandbox OTP
│   └── obfuscator.py            fail-closed alias resolution pass-through
│
├── dashboard/               ◐ Dark operator dashboard (Vite · React · TS · Tailwind)
│   ├── index.html               dark-mode shell (no marketing landing page)
│   ├── package.json             npm run dev / build / preview
│   └── src/                     main.tsx · index.css
│
├── docs/
│   ├── WHITEPAPER.md            Threat model, invariants, and the formal argument
│   └── IMPLEMENTATION_WEB.md    Web / implementation companion
├── SECURITY_THREAT_MODEL.md ◐ Formal adversary model + attack→defense→code matrix
│
├── Dockerfile               ◐ Multi-stage: 3.12-slim builder venv → non-root runtime
├── docker-compose.yml       ◐ gateway API + redis, internal redis, hardened edge
└── .dockerignore            ◐ Keep the image to "app + venv" — no secrets, no data
```

---

## Quickstart

**Free forever self-host (BSL source-available) · no demo call · sandbox in one command.**

Three concepts are enough to start: **Connect** (point your agent at one URL — the
gateway *is* an MCP server), **Protect** (skills = opaque aliases with risk tiers),
**Approve** (high-risk calls stage a payload-bound one-time PIN). Everything else —
tenants, compartments, canaries, editions — can wait until you need it.

```bash
# ONE blessed path — clone, then bring up the whole sandbox (Redis + gateway +
# a live governed walkthrough) and print your zero→first-governed-call time.
# Self-contained, idempotent, macOS/Linux — nothing to install first.
git clone https://github.com/mcpip-security/mcpip.git && cd mcpip
./scripts/quickstart_demo.sh
```

Prefer a CLI? Install it (`curl -fsSL https://raw.githubusercontent.com/mcpip-security/mcpip/main/install.sh | bash`, or
`pipx install ./sdk/python` — see [Release, Packaging & Verification](#release-packaging--verification)) and run
`mcpip up` for the exact same thing.

Then **connect any MCP client** — one URL, the same pipeline (in sandbox, mint a JWT
with `mcpip sandbox dev-token` or `POST /v1/dev/token`):

```json
{ "mcpServers": { "mcpip": {
    "type": "http",
    "url": "http://localhost:8080/v1/mcp",
    "headers": { "Authorization": "Bearer <jwt>" } } } }
```

Or zero-to-authorized in **three CLI commands**:

```bash
mcpip login --gateway http://localhost:8080 --sandbox --context sbx
mcpip --context sbx sandbox dev-token --agent demo
mcpip --context sbx authorize skill_spend_summary --arg period=2026-Q2
```

<details>
<summary><b>Manual setup (reference)</b> — the same stack by hand</summary>

Every command below is copy-paste runnable from the repository root. The gateway reads `MCPIP_REDIS_URL` (default `redis://localhost:63790/0`).

```bash
# Redis (host port 63790 -> container 6379); reuse if the container already exists
docker run -d --name mcpip-v2-redis -p 63790:6379 redis:7-alpine \
  || docker start mcpip-v2-redis

/opt/homebrew/bin/python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export MCPIP_REDIS_URL=redis://localhost:63790/0   # default; optional
python main.py         # runs the 10-gate demo, exits 0 iff all hold
```

The `docker run ... || docker start ...` idiom **creates** the `mcpip-v2-redis` container the first time and **reuses** it on every subsequent run. `python main.py` exits `0` only if all ten gates hold.

</details>

### Run the HTTP API

The same engine is served over HTTP by the FastAPI app in `app/main.py`. From the repo root, with the venv active and Redis up on `63790`:

```bash
# Serves POST /v1/authorize, GET /healthz, GET /readyz (+ sandbox helpers).
uvicorn app.main:app --host 0.0.0.0 --port 8080

# In another shell — liveness + readiness:
curl -s http://localhost:8080/healthz   # {"status":"live","glyph":"◐"}
curl -s http://localhost:8080/readyz    # {"status":"ready","redis":"up"}
```

In sandbox mode (`MCPIP_SANDBOX_MODE=true`) the app boots an ephemeral in-process IdP and WORM signing key, so it is runnable end-to-end with no external secrets — see [HTTP API](#http-api) for the full step-up walkthrough. **`sandbox_mode` defaults to `false` (secure-by-default) everywhere** — the bare `uvicorn` process, the shipped Docker image, and Compose: the sandbox helper endpoints stay unmounted and the gateway fails closed at boot unless real PEM paths are supplied. Opt into the demo explicitly with `MCPIP_SANDBOX_MODE=true` (e.g. `MCPIP_SANDBOX_MODE=true docker compose up gateway`); a loud banner is logged whenever the sandbox affordances are mounted. Run sandbox with a **single** uvicorn worker (the in-process demo IdP / WORM keys are per-process); multi-worker deployments must supply shared PEM key files (the production posture).

### Run the operator dashboard

```bash
cd dashboard
npm install
npm run dev            # dark operator dashboard on http://localhost:5173
# Production build (static assets in dashboard/dist):
npm run build
```

### Talk to the gateway — SDKs + the `mcpip` CLI

Two Apache-2.0 client libraries wrap the same wire contract: a typed Python
client (`sdk/python`, distribution `mcpip-sdk`) and a zero-dependency
TypeScript/ESM client (`sdk/typescript`, `@mcpip/sdk`). Both are fail-closed and
opaque — a deny surfaces only a `correlation_id` — and never auto-retry.

Installing `mcpip-sdk` also puts the **`mcpip` CLI** on your PATH (the command
you *run*, wrapping the typed clients — like `gh` / `kubectl` / `vault`). Zero to
an authorized call in three commands:

```bash
pipx install ./sdk/python                                  # or: brew install --HEAD mcpip/tap/mcpip
mcpip login --gateway http://localhost:8080 --sandbox --context sbx
mcpip --context sbx sandbox dev-token --agent agent-quickstart   # sandbox identity, never printed
mcpip --context sbx authorize skill_spend_summary --arg period=2026-Q2
```

`--json` for scripting, `--quiet` for the load-bearing id only, stable exit codes
(a deny is `3`), secrets never on stdout/argv. Full reference:
[`docs/CLI.md`](./docs/CLI.md) · library guide: [`docs/SDK.md`](./docs/SDK.md).

---

## The 10-gate demo

`python main.py` runs an executable proof: three allow-paths and seven attacks, each printing `PASS` / `FAIL`. The process exits `0` **only if every gate holds**, then re-reads the WORM log and asserts `verify_chain()` is intact.

| # | Scenario | Setup | Expectation |
|---|---|---|---|
| 1 | Happy AUTO | valid JWT, `skill_spend_summary`, no PIN | **ALLOW**, transport ok |
| 2 | Happy PIN_REQUIRED | register lock (pin `483920`) for `skill_payroll_run`, consume with same pin + payload | **ALLOW**, mainframe frame len 80 |
| 3 | PIN replay | re-consume the lock from #2 | **DENY** — `PIN_NOT_FOUND` (code −1) |
| 4 | Payload byte-tamper | register lock, consume with one byte changed | **DENY** — `PAYLOAD_MISMATCH` (−3), lock still alive |
| 5 | Extra / oversize field | arguments carry an unexpected key or exceed limits | **DENY** — `SCHEMA_VIOLATION` / `SIZE_EXCEEDED` |
| 6 | Forged JWT signature | tamper the token payload after signing | **DENY** — `JWT_INVALID` |
| 7 | `alg=none` token | craft an unsigned `{"alg":"none"}` token | **DENY** — `JWT_INVALID` |
| 8 | Identity injection | arguments include `"tenant_id":"evil"` | **DENY** — `IDENTITY_INJECTION` |
| 9 | Unknown alias | `skill_does_not_exist` | **DENY** — `UNKNOWN_ALIAS` |
| 10 | Cross-tenant | globex JWT requests `skill_payroll_run` | **DENY** — `CROSS_TENANT` |
| C1 | Compartment own | falcon JWT (`compartment=FALCON`) → `skill_airframe_telemetry` | **ALLOW** |
| C2 | Compartment cross | aegis JWT (`compartment=AEGIS`) → `skill_airframe_telemetry` | **DENY** — `COMPARTMENT_DENIED` |
| C3 | Un-compartmented | aegis JWT (no compartment) → `skill_status_probe` | **ALLOW** (back-compat) |
| C4 | Grant issue | holder of `CAP_COMPARTMENT_GRANT` **+** the FALCON-scoped `grant_capability_for(FALCON)` issues a step-up-gated FALCON grant | **ALLOW**, grant written |
| C5 | Delegated grant | grantee reaches `skill_airframe_telemetry` via the active grant | **ALLOW** |
| C6 | Capability missing | principal without the capability issues a grant | **DENY** — `CAPABILITY_DENIED` |
| C7 | Grant expiry/revoke | grant removed, grantee retries | **DENY** — `COMPARTMENT_DENIED` |
| C10 | Cross-compartment grant | FALCON-scoped holder tries to grant a **different** compartment (AEGIS) | **DENY** — `CAPABILITY_DENIED` (issuance is compartment-scoped; no tenant-wide master key) |
| C8 | Catalog filter | falcon agent lists visible skills | falcon + tenant-wide only; **no** aegis/sentinel |
| C9 | WORM epoch integrity | `close_epoch()` → `verify_chain()` + every event's inclusion proof | `(True, None)` + all proofs verify |

Expected terminal transcript — verbatim `python main.py` output (correlation ids are opaque uuid4; `…` is display truncation only):

```
◐ MCPIP V2 — Authorize every AI action before execution.
  AI Reasons. MCPIP Authorizes. Systems Execute.
  Redis: redis://localhost:63790/0   WORM: ./mcpip_worm.jsonl
  Pipeline: ◐ Bridge → Obfuscator → Auth → Audit
--------------------------------------------------------------------
  [PASS] 1 AUTO spend_summary       ALLOW rest.ledger.spend.summary 200
  [PASS] 2 PIN payroll_run          ALLOW mainframe.cics.PAYR RC=0 frame=80B
  [PASS] 3 PIN replay               DENY corr=a3facf… reason=pin_not_found
  [PASS] 4 payload tamper           DENY corr=fe08ba… reason=payload_mismatch
  [PASS] 4b lock survived           correct retry code=1
  [PASS] 5 schema/oversize          DENY corr=d887d5… reason=size_exceeded
  [PASS] 6 forged JWT               DENY corr=403534… reason=jwt_invalid
  [PASS] 7 alg=none                 DENY corr=8a0e84… reason=jwt_invalid
  [PASS] 8 identity injection       DENY corr=a20930… reason=identity_injection
  [PASS] 9 unknown alias            DENY corr=9a2864… reason=unknown_alias
  [PASS] 10 cross-tenant            DENY corr=065488… reason=cross_tenant
  [PASS] C1 compartment own         ALLOW rest.falcon.telemetry.get 200
  [PASS] C2 compartment cross       DENY corr=18eb00… reason=compartment_denied
  [PASS] C3 uncompartmented ok      ALLOW rest.health.status.get 200
  [PASS] C4 grant issue             ALLOW grant_id=76191fa6…
  [PASS] C5 delegated grant         ALLOW rest.falcon.telemetry.get (via grant)
  [PASS] C6 capability missing      DENY corr=db2122… reason=capability_denied
  [PASS] C7 grant expired           DENY corr=f60dda… reason=compartment_denied
  [PASS] C10 cross-compartment grant denied DENY corr=8a6069… reason=capability_denied
  [PASS] C10b mole cannot reach AEGIS alias DENY corr=cca00f… reason=compartment_denied
  [PASS] C8 catalog filter          visible=4 (falcon+tenant-wide, no aegis/sentinel)
  [PASS] C9 WORM epoch verify       INTACT (Merkle-epoch, signed root chain)
--------------------------------------------------------------------
exit 0 — all gates held. ◐
```

---

## HTTP API

The gateway exposes the four-stage pipeline over one endpoint, `POST /v1/authorize`, plus liveness/readiness probes and two sandbox-only helpers. The agent boundary is opaque by construction: every denial returns the same generic message and a `correlation_id` (uuid4), echoed on every response in the `X-MCPIP-Correlation-Id` header. Concrete reasons live only in the WORM log.

| Method · Path | Purpose | Status codes |
|---|---|---|
| `POST /v1/authorize` | Authorize (and, on ALLOW, execute) one tool-call. Exactly one of `source_format` / `vendor` declares the dialect. | `200` executed · `202` staged · `403` denied · `422` malformed · `500` fail-closed |
| `POST /v1/mcp` | The [MCP-native edge](#the-mcp-native-edge--post-v1mcp) — JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`). An authorization boundary, **not** a proxy. | `200` (JSON-RPC result *or* error) · `202` (initialized notification) |
| `GET /healthz` | Liveness (no dependency check). | `200` |
| `GET /readyz` | Readiness — pings Redis. | `200` ready · `503` not-ready |
| `GET /v1/catalog` | JWT-gated — lists the skills the caller may **see** (un-compartmented, own-compartment, or granted). Metadata only (`alias`, `risk_tier`, `transport_class`, `classification`, `compartment`) — never the target. | `200` · `403` |
| `GET /v1/authenticator/{challenge_id}` | **Sandbox only** — stands in for the enrolled authenticator delivering the OTP. `404` when `MCPIP_SANDBOX_MODE=false`. | `200` · `404` |
| `GET /v1/audit/verify` | **Sandbox only** — force an epoch close, then `verify_chain()`. Returns `{intact, first_bad_epoch}`. | `200` · `404` |
| `GET /v1/audit/proof/{event_id}` | **Sandbox only** — O(log n) inclusion proof of a buffered event to its signed epoch root. | `200` · `404` |
| `POST /v1/dev/token` | **Sandbox only** — mints a demo JWT (optional `compartment` + `capabilities` UUID claims) so the artifact is runnable end-to-end. `404` in production. | `200` · `404` |

### `POST /v1/authorize`

**Request** (identity may instead be supplied as `Authorization: Bearer <jwt>`; `pin` and `challenge_id` must be supplied together):

```json
{
  "source_format": "openai_tool_call",
  "tool_call": {"id":"call_1","type":"function","function":{"name":"skill_wire_transfer","arguments":"{\"payee\":\"enrolled:ACME_PAYROLL\",\"amount_cents\":2418000}"}},
  "trace": {"trace_id":"6f1c...uuid","hops":[{"hop_index":0,"agent_id":"agent-orchestrator-1","parent_agent_id":null,"purpose":"pay run"}]},
  "pin": null,
  "challenge_id": null
}
```

`tool_call` is the raw provider envelope in the **declared** dialect (`openai_tool_call` / `anthropic_tool_use` / `gemini_function_call` / `bedrock_tool_use` / `mcp_jsonrpc` / legacy `raw_mcp`); the Bridge is the authoritative deep validator, so it is passed through as-is. Exactly one of `source_format` / `vendor` must be present — the format is [declared, never guessed](#format-is-declared-never-guessed). `trace` is optional — a single-hop trace is synthesized from the verified `agent_id` when omitted.

**`200 ExecutionReceipt`** — an AUTO alias, or a completed step-up. `executed_target_class` is the coarse transport class only; the real target never crosses the boundary:

```json
{"correlation_id":"9f2c41a7e83b4d15a0c6f7b2e5d81a3c","decision":"allow","status":"committed","transaction_ref":"txn_4c8a1e0b7d2f4906","executed_target_class":"cloud_rest","worm_sequence":42}
```

**`202 StagedChallenge`** — a `pin_required` alias submitted with no PIN. No ALLOW is emitted; the caller must approve out-of-band, obtain the one-time code, and resubmit:

```json
{"correlation_id":"9f2c41a7e83b4d15a0c6f7b2e5d81a3c","action_required":"Step-up required: approve in your enrolled authenticator to obtain a one-time code, then resubmit with pin + challenge_id.","challenge_id":"b7e14d92c3a04f6685d1097fae2b3c48","risk_tier":"pin_required"}
```

**`403 ErrorResponse`** — any policy denial (replay, tamper, jwt, cross-tenant, injection, unknown alias, pin mismatch, `compartment_denied`, `capability_denied`). Opaque by design:

```json
{"error":"MCPIP: request denied by policy.","correlation_id":"9f2c41a7e83b4d15a0c6f7b2e5d81a3c"}
```

### The staged-challenge (step-up) flow

High-risk aliases (`skill_payroll_run`, `skill_ledger_posting`, `skill_wire_transfer`, `skill_emergency_reset`) are `pin_required` and consume a payload-bound, exactly-once lock:

1. **Stage** — `POST /v1/authorize` with the high-risk alias and no `pin` → **`202`** carrying a `challenge_id`. The one-time code is delivered **out-of-band** (never in the `202` body).
2. **Complete** — resubmit the *same* payload with `pin` + `challenge_id` → **`200`** executed. The lock is spent atomically in a single Redis Lua consume.
3. **Replay** — the same `(pin, challenge_id, payload)` again → **`403`** (`pin_not_found`; the lock is already spent).
4. **Tamper** — a fresh challenge, then one byte of the payload drifts after staging → **`403`** (`payload_mismatch`; the lock survives, so a correct-payload retry still consumes it).

#### Out-of-band delivery — the authenticator channel

How the one-time code reaches the operator is a **pluggable delivery seam**, not part of the lock. `register_lock` still mints the code with `secrets` and still registers the payload-bound scrypt lock **unchanged**; only the *delivery* of the code lives behind a `BaseAuthenticatorChannel` (`interfaces.py` §1.5b → `services/authn_channel.py`) — the channel is strictly downstream of registration and never touches how the OTP is derived or bound.

- **Sandbox** wires `SandboxRedisAuthenticatorChannel` — the runnable-demo stand-in that stashes the code under a tenant-scoped Redis key and reads it back via the sandbox-only `GET /v1/authenticator/{challenge_id}` endpoint (unchanged behavior).
- **Production** wires `WebhookAuthenticatorChannel` — the one real channel. It **pushes** the notice (including the raw code) to your tenant-configured authenticator/approver sink over an **SSRF-guarded, HMAC-SHA256-signed HTTPS** request and **persists no OTP anywhere** (the code exists only in flight). The guard is enforced per delivery: https-only; the host is resolved and refused if **any** resolved address is private/loopback/link-local (covers `169.254.169.254` cloud metadata)/reserved/multicast/unspecified; the connection is **pinned to the validated IP** (defeating DNS-rebinding) while the original hostname drives SNI/cert verification; redirects are not followed; the timeout is bounded; a non-2xx is a failure. Activate it by setting **both** `MCPIP_AUTHN_WEBHOOK_URL` and `MCPIP_AUTHN_WEBHOOK_SECRET_PATH` (see [Configuration](#configuration)).

Delivery is **fail-closed**. With no channel configured (an unconfigured production deploy) or a channel whose delivery raises, `register_lock` denies `otp_delivery_failed` **before any `202`/`challenge_id` is produced** — a `pin_required` action can never silently allow or stage a challenge no authenticator can answer. The raw code never enters the `202`, the audit `ctx`, or the WORM log (and `otp` is in the WORM redaction set as defense-in-depth). Setting exactly one of the two webhook settings is a fail-closed **boot** error; an AUTO-only deployment leaves both unset.

### Deny-only policy overlay — velocity caps & amount ceilings

An optional, **stateless, deny-only** policy step (`services/policy_engine.py`, `VelocityAmountPolicyEngine`) runs on the hot path **after** the entitlement/sender-constraint gates and **before** the risk gate (identically ordered in both entrypoints). It can only ever **add** a `policy_denied` — a `PolicyDecision` carries no allow/override outcome, so it can never turn an earlier gate's deny into an allow, never mint identity, and never mutate the intent or target. Two rule kinds are enforced against a per-tenant document: a **velocity** fixed-window action cap (atomic `INCR` + first-hit `EXPIRE`) and an **amount** ceiling on a named numeric argument (compared as `Decimal`, no float drift; a value smuggled as a string or other non-number is refused, not coerced). The pure amount check runs before the state-mutating velocity `INCR`, so an over-ceiling request denies without consuming velocity budget.

It is **opt-in and honest**: with no policy document for a tenant the engine imposes **no limits** (never a fabricated default). A Redis transport error or a malformed stored document **fails closed** (`policy_denied`) for that tenant until an admin repairs it, and the gate wraps evaluation in a fail-closed guard so even a raising provider denies rather than proceeds. The concrete cause (`velocity exceeded` / `amount exceeds ceiling` / `policy evaluation unavailable`) rides only in the WORM `detail` — never over the agent wire, never as a metric label. Rules live in a per-tenant document read/written **only** via the `CAP_DIRECTORY_ADMIN`-gated `PUT`/`GET /v1/admin/policy` (+ `POST /v1/admin/policy/delete`), strict-validated (`≤ MAX_POLICY_RULES`, `≤ MAX_POLICY_DOC_BYTES`), emit-before-mutate WORM-logged, tenant-scoped, and opaque on failure. The document stores **only** velocity/amount rules — never an alias→target mapping or identity — so it can never repoint a skill or mint a principal.

### Copy-paste end-to-end (sandbox)

```bash
API=http://localhost:8080

# 1) Mint a demo JWT (sandbox only).
JWT=$(curl -s -X POST $API/v1/dev/token \
  -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-acme","agent_id":"agent-orchestrator-1","role":"ops"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])')

# 2) AUTO alias — executes immediately (200).
curl -s -X POST $API/v1/authorize -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d '{
    "source_format":"openai_tool_call",
    "tool_call":{"id":"call_1","type":"function","function":{"name":"skill_spend_summary","arguments":"{\"period\":\"2026-Q2\"}"}}
  }'

# 3) High-risk alias, no PIN — staged (202), returns a challenge_id.
CH=$(curl -s -X POST $API/v1/authorize -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d '{
    "source_format":"openai_tool_call",
    "tool_call":{"id":"call_2","type":"function","function":{"name":"skill_wire_transfer","arguments":"{\"payee\":\"enrolled:ACME_PAYROLL\",\"amount_cents\":2418000}"}}
  }' | python3 -c 'import sys,json; print(json.load(sys.stdin)["challenge_id"])')

# 4) Fetch the one-time code from the sandbox authenticator stand-in.
OTP=$(curl -s -H "authorization: Bearer $JWT" $API/v1/authenticator/$CH \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["otp"])')

# 5) Complete the step-up — same payload + pin + challenge_id → executed (200).
curl -s -X POST $API/v1/authorize -H "authorization: Bearer $JWT" \
  -H 'content-type: application/json' -d "{
    \"source_format\":\"openai_tool_call\",
    \"tool_call\":{\"id\":\"call_3\",\"type\":\"function\",\"function\":{\"name\":\"skill_wire_transfer\",\"arguments\":\"{\\\"payee\\\":\\\"enrolled:ACME_PAYROLL\\\",\\\"amount_cents\\\":2418000}\"}},
    \"pin\":\"$OTP\",\"challenge_id\":\"$CH\"
  }"

# 6) Replay the same triple → denied (403, pin_not_found — lock already spent).
```

The formal adversary model, the attack→defense→code matrix, and the residual-risk analysis for every one of these paths are in [`SECURITY_THREAT_MODEL.md`](SECURITY_THREAT_MODEL.md).

### Forensic payload reconstruction

The agent wire is opaque by design (a denial is only a generic message + `correlation_id`) and the operator decision feed omits arguments — which leaves an incident investigator without the **real** query an agent sent. The forensic side-channel closes that gap without softening the agent boundary. Each authorization's query (the opaque alias, the already-normalized arguments, and non-secret identity context) is captured into `services/forensic_store.py`, **AES-256-GCM encrypted at rest** under a dedicated master key held outside Redis (Redis holds ciphertext only), TTL-bounded, and bound to `(tenant, correlation_id)`. **Secrets are never captured** — the snapshot runs through the same WORM `_redact` discipline before encryption, and pin/JWT/proof/vended-credential/identity-shaped material never enters it. Capture is a **best-effort side-channel fired strictly after the authoritative WORM emit**, so it can never delay, reorder, or flip a decision; any capture error is swallowed.

Reconstruction is deny-by-default and lives on one route, `GET /v1/admin/forensic/{correlation_id}`, gated on the **`CAP_FORENSIC_READ`** capability — a distinct UUID from `CAP_DIRECTORY_ADMIN`, so holding directory-admin does **not** confer raw-payload read (least privilege); the `role` claim still authorizes nothing. The read is constant-time, kill-switch-enforced (a revoked/quarantined credential is denied), and tenant-scoped, and every access emits a WORM `admin_action='forensic_read'` **before** anything is disclosed (audit-before-disclosure; the payload is never re-embedded into that record). An unknown/expired id, a cross-tenant id, or the feature being off all return the same opaque `404`. Capture is **off by default in production** and, when enabled there, additionally requires a 32-byte key file (see `MCPIP_FORENSIC_CAPTURE` / `MCPIP_FORENSIC_KEY_PATH` in [Configuration](#configuration)); absent the key the feature is absent, never plaintext. The SDKs expose it as `MCPIPAdminClient.forensic_get()` / `forensicGet()`, and the console's Audit Ledger carries a "Reconstruct payload" inspector (admin-only, with an honest empty state when capture is off).

### Author-your-own skills (reviewer-approved)

Customers and the community can author their own **skills** without MCPIP hand-building every connector — a community skill is nothing more than one additive `alias → target` catalog entry, declarative data that flows through the SAME hardened overlay path an operator `register_skill` uses. Two capabilities gate the workflow (both distinct UUIDs, matched constant-time; the `role` claim authorizes nothing): a **Contributor** is any authenticated principal, while a **Reviewer** must hold the new **`CAP_CATALOG_REVIEWER`** — separable from `CAP_DIRECTORY_ADMIN` and `CAP_FORENSIC_READ`, so "can approve community extensions" is not "can revoke a principal" and is not "can read raw forensic payloads." Holding a sibling capability never confers it.

The flow is submit → review → approve, all tenant-scoped from the JWT (cross-tenant approve is structurally impossible) and tamper-evidently recorded:

- **`POST /v1/extensions/submit`** — Contributor, deliberately **outside** the `/v1/admin/*` prefix. The `mcpip-extension/1` manifest (`services/extension_manifest.py`) is validated fail-closed: strict Pydantic (`extra='forbid'`), `reject_unsafe_string` on every human field, an identity-shaped-key hard-deny on `id`/`author`/`alias` (so `alias='role'`, homoglyph, or bidi variants trip), a `sha256` **self-pin** over `canonical_manifest_bytes` (distinct from the payload-lock `canonical_json` — no lock hash is ever recomputed), then the authoritative `_overlay_skill_invalid` predicate. Submit does **not** probe alias existence (that would be an alias-existence oracle for un-entitled contributors); conflict resolution is the reviewer's job.
- **`GET /v1/admin/extensions/pending`** — Reviewer, read-only, a strict whitelist projection plus a `conflicts_existing_alias` diff and a `submitter_is_reviewer` separation-of-duties hint.
- **`POST /v1/admin/extensions/{id}/approve`** · **`/reject`** — Reviewer. Approve **re-runs** the authoritative checks (re-verify the `sha256` pin, re-run `_overlay_skill_invalid`, additive-only `has_alias`, the `MAX_OVERLAY_ENTRIES` ceiling); any failure refuses with no state change. On success it emits a WORM `extension_approve` **before** applying (write-before-execute — the approval becomes a hash-chained, Ed25519-epoch-signed, non-repudiable record), then mints the skill through the shared overlay path and **hash-pins** the approved manifest.

Every ceiling is **by construction**, not by reviewer vigilance: a community skill can only ever ADD a new opaque alias onto a `cloud_rest` target — it can never repoint an existing alias, reach a privileged transport (`legacy_mainframe`/`grant_issue`/`cloud_iam`), or smuggle a `restricted`-classification AUTO read (the overlay forces `restricted ⇒ pin_required`). **Rug-pull defense on load:** `_hydrate_catalog_overlay` re-verifies each community row's pinned manifest against `mcpip:ext:approved:{tenant}` and skips any mismatch, so a post-approval edit to the manifest or the overlay fields refuses to load and forces re-review — the same "refuse on unexpected edit" discipline as the hash-pinned connector registry.

Community **gates** (a custom deny predicate on the hot path) ship in this release only as the `kind='gate'` manifest **schema** and a deny-only `CommunityGateProvider` **seam** (pipeline step 4c′), a fail-closed no-op until a CEL engine is registered — the CEL runtime is a deferred owner dependency decision. See [`docs/EXTENSIBILITY.md`](docs/EXTENSIBILITY.md) for the full design and the deferred-runtime rationale.

### ReBAC relation graph — the operator Knowledge-Graph, made real

The console's team/grant graph is now backed by a real **Zanzibar-style relation-tuple projection** of committed grants (`services/relation_store.py`, `RelationTupleStore`), not a decorative render. It is **strictly additive** and a projection, never a second source of truth: `GrantStore.issue`/`has_active_grant`/`revoke`, the payload lock, and WORM are byte-for-byte unchanged. `GrantStore` takes an optional injected relation store and projects one member tuple **only after** the authoritative grant `.set()` succeeds — `mcpip:rel:{tenant}:{object}#{relation}@{subject}` (object = compartment UUID, relation = `member`, subject = agent id), written with `EX=ttl` **mirroring the grant** so the projection self-heals to grant expiry even if a best-effort remove on revoke is dropped. `project_member`/`remove_member` swallow every `RedisError` (metric only, `mcpip_relation_projection_total{event}`) and **never raise into the grant path**; a projection outage degrades only the graph, never a decision. **The authorization pipeline never consults it** — the capability-UUID + grant gates remain the sole authority (and a documented rule keeps the closure check deny-only/additive if it were ever promoted to the hot path).

`GET /v1/admin/directory/relations` (gated on `CAP_DIRECTORY_ADMIN`, mirroring `GET /v1/admin/quarantine`) lists the projected `member` edges plus a read-time-derived `grantor` edge (issuing principal → compartment); optional `?subject=`/`?relation=`/`?object=` filters narrow the edges, and a full `(subject, member, object)` triple additionally returns `allowed` — the result of a **bounded transitive-closure `check`** (hop-capped by `MAX_RELATION_DEPTH`, fanout-capped by `MAX_RELATION_FANOUT`, fail-closed). The read is tenant-scoped, glob-escaped, bounded by `MAX_RELATION_ROSTER`, fail-soft (`[]` on transport error — it backs a listing, never a decision), and opaque on a malformed filter. Tuples carry only operator-facing identifiers + non-secret grant metadata — never a target, secret, or alias→target mapping — and nothing here crosses the agent boundary.

### Portable audit attestation — `GET /v1/audit/attestation`

A single **read-only** endpoint returns a portable, externally-checkable snapshot of the current audit state: the latest **sealed** epoch header (`epoch`/`end_seq`/`merkle_root`/`epoch_hash`/`signature`), the WORM epoch key's public `signing_key_id` (a domain-separated fingerprint of the *public* key — an identifier only, never secret material or a signature), a **fresh** `verify_chain` result (`intact` + `first_bad_epoch`), and the out-of-tamper-domain anchor low-watermark (`anchor_epoch`/`anchor_epoch_hash`). Every signed field was Ed25519-signed by the WORM key at epoch close / anchor append, so producing an attestation **mints no key, signs nothing new, closes no epoch, and touches no counter** — it never runs on or blocks the emit hot path. It discloses no hidden target, payload, or secret — but it commits to the **global, cross-tenant** WORM head (`epoch`/`end_seq` is one fleet-wide ledger height), and unlike the sandbox-only `/v1/audit/verify` + `/v1/audit/proof` it is available **in production** (a portable attestation an external verifier can check against a known WORM public key is a production artifact). So it is **`CAP_DIRECTORY_ADMIN`-gated** — a plain agent JWT cannot read it (that would leak cross-tenant activity volume and let any principal force a full `verify_chain`). The epoch fields are `null` before the first epoch is sealed (an honest empty state); any auth or engine error is an opaque `MCPIPDenied`.

### Rotating verification keys — the JWKS refresh helper (fail-closed, never empty)

For a deployment whose IdP / workload-identity STS **rotates** its signing keys, `auth/jwks_refresher.py` completes the existing `JWKSKeyProvider` with its off-hot-path other half. `JWKSRefresher` is itself a `KeyProvider` wrapping a live inner `JWKSKeyProvider`, so it drops straight into a `TokenResolver`; `resolve` simply delegates (the only per-request op — there is still **no synchronous JWKS fetch on the auth path**). `refresh`/`bootstrap` pull a fresh document off the hot path over an **SSRF-guarded, hermetic** client — https-only; resolve and reject any private/loopback/link-local/reserved/multicast/unspecified address; connection **pinned to the validated IP** with original-host SNI/cert to defeat DNS-rebinding; no redirects; bounded timeout; bounded read (`MAX_JWKS_DOC_BYTES`); `trust_env=False` + `proxy=None` so an ambient `HTTPS_PROXY`/`SSL_CERT_FILE` can neither reroute nor MITM the key fetch (the same guard as the authenticator webhook push). It **builds and fully validates a new `JWKSKeyProvider` before** the single atomic swap (re-running the authoritative non-empty / well-formed / no-private-material / unique-`kid` checks + the `MAX_JWKS_KEYS` cap), so **any failure retains the last good set — the verification key set is never silently emptied**; an unknown `kid` after a failed refresh still fails closed. `bootstrap` makes the seed a mandatory non-empty provider (boot fails closed rather than come up empty), and the `TokenResolver` alg allow-list `{EdDSA, RS256}` stays the gate — a rotated set can add keys but never widen it. It is **strictly opt-in and additive**: a standalone helper you construct directly from a mounted document or via `bootstrap` for a rotating-STS deployment; the default `StaticPEMKeyProvider` / single-IdP boot path is entirely unchanged.

---

## Dashboard

A dark-mode **operator** dashboard lives under `dashboard/` — a Vite + React + TypeScript + Tailwind app. It renders the four-stage pipeline, the tenant-scoped alias registry, the exactly-once payload-lock story, and the live `/v1/authorize` request/response shapes from an operator's vantage point. There is **no marketing landing page** and no root `index.html`; this dashboard is the only web surface.

```bash
cd dashboard
npm install
npm run dev            # http://localhost:5173  (dark operator dashboard)
npm run build          # static production bundle -> dashboard/dist
npm run preview        # serve the production build locally
```

Run it alongside the API (`uvicorn app.main:app` on `:8080`) to watch authorizations, staged step-ups, and denials as they land.

---

## Docker & docker-compose

**Build and run the whole stack** (gateway API + redis, redis on a private internal-only network) with a single command from the repo root:

```bash
docker compose up --build
```

Compose brings up two hardened services (a third, `gateway-demo`, is opt-in via the `demo` profile):

| Service | Image | Network exposure | Hardening |
|---|---|---|---|
| `redis` | `redis:7-alpine` | **internal-only** — never on the edge, never published to the host | `no-new-privileges`, read-only rootfs, `tmpfs:/data`, healthcheck (`redis-cli ping`) |
| `gateway` | built from `Dockerfile` | API port **`8080` published** on the `mcpip-edge` bridge; reaches redis over `mcpip-internal` | non-root, `cap_drop: ALL`, `no-new-privileges`, read-only rootfs, `tmpfs:/tmp`, WORM volume, `restart: unless-stopped`, `GET /healthz` liveness healthcheck |

The gateway runs the long-lived API (`uvicorn app.main:app`). It straddles two networks: **`mcpip-internal`** (`internal: true`, no host/egress routing) to reach Redis at the service DNS name **`redis://redis:6379/0`**, and **`mcpip-edge`** (a normal bridge) which carries **only** the published `8080` API port. Redis is attached solely to `mcpip-internal`, so it is never reachable from the host or the internet.

**No LLM egress, by design.** The gateway needs **no outbound route to any LLM or cloud-AI vendor** — the end user's client calls its LLM directly on its own keys/billing, and every connector under `bridge/connectors/` is a parser with no SDK and no network capability. The MCP edge (`POST /v1/mcp`) is likewise an authorization boundary, not a proxy: it never dials an upstream MCP server. Operationally this means the gateway's egress allowlist can be **empty except for Redis and your own downstream transports** — if you ever observe the gateway connecting to an LLM vendor endpoint, that is an incident, not a configuration.

Note the deliberate **Redis port asymmetry**: the host-run quickstart talks to a stand-alone Redis on host port **63790**, while the compose deployment keeps Redis entirely internal on **6379** with no host exposure. The WORM audit log is written to a named volume (`worm-data` → `/var/lib/mcpip`), so the tamper-evident ledger survives container restarts.

```bash
docker compose up --build            # build + run the API + redis
curl -s http://localhost:8080/healthz   # {"status":"live","glyph":"◐"}
docker compose logs -f gateway       # watch authorization decisions land
docker compose down                  # stop; add -v to also drop the WORM volume

# The self-verifying 10-gate demo, on demand (internal network only, exits 0):
docker compose --profile demo run --rm gateway-demo
```

The image itself is multi-stage: a `python:3.12-slim` **builder** resolves `requirements.txt` into an isolated venv at `/opt/venv`, and a minimal `python:3.12-slim` **runtime** copies only that venv plus the app, runs as a non-root user, sets `PYTHONDONTWRITEBYTECODE`/`PYTHONUNBUFFERED`, `EXPOSE`s `8080`, and carries no secrets. Its default `CMD` is `uvicorn app.main:app`; the demo stays runnable by overriding it (`docker run --rm mcpip-gateway:v2 python main.py`). *(Distroless `python3` ships CPython 3.11, so the 3.12-built venv would be ABI-mismatched there — hence the matching 3.12-slim runtime base.)*

---

## Release, Packaging & Verification

**Version:** `3.0.0` — the `VERSION` file is the single source of truth (strict
`MAJOR.MINOR.PATCH`), read at build time by `pyproject.toml` and at runtime by
`core/version.py`; `GET /healthz` reports it. A missing/malformed `VERSION` is a
fail-closed boot error. Releases are catalogued in [`CHANGELOG.md`](CHANGELOG.md).

**The philosophy: immutable, verifiable releases — no runtime self-update.** A release
is a set of SHA-256 artifact digests signed with an **offline Ed25519 release-root
key**. The gateway proves at every boot that its shipped source set is byte-identical
to what was signed (`core/integrity.py` — verified boot, fail-closed, no
remediation/self-heal path), and it contains **no updater**: it never pulls code, never
patches itself, never mutates its own files. Upgrading is the *operator's*
change-control action — verify a new signed release, pin its digest, redeploy. If
update automation is ever wanted, the documented path is an external TUF/Sigstore
delivery pipeline (future work, never in-binary).

Three separate Ed25519 roots, never conflated: **release-root** (release + integrity
manifests), **license-root** (entitlement files), and the **audit epoch key**
(`MCPIP_WORM_SIGNING_KEY_PATH`). Private keys live only on the offline signer (dev keys
land in the gitignored `.keys/`); only public PEMs + `release/keys/rotation.json` ship.

### Build & sign a release

```bash
# 0) One-time: dev signing roots (private -> .keys/ (gitignored), public -> release/keys/)
./.venv/bin/python scripts/gen_release_keys.py

# 1) Build the wheel + sdist -> dist/
./.venv/bin/python -m build

# 2) CycloneDX SBOM of the resolved pinned set -> release/sbom/mcpip-3.0.0.cdx.json
bash scripts/build_sbom.sh

# 3) Sign the release manifest (offline root) -> release/manifest.json + manifest.sig
./.venv/bin/python scripts/sign_release.py \
  --version 3.0.0 \
  --private-key .keys/release_root_ed25519.pem \
  --artifact dist/mcpip-3.0.0-py3-none-any.whl \
  --artifact dist/mcpip-3.0.0.tar.gz \
  --artifact release/sbom/mcpip-3.0.0.cdx.json

# 4) Sign the boot-integrity manifest (LAST source-touching step)
./.venv/bin/python scripts/gen_integrity_manifest.py \
  --private-key .keys/release_root_ed25519.pem

# 5) SLSA v1 / in-toto provenance over the SAME signed artifact digests
#    (subjects copied verbatim from manifest.json; materials = git commit +
#    requirements*.txt + VERSION). --builder-id is the OWNER's real build-platform
#    identity — never defaulted or fabricated. Writes only to release/ (outside the
#    hashed source set). This SIGNS NOTHING — cosign attest is the owner offline-key
#    step below.  -> release/provenance.intoto.json  (gitignored)
./.venv/bin/python scripts/gen_slsa_provenance.py \
  --manifest release/manifest.json \
  --builder-id "<owner build-platform identity URI>"

# 6) Build the image; record the immutable digest for deploy pinning
docker build -t mcpip-gateway:3.0.0 .
docker images --digests mcpip-gateway
```

**SLSA provenance is generated here but attested (signed) offline by the owner.** Like
release-root and license-root signing, the SLSA/in-toto predicate is signed with the
**owner's offline cosign key** (`cosign attest-blob --type slsaprovenance1 --predicate
release/provenance.intoto.json …`) on the air-gapped signer — never fabricated, never
committed from a normal checkout. The generator itself signs nothing; see
[`RELEASE.md`](RELEASE.md) §6 for the full ceremony and the required `builder.id` /
`buildType` owner decision.

### Verify a release — `mcpip verify`

`mcpip` is the console script the wheel installs (`mcpip_verify/cli.py`); from a
checkout, `./.venv/bin/python -m mcpip_verify.cli` is identical. It is **read-only and
fail-closed**: any failure prints exactly `verification failed` (opaque — no reason, no
path) and exits `2`; success prints `verified: mcpip 3.0.0 (3 artifacts)` and exits `0`.
Verification is pure local cryptography — no network, no TLS dependency.

```bash
# Manifest + every listed artifact on disk:
./.venv/bin/python -m mcpip_verify.cli verify \
  --manifest release/manifest.json \
  --pubkey release/keys/release_root_ed25519.pub.pem \
  --base-dir .

# Read-only WORM audit export + independent re-verification of the signed chain
# (Merkle roots, epoch_hash, prev_epoch_hash linkage, Ed25519 epoch signatures, and the
# out-of-tamper-domain anchor rollback watermark). --pubkey is required by --verify:
./.venv/bin/python -m mcpip_verify.cli export-audit \
  --redis-url redis://localhost:63790/0 --out audit_export.jsonl --verify \
  --pubkey <worm_signing_ed25519.pub.pem> --require-anchor
```

### The offline (air-gap) bundle

```bash
bash scripts/build_bundle.sh 3.0.0     # -> dist/mcpip-airgap-3.0.0.tar.gz
```

A deterministic tarball carrying the signed manifest + detached signature, **public**
keys + rotation manifest, the artifacts (or `BUILD_RECIPE.md` to rebuild the image from
the verified sdist), the SBOM, `SHA256SUMS`, and an in-enclave `INSTALL.md` runbook.
Every artifact is re-verified against the signed manifest **before** packing. Inside
the enclave: check the release public-key fingerprint against your out-of-band copy,
then

```bash
./.venv/bin/python -m mcpip_verify.cli verify bundle dist/mcpip-airgap-3.0.0.tar.gz \
  --pubkey release/keys/release_root_ed25519.pub.pem
```

— zero network at any step, including CVE scanning (`grype`/`trivy` against the bundled
SBOM with a mirrored DB).

### Helm / Kubernetes deploy

The chart (`chart/`, name `mcpip`) never embeds secret material and cannot express
`MCPIP_SANDBOX_MODE` or the integrity dev-bypass — production pods always boot
fail-closed with verified boot + the license gate enforced. Plain manifests live in
`k8s/` (`kubectl apply -f k8s/`).

```bash
kubectl create namespace mcpip
kubectl -n mcpip create secret generic mcpip-keys \
  --from-file=jwt_public.pem=/secure/path/jwt_public.pem \
  --from-file=worm_signing.pem=/secure/path/worm_signing.pem \
  --from-file=license.json=/secure/path/license.json

helm upgrade --install mcpip ./chart -n mcpip \
  --set image.repository=<your-registry>/mcpip-gateway \
  --set image.digest=sha256:<digest-from-release>      # deploy BY DIGEST, never by tag
```

Ships: 2 replicas + HPA (2→10 @ 70% CPU), non-root, read-only rootfs, default-deny
NetworkPolicy, internal-only Redis (AOF `appendfsync always`), persistent WORM volume.

### Boot gates & `/metrics`

Two fail-closed startup hooks run before a socket is bound (both preconfigured in the
k8s/Helm ConfigMaps):

| Hook | Env | Behavior |
|---|---|---|
| **Verified boot** | `MCPIP_INTEGRITY_MANIFEST_PATH` + `MCPIP_INTEGRITY_PUBLIC_KEY_PATH` | Re-hashes every shipped source file against the signed integrity manifest; any mismatch → opaque `integrity verification failed`, exit nonzero. No self-heal — redeploy. |
| **License gate** | `MCPIP_LICENSE_PATH` + `MCPIP_LICENSE_PUBLIC_KEY_PATH` | Ed25519-signed entitlement file (separate license root), checked at boot **only** — never consulted per-request. Mint dev licenses with `scripts/gen_license.py`. |

`GET /metrics` (Prometheus, exempt from shedding, network-scoped by the NetworkPolicy)
exposes `mcpip_authorize_decisions_total{decision,deny_reason}`,
`mcpip_authorize_latency_seconds{decision}`, `mcpip_requests_shed_total{cause}`, and the
`mcpip_worm_epoch` / `mcpip_worm_sequence` chain heights. Label discipline is enforced
by construction (`core/metrics.py`): every label value is a string literal or a
closed-enum value — **no** tenant, agent, alias, compartment, capability UUID,
correlation id, JWT material, or approval code can ever appear in a metric name or
label. Multi-worker aggregation via `PROMETHEUS_MULTIPROC_DIR` (set in the image).

The full deploy/rotate/backup/incident procedures live in the
[**Operations runbook**](docs/OPERATIONS.md); the control mapping in the
[**Compliance pack**](docs/COMPLIANCE.md).

---

## Module reference

| Module | Stage | Responsibility |
|---|---|---|
| `interfaces.py` | shared | Limits (`MAX_ARG_DEPTH=8`, `MAX_CANONICAL_BYTES=16384`, `PIN_TTL_SECONDS=300`, …), enums (`Decision`, `DenyReason`, `RiskTier`, `SourceFormat`), `canonical_json` / `sha256_hex`, `reject_unsafe_string`, Pydantic models (`NormalizedIntent`, `Identity`, `AuthorizedIntent`, `SwarmTrace`), `BaseTransport` ABC, `MCPIPDenied`. |
| `bridge/intent_parser.py` | Bridge | `parse(raw, declared_format, trace)` — selects the pure format parser through the pinned registry, feeds the candidate into `NormalizedIntent`; owns the `enforce_argument_safety` depth-walker and the identity-injection hard-deny. |
| `bridge/connectors/formats.py` | Bridge | The strict ingress models + pure parsers for all seven wire shapes (`parse_openai` / `parse_anthropic` / `parse_gemini` / `parse_bedrock` / `parse_mcp` / `parse_raw_mcp` / `parse_a2a_task`). Parser-only: no SDK imports, no outbound network, no credentials (AST-enforced by `tests/test_connector_conformance.py`). |
| `bridge/connectors/registry.py` | Bridge | Hash-pinned vendor→format table (`REGISTRY_VERSION`, `REGISTRY_SHA256`); `resolve_vendor` / `parser_for`, both fail-closed (`unknown_vendor` / `unknown_format`); an unpinned mapping edit refuses to boot. |
| `bridge/connectors/base.py` | Bridge | `Candidate` (NamedTuple, deliberately not a validation boundary) + the `FormatParser` protocol. |
| `bridge/errors.py` | Bridge | Bridge deny taxonomy (`UnknownFormat`, `UnknownVendor`, `IdentityInjection`, `DepthExceeded`, `SizeExceeded`) shared by Python and the Rust walker. |
| `bridge/fastwalk.py` | Bridge | Opt-in Rust fast-walk dispatch shim (`MCPIP_FAST_WALKER=1`): byte-identical canonicalization, decision-identical rejections, transparent pure-Python fallback. |
| `obfuscator/alias_registry.py` | Obfuscator | Per-tenant bi-directional `alias ↔ target` with `risk_tier` + `transport`; fail-closed on unknown alias / cross-tenant. |
| `auth/token_resolver.py` | Auth | `TokenResolver` + `KeyProvider` ABC / `StaticPEMKeyProvider`; EdDSA/RS256 only; rejects `alg=none` and HMAC confusion; verifies the 8 required claims; emits a frozen `Identity`. |
| `auth/pin_validator.py` | Auth | Canonical payload-lock: `register` / `consume`; the single atomic `LOCK_CONSUME_LUA` `EVAL` (return codes `1 / -1 / -2 / -3`); payload-before-PIN ordering; 5-attempt self-destruct under a 300 s TTL. |
| `audit/worm_logger.py` | Audit | Hybrid Merkle-epoch WORM: durable Redis-Stream event buffer (write-before-execute), ~1s background epoch daemon sealing per-epoch signed Merkle roots (root-chained), recursive redaction of `pin/jwt/token/…`; `emit` / `close_epoch` / `verify_chain` / `inclusion_proof`. Legacy per-event chain behind `mode="per_event"`. |
| `audit/merkle.py` | Audit | Pure, domain-separated Merkle tree: `leaf_digest` / `node_digest` / `merkle_root` / `inclusion_proof` / `verify_inclusion`. |
| `obfuscator/tenant_catalog.py` | Obfuscator | Multi-industry tenant catalog (finance/healthcare/gov/defense/energy/retail/telecom/pharma) + the compartmented defense tenant's compartments. |
| `services/grant_store.py` | Services | Redis-backed delegated compartment grants (`GrantStore`/`GrantRecord`); TTL = active-grant test; fail-closed reads. |
| `services/authn_channel.py` | Services | Out-of-band step-up **OTP delivery** seam (only delivery moves here; derivation/binding stay in `PinValidator`). `SandboxRedisAuthenticatorChannel` (Redis stash + `peek`, the sandbox demo stand-in) and `WebhookAuthenticatorChannel` (the one real prod channel — SSRF-guarded, HMAC-SHA256-signed HTTPS push, persists no OTP); any failure → fail-closed `otp_delivery_failed`. |
| `services/policy_engine.py` | Services | The **deny-only** policy overlay: `VelocityAmountPolicyEngine` (fixed-window velocity cap + amount ceiling, all fail-closed) + `PolicyDocStore` for the per-tenant `mcpip-policy/1` document behind `PUT`/`GET /v1/admin/policy`. No document ⇒ no limits (opt-in); Redis error / malformed doc ⇒ `policy_denied`. |
| `services/extension_manifest.py` | Services | The `mcpip-extension/1` **community-extension** manifest schema (strict Pydantic, `reject_unsafe_string` + identity-fold hard-deny + a `sha256` self-pin via `canonical_manifest_bytes`). `ExtensionManifest` = community-SKILL (`kind='skill'`, `cloud_rest`-only; `parse_manifest`); `GateManifest` = community-GATE (`kind='gate'`, `language='cel'`, `referenced_context_fields ⊆ GATE_CONTEXT_FIELDS`, `max_cost ≤ MAX_GATE_COST` — **DATA validation only, no CEL parse**; `parse_gate_manifest`). `manifest_kind` routes the two, which never share a code path. |
| `services/extension_submissions.py` | Services | `ExtensionSubmissionStore` — the per-tenant submit/review state: `mcpip:ext:pending:{tenant}` (bounded by `MAX_PENDING_SUBMISSIONS`) + `mcpip:ext:approved:{tenant}` (canonical manifest + pinned `sha256`). Writes fail closed, reads fail soft; tenant comes only from the JWT, so cross-tenant approve is structurally impossible. Backs the submit → review → approve flow and the boot rug-pull re-verify. |
| `services/community_gate.py` | Services | The Phase-2 **deny-only** community-gate seam. `NoOpCommunityGateProvider` (default; always `continue` — the honest "no engine configured" state) + `register_community_gate_engine` / `active_community_gate_provider` / `community_gate_engine_registered`. **No `celpy` import** — the CEL runtime is a deferred owner decision (`docs/EXTENSIBILITY.md §8`); registering an engine is the single additive change that turns gates on. |
| `main.py` | gateway | `MCPIPGateway.authorize_and_execute(...)`; `CloudRESTTransport` + `LegacyMainframeTransport` (EBCDIC cp500 80-byte frame); the 10-gate `__main__` demo with a PASS/FAIL report and `sys.exit`. |
| `app/main.py` | HTTP edge | FastAPI app (`uvicorn app.main:app`); reproduces the pipeline over `POST /v1/authorize` with the staged-challenge branch; `POST /v1/mcp` (the MCP-native edge — same pipeline, JSON-RPC framing, no proxying); `GET /healthz` · `/readyz` · `/v1/catalog`; correlation-id middleware + opaque exception handlers. |
| `core/` · `models/` · `services/` | HTTP edge | `core/config.py` (`MCPIP_*` settings), `core/security.py` (`map_engine_exception`), `models/schemas.py` (strict request/response), `services/*` (thin `TokenResolver`/`PinValidator`/registry adapters). |

### Tenant-scoped alias registry (demo)

Agents only ever see the left column. Real targets stay invisible.

| Tenant | Alias | Real target | Transport | Risk |
|---|---|---|---|---|
| `tenant-acme` | `skill_customer_lookup` | `rest.crm.customers.get` | cloud_rest | auto |
| `tenant-acme` | `skill_spend_summary` | `rest.ledger.spend.summary` | cloud_rest | auto |
| `tenant-acme` | `skill_status_probe` | `rest.health.status.get` | cloud_rest | auto |
| `tenant-acme` | `skill_payroll_run` | `mainframe.cics.PAYR` | legacy_mainframe | **pin_required** |
| `tenant-acme` | `skill_ledger_posting` | `mainframe.db2.GLPOST` | legacy_mainframe | **pin_required** |
| `tenant-acme` | `skill_wire_transfer` | `rest.payments.wire.create` | cloud_rest | **pin_required** |
| `tenant-acme` | `skill_emergency_reset` | `aws.vpc.prod.db_drop` | cloud_rest | **pin_required** |
| `tenant-globex` | `skill_status_probe` | `rest.health.status.get` | cloud_rest | auto |

`tenant-globex` owns a single alias, so `globex` asking for `skill_payroll_run` deterministically denies with `CROSS_TENANT`.

### Multi-industry tenant catalog

Beyond the legacy `tenant-acme` / `tenant-globex` demo rows, the Obfuscator ships a
representative **multi-industry** catalog (`obfuscator/tenant_catalog.py`,
`seed_industry_catalog`) — eight industry tenants plus one compartmented **defense** tenant.
The acme/globex rows are seeded first and stay byte-identical, so every existing scenario
keeps passing; the industry rows are additive. Agents still only ever see the alias; the real
targets below never cross the boundary.

| Industry | Tenant | Example aliases (risk) |
|---|---|---|
| Finance | `meridian-retail-bank` | `skill_account_balance` (auto) · `skill_wire_transfer` (**pin**) · `skill_core_posting` (**pin**) |
| Healthcare (PHI) | `st-caritas-health` | `skill_patient_lookup` (auto) · `skill_rx_order` (**pin**) · `skill_claim_submit` (**pin**) |
| Government | `us-treasury-fiscal` | `skill_disbursement_status` (auto) · `skill_treasury_disbursement` (**pin**) |
| **Defense (compartmented)** | `aegis-dynamics` | `skill_status_probe` (auto, tenant-wide) · `skill_airframe_telemetry` (FALCON) · `skill_radar_calibration_set` (AEGIS, **pin**) · `skill_recon_feed_read` (SENTINEL) · `skill_compartment_grant` (governance, **pin**) |
| Energy / SCADA | `voltgrid-utility` | `skill_grid_load` (auto) · `skill_breaker_trip` (**pin**) · `skill_der_dispatch` (**pin**) |
| Retail | `novabuy-commerce` | `skill_order_status` (auto) · `skill_refund_issue` (**pin**) · `skill_price_override` (**pin**) |
| Telecom | `orbital-telecom` | `skill_sim_status` (auto) · `skill_sim_swap` (**pin**) · `skill_number_port` (**pin**) |
| Pharma / biotech | `helix-biotherapeutics` | `skill_trial_status` (auto) · `skill_batch_release` (**pin**) · `skill_assay_result_post` (**pin**) |

### Compartmented team separation (need-to-know)

Only the **defense** tenant `aegis-dynamics` separates its teams into UUID-identified
**compartments** — `project-falcon` (`FALCON`), `project-aegis` (`AEGIS`),
`project-sentinel` (`SENTINEL`). A same-tenant agent must be *entitled* to a compartment
before it can see or invoke that team's MCPs. **Authorization is UUID-capability based, never
role-based:** the JWT `role` claim stays validated for back-compat but authorizes **nothing**
(role-based authz was removed from every decision path). A privileged action is allowed only
if the principal holds the required **capability UUID** (strict JWT `capabilities` claim
and/or an active Redis grant). Two new deny reasons carry this:

| Deny reason | Meaning |
|---|---|
| `compartment_denied` | Caller is not entitled to the alias's compartment (no direct JWT `compartment` match and no active delegated grant), or a grant has expired/been revoked. |
| `capability_denied` | Caller lacks the required capability UUID for a privileged action (e.g. issuing a compartment grant, or issuing one for a compartment it is not scoped to). |

The compartment story is exercised end-to-end by demo gates **C1–C10b** in `python main.py`
(the transcript above). The same behaviour is reachable over HTTP — the sandbox `/v1/dev/token`
minter accepts optional `compartment` + `capabilities` UUID claims, and `GET /v1/catalog`
filters visibility so a team cannot even *enumerate* another team's classified MCPs:

```bash
API=http://localhost:8080
FALCON=f4100000-0000-4000-8000-0000000fa1c0
AEGIS=ae610000-0000-4000-8000-0000000ae615
CAP_GRANT=9c2b6f14-7a3d-4e8b-b1c0-2f5a9d3e4c71

# grant_capability_for(FALCON) is a uuid5-derived, compartment-scoped grant capability.
# Compute it the same way the engine does (stable, offline):
GRANT_CAP_FALCON=$(python3 -c "import interfaces,sys; print(interfaces.grant_capability_for('$FALCON'))")

jwt() { curl -s -X POST $API/v1/dev/token -H 'content-type: application/json' -d "$1" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["jwt"])'; }

# Team Falcon agent (compartment=FALCON) → its own alias → ALLOW (200).
FALCON_JWT=$(jwt "{\"tenant_id\":\"aegis-dynamics\",\"agent_id\":\"agent-falcon-1\",\"role\":\"ops\",\"compartment\":\"$FALCON\"}")
curl -s -X POST $API/v1/authorize -H "authorization: Bearer $FALCON_JWT" \
  -H 'content-type: application/json' -d '{
    "source_format":"openai_tool_call",
    "tool_call":{"id":"c1","type":"function","function":{"name":"skill_airframe_telemetry","arguments":"{}"}}
  }'   # -> 200 executed

# Team Aegis agent (compartment=AEGIS) → the Falcon alias → COMPARTMENT_DENIED (opaque 403).
AEGIS_JWT=$(jwt "{\"tenant_id\":\"aegis-dynamics\",\"agent_id\":\"agent-aegis-1\",\"role\":\"ops\",\"compartment\":\"$AEGIS\"}")
curl -s -X POST $API/v1/authorize -H "authorization: Bearer $AEGIS_JWT" \
  -H 'content-type: application/json' -d '{
    "source_format":"openai_tool_call",
    "tool_call":{"id":"c2","type":"function","function":{"name":"skill_airframe_telemetry","arguments":"{}"}}
  }'   # -> 403 {"error":"MCPIP: request denied by policy.","correlation_id":"…"}  (reason compartment_denied, in the WORM log only)

# Catalog enumeration: the Aegis agent cannot even SEE Falcon's classified MCP.
curl -s -H "authorization: Bearer $AEGIS_JWT" $API/v1/catalog   # no skill_airframe_telemetry in the list

# Security officer holding CAP_COMPARTMENT_GRANT + grant_capability_for(FALCON) issues a
# FALCON grant to agent-aegis-2 (a step-up-gated, payload-bound governance mandate).
OFFICER_JWT=$(jwt "{\"tenant_id\":\"aegis-dynamics\",\"agent_id\":\"agent-security-officer-1\",\"role\":\"ops\",\"capabilities\":[\"$CAP_GRANT\",\"$GRANT_CAP_FALCON\"]}")
# … stage skill_compartment_grant (pin_required) with {"grantee":"agent-aegis-2","compartment":"<FALCON>","ttl_seconds":3600},
#    complete the step-up with the one-time code → grant written. agent-aegis-2 now reaches
#    skill_airframe_telemetry via the active delegated grant (ALLOW) until the TTL expires or the
#    grant is revoked, after which the same reach denies compartment_denied again.
```

The officer is **compartment-scoped**: holding `grant_capability_for(FALCON)` lets it grant
FALCON and *only* FALCON — attempting to grant AEGIS denies `capability_denied` (no
tenant-wide master key; demo gate C10). The full grant → access → expiry → denied lifecycle
is proved deterministically by gates **C4/C5/C7** in `python main.py`.

---

## Configuration

All settings are read by `core/config.py` (`pydantic-settings`, env-prefix `MCPIP_`).

| Variable | Default | Purpose |
|---|---|---|
| `MCPIP_REDIS_URL` | `redis://localhost:63790/0` | Redis endpoint for locks + WORM chain state. Compose overrides to `redis://redis:6379/0`. |
| `MCPIP_WORM_PATH` | `./mcpip_worm.jsonl` | JSONL ledger path used **only** in the legacy `mode="per_event"` migration path. The default hybrid Merkle-epoch model keeps the durable event buffer + signed epoch chain in Redis Streams; production requires Redis AOF with `appendfsync always` so each event's XADD is fsync-durable **before** the action is authorized (write-before-execute). The image/compose set this to `/var/lib/mcpip/mcpip_worm.jsonl`. |
| `MCPIP_SANDBOX_MODE` | `false` (secure-by-default) | When true, boot an ephemeral in-process IdP + WORM signing key and mount the sandbox helper endpoints (and log a loud banner). Defaults `false` **everywhere** — bare `uvicorn`, image, and Compose — so a misconfigured deployment fails closed at boot rather than exposing the token-minting oracle; opt in explicitly for the demo. |
| `MCPIP_JWT_ISSUER` | `mcpip-demo-idp` | Expected JWT `iss`, verified by `TokenResolver`. The default is a **demo** value: with `sandbox_mode=false` the gateway refuses to boot while `iss` is still `mcpip-demo-idp`, because the shipped defaults are published and predictable. |
| `MCPIP_JWT_AUDIENCE` | `mcpip-gateway` | Expected JWT `aud`, verified by `TokenResolver`. Same demo-default rule as `MCPIP_JWT_ISSUER` — production boot refuses `mcpip-gateway`, so set your own gateway audience. |
| `MCPIP_JWT_PUBLIC_KEY_PATH` | `None` | PEM public key for verifying JWTs. When unset **and** `sandbox_mode`, the in-process demo IdP is used; unset with `sandbox_mode=false` is a fail-closed boot error. |
| `MCPIP_WORM_SIGNING_KEY_PATH` | `None` | Ed25519 PKCS8 PEM signing key for the WORM log. Unset ⇒ ephemeral key (sandbox); unset with `sandbox_mode=false` refuses to start. |
| `MCPIP_WORM_ANCHOR_PATH` | `None` | Out-of-tamper-domain append-only anchor file for the Ed25519-signed epoch-head low-watermark (`audit/anchor.py`) that catches rollback/tail-truncation. Must sit on a durable volume **distinct** from the Redis store. Unset ⇒ derived next to `MCPIP_WORM_PATH` (`.anchor`). |
| `MCPIP_FORENSIC_CAPTURE` | `None` (per-env) | Toggle for the [forensic payload capture](#forensic-payload-reconstruction) side-channel. Tri-state: unset ⇒ **ON in sandbox, OFF in production** (the fail-safe default); an explicit `true`/`false` always wins. Controls capture breadth only — retrieval is always `CAP_FORENSIC_READ`-gated + WORM-audited. In production, `true` additionally REQUIRES `MCPIP_FORENSIC_KEY_PATH`; the flag alone is not enough. |
| `MCPIP_FORENSIC_KEY_PATH` | `None` | Path to a raw **32-byte** AES-256 master key file, DEDICATED to forensics (never the vault or WORM key), encrypting captures at rest so Redis holds ciphertext only. In production with capture on, an absent key means the feature is **ABSENT** (captures dropped, retrieval `404`s) — fail-closed, never a plaintext fallback. Unset + sandbox ⇒ a persistent dev key auto-provisions under `.keys/`. |
| `MCPIP_AUTHN_WEBHOOK_URL` | `None` | HTTPS sink the [out-of-band step-up code](#out-of-band-delivery--the-authenticator-channel) is pushed to in production (SSRF-guarded, HMAC-signed; no OTP is ever stored in Redis). Required **together with** the secret path to activate delivery. With **both** unset, every `pin_required` staging fails closed (`otp_delivery_failed`) — an AUTO-only deploy leaves them blank. Setting **exactly one** of the two is a fail-closed **boot** error. The URL must be `https` and must not resolve into a private/loopback/link-local range. Sandbox ignores this (it uses the Redis stash+peek demo channel). |
| `MCPIP_AUTHN_WEBHOOK_SECRET_PATH` | `None` | Path to the raw **≥32-byte** HMAC-SHA256 signing secret used to sign each pushed notice (`X-MCPIP-Signature`). Loaded as raw bytes; never logged, never a metric label, never in the notice body. A shorter secret is a fail-closed boot error. Unset ⇒ (with the URL also unset) delivery is **absent**. |
| `MCPIP_AUTHN_WEBHOOK_TIMEOUT_S` | `5.0` | Bounded connect+read wall-clock ceiling for one webhook push, clamped to `[MIN_AUTHN_WEBHOOK_TIMEOUT_S, MAX_AUTHN_WEBHOOK_TIMEOUT_S]` = `[0.5s, 30s]` at construction so a misconfiguration can neither hang a staging request nor set a sub-threshold value that always fails closed. |
| `MCPIP_REDIS_MAX_CONNECTIONS` | `64` | Redis async connection-pool size (safe-win: pooling on the hot path). |
| `MCPIP_REDIS_POOL_TIMEOUT_S` | `5.0` | Max seconds to wait for a pooled Redis connection before failing closed. |
| `MCPIP_LOCK_TTL_SECONDS` | `300` | Payload-lock TTL (`PIN_TTL_SECONDS`). |
| `MCPIP_MAX_IN_FLIGHT` | `64` | Admission bound: max concurrent in-flight `/v1/authorize`-class requests **per worker** before new arrivals are shed with an opaque `503 + Retry-After`. Bounds tail latency (excess load fast-fails instead of queueing unboundedly). Probes (`/healthz`, `/readyz`) are never counted or shed. |
| `MCPIP_REQUEST_TIMEOUT_S` | `15.0` | Per-request wall-clock ceiling (backstop for a stuck dependency). A timeout only cancels the coroutine — it never double-executes and never converts a DENY into an ALLOW. |
| `MCPIP_SHED_RETRY_AFTER_S` | `1` | `Retry-After` seconds advertised on a shed `503`. |
| `MCPIP_WORKERS` · `MCPIP_BACKLOG` | `4` · `2048` | uvicorn worker processes and kernel accept backlog (horizontal + backlog half of the load-shed fix). |
| `MCPIP_API_HOST` · `MCPIP_API_PORT` | `0.0.0.0` · `8080` | Bind address/port for `uvicorn app.main:app`. |
| `MCPIP_REGION` | `None` | **Behavior-neutral** operator region/cell tag (e.g. `us-east-1`, `eu-frankfurt`, `gov-cloud`), surfaced read-only on `/healthz` + `/v1/version` for console/SDK display and log correlation. It changes **nothing** — no routing, authorization, Redis key derivation, or storage (every key is already tenant-prefixed, so region pinning is an edge/deployment concern: one MCPIP + Redis stack per region). Deliberately **never a metric label** (a free-form string would break the closed-enum label discipline). Unset ⇒ the tag is simply absent (honest unset state); boot is byte-for-byte unchanged. Design: [`docs/OPERATIONS.md`](docs/OPERATIONS.md). |

### Scaling & graceful load-shedding

The gateway is fully **stateless** — every synchronization datum (payload locks,
compartment grants, the WORM durable buffer + signed epoch chain, rate counters) lives
in Redis; epoch closes are Redis-lock-serialized and `emit` is atomic Lua. So it scales
**horizontally by process and by node**:

- Run `MCPIP_WORKERS ≈ 1–2 × cores` per node behind an L4/L7 load balancer, and add
  nodes for more throughput. Each worker installs **uvloop** (`--loop uvloop`, clean
  fallback to stdlib asyncio) and the **httptools** parser.
- Each worker holds its own `BlockingConnectionPool` (`MCPIP_REDIS_MAX_CONNECTIONS=64`)
  and its own `MCPIP_MAX_IN_FLIGHT` admission bound. Size `workers × max_in_flight ≤`
  the shared Redis `maxclients` headroom.
- `--backlog 2048` lets momentary bursts **queue at the kernel accept layer** instead of
  being refused with `ConnectError`, while `MCPIP_MAX_IN_FLIGHT` **sheds sustained
  overload** with a fast `503 + Retry-After` and bounded p99. This resolves the prior
  single-worker failure mode (flat throughput, unbounded p99, dropped connections under
  extreme concurrency).

> **Two halves, and why a single box can't prove it.** App-layer admission control
> (`MCPIP_MAX_IN_FLIGHT`) bounds **work-in-flight** — excess load fast-fails with an opaque
> `503` and bounded p99 the instant a connection is *accepted*. But the connection **storm**
> tail (the ~0-drop / bounded-end-to-end-p99 target at 2k–10k concurrency) also needs the
> **kernel accept queue** raised: `--backlog 2048` is **silently clamped** to
> `net.core.somaxconn` (Linux) / `kern.ipc.somaxconn` (macOS), whose default is often `128`.
> Until you raise that sysctl (`sysctl -w net.core.somaxconn=2048`, or a k8s
> `sysctl`/initContainer), a >128-connection burst is refused **by the kernel** before the
> app-layer limiter can shed it — so a single co-located host (notably macOS at
> `somaxconn=128`) cannot demonstrate the ~0-drop claim regardless of `--backlog` or worker
> count. The full guarantee is: **raise somaxconn ≥ backlog + put an L4/L7 load balancer in
> front + scale horizontally across worker processes and nodes.** The app-layer `503`
> shedding provably engages and is fast *once connections are accepted*; the storm/tail
> bound is a deployment-topology property, not something a single box provides.

Shedding is **fail-closed and shedding-only**: a shed request never reaches `authorize()`
and produces no receipt, so it is structurally impossible for load-shedding to convert a
would-be DENY into an ALLOW.

Runtime dependencies (`requirements.txt`) — std-lib only otherwise:

```
pydantic>=2.6,<3
redis>=5.0,<6
PyJWT>=2.8,<3
cryptography>=42.0
fastapi>=0.111,<1
uvicorn[standard]>=0.30,<1
pydantic-settings>=2.2,<3
prometheus-client>=0.20,<1
```

---

## Performance

The performance tier is opt-in speed on top of an unchanged security posture — no
fast path is allowed to alter a single authorization decision.

- **uvloop + httptools.** `app.main` installs uvloop as the event-loop policy at import
  (clean fallback to stdlib asyncio — `/healthz` reports which via its `loop` field),
  and the image runs `uvicorn --loop uvloop --http httptools`.
- **Request pre-check.** The edge middleware rejects an oversized declared
  `Content-Length` with an opaque `413` **before reading a single body byte** (then
  hard-caps buffered/chunked bodies at the same 256 KiB bound), so oversized traffic
  never costs parsing work or an admission slot.
- **Admission control / load-shedding.** `MCPIP_MAX_IN_FLIGHT` (default 64/worker)
  bounds work-in-flight; excess arrivals shed with an opaque `503 + Retry-After`
  (`mcpip_requests_shed_total{cause="overload"}`), keeping p99 bounded under sustained
  overload. Probes (`/healthz`, `/readyz`, `/metrics`) are never counted or shed, and a
  shed request never reaches `authorize()` — shedding structurally cannot turn a DENY
  into an ALLOW. See [Scaling](#scaling--graceful-load-shedding) for the
  `--backlog`/somaxconn half.
- **Read-side caching (honest note).** Server-assisted RESP3 client-side caching was
  evaluated and is **not usable here**: redis-py's *async* client (the only client MCPIP
  uses) exposes no `cache`/`cache_config` hooks. The shipped equivalent is
  `services/grant_cache.py` — a per-worker, TTL-bounded (1 s) **negative** cache on the
  hot grant lookup that only ever memoizes "no active grant": a stale entry can only
  turn a would-be ALLOW into a brief DENY (fail-safe); an ALLOW is always a fresh
  authoritative Redis read, so revocations bite on the very next lookup.
- **Opt-in Rust fast path.** `MCPIP_FAST_WALKER=1` routes `canonical_json` and the
  ingress safety walk through the PyO3 crate `rust/mcpip_fastwalk` (build with
  `maturin`). It activates only if the extension imports **and** its Unicode tables
  match CPython's; on any `Defer` (floats, out-of-range ints, lone surrogates) it falls
  back per-payload. The gate is `tests/test_fastwalk_differential.py`: byte-identical
  canonical bytes and decision-identical rejections versus pure Python, or it doesn't
  ship. **Pure Python is the default** — the flag unset, missing, or mismatched always
  means the reference implementation.

**Honest capacity notes** (order-of-magnitude planning numbers, not marketing):
durability is the ceiling — with `appendfsync always` (non-negotiable: write-before-
execute) the **measured** durable audit-emit rate is **~750 emit/s single-caller**
(fsync-latency-bound, p50 ≈ 1.1 ms) rising to **~2.3–4.5k emit/s in aggregate under
concurrency** (Redis coalesces fsyncs per event-loop tick, so the bottleneck shifts off
the fsync onto Redis's single-threaded Lua) — per Redis shard. A single CPU-bound worker
sustains **~850 authorize/s** on the AUTO path; the step-up
approval path is far heavier (staging + out-of-band code + atomic consume), so plan
around **~100 approval-consume/s per process**. Scale reads horizontally (stateless
workers/nodes); scale durable writes by sharding Redis per tenant/cell. The durable-emit
ceiling is now measured, not estimated — reproduce it with
[`scripts/bench_worm_emit.py`](scripts/bench_worm_emit.py) and see
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full curve (serial vs.
concurrent, `always` vs. `everysec`) and the group-commit design that would raise it.

---

## Documentation

**The enterprise doc set** — the hubs below are the front door;

- [**Operator & deployment guide**](docs/OPERATIONS.md) — self-host / VPC / air-gapped install, the fail-closed production boot, the dark-feature flags stated honestly, region topology, non-bypassability, and desktop packaging. The deployment hub.
- [**Client SDKs & CLI index**](docs/GETTING_STARTED.md) — the shared Python/TypeScript client contract + the `mcpip` CLI, the three-client model, the PIN ceremony, envelopes, and opaque-deny semantics. The client hub.
- [**Coordinated disclosure**](SECURITY.md) — how to report a vulnerability privately.

**Reference docs** (authoritative product/security/legal/feature references):

- [**Operations runbook**](docs/OPERATIONS.md) — the deep day-2 ops: key ceremony + rotation, `mcpip verify`, license install, audit verification/export, backup & restore, incident response, deploy preflight.
- [**Compliance pack**](docs/COMPLIANCE.md) — the shipped controls mapped to SOC 2 / FedRAMP (NIST 800-53) families and the supply-chain statement (illustrative mapping, **not** a certification).
- [**Security threat model**](SECURITY_THREAT_MODEL.md) — the formal adversary model, the per-threat attack→defense→code matrix, the §17 OWASP ASI-2026 coverage map, and an honest residual-risk analysis.
- [**Whitepaper**](docs/WHITEPAPER.md) — threat model, the seven invariants, and the formal argument for authorization-before-execution.
- Feature deep-dives: [workload identity](docs/INTEGRATIONS.md) · [telemetry](docs/TELEMETRY.md) · [OAuth resource server](docs/INTEGRATIONS.md) · [extensibility](docs/EXTENSIBILITY.md) · [governed-alias pattern](docs/INTEGRATIONS.md) · [A2A choke-point](docs/ARCHITECTURE.md) · [workspace generate](docs/WORKSPACE_GENERATE.md).
- Runnable walkthroughs: [demo company](docs/GETTING_STARTED.md) · [Claude MCP bridge](docs/GETTING_STARTED.md) · [DynamoDB live-fire](docs/INTEGRATIONS.md) · [end-to-end lifecycle](docs/GETTING_STARTED.md).

**FUTURE-wave design docs** (rigorous designs + honest scope boundaries — the three below are *designs and decisions, not built substrate rewrites*):

- [**Group-commit WORM throughput**](docs/ARCHITECTURE.md) — a **REAL benchmark** of the current durable-before-authorize ceiling (reproduce with [`scripts/bench_worm_emit.py`](scripts/bench_worm_emit.py)) plus the app-managed-WAL group-commit design that would raise it. Raising the ceiling for real is a substrate rewrite of the tamper-evidence core — an explicit **owner decision, deferred**; `audit/worm_logger.py` is untouched.
- [**Multi-region topology & residency**](docs/OPERATIONS.md) — region-pinned tenants as a *deployment* shape (one MCPIP + Redis cell per region, because every key is already tenant-prefixed); per-region WORM ledger with no cross-region chain. Ships only the behavior-neutral `MCPIP_REGION` observability tag; a cross-region control plane stays deferred.
- [**The data-plane fork**](docs/ARCHITECTURE.md) — a **decision memo** on whether MCPIP should ever enter the model's prompt/content path (the "oracle inversion" / taint-tracking pillars). Recommendation: hold the "interceptor, not a proxy" line; this is an explicit **owner decision, pending**. Writes no data-plane code and reserves no pointer token.

---

## Evaluate & work with us

- **Try it alone, free, now:** `./scripts/quickstart_demo.sh` (or `mcpip up`) — sandbox
  gateway + live walkthrough in one command; no signup, no sales call.
- **Questions / evaluation help:** [GitHub Issues](https://github.com/mcpip-security/mcpip/issues)
  · security reports via [`SECURITY.md`](SECURITY.md) (private disclosure).
- **Design-partner program** (regulated / high-consequence workflows): time-boxed pilot,
  self-hosted in your boundary, direct maintainer support — details + openly published
  structure in [`SUPPORT.md`](SUPPORT.md).

## Project policies

Published, versioned in-repo, and changed only by commit — diff the policy exactly as you
diff the code.

| Policy | What it covers |
|---|---|
| [`TERMS.md`](TERMS.md) | Terms of use: the license grant in plain terms, entitlements, acceptable use, operator responsibilities, no-certification statement, warranty & liability. |
| [`PRIVACY.md`](PRIVACY.md) | Data handling: what stays inside your boundary, and the two opt-in, default-off channels that can leave it. |
| [`SECURITY.md`](SECURITY.md) | Coordinated disclosure — how to report a vulnerability privately. |
| [`TRADEMARK.md`](TRADEMARK.md) | Name and mark usage: what needs no permission, what needs a different name. |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to contribute, the gates a change must pass, and what gets rejected. |
| [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1, plus one security-specific clause. |
| [`LICENSING.md`](LICENSING.md) | The component→license map (BSL core / Apache-2.0 SDKs). |

## License

**Open-core, source-available.** The gateway **core is licensed under the Business Source License
1.1** ([`LICENSE`](LICENSE)) — read, self-host, modify, and run in production for your own
organization; it converts to **Apache-2.0** on the Change Date (2030-07-16). The **client SDKs
(`sdk/python`, `sdk/typescript`) are Apache-2.0**. Enterprise features/support are gated by a
signed entitlement license (`core/licensing.py`), unchanged. Full map and the rationale:
[`LICENSING.md`](LICENSING.md) · [`TERMS.md`](TERMS.md).

<div align="center">

**◐ MCPIP** · _Authorize every AI action before execution._

**AI Reasons. MCPIP Authorizes. Systems Execute.**

</div>
