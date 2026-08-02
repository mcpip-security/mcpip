# ◐ MCPIP — Getting Started

This is the consolidated getting-started and onboarding reference for MCPIP — the one
page a new client, developer, or operator reads to go from a fresh clone to an
authorized, audited tool call. It folds together the client SDK/CLI index, the operator
run-up guide, the Claude / MCP host setup, the runnable company walkthrough, and the full
end-to-end lifecycle so you never have to hunt across scattered docs. MCPIP is a
zero-trust authorization gateway between an autonomous agent's tool calls and the systems
that execute them — pipeline: **Bridge** (normalize the provider dialects) →
**Obfuscator** (opaque alias → hidden target) → **Auth** (JWT + payload-bound one-time
PIN + proof-of-possession) → **Audit** (signed Merkle-epoch WORM log, written before
execution). Everything fails closed and opaque: an agent only ever names an opaque alias
and only ever sees a generic `MCPIPDenied` + a `correlation_id`; the real target and the
real deny-reason never cross the boundary.

> **The one rule that governs everything:** production is **fail-closed by default**
> (`MCPIP_SANDBOX_MODE=false`). The gateway *refuses to boot* until you supply a valid
> license, integrity manifest, and key material. That refusal is the safety net — not a
> bug to work around. Sandbox mode mounts a sandbox IdP (JWT forge) + OTP peek so you can
> exercise the whole pipeline before provisioning anything; **never** run sandbox in
> production.

For deeper reading: the product overview is in [`README.md`](../../README.md) and the
seven security invariants, the adversary model, and the attack → defense → code matrix are
in [`SECURITY_THREAT_MODEL.md`](../SECURITY_THREAT_MODEL.md) — which also carries the
honest residual-risk boundary, including what is deferred rather than shipped. The design
thesis ("an interceptor, never a proxy") and the request pipeline are in
[`ARCHITECTURE.md`](../integrate/ARCHITECTURE.md); deploy, upgrade, compliance and runbook
procedures in [`OPERATIONS.md`](../operate/OPERATIONS.md); workload-identity,
provider-dialect and cloud-IAM integration in
[`INTEGRATIONS.md`](../integrate/INTEGRATIONS.md); and the full HTTP surface in
[`API.md`](API.md).

---

## Quickstart — run it now

**Three concepts are enough to start — the rest can wait:**

1. **Connect** — point your agent at one URL. The gateway *is* an MCP server
   (`POST /v1/mcp`), and the REST edge (`POST /v1/authorize`) speaks every major
   provider dialect. One config block, no proxy, no sidecar.
2. **Protect** — a *skill* is an opaque alias for a real target, with a risk tier.
   Agents only ever see the alias; the target never crosses the boundary.
3. **Approve** — a high-risk call doesn't fail, it *stages*: a one-time PIN bound to
   the exact payload must come back before anything executes.

Tenants, compartments, canaries, grants, editions — all real, all documented below,
none needed for your first governed call.

You have three ways to get a live sandbox gateway on `:8080`. All are self-contained; none
needs an external IdP.

### Option A — one command (the company walkthrough)

The fastest path also runs the walkthrough. **Just run this — it does everything**
(auto-installs Redis via Homebrew if missing, creates a venv, installs deps, boots the
sandbox gateway, and runs the `mcpip-inc` walkthrough):

```bash
./scripts/quickstart.sh     # or, with the mcpip CLI installed:  mcpip up
```

Both run the same script (the CLI verb just finds your checkout and executes it), are
idempotent, and finish by printing your **zero → first governed call** time — the DX
north star is under five minutes on a clean machine.

Only prerequisite: **Python 3.12** (and, on macOS, [Homebrew](https://brew.sh) so the
script can install Redis for you). It is idempotent — anything already running is reused,
never restarted. See [Company Walkthrough](#company-walkthrough) for what it
shows.

### Option B — Docker (60-second smoke test)

```bash
git clone https://github.com/mcpip-security/mcpip.git && cd mcpip
MCPIP_SANDBOX_MODE=true docker compose up --build     # gateway :8080 + internal Redis (AOF always-on)

# In another shell — mint a sandbox token and fire an authentic call:
TOKEN=$(curl -s localhost:8080/v1/dev/token -d '{}' -H 'content-type: application/json' | jq -r .jwt)
curl -s localhost:8080/v1/authorize -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{
  "source_format":"openai_tool_call",
  "tool_call":{"id":"c1","type":"function","function":{"name":"skill_spend_summary","arguments":"{\"period\":\"2026-Q2\"}"}}}'
# -> {"decision":"allow","status":"committed","executed_target_class":"cloud_rest",...}
```

> **Discover capabilities & confirm a token (sandbox).** The capability UUIDs that gate the
> admin/audit control plane are fixed constants — `GET /v1/dev/capabilities` lists them by name
> (`CAP_DIRECTORY_ADMIN`, `CAP_FORENSIC_READ`, …) so you never have to read source to mint an
> admin token, and `GET /v1/whoami` echoes the *verified* identity + effective capabilities of
> whatever token you present, so you can confirm what it carries instead of probing via opaque
> denies. Minting a token with a non-UUID capability now fails fast with a clear `400`.

### Option C — manual (venv + Redis + uvicorn)

MCPIP is Python 3.12 + Redis. In sandbox mode the gateway also exposes a sandbox-token minter
(`POST /v1/dev/token`) so the walkthrough is runnable without an external IdP; production
never mints identities. `redis-server` needs Redis installed (`brew install redis`), and
`python -m uvicorn` avoids depending on a console script.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1. Redis. The AOF flags are what make a decision's audit record fsync-durable BEFORE
#    the action is authorized — the write-before-execute invariant. Production requires
#    them (the gateway refuses to boot otherwise); set them here so the sandbox behaves
#    like production rather than only claiming to.
redis-server --port 63790 --daemonize yes --appendonly yes --appendfsync always

# 2. The gateway, in sandbox mode (background). Wait ~2s, then check /healthz.
MCPIP_SANDBOX_MODE=true MCPIP_REDIS_URL=redis://localhost:63790/0 \
    python -m uvicorn app.main:app --port 8080 &

# 3. Confirm it's live  →  {"status":"live","glyph":"◐",...}
sleep 2 && curl -s http://localhost:8080/healthz
```

### Smoke-test the invariants, then open the console

```bash
python main.py                       # 29 checks: 7 allow-paths + 22 attacks — exits 0 iff every one holds
docker compose --profile demo up     # the same demo, containerized
cd dashboard && npm install && npm run dev     # operator console → :5173
```

`python main.py` needs Redis and is the fastest confidence check: forged-JWT rejections,
the canary tripwire, the WORM epoch verify, and more — exit 0 means all invariants hold.

### Troubleshooting

The gateway is **fail-closed**, so the most common first-run surprise is a call that
denies for a reason the *agent* is never told (that opacity is the design — reasons live
in the audit log, not on the wire). The fixes below cover what that usually means.

When you have a `correlation_id` from a denial, start with **`mcpip why <correlation_id>`**.
It resolves the id against the audit log and prints what happened plus the concrete next
step, instead of leaving you to interpret a machine token:

```console
$ mcpip why ee843779451141798559da2f23acf4c4
ee843779451141798559da2f23acf4c4  DENY
  alias          skill_spend_summry
  agent          agent-dev
  format         raw_mcp
  reason         unknown_alias  (catalog)
  arguments      {'period': '2026-Q2'}

The alias does not resolve for this tenant.

  Fix: Check the spelling, and confirm the alias is in this tenant's catalog:
  `mcpip catalog`. Registering one is `mcpip admin skills register`.
```

This reads the same capability-gated surfaces the console does — it does not make the
agent-facing wire any less opaque. Without a credential it says so rather than guessing.

| Symptom | Almost always means | Do this |
|---|---|---|
| **Every** call returns `MCPIP: request denied by policy` | Two common causes, and they are easy to tell apart. (1) The gateway is reachable but **not ready** — its Redis-backed audit store is down, so it refuses to execute anything it cannot first record. `GET /healthz` still says `live`, because it checks the process, not Redis. (2) Your token's `tenant_id` owns none of the aliases you are calling, so every alias resolves to `unknown_alias`. Minting with `-d '{}'` takes the default tenant, which is a common mismatch. | `curl localhost:8080/readyz` first — if `redis` is not `up`, start it (`redis-server --port 63790`). If it *is* up, the audit log has the real reason: `mcpip why <correlation_id>`. Check the tenant you are calling as with `mcpip whoami`, and what it can see with `mcpip catalog`. |
| `command not found: mcpip` | The CLI (the `mcpip-sdk` package) is not on your `PATH` — `quickstart.sh` builds the gateway's venv but does not install the CLI. | `source .venv/bin/activate && pip install ./sdk/python`, or `pipx install ./sdk/python` for a global command. |
| One specific alias denies with exit `3` | Opaque deny — the identity is not entitled (wrong tenant/compartment, missing capability), or a `pin_required` alias needs the step-up. It is working as designed. | `mcpip why <correlation_id>` — it reads the audit log and tells you the reason **and the fix**. Needs `CAP_FORENSIC_READ` or `CAP_DIRECTORY_ADMIN`; the agent wire stays opaque. |
| A `pin_required` alias returns `202` with a `challenge_id` | Not an error — a payload-bound one-time PIN is staged. | Fetch the code (`sandbox authenticator <challenge_id>`) and complete the call with the same payload + pin. |
| `/v1/audit/verify` reports `intact:false` (and the compliance evidence bundle agrees) | The chain and its **witness** disagree. The out-of-tamper-domain anchor records the highest epoch ever sealed, and lives outside Redis precisely so a rollback cannot erase it — so a store that was wiped while the anchor survived is, correctly, indistinguishable from a rollback. Until 3.0.0 the sandbox reproduced this routinely: Redis ran without AOF, so the documented stop line (`shutdown nosave`) discarded the chain and left the witness behind. | The quickstart now runs Redis with `--appendonly yes --appendfsync always`, so the chain survives a normal stop and this no longer happens. If you deliberately reset, wipe **both together**: `redis-cli -p 63790 flushall; rm -f mcpip_worm.jsonl.anchor`. Never delete the anchor in production — there, an anchor ahead of the chain is the incident it exists to surface. |
| Production gateway **refuses to boot** | Also by design — `MCPIP_SANDBOX_MODE=false` fails closed until a valid license, integrity manifest, and key material are supplied. | See [Boot production](#boot-production-fail-closed-zero-hardcoded-secrets). For a quick local run, use sandbox mode. |

---

## Connecting an Agent (REST + MCP)

**Two edges, one pipeline, six declared dialects (never sniffed).** The gateway *is* the
MCP server the client connects to — it never forwards to an external MCP server.

- `POST /v1/authorize` — REST. Identity via `Authorization: Bearer` (or body `jwt`).
- `POST /v1/mcp` — MCP-native JSON-RPC 2.0 (`initialize`, `tools/list`, `tools/call`).

**Format is declared, never guessed.** Supply exactly one of:

- `source_format` — one of `openai_tool_call`, `anthropic_tool_use`,
  `gemini_function_call`, `bedrock_tool_use`, `mcp_jsonrpc`, `raw_mcp`; **or**
- `vendor` — e.g. `openai`, `gemini`, `claude`, `bedrock`, `copilot`, `deepseek`, `qwen`,
  resolved through a **hash-pinned** registry to one of those formats.

Unknown vendor → opaque `403`; neither field → `422`. (The A2A `a2a_task` dialect is the
7th connector format, gated the same way.)

### Copy-paste end-to-end (sandbox)

```bash
# 1) Mint a sandbox JWT (sandbox only — 404s in production).
TOKEN=$(curl -s localhost:8080/v1/dev/token -d '{}' -H 'content-type: application/json' | jq -r .jwt)

# 2) AUTO alias → executes immediately. Response is opaque: decision + committed status
#    + a coarse transport CLASS (executed_target_class), never the real target.
curl -s localhost:8080/v1/authorize -H "authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{
  "source_format":"openai_tool_call",
  "tool_call":{"id":"c1","type":"function","function":{"name":"skill_spend_summary","arguments":"{\"period\":\"2026-Q2\"}"}}}'

# 3) Enumerate only what THIS identity may see (opaque aliases; other teams filtered out).
curl -s localhost:8080/v1/catalog -H "authorization: Bearer $TOKEN"
```

### Entitlements, opaque deny, and the PIN step-up

- **Entitlements** ride the **JWT `capabilities` claim** (strict UUID list) and/or
  Redis-held **grants** — never a role string. Compartmented aliases deny unless the
  caller holds a direct compartment claim or an active delegated grant.
- **Every denial is opaque** — `{error, correlation_id}`; the concrete reason lives in the
  WORM ledger only. Your agents see only opaque aliases; real targets never cross the wire.
- **High-risk tools return a `202` step-up** — the `PIN_REQUIRED` alias returns a
  `challenge_id`, not data. A human approver completes it out-of-band via the enrolled
  authenticator (OTP) against the **same** payload; nothing about the amount can change
  between challenge and execution. See [The human factor](#the-human-factor--pin-step-up).

---

## SDKs and the `mcpip` CLI

MCPIP ships two first-party clients with **full console parity** plus the `mcpip` CLI that
wraps them. Both speak the **identical wire protocol** and expose the same surface with the
same method names (snake_case in Python, camelCase in TypeScript). The shipping package
READMEs remain authoritative for install:
[`sdk/python/README.md`](../../sdk/python/README.md) ·
[`sdk/typescript/README.md`](../../sdk/typescript/README.md). Full contract + code samples:
[`SDK.md`](SDK.md); full CLI command tree: [`CLI.md`](CLI.md).

| | Python | TypeScript |
|---|---|---|
| Location | `sdk/python` | `sdk/typescript` |
| Package | `mcpip-sdk` (import `mcpip_sdk`) | `@mcpip/sdk` |
| Runtime deps | `httpx` only | none (global `fetch`, Node ≥ 18) |
| Types | `py.typed`, frozen dataclasses, `mypy --strict` | `.d.ts`, `strict: true` |
| Own version | `0.1.0` — independently versioned, **not** gateway-lockstep | `0.1.0` |

> **Version nuance — the SDKs are independently versioned.** `sdk/python/pyproject.toml`
> and `sdk/typescript/package.json` sit at `0.1.0` **deliberately** — they are not bumped
> in lockstep with the gateway `VERSION`. A client reconciles with the gateway by *reading*
> its running version (`mcpip version` → `/v1/version`), never by matching package numbers.

### The three-client model

| Python | TypeScript | Role |
|---|---|---|
| `MCPIPClient` | `McpipClient` | Agent surface — authorize, catalog, MCP edge, health/version/license, the COAZ decision + RFC 9728 metadata reads |
| `SandboxClient` | `McpipSandboxClient` | Agent surface **plus** sandbox-only affordances (dev token, authenticator code, audit verify/proof) — `404` in production, by design |
| `MCPIPAdminClient` | `McpipAdminClient` | the `CAP_DIRECTORY_ADMIN` control plane — skills, decisions feed, principals, directory, workspace, cloud environments, vault, quarantine/canary rosters, extensions/publishers, compliance evidence, deployment stats |

### Opaque-deny semantics (identical to the gateway)

A denial surfaces **only** as `MCPIPDenied` (Python) / `McpipDenied` (TS) carrying the
generic message + `correlation_id` — never a reason, target, topology, or gateway state.
Clients are fail-closed and **never auto-retry**. Secrets (JWT, OTP, vended credentials)
never touch stdout/argv/logs — a bearer is never accepted as a plain argv value.

### The PIN step-up ceremony (in code)

A `PIN_REQUIRED` alias submitted with no PIN stages a challenge; the client completes it
with the out-of-band one-time code against the **same** payload:

`authorize()` returns a union — `Allowed` (200) or `Staged` (202) — so you narrow on the
type rather than checking a flag. The type checker then knows `challenge_id` exists only
on the staged branch.

```python
from mcpip_sdk import MCPIPClient, Staged

with MCPIPClient("http://localhost:8080", token=jwt) as client:
    result = client.authorize(
        "skill_wire_transfer",
        {"payee": "enrolled:ACME_PAYROLL", "amount_cents": 2418000},
    )
    if isinstance(result, Staged):        # 202 — a challenge_id was returned
        receipt = client.complete(result, pin=one_time_code)   # same payload + pin → 200
```

In sandbox you can read the code back through `SandboxClient`, which stands in for the
out-of-band delivery your enrolled authenticator does in production:

```python
from mcpip_sdk import SandboxClient, Staged

with SandboxClient("http://localhost:8080") as client:
    client.set_token(client.dev_token(tenant_id="tenant-acme", agent_id="agent-1"))
    result = client.authorize(
        "skill_wire_transfer",
        {"payee": "enrolled:ACME_PAYROLL", "amount_cents": 2418000},
    )
    if isinstance(result, Staged):
        receipt = client.complete(result, pin=client.authenticator_code(result.challenge_id))
        print(receipt.decision, receipt.worm_sequence)     # allow 179
```

The payload lock is format-independent and byte-identical across all seven dialects; the
client never sees the target. Over the MCP edge, the same step-up can ride the opt-in MRT /
SEP-2322 transport (`stepUp:"mrt"`) — see [`INTEGRATIONS.md`](../integrate/INTEGRATIONS.md).

### Envelopes — every dialect

Both SDKs ship builders for every wire shape (`openai_tool_call`, `anthropic_tool_use`,
`gemini_function_call`, `bedrock_tool_use`, `mcp_jsonrpc`, `raw_mcp`, `a2a_task`) so a
caller constructs the provider envelope without hand-assembling JSON. Format is
**declared, never sniffed** — and a `tests/test_connector_conformance.py` guard runs each
builder's output through the real strict ingress, so a builder can never drift from the
dialect it claims to speak.

### The `mcpip` CLI

The library you *import* also ships the `mcpip` command you *run* — a fail-closed, opaque,
git/kubectl-style CLI that wraps the typed clients (no reimplemented wire/auth/envelope
logic; `httpx` stays the one runtime dep). Zero to an authorized call in three commands:

```bash
pipx install ./sdk/python                          # or: brew install --HEAD mcpip/tap/mcpip
mcpip login --gateway http://localhost:8080 --sandbox --context sbx
mcpip --context sbx sandbox dev-token --agent agent-quickstart   # identity, never printed
mcpip --context sbx authorize skill_spend_summary --arg period=2026-Q2
```

- **`mcpip version`** reads the running gateway's `/v1/version` — the **real** version,
  reconciling with whatever gateway it points at, never a baked-in literal.
- `--json` for scripting, `--quiet` for the load-bearing id only, stable exit codes (a deny
  is `3`). The `--json` deny payload is `{"error":"denied","correlation_id":…}` — never
  `http_status`.
- Admin surface (needs a `CAP_DIRECTORY_ADMIN` / `CAP_CATALOG_REVIEWER` token):

  ```bash
  mcpip --context sbx admin stats                        # live deployment/license/usage + honest telemetry state
  mcpip --context sbx admin compliance evidence --json   # export the REAL signed evidence bundle (evidence, never a cert)
  mcpip --context sbx admin publishers set --namespace io.github.acme
  ```

- Config is kubeconfig-shaped TOML contexts (`O_EXCL 0600` writes; fail-closed on
  group/world-readable). Secrets go via file/stdin/getpass — never argv.

---

## Claude / MCP client setup

Let Claude (Claude Code or Claude Desktop) call tools **through** the MCPIP gateway, so
every tool call is authorized, obfuscated, and WORM-logged before it runs.

### Why a bridge?

MCPIP's MCP edge (`POST /v1/mcp`) is zero-trust and fail-closed: identity comes only from a
verified JWT on the `Authorization: Bearer` header. A plain MCP client has no way to obtain
or attach that token, so pointing Claude straight at `/v1/mcp` gets **every `tools/list` /
`tools/call` denied** — correctly, by design.

`scripts/claude_mcp_bridge.py` is the missing piece. It speaks the MCP **stdio** transport
to Claude and forwards each call to MCPIP over HTTP, attaching a valid JWT and pinning the
right tenant:

```
Claude ──stdio(JSON-RPC)──▶ claude_mcp_bridge.py ──HTTP + Bearer JWT──▶ MCPIP /v1/mcp
```

It is a thin, honest proxy — it never fabricates a tool result; every response is the
gateway's real decision (an allow receipt or an opaque deny). Stdlib only, Python 3.9+.

### The easy way — zero setup (Claude Code)

The repo already ships a project `.mcp.json` registering the bridge. Just run `claude`
inside the repo and approve the `mcpip` server when prompted — the bridge mints the sandbox
token itself and refreshes it before expiry, so a long session keeps working. Ask Claude to
list its `mcpip` tools, then call one (e.g. `skill_company_overview`). To register it in
another project:

```bash
claude mcp add mcpip --env MCPIP_URL=http://localhost:8080 --env MCPIP_TENANT=mcpip-inc -- python3 /path/to/mcpip/scripts/claude_mcp_bridge.py
```

### Alternative — HTTP transport with a pinned token

MCPIP's `/v1/mcp` is Streamable-HTTP-compatible, so this also works:

```bash
claude mcp add mcpip --transport http http://localhost:8080/v1/mcp --header "Authorization: Bearer $TOKEN"
```

> ⚠️ **Sandbox pitfall — the pinned token expires.** A `/v1/dev/token` JWT lives ~5
> minutes, and the HTTP transport pins it as a static header — after expiry EVERY call is
> an opaque deny until you re-add the server with a fresh token. That is the gateway being
> correct, not broken. For anything longer than a quick probe, prefer the **stdio bridge**
> (above): it re-mints proactively, so a long Claude session keeps working. In production
> the HTTP variant is fine with a long-lived IdP-issued JWT.

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcpip": {
      "command": "python3",
      "args": ["/absolute/path/to/mcpip/scripts/claude_mcp_bridge.py"],
      "env": { "MCPIP_URL": "http://localhost:8080", "MCPIP_TENANT": "mcpip-inc" }
    }
  }
}
```

### Bridge configuration

| Env | Default | Meaning |
|-----|---------|---------|
| `MCPIP_URL` | `http://localhost:8080` | Gateway base URL |
| `MCPIP_TENANT` | `tenant-acme` | Tenant the agent acts under (use your company tenant) |
| `MCPIP_AGENT` | `anthropic-claude` | Agent id recorded on the minted JWT — vendor-prefixed by convention, so decisions are attributed to their framework |
| `MCPIP_TOKEN` | — | A real IdP-issued JWT. **Set this in production** — when present the sandbox dev-token minter is never called, so MCPIP stays identity-sovereign. |

### Production

`/v1/dev/token` does not exist on a production gateway (it `404`s), so set `MCPIP_TOKEN` to
a JWT your own IdP issued for the agent. The bridge attaches it verbatim and never mints —
identity stays with your IdP; MCPIP only authorizes and audits.

### Why calls get denied

- **No token** → the boundary denies `tools/list` / `tools/call` (use this bridge, or
  attach `Authorization: Bearer <jwt>` yourself).
- **Wrong tenant** → a token for tenant A can't see tenant B's skills (`UNKNOWN_ALIAS`).
  Point `MCPIP_TENANT` at the tenant your skills are registered under.
- **Compartment / PIN** → compartmented or `pin_required` skills deny without the grant or
  a payload-bound PIN. That's the gateway doing its job.

### Drive the MCP connector live from your terminal

Before wiring up a full agent host, hold the MCP session in your own hands.
`scripts/mcp_terminal.py` is an interactive MCP **client** speaking the exact protocol
Claude Code speaks (`initialize → tools/list → tools/call`), every command a real
round-trip:

```
$ python scripts/mcp_terminal.py
◐ connected — mcpip v3.0.0 · MCP 2025-06-18 · http://localhost:8080

mcp❯ login agent-eng-1 engineering
✓ licensed agent-eng-1 @ mcpip-inc · team engineering
mcp❯ tools
✓ 4 tool(s) visible … (finance skills are NOT listed — invisible, not merely forbidden)
mcp❯ call skill_company_overview
✓ ALLOW — committed through the pipeline (WORM-logged before dispatch)
mcp❯ call skill_financial_wage_sheet
✕ DENY — "MCPIP: request denied by policy."   · correlation …
mcp❯ login agent-fin-1 finance
mcp❯ call skill_financial_wage_sheet
✓ ALLOW — committed
```

It is also scriptable (`printf 'login\ntools\n' | python scripts/mcp_terminal.py` — `printf`
rather than `echo`, which does not interpret `\n` in bash), and in
production it uses your IdP-minted license via `MCPIP_TOKEN` instead of the sandbox minter.

### A note on console visibility

Claude's calls through the bridge are real `/v1/authorize` decisions and are durably
WORM-logged. They do **not** yet stream into the operator console's live decision feed —
the gateway intentionally exposes no list-events HTTP endpoint, so the console shows only
decisions it drives itself. Audit them via `export-audit` / the signed chain.

---

## Standing up a gateway (operator: provision, license, boot)

A hands-on runbook for the operator standing MCPIP up in your environment: provision
credentials, install your license, boot production fail-closed, then operate and upgrade.
Every command is copy-paste and grounded in the shipped tooling. Full ops procedures live
in [`OPERATIONS.md`](../operate/OPERATIONS.md).

### Prerequisites

- Docker + docker-compose (or Kubernetes + Helm — see [`OPERATIONS.md`](../operate/OPERATIONS.md)).
- A Redis you control (linearizable, `appendonly yes` / `appendfsync always`,
  `maxmemory-policy noeviction`). The bundled compose ships one, internal-only.
- Python 3.12 (production target; the Rust accelerator is `abi3-py312`).
- The signed release bundle + the public verification keys you were delivered.

### Verify the supply chain (before you install)

Nothing is trusted on faith — verify before you install. The release ships a **CycloneDX
SBOM**, an offline-root-signed **release manifest**, and a **boot-integrity manifest**
signed as the last step before the image is built (an air-gap bundle is available for
disconnected installs). These matter because the gateway **refuses to boot** in production
unless the integrity manifest and license verify.

Verifying *before* you install means you cannot rely on an installed command, so run the
verifier straight from the checkout — it needs only Python, and never touches the network:

```bash
python -m mcpip_verify verify --manifest release/manifest.json \
  --pubkey release/keys/release_root_ed25519.pub.pem --base-dir .
```

Exit `0` prints `verified: mcpip <version> (<n> artifacts)`. Any failure prints exactly
`verification failed` and exits `2` — opaque on purpose, so a tampered artifact learns
nothing about which check caught it.

Once something is installed, the same verifier is `mcpip-verify verify …` (gateway
distribution) or `mcpip verify …` (the SDK CLI passes through to it).

The audit export is the same tool. `--verify` independently re-checks the whole signed
chain: Merkle roots, `epoch_hash`, `prev_epoch_hash` linkage, the Ed25519 epoch
signatures, and the out-of-tamper-domain anchor low-watermark. `--pubkey` is required by
`--verify` — it refuses to report a verdict no signature backed.

```bash
python -m mcpip_verify export-audit --redis-url "$MCPIP_REDIS_URL" \
  --out audit_export.jsonl --verify --pubkey worm_signing_ed25519.pub.pem
```

Both are pure local cryptography — no network, no trust in us at runtime.

### Provision credentials (the key ceremony)

MCPIP needs two Ed25519 keypairs it does **not** ship (you generate them so no vendor ever
holds your keys). Run on an offline signer / into a KMS:

```bash
python scripts/provision_gateway_keys.py --keys-dir <offline> --public-dir <staging>
```

| Output | Role | Wire to |
|---|---|---|
| `worm_signing_ed25519.key` (private, 0600) | signs the WORM audit epochs | `MCPIP_WORM_SIGNING_KEY_PATH` (gateway-held) |
| `worm_signing_ed25519.pub.pem` | auditor re-verification (**required** by `--verify`: it checks the epoch signatures *and* the anchor watermark lines) | `mcpip export-audit --verify --pubkey …` |
| `idp_signing_ed25519.key` (private, 0600) | your IdP signs agent tokens | your token minter / KMS — **never** the gateway |
| `idp_signing_ed25519.pub.pem` | gateway verifies tokens | `MCPIP_JWT_PUBLIC_KEY_PATH` |

Private keys are written `0600` to your gitignored keys dir, **never printed or logged**;
the tool refuses to overwrite without `--force`. Identity is **verify-only**: the gateway
holds the IdP *public* key and never mints tokens itself.

### Wire your identity provider

Config is env-driven, prefix `MCPIP_` (`core/config.py`). Pick the `KeyProvider` that
matches your IdP (`auth/token_resolver.py`):

```python
StaticPEMKeyProvider(pem)                 # one signing key — a single IdP
JWKSKeyProvider(jwks_document)            # rotating keys, selected by header `kid`
MultiIssuerResolver([                     # several issuers, each with an assurance level
    TokenResolver(JWKSKeyProvider(sts_jwks),  issuer="https://sts…",  audience="…", attesting=True),
    TokenResolver(JWKSKeyProvider(oidc_jwks), issuer="https://oidc…", audience="…", attesting=False),
])
```

`attesting=True` designates which issuers' `cnf` (sender-constraint) counts for a resource
that demands it — so trusting a weaker IdP for identity never downgrades the
sender-constraint gate. See [`INTEGRATIONS.md`](../integrate/INTEGRATIONS.md).

### Mint agent principals (your clients' identities)

Each agent presents a signed JWT scoping it to a tenant + entitlements. Mint with your IdP
private key — the production analog of the sandbox `/v1/dev/token`:

```bash
python scripts/mint_principal.py --idp-key <idp_private> \
  --tenant tenant-acme --agent agent-hero-1 --role ops \
  --issuer "$MCPIP_JWT_ISSUER" --audience "$MCPIP_JWT_AUDIENCE" --ttl 900 \
  --capability <capability-uuid> --compartment <compartment-uuid>
```

- `--capability` (repeatable, UUIDs) and `--compartment` (UUID) are the **entitlements the
  gateway enforces**. `--role` is descriptive and authorizes nothing.
- Keep `--ttl` short. For fleets, prefer sender-constrained tokens (`--cnf-jkt`) over
  ephemeral per-session keys instead of long-lived bearers — see
  [`INTEGRATIONS.md`](../integrate/INTEGRATIONS.md).

### Model the catalog

The catalog is your policy surface (`obfuscator/tenant_catalog.py`). Each `AliasEntry`
binds an **opaque alias** (what the agent sees, e.g. `skill_payroll_run`) to a **hidden
target** (e.g. `mainframe.cics.PAYR`, which the agent never sees) plus:

| Field | Meaning |
|---|---|
| `risk_tier` | `AUTO` (execute) or `PIN_REQUIRED` (human step-up) |
| `compartment` | UUID gating team/MCP separation (or tenant-wide) |
| `classification` | `UNCLASSIFIED` / `RESTRICTED` / `CLASSIFIED` |
| `required_capability` | capability UUID a caller must hold |
| `canary` | a decoy skill — selecting it trips a tripwire + quarantines the caller |
| `require_sender_constraint` | demand a key-proven token (default off; **on for every sensitive read** in the shipped catalog) |

The reference catalog is **secure-by-default**: classified telemetry, PHI, and taxpayer PII
reads are `RESTRICTED`/`CLASSIFIED` **and** sender-constrained — and the boot-lint (below)
makes forgetting the flag a boot failure.

### License token — generation & verification

Your license is an **Ed25519-signed entitlement document** that gates **process boot only**
— it is *never* consulted by the per-request authorization pipeline (entitlement is a
change-control matter; per-request authorization is the engine's). Production licenses are
minted on the vendor's **offline license-root signer** and delivered out-of-band; you
install the file plus the license root **public** key.

**Generated** with `scripts/gen_license.py`, on the offline signer holding the license root
private key (separate from the release root and the WORM key):

`--tier` is one of `cloud`, `self-hosted`, or `air-gapped`.

```bash
python scripts/gen_license.py \
  --customer "Hero Systems, Inc." \
  --tier air-gapped \
  --days 365 \
  --entitlements authorize,mcp_edge,audit_export,metrics \
  --private-key <license_root_private.pem> \
  --out license.json
```

The signed document (`schema: mcpip-license/1`):

```json
{
  "schema": "mcpip-license/1",
  "license_id": "<uuid>",
  "customer": "Hero Systems, Inc.",
  "tier": "air-gapped",
  "issued_at": "2026-07-15T00:00:00Z",
  "expires_at": "2027-07-15T00:00:00Z",
  "entitlements": ["audit_export", "authorize", "mcp_edge", "metrics"],
  "signing_key_id": "ed25519:<fp>",
  "signature": "<base64 Ed25519 over canonical JSON, signature field excluded>"
}
```

**Verified** at boot, fail-closed (`core/licensing.load_and_verify_license`). Production
requires **both** the license and the license-root public key; the gateway checks the
Ed25519 signature over the canonical bytes and the validity window, then refuses to boot on
any failure. Only `license_id`, `tier`, and expiry are logged (to the boot banner) — never
the signature:

```bash
MCPIP_LICENSE_PATH=/etc/mcpip/license.json
MCPIP_LICENSE_PUBLIC_KEY_PATH=/etc/mcpip/license_root_ed25519.pub.pem
```

Renewal / tier change = install a new signed `license.json` and redeploy. An expired or
tampered license → the process will not start.

### Boot production (fail-closed, zero-hardcoded-secrets)

Config + **paths** come from `.env.production` (copy `deploy/.env.production.example`). No
committed `.env*` file contains a secret value — the only others in the repository are the
console's three build-edition files, which set a single `VITE_MCPIP_EDITION` flag. Secret
**material** is injected at deploy time from your secret store, never committed, never in
the image:

```bash
cp deploy/.env.production.example .env.production            # edit non-secret config + paths
# In CI/CD, AFTER the secret store exports the *_PEM / *_JSON secrets:
set -a; . ./.env.production; set +a
scripts/deploy_hero.sh                                 # materializes secrets 0600 -> tmpfs,
                                                       # scrubs memory, execs the gateway
```

`deploy_hero.sh` requires `MCPIP_WORM_SIGNING_KEY_PEM`, `MCPIP_JWT_PUBLIC_KEY_PEM`,
`MCPIP_LICENSE_JSON` from the store; if any is missing — or `MCPIP_SANDBOX_MODE≠false` — it
aborts before boot. (Kubernetes uses the `mcpip-keys` Secret instead; see
[`OPERATIONS.md`](../operate/OPERATIONS.md).) The key env vars and their production requirements:

| Var | Default | Production |
|---|---|---|
| `MCPIP_SANDBOX_MODE` | `false` | keep `false` — sandbox mounts a JWT-forge + OTP-peek |
| `MCPIP_REDIS_URL` | `redis://localhost:63790/0` | your Redis (linearizable, `noeviction` for the replay guard) |
| `MCPIP_JWT_ISSUER` / `_AUDIENCE` | `mcpip-demo-idp` / `mcpip-gateway` | your IdP's `iss` / your gateway `aud` |
| `MCPIP_JWT_PUBLIC_KEY_PATH` | – | your IdP's public key (or wire a JWKS provider) |
| `MCPIP_WORM_SIGNING_KEY_PATH` / `_ANCHOR_PATH` | – | Ed25519 WORM root key + external anchor file |
| `MCPIP_INTEGRITY_MANIFEST_PATH` / `_PUBLIC_KEY_PATH` | – | **required** in prod — boot refuses without them |
| `MCPIP_LICENSE_PATH` / `_PUBLIC_KEY_PATH` | – | **required** in prod — boot refuses without |

**Production boot is fail-closed by construction.** With `sandbox_mode=false` and any of
{integrity manifest, license, WORM/JWT keys} missing or invalid, the process **refuses to
boot** (`RuntimeError`, `app/main.py` composition root). Two newer refusals belong to the
posture:

- The **sender-constraint boot-lint** (`_enforce_sender_constraint_policy`): boot refuses
  if any `RESTRICTED`/`CLASSIFIED`, non-`PIN_REQUIRED` alias lacks
  `require_sender_constraint` — a bearer token could otherwise read that data.
- The sandbox forge (`/v1/dev/token`, OTP peek) **404s** unless sandbox mode.

Verify liveness/readiness:

```bash
curl -s localhost:8080/healthz     # {"status":"live",...}
curl -s localhost:8080/readyz      # {"status":"ready","redis":"up"}
```

### Version control & upgrades

- **Single source of truth:** the repo-root `VERSION` file (strict `MAJOR.MINOR.PATCH`).
  `core/version.py` reads + validates + caches it and **fails boot** on a
  missing/malformed value — no default is ever substituted. The version surfaces in
  `/healthz` and the MCP `serverInfo`.
- **Cutting a release** (vendor side): bump `VERSION` **and** `CHANGELOG.md` first, then
  build → SBOM → sign the release manifest → sign the boot-integrity manifest (which covers
  `interfaces.py`, `main.py`, and `VERSION`) → build the image and record its immutable
  digest (see [`OPERATIONS.md`](../operate/OPERATIONS.md)).
- **An upgrade is a redeploy.** Artifacts are immutable and signed; there is no in-place
  mutation. To upgrade: `mcpip verify` the new signed release, then deploy the new
  **digest** (never a mutable tag) — compose repull, or
  `helm upgrade … --set image.digest=sha256:<new>`. Roll back by redeploying the previous
  verified digest.

---

## End-to-End Lifecycle (a request's journey)

A new client's complete journey with MCPIP, seen through every persona that touches it —
from first evaluation, through install and boot, to steady-state operation. Each step is
grounded in a real command, endpoint, or file, and is honest about what is **shipped**,
what is **sandbox-only**, and what is a **you/your-platform integration**.

### The cast

| Persona | Owns | Cares about |
|---|---|---|
| 🛡️ **CISO / security owner** | The decision to adopt; sign-off; monitoring | Guarantees, threat model, audit, supply chain, compliance |
| 🔧 **Platform / DevOps** | Install, boot, IdP wiring, Redis, deploy | Config, fail-closed boot, availability, rotation |
| 👩‍💻 **Developer** | Agent integration | The two edges, token minting, catalog, provider dialects |
| 🙋 **End user / human approver** | Key enrollment, step-up approval | The PIN ceremony, the operator console |
| 🤖 **Agent fleet** | Runtime tool calls | Sender-constraint by action risk, delegation, graceful degradation |

### The trust boundary to internalize first

MCPIP decides *whether* a proposed action may run. It never sits in the prompt path, holds
no vendor keys, and opens no outbound connection of its own — after ALLOW it dispatches
through a transport table. Identity is **sovereign**: `tenant_id` / `agent_id` / `role`
come *only* from a verified JWT; the `role` claim authorizes nothing; an identity- or
capability-shaped key in a tool-call payload is a **hard deny, not a strip**. The reading
path for the security owner, before any code runs: `README.md` (what it is + the 5
invariants), the internal strategy notes (the design thesis),
[`ARCHITECTURE.md`](../integrate/ARCHITECTURE.md) (attack → defense → code), [`OPERATIONS.md`](../operate/OPERATIONS.md)
(control mapping), and the internal roadmap (delivered vs deferred, self-audit).

### The human factor — PIN step-up 🙋

For `PIN_REQUIRED` actions, a human must approve a **specific payload** — the machine
cannot self-approve. A high-risk alias with no pin returns a `202` `StagedChallenge`
(returning a `challenge_id`; the OTP is NEVER in the body). The one-time code is delivered
out-of-band to the enrolled authenticator (sandbox exposes
`GET /v1/authenticator/{challenge_id}` as the stand-in). Resubmit the IDENTICAL payload +
pin + `challenge_id` → `200` executed; replay the spent triple → `403` (the lock is
consumed exactly once).

The PIN is bound to `sha256(canonical_json(tenant, agent, alias, arguments))` and consumed
by a single atomic Redis Lua `EVAL` (fetch + compare + delete) — one byte of payload drift
→ `PAYLOAD_MISMATCH`, and the lock survives a correct retry. In production the raw OTP is
**never persisted**; the enrolled device is the sole source. The human enrolls **one** key
once; agents attest per session.

### Run the fleet 🤖

One employee launches an orchestrator that spawns many ephemeral sub-agents. MCPIP scales
to that **without** breaking keyless agents, because it enforces by **action risk**, not
per agent (see [`INTEGRATIONS.md`](../integrate/INTEGRATIONS.md)):

- **Cheap / low-risk work rides a bearer token** — no key, never newly denied.
- **Sensitive actions demand a key-proof.** A sender-constrained token (`cnf.jkt`) requires
  a DPoP-style proof bound to *this* request: method + URL + the token (`ath`) + the
  canonical payload (`pch`) + freshness + single-use `jti`. Possession of the token is
  never enough; a sniffed/relayed proof can't be replayed onto another action.
- **Keys are born per session, not enrolled.** An agent generates an in-memory keypair; the
  runtime attests (SPIFFE/TPM/KMS) and the org STS exchanges that (RFC 8693) for a
  short-lived `cnf`-bound token. The key dies with the process.
- **Delegation is recorded and provable.** `act.sub` names the human principal (WORM-only);
  a granted agent still must present a proof for a sensitive read.
- **Degrade scoped, never silent.** A runtime that can't sign gets a bearer token and is
  refused — fail-closed — only at actions above its assurance level.

### One request's journey through the pipeline 🛡️🤖

Every request runs the same choke point (`_run_authorize_pipeline`). Any failure emits a
concrete reason to WORM **and** raises the same opaque `MCPIPDenied` (`{error,
correlation_id}`) — the attacker learns nothing:

1. **Auth** — verify JWT (alg pinned to `{EdDSA, RS256}`; `alg=none`/HMAC rejected; 8
   claims required) → sovereign `Identity`.
2. **Quarantine gate** — a canary-tripped agent is frozen (`AGENT_QUARANTINED`).
3. **Bridge** — declared dialect → pure parser → `NormalizedIntent` (deep schema / char /
   size / injection gates; identity-shaped keys → hard deny).
4. **Obfuscator** — tenant-scoped alias → real target (timing-uniform denial).
   4a **Canary** — selecting a decoy trips the tripwire + quarantines.
   4b/4c **Compartment + capability/mandate** gates.
5. **Bind + canonical payload hash.**
   5a **Sender-constraint** — token-side (`cnf`) or resource-side
   (`require_sender_constraint`) → verify the action-bound proof; a resource-demanded
   constraint requires an **attested** cnf.
6. **Risk gate** — `PIN_REQUIRED` with no pin → 202 staged; with pin → atomic exactly-once
   lock consume.
7. **Audit ALLOW** — WORM-emitted **before** dispatch (write-before-execute).
8. **Dispatch** — through the transport table; the wire sees only a coarse transport
   *class*, never the dotted target topology.

### Operate & audit 🛡️🔧

| Concern | How |
|---|---|
| Liveness / readiness | `GET /healthz`, `GET /readyz` (gated on Redis) |
| Metrics | `GET /metrics` — decision/latency counters, closed-enum labels only (no tenant/agent/alias) |
| Tamper-evidence | `GET /v1/audit/verify` (signed Merkle-epoch chain), `GET /v1/audit/proof/{event_id}` (O(log n) inclusion proof), `mcpip export-audit --verify --pubkey …` (offline re-verify of the Merkle roots, `epoch_hash`, chain linkage, Ed25519 epoch signatures and the anchor rollback watermark — the production path, since `/v1/audit/*` is sandbox-only) |
| Deception | Canary aliases trip `CANARY_TRIPPED` → TTL-bounded quarantine; the operator gets the alert, the attacker gets a generic deny |
| Console | The dashboard's WORM Audit Ledger + live stream + tenant/compartment views (`:5173`) |

Because denials are opaque to the agent but concrete in WORM, **the operator sees
everything the attacker cannot** — that asymmetry is the point.

### Steady state — what's yours vs MCPIP's

**MCPIP guarantees (verifiable in-repo):** fail-closed opaque denials; JWT identity
sovereignty; the payload-bound exactly-once lock; sender-constrained, action-bound proofs
demandable per resource and enforced at boot; canary tripwires; the signed, tamper-evident
WORM ledger; secure-by-default catalog; rotating-key + multi-issuer verification.

**Your platform owns (integration):** the IdP / workload-identity STS and its attestation
(SPIFFE/TPM/KMS), ephemeral agent-key custody, Redis durability (`noeviction`,
linearizable, NTP discipline), and your real catalog's policy.

**Honest residual risk:** sender-constraint relocates trust into the attestation layer — a
node-foothold adversary that forges attestation binds `cnf` to its own key and MCPIP
verifies it flawlessly. That boundary is named, not hidden; the MCPIP-side roadmap
(delegation-chain attenuation re-verified at execute, replay-guard Redis hardening, a PoP
stage for the legacy pipeline) is tracked in the internal roadmap.

---

## Company Walkthrough

A real, end-to-end walkthrough you can run on your own machine. **No mock data**: every
decision is an actual round-trip through the zero-trust pipeline, WORM-logged before the
action is dispatched. The agent only ever names an opaque alias and only ever sees an
opaque deny.

The company `mcpip-inc` is a single small tenant whose **teams are separated by
compartment**:

```
mcpip-inc
├── team-engineering   → skill_engineering_roadmap, skill_aws_s3 (vends a scoped AWS credential)
├── team-finance       → skill_financial_wage_sheet, skill_financial_ledger_post
└── (company-wide)     → skill_company_overview, skill_data_lake
```

- An **Engineering** agent reads the company overview and the engineering roadmap, but is
  **denied** the finance wage sheet — cross-team `COMPARTMENT_DENIED`, opaque.
- A **Finance** agent reads the wage sheet.
- A company agent with **no team** reads only the company-wide overview.

The finance skills do not even appear in Engineering's `tools/list` — an agent cannot
enumerate another team's tools.

### Launch and run the scripted walkthrough

Launch the gateway with `./scripts/quickstart.sh` (see [Quickstart](#quickstart--run-it-now)),
then run the scripted walkthrough — it doubles as a smoke test (exit `0` when every
decision matches policy):

```bash
python scripts/live_company.py
python scripts/live_company.py --base http://host:8080
```

Expected output:

```
Scenario 1 — Engineering agent  ("I'm on the mcpip team")
  tools/list → skill_company_overview, skill_engineering_roadmap
    ALLOW  skill_company_overview            ✓
    ALLOW  skill_engineering_roadmap         ✓
    DENY   skill_financial_wage_sheet        opaque · correlation …  ✓   ← cross-team

Scenario 2 — Finance agent
    ALLOW  skill_financial_wage_sheet        ✓
    DENY   skill_engineering_roadmap         ✓

Scenario 3 — Company agent, no team
    ALLOW  skill_company_overview            ✓
    DENY   skill_financial_wage_sheet        ✓
    DENY   skill_engineering_roadmap         ✓
```

> Run the walkthrough from `quickstart.sh`, not the raw `python3 scripts/live_company.py` on
> its own — the latter only works once a gateway is already up. You can also hold the MCP
> session yourself with `scripts/mcp_terminal.py` (see
> [Drive the MCP connector live from your terminal](#drive-the-mcp-connector-live-from-your-terminal)).

### Connect Claude Code to the walkthrough

Point Claude Code's MCP client at the gateway (see
[Claude / MCP client setup](#claude--mcp-client-setup)) and the gateway enforces team scope
on every tool call. Inside Claude Code, using the Engineering token:

- "**Give me the company overview**" → Claude calls `skill_company_overview` → **allowed**.
- "**Pull the finance wage sheet**" → Claude calls `skill_financial_wage_sheet` →
  **denied** (the agent is on Engineering, not Finance). Claude sees only *"request denied
  by policy"* + a correlation id; the real reason (`COMPARTMENT_DENIED`) lives only in the
  WORM ledger.

Swap the token for a Finance agent (`agent-fin-1`, compartment
`f1a00000-0000-4000-8000-f1a00000f1a0`) and the wage-sheet call is allowed — same gateway,
different license, different blast radius. To mint a team token via the sandbox helper for
the HTTP transport:

```bash
ENG_TOKEN=$(curl -s -X POST http://localhost:8080/v1/dev/token \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"mcpip-inc","agent_id":"agent-eng-1",
       "compartment":"e0900000-0000-4000-8000-e0900000e090"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["jwt"])')
```

### More use cases to demonstrate

- **Cloud IAM — vend a scoped credential, no standing key:** `skill_aws_s3` is a
  `cloud_iam` skill scoped to team-engineering. An Engineering agent that invokes it gets a
  **short-lived, scoped AWS session credential** vended for that one call (the receipt's
  `vended_credential`) — the agent never holds a permanent key. A Finance agent is denied
  `COMPARTMENT_DENIED`. The vended secret is the agent's deliverable and is **never written
  to the WORM log**:

  ```
  mcp❯ login agent-eng-1 engineering
  mcp❯ call skill_aws_s3
  ✓ ALLOW — committed through the pipeline (WORM-logged before dispatch)
    ⛅ vended cloud credential (SANDBOX — fake): AWS STS AssumeRole → mcpip-eng-readonly · us-east-1 · 900s
       the agent uses this directly, then it expires — no standing key ever existed.
  ```

  In production the gateway assumes the environment's role with its **own host identity**
  (instance profile / IRSA / OIDC) — no cloud secret is ever stored. Operators manage the
  role→compartment bindings via `/v1/admin/cloud/environments`. This is the zero-trust
  answer to "give an agent an AWS/GCP/Azure role": per-call, scoped, short-lived, killable,
  and provably audited. See [`INTEGRATIONS.md`](../integrate/INTEGRATIONS.md).
- **Step-up (human-in-the-loop):** `skill_financial_ledger_post` is `pin_required`. A
  Finance agent calling it gets a `202` challenge, not data — the write only commits after
  a payload-bound one-time PIN. Nothing about the amount can be changed between challenge
  and execution.
- **Deception tripwire:** the catalog seeds decoy skills (`skill_export_all_credentials`,
  `skill_disable_audit_log`). A prompt-injected agent sweeping for exfiltration primitives
  trips the canary → denied `CANARY_TRIPPED` **and quarantined** — every subsequent call
  from that agent is frozen.
- **Kill-switch:** from the operator console (Threat Policy → Skills & Tools) **■ Stop**
  `skill_company_overview` — every agent is then denied `SKILL_DISABLED` until you **▶
  Play** it again. The alias→target mapping is never edited.
- **Principal revocation:** revoke `agent-eng-1` from the console (Principal Directory) and
  its very next call is denied `PRINCIPAL_REVOKED`, no matter what token it holds.
- **Register a new skill live:** in Skills & Tools, **+ Register skill** adds a new
  alias→target for the tenant (additive-only — you can never shadow a config skill).
- **Tamper-evidence:** run WORM Audit → Chain integrity to recompute every sealed
  Merkle-epoch root and walk the signed chain back to genesis.

### See it live — the operator console (web + native app)

The same console ships two ways from one codebase; both flip to **live** the moment they
reach the gateway (`http://localhost:8080`), and the first launch runs the animated setup
flow (Welcome → Connect → Company → Workspace → Launch).

**Web (zero-install)** — serves on http://localhost:5173:

```bash
cd dashboard && npm install && npm run dev
```

**Native desktop app (downloadable installer)** — build the real `.dmg`/`.msi`/`.deb` from
the same code (full details in [`OPERATIONS.md`](../operate/OPERATIONS.md)). Run each line on its own —
**do not paste a trailing `#` comment into the shell**:

```bash
cd dashboard && npm install
npm run desktop:build
```

That native build lands in `src-tauri/target/release/bundle/`. For the macOS **universal**
installer instead, first `rustup target add x86_64-apple-darwin aarch64-apple-darwin`, then
`npm run desktop:build:mac`, which writes `src-tauri/target/**/release/bundle/dmg/*.dmg`.
Open the resulting `.dmg`, drag **MCPIP** to Applications, launch it, and Test & Connect to
`http://localhost:8080` — the native app runs on the same live gateway data as the web
portal (a thin, plugin-free Tauri shell). Prebuilt installers for every OS also come out of
CI: `.github/workflows/desktop-release.yml` (trigger via `workflow_dispatch` or a
`desktop-v*` tag).

### Sandbox vs. production

The walkthrough mints bearer tokens via the sandbox `/v1/dev/token` helper purely so the
walkthrough is self-contained. In production MCPIP is **identity-sovereign**: it never
mints principals. A real agent license is issued out-of-band by your IdP —

```bash
python scripts/mint_principal.py --idp-key /secure/idp_ed25519.pem \
  --tenant mcpip-inc --agent agent-eng-1 \
  --compartment e0900000-0000-4000-8000-e0900000e090 \
  --issuer $MCPIP_JWT_ISSUER --audience $MCPIP_JWT_AUDIENCE \
  --cnf-jkt <agent-key RFC-7638 thumbprint> --ttl 3600 --out ./eng.jwt
```

— and the gateway only ever *verifies* it. Production additionally requires
sender-constrained (proof-of-possession) tokens for sensitive AUTO reads, so a stolen
bearer cannot read across the compartment gate; the walkthrough's compartment is the
team-separation control the walkthrough is built to show.

---

*A → Z: a new client can go from this page's top to a fail-closed, audited,
sender-constrained production gateway — and knows exactly where MCPIP's guarantees end and
their platform's responsibility begins.*
