# End-to-end walkthrough — a real production cycle

Every command, input and output on this page was executed against a real MCPIP
`3.0.0` gateway. Nothing is illustrative: the Cloudflare and GitHub responses are
live API results, the correlation ids and `worm_sequence` values are the ones the
gateway actually emitted, and the console screenshot is that run's own state.

Two agents are governed end to end — a Cloudflare platform agent and a GitHub
release agent — plus the developer-facing path (SDK) and the operator-facing path
(console). Where a control could not be exercised in this environment, that is
stated rather than simulated.

**Contents**

1. [Key ceremony](#1-key-ceremony)
2. [License](#2-license)
3. [Boot integrity manifest](#3-boot-integrity-manifest)
4. [Production boot, and the four gates that refuse it](#4-production-boot-and-the-four-gates-that-refuse-it)
5. [Identity — minting principals](#5-identity--minting-principals)
6. [Catalog — registering the tool surface](#6-catalog--registering-the-tool-surface)
7. [Governed calls — Cloudflare and GitHub](#7-governed-calls--cloudflare-and-github)
8. [Execution — the authorized call against the real provider](#8-execution--the-authorized-call-against-the-real-provider)
9. [Developer path — the SDK](#9-developer-path--the-sdk)
10. [Developer vs operator — the capability boundary](#10-developer-vs-operator--the-capability-boundary)
11. [Step-up — the PIN cycle](#11-step-up--the-pin-cycle)
12. [Evidence — the WORM ledger](#12-evidence--the-worm-ledger)
13. [The operator console](#13-the-operator-console)
14. [What this run did not prove](#14-what-this-run-did-not-prove)

---

## 1. Key ceremony

Four Ed25519 keypairs, none of which the gateway may generate for itself. The
release and license roots are the offline signing identities; the WORM epoch key
signs the audit chain; the IdP key signs principal tokens and the gateway holds
only its public half.

```bash
python3 scripts/gen_release_keys.py      --keys-dir ./keys --public-dir ./pub
python3 scripts/provision_gateway_keys.py --keys-dir ./keys --public-dir ./pub
```

```
generated release-root: ed25519:859645e4f45c87b4
generated license-root: ed25519:6a43de9d6cca881c

MCPIP gateway key ceremony complete.
  WORM epoch-signing  ed25519:f498dc4757b3efba
    private (0600)    keys/worm_signing_ed25519.key   -> MCPIP_WORM_SIGNING_KEY_PATH
    public            pub/worm_signing_ed25519.pub.pem -> auditors
  IdP identity-signing ed25519:a2d94615b1240fb3
    private (0600)    keys/idp_signing_ed25519.key    -> the token minter, NEVER the gateway
    public            pub/idp_signing_ed25519.pub.pem -> MCPIP_JWT_PUBLIC_KEY_PATH
```

Only public material and key-id fingerprints are ever printed. The IdP private key
never reaches the gateway — identity is verify-only, which is what makes the
`agent_id` in an audit record non-repudiable.

## 2. License

The license gates **process boot only**. It is never consulted by the
authorization pipeline — entitlement is an operator/change-control matter, and
per-request authorization is the engine's. This separation is why a lapsed
license cannot silently change a decision.

```bash
python3 scripts/gen_license.py \
  --customer "Cloudflare Platform Ops" --tier self-hosted --days 90 \
  --entitlements authorize,mcp_edge,audit_export,metrics \
  --private-key keys/license_root_ed25519.pem --out state/license.json
```

```json
{
  "schema": "mcpip-license/1",
  "license_id": "e0d5437b-d0ae-4eb7-a8e4-c21a858166df",
  "customer": "Cloudflare Platform Ops",
  "tier": "self-hosted",
  "issued_at": "2026-07-29T10:57:21Z",
  "expires_at": "2026-10-27T10:57:21Z",
  "entitlements": ["audit_export", "authorize", "mcp_edge", "metrics"],
  "signing_key_id": "ed25519:6a43de9d6cca881c",
  "signature": "hKMhkfoMkObdL+Z4rI/Mbq9nxMbktk6VzD1CsJ/n+PW4x3TsIBGBf03ZXIb8PJxBPoHNHArZXYkpDWwGx1RQAA=="
}
```

The signature covers the canonical JSON of every field except `signature` itself,
so any edit to tier, customer or expiry invalidates it — demonstrated in §4.

## 3. Boot integrity manifest

```bash
python3 scripts/gen_integrity_manifest.py \
  --private-key keys/release_root_ed25519.pem --base-dir . --out state/integrity_manifest.json
```

```
integrity manifest: 85 files -> state/integrity_manifest.json
  key id: ed25519:859645e4f45c87b4
```

## 4. Production boot, and the four gates that refuse it

Production posture is `MCPIP_SANDBOX_MODE=false`. Four separate gates each
refused the boot before a valid configuration was reached. All four outputs below
are real refusals, not descriptions of them.

**Gate 1 — no license**

```
RuntimeError: production boot (MCPIP_SANDBOX_MODE=false) requires both
MCPIP_LICENSE_PATH and MCPIP_LICENSE_PUBLIC_KEY_PATH
```

**Gate 2 — license edited** (`tier: self-hosted → cloud`, `customer → Attacker Corp`,
signature left untouched)

```
RuntimeError: license verification failed
```

**Gate 3 — source tree modified after the manifest was signed**
(`echo "# injected backdoor" >> core/metrics.py`)

```
startup integrity self-check failed: hash mismatch: core/metrics.py
RuntimeError: integrity verification failed
```

**Gate 4 — Redis not fsync-durable**

```
RuntimeError: MCPIP WORM-DURABILITY: Redis persistence is appendonly=no
appendfsync=everysec maxmemory-policy=noeviction; write-before-execute requires
appendonly=yes appendfsync=always and maxmemory-policy=noeviction so the audit
buffer XADD is fsync-durable before /v1/authorize returns allow and WORM/replay
keys are never evicted.
```

Gate 4 is the write-before-execute contract in enforcement form: MCPIP will not
serve at all unless the ledger write is durable *before* an allow is returned.

With all four satisfied:

```
MCPIP connector registry v4 sha256=c755c47019d17271f2b1a8ccd30ff2020dc0b27beaa0466e1f3a49fbcafb622a
MCPIP LICENSE: verified license_id=e0d5437b-d0ae-4eb7-a8e4-c21a858166df tier=self-hosted expires_at=2026-10-27T10:57:21+00:00
MCPIP WARNING: MCPIP_REDIS_URL is plaintext (redis://) in production — the payload-lock
hashes, WORM buffer, and rate counters cross it unencrypted and unauthenticated. Use
rediss:// with a CA + AUTH/ACL, or ensure the Redis link is on an isolated internal-only network.
INFO:     Started server process
```

```console
$ curl -s http://127.0.0.1:8080/healthz
{"status":"live","glyph":"◐","loop":"uvloop","version":"3.0.0","region":null}
```

The plaintext-Redis line is a warning, not a refusal — network isolation is a
valid documented control, so the gateway says so loudly instead of breaking an
isolated deployment.

> **Note on `MCPIP_JWT_AUDIENCE`.** Production also refuses the shipped demo
> issuer/audience pair (`mcpip-demo-idp` / `mcpip-gateway`), because those values
> are published and predictable. Set both to values you control.

## 5. Identity — minting principals

Three principals, all signed by the IdP key, all in tenant `acme-platform`. Only
the third carries a capability.

```bash
python3 scripts/mint_principal.py --idp-key keys/idp_signing_ed25519.key \
  --tenant acme-platform --agent cf-platform-agent-1 --role platform-ops \
  --issuer prod-idp.hero --audience mcpip-gw.hero --ttl 3600
```

Decoded claims:

```json
{
  "iss": "cloudflare-ops-idp.internal",
  "aud": "mcpip-gw.cf-ops.internal",
  "tenant_id": "cloudflare-ops",
  "agent_id": "cf-platform-agent-1",
  "role": "platform-ops",
  "exp": 1785326423, "iat": 1785322823, "nbf": 1785322823,
  "jti": "9e36586c7097469582dadc2751148a81"
}
```

```console
$ curl -s -H "Authorization: Bearer $JWT" http://127.0.0.1:8080/v1/whoami
{
    "tenant_id": "cloudflare-ops",
    "agent_id": "cf-platform-agent-1",
    "role": "platform-ops",
    "compartment": null,
    "capabilities": [],
    "sender_constrained": false
}
```

`role` is descriptive and authorizes nothing. Entitlement is the capability UUID
list — empty here, which is exactly what §10 exploits.

## 6. Catalog — registering the tool surface

Aliases are registered by an operator holding `CAP_DIRECTORY_ADMIN`. Registration
is additive-only: an alias that already resolves cannot be overridden or shadowed.

```bash
curl -X POST http://127.0.0.1:8080/v1/admin/skills/register \
  -H "Authorization: Bearer $ADMIN" -H 'Content-Type: application/json' \
  -d '{"alias":"cf.d1.query",
       "target":"https://api.cloudflare.com/client/v4/accounts/{account_id}/d1/database/query",
       "risk_tier":"pin_required","classification":"restricted",
       "service":"cloudflare","access":"write"}'
```

| alias | risk tier | classification | service | access |
|---|---|---|---|---|
| `cf.d1.databases.list` | `auto` | `unclassified` | cloudflare | read |
| `cf.d1.query` | `pin_required` | `restricted` | cloudflare | write |
| `gh.branches.list` | `auto` | `unclassified` | github | read |
| `gh.repo.delete` | `pin_required` | `restricted` | github | write |

What the **agent** sees — aliases only, never the real provider URLs:

```console
$ curl -s -H "Authorization: Bearer $AGENT" http://127.0.0.1:8080/v1/catalog
{
    "catalog": [
        {"alias": "cf.d1.databases.list", "risk_tier": "auto",
         "transport_class": "cloud_rest", "classification": "unclassified",
         "compartment": null, "access": "read"},
        {"alias": "cf.d1.query", "risk_tier": "pin_required",
         "transport_class": "cloud_rest", "classification": "restricted",
         "compartment": null, "access": "write"}
    ]
}
```

The alias indirection is the point: a compromised agent cannot discover the
account id, the hostname, or the credential from anything MCPIP hands it.

## 7. Governed calls — Cloudflare and GitHub

Each request is a standard MCP JSON-RPC 2.0 `tools/call` envelope with the wire
dialect **declared** (`vendor`), never sniffed from the payload.

### CF-1 — Cloudflare read, `auto` risk → allow

```json
{"vendor":"claude_code","tool_call":{"jsonrpc":"2.0","id":1,"method":"tools/call",
 "params":{"name":"cf.d1.databases.list","arguments":{}}}}
```

```json
{
  "correlation_id": "517db613ec1042a1886e4778cc921969",
  "decision": "allow",
  "status": "committed",
  "transaction_ref": "txn_880bed37ae974502be7d7016fbc514b0",
  "executed_target_class": "cloud_rest",
  "worm_sequence": 5,
  "vended_credential": null
}
```
`HTTP 200`

### GH-1 — GitHub read, `auto` risk → allow

```json
{"vendor":"claude_code","tool_call":{"jsonrpc":"2.0","id":3,"method":"tools/call",
 "params":{"name":"gh.branches.list","arguments":{"owner":"mcpip-security","repo":"mcpip"}}}}
```

```json
{
  "correlation_id": "3eaa2f4ef7564182810687f7233aea01",
  "decision": "allow",
  "status": "committed",
  "transaction_ref": "txn_b49eb8dc010e49d29ddfc8f4aa394dc8",
  "executed_target_class": "cloud_rest",
  "worm_sequence": 7,
  "vended_credential": null
}
```
`HTTP 200`

### CF-2 / GH-2 — destructive calls → denied

`DROP TABLE customers` through `cf.d1.query`, and `gh.repo.delete` against this
very repository:

```json
{"error": "MCPIP: request denied by policy.",
 "correlation_id": "4f7774d648d24a21b732ad5e07cd2537"}
```
`HTTP 403`

### X-1 — an alias that was never registered

```json
{"vendor":"claude_code","tool_call":{"jsonrpc":"2.0","id":6,"method":"tools/call",
 "params":{"name":"gh.secrets.exfiltrate","arguments":{}}}}
```

```json
{"error": "MCPIP: request denied by policy.",
 "correlation_id": "33c33fb32edb439c8788155ec7ecb4c2"}
```
`HTTP 403`

Every denial returns the **same opaque body**. The caller learns only that it was
denied — never whether the alias exists, whether it is restricted, or which gate
fired. The concrete reason goes to the ledger, not to the agent (§12).

## 8. Execution — the authorized call against the real provider

MCPIP authorizes; the caller executes. These are the live provider responses for
the two calls allowed in §7.

**Cloudflare**, after `worm_sequence 5`:

```json
{"result":[{"uuid":"ee77852d-639f-4874-860f-6a32be479d24","name":"mcpip-site",
  "created_at":"2026-07-21T23:06:19.622Z","version":"production",
  "num_tables":0,"file_size":114688,"jurisdiction":null}],
 "result_info":{"count":1,"page":1,"per_page":100,"total_count":1}}
```

**GitHub**, after `worm_sequence 7`:

```json
[{"name":"claude/new-session-6g22zk","sha":"75751e2ef1d7e777854e5703b4f14528f82ce148","protected":false},
 {"name":"dependabot/github_actions/actions/checkout-7","sha":"2e686a4e97a1c73a97312a736e0f06392952ba7a","protected":false}]
```

The denied calls in §7 were never executed against either provider.

## 9. Developer path — the SDK

A developer integrates through the SDK rather than raw HTTP. Same gateway, same
decisions.

```python
from mcpip_sdk import MCPIPClient, MCPIPDenied

c = MCPIPClient("http://127.0.0.1:8080", token=agent_jwt)

print(c.health())
for item in c.catalog():
    print(item)

r = c.authorize(vendor="claude_code", tool_call={
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "cf.d1.databases.list", "arguments": {}}})
print(r)

try:
    c.authorize(vendor="claude_code", tool_call={
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "cf.d1.query", "arguments": {"sql": "DROP TABLE customers"}}})
except MCPIPDenied as e:
    print("denied:", e)
```

```
Health(status='live', glyph='◐', loop='uvloop', version='3.0.0')
VersionInfo(running='3.0.0', latest='3.0.0', update_available=False, channel='self-hosted', ...)

CatalogItem(alias='cf.d1.databases.list', risk_tier='auto', transport_class='cloud_rest', classification='unclassified', compartment=None)
CatalogItem(alias='cf.d1.query',          risk_tier='pin_required', transport_class='cloud_rest', classification='restricted',  compartment=None)
CatalogItem(alias='gh.branches.list',     risk_tier='auto', transport_class='cloud_rest', classification='unclassified', compartment=None)
CatalogItem(alias='gh.repo.delete',       risk_tier='pin_required', transport_class='cloud_rest', classification='restricted',  compartment=None)

Allowed(correlation_id='0dd455de98d84f35a8bf2d9faa84652c', decision='allow',
        status='committed', transaction_ref='txn_b71559f7d58946629a5c28ac2dc953ac',
        executed_target_class='cloud_rest', worm_sequence=11, vended_credential=None)

denied: MCPIP: request denied by policy.
```

The denial surfaces as a typed `MCPIPDenied` exception carrying the same opaque
message the HTTP caller saw — the SDK does not widen the disclosure.

## 9a. Developer path — the other integration options

The SDK above is one of five supported ways in. All five hit the same choke point
and get the same decision; they differ only in what the calling code looks like.

**Option 1 — raw HTTP.** `POST /v1/authorize`, shown throughout §7. No dependency
beyond an HTTP client.

**Option 2 — Python / TypeScript SDK.** §9. Typed results, `MCPIPDenied` for
refusals, staged step-up handled by `complete()`.

**Option 3 — MCP-native edge.** `POST /v1/mcp` speaks JSON-RPC directly, so an MCP
host can treat the gateway itself as a server and get a catalog that is already
filtered to what this identity may see:

```console
$ curl -X POST http://127.0.0.1:8080/v1/mcp -H "Authorization: Bearer $AGENT" \
    -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
{"jsonrpc":"2.0","id":1,"result":{"tools":[
  {"name":"cf.d1.databases.list","description":"risk_tier=auto; classification=unclassified","inputSchema":{"type":"object"}},
  {"name":"cf.d1.query","description":"risk_tier=pin_required; classification=restricted","inputSchema":{"type":"object"}},
  {"name":"gh.branches.list","description":"risk_tier=auto; classification=unclassified","inputSchema":{"type":"object"}},
  {"name":"gh.repo.delete","description":"risk_tier=pin_required; classification=restricted","inputSchema":{"type":"object"}}]}}
```

The risk tier travels in the tool description, so a well-behaved host can warn
before it proposes a `pin_required` call.

**Option 4 — the `mcpip` CLI**, shipped with the Python SDK:

```
usage: mcpip [-h] [--gateway URL] [--context NAME] [--sandbox | --no-sandbox]
             [--token-file PATH] [--token-stdin] [--token-cmd CMD] [--json] ...

  up          boot the local sandbox stack — Redis + gateway + walkthrough, one command
  login       validate reachability and save a context
  whoami      decode the active bearer and confirm the gateway accepts it
  catalog     list the aliases this identity may see
  authorize   authorize one tool call through the choke point
  complete    finish a staged step-up from the persisted envelope
  decision    ask for an AuthZEN PDP verdict (nothing executes)
```

Named contexts plus `--token-cmd` mean a developer can point the same commands at
sandbox and production without a token ever landing in shell history.

**Option 5 — PDP mode.** `POST /v1/authz/decision` returns an AuthZEN verdict and
executes nothing, for teams that already have an enforcement point and want MCPIP
only as the decision point.

## 10. Developer vs operator — the capability boundary

Both principals come from the same IdP and the same tenant. The only difference is
one capability UUID (`CAP_DIRECTORY_ADMIN`,
`b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20`) in the token claims.

| endpoint | developer token | operator token |
|---|---|---|
| `GET /v1/whoami` | `200` | `200` |
| `GET /v1/catalog` | `200` | `200` |
| `GET /v1/admin/decisions/recent` | **`403`** | `200` |
| `GET /v1/admin/stats` | **`403`** | `200` |
| `POST /v1/admin/skills/register` | **`403`** | `200` |

A developer can see the catalog and get calls authorized. A developer cannot read
other agents' decisions, read tenant statistics, or register a new alias — so
self-granting a route to a new target is not available to the identity that would
most benefit from it. `role: "platform-ops"` in the token changes none of this.

### The other personas

Four more principal types were exercised against the same gateway. Capabilities
are **non-hierarchical** — note that the operator is refused two routes:

| route | agent | developer | operator | auditor | reviewer |
|---|---|---|---|---|---|
| `GET /v1/catalog` | `200` | `200` | `200` | `200` | `200` |
| `POST /v1/authorize` | `200` | `200` | `200` | `200` | `200` |
| `GET /v1/admin/stats` | `403` | `403` | `200` | `403` | `403` |
| `GET /v1/admin/decisions/recent` | `403` | `403` | `200` | `403` | `403` |
| `POST /v1/admin/skills/register` | `403` | `403` | `200` | `403` | `403` |
| `GET /v1/admin/forensic/{corr}` | `403` | `403` | **`403`** | `404`¹ | `403` |
| `GET /v1/admin/extensions/pending` | `403` | `403` | **`403`** | `403` | **`200`** |

¹ `404` not `403`: the auditor is authorized, but no forensic capture existed for
that correlation id. An authorized-but-empty lookup is distinguishable from a
capability refusal.

`CAP_DIRECTORY_ADMIN` does not subsume `CAP_FORENSIC_READ` or
`CAP_CATALOG_REVIEWER`. There is no super-admin: compromising the operator does
not yield payload forensics or extension approval.

A worked multi-agent, multi-persona run — including a live revocation during
concurrent traffic — is in [`ORGANIZATION_AT_SCALE.md`](ORGANIZATION_AT_SCALE.md).

## 11. Step-up — the PIN cycle

`pin_required` aliases stage rather than allow. The full cycle below was run
against a **sandbox** gateway, because completing it needs an out-of-band OTP sink
(see §14).

**Stage** — no allow is issued:

```json
{
  "correlation_id": "e3c9b4a151e24f6b9a2e401a03677bef",
  "action_required": "Step-up required: approve in your enrolled authenticator to obtain a one-time code, then resubmit with pin + challenge_id.",
  "challenge_id": "a3ae0701a7e442fd8fb9f400dff4fbf6",
  "risk_tier": "pin_required"
}
```
`HTTP 202`

**Retrieve the payload-bound code** (sandbox-only disclosure; in production this
is pushed to the enrolled authenticator over a signed webhook):

```json
{"challenge_id": "a3ae0701a7e442fd8fb9f400dff4fbf6", "otp": "752398"}
```

**Complete** — resubmit the identical payload with `pin` + `challenge_id`:

```json
{
  "correlation_id": "485197e83e424435adb0a3b803c5a800",
  "decision": "allow",
  "status": "committed",
  "transaction_ref": "txn_1d2e54f2e62f489cb5807f23063f4a7a",
  "worm_sequence": 12
}
```
`HTTP 200`

**Replay the same PIN** — the lock is exactly-once:

```json
{"error": "MCPIP: request denied by policy.",
 "correlation_id": "bcc82cd29d9e4127a4a8d4ab23ded744"}
```
`HTTP 403`

The code is bound to the canonical payload hash, so an approval for
`DROP TABLE customers` cannot be replayed to authorize a different statement, and
cannot be replayed at all a second time.

## 12. Evidence — the WORM ledger

The agent got one opaque message for every denial. The ledger has the reasons:

```
seq  decision  deny_reason            alias                  agent                correlation_id
  5  allow     None                   cf.d1.databases.list   cf-platform-agent-1  517db613ec1042a1886e4778cc921969
  6  deny      otp_delivery_failed    cf.d1.query            cf-platform-agent-1  4f7774d648d24a21b732ad5e07cd2537
  7  allow     None                   gh.branches.list       gh-release-agent-1   3eaa2f4ef7564182810687f7233aea01
  8  deny      otp_delivery_failed    gh.repo.delete         gh-release-agent-1   d615ea19dba94c1f8d58f8eed1122f87
  9  deny      otp_delivery_failed    cf.d1.query            gh-release-agent-1   17d480e3425b49beb06142e3aa7a4242
 10  deny      unknown_alias          gh.secrets.exfiltrate  gh-release-agent-1   33c33fb32edb439c8788155ec7ecb4c2
```

Signed epoch attestation over those records:

```json
{
  "epoch": 1,
  "end_seq": 10,
  "merkle_root": "ad98e05c96030e4df2f056c4c5de00198ad363791cc0f1269769d63087b2f339",
  "epoch_hash": "4a721474c032a51c5288ead7bfe7c845db4c69e76a49702b7be1bbb17bbbd7d9",
  "signature": "52a280129e963f2bea5f06a935de005b9796e7dad67c40517e652e01d26b16a4...",
  "signing_key_id": "090da9528a854204cffe2d461e4b6826867a2d6c86543b8ca689ba4c56d17bf9",
  "intact": true,
  "first_bad_epoch": null,
  "anchor_epoch": 1
}
```

### Tamper detection

One sealed event was deleted directly from the ledger's backing store, bypassing
the gateway entirely:

```console
$ redis-cli xdel mcpip:worm:events 1785322863572-0
1
```

Re-verification, same endpoint, no restart:

```json
{"epoch": 2, "end_seq": 8, "intact": false, "first_bad_epoch": 0, ...}
```

An operator with database access can destroy a record, but cannot destroy the
*evidence* that a record was destroyed — the Merkle root no longer reconciles
against the signed epoch head.

## 13. The operator console

### 13.1 Giving the console an identity

The console has no identity of its own on a production gateway. It normally mints
one via `POST /v1/dev/token` — a **sandbox affordance** that returns `404` when
`MCPIP_SANDBOX_MODE=false`. Connect it to a production gateway and it says so,
and takes a real bearer minted by your IdP:

![Console settings: the Operator token card explaining that this gateway is in production posture, the sandbox token forge is not mounted, and a bearer minted by your IdP is required](images/console-operator-token.png)

The token is stored in that browser only and sent as `Authorization: Bearer`.
MCPIP never mints identity — the gateway verifies the bearer against
`MCPIP_JWT_PUBLIC_KEY_PATH`, exactly as it does for an agent. Admin surfaces
additionally require `CAP_DIRECTORY_ADMIN`; a bearer without it authenticates
fine and simply gets `403` on those reads.

### 13.2 The console on live production traffic

With the token pinned, the same production gateway drives every panel — this is
the fleet from §7 and [`ORGANIZATION_AT_SCALE.md`](ORGANIZATION_AT_SCALE.md)
running while the screenshot was taken:

![MCPIP console Live monitor against a production gateway: 133 decisions since start (111 allow, 22 deny), 3.2 decisions per second, gateway p50 3.9 ms, 50 rows in the decision stream showing per-row alias, agent, worm sequence and ALLOW or DENY with otp_delivery_failed reasons](images/console-production-live.png)

**133 decisions (111 allow · 22 deny)**, **3.2 decisions/s**, **p50 3.9 ms**, and
50 rows in the stream. Each row is a 1:1 projection of a WORM record: timestamp,
alias, `agent_id`, tenant, transport, the `#worm_sequence`, the verdict, and the
event id. The `data-agent-1` rows carry `otp_delivery_failed` — the same
production step-up refusal as §12, visible per call.

Note the audit-chain tile reads **Unverified · external verifier required**. That
is correct rather than a failure: `/v1/audit/verify` is sandbox-gated, so in
production the console will not claim a verdict it cannot obtain. The signed
attestation in §12 and `mcpip-verify export-audit --redis-url <URL> --out audit.jsonl --verify --pubkey worm_signing_ed25519.pub.pem` are the production paths. The verifier ships in the
gateway distribution as `mcpip-verify`; the SDK's `mcpip export-audit` passes through to it.

### 13.3 Against a sandbox gateway

For comparison, the same console against a sandbox gateway, where it mints its
own identity and can verify the chain in-place:

![MCPIP console against a sandbox gateway: 9 decisions since start (3 allow, 3 deny, 3 staged), gateway p50 62.5 ms, audit chain Intact at seq 12 epoch 2, catalog 9 entries](images/console-live.png)

**Audit chain Intact · seq #12 · epoch 2** — the verdict the production view
correctly declines to assert. The footer states the posture both runs
demonstrated: *fail-closed · opaque · WORM-first*.

## 13a. From a number back to the records — the SOC 2 report

§12 shows six records. An auditor asks about ninety days. `/v1/audit/attestation`
answers "is the ledger intact *now*"; a Type II engagement is about a *period*.

`scripts/soc2_report.py` closes that gap by composing surfaces the gateway already
exposes — the cursor-paged decision history (`GET /v1/admin/decisions`), the
signed attestation, the compliance bundle, and the running version and
entitlement — into a period report where **every figure carries the records
behind it**.

```bash
python3 scripts/soc2_report.py \
  --gateway http://127.0.0.1:8080 --token-file operator.jwt \
  --days 90 --out report.md --json report.json
```

```
report -> report.md  (225 decisions, coverage=exhausted)
```

Real output from this run:

```markdown
| Period start        | 2026-07-28T11:41:12Z |
| Period end          | 2026-07-29T11:41:12Z |
| Tenant              | acme-platform        |
| Running version     | 3.0.0                |
| Entitlement         | self-hosted (e0d5437b-d0ae-4eb7-a8e4-c21a858166df) |
| Decisions in period | 225                  |
| worm_sequence range | 11–238               |

## Coverage of this report
The decision history was walked to exhaustion — 2 page(s), 228 row(s) scanned.

## Signed ledger commitment (period end)
| Chain intact  | True |
| Epoch         | 33   |
| End sequence  | 238  |
| Merkle root   | 81c4a9b6056f582358fac0a9ea0eeb86f6a1bc34a59b6fe60ad65d0d5218536d |
| Signing key id| 090da9528a854204cffe2d461e4b6826867a2d6c86543b8ca689ba4c56d17bf9 |

### Outcomes
| value   | count | share | worm_sequence range | sample correlation ids |
| allow   | 187   | 83.1% | 11–237              | 53cface29248…, bf7073ec27cd…, … |
```

Three properties make it auditable rather than merely informative:

- **Coverage is stated before any figure.** The report says whether the history
  was walked to exhaustion, truncated at the page cap, or cut short by a failed
  read. A truncated walk is labelled a lower bound, not a total.
- **Every bucket is traceable.** Each row carries its `worm_sequence` range and
  sample correlation ids, so "22 denials" is 22 records you can re-fetch by id —
  not a number you have to trust.
- **The figures are bound to a signed commitment.** The period-end Merkle root,
  epoch hash, signature and key id are printed, so an auditor can re-derive the
  root from an export and check the signature **without trusting the report or
  the gateway that produced it**. If `intact=false`, the report says so at the
  top, and the script exits non-zero.

The control mapping is phrased as evidence throughout — "this mechanism provides
evidence FOR this criterion" — never as a pass. Whether a control is satisfied is
an auditor's determination, not software's. See
[`COMPLIANCE.md`](../operate/COMPLIANCE.md) for the full clause mapping.

## 14. What this run did not prove

- **Step-up in production.** `MCPIP_AUTHN_WEBHOOK_URL` and
  `MCPIP_AUTHN_WEBHOOK_SECRET_PATH` were unset, so every production `pin_required`
  call failed closed with `otp_delivery_failed` (seq 6, 8, 9 above) — correct
  behaviour, but it means §11 was completed on a sandbox gateway, not in
  production.
- **Cross-tenant isolation.** Both agents shared tenant `acme-platform`, so the
  seq-9 denial (`gh-release-agent-1` reaching for `cf.d1.query`) came from the
  risk gate, *not* from tenant or compartment separation. Compartment scoping is
  a separate control and was not exercised here.
- **The background integrity monitor.** `_audit_integrity_daemon` runs every 300 s
  and had not re-run when the tamper was introduced, so the metric still read
  `mcpip_audit_integrity_total{event="verified"} 1.0`. Detection in §12 came from
  the on-demand attestation endpoint, which runs the same `verify_chain`.
- **Signed release verification.** The gateway reported
  `ReleaseProvenance(version='2.0.0', verified=False)` — this build was not
  produced by the signed release ceremony in `docs/operate/RELEASE.md`.
- **Real R2.** `r2_buckets_list` returned `Please enable R2 through the Cloudflare
  Dashboard`, so the Cloudflare execution in §8 used D1 instead.

---

**Measuring your own flow.** `scripts/e2e_flow_timing.py` is a timing harness for
the same paths this document walks — as an app (MCP), the SDK and the CLI, as
both a plain user and an admin, including token issuance and forensic
reconstruction. Every segment is a real wall-clock measurement against a running
sandbox gateway; nothing is estimated. Run instructions are in its docstring.
