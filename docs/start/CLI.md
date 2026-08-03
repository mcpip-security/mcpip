# The `mcpip` CLI

`mcpip` is the command you **run** — the shell-native front door to the same
authorization gateway the SDK talks to. It **wraps** the typed SDK clients
(`MCPIPClient` / `SandboxClient` / `MCPIPAdminClient`); it reimplements no wire
protocol, no auth, no envelope logic. It ships in the `mcpip-sdk` Python
distribution and adds **no runtime dependency** (stdlib `argparse`; `httpx`
stays the only one).

It inherits the gateway's non-negotiables:

- **Fail closed, stay opaque.** A policy deny prints **only** a generic message
  and a `correlation_id` — never a reason, target, topology, or gateway state.
- **Secrets never leak.** No JWT, OTP, or vended credential is ever written to
  stdout/stderr/logs. A bearer is **never** accepted as a plain argv value (it
  would leak via shell history and `ps`).
- **No mock / no fake data.** The CLI operates on real gateway state only —
  honest empties over invented rows.
- **Honest exit codes** so it composes in scripts and CI.

```
mcpip [global options] <command> [args]
```

---

## Install

`mcpip` ships in the `mcpip-sdk` distribution. **Neither distribution is on PyPI yet**, so
install from this checkout:

```bash
pipx install ./sdk/python        # isolated, puts mcpip on PATH — recommended
pip install ./sdk/python         # into the active environment (venv or otherwise)
```

No pipx? `python3 -m pip install --user ./sdk/python` needs nothing but Python and puts
`mcpip` in your user bin — `$(python3 -m site --user-base)/bin`, which you may need to add
to `PATH`. Once the package is importable by any route, `python3 -m mcpip_sdk <args>` runs
the identical CLI, which is useful inside a venv or with `PYTHONPATH=sdk/python/src` set
from a checkout.

Once published, `pipx install mcpip-sdk` will be the one-liner. Until then, any instruction
of that shape will fail with "No matching distribution found" — that is the package not
existing yet, not a broken environment.

The release verifier is a separate, deliberately standalone tool — an auditor
must be able to verify a signed release with no gateway, no SDK and no network.
It ships in the **gateway** distribution as `mcpip-verify`, and `mcpip verify` /
`mcpip export-audit` here pass straight through to it when it is importable:

```bash
pip install mcpip                # the gateway distribution: adds mcpip-verify
python -m mcpip_verify verify    # or run it from a checkout, nothing installed
```

Only one distribution may claim the `mcpip` command; a test fails the build if
both ever do again, because installation order would otherwise decide which CLI
a user gets.

**Homebrew (macOS/Linux).** A real virtualenv formula lives at
`packaging/homebrew/mcpip.rb`. The `mcpip/tap` tap is **not published yet**, so
`brew install mcpip/tap/mcpip` has nothing to tap. Install the formula from this checkout:

```bash
brew install --HEAD --build-from-source packaging/homebrew/mcpip.rb
```

After a tagged release, the stable tap:

```bash
brew tap mcpip/tap && brew install mcpip   # or: brew install mcpip/tap/mcpip
```

`httpx` is the only runtime dependency (plus `tomli` on the Python 3.10 floor).
`python -m mcpip_sdk …` and `python -m mcpip_sdk.cli …` are equivalent to `mcpip …`.

---

## Zero to authorized (three commands)

```bash
mcpip login --gateway http://localhost:8080 --sandbox --context sbx
mcpip --context sbx sandbox dev-token --agent agent-quickstart   # sandbox identity
mcpip --context sbx authorize skill_spend_summary --arg period=2026-Q2
```

`python -m mcpip_sdk …` and `python -m mcpip_sdk.cli …` are equivalent to `mcpip …`.

---

## Configuration & precedence

Highest wins:

1. **Explicit flags** — `--gateway`, `--context`, `--sandbox/--no-sandbox`,
   `--token-file` / `--token-stdin` / `--token-cmd`, `--json`, `--config`.
2. **Environment** — `MCPIP_GATEWAY`, `MCPIP_TOKEN`, `MCPIP_CONTEXT`,
   `MCPIP_SANDBOX`, `MCPIP_CONFIG` (exact file), `MCPIP_CONFIG_HOME` (state dir).
3. **Config file** — `~/.mcpip/config.toml` (override the dir with
   `MCPIP_CONFIG_HOME`, or the exact path with `MCPIP_CONFIG`).
4. **Built-in fallback** — `base_url = http://localhost:8080` when nothing else
   resolves.

A consequence worth knowing: `mcpip sandbox dev-token` wires the minted token into the
context (level 3), so `MCPIP_TOKEN` or a `--token-*` flag still wins afterwards. The next
command would then run as a *different* identity and fail with an opaque 403. `dev-token`
warns when that applies — unset `MCPIP_TOKEN`, or keep using it deliberately.

The config file is **kubeconfig-shaped**: a `current-context` plus named
`[context.NAME]` tables, each holding `base_url`, `sandbox`, and a **token-source
reference** — `env:VARNAME` | `file:PATH` | `cmd:'…'`, deliberately **not** a
literal JWT.

```toml
current-context = "sbx"

[context.sbx]
base_url = "http://localhost:8080"
sandbox = true
token-source = "file:/home/you/.mcpip/tokens/sbx.jwt"
```

**Hardening (fail-closed, never best-effort):**

- The config and any token store the CLI writes are created `O_EXCL` at mode
  `0600`. On every read the CLI stats the file and **refuses** (exit `8`) if it
  is group- or world-readable/writable, or if a referenced token file is not
  `0600`.
- Writes are atomic (temp `O_EXCL 0600` in the same dir → fsync → rename).
- `config set` refuses to store anything but an `env:`/`file:`/`cmd:`
  token-source (a literal token would leak into the file); `config list`
  redacts any secret-bearing field.

---

## Authentication (a bearer never touches argv)

The bearer resolves to the SDK's `TokenProvider`, first present wins:

| Source | Notes |
| --- | --- |
| `--token-file PATH` | opened + mode-checked (refuses group/world-readable); used verbatim |
| `--token-stdin` | one line from stdin |
| `--token-cmd 'CMD'` | run per request as a **callable** so the SDK refreshes ~30s before `exp`; never cached to disk by the CLI |
| `MCPIP_TOKEN` | environment |
| context `token-source` | the active context's `env:`/`file:`/`cmd:` reference |

There is deliberately **no** `--token STRING` flag. Minted sandbox dev tokens
(`sandbox dev-token`) are written straight into a `0600` token file and never
echoed.

**Step-up OTP** is read with `getpass` (no echo) on a TTY, or from `--otp-stdin`
— never from argv, never logged, passed once to `complete` and discarded.

**Vault secret material** enters only via `--material-file` / `--material-stdin`,
never `--arg`. A vended cloud credential on an `Allowed` receipt is a **real
secret** and is **never** written to stdout — not on a TTY, not down a pipe, not
to a `>` redirect (`isatty()` is false for a CI pipe, `| tee`, and `> file`
alike, so it is no proxy for a private sink). Human output **summarizes** it
(field names + expiry); `--json` emits a redaction marker. To **capture** the
material, pass `authorize … --credential-out FILE` — it lands via the same
`O_EXCL 0600` write the dev-token / OTP affordances use, and only the path is
printed.

---

## Arguments (`--arg`) — explicit typing, no inference

`--arg key=value` is repeatable. The value is a **string by default** — no type
inference, because the step-up lock binds the exact payload (a ZIP `01234` must
stay a string). Opt into another JSON type with an explicit prefix:

| Prefix | Example | Result |
| --- | --- | --- |
| *(none)* / `str:` | `--arg zip=01234` | `"01234"` |
| `int:` | `--arg n=int:42` | `42` |
| `float:` | `--arg amt=float:19.99` | `19.99` |
| `bool:` | `--arg dry=bool:true` | `true` |
| `json:` | `--arg filter=json:{"a":1}` | `{"a":1}` |

Whole-document inputs (`--tool-call`, `--authz-context`, `--file`, `--manifest`,
`--material-file`) accept `@path`, `-` (stdin), or a literal JSON string.

---

## Output

Human-readable by default: aligned column tables for lists, `key: value` blocks
for single objects, rendered from the frozen SDK models. `--json` emits the model
as stable JSON; `--quiet` prints only the load-bearing id (`transaction_ref`,
`correlation_id`, …). An empty list prints `No <resource>.` (human) or `[]`
(JSON) — **never an invented row**. Color auto-disables off a TTY (`isatty()`); tables do
not — they render identically to a pipe, so column output stays stable in scripts. For
machine consumption use `--json`, which is the supported contract.

A **deny renders identically everywhere** and discloses only the correlation id:

```
denied: request denied by policy (correlation_id=…)   # human → stderr
{"error":"denied","correlation_id":"…"}               # --json → stdout
```

The `--json` deny payload carries **only** `error` (the invariant literal
`"denied"`) and the opaque `correlation_id` — never `http_status`. The gateway
maps 401 (authless) / 403 (policy) / 200 (MCP JSON-RPC edge) / 500 (internal)
all into one deny; surfacing the status would hand a script a reason/edge
discriminator. Exit code `3` is the single, uniform deny signal.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | ok / allowed (also an honest `ready=false` or a forensic miss — the command succeeded) |
| `2` | CLI usage error (bad flags, unknown command, missing argument) |
| `3` | opaque policy **deny** (`MCPIPDenied`) — final; prints only the correlation id |
| `4` | gateway unreachable / timed out / shedding (`MCPIPUnavailable`, incl. 503) |
| `5` | invalid request rejected pre-authorization (`MCPIPInvalidRequest`, 422/413) |
| `6` | referenced resource not found on a live endpoint (`MCPIPNotFound`) |
| `7` | sandbox-only endpoint called against production (`MCPIPSandboxOnly`) |
| `8` | local config/permission error (lax file mode, missing context, bad token-source) |
| `9` | step-up **required** but not completed here — envelope persisted, resume with `mcpip complete` |
| `1` | unexpected/other error |

---

## Command reference

### Up — the one blessed front door

| Command | Wraps |
| --- | --- |
| `mcpip up [--repo PATH] [--print-only] [--auto [--yes] [--brief TEXT] [--company NAME]]` | `scripts/quickstart.sh` from an MCPIP checkout (auto-detected from the CWD upward, or `--repo`): prereq checks → Redis `:63790` → **sandbox** gateway `:8080` → live walkthrough, then prints the zero→governed-call time. Idempotent — reuses anything already running. Sandbox-only; production boot stays the fail-closed ceremony (`docs/operate/OPERATIONS.md`). Outside a checkout it prints the exact `git clone` line, never a stack trace. `--print-only` shows the plan without starting anything. After a successful boot it prints the **proof beat** — the signed audit attestation (chain intact, WORM head, Merkle root, signing key): success is a line you can see, not an exit code. `--auto` (sandbox-only, self-driving) drafts a deny-by-default workspace plan from `--brief`/`--company` via the gateway's own deterministic draft endpoint, validates it, prints the reviewable proposal (alias → target · risk tier), and applies **only on explicit consent** (`--yes` or an interactive `y`; off-TTY with no `--yes` it saves `mcpip-workspace-plan.json` for `mcpip admin workspace apply --file …` and applies nothing). Apply is the same hardened, WORM-logged admin endpoint the console uses. |

### Connect

| Command | Wraps |
| --- | --- |
| `mcpip login [--gateway URL] [--sandbox] [--context NAME] [--token-source REF]` | `MCPIPClient.health()`; saves a context (mints no token) |
| `mcpip whoami` | decodes the active bearer's claims LOCALLY (unverified, display only), then confirms via `MCPIPClient.version()` — never prints the token |
| `mcpip config list \| get <KEY> \| set <KEY> <VALUE> \| unset <KEY>` | reads/writes `config.toml` (0600, redacts secrets, refuses a literal token) |
| `mcpip context list \| current \| use <NAME> \| set <NAME> […] \| delete <NAME>` | kubeconfig-style context management |

### Agent

| Command | Wraps |
| --- | --- |
| `mcpip catalog` | `MCPIPClient.catalog()` |
| `mcpip authorize <ALIAS> [--arg k=v …] [--format FMT] \| [--tool-call @file [--vendor V]] [--credential-out FILE] [--otp-stdin\|--otp-prompt]` | `MCPIPClient.authorize()`; on 202 runs step-up inline or persists the envelope and exits `9`. A vended cloud credential is never printed — capture it with `--credential-out FILE` (`O_EXCL 0600`) |
| `mcpip complete --challenge <ID> [--otp-stdin\|--otp-prompt]` | `MCPIPClient.complete()` — replays the byte-identical persisted envelope |
| `mcpip decision <ALIAS> [--arg k=v …] [--action NAME] [--authz-context @file]` | `MCPIPClient.authz_decision()` (AuthZEN PDP verdict; nothing executes) |
| `mcpip mcp initialize` | `MCPIPClient.mcp_call('initialize')` |
| `mcpip mcp tools list` | `MCPIPClient.mcp_call('tools/list')` |
| `mcpip mcp tools call <ALIAS> [--arg k=v …] [--otp-stdin]` | `MCPIPClient.mcp_call('tools/call', …)`; an `isError` step-up is completed format-independently |
| `mcpip verify <...>` | The release verifier (`mcpip_verify`), read-only and network-free. Arguments pass straight through, so `mcpip verify --manifest … --pubkey …` and `mcpip verify bundle …` behave exactly as [Operations](../operate/OPERATIONS.md) documents. Ships in the **gateway** distribution; with only the SDK installed this reports that and names `mcpip-verify` / `python -m mcpip_verify` rather than returning a verdict |
| `mcpip export-audit <...>` | Read-only WORM export, with `--verify` re-verifying the signed chain offline. Same passthrough and same absence behavior as `verify` |
| `mcpip why <CORRELATION_ID>` | Resolves a denial to its reason **and the fix**. Reads `admin.forensic_get()` first (`CAP_FORENSIC_READ`), falling back to the decision projection (`CAP_DIRECTORY_ADMIN`). Changes nothing about agent-facing opacity; with neither capability it reports what it lacked rather than guessing. `--json` returns a stable shape (nulls, never missing keys); `--quiet` prints the bare reason token |

### Reads

| Command | Wraps |
| --- | --- |
| `mcpip health` | `MCPIPClient.health()` |
| `mcpip ready` | `MCPIPClient.ready()` (503 → honest `ready:false`, exit `0`) |
| `mcpip version [--client]` | `MCPIPClient.version()`; `--client` prints the local CLI+SDK version (no gateway call) |
| `mcpip license` | `MCPIPClient.license()` |
| `mcpip discovery` | `MCPIPClient.protected_resource_metadata()` (public RFC 9728; no token sent) |
| `mcpip audit attestation` | `MCPIPClient.audit_attestation()` (signed WORM snapshot; `CAP_DIRECTORY_ADMIN`) |

### Authenticator — completing a step-up in production

A `pin_required` alias stages rather than allows, and finishing the cycle needs a
one-time code that reached a human out of band. In the sandbox the code is simply
disclosed (`mcpip sandbox authenticator`). **In production the channel is an
enrolled RFC 6238 authenticator**, and these commands drive it — before they
existed, `mcpip authorize` would stage, tell you to run `mcpip complete`, and that
command could not succeed, because no command could fetch the code.

| Command | Wraps |
| --- | --- |
| `mcpip authenticator status` | `MCPIPClient.authenticator_status()` — is an authenticator enrolled for this principal |
| `mcpip authenticator enroll --out FILE` | `MCPIPClient.authenticator_enroll()`; writes the `otpauth://` URI to `FILE` (`O_EXCL 0600`) and prints only the path — **the URI embeds the secret**. Returned exactly once; re-enrolling over a live authenticator is refused |
| `mcpip authenticator confirm --code DIGITS` | `MCPIPClient.authenticator_confirm()` — proves possession and activates the enrollment |
| `mcpip authenticator reveal --challenge ID --code DIGITS [--out FILE] [--credential-out FILE]` | `MCPIPClient.authenticator_reveal()`; releases the payload-bound OTP and completes the staged challenge **inline**, never echoing it. `--out` captures the code instead of completing |
| `mcpip authenticator disable --code DIGITS` | `MCPIPClient.authenticator_disable()` — retires the authenticator; needs a valid current code, so a stolen bearer alone cannot swap someone's second factor |

Two distinct secrets are in play, and conflating them is the usual mistake: the
**TOTP code** proves a human is present, and the **OTP** it releases is bound to the
canonical hash of *this* payload. Proving presence does not authorize an action —
it only unseals the lock for the one action already staged.

```console
$ mcpip authorize skill_wire_transfer --arg amount=9000
step-up required: envelope persisted. Resume with:
  sandbox     mcpip sandbox authenticator c3640d741971455aad5c9321013f3b91
  production  mcpip authenticator reveal --challenge c3640d741971455aad5c9321013f3b91 --code <6 digits from your enrolled authenticator>

$ mcpip authenticator reveal --challenge c3640d741971455aad5c9321013f3b91 --code 314159
decision              : allow
status                : committed
transaction_ref       : txn_d8b39ef4a1774a73baee8acd478e05da
worm_sequence         : 22
```

### Sandbox (404 opaque in production → exit `7`)

| Command | Wraps |
| --- | --- |
| `mcpip sandbox capabilities` | `SandboxClient.capabilities()` — the well-known capability UUIDs by name, so minting an admin token needs no source-reading |
| `mcpip sandbox dev-token [--tenant --agent --role --cap UUID … --compartment --session-id UUID] [--out FILE]` | `SandboxClient.dev_token()`; writes the JWT into the 0600 token store (or `--out`, `O_EXCL 0600`), **never printed**. Stamps a stable per-context `session_id` (minted once, reused on re-mints) so the WORM chain attributes this context's calls to one session; `--session-id` overrides |
| `mcpip sandbox authenticator <CHALLENGE_ID> [--out FILE]` | `SandboxClient.authenticator_code()`; completes the staged challenge inline (or writes the OTP to a 0600 file), **never echoed** |
| `mcpip sandbox audit verify` | `SandboxClient.audit_verify()` |
| `mcpip sandbox audit proof <EVENT_ID>` | `SandboxClient.audit_proof()` |

### Admin (`CAP_DIRECTORY_ADMIN`, except where noted)

Capabilities are UUIDs in the JWT `capabilities` claim — a role string never grants one. In
sandbox, list the well-known ones and mint a token carrying what you need:

```bash
mcpip sandbox capabilities                            # the UUIDs, by name
mcpip sandbox dev-token --agent ops-admin \
  --cap b8e4a1d7-2c6f-4e93-9a05-7f1c3b5d8e20          # CAP_DIRECTORY_ADMIN
```

In production the gateway mints nothing — your IdP issues a token carrying the capability,
and a missing one is the same opaque deny as any other refusal. `mcpip whoami` echoes what
the token you are presenting actually carries, which is faster than probing.

| Command | Wraps |
| --- | --- |
| `mcpip admin skills ls \| disabled` | `skills_registered()` / `skills_disabled()` |
| `mcpip admin skills register <ALIAS> <TARGET> [--risk-tier] [--classification]` | `skills_register()` |
| `mcpip admin skills deregister\|disable\|enable <ALIAS>` | `skills_deregister/disable/enable()` |
| `mcpip admin extensions submit --manifest @file` | `extension_submit()` (Contributor; any valid token) |
| `mcpip admin extensions pending\|approve <ID>\|reject <ID>` | `extensions_pending/approve/reject()` (`CAP_CATALOG_REVIEWER`) |
| `mcpip admin decisions [--limit N] [--watch] [--interval S]` | `decisions_recent()`; `--watch` polls politely, honest empty tail, a mid-watch transport error exits `4` |
| `mcpip admin forensic get <CORRELATION_ID>` | `forensic_get()` (`CAP_FORENSIC_READ`); an honest miss is `null` at exit `0` |
| `mcpip admin principals ls \| revoke <AGENT_ID> [--reason] \| reactivate <AGENT_ID>` | `principals_revoked/revoke/reactivate()` |
| `mcpip admin quarantine \| canaries` | `quarantine()` / `canaries()` |
| `mcpip admin directory get \| put --file @doc \| relations [--subject --relation --object]` | `directory_get/put/relations()` |
| `mcpip admin policy get \| put --file @doc \| delete` | `policy_get/put/delete()` |
| `mcpip admin workspace draft […] \| validate --file @plan \| apply --file @plan` | `workspace_draft/validate/apply()` |
| `mcpip admin cloud-env ls \| put <ENV_ID> --provider --role --region [--compartment --session-ttl --vault-secret-id] \| rm <ENV_ID>` | `cloud_environments_list/put/delete()` |
| `mcpip admin vault ls \| put <SECRET_ID> --vendor [--description] (--material-file @json\|--material-stdin) \| rm <SECRET_ID>` | `vault_secrets_list/put/delete()` — material never via argv |
| `mcpip admin users ls \| invite <EMAIL> [--role] \| update <EMAIL> [--role] [--status] \| rm <EMAIL>` | `users_list/invite/update/remove()` — the console team roster. `role` is a management label; it authorizes nothing |
| `mcpip admin compliance evidence` | `compliance_evidence()` — the portable evidence bundle. Evidence, never a certification |
| `mcpip admin publishers get \| set <NAMESPACE>...` | `verified_publishers_get/put()` — the reverse-DNS allow-list a registry-server approval is checked against (`CAP_CATALOG_REVIEWER`) |
| `mcpip admin decisions-history [--from-ms] [--to-ms] [--cursor] [--limit] [--filter K=V] [--all]` | `decisions_query()` / `decisions_iter()` — the date-ranged, multi-filtered, cursor-paged decision history. `--all` walks every page for an export; `--filter correlation_id=…` is the direct lookup behind `mcpip why` |
| `mcpip admin canaries` | `canaries()` — the seeded decoy aliases. Nothing legitimate calls one, so a hit is an enumeration signal |
| `mcpip admin stats` | `stats()` — local deployment, license and usage counters, plus telemetry state |

---

## Shell completion

Not shipped in this wave. argparse has no built-in completion generator, and the
usual route (`argcomplete`) would add a runtime dependency — breaking the CLI's
one-dependency property (`httpx`, plus `tomli` only on the 3.10 floor). The
command tree is shallow and discoverable via `mcpip --help` / `mcpip <group>
--help`; a dependency-free static-completion generator (`mcpip completion bash`)
is a candidate for a follow-up if demand warrants it.

---

## TypeScript parity

A thin, zero-dependency `mcpip` bin ships with `@mcpip/sdk`, mirroring the same command
tree, config precedence, token/OTP rules, opaque-deny rendering, and exit codes.

`@mcpip/sdk` is not on npm yet, so `npx @mcpip/sdk` has nothing to fetch. Build and run it
from the checkout:

```bash
cd sdk/typescript && npm install && npx tsc -p tsconfig.json
node dist/cli.js --help
```

Installing the package (`npm install -g ./sdk/typescript`) puts its own `mcpip` on your
PATH. If you also installed the Python SDK, whichever comes first in `PATH` wins — keep one,
or invoke the TypeScript build by path. See [`SDK.md`](SDK.md).
