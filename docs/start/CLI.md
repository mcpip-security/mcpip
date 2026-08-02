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

`mcpip` ships in the `mcpip-sdk` distribution. Any of:

```bash
pipx install ./sdk/python        # from this checkout — isolated, mcpip on PATH
pip  install ./sdk/python        # into the active environment
pipx install mcpip-sdk           # once published to PyPI
```

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
`packaging/homebrew/mcpip.rb`. It works **today**, before any published release,
straight from git:

```bash
brew install --HEAD mcpip/tap/mcpip     # bleeding edge, builds from the repo
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
(JSON) — **never an invented row**. Color/tables auto-disable off a TTY.

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

### Sandbox (404 opaque in production → exit `7`)

| Command | Wraps |
| --- | --- |
| `mcpip sandbox dev-token [--tenant --agent --role --cap UUID … --compartment --session-id UUID] [--out FILE]` | `SandboxClient.dev_token()`; writes the JWT into the 0600 token store (or `--out`, `O_EXCL 0600`), **never printed**. Stamps a stable per-context `session_id` (minted once, reused on re-mints) so the WORM chain attributes this context's calls to one session; `--session-id` overrides |
| `mcpip sandbox authenticator <CHALLENGE_ID> [--out FILE]` | `SandboxClient.authenticator_code()`; completes the staged challenge inline (or writes the OTP to a 0600 file), **never echoed** |
| `mcpip sandbox audit verify` | `SandboxClient.audit_verify()` |
| `mcpip sandbox audit proof <EVENT_ID>` | `SandboxClient.audit_proof()` |

### Admin (`CAP_DIRECTORY_ADMIN`, except where noted)

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

A thin, zero-dependency `mcpip` bin ships with `@mcpip/sdk` mirroring the same
command tree, config precedence, token/OTP rules, opaque-deny rendering, and exit
codes. Until it is published, run it with `npx @mcpip/sdk mcpip <args>`. See
[`docs/start/SDK.md`](SDK.md).
