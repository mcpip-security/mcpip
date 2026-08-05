# mcpip-sdk (Python)

Typed Python client for the **MCPIP** authorization gateway — authorize every
AI action before execution.

- Import package: `mcpip_sdk` · distribution: `mcpip-sdk`
- Python **≥ 3.10** · single runtime dependency: **httpx** (plus `tomli` only on
  the 3.10 CLI floor, where stdlib `tomllib` does not yet exist)
- Fully typed (`py.typed`), `mypy --strict`-clean, frozen-dataclass wire models
  (no pydantic — the SDK never collides with your agent framework's pin)
- Ships the `mcpip` CLI on your PATH (see below)

```bash
pipx install mcpip-sdk          # isolated install, `mcpip` on PATH (recommended)
pip  install mcpip-sdk          # into the active environment

# from a checkout instead, to run an unreleased change:
#   pipx install ./sdk/python
pipx install mcpip-sdk          # once published to PyPI

# Homebrew (works TODAY from git, no published release needed):
brew install --HEAD mcpip/tap/mcpip
# after a tagged release: brew tap mcpip/tap && brew install mcpip
```

## Quickstart (sandbox)

Run a sandbox gateway (`MCPIP_SANDBOX_MODE=true uvicorn app.main:app --port 8080`,
Redis on `:63790`), then:

```python
from mcpip_sdk import Allowed, MCPIPDenied, SandboxClient, Staged

with SandboxClient("http://localhost:8080") as client:
    # SANDBOX ONLY: mint a demo identity. Production tokens come from YOUR IdP.
    client.set_token(lambda: client.dev_token(agent_id="agent-quickstart"))

    print([item.alias for item in client.catalog()])   # metadata, never targets

    outcome = client.authorize("skill_spend_summary", {"period": "2026-Q2"})
    assert isinstance(outcome, Allowed)
    print(outcome.transaction_ref, outcome.worm_sequence)
```

`sdk/python/examples/quickstart.py` is the runnable version of the above.

## The `mcpip` CLI — zero to authorized in three commands

Installing the SDK also installs the `mcpip` command (argparse, no new
dependency). It wraps the very same typed clients — nothing is reimplemented —
and inherits the gateway's discipline: a deny prints **only** a correlation id,
secrets never touch stdout/argv/logs, and exit codes are stable for scripts.

```bash
# 1) point at a gateway and save a named context (mints NO token)
mcpip login --gateway http://localhost:8080 --sandbox --context sbx

# 2) SANDBOX ONLY: mint a demo identity straight into the 0600 token store
#    (the JWT is never printed). Production tokens come from YOUR IdP —
#    supply them via MCPIP_TOKEN, --token-file, or --token-cmd, never argv.
mcpip --context sbx sandbox dev-token --agent agent-quickstart

# 3) authorize one tool call through the choke point
mcpip --context sbx authorize skill_spend_summary --arg period=2026-Q2
```

Everything scripts: `--json` emits the typed model, `--quiet` prints only the
load-bearing id, a deny exits `3` with just `{"error":"denied","correlation_id":…}`.
The step-up ceremony works headless too — a non-interactive `authorize` on a
`pin_required` alias persists the exact envelope and exits `9`; resume with
`mcpip complete --challenge <id>` (OTP via `--otp-stdin` or an interactive
no-echo prompt, never argv). Full reference: [`docs/start/CLI.md`](../../docs/start/CLI.md).

## The three clients

| Client | Surface |
| --- | --- |
| `MCPIPClient` | Agent surface: `authorize`, `complete`, `catalog`, `mcp_call` (JSON-RPC 2.0 on `/v1/mcp`), `health`, `ready`, `version`, `license`, `audit_attestation` (production-available signed audit snapshot), `authz_decision` (OpenID-AuthZEN / COAZ pre-execution PDP verdict), `protected_resource_metadata` (public OAuth 2.1 RS discovery, RFC 9728 — no token) |
| `SandboxClient` | `MCPIPClient` + sandbox-only: `dev_token`, `authenticator_code`, `audit_verify`, `audit_proof` — **each answers 404 on production gateways by design** |
| `MCPIPAdminClient` | `CAP_DIRECTORY_ADMIN` control plane: skills, principals, `decisions_recent`, directory (incl. `directory_relations`, the ReBAC Knowledge-Graph read), workspace plans, cloud environments, vault secrets, `quarantine()`, `canaries()`, `compliance_evidence` (portable evidence bundle — **evidence, never a certification**); `forensic_get` (distinct `CAP_FORENSIC_READ`); community-extension review `extensions_pending` / `extension_approve` / `extension_reject` + registry-governance `verified_publishers_get` / `verified_publishers_put` (distinct `CAP_CATALOG_REVIEWER`) + Contributor `extension_submit` (no capability) |

## The PIN ceremony (step-up)

A `pin_required` alias never executes on the first call. The gateway stages a
**payload-bound, one-time lock** and the approval code travels out-of-band:

```python
staged = client.authorize("skill_payroll_run", {"run_id": "PR-7"})
if isinstance(staged, Staged):                       # HTTP 202 — a RESULT, not an error
    pin = client.authenticator_code(staged.challenge_id)  # sandbox stand-in for the
                                                          # enrolled authenticator
    receipt = client.complete(staged, pin)           # resubmits the IDENTICAL payload
```

Rules the gateway enforces (and the SDK is built around):

- The lock binds `(tenant, agent, alias, arguments)`. `complete()` resends the
  exact envelope kept on `staged.envelope` — **any argument drift is an opaque
  deny** (the lock survives for a correct retry).
- The lock lives `staged.expires_in` seconds (300), allows 5 wrong-PIN
  attempts, and is **consumed exactly once** — replays deny.
- The OTP is never in the 202 and never in any log. In production it reaches
  the approver's enrolled authenticator; model acquisition as your own
  callback, with `authenticator_code` as the sandbox default.
- A step-up staged on the MCP edge (`tools/call` → `isError` result with a
  `challenge_id`) completes on `/v1/authorize`:
  `client.authorize(tool_call=<same JSON-RPC dict>, source_format="mcp_jsonrpc",
  pin=..., challenge_id=...)` — the lock is format-independent.

## Denials are opaque — by design

Every policy deny raises `MCPIPDenied` carrying **only** `correlation_id` (and
the HTTP status). No reason ever crosses the agent boundary; the concrete
cause lives in the gateway's WORM audit log, where an operator resolves it by
that id (`MCPIPAdminClient.decisions_recent` shows it operator-side).

**Never retry a denied call.** Token expiry and policy denials are
indistinguishable on the wire, and a retried step-up consume is itself a real
deny that double-counts audit events. The SDK never retries anything for you.

## Tokens in production

The gateway **verifies** JWTs; it never mints them. Your IdP does (EdDSA or
RS256; 8 required claims — see `scripts/mint_principal.py` in the gateway repo
for the reference minter, including `capabilities` for admin clients).

```python
# Static (externally rotated):
client = MCPIPClient("https://gateway.example", token=os.environ["MCPIP_TOKEN"])

# Callback (your IdP/STS integration) — invoked lazily, cached, and refreshed
# proactively ~30s before the token's own exp; NEVER refreshed on a deny:
client = MCPIPClient("https://gateway.example", token=fetch_token_from_idp)
```

`dev_token` is a sandbox convenience only; it raises `MCPIPSandboxOnly` where
`/v1/dev/token` does not exist (production — identity stays IdP-sovereign).

## Errors

| Exception | Meaning |
| --- | --- |
| `MCPIPDenied(correlation_id, http_status)` | Policy deny — opaque, final, never retry |
| `MCPIPInvalidRequest` | Malformed/oversized envelope (422/413, JSON-RPC -327xx/-32601) |
| `MCPIPUnavailable(retry_after)` | Unreachable / timed out / shedding (503) |
| `MCPIPNotFound` | Unknown challenge/event on a live endpoint |
| `MCPIPSandboxOnly` | Sandbox-only endpoint called against production |

There is deliberately **no** `MCPIPStaged` exception — a staged step-up is a
successful `Staged` result.

Full documentation for both SDKs (Python and TypeScript): `docs/start/SDK.md` in the
gateway repository.
