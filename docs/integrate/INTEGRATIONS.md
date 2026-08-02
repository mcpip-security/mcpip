# MCPIP Integrations & Cloud-Identity Reference

This is the consolidated reference for how MCPIP interoperates with the identity
and cloud infrastructure around it: how a fleet's ephemeral agents obtain the
sender-constrained tokens the gateway verifies (**Workload Identity**), how the
MCP edge presents itself as a discoverable, audience-bound **OAuth 2.1 Resource
Server**, how to bring a money-moving / data-egress / email-send tool inside the
authorization boundary (the **Governed-Alias Pattern**), and a runnable
end-to-end **Cloud IAM Live-Fire** that vends a real least-privilege AWS
credential through the gateway. Each section below is a distinct integration
topic, co-located here as the single cloud-identity reference. For orientation
elsewhere: setup lives in `docs/start/GETTING_STARTED.md`, the pipeline and domain
concepts in `docs/integrate/ARCHITECTURE.md`, running/operating the gateway in
`docs/operate/OPERATIONS.md`, and client-side integration in `docs/start/SDK.md`.

---

## Workload Identity

*Workload Identity & Sender-Constrained Tokens at Fleet Scale*

How an autonomous **fleet** — an employee launches an orchestrator that spawns
many ephemeral sub-agents — satisfies MCPIP's enforced sender-constraint posture
without hand-enrolling a key into every agent.

This is the **provisioning** half of proof-of-possession. MCPIP itself only ever
*verifies* (§4); the minting, attestation, and key custody are the org's platform
responsibility (§2–3). The boundary is drawn deliberately and the residual risks
that live outside it are named honestly (§6).

### 1. The problem

A sender-constrained token (`cnf.jkt`) is unusable without the matching private
key. That is the point — a stolen token is inert. But it presumes each caller
*has* a key and can *sign*. Fleets break three assumptions:

- **Ephemeral agents** are spawned on demand and have no pre-enrolled key.
- **Fan-out**: one human → one orchestrator → 50 sub-agents. Copying one key to
  all 50 destroys isolation; enrolling 50 keys by hand does not scale.
- **Heterogeneous runtimes**: some can hold a key in a TEE/KMS, some are a bare
  process loop.

Enforcing PoP on *every* agent would fail-close the keyless ones and break the
fleet. MCPIP's answer is **not** to enforce per-agent — it enforces per **action
risk** at the resource (see `require_sender_constraint` + the production
boot-lint; see [the security invariants](../SECURITY_THREAT_MODEL.md#1b-the-security-invariants)). Cheap/low-risk work rides a bearer
token and never newly fails; only sensitive actions demand a key-proof. This
document is how the agents that *do* reach sensitive actions get a key.

### 2. The model: enroll the human once, attest the agents per session

- The **human/employee** enrolls **one** key (device authenticator / org IdP)
  — done once.
- Each **agent**, on spawn, generates an **ephemeral keypair in memory** (or in
  a TEE, or references a non-exportable KMS handle). No agent key is ever
  enrolled, persisted, or shared.
- The agent's **runtime** proves what it is via an attestation the platform
  already issues: a SPIFFE SVID, a cloud instance-identity document, a TPM
  quote, or a KMS-signed challenge.
- The org **STS** exchanges that attestation (RFC 8693 token-exchange) for a
  **short-lived** (≤5 min) MCPIP-audience JWT whose `cnf.jkt` is the RFC-7638
  thumbprint of the agent's ephemeral public key, and whose `act.sub` records
  the human principal the agent acts for.

The key is born in the agent and dies with the process: no sprawl, no theft
across restarts, and a compromised leaf discloses only its own short-lived,
minimal authority.

### 3. The exchange flow (org STS — NOT MCPIP)

```
 agent (on spawn)                    runtime attestor            org STS / IdP
 ────────────────                    ───────────────            ─────────────
 1. keypair = generate()  (in memory / TEE / KMS)
 2. jwk_pub = public(keypair)
 3. attestation = attest()  ──────▶  SPIFFE SVID / IMDS doc /
                                     TPM quote / KMS signature
 4. POST /token  (RFC 8693)  ─────────────────────────────────▶  verify attestation,
      grant_type=token-exchange                                  bind req_cnf=jwk_pub,
      subject_token=attestation                                  set act.sub=human,
      req_cnf={ "jkt": thumbprint(jwk_pub) }                     narrow scope/caps,
                                                                 sign (kid=…)
 5.  ◀───────────────────────────────────────────────────────  short-lived JWT
                                                                 { cnf.jkt, act.sub, exp≤5m }
```

Per request thereafter the agent signs a fresh DPoP proof with `keypair` and
sends it in the `DPoP` header alongside the bearer JWT (§4).

### 4. MCPIP's role: verify only

MCPIP never mints in production (the sandbox `/v1/dev/token` forge 404s when
`sandbox_mode=false`). It verifies:

1. **The JWT** — via a `KeyProvider`. For an STS that rotates signing keys, wire
   `JWKSKeyProvider` (ships in `auth/token_resolver.py`): it selects the
   verification key by the token header's `kid` from a JWKS document you supply
   at boot. It is deliberately **not** network-fetching — a synchronous JWKS
   round-trip on the auth path would be a fail-closed single point of failure —
   so load/refresh the JWKS out-of-band (config, mounted file, or a boot-time
   fetch you perform) and overlap old+new `kid` across a rotation window.

   ```python
   from auth import JWKSKeyProvider, TokenResolver

   jwks = load_jwks_document()  # your boot-time fetch/mount — MCPIP does not dial out
   resolver = TokenResolver(
       JWKSKeyProvider(jwks),
       issuer="https://sts.example",     # verified against the token's iss
       audience="mcpip-gateway",         # verified against the token's aud
   )
   ```

2. **The proof-of-possession** (`auth/pop.py`, pipeline step 5a) — `typ`,
   asymmetric alg allow-list, public-only JWK, RFC-7638 thumbprint == `cnf.jkt`
   (constant-time), signature, `htm`/`htu`, `ath` (token hash) + `pch`
   (canonical payload hash), freshness, single-use `jti`. See [the security invariants](../SECURITY_THREAT_MODEL.md#1b-the-security-invariants).

3. **The resource requirement** — a sensitive alias
   (`require_sender_constraint`) demands the above; a bare bearer is denied
   `SENDER_CONSTRAINT_REQUIRED`, and production refuses to boot if a sensitive
   AUTO alias forgets the flag.

That is the whole MCPIP surface. Everything else is the platform's.

### 5. Heterogeneous runtimes degrade *scoped*, never silent

A runtime that cannot hold a key simply receives a bearer token and is
structurally confined by the resource-side requirement to the actions its
assurance permits: it keeps doing its legitimate low-risk work and is refused —
fail-closed — only at a sensitive action it cannot prove it deserves. Nobody is
forced to sign for work that does not require it.

### 6. Residual risk — honest boundary

Sender-constraint relocates trust into the attestation/STS layer; it does not
eliminate these, and MCPIP is structurally blind to them:

- **Node-foothold adversary.** SSRF-to-IMDS, a stolen SPIRE SVID, a co-tenant
  container, a leaked KMS/IAM role, or `ptrace`/`/proc/<pid>/mem` on a shared
  host lets an attacker present a *genuine* attestation and bind `cnf` to a key
  **it controls**, or invoke the node's signer directly. MCPIP verifies both
  flawlessly. Mitigation is hardware-rooted attestation (TPM/TEE),
  non-exportable KMS keys, and host isolation — the org's job, not MCPIP's.
- **Weak-issuer downgrade lane — closed.** If you trust a *second* issuer of
  lower assurance that also stamps `cnf` (e.g. a human OIDC IdP on password
  auth), its `cnf` must not satisfy a resource that demands sender-constraint.
  MCPIP addresses this: compose per-issuer `TokenResolver`s with
  `MultiIssuerResolver`, and mark only the workload STS `attesting=True`. The
  per-issuer flag flows to `Identity.cnf_attested`, and the resource gate
  requires an **attested** cnf — a non-attesting issuer's `cnf` is refused
  `SENDER_CONSTRAINT_REQUIRED`. Routing is by the *verified* `iss` (a forged
  `iss` selects a resolver that then rejects the signature).

  ```python
  from auth import MultiIssuerResolver, TokenResolver, JWKSKeyProvider

  resolver = MultiIssuerResolver([
      TokenResolver(JWKSKeyProvider(sts_jwks), issuer="https://sts.example",
                    audience="mcpip-gateway", attesting=True),    # workload STS
      TokenResolver(JWKSKeyProvider(oidc_jwks), issuer="https://oidc.example",
                    audience="mcpip-gateway", attesting=False),   # human IdP
  ])
  ```
- **Availability.** The STS, the JWKS you supply, and the per-request `jti`
  replay guard are all fail-closed. An outage denies high-value actions
  fleet-wide (the correct posture, but a real availability weapon). Keep the
  replay-guard Redis linearizable and `noeviction`; enforce fleet NTP discipline
  (clock skew > 120 s can reopen single-use on a lagging node).

### 7. Status & roadmap

| Piece | Owner | Status |
|-------|-------|--------|
| DPoP proof (method+url+ath+pch, single-use) | MCPIP | shipped (`auth/pop.py`) |
| Resource-side `require_sender_constraint` + boot-lint | MCPIP | shipped |
| Secure-by-default catalog for sensitive reads | MCPIP | shipped |
| `JWKSKeyProvider` (rotating signing keys, no network) | MCPIP | shipped (`auth/token_resolver.py`) |
| Multi-issuer trust + attesting-issuer scoping | MCPIP | shipped (`MultiIssuerResolver`, `attesting`) |
| Runtime attestation → RFC 8693 token-exchange STS | **Org platform** | integration |
| Ephemeral in-memory / TEE / KMS agent keys | **Org platform** | integration |

---

## OAuth 2.1 Resource Server

MCPIP's MCP edge is an **OAuth 2.1 Resource Server (RS)**. A conformant MCP
client must be able to *discover* how to obtain a token MCPIP will accept, and
must not be able to route around the gateway by presenting a token minted for a
different resource. Three strictly-additive, opt-in pieces make that true. None
of them widens the identity model, changes any existing request shape, or
touches the payload lock — every existing token behaves exactly as before.

### 1. RFC 9728 — Protected Resource Metadata

```
GET /.well-known/oauth-protected-resource        (public, unauthenticated)
```

A small, static JSON discovery document, derived entirely from live gateway
configuration. Reachable in **both sandbox and production** (a discovery doc
must be findable) and exempt from admission-control shedding (parity with
`/healthz` and `/metrics`). It is a `GET`, so the edge middleware's bodyless /
unauthenticated-`POST` 401 — scoped to `POST /v1/authorize` — never applies.

Example (the shipped single-issuer sandbox boot):

```json
{
  "resource": "mcpip-gateway",
  "authorization_servers": ["mcpip-demo-idp"],
  "bearer_methods_supported": ["header"]
}
```

| Field | Source | Meaning |
|---|---|---|
| `resource` | `settings.jwt_audience` | The gateway's own resource identifier — the single RFC 8707 audience this RS represents. |
| `authorization_servers` | the trusted-issuer set read from the **resolver** (`resolver.issuers`), sorted | The AS(es) whose tokens MCPIP verifies. A multi-issuer deployment lists all of them; the shipped single-`TokenResolver` path lists exactly `[settings.jwt_issuer]`. |
| `bearer_methods_supported` | constant `["header"]` | MCPIP accepts the bearer token only in the `Authorization: Bearer` header (or the header-class JSON `jwt` field) — **never** a query parameter. |

There is deliberately **no `scopes_supported`** key. MCPIP has no OAuth scopes:
the `role` claim authorizes nothing, and authorization is capability-UUID /
grant based — those UUIDs are hidden topology and must never be published.
Honest omission beats a fabricated scope list.

The document carries **no secret and no alias→target topology** — only the two
non-secret discovery identifiers RFC 9728 exists to publish. The builder
(`auth/oauth_metadata.build_protected_resource_metadata`) is pure and boot-free:
it imports no HTTP client / socket / SDK, holds no state, and can be rendered in
a test without an app reboot.

### 2. RFC 8707 — Resource-indicator / audience binding

MCPIP already binds every token to its resource. `TokenResolver.resolve` calls

```python
jwt.decode(..., audience=self._audience, options={"verify_aud": True})
```

so a token minted for a **different** resource (a different `aud`) raises
`InvalidAudienceError` → `TokenError` → the opaque `JWT_INVALID` deny the agent
already sees. This is exactly what stops a compliant client (or an attacker)
from replaying a token obtained for some *other* resource server at MCPIP's
edge: the audience is the resource indicator, and it must name this gateway.

This binding is **not relaxed and not widened** by issuer pinning — that adds regression
coverage (resolver-level and end-to-end) and nothing else. See
`tests/test_oauth_resource_metadata.py::test_rfc8707_*`.

### 3. SEP-2352 — Issuer pinning (`iss_binding`)

The issuer is a verified, pinned dimension. `MultiIssuerResolver` routes by the
*unverified* `iss` only to select a per-issuer `TokenResolver`, which then fully
verifies `iss == self._issuer` cryptographically; the verified value is recorded
on `Identity.issuer`.

Issuer pinning is an **optional, fail-closed defense-in-depth check**. If a token carries a
top-level `iss_binding` claim, it MUST be a string equal to the cryptographically
verified issuer:

```
iss_binding present and (not a string, or != verified iss)  ⇒  TokenError → JWT_INVALID
iss_binding absent                                          ⇒  no-op (legacy tokens unchanged)
```

This defends against a re-wrapped / token-exchanged token whose internal
issuer-binding assertion disagrees with the AS that actually signed it. Because
the check lives inside the per-issuer `TokenResolver`, `MultiIssuerResolver`
inherits it automatically. It adds no `Identity` field (the issuer already
carries the verified value) and touches nothing in the `{EdDSA, RS256}` algorithm
allow-list — it is an *additional* check performed **after** full cryptographic
verification, never a relaxation.

### What issuer pinning does NOT do

- It does **not** add a `WWW-Authenticate: Bearer resource_metadata=...` header to
  the existing 401 path — that would alter the current opaque 401 response shape.
  The RFC 9728 endpoint alone satisfies the discovery requirement; adding the
  header is a separate, owner-visible decision.
- It does **not** widen the `{EdDSA, RS256}` algorithm allow-list.
- It does **not** add a synchronous JWKS fetch to the hot path; the Wave-5
  `jwks_refresher` substrate (last-good / fail-closed) is unchanged.
- It does **not** touch `canonical_json`, `enforce_argument_safety`, the scrypt
  PIN-hash derivation, the Rust mirror, or the WORM epoch header.

---

## Governed-Alias Pattern

*How to bring a money-moving / data-egress / email-send tool inside MCPIP's authorization
boundary — and exactly what that does and does not buy you.*

Status: reference deployment pattern. Built entirely on shipped mechanisms — no new engine, no
payload-lock change. Drivable end to end against the sandbox gateway
(`tests/test_governed_alias_pattern.py`, `scripts/dynamodb_vend.py`).

### 1. The gap: interceptor, not proxy

MCPIP is an **authorization interceptor** on the agent's tool-call plane, not a proxy sitting in
front of every third-party MCP server. It governs a call **only when the agent invokes it as an
MCPIP alias**. Two real-world 2026 attack classes live *outside* that plane unless you bring the
sensitive tool inside it (see the internal strategy notes §5.5):

- **The MCP rug pull (`postmark-mcp`).** The first confirmed malicious MCP server in the wild:
  correct for 15 versions, then v1.0.16 silently BCC'd every agent-sent email to an attacker
  domain. `postmark-mcp` was a *third-party* server the agent called directly. MCPIP never saw
  that traffic — it would not have caught the package.
- **Tool-description injection ("line jumping," Trail of Bits).** A malicious server poisons the
  agent's planning context the moment the client connects, *before any tool is invoked*. This
  lives **upstream** of MCPIP, in the model's context — MCPIP does not read it.

Neither is a flaw in the gateway; both are simply on a plane MCPIP does not observe. The fix is a
**deployment posture**: register the sensitive side-effecting tool as a *governed MCPIP alias*
instead of handing the agent the raw third-party MCP server. Then the side-effecting call crosses
MCPIP's choke point and inherits the payload lock, the out-of-band step-up, and the
write-before-execute WORM record — for free, with no new code.

### 2. The recipe

Take the tool that actually moves money / sends email / egresses data. Instead of the agent
holding the raw vendor MCP server, point an **MCPIP alias** at your real send endpoint and let the
agent call the alias. Make it `PIN_REQUIRED` (secure by default — see §4). Two registration routes,
both shipped:

#### Route A — `cloud_rest` egress alias (money-move / email-send)

The side-effecting endpoint is an HTTP call you control. Register a `cloud_rest`,
`RiskTier.PIN_REQUIRED` alias whose `target` is your real send endpoint — the agent only ever sees
the opaque alias name and the transport *class*, never the dotted target.

- **Shipped reference:** `skill_email_send` on the `mcpip-inc` teaching tenant
  (`obfuscator/tenant_catalog.py`) — `cloud_rest`, `PIN_REQUIRED`, un-compartmented,
  `UNCLASSIFIED`. This is the permanent, drivable "postmark-mcp would have been a governed alias"
  example. The recipient set rides in `arguments` (`{"to": [...], "subject": ..., "body": ...}`).
- **Runtime route (no redeploy):** an operator with `CAP_DIRECTORY_ADMIN` calls
  `POST /v1/admin/skills/register` with
  `{"alias": "skill_notify_send", "target": "rest.ops.notify.send", "risk_tier": "pin_required",
  "classification": "unclassified"}`. The overlay path (`_apply_overlay_skill`) mints it
  additive-only: `cloud_rest`-only, never repoints an existing alias, WORM-logged before apply.

#### Route B — `cloud_iam` credential-vend egress (no standing key)

The side-effecting call needs a cloud credential (e.g. a DynamoDB `PutItem`, an S3 write). Register
a `cloud_iam`, `PIN_REQUIRED` alias whose `target` is a `CloudEnvironment` `env_id` bound to a
**distinct least-privilege role**. Completing the step-up **vends a short-lived, scoped credential**
(STS `AssumeRole` / SA impersonation / AAD token) instead of the agent holding a standing key. A
read binding can never satisfy a write skill (distinct `env_id`, distinct role).

- **Shipped reference:** `skill_aws_dynamodb` (`obfuscator/tenant_catalog.py`) — `cloud_iam`,
  `PIN_REQUIRED`, `team-engineering`, backed by a write-scoped `CloudEnvironment`. Drivable in
  sandbox via `scripts/dynamodb_vend.py`; against a real table with a least-privilege role via
  [Cloud IAM Live-Fire (DynamoDB)](#cloud-iam-live-fire-dynamodb).

### 3. The threat it closes

Once the sensitive tool is a governed alias, two structural controls attach automatically. Neither
is a new mechanism — both fall out of the shipped payload lock and OTP channel.

#### 3.1 The exact recipient set is cryptographically bound

The one-time PIN is bound to `lock_payload_hash({tenant, agent, alias, arguments})`
(`auth/pin_validator.py`) at staging, and the atomic `LOCK_CONSUME_LUA` compares the payload hash
**before** it spends the PIN. So the recipient set / payload rides in `arguments` and is bound at
staging. A covert extra recipient — the exact `postmark-mcp` BCC — or a redirected payload injected
at *completion* changes `arguments` → a different hash → **`PAYLOAD_MISMATCH` deny**. Nothing
egresses. (Because a payload mismatch is rejected *without* spending a PIN attempt, a legitimate
correct-payload retry still works.)

#### 3.2 Write-before-execute makes the real staged payload forensically undeniable

The staged decision is emitted to the signed Merkle WORM log **before** any receipt is returned and
**before** dispatch. The honest recipient set captured at staging is durable and tamper-evident on
the operator decision feed (`GET /v1/admin/decisions/recent`) and reconstructable via the forensic
surface — *before* the send could fire. Covert exfil is therefore either payload-mismatch-denied or
forensically undeniable.

#### 3.3 The out-of-band OTP is the circuit-breaker for a line-jumped agent

A `PIN_REQUIRED` egress alias **cannot complete** without the one-time code delivered out-of-band
via `BaseAuthenticatorChannel` (a signed HTTPS webhook push in production; the enrolled-device
stand-in in sandbox). A fully line-jumped agent — one whose planning context was poisoned upstream,
so *its intent is already compromised* — still cannot produce a code it never received. This holds
**regardless of why the agent decided to act**: the OTP is independent of the token and the agent's
reasoning. That is the structural circuit-breaker the injection classes lack an answer to.

### 4. Secure by default

- **A sensitive egress alias MUST be `PIN_REQUIRED` and/or `require_sender_constraint`.** The
  production boot-lint `_enforce_sender_constraint_policy` (`app/main.py`) refuses to boot if any
  `RESTRICTED`/`CLASSIFIED` alias that is *not* `PIN_REQUIRED` lacks `require_sender_constraint` —
  an AUTO-tier sensitive read has no PIN, so a bearer that clears the compartment gate could
  exfiltrate it. A `PIN_REQUIRED` alias is **exempt** from that lint: the out-of-band OTP is the
  human-in-the-loop control, independent of the token. That is why `skill_email_send` is
  `PIN_REQUIRED` and stays secure-by-default in production without provisioning a `cnf`/attesting
  token.
- **Runtime overlay entries are `cloud_rest`-only and additive-only.** `register_skill` refuses
  `restricted`+`auto` (it would smuggle in exactly the alias the boot-lint rejects), forces
  `cloud_rest`, and the `HSETNX`-backed apply can only *add* a new opaque alias — never repoint an
  existing one, never reach a privileged transport.
- **Community-authored skills inherit the same guarantees plus a manifest hash-pin** re-verified on
  every boot-load (rug-pull defense — see `docs/integrate/EXTENSIBILITY.md`). This is MCPIP defending its
  *own* extension supply chain, the T13 answer to the `postmark-mcp` class for skills you host.

### 5. Honest scope

**MCPIP does not detect the prompt-injection itself.** For an `AUTO`-classified *read*, MCPIP
authorizes and audits the call but does not content-inspect the request or the downstream response —
if the agent is entitled to the read, it reads. This pattern does **not** turn MCPIP into a
magic injection detector.

What it *does* is **govern the side-effecting call**: it authorizes it (entitlement + compartment +
payload-bound step-up), for `cloud_iam` it *vends* a short-lived least-privilege credential instead
of a standing key, and it *audits* every decision write-before-execute — it never proxies or
content-inspects the downstream call. The blast radius of a governed egress is the payload-bound
recipient set plus, for `cloud_iam`, the vended role's least-privilege policy and clamped TTL.

This is a **deployment posture**, not a detector. The differentiated claim is narrow and true: had
the sensitive tool been a governed MCPIP alias, `postmark-mcp`'s covert BCC would have been
payload-mismatch-denied or forensically undeniable, and a `PIN_REQUIRED` send could not have fired
without out-of-band human approval — regardless of the upstream injection.

### 6. Proof

- `tests/test_governed_alias_pattern.py` — drives the REAL sandbox gateway (TestClient, Redis, zero
  mock): staging binds the recipient set and records write-before-execute; a covert extra recipient
  is `PAYLOAD_MISMATCH`-denied; the PIN-gated egress completes only with the out-of-band OTP and is
  exactly-once; and the operator runtime-registration route (`POST /v1/admin/skills/register`)
  enforces the identical guarantees. Every deny is asserted opaque.
- `scripts/dynamodb_vend.py` + [Cloud IAM Live-Fire (DynamoDB)](#cloud-iam-live-fire-dynamodb) — Route B end to end
  (entitlement → step-up → vend → audit).

---

## Cloud IAM Live-Fire (DynamoDB)

*DynamoDB write, live-fire — vend a real credential through MCPIP.*

Prove the `cloud_iam` **write** path end to end: an agent asks to write to DynamoDB, the
MCPIP gateway authorizes and audits the call, and — only then — mints a **short-lived,
least-privilege** AWS credential scoped to exactly that one write. The agent never holds
a standing cloud key; stop the skill or revoke the principal and the next vend is denied.

This is the `skill_aws_dynamodb` skill (mcpip-inc / team-engineering). It is a
mutation, so it is **`PIN_REQUIRED`**: the agent must complete a payload-bound step-up
before anything is vended.

### Two halves, two scripts

The full production path is *authorize → audit → vend → use*. On a laptop it is cleanest
to prove it in two runnable pieces:

| Half | Script | Needs AWS? | Proves |
|------|--------|-----------|--------|
| authorize + step-up + **audit** | `scripts/dynamodb_vend.py` | **No** | entitlement deny, payload-bound PIN, WORM-before-vend, a vend scoped to the write role (sandbox = fake credential, real *flow*) |
| **vend** (real STS) + least-privilege | `scripts/dynamodb_live_fire.py` | **Yes (your account)** | MCPIP's real broker assumes the role via STS and vends a credential that can write one row to one table — and nothing else |

`dynamodb_live_fire.py run` can also drive the gateway ceremony first (via `--gateway`),
so a single command reproduces the whole path: the gateway authorizes and WORM-logs the
ALLOW, *then* the broker vends for real.

### What MCPIP does — and does not — do

Read this before you draw conclusions from the run:

- **MCPIP authorizes, audits, and vends.** Identity + compartment + payload-bound PIN
  gate the call; a signed WORM record is written **before** any credential exists; the
  vended credential is per-call, short-lived, and scope-reduced. It is killable.
- **MCPIP does not proxy or inspect the DynamoDB request.** It is an authorization
  gateway, not a data-plane content filter. It does **not** read the item you `PutItem`
  and it will **not** block a payload because of what is inside it. If you need to keep
  PII out of a table, that is a **data-layer** control (schema validation, a resource
  policy, a VPC endpoint policy, application code) — not something to expect from this
  gateway. The control MCPIP gives you is the credential's **least-privilege boundary**:
  the agent simply cannot reach anything the role does not allow. The live-fire run
  proves that boundary directly.

### Prerequisites

- A **non-production** AWS account. Use throwaway/rotated credentials — rotate any key
  you have ever pasted into a chat or terminal history.
- `python3`, `boto3` (`pip install boto3`), and this repo checked out (the live-fire
  script imports MCPIP's real `CloudBroker`, so the vend is the actual gateway code).
- Your default AWS credential chain populated (env vars, a named profile, or SSO). The
  broker assumes the role using *your* identity — this stands in for the gateway's own
  host workload identity (instance profile / IRSA / OIDC) in production.

### Run it

From the repo root, with your credentials exported:

```bash
# 0) (optional) a sandbox gateway, so `run` can drive the real authorize+audit half
./scripts/quickstart.sh

# 1) provision: one on-demand table + a role whose ONLY permission is
#    dynamodb:PutItem on that one table
python scripts/dynamodb_live_fire.py provision --region us-east-1

# 2) run: authorize through the gateway → vend via real STS → prove the boundary
python scripts/dynamodb_live_fire.py run --region us-east-1

# 3) teardown: delete exactly what provision created
python scripts/dynamodb_live_fire.py teardown --region us-east-1
```

Flags (all optional): `--table mcpip-live-fire`, `--role mcpip-eng-dynamodb-write`,
`--gateway http://localhost:8080`, `--no-gateway` (skip the ceremony half and vend
directly — less faithful; in production the gateway *always* authorizes first).

#### What `run` asserts

1. **Authorize + audit** (when `--gateway` is reachable): mint a team-engineering
   identity → the gateway stages a payload-bound step-up → complete it → **ALLOW**,
   committed to the WORM ledger **before** any credential is vended. If the gateway does
   not ALLOW, the script **refuses to vend** (fail closed).
2. **Real vend**: MCPIP's `CloudBroker(sandbox_mode=False)` performs a real
   `sts:AssumeRole` against your role and returns a short-lived credential. The
   operator-visible **fingerprint** names the role and TTL; the secret material is
   redacted from it (and never enters WORM).
3. **The boundary** — with the vended credential:
   - `PutItem` to the one table → **ALLOWED** (the authorized write succeeds).
   - `GetItem` on the *same* table → **AccessDenied** (only `PutItem` was granted — the
     agent can write but cannot read back or exfiltrate).
   - `s3:ListBuckets` → **AccessDenied** (no blast radius beyond the role).

A non-zero exit means a boundary check did not hold — inspect the role policy the run
prints.

### The role (least-privilege, verbatim)

`provision` attaches exactly this inline policy — one action, one resource:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "PutItemOneTableOnly",
    "Effect": "Allow",
    "Action": "dynamodb:PutItem",
    "Resource": "arn:aws:dynamodb:<region>:<account>:table/mcpip-live-fire"
  }]
}
```

The trust policy allows the account to assume the role (so the gateway's host identity
can), and `MaxSessionDuration` caps the session at one hour; MCPIP clamps every vend to
the environment's `session_ttl` (900s here) on top of that.

### Production wiring (no laptop, no shared secret)

In a real deployment nothing above changes shape — only *who* holds the identity:

- The gateway runs with its own **host workload identity** (instance profile, IRSA, or
  OIDC federation). No AWS key is ever stored; `CloudBroker._vend_real` uses the default
  credential chain, exactly as the script does with your creds.
- An operator registers the binding once via
  `PUT /v1/admin/cloud/environments` (`CAP_DIRECTORY_ADMIN`): `env_id`,
  `provider: aws`, the real role ARN, region, compartment, `session_ttl`. Bindings hold
  **no** secret.
- The role's trust policy trusts the gateway's host identity (not account-root), and its
  permission policy is scoped to the real table(s) the skill may write.

The sandbox seeds a placeholder binding (`aws-eng-dynamodb-write`, account
`000000000000`) so `skill_aws_dynamodb` is selectable and the *flow* is demonstrable
out of the box; the placeholder can never vend a real credential (sandbox returns a
clearly-marked fake).
