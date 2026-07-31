# Session identity & attenuated delegation — design proposal

> **Status: PHASES 1–3 SHIPPED.** Attribution (§1,
> ``tests/test_session_attribution.py``), delegation grants + authorize-path
> intersection + cascading revocation (§2–§4, ``services/delegation.py``,
> ``tests/test_delegation.py``), and the console surfaces (§5: the session
> facet, stream-inspector fields, and the Delegation lineage panel). Delegation
> ships behind ``MCPIP_DELEGATION_ENABLED`` (default **off**): when off,
> ``/v1/delegate`` does not exist (404) and a token carrying ``delegation_id``
> denies ``DELEGATION_INVALID`` — ignoring the claim would grant MORE than the
> token was minted for.

## The gap

The WORM chain answers *"what did this agent do"*. It cannot answer *"which
session of this agent did it, and who started that session"* — because nothing
in the verified identity distinguishes sessions:

* A production `Identity` carries `tenant_id`, `agent_id`, `role`, and the
  optional compartment/capability claims. No session identity exists anywhere
  in the chain.
* The CLI writes its token to `~/.mcpip/tokens/<context>.jwt`. Every process
  on the machine that reads that file **is** that principal. Run one agent
  under an orchestrator that spawns three worker sessions and the chain
  records four actors as one `agent_id`, indistinguishably.

Agent-orchestration stacks make this the common case, not the corner case:
sessions spawn sessions, hand work to successors, and steer each other by
injecting instructions. MCPIP's choke point already bounds what any of those
sessions can *do* — an injected instruction cannot exceed the token's
capability set, and that guarantee is unaffected by anything here. What is
missing is **attribution** (which session acted) and **governed hand-off**
(a spawned session should be able to hold *less* than its spawner, never the
same-by-default).

## Goals

1. Every decision in the WORM chain attributable to a **session**, not only a
   principal, when the deployment opts in.
2. A session can delegate to a child session with **attenuated** authority —
   capabilities strictly a subset, compartment the same or narrower, lifetime
   the same or shorter — and the delegation itself is a sealed, auditable act.
3. Revoking a session kills its whole delegation subtree, with the same
   fail-closed, key-presence enforcement the principal kill-switch uses today.

## Non-goals

* Governing the *prompt* layer. What a session is told is out of scope; MCPIP
  governs what it may do. No change.
* Minting identity in production. Identity sovereignty stands: the gateway
  never issues tokens outside the sandbox forge. Delegation is **gateway-side
  state that narrows** an IdP-issued identity — the same shape as the deny-only
  policy overlay and the additive-only catalog overlay, never a new issuer.
* A new token format. Offline cryptographic attenuation (Macaroons-style
  caveats) is a possible future direction, noted at the end; this proposal
  requires nothing beyond one optional JWT claim.

## Design

### 1. The `session_id` claim (opt-in, verified)

A token MAY carry `session_id: <uuid>`. It is read only from the **verified**
JWT payload — never from a header, query parameter, or request body, which
would let any caller impersonate a session. Present → stamped into `Identity`,
every decision record, and the tenant-scoped decisions projection (whitelist
gains `session_id`, `delegation_id`). Absent → `null` throughout; behaviour is
byte-for-byte today's. In production the claim comes from the customer IdP; an
IdP that cannot add claims simply cannot use delegation — an honest constraint,
not a fallback to unverified transport.

Sandbox: the dev-token forge accepts optional `session_id`, and the CLI mints
one automatically per login context, which also fixes the shared-token-file
collapse for walkthrough users.

### 2. `POST /v1/delegate` — register an attenuated grant

The parent session (authenticated, carrying `session_id`) registers a grant:

```json
{
  "child_agent_id": "agent-worker-3",
  "child_session_id": "<uuid the child's token will carry>",
  "capabilities": ["<uuid>", "..."],
  "compartment": "<uuid or null>",
  "expires_in_s": 3600
}
```

*Normative — the attenuation rules, enforced at registration:*

* `capabilities` ⊆ the parent's **effective** capability set (JWT ∩ any grant
  already narrowing the parent). Requesting one the parent lacks → the whole
  registration is refused. Never silently intersected — silent narrowing hides
  operator mistakes.
* `compartment` must be **None or exactly the delegating session's own
  compartment** — never an arbitrary one. An un-compartmented (tenant-wide)
  parent is itself entitled to *no* specific compartment under the compartment
  gate, so it can hand down only `None`; it can never conjure compartment access
  it lacks. (Deliberately conservative: a parent holding a compartment only via
  a ReBAC grant, not its JWT claim, also cannot delegate it — fail-safe.)
  `tenant_id` is fixed to the parent's, not a parameter.
* Effective expiry = `min(parent token exp, parent grant expiry, requested)`.
* Chain depth ≤ 4. A child registering its own grant is checked against its
  *effective* (already-narrowed) set, so authority can only shrink down a
  chain. Cycles cannot form: a grant references its parent grant's id, which
  must already exist.
* The grant is sealed to the WORM chain (`delegation_granted`, carrying
  parent/child session ids, the capability set, expiry) **before** it becomes
  readable by the authorize path — write-before-execute applies to the grant
  exactly as it does to a decision.

### 3. Authorize-path semantics

*Normative:*

* Token carries `delegation_id` claim + live matching grant → effective
  capabilities = JWT capabilities ∩ grant capabilities. Effective compartment is
  the **narrower of the child's own JWT compartment and the grant** — never
  wider than either: a grant conveys compartment X only when *both* the grant and
  the child's verified JWT already carry X; any disagreement collapses to `None`
  (no compartmented access). Delegation subtracts, never adds. Intersection only
  — a grant can never widen.
* Token carries `delegation_id` but the grant is missing, expired, or revoked
  → **deny, fail closed**, deny reason `delegation_invalid`, opaque to the
  agent as all denies are.
* Token carries neither claim → today's path, untouched. Opt-in means the
  feature's absence is exactly the current gateway.
* Cost: grant liveness is key-presence, O(depth ≤ 4) reads on the hot path,
  same enforcement shape as the revocation kill-switch. No JSON parsing on
  the deny path.

### 4. Revocation cascades

`RevocationStore` today blocks `(tenant_id, agent_id)`. Delegation adds
revocation by `(tenant_id, session_id)`: throwing it kills that session's
grant and, because every descendant's chain check walks through it, the whole
subtree dies with one key — no subtree enumeration needed at revoke time.
Sealed as `delegation_revoked`. `CAP_DIRECTORY_ADMIN`-gated like the existing
kill-switch; additionally the **parent session itself** may revoke its own
descendants (a dispatcher cleaning up its workers is routine operation, not an
admin event).

**The principal kill-switch also cascades.** Revoking (or quarantining) a
principal `(tenant_id, agent_id)` must sever every delegated descendant, or a
compromised admin escapes containment through a pre-positioned escape token — a
child minted on a *fresh* `agent_id` before the revocation, holding delegated
authority. Each grant therefore denormalizes its ancestor **agent** ids
alongside its ancestor session ids, and `_apply_delegation` probes the principal
revocation/quarantine store for every ancestor agent (O(depth ≤ 4), fail-closed).
A delegated token whose ancestor principal is revoked is denied
`delegation_invalid` everywhere an identity is resolved.

### 5. Console

The principal directory renders sessions under their agent, children nested
under `spawned_by`, each node showing its effective capability count and grant
expiry. The decisions views gain a session facet. (Console work ships after
the gateway surface; listed for completeness.)

## What this deliberately does not fix

An orchestrator that copies the *parent's own token file* to a worker instead
of delegating still collapses attribution — indistinguishable by construction,
since the JWT is bearer. Delegation makes the governed path *cheaper* than the
copy (one POST, and the child shows up in the console tree); it cannot make
the ungoverned path impossible. The threat-model addition should say exactly
that.

## Rollout

1. **SHIPPED** — `session_id` claim end-to-end (identity → WORM → projection →
   CLI/sandbox forge). Pure attribution; no behaviour change.
2. **SHIPPED** — grant store + `/v1/delegate` + authorize-path intersection +
   revocation cascade, behind `MCPIP_DELEGATION_ENABLED` (default off).
3. **SHIPPED** — console: Delegation lineage panel (Principals → Hierarchy),
   session facet + CSV columns in History, session/grant rows in the stream
   inspector.

## Resolved questions

* One deny reason (`delegation_invalid`), with the concrete cause (expired /
  revoked / mis-bound / disabled) riding ONLY in the WORM `detail` string —
  matching how `policy_denied` keeps its causes out of metric labels.
  Agent-facing stays opaque either way.
* Grant GC: Redis TTL at effective expiry. The WORM chain holds the forensic
  record (`delegation_granted` / `delegation_revoked` are sealed events); live
  state needs no tombstones.

## Open questions
* Does the compliance evidence bundle need a delegation section (grants active
  at attestation time)?

## Prior art

* **OAuth 2.0 Token Exchange (RFC 8693)** — delegation/impersonation
  semantics, `may_act`/actor claims; ours differs in never issuing the token.
* **Macaroons / Biscuit tokens** — offline attenuation via caveats; the
  future direction if gateway-side grant state ever becomes the bottleneck,
  at the cost of a token format nobody's IdP speaks natively today.
