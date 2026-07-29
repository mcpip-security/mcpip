# MCPIP Architecture & Design Reference

This is the canonical architecture and design reference for MCPIP. It
co-locates three **distinct** subsystem design documents so they can be read
together under one roof: the **A2A Side-Effect Choke Point** (a 7th provider
dialect that gates the one side-effecting leg of an agent-to-agent workflow),
the **Data-Plane Fork** (the deferred, owner-owned decision on whether MCPIP
ever crosses from post-reasoning tool-call interception into the model's
content/generation path), and **WORM Group-Commit** (the measured audit-log
throughput ceiling and the app-managed WAL design that would raise it). These
are not redundant — they are separate concerns, each preserved here in full:
exact invariants, envelopes, diagrams, tables, benchmarks, and pseudocode are
unchanged from their originating design memos. Sibling references: operational
and deployment concerns live in [docs/OPERATIONS.md](OPERATIONS.md), connector
and dialect extension in [docs/EXTENSIBILITY.md](EXTENSIBILITY.md), and
future-wave sequencing in the internal roadmap.

---

## A2A Side-Effect Choke Point

*Gating the side-effecting leg of an agent-to-agent workflow.*

MCPIP now accepts a **7th `SOURCE_FORMAT`, `a2a_task`**: a pure parser that
normalizes a representative **A2A (Agent-to-Agent) Task envelope** carrying one
side-effecting skill invocation into the same `NormalizedIntent` the other six
dialects produce. It then flows through the identical Obfuscator → Auth → Audit
pipeline and the **unchanged payload lock**. This section states the
choke-point position and — importantly — its **honest scope**.

### Why A2A, and why only the side-effecting leg

A2A won agent interoperability but, structurally, **cannot express
authorization** (LANDSCAPE_2026H2 §2.6). A swarm of A2A agents negotiates tasks
over a message bus that has no notion of *"is this identity allowed to perform
this side effect, on this payload, right now?"*. The Unit 42 "agent session
smuggling" work (LANDSCAPE_2026H2 §5.6) shows the danger: a multi-agent
conversation can be steered so that a **side-effecting tool call** — the write,
the transfer, the egress — is emitted with attacker-chosen arguments.

MCPIP's answer is deliberately narrow and honest:

- **MCPIP is not on the A2A message bus and does not dial A2A.** It does not
  observe the inter-agent conversation, does not proxy A2A traffic, and holds no
  A2A client. It is an **authorization interceptor, not an LLM/A2A proxy**.
- **MCPIP gates the one leg that matters: a single governed identity's
  side-effecting alias call.** When an A2A agent is about to perform a
  side effect it has registered as an MCPIP alias, that call is expressed as an
  `a2a_task` envelope and authorized through the full pipeline — opaque alias
  resolution, JWT-only identity, payload-bound one-time PIN for `PIN_REQUIRED`
  egress, and a signed WORM record written **before** execution.

So a `PIN_REQUIRED` A2A egress **still cannot fire without the out-of-band OTP**,
and a covert extra argument still produces a different payload-lock hash →
`PAYLOAD_MISMATCH`. That is the concrete security value this connector delivers.

### The representative envelope (pinned, strict)

Grounded in the A2A v1.0.1 data model (Task / Message / Part, where a `DataPart`
carries structured JSON), MCPIP pins **one** strict envelope shape — a top-level
`Task` whose message carries **exactly one `DataPart`** skill invocation:

```json
{
  "kind": "task",
  "id": "task-abc",
  "contextId": "ctx-1",
  "status": {"state": "submitted"},
  "message": {
    "kind": "message",
    "role": "agent",
    "messageId": "msg-1",
    "parts": [
      {"kind": "data", "data": {"skill": "skill_email_send", "arguments": {"to": ["ap@corp.com"]}}}
    ],
    "metadata": {"actor": "urn:a2a:orchestrator-7"}
  }
}
```

- `data.skill` → the opaque MCPIP **alias**.
- `data.arguments` → the tool-call **arguments** (absent → `{}`, like MCP/Gemini).
- **One invocation per request.** More than one part, a non-data part, a wrong
  `kind`, or **any** extra key at any level fails the strict `extra="forbid"`
  ingress model → `SCHEMA_VIOLATION`. This mirrors Gemini's bare-single-part and
  the JSON-RPC one-call discipline. The `MAX_A2A_PARTS` bound lives in
  `interfaces.py` (hard limits in one place).

Every A2A ingress model is Pydantic v2 `extra="forbid", strict=True`, exactly
like the other six dialects' models.

### Identity is JWT-only; the envelope's actor is *recorded-not-trusted*

The envelope carries a `message.metadata` channel and task/context/message IDs.
These are **declared and UNVERIFIED** — an A2A message can claim any actor or
delegation. MCPIP therefore:

- Extracts them into a **separate, non-locked `a2a_context` channel** — the same
  posture X3 uses for registry `server.json` `_meta` provenance:
  **recorded-not-trusted**. It is surfaced to the **WORM audit ctx only** (the
  task/context/message IDs + the declared actor), as topology-free correlation
  provenance that lands on ALLOW and every DENY leaf, just like `jti` /
  `delegation_chain`.
- **Never merges it into `arguments`**, so it can enter neither the payload lock
  (which hashes only `{tenant, agent, alias, arguments}`) nor the agent wire (the
  authorize response, `/v1/catalog`, and MCP `tools/list` build explicit
  whitelists and never serialize the audit ctx).
- The metadata envelope is size-bounded (`MAX_A2A_META_BYTES`) so an untrusted
  A2A document cannot smuggle unbounded provenance into the audit log.

**Authorization identity comes only from the verified JWT.** The `role` claim
authorizes nothing; the envelope's declared actor authorizes nothing. If an
A2A envelope tries to smuggle an identity-shaped key **inside `data.arguments`**
(`tenant`/`agent`/`role`/`actor`/`principal`/`sub`/`capabilities`/…), the
unchanged `enforce_argument_safety` `_FORBIDDEN_IDENTITY_KEYS` hard-deny catches
it at every nesting level → `IDENTITY_INJECTION`. This defense is **reinforced,
not widened** — no new key was added to the set.

### What is explicitly OUT of scope

- **Ungoverned swarm agents stay ungoverned.** MCPIP governs the
  side-effecting alias call of a governed identity — not the surrounding A2A
  conversation. An agent that never routes its side effect through an MCPIP alias
  is not observed.
- **MCPIP does not detect A2A session smuggling** (LANDSCAPE_2026H2 §5.6) as a
  behavioral phenomenon. It has no view of the inter-agent dialogue and runs no
  in-agent probabilistic detector ("the fox can't guard the henhouse",
  SECURITY_THREAT_MODEL §17 — ASI07 A2A is out-of-scope-by-design). What it
  guarantees is narrower and stronger: the moment a smuggled intent becomes a
  **governed side-effecting call**, it is subject to opaque aliasing, JWT-only
  identity, the payload-bound PIN (a `PIN_REQUIRED` egress cannot fire without
  the out-of-band OTP — the line-jump circuit breaker), and a write-before-execute
  signed audit record.
- **No message-bus mediation, no A2A proxying, no content/prompt-path fork.**
  This wave is a pure normalizer + choke-point positioning. It adds no
  per-identity anomaly detector and does not enter the model's content path
  (that data-plane decision stays the owner's call — see the
  [Data-Plane Fork](#data-plane-fork) section).

### Invariants preserved

- **Payload lock / canonicalization / Rust mirror: untouched.** `a2a_task` is a
  new *parser*; `canonical_json`, `enforce_argument_safety`, the scrypt PIN-hash,
  and `rust/mcpip_fastwalk` get no edit. The same `(alias, arguments)` yields a
  **byte-identical lock hash** whether expressed as A2A, MCP, OpenAI, etc.
  (proven by extending the cross-format parity proof to six shapes, and by an
  e2e test that completes an A2A staging with an OpenAI re-issue).
- **Connector purity:** the A2A parser imports only
  `interfaces`/`bridge.errors`/`bridge.connectors.base`/`json`/`typing`/`pydantic`
  — no LLM SDK, HTTP client, socket, or env credentials, mechanically enforced by
  the AST purity scan.
- **Deliberate registry re-pin:** adding `Vendor.A2A` + the `a2a` binding bumped
  `REGISTRY_VERSION` 2 → 3 and recomputed `REGISTRY_SHA256`; the hash pin was
  neither hand-faked nor weakened (the conscious re-pin is the whole point of the
  connector wave).
- **Fail-closed + opaque:** every malformed / oversized / identity-smuggling A2A
  envelope denies with only `MCPIPDenied` + a `correlation_id`; the concrete
  reason lives solely in the WORM log.

---

## Data-Plane Fork

*Does MCPIP ever enter the prompt path?*

*Last updated: 2026-07-17 (2026-H2 reaffirmation, the internal roadmap **F2** — see §7). A decision memo for the single most consequential product decision MCPIP
faces — whether to cross from post-reasoning tool-call **interception** into the model's **content /
generation path** to build the two data-plane pillars (the internal roadmap Pillars 1–2: **oracle
inversion** and **cryptographic taint-tracking**). This is a **DESIGN DOCUMENT ONLY**: it writes no
data-plane code, reserves no pointer token, and changes no behavior. It exists so the call is made
**deliberately, by the owner** — the roadmap's explicit instruction: "decide it deliberately, don't
drift into it" (the internal roadmap). Companions: `WHITEPAPER.md §2.2`
(the "interceptor, not an LLM proxy" trust boundary), the internal strategy notes (primitive #7),
the internal roadmap (the pillar sketches), `docs/OPERATIONS.md` (sibling
FUTURE-wave design material).*

---

### TL;DR

- **Recommendation: DO NOT enter the prompt path now. Hold the "interceptor, not a proxy" line.** It is
  the correct call for today's stage, positioning, and (solo-founder) resourcing, and it is the honest
  reading of the whitepaper's own threat model. Keep this a *deferred, owner-made, prospect-pulled*
  decision, not a drift.
- **The fork has two depths, and conflating them is the most common error.** (A) **Content mediation** —
  MCPIP sits on the data flowing *into* the model's context (vault tool results, hand the model opaque
  pointers, de-reference only at dispatch). This does **not** require MCPIP to call a model or hold vendor
  keys, but it *does* insert MCPIP into context assembly. (B) **Generation proxy** — MCPIP actually calls
  the model and holds vendor keys. These are different bets with different blast radii. **(B) is a
  do-not-build** (it *is* the "LLM proxy" the whitepaper disavows). (A) is the only version worth ever
  reconsidering, and only on the transports where MCPIP already dispatches inline.
- **Crossing the line deletes a named product primitive.** The internal strategy notes primitive #7 —
  "self-hosted, **inference-free** data-plane; the gateway never calls a model, holds no vendor keys" — and
  the "the fox can't guard the henhouse; the authorizer must be independent of the thing it authorizes"
  battlecard are *positioning assets*, not incidental facts. The fork spends them.
- **What it would unlock is genuinely category-defining** — a deterministic data air-gap ("the model acts
  on your secrets without ever seeing them") and deterministic information-flow control ("untrusted web
  content can never reach a privileged sink"). Nobody ships either. That is exactly why the decision is
  hard and must not be made by accident.
- **What ships now: this memo. What stays unbuilt: everything else** — no `dataplane/` stage, no vault
  write, no `{{PTR_}}` reservation, no taint labels. The parity-sensitive pointer-token reservation is
  *its own future wave* under the byte-identity invariant (the internal roadmap), and even that is not this
  wave.

---

### 1. Where the line is today, precisely

MCPIP is defined — in code, in the whitepaper, and on the battlecard — by **where it sits**:

> "MCPIP is an authorization interceptor, **not an LLM proxy**. The client calls its LLM directly on its
> own keys/billing; the gateway receives only the resulting tool-call payload, so it holds no vendor
> credentials and makes no LLM calls." — `WHITEPAPER.md §2.2`

Concretely, four facts define the current boundary:

1. **MCPIP sees only the *post-reasoning* artifact.** It receives the tool call the model *already
   produced* — an alias plus arguments — never the prompt, the system message, the retrieved documents,
   the tool *results* fed back into context, or any raw generation token. The reasoning surface is
   explicitly *untrusted* and explicitly *out of MCPIP's hands* (`WHITEPAPER.md §2.1` A1–A2).
2. **Format is declared, never sniffed.** The caller states `source_format` / `vendor`; MCPIP never
   infers a parser from payload bytes, because content-sniffing would let the adversary steer which parser
   reads its bytes — "the same class of hazard as an unpinned JWT `alg`" (`WHITEPAPER.md §2.2`). This is
   only defensible *because* MCPIP is not in the content path.
3. **Parsers are pure; the gateway holds no vendor keys.** Connector purity is mechanically enforced (no
   LLM SDK, no HTTP client, no socket — `tests/test_connector_conformance.py`); the gateway makes no model
   call and stores no vendor credential. For `cloud_iam` it does not even hold the *target* payload — it
   vends a short-lived credential and the agent makes the call (`docs/OPERATIONS.md`).
4. **The hot path is a single-round-trip, sub-ms, fail-closed decision.** Strict schema → alias resolve →
   entitlement gates → payload lock (one atomic Lua) → write-before-execute WORM → dispatch. MCPIP judges
   *whether the exact action may run*, never *what the model should read or say*.

**"Entering the prompt path" means breaking fact #1** — inserting MCPIP into the flow of content *to and
from* the model, so it can vault-and-swap what the model reads (Pillar 1) or enforce taint at the moment
content is interpolated (Pillar 2). The internal roadmap states the dependency plainly: "you cannot
vault-and-pointer-swap what the model reads (P1) [or] enforce taint at interpolation time (P2) … unless
you mediate content flowing to and from the model."

---

### 2. The two pillars, concretely

#### 2.1 Pillar 1 — Oracle inversion (data air-gap, late binding)

**What it is.** Today's obfuscator late-binds the *target* (the agent picks `skill_payroll_run`, never
learns `mainframe.cics.PAYR`). Oracle inversion generalizes that inversion from the *target* to the
*data*: the model operates over **opaque pointers**, and the real bytes are late-bound only at execution,
*after* the authorization decision is committed.

**What it would concretely require** (sketch from the internal roadmap, not a build order):

- A `dataplane/` stage at the point where tool results / untrusted content re-enter the agent loop.
- **Vault write:** `SETEX vault:{tenant}:{sha256_16} <raw bytes>` (short TTL); the raw string handed to
  the model's context is replaced with a token `{{PTR_<sha256_16>}}`. The model reasons over the
  pointer; it never sees the secret/PHI/PII bytes.
- **Pointer as an atomic type** in `enforce_argument_safety` — recognized in **Python *and* the Rust
  mirror in lockstep**, under the byte-identity parity invariant.
- **De-referencing compiler:** one pipelined `MGET` in `_dispatch`, **after** the WORM ALLOW is emitted,
  so the decision is provably made over pointers and only the executing transport ever sees plaintext.
- **The load-bearing invariant:** `lock_payload_hash` must hash the **pointer form**, never the
  interpolated form, "or the TOCTOU lock re-opens" (the internal roadmap). This single sentence is the
  reason the pointer-token reservation is *its own parity-sensitive wave* and not a casual add.

**What it unlocks.** A deterministic **data air-gap**: an agent can act on data it structurally cannot
read. Exfiltration-via-prompt-injection is defeated not probabilistically but by construction — there is
nothing in context to exfiltrate, because the model only ever held a pointer. The marketing claim is
category-defining and, unusually, *true*: "the model never sees your secrets, even while acting on them."

#### 2.2 Pillar 2 — Cryptographic IFC (taint tracking)

**What it is.** Information-flow control: every vaulted datum carries a provenance label, and the gateway
refuses to let low-trust data flow into a high-trust sink.

**What it would concretely require** (sketch from the internal roadmap, *builds on 2.1*):

- Per vault entry, store `{"bytes": …, "taint": UNTRUSTED_USER | EXTERNAL_WEB | INTERNAL_DB | SYSTEM}`.
- Per-field **taint ceilings** declared on `AliasEntry` (`field_policies: dict[str, frozenset[Taint]]`,
  alongside the existing `classification`).
- Enforcement at the single interpolation choke point: if a field's allowed set does **not** contain the
  pointer's taint → a new `DenyReason.TAINT_VIOLATION`, concrete reason to WORM, opaque `MCPIPDenied` out.
  O(fields) hash lookups; the sketch claims no measurable hot-path cost *once the vault exists*.

**What it unlocks.** Deterministic defense of the #1 agentic attack class — untrusted content (a web page,
a user message, a poisoned tool result) reaching a privileged sink (a shell argument, a recipient
account, a SQL string). The entire guardrail industry attempts this *probabilistically, in-model*;
cryptographic IFC does it *deterministically, at the gate*. It is the strongest possible expression of
"AI Reasons, MCPIP Authorizes."

#### 2.3 The two depths of the fork (the distinction that governs the decision)

Both pillars require *content mediation* (fact #1 broken). Neither *strictly* requires the deeper
crossing. Keep these separate:

| Depth | What MCPIP touches | Vendor keys? | Calls a model? | Latency added | Positioning cost |
|---|---|---|---|---|---|
| **Today** | The final tool-call payload only | No | No | none (sub-ms authz) | — (this *is* the positioning) |
| **(A) Content mediation** | Tool results / context in & out; vault + pointer-swap + taint | **No** (client still calls its own model) | **No** | vault write on ingest + `MGET` at dispatch | High — breaks "interceptor, not a proxy"; **keeps** "no vendor keys / no model call" |
| **(B) Generation proxy** | The full prompt/generation stream; MCPIP calls the model | **Yes** | **Yes** | model-generation latency on the critical path | Total — **is** the "LLM proxy" the whitepaper disavows; deletes primitive #7 outright |

The single most important analytical point in this memo: **(A) and (B) are not the same bet.** (A) can
deliver *both* pillars while MCPIP still holds no vendor keys and still makes no model call — the client's
own model is still called by the client; MCPIP only intercepts the *content* on its way in and out. (B) —
proxying inference — is a different company, a different liability posture, and a different latency
budget, and it delivers **no additional authorization guarantee** that (A) does not. **(B) is a
do-not-build.** If the fork is ever taken, it is (A), and only (A).

---

### 3. Why crossing contradicts today's positioning — and the four consequences

The "interceptor, not a proxy / never calls a model / holds no vendor keys" stance is not a modest
implementation detail. It is load-bearing in three places at once: the whitepaper's **formal threat
model** (§2.2 scopes the reasoning surface as untrusted and out of scope), the competitive **battlecard**
(primitive #7 + "the fox can't guard the henhouse"), and the **latency/ops story** (a sub-ms, stateless,
fail-closed gate). Crossing the line taxes all three. Four consequences, in order of how hard they bite:

**3.1 Trust — MCPIP becomes a data custodian.** Today MCPIP holds no vendor keys and, for `cloud_iam`,
not even the target payload. Content mediation makes MCPIP transiently hold *the raw untrusted and
sensitive bytes it is protecting* — in the vault, even if short-TTL and encrypted. The product whose pitch
is "the agent never sees the real target" would now itself be the place the real data lives. That is a
*larger* breach target and a *new* class of "what if the vault leaks" question, and it must be answered
under the same fail-closed, tamper-evident discipline as the rest of the system (encryption at rest,
tenant-bound AAD, short TTL — the `ForensicCaptureStore` model is the nearest existing precedent, and note
that even *it* is a redacted, secrets-scrubbed side-channel, precisely because holding plaintext is
treated as hazardous).

**3.2 Latency — the sub-ms authorizer story is at risk.** Depth (A) adds a vault write on every tool-result
ingestion and an `MGET` de-reference at dispatch — bounded, but it puts MCPIP inline on *context
assembly*, not just the final decision, so it is now touched many times per agent turn instead of once per
tool call. Depth (B) is worse by orders of magnitude: model-generation latency (seconds) lands on the
critical path and MCPIP is on the path of every token. The "deterministic sub-ms L7 authorizer" that the
competitive analysis leads with survives (A) only with care and does **not** survive (B).

**3.3 Liability — MCPIP starts to own the reasoning it deliberately disclaims.** The philosophy is
narrow on purpose: "MCPIP does not judge whether an action is wise — that is the province of policy and of
the guardrails above it" (`WHITEPAPER.md §10`). The moment MCPIP mediates what the model reads (A) or
generates (B), it becomes *partly responsible* for prompt-injection outcomes as a **product promise**
rather than a bounded gate — it inherits the failure modes of the content layer. Taint-tracking in
particular is a promise ("untrusted data cannot reach this sink") that is only as good as the labeling of
*every* ingress, and a single unlabeled source is a silent IFC hole. That is a much heavier promise to
stand behind than "the executed bytes equal the approved bytes."

**3.4 Attack surface — from a narrow typed API to arbitrary untrusted content.** Today's ingress is a
narrow, strict-Pydantic, declared-format, unicode-scrubbed, size/depth-bounded surface. Content mediation
means handling *arbitrary tool-result and retrieved-document content* — a vastly larger, fuzzier surface.
The de-referencing compiler is a new TOCTOU-sensitive component (get the pointer-vs-interpolated hashing
wrong and the payload lock re-opens — §2.1). The taint choke point is a new single point that either
over-blocks (breaks legitimate flows, erodes trust) or under-blocks (silent bypass). And the format-sniff
hazard the whitepaper deliberately avoids (§2.2) re-emerges the instant MCPIP parses content it did not
receive in a declared frame.

**Net:** the fork spends the three assets that currently *are* the product — the inference-free posture,
the sub-ms narrow gate, and the "independent of the thing it authorizes" independence — to buy two
genuinely novel capabilities. That trade can be worth making. It is not worth making by accident, and it
is not worth making before a buyer has pulled it.

---

### 4. What it would take (architecture, new trust boundaries, new failure modes)

If depth (A) is ever taken, the honest cost is:

**Architecture.** A new `dataplane/` stage; a vault store (encryption at rest, tenant-bound AAD, short
TTL); the pointer-token type threaded through `enforce_argument_safety` in **Python and Rust in
lockstep**; a de-referencing compiler in `_dispatch` strictly *after* the WORM ALLOW; and (Pillar 2)
per-field taint ceilings on `AliasEntry` plus enforcement at one interpolation choke point.

**New trust boundaries.**
- The **context-ingestion boundary** — MCPIP now trusts that *all* content reaching the model passes
  through it (else the pointer-swap and taint labels are incomplete). This is a *deployment* trust
  assumption analogous to the non-bypassability gap in `docs/OPERATIONS.md`: if the agent can fetch
  content around MCPIP, the air-gap has a hole. Enforcing it is an egress-lockdown/mesh problem, not a
  gateway-code problem — the same "compose, don't fight" posture applies.
- The **vault confidentiality boundary** — a new "MCPIP holds plaintext" boundary that did not exist.
- The **labeling completeness boundary** (Pillar 2) — taint is only sound if *every* source is labeled at
  ingress; an unlabeled source defaults must be fail-closed (treated as most-untrusted), never fail-open.

**New failure modes.**
- **Pointer/interpolated hash divergence → TOCTOU lock re-opens** (§2.1) — the single most dangerous new
  failure, and it lands squarely on the byte-identity invariant (`canonical_json` / `enforce_argument_safety`
  / `lock_payload_hash` / Rust mirror) that the repo treats as untouchable.
- **Vault miss / TTL expiry between decision and dispatch** — must fail closed (deny), never dispatch a
  half-interpolated payload.
- **Incomplete taint labeling** — must fail closed, never silently allow.
- **Parity drift** in the Rust mirror on the new pointer type — caught only by the differential gate
  (`tests/test_fastwalk_differential.py`), which would (correctly) refuse to ship until re-pinned.

**Scaffold that is parity-safe to pre-decide (but still not this wave).** Per the internal roadmap, the *shape*
can be reserved so a future entry is additive not a rewrite: reserve the `{{PTR_<hash>}}` token shape in
`enforce_argument_safety` (Python **and** Rust, per the parity invariant) and pre-decide that
`lock_payload_hash` hashes the *pointer* form. **This memo does not do that** — it is called out here
because it is the *correct first concrete step if and only if §6's decision flips*, and because doing it
carelessly (touching the parity core without the differential re-pin) is precisely the mistake the
invariants guard against. It is its own wave, gated by the owner decision below.

---

### 5. The strategic case — for and against

#### For (why this is the genuine frontier)

- **The two pillars are the only truly un-copied capabilities left.** The internal strategy notes
  finds no incumbent scoring above ~3/7 on today's primitives, and the two *rare* primitives (opaque
  aliasing, write-before-execute) are already MCPIP's. Oracle inversion and cryptographic IFC are the
  *next* two nobody ships — a deterministic data air-gap and deterministic IFC would be a moat an order of
  magnitude deeper than the current integration-and-architecture moat.
- **It is the natural extension of the two rare primitives**, not a pivot: opaque *target* → opaque
  *data*; write-before-execute *decision* → a decision *provably made over pointers*. The conceptual
  through-line is clean.
- **It maps to the target buyer.** The strategy is "regulated / air-gapped accounts where closed cloud
  bundles structurally can't play" (the internal strategy notes). "The model never sees the regulated
  data" is a claim that exact buyer pays for.

#### Against (why not now, and maybe not ever at depth B)

- **It contradicts the whitepaper's own formal threat model.** §2.2 scopes the reasoning surface as
  untrusted and out of scope *by design*; the security proofs (exactly-once, TOCTOU-safety) rest on MCPIP
  being a narrow deterministic gate. Entering the content path doesn't invalidate those proofs, but it
  bolts a much larger, softer surface onto a system whose entire credibility is its narrowness.
- **It is a multi-quarter, high-risk build touching the most dangerous code in the repo** — the
  byte-identity parity core. For a solo founder (the internal roadmap's explicit lens), this is the textbook
  "expensive, speculative, defer-until-pulled" feature. The roadmap ranks it #10 and says exactly this.
- **It spends a named positioning primitive (#7) and the "independent authorizer" battlecard** — the two
  things that let MCPIP compose *beneath* every guardrail and *beside* every IdP rather than compete with
  them. A content data-plane starts overlapping the guardrail/model-serving layer, inviting a fight MCPIP
  currently sidesteps.
- **Depth (B) buys no authorization guarantee (A) doesn't** while costing the most — it is strictly
  dominated and should be permanently off the table.

---

### 6. Decision framework + recommendation

#### 6.1 Recommendation

**Do not enter the prompt path now.** Hold the "interceptor, not a proxy" line as a *stated, deliberate*
posture — the same way `docs/OPERATIONS.md` holds "don't build a VPN" and "no cross-region chain." Keep the
fork a documented, owner-owned, prospect-pulled decision. **Depth (B)
(inference proxy) is a permanent do-not-build.** Depth (A) (content mediation) is *deferred*, not
rejected — reconsidered only when the triggers below fire.

#### 6.2 The gating questions (all must be "yes" before building depth A)

1. **Pull, not push.** Is there a *named, paying* prospect whose requirement is specifically "the model
   must not see this data" or "untrusted content must be structurally barred from this sink" — one that
   today's payload-lock + classification + sender-constraint story provably cannot meet? (If the need is
   met by existing controls, the answer is no.)
2. **Non-bypassability is already solved for that account.** Is that deployment already egress-locked so
   *all* content provably transits MCPIP (`docs/OPERATIONS.md`)? Content mediation with a bypassable
   context path is theater — the air-gap has a hole and the taint labels are incomplete.
3. **Resourcing.** Is there capacity to touch the byte-identity parity core (Python + Rust + lock hash +
   differential re-pin) *correctly*, under the invariant discipline, without rushing? This is the repo's
   highest-consequence code.
4. **Positioning is a deliberate trade, not a drift.** Is the owner willing to *re-write* primitive #7 and
   the "independent authorizer" battlecard into a new story ("inference-free authorizer **plus** a data
   air-gap the client's own model runs behind"), and defend it — rather than silently contradict the
   whitepaper?
5. **Scope is depth (A) only.** Is the plan explicitly content-mediation on the transports where MCPIP
   *already dispatches inline* (`cloud_rest` / `legacy_mainframe` / `grant_issue`) — never an inference
   proxy, never holding a vendor key, never calling a model?

If any answer is "no," the decision stays **deferred**.

#### 6.3 If the triggers fire — the minimum-regret entry path

Take it in the smallest positioning-preserving increments, each fail-closed and additive:

1. **Reserve the pointer token** (`{{PTR_}}`) in `enforce_argument_safety`, Python + Rust in lockstep,
   with `lock_payload_hash` pre-decided to hash the pointer form. Its *own* wave; re-pin the differential
   gate deliberately. No behavior yet — pure scaffold. (This is the item the internal roadmap allows to
   pre-decide; it is still not this wave.)
2. **Pillar 1, scoped to proxy transports only** — vault + pointer-swap on tool results MCPIP *already*
   handles inline, where entering the content path costs the least positioning (MCPIP is already the data
   plane there). De-reference strictly after the WORM ALLOW.
3. **Pillar 2 on top** — taint labels + per-field ceilings + `TAINT_VIOLATION`, once the vault exists
   (the internal roadmap estimates ~20% marginal cost over Pillar 1).
4. **Never depth (B).** No inference proxy, no vendor keys, ever.

Each step preserves fail-closed opacity (agent sees only `MCPIPDenied` + `correlation_id`),
write-before-execute ordering, tenant-prefixed keys, and the byte-identity invariant — or it does not
ship.

#### 6.4 Why this is framed as an owner decision

Every other FUTURE-wave item (`docs/OPERATIONS.md`, the [group-commit WORM ceiling](#worm-group-commit),
the network-enforcement posture) is an *edge* or *packaging* concern the roadmap resolves with a design doc
and a behavior-neutral scaffold. This one is different in kind: it changes **what MCPIP is** — from a narrow
deterministic authorizer of the final action to a mediator of the agent's data flow. It rewrites the threat
model, the battlecard, the latency story, and the trust posture at once. The internal roadmap names it
correctly: "a product decision (deployment story, threat model, latency budget) that should be made
*deliberately* before any data-plane code is written." That is why this memo exists, why it writes no code,
and why the call belongs to the owner — made once, on purpose, with the triggers above met, and never by drift.

---

### 7. 2026-H2 reaffirmation (the internal roadmap F2) — the line holds, and ASI06 does not move it

*Roadmap action: The internal roadmap scopes this wave as **"nothing new — reaffirm."** This section
is that reaffirmation, forced into the open by two 2026-H2 developments — the OWASP ASI-2026 taxonomy
(the internal strategy notes, ASI06 memory/context poisoning) and the shipped **F1 A2A choke-point**
connector. Neither changes the recommendation of §6. Both sharpen why.*

**7.1 The recommendation is unchanged and now dated: DO NOT enter the prompt path.** MCPIP remains an
authorization **interceptor, not a proxy**. It sees only the post-reasoning tool-call artifact (§1 fact
#1), holds no vendor keys, calls no model, and does **not** enter the model's prompt / content /
generation path. Depth (B) (inference proxy) stays a **permanent do-not-build**; depth (A) (content
mediation) stays **deferred, not rejected**, gated by the five prospect-pull triggers of §6.2. Status:
**PENDING (owner)** — nothing in the 2026-H2 landscape flips a §6.2 trigger, so the decision has not been
made and this wave writes no data-plane code, reserves no `{{PTR_}}` token, and changes no behavior.

**7.2 ASI06 (memory & context poisoning) is OUT-OF-SCOPE-BY-DESIGN — and that is the correct scope, not a
gap to close with a detector.** ASI06 writes malicious content into an agent's persistent memory / RAG
store so it later behaves wrongly across sessions, with attack and effect temporally decoupled
(the internal strategy notes; MINJA-style trajectory injection). MCPIP is stateless and sees only the
individual tool-call payload — it has **zero visibility into the agent's memory store**, so a
memory-poisoned agent's later well-formed, in-policy call is authorized like any other. This is not an
accident to be patched: **MCPIP governs the tool call, not the agent's memory or reasoning.** Judging
*why* an agent decided to act is exactly the reasoning surface the whitepaper scopes as untrusted and
out of scope (§1, `WHITEPAPER.md §2.1`/§10). Entering the memory/content path to inspect *why* an agent
acted is the very prompt-path crossing this memo defers — ASI06 is therefore a reason the fork exists as
a question, not a reason to answer it now.

**7.3 The honest answer to ASI06 is damage-limiting, not detection — and MCPIP already ships all of it.**
The gate does not stop a poisoned agent from *deciding* to act, but it bounds and proves what a decided
action can do, deterministically and from outside the agent:

- **Payload-bound one-time PIN** — every `PIN_REQUIRED` high-risk action needs the out-of-band OTP bound
  to `sha256(canonical_json({tenant,agent,alias,arguments}))`, *irrespective of why the agent decided to
  act*. Poisoned memory cannot forge a human OTP, and one byte of argument drift → `PAYLOAD_MISMATCH`.
- **Velocity / amount policy engine** — the deny-only `VelocityAmountPolicyEngine` caps per-identity
  blast radius (rate / cumulative amount), so a poisoned agent cannot amplify into a fleet-scale loss.
- **Write-before-execute WORM** — the signed Ed25519 Merkle record is committed *before* dispatch, so
  every action a poisoned agent takes is non-repudiably recorded before its side effect.
- **Forensic reconstruction** — the encrypted, tenant-bound capture side-channel lets an investigator
  trace the poisoned trajectory *after the fact*, from the authoritative record, without the gate ever
  having entered the content path.

This is the same posture the shipped **F1 A2A choke point** takes for the sibling ASI07 gap (see the
[A2A Side-Effect Choke Point](#a2a-side-effect-choke-point) section, "What is explicitly OUT of scope"):
MCPIP does not observe the inter-agent conversation or the memory store, but the moment a smuggled/poisoned
intent becomes a **governed side-effecting alias call**, it is subject to opaque aliasing, JWT-only
identity, the payload-bound PIN, and a write-before-execute audit record. Narrower than detection, and
stronger where it bites.

**7.4 Explicitly RESIST building a per-identity behavioral-anomaly detector.** The tempting "fix" for
ASI06/ASI07 is an in-agent, per-identity behavioral / probabilistic anomaly detector. **Do not build
it.** It forfeits the deterministic-gate identity that *is* the moat and drifts MCPIP onto the
commoditizing model-guardrail turf it deliberately avoids (the internal strategy notes, `SECURITY_THREAT_MODEL.md §17`). **"The fox can't guard the henhouse"** —
a probabilistic detector that lives inside, and reasons about, the very agent it is meant to police is
not an independent authorizer; the authorizer must stay independent of the thing it authorizes. An
honest "out-of-scope-by-design, here is the damage limit" is worth more than a detector that manufactures
false confidence.

**7.5 This remains the owner's call, prospect-pulled.** The fork is still **the single most consequential
product decision MCPIP faces** — it changes *what MCPIP is*, not merely what it does (§6.4). It is
explicitly **the owner's to make**, made once and deliberately, only when a named paying prospect pulls
it and all five §6.2 triggers are "yes" — never by drift, and never in reaction to a taxonomy line item.
As of this reaffirmation: **PENDING (owner). No trigger has fired. The line holds.**

---

*◐ MCPIP — AI Reasons. MCPIP Authorizes. Systems Execute. (Today, deliberately, from outside the prompt
path — and, reaffirmed 2026-H2, from outside the agent's memory too.)*

---

## WORM Group-Commit

*Group-commit WORM throughput: ceiling, measurement, and design.*

*Last updated: 2026-07-17. Companion to the internal roadmap (line 76 / line 149) — the
"group-commit WORM throughput (the known ~1k emit/s ceiling)" future item. This document
is a **rigorous design + a REAL benchmark of the current ceiling**. It deliberately does
**NOT** rewrite the durable substrate: raising the ceiling for real requires a NEW
app-managed WAL — a substantial change to the tamper-evidence core — and that is an
explicit OWNER decision, flagged at the end. Reproduce every number here with
`python scripts/bench_worm_emit.py`.*

---

### 0. TL;DR

- The **durable-before-authorize** contract (`audit/worm_logger.py`) makes `WormLogger.emit`
  return only after its atomic `INCR`+`XADD` Lua is **fsync-durable** on an
  `appendfsync=always` AOF. That fsync is the anchor of the whole product: every authorized
  decision's audit event is on disk before any effect.
- **Measured, real, on the sandbox Redis (:63790, Redis 7.0.15):**
  - Durable (`appendfsync=always`), **single caller, one emit in flight:** **~750 emits/s**,
    p50 **≈ 1.06 ms/emit** — the fsync-latency-bound serial ceiling. *This is the "~1k
    emit/s" figure the roadmap names.*
  - Non-durable contrast (`appendfsync=everysec`), single caller: **~2,800 emits/s**
    (p50 ≈ 0.34 ms) — **~3.7× faster serially**, proving the per-write fsync IS the serial
    bottleneck.
  - Durable, **under concurrency:** climbs to **~4,500 emits/s at ~64 in-flight** — because
    Redis coalesces fsyncs **once per event-loop iteration** (`flushAppendOnlyFile` in
    `beforeSleep`), so concurrent emits landing in the same tick share ONE fsync. Redis
    already gives us an *implicit, opaque* group commit.
  - At high concurrency `always` (~4,500/s) and `everysec` (~4,700/s) **converge** — the
    bottleneck has shifted OFF the fsync and ONTO Redis's single-threaded per-command Lua
    execution + the client round-trip.
- **Conclusion:** the ceiling is architectural in the sense the roadmap means, but the
  honest shape is subtler than "1k, period":
  1. The per-write fsync dominates only the **low-concurrency / latency-bound** regime.
  2. Redis's per-tick fsync coalescing already lifts **aggregate** durable throughput to
     ~4–5k/s — but MCPIP **cannot trigger, tune, or reason about** that coalescing; it is a
     side effect of arrival timing, and Redis exposes **no application-controlled group
     fsync**.
  3. To *own* the durability/latency/throughput tradeoff — an explicit "batch N waiters,
     one fsync, everyone returns durable" — MCPIP would need a **new app-managed WAL**. That
     is a rewrite of the durable substrate and an OWNER decision (§7). **Not built here.**

---

### 1. Why there is a ceiling at all (the durability contract)

`emit` is the write-before-execute anchor (`audit/worm_logger.py`, module docstring +
`assert_persistence_posture`). The chain of guarantees:

1. An ALLOW is acted on **only after** `emit` returns (`_run_authorize_pipeline` /
   `MCPIPGateway._emit_allow` → `_safe_emit`; dispatch is strictly after).
2. `emit` returns **only after** the atomic `_EMIT_LUA` (`INCR mcpip:worm:seq` +
   `XADD mcpip:worm:events`) completes on the server.
3. Production **refuses to boot** unless AOF is `appendonly=yes appendfsync=always`
   (`assert_persistence_posture(require=True)`), so under `always` Redis fsyncs the AOF
   **before it replies** to the write — the reply (and thus `emit`'s return) is gated on the
   fsync.

So **one authorized decision ⇒ at least one fsync-gated round trip**. fsync latency on the
underlying disk is therefore a hard floor on single-caller authorize latency, and its
reciprocal is the single-caller emit ceiling. This is intrinsic to "durable before
authorize" — it is not an inefficiency to optimize away without changing the durability
model. **Do not weaken it.** (`invariants.md` → WORM/audit: "Production refuses to boot
unless Redis AOF is `appendfsync always`".)

---

### 2. The measurement (`scripts/bench_worm_emit.py`)

The benchmark drives the **real** `WormLogger.emit` — same atomic Lua, same `_redact`, same
`leaf_digest`/`canonical_json`, same code the pipeline calls — against the sandbox Redis.
It measures two things per durability posture:

- **Sequential phase** — await one emit at a time → the true per-emit latency distribution
  (p50/p95/p99) and the serial emits/s a single authorize caller sees.
- **Concurrency sweep** — keep N emits in flight with `asyncio.gather` → aggregate emits/s
  as in-flight width rises.

It measures the **as-found** posture, an `appendfsync=everysec` **non-durable contrast**,
and the `appendfsync=always` **production** posture (each set via `CONFIG SET`, verified by
re-reading the posture through the existing `read_persistence_posture` probe — it never
fabricates a durable number, and if a managed Redis refuses the `CONFIG SET` it says so and
reports only what it could measure). It isolates onto a dedicated logical DB (default 15),
flushes exactly `ALL_WORM_KEYS`, and **restores the server's original AOF config on exit**,
so the run is behavior-neutral. It never touches `audit/worm_logger.py`.

#### 2.1 Real numbers (Redis 7.0.15, sandbox :63790, 3,000 emits/posture)

| Posture | Durable | Serial emits/s | Serial p50 | Aggregate @ ~64 in-flight |
|---|---|---|---|---|
| `appendfsync=always` (production) | ✅ yes | **~750** | **~1.06 ms** | **~4,500** |
| `appendfsync=everysec` (contrast) | ❌ no | ~2,800 | ~0.34 ms | ~4,700 |

Representative concurrency sweep under **`always`** (durable):

```
concurrency=   1     ~720 emits/s
concurrency=   8    ~1,900 emits/s
concurrency=  16    ~2,900 emits/s
concurrency=  64    ~4,500 emits/s
concurrency= 256    ~4,200 emits/s   (past the knee; Lua/CPU-bound, mild contention)
```

(Numbers vary ±15% run-to-run on the shared container — background AOF activity produces
occasional p99/max spikes into the tens of ms — but the **shape** is stable and
reproducible: serial ~750/s durable vs ~2,800/s relaxed; durable aggregate knees at ~4–5k/s
where it meets the relaxed curve.)

#### 2.2 What the numbers mean

- **Serial `always` ~750/s, p50 ~1.06 ms** is the "~1k emit/s ceiling" the roadmap names —
  it is one fsync per emit, latency-bound.
- **Serial `everysec` ~2,800/s** with the fsync removed proves the fsync is ~3.7× of the
  serial cost. The residue (~0.34 ms) is the round-trip + `INCR`/`XADD` + Python
  redact/canonicalize/leaf-hash.
- **Durable aggregate reaching ~4,500/s** is the important, non-obvious finding: under
  `always`, Redis calls `flushAppendOnlyFile` **once per event-loop iteration**, so K writes
  that arrive within one iteration are made durable by **one** fsync. Redis is *already*
  doing group commit — but the batch size is whatever happened to arrive in that tick, and
  **nothing in MCPIP can influence it**.
- **`always` and `everysec` converging at high concurrency** (~4,500 vs ~4,700) shows that
  once the implicit batch is large, the fsync is no longer the bottleneck — Redis's
  **single-threaded** execution of one Lua `INCR`+`XADD` per emit, plus the per-emit client
  round trip, is. Beyond that knee, more concurrency does not help (256 < 64's rate).

**Corollary:** an app-managed group commit would help most in the **latency-bound regime**
(few concurrent callers — the common case for a single busy agent or a low-QPS tenant),
where it could turn ~1 ms/emit serial into batched-fsync-amortized emits without waiting for
Redis's arrival-timing luck. At very high concurrency the win is smaller and the real ceiling
becomes the substrate's per-op CPU, which argues for moving off the Redis round-trip entirely
(§4).

---

### 3. Why Redis cannot be pushed further *in-app*

The ceiling is architectural because **Redis exposes no application-triggered group fsync**:

- `appendfsync=always` fsyncs per event-loop tick, on Redis's schedule, invisibly. We cannot
  say "hold these 50 emits, fsync once, then release all 50 waiters as durable." We only get
  whatever coalescing arrival timing produces.
- `appendfsync=everysec` *would* batch, but it **breaks durable-before-authorize** (a crash
  loses up to ~1 s of already-authorized decisions). Non-negotiable: the benchmark shows it
  only as a physical contrast, never as a shippable mode.
- `WAIT`/`FSYNC`, `MULTI`/`EXEC`, and Lua all run *inside* the same per-tick fsync model —
  none give the app a "one fsync covers these N acknowledgements, and I decide N" primitive.
- Redis is single-threaded for command execution, so even with durability removed the
  substrate tops out around ~4–5k emits/s for this `INCR`+`XADD` pair on this hardware.

So: **within the current substrate**, MCPIP is already at the physical envelope Redis
offers. Raising the real ceiling means changing the substrate.

---

### 4. The design that WOULD raise it: an app-managed WAL with explicit group commit

The only way to *own* the batch is to own the durable write. Sketch of the design (a **new**
component, `audit/group_wal.py` in a future wave — **not built here**):

#### 4.1 Structure

- A single **append-only WAL file** per node (`worm-<node>.wal`), opened once, holding the
  same redacted+leaf-hashed event records `emit` builds today. The record framing carries the
  monotonic `seq`, the `event_id`, the `timestamp_ns`, the canonical record bytes, and the
  leaf hash — i.e. exactly what the Redis stream row carries now, so the epoch/Merkle layer
  is unchanged downstream.
- An in-process **commit queue**: each `emit` builds its record, enqueues it with a
  `Future`, and awaits that future.
- A single **group-commit driver** (one per WAL): it drains the queue, `write()`s the batch
  of framed records to the WAL, issues **ONE `fdatasync`** covering the whole batch, and only
  **then** resolves every waiter's future. A waiter returns **only after the fsync that
  covers its record** — so **durable-before-authorize is preserved byte-for-byte** (each
  caller still cannot proceed until its own event is on stable storage).

#### 4.2 Why this raises the ceiling

- With B concurrent emits, the batch is B records and **one** fsync, so per-emit fsync cost
  is `fsync_latency / B` — the classic group-commit amortization, but now with a batch size
  MCPIP **controls** (bounded by a max-batch and a max-linger, e.g. "fsync when 256 records
  queued OR 500 µs elapsed"), instead of Redis's arrival-timing luck.
- It removes the per-emit **client round trip** to Redis for the durable write; the durable
  path becomes an in-process `write`+`fdatasync`, which is where the ~0.34 ms residue in §2.1
  mostly goes.
- The linger knob makes the **latency-bound low-concurrency regime** — the one Redis's
  implicit coalescing helps least — the primary beneficiary: a lone caller waits at most
  `max_linger` extra to join a (possibly size-1) batch, still one fsync, but the *system*
  sustains far more when load arrives.

#### 4.3 Crash-safety & recovery

- The WAL is the durable substrate; the fsync-before-resolve rule is the whole point, so no
  authorized decision is ever lost (identical guarantee to today, different disk).
- **Torn tail on crash:** each record is length-prefixed + carries a CRC over its framed
  bytes; recovery replays the WAL, stops at the first record whose length overruns EOF or
  whose CRC fails, and treats everything after as never-committed. Because a waiter is
  resolved only *after* the covering fsync, a torn/half-written tail record can only belong to
  an emit that **never returned** — so it was never authorized, and dropping it is correct
  (write-before-execute: no acted-upon decision is lost).
- **Monotonic seq without Redis `INCR`:** the seq generator moves in-process, checkpointed in
  the WAL header + fsync'd on rotation; recovery resumes from the highest intact record's seq,
  preserving the "counter never advances without a matching durable record" property that the
  atomic Lua gives today.
- **Redis becomes the projection, not the source of durability:** after a record is
  WAL-durable, it is XADD'd to `mcpip:worm:events` best-effort for the epoch/Merkle/inclusion
  machinery, recent-decisions feed, etc. A Redis outage no longer risks a lost authorized
  event (the WAL already has it); the stream self-heals from WAL replay. This *inverts*
  today's model (Redis is the durable buffer) and is exactly why it is a substrate change,
  not a tweak.

#### 4.4 Tamper-evidence preservation

The tamper-evidence core (`close_epoch` Merkle build, root-chaining, Ed25519 epoch
signatures, the out-of-domain `AnchorStore` low-watermark, `verify_chain`,
super-checkpoints) operates on the **ordered leaf records**, and is **agnostic to where they
were durably staged**. The design keeps:

- the same `leaf_digest` / `canonical_json` record bytes → identical Merkle roots and epoch
  hashes (no change to `audit/merkle.py`, no change to signing);
- the same contiguous-seq coverage invariant → `verify_chain`'s per-epoch checks are
  unchanged;
- the WAL as an **additional** in-tamper-domain artifact — but the signed epoch chain + the
  out-of-domain anchor remain the authority, so tail-truncation/rollback detection is
  unaffected.

The one genuinely new surface is the WAL file itself: it must be treated as in-tamper-domain
(an attacker who can rewrite it can forge unsealed events exactly as one who can rewrite the
Redis stream can today), and the existing anchor-witnessed epoch chain is what makes any such
forgery detectable once sealed. No weakening; a like-for-like relocation of the durable
buffer with an app-owned fsync batch on top.

---

### 5. Migration & back-compat

- **Additive, mode-gated.** Introduce it exactly like the existing `mode="epoch"` /
  `mode="per_event"` seam: a new `durable_substrate="redis_stream"` (default, today's
  behavior, byte-identical) vs `"group_wal"` (opt-in). Default stays the shipped path; no
  existing deployment changes behavior on upgrade.
- **No agent-facing or wire change.** `emit`'s signature and `WormReceipt` are unchanged;
  callers (`_safe_emit`, the pipeline) are untouched. The epoch/proof/attestation/
  recent-decisions APIs are unchanged.
- **`assert_persistence_posture` generalizes:** under `group_wal` the boot check asserts the
  WAL directory is on an fsync-honoring filesystem and that the group-commit driver resolves
  only post-fsync (the same fail-closed spirit as today's `appendfsync always` refusal),
  rather than probing Redis AOF.
- **Rollout:** ship the WAL writer + a WAL→stream replayer first behind the flag; run it in
  shadow (WAL durable, Redis still authoritative) to validate crash-recovery and Merkle
  parity against the current path; only then flip the authority. A one-time reconciliation
  tool replays any WAL tail into the stream so an operator can switch back and forth during
  bring-up.
- **Parity note:** none of this touches `canonical_json` / `enforce_argument_safety` / the
  scrypt PIN-hash or the Rust mirror — the record bytes are produced by the same
  `canonical_json` already used in `emit`, so the byte-identity invariant is not in scope and
  not at risk.

---

### 6. What was NOT changed in this wave (scope discipline)

- `audit/worm_logger.py` — **untouched.** No change to `emit`, the atomic Lua, the durability
  probe, `close_epoch`, retention, compaction, or `verify_chain`.
- No new durable substrate was built. No durability guarantee was weakened, reordered, or
  relaxed. `everysec` appears in the benchmark **only** as a physical contrast and is
  restored away on exit.
- Deliverables are exactly: a **real benchmark** (`scripts/bench_worm_emit.py`) and **this
  design**.

---

### 7. OWNER decision & recommendation

**This is a substantial change to the tamper-evidence core.** It relocates the durable
substrate from Redis's AOF to an app-managed WAL and makes MCPIP — not Redis — the owner of
the durable-write fsync. That is precisely the kind of change the invariants guard most
heavily (durable-before-authorize is the anchor of the entire product), so it must be a
**deliberate owner decision**, not an incremental optimization.

**Recommendation:**

1. **Do not build it speculatively.** The measured serial ceiling (~750 durable emits/s per
   node) and the measured aggregate (~4–5k/s under load, via Redis's own per-tick coalescing)
   are **ample** for the current design point: one gateway node authorizing on the order of
   thousands of decisions/second, with horizontal scale-out available per node (each node its
   own WAL, seq space is already per-deployment and the epoch chain is per-node). No customer
   workload in sight is fsync-ceiling-bound.
2. **Reach for it when a real workload is latency-bound at low concurrency** (a single
   high-rate agent or a tenant needing sub-millisecond authorize p99 under bursty serial
   load) — that is the regime where app-owned group commit, with a linger knob, beats Redis's
   arrival-timing coalescing.
3. **When built, build it behind the `durable_substrate="group_wal"` flag, shadow-validate
   Merkle/crash parity before flipping authority, and keep the signed epoch chain + anchor as
   the tamper authority** exactly as today.

Until then, the honest, shippable posture is: **the ceiling is real, measured, and
sufficient; the path past it is designed and understood; and the substrate rewrite is
deferred to an explicit owner call.**
