# Payload-Bound Intent Authorization: TOCTOU-Safe Execution Control for Autonomous LLM Agents

**◐ MCPIP — The Authorization Layer for Autonomous AI**

*Authorize every AI action before execution.*
*AI Reasons. MCPIP Authorizes. Systems Execute.*

---

## Abstract

Autonomous large-language-model (LLM) agents increasingly emit machine-to-machine tool calls that reach payment rails, mainframe transaction monitors, and production infrastructure without a human in the synchronous path. The dominant failure mode is not model incompetence but *authorization drift*: the arguments a human (or upstream policy) approved are not provably the arguments that execute. Between the moment of approval and the moment of dispatch, an adversary controlling the agent's context — through prompt injection, tool-schema tampering, or a compromised orchestrator — can substitute a different payload, replay a spent approval, forge an identity claim inside the tool-call body, or launder a delegation across a swarm of cooperating agents. Classical identity-and-access-management (IAM) authorizes *principals* and *scopes*; it does not bind an approval to an *exact payload*, and so it is structurally blind to time-of-check/time-of-use (TOCTOU) substitution.

This paper presents **Payload-Bound Intent Authorization**, the mechanism at the core of MCPIP, a four-stage authorization gateway (Bridge → Obfuscator → Auth → Audit) that sits between an agent's reasoning and any system of record. The central contribution is a **payload lock**: a six-digit nonce bound to the SHA-256 digest of a *canonical* serialization of the intent (tenant, agent, alias, arguments), consumed *exactly once* by a single atomic Redis Lua script whose fetch-compare-delete executes without interruption on Redis's single-threaded command loop. One byte of drift between authorization and execution yields a different digest and an instant deny, with no PIN attempt spent and the lock preserved for the legitimate retry. We complement the lock with (i) **identity sovereignty** — tenant, agent, and role derive exclusively from a verified JWT, and any identity-shaped field arriving in the tool-call payload is a hard deny rather than a silently ignored value; (ii) **schema rigidity** — deeply strict Pydantic v2 models that forbid unknown fields, bound depth and size, and reject control, bidirectional-override, and zero-width characters used for prompt smuggling; and (iii) **swarm traceability** — a hash-chained, Ed25519-signed write-once-read-many (WORM) audit log that renders every decision non-repudiable and tamper-evident. We give a threat model, formal system notation, an exactly-once argument under concurrent adversarial interleaving, a property-by-adversary security matrix, and an honest account of residual limitations (canonicalization edge cases, the Lua string-compare timing residual and why PIN-hash storage neutralizes it, TTL trade-offs). We close with numbered, patent-style method claims. Every mechanism described corresponds to code that exists in the MCPIP reference implementation; no property is asserted that the implementation does not enforce.

---

## 1. Introduction

An autonomous LLM agent is, operationally, a program that consumes natural-language and tool-result context and emits structured tool calls. When those tool calls carry consequences — moving money, posting to a general ledger, dropping a production database — the security-relevant question is not "did the model choose well?" but "is the action that executes *exactly* the action that was authorized, by *exactly* the principal entitled to it, and is that fact *provable* afterward?"

Three properties of the agent setting break the assumptions that classical authorization relies on:

1. **The context is attacker-influenced.** Retrieved documents, tool outputs, prior messages, and even tool *schemas* flow into the model's context. Any of these can carry adversarial instructions (prompt injection) that steer the agent to emit an action the operator never intended, or to alter an action already in flight.

2. **Approval and execution are separated in time.** Realistic agent workflows stage an action, obtain an approval (a human step-up, a policy sign-off), and then dispatch. That interval is a TOCTOU window. A scope-based token authorizes *"this agent may create wires"* — it says nothing about *which* wire, so a payload swapped inside the window is indistinguishable from the approved one.

3. **Identity is ambient and forgeable in-band.** Agents pass structured arguments that can trivially contain fields named `tenant_id`, `role`, `principal`, or `sub`. If any layer trusts those fields, an injected instruction can impersonate a tenant or escalate a role from inside the payload — the confused-deputy problem in its purest form.

MCPIP's thesis is that the authorization layer must **bind the approval to the payload, cryptographically and atomically**, and must **refuse to derive identity from anything the agent can write**. Concretely:

- Every high-risk action is gated by a **payload lock**: a nonce whose validity is conditioned on the SHA-256 of a canonical encoding of the intent. The lock is spent by one atomic server-side operation, never a Python-side check-then-act.
- Identity is resolved **only** from a signed JWT (EdDSA/RS256, `alg=none` and HMAC-confusion rejected, eight claims required and verified). Identity-shaped keys in the arguments are a hard deny.
- Ingress is validated by **deeply strict** schemas that forbid unknown fields at every nesting level, bound depth/size, and strip the Unicode classes used for smuggling.
- Every decision is written to a **hash-chained, Ed25519-signed WORM log** that a verifier can replay to detect a single altered byte.

The pipeline is four stages, in a fixed order, branded canonically:

```
◐ Bridge → Obfuscator → Auth → Audit
```

**Bridge** normalizes any provider tool-call format (OpenAI, Anthropic, raw MCP) into a single internal intent. **Obfuscator** resolves a tenant-scoped *alias* to a real target, so agents never see production system identifiers. **Auth** establishes identity from the JWT and, for risk-tiered actions, enforces the payload lock. **Audit** records the decision immutably. This paper formalizes the pipeline, proves the exactly-once property of the lock under adversarial concurrency, and analyzes the design property-by-property against a stated adversary.

---

## 2. Threat Model

### 2.1 Adversary capabilities

We assume a powerful adversary who has compromised the agent's *reasoning surface* but not the gateway's trust roots. Concretely, the adversary can:

- **A1 — Prompt injection into agent context.** Inject arbitrary instructions via retrieved documents, tool results, memory, or upstream messages, causing the agent to emit tool calls of the adversary's choosing, or to modify a staged call.
- **A2 — Tool-schema tampering.** Influence the *declared* schema of a tool (name, argument shape) that the agent believes it is calling, attempting to smuggle extra fields or coerce types.
- **A3 — TOCTOU payload substitution.** Within the interval between an action's authorization (e.g., a human-supplied step-up code) and its execution, replace the arguments with different ones — the canonical TOCTOU attack.
- **A4 — Approval replay / double-spend.** Capture a valid approval (nonce/PIN) and reuse it to authorize a second, unapproved execution.
- **A5 — Confused-deputy identity injection.** Place identity-shaped fields (`tenant_id`, `role`, `principal`, `sub`, …) into the tool-call arguments so a downstream component acts under a forged principal.
- **A6 — Delegation laundering across agent swarms.** In a multi-agent topology, route an action through a chain of sub-agents to obscure its true origin or to fabricate a plausible-looking delegation that never occurred.
- **A7 — Unicode smuggling.** Embed bidirectional-override, zero-width, or control characters in string arguments to hide payload content from human review, to desynchronize visual and byte-level representations, or to defeat naive string matching.

The adversary may drive concurrency: fire many requests in parallel, interleave register/consume operations, and race the TTL boundary.

### 2.2 Trust boundaries and assumptions

- **Trusted:** the JWT signing key (held by the identity provider), the WORM signing key, the Redis instance's single-threaded execution guarantee for scripts, and the gateway code itself. Redis is assumed reachable over a trusted network segment; the caller may reference *only its own tenant's* lock keys (keys are tenant-scoped).
- **Untrusted:** everything in the agent's context, every field of every tool-call payload, all provider-format framing, and any identity assertion not carried by a verified JWT.
- **Positioning:** MCPIP is an authorization interceptor, **not an LLM proxy**. The client calls its LLM directly on its own keys/billing; the gateway receives only the resulting tool-call payload, so it holds no vendor credentials and makes no LLM calls. Consequently the provider **format is declared by the caller** (`source_format`, or a vendor id resolved through a pinned registry) and never inferred from payload bytes — content sniffing would let the adversary steer which parser interprets its bytes, the same class of hazard as an unpinned JWT `alg`. The format parsers are pure (no SDKs, no outbound network — mechanically enforced), and the MCP-native edge is itself the authorization boundary rather than a proxy to an upstream MCP server.
- **Out of scope:** compromise of the signing keys themselves, physical extraction of Redis memory, side channels below the level considered in §7, and the correctness of the *downstream* system of record once a correctly authorized action is dispatched. MCPIP authorizes; it does not re-implement the executing system.

### 2.3 Security goals

- **G1 Payload integrity (TOCTOU-safety):** an action executes only if its exact arguments match those bound at authorization time.
- **G2 Exactly-once approval:** a payload lock authorizes at most one execution.
- **G3 Identity non-forgeability:** the acting principal is exactly the one in the verified JWT; no in-band claim can alter it.
- **G4 Tenant isolation:** no principal can resolve, lock, or execute against another tenant's resources.
- **G5 Fail-closed opacity:** any error denies, and the agent-facing response leaks nothing beyond a generic message and an opaque correlation id.
- **G6 Non-repudiation & tamper-evidence:** every decision is provably recorded; any post-hoc alteration is detectable.

---

## 3. System Model

### 3.1 Notation

We model the gateway as a deterministic function over a request tuple. Let:

- **T** — the set of tenants; **G** — the set of agents; **R** — roles; **Σ*** — finite byte strings.
- An **identity** `id ∈ I` is a tuple `id = (t, g, r, iss, aud, jti)` with `t ∈ T`, `g ∈ G`, `r ∈ R`, issuer `iss`, audience `aud`, and optional token id `jti`. Identities are *frozen* (immutable once constructed) and are producible **only** by verifying a JWT (§5).
- An **alias** `a` is a tenant-scoped logical name. The **alias registry** is a partial function `ρ : T × A ⇀ E`, where an entry `e = (a, target, transport, tier)` gives the concrete target, transport class, and risk tier `tier ∈ {AUTO, PIN_REQUIRED}`. `ρ` is undefined on unknown aliases (→ `UNKNOWN_ALIAS`) and on aliases owned by another tenant (→ `CROSS_TENANT`).
- **Arguments** `args` are a JSON value drawn from JSON-native types only: `dict[str, ·]`, `list`, `str`, `int`, `float`, `bool`, `None`.
- A **normalized intent** is `μ = (a, args, τ, fmt)` where `τ` is a swarm trace (§3.3) and `fmt` a source format.
- An **authorized intent** is `α = (μ, id, cid)` with correlation id `cid` (a fresh uuid4 minted at gateway entry).

### 3.2 Canonical serialization

The linchpin of payload binding is a **deterministic** encoding `C : JSON → Σ*` with an exact contract:

1. Recursively NFC-normalize every string, both object keys and values.
2. Reject `NaN`/`±Inf` (`allow_nan=False`).
3. Sort object keys lexicographically by Unicode code point.
4. Emit with separators `(",", ":")` — no insignificant whitespace.
5. `ensure_ascii=False`, then UTF-8 encode.

Only JSON-native types are permitted; any other Python object raises `TypeError` (fail-closed). Implementation shape: a pre-pass `_nfc(obj)` rebuilds the structure with normalized strings, then `json.dumps(_nfc(obj), sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode("utf-8")`. We write `H(x) = SHA256hex(C(x))` for the canonical digest and use `C` identically in both the payload lock (§4) and the WORM record hash (§6); byte-for-byte agreement across those two uses is a cross-artifact invariant.

Determinism of `C` is what makes the digest a stable binding: two encoders, on two hosts, at two times, produce the same bytes for the same logical value, so `H(x)` computed at authorization equals `H(x)` computed at execution *iff* the logical value is unchanged.

### 3.3 Swarm trace

Multi-agent provenance is a first-class field of every intent. A **hop** is `(hop_index, agent_id, parent_agent_id, purpose)`; a **trace** `τ = (trace_id, [h₀, …, h_{n−1}])` with `1 ≤ n ≤ MAX_CHAIN_HOPS = 16`. A structural validator enforces:

- `trace_id` parses as a UUID.
- `h₀.parent_agent_id = None` (the origin hop has no parent).
- for every `i > 0`, `h_i.parent_agent_id = h_{i−1}.agent_id` (contiguous delegation).
- `h_i.hop_index = i` (strict positional order; no gaps, no reordering).

A trace that fails any clause is rejected at ingress. This turns "who delegated to whom" from prose into a checkable structure and is the substrate for the audit chain of §6.

### 3.4 Limits (single source of truth)

All bounds live as module constants and are referenced identically across code and docs:

| Constant | Value | Governs |
|---|---|---|
| `MAX_CHAIN_HOPS` | 16 | trace length |
| `MAX_ARG_DEPTH` | 8 | nested container depth |
| `MAX_ARG_KEYS` | 64 | keys per object |
| `MAX_ARG_ARRAY` | 256 | elements per array |
| `MAX_STRING_LEN` | 4096 | per string field (post-NFC) |
| `MAX_CANONICAL_BYTES` | 16384 | canonical-encoded args payload |
| `PIN_TTL_SECONDS` | 300 | payload-lock lifetime |
| `PIN_MAX_ATTEMPTS` | 5 | wrong-PIN lockout |
| `PIN_LENGTH` | 6 | decimal PIN digits |

### 3.5 The pipeline as a function

`authorize_and_execute(token, raw, fmt, τ, pin?)` proceeds:

1. mint `cid`;
2. **Auth:** `id ← resolve(token)` or deny (`JWT_INVALID` / `JWT_CLAIMS_MISSING`);
3. **Bridge:** `μ ← parse(raw, fmt, τ)` with full schema rigidity, identity-injection check, and character/size/depth gates;
4. **Obfuscator:** `e ← ρ(id.t, μ.a)` or deny (`UNKNOWN_ALIAS` / `CROSS_TENANT`);
5. form `α = (μ, id, cid)`; compute `payload_hash = H({t, g, a, args})`;
6. **Risk gate:** if `e.tier = PIN_REQUIRED`, require and `consume` the lock (§4); a non-success code denies;
7. **Audit:** emit the ALLOW record (redacted; includes `payload_hash` and lock code);
8. **Dispatch:** select transport by `e.transport`, execute against `e.target`;
9. on any deny: emit the DENY record with reason, then raise `MCPIPDenied(cid)`.

The function is *fail-closed*: every parse/validation/lookup/lock failure short-circuits to step 9. The agent boundary never observes the reason — only the generic message `"MCPIP: request denied by policy."` and `cid`.

---

## 4. The Payload Lock Protocol

The payload lock is the mechanism that satisfies G1 (payload integrity) and G2 (exactly-once). It is a nonce whose acceptance is conditioned on a payload digest and whose consumption is a single atomic server-side operation.

### 4.1 What is bound

Registration and consumption both compute the *same* payload digest over the *same* four fields:

```
lock_payload_hash(t, g, a, args) = SHA256hex( C({ "tenant_id": t,
                                                  "agent_id":  g,
                                                  "alias":     a,
                                                  "arguments": args }) )
```

Because `C` is canonical, this digest is invariant to key ordering and to Unicode normalization form of the input, but *sensitive to every semantically meaningful byte*. Drift in any of the four fields — a different recipient account, a re-scoped alias, an altered amount, a spoofed agent — produces a different digest.

### 4.2 Storage schema

A lock is a single Redis key, tenant-scoped so a caller can reference only its own tenant's locks:

```
Key:   mcpip:pinlock:{tenant_id}:{lock_id}         lock_id = uuid4().hex
Value: JSON = { "pin":      SHA256hex(6-digit PIN),
                "payload":  payload_hash,
                "alias":    a, "agent_id": g,
                "attempts": 0, "created_ns": <int> }
TTL:   PIN_TTL_SECONDS via SET … NX EX 300
```

Two storage decisions are load-bearing. First, **only the SHA-256 of the PIN is stored** — never the raw six digits. Second, registration uses `SET … NX`: if the (random) `lock_id` collides, `NX` fails and the gateway denies (`LOCK_ERROR`) rather than overwriting. Registration is *not* on the critical concurrency path; only *consumption* must be atomic.

### 4.3 The atomic consume operation

Consumption is one Redis `EVAL` with the following exact script (a constant, registered once via `register_script` so subsequent calls use cached `EVALSHA`):

```lua
local raw = redis.call('GET', KEYS[1])
if not raw then
  return -1
end
local rec = cjson.decode(raw)
if rec.payload ~= ARGV[2] then
  return -3
end
-- Constant-time PIN-hash comparison: XOR-fold every byte with no early exit.
local stored = rec.pin
local presented = ARGV[1]
local diff = 0
if #stored ~= #presented then
  diff = 1
else
  for i = 1, #stored do
    diff = bit.bor(diff, bit.bxor(string.byte(stored, i), string.byte(presented, i)))
  end
end
if diff ~= 0 then
  rec.attempts = (rec.attempts or 0) + 1
  if rec.attempts >= tonumber(ARGV[3]) then
    redis.call('DEL', KEYS[1])
  else
    local pttl = redis.call('PTTL', KEYS[1])
    if pttl and pttl > 0 then
      redis.call('SET', KEYS[1], cjson.encode(rec), 'PX', pttl)
    else
      redis.call('SET', KEYS[1], cjson.encode(rec))
    end
  end
  return -2
end
redis.call('DEL', KEYS[1])
return 1
```

Invocation: `EVAL <script> 1 KEYS[1] ARGV[1] ARGV[2] ARGV[3]`, where `KEYS[1]` is the tenant-scoped lock key, `ARGV[1] = SHA256hex(pin)`, `ARGV[2] = payload_hash`, `ARGV[3] = str(PIN_MAX_ATTEMPTS)`. Return codes: `1` = consumed and deleted; `-1` = not found; `-2` = PIN mismatch; `-3` = payload mismatch. The gateway maps these to `proceed`, `PIN_NOT_FOUND`, `PIN_MISMATCH`, `PAYLOAD_MISMATCH`.

**Ordering rationale (payload before PIN).** The script compares the payload digest *first*. A tampered payload (attack A3) returns `-3` immediately — without incrementing `attempts`, without touching the TTL, and without deleting the lock. This is deliberate: a TOCTOU substitution must not be able to burn a legitimate user's lock or exhaust their attempt budget, and a genuine correct-payload retry after a wrong PIN must still be possible. Only a *wrong PIN on the correct payload* spends an attempt; on the fifth wrong attempt the script deletes the lock outright, capping brute force at four guesses within the 300-second TTL against a space of 10⁶ PINs (with only the PIN *hash* stored, an attacker with read access to Redis still cannot recover the PIN offline in time, but the online path is what the attempt counter closes).

### 4.4 Exactly-once under adversarial concurrency

We argue G2: **a single registered lock authorizes at most one execution, even under arbitrary concurrent, adversarial invocation.**

*Setup.* Let a lock `L` be registered at key `k` with stored digest `p` and PIN-hash `q`. Consider any set of concurrent `consume` calls `{o₁, …, o_m}` targeting `k`, issued by cooperating adversarial clients with arbitrary argument choices and arbitrary interleaving of network delivery.

*Redis execution model.* Redis executes commands, and in particular each `EVAL` script, on a single thread; a script runs to completion as an isolated unit with no interleaving of other commands against the same keyspace. Thus the `m` scripts are *totally ordered* by the server into some sequence `o_{π(1)}, …, o_{π(m)}`, and each observes the datastore state left by its predecessor. There is no window between the script's `GET` and its `DEL`: fetch, compare, and delete are one indivisible step. This is the crux — the classic TOCTOU gap (a Python `get()` … evaluate … `delete()`) does not exist here because no Python code sits between the read and the delete.

*Claim.* At most one `o_j` returns `1`.

*Argument.* A script returns `1` only on the path where `GET` yields a record, its `payload = ARGV[2]`, and its `pin = ARGV[1]`; the *last* action on that path is `DEL k`. Consider the first script in the server order, `o_{π(1)}`.

- If it returns `1`, it has deleted `k`. Every later script's `GET` returns `nil` (no other writer recreates `k`: `consume` never issues a create, and `register` uses `NX` which cannot resurrect a live key mid-sequence to the same `lock_id`), so each later script returns `-1`. Exactly one success.
- If it returns `-3` (payload mismatch), `k` is untouched; the invariant "lock still live, digest `p`, PIN-hash `q`, attempts unchanged" is preserved for the successor. Induction proceeds on the remaining `m−1` scripts against the same live lock.
- If it returns `-2` (PIN mismatch on correct payload), it increments `attempts`. If that reaches `PIN_MAX_ATTEMPTS` it deletes `k` (subsequent scripts see `-1`, zero successes total — the lock self-destructed, which is safe: no execution authorized). Otherwise `k` remains with `attempts+1`; induction proceeds.

In every branch, the number of `1`-returns over the whole sequence is at most one: the first success deletes the key and no path recreates it, and no non-success path can later manufacture a second success on a deleted key. Therefore at most one execution is authorized. ∎

*Corollaries.*
- **Replay/double-spend (A4) is impossible.** The success path's `DEL` is inside the atomic unit; a replayed `consume` of an already-consumed lock reads `nil` → `-1` (`PIN_NOT_FOUND`). This is exactly demo gate #3.
- **TOCTOU substitution (A3) is caught with zero collateral.** A `consume` whose `arguments` were altered after registration computes a different `payload_hash ≠ p`, hits the first comparison, returns `-3`, and leaves the lock intact for the honest retry — demo gate #4.
- **No check-then-act race.** Because the gateway performs *zero* Python-side inspection of lock state and defers the entire decision to the script's return code, there is no TOCTOU on MCPIP's own side.

### 4.5 Validator contract

`PinValidator.register(t, g, a, args, pin)` validates `pin` against `^\d{6}$`, computes `payload_hash` and `SHA256hex(pin)`, mints `lock_id`, performs `SET … NX EX`, and returns `lock_id` (raising on `NX` failure). `PinValidator.consume(t, lock_id, g, a, args, pin)` recomputes the digests, `EVAL`s the script, and returns the raw code. The raw PIN is never stored and never logged.

---

## 5. Identity Sovereignty

Identity in MCPIP is *sovereign*: it originates solely from a verified JWT and is immune to anything the agent can place in a payload. This satisfies G3 and defeats confused-deputy identity injection (A5).

### 5.1 JWT verification

`TokenResolver.resolve(token)` performs:

1. **Algorithm pinning.** Read the *unverified* header and assert `alg ∈ {EdDSA, RS256}` before any verification. This rejects `alg=none` (unsigned) tokens and defeats the HMAC-confusion attack in which an attacker re-signs with `HS256` using a public key as the shared secret. PyJWT's explicit `algorithms=` list already refuses out-of-list algorithms; the pre-check is defense-in-depth against header manipulation.
2. **Claim requirement and verification.** `require = ["exp","iat","nbf","iss","aud","tenant_id","agent_id","role"]`, with `verify_exp`, `verify_iat`, `verify_nbf`, `verify_aud`, `verify_iss` all true; `audience` and `issuer` are passed explicitly and must match configuration. A token missing any required claim, expired, not-yet-valid, or bound to the wrong audience/issuer is rejected.
3. **Frozen identity construction.** On success, a *frozen* `Identity(tenant_id, agent_id, role, issuer, audience, jti)` is built from the verified claims. Immutability prevents any later stage from mutating the principal.

Keys are supplied through a `KeyProvider` abstraction; the shipped `StaticPEMKeyProvider` returns a single public PEM. The abstraction is a documented extension point for a future JWKS provider — declared, not stubbed. Any exception in the path raises and the gateway converts it to `JWT_INVALID` or `JWT_CLAIMS_MISSING`; the resolver is strictly fail-closed.

### 5.2 Hard-deny on in-band identity claims

Identity sovereignty would be hollow if an agent could smuggle `tenant_id` in the arguments and have some downstream component honor it. MCPIP therefore treats identity-shaped keys as *contraband*, not as fields to be ignored. During the recursive argument walk (§ below), at **every** nesting level, a case-insensitive match against

```
{ tenant_id, agent_id, role, tenant, actor, principal, identity, sub }
```

triggers a hard deny with reason `IDENTITY_INJECTION`. The distinction between *hard-deny* and *silently strip* is deliberate and security-relevant: stripping would mask an active attack and let the surrounding (possibly malicious) request proceed; denying surfaces the attempt to the audit log and halts the request. This is demo gate #8.

### 5.3 Schema rigidity as an identity boundary

Every ingress model uses `ConfigDict(extra="forbid", strict=True)`, including every nested model. `extra="forbid"` means an unknown field is a validation error, not a discarded extra; `strict=True` disables type coercion, so a string where an int is expected fails rather than silently converting. The argument walker additionally enforces `depth ≤ 8`, `keys ≤ 64` per object, `arrays ≤ 256`, canonical size `≤ 16 KiB`, scalar leaves restricted to `{str, int, float, bool, None}`, `NaN`/`Inf` rejected, and every string (keys and values) passed through the smuggling filter of §5.4. Violations map to `SCHEMA_VIOLATION`, `DEPTH_EXCEEDED`, `SIZE_EXCEEDED`, or `ILLEGAL_CHARACTER`. Together these close A2 (schema tampering): the gateway's schema, not the agent's declared one, is authoritative, and it admits nothing it does not explicitly model.

### 5.4 Unicode smuggling defense

`reject_unsafe_string(s, field)` runs in a fixed order: (1) NFC-normalize; (2) scan for forbidden codepoints; (3) length-check the normalized form against `MAX_STRING_LEN`. The forbidden set (attack A7):

- **C0/C1 controls** `U+0000–U+001F`, `U+007F–U+009F` — with no exceptions: tab and newline are rejected in ingress arguments, since a machine tool-call has no need for them and they are common smuggling carriers.
- **Bidirectional overrides/isolates** `U+202A–U+202E`, `U+2066–U+2069` — the characters behind visual/byte desynchronization ("Trojan Source"-style) attacks that make a rendered argument read differently from its bytes.
- **Zero-width / invisible** `U+200B`, `U+200C`, `U+200D`, `U+2060`, `U+FEFF`, `U+00AD` — used to hide content inside otherwise-innocuous strings or to defeat naive equality checks.

NFC-normalizing *before* scanning and hashing means visually identical inputs in different normalization forms collapse to one canonical byte sequence, so an attacker cannot use normalization ambiguity to produce two "equal-looking" payloads with different digests. The validator is attached as a Pydantic `field_validator(mode="after")` on every string field and applied recursively to strings inside `arguments`.

---

## 6. Swarm Traceability

Autonomous work increasingly fans out across *swarms* of cooperating agents. Two swarm-specific risks (A6) are **delegation laundering** — routing an action through intermediaries to disguise its origin — and **non-repudiation gaps** — the inability to prove, after the fact, which agent authorized what. MCPIP addresses both with the structured swarm trace of §3.3 and a hash-chained, signed WORM log satisfying G6.

### 6.1 Delegation-chain model

The swarm trace makes a delegation chain a *validated data structure*, not a claim. Because each hop must name a `parent_agent_id` equal to the previous hop's `agent_id`, and `hop_index` must equal the list position, a chain cannot have gaps, cannot be reordered, and cannot silently drop an intermediary — any such tampering violates a structural clause and is rejected at ingress. The origin hop is pinned by `parent_agent_id = None`. Laundering that would require fabricating a contiguous, correctly indexed chain is thus forced into the open: the fabricated chain is itself recorded verbatim in the audit log, attributable and reviewable, rather than lost.

### 6.2 Hash-chained, signed WORM records

Each decision appends one JSON line:

```
{ "sequence":    <monotonic int from 0>,
  "timestamp_ns":<int>,
  "prev_hash":   <hex, or "GENESIS" for sequence 0>,
  "event":       { …redacted event… },
  "record_hash": SHA256hex( C({sequence,timestamp_ns,prev_hash,event}) ),
  "signature":   Ed25519( bytes.fromhex(record_hash) ).hex() }
```

Two independent integrity mechanisms compose. The **hash chain** sets `prev_hash` of record *N* to `record_hash` of record *N−1* (record 0 uses the literal `"GENESIS"`), so altering any past record breaks the linkage of every subsequent record — the tamper is not merely detectable but *localizable* to a first-bad sequence. The **Ed25519 signature** over the record hash means an attacker cannot forge or re-chain records without the signing key: recomputing a consistent `record_hash` after an edit is easy, but producing a valid signature over it is not. Sequence and last-hash state persist in Redis (`mcpip:worm:seq`, `mcpip:worm:last_hash`) so gateway nodes remain stateless, and appends are serialized by a short-TTL Redis lock (`mcpip:worm:lock`) to keep the sequence monotonic under concurrency.

This record is where the *ordering* half of write-before-execute lives: the ALLOW record is committed at §3.5 step 7, strictly before dispatch at step 8, and a failed emit denies rather than proceeds. As independent systems now ship pre-execution hash-chained audit (§8, "Pre-execution audit convergence"), the durable differentiation is not the signed record in isolation but its role as an *inline fail-closed gate* over a *payload-bound* approval whose target the agent never saw — the tamper-evident chain merely makes that composite provable after the fact.

### 6.3 Redaction

The log is a security record, not a secret store. A recursive, case-insensitive redaction pass strips any key in `{pin, jwt, token, authorization, password, secret}` before writing, and the emitter never writes a raw PIN or raw JWT. What *is* recorded is exactly what an auditor needs and nothing a thief could reuse: `jti`, alias, target, `tenant_id`, `agent_id`, decision, `deny_reason`, `correlation_id`, `payload_hash`, and the lock return code.

### 6.4 Chain verification

`verify_chain()` re-reads the JSONL and, for each line, recomputes `record_hash` from the canonical encoding, checks that `prev_hash` links to the prior record's hash, and verifies the Ed25519 signature over the hash bytes. Hex comparisons use `secrets.compare_digest`. It returns `(True, None)` if the entire chain is intact, else `(False, first_bad_sequence)`. Because `C` is the *same* canonical encoder used for the payload lock, verification is deterministic and portable: a third party with the public key and the log file can independently confirm — or refute — the integrity of the entire decision history. This is demo gate #11.

---

## 7. Security Analysis

### 7.1 Property-by-adversary matrix

| Adversary | Vector | MCPIP mechanism | Result |
|---|---|---|---|
| A1 Prompt injection | Steer/alter emitted tool call | Payload lock binds approved args (§4); schema rigidity (§5.3) | Any deviation → different digest → `PAYLOAD_MISMATCH`; unmodeled fields → `SCHEMA_VIOLATION` |
| A2 Schema tampering | Extra/typed fields, coercion | `extra="forbid" + strict=True` at every level; depth/size/array bounds | `SCHEMA_VIOLATION` / `DEPTH_EXCEEDED` / `SIZE_EXCEEDED` |
| A3 TOCTOU substitution | Swap args in approval→exec window | Canonical digest compared first, atomically (§4.3–4.4) | `PAYLOAD_MISMATCH` (−3); lock intact, no attempt spent |
| A4 Replay / double-spend | Reuse spent approval | Atomic fetch-compare-delete; single success | `PIN_NOT_FOUND` (−1) on second consume |
| A5 Identity injection | `tenant_id`/`role`/`sub` in args | Hard-deny on identity-shaped keys, all levels (§5.2); JWT-only identity (§5.1) | `IDENTITY_INJECTION` |
| A6 Delegation laundering | Fake/obscured swarm chain | Structural trace validation (§6.1); signed WORM (§6.2) | Malformed chain rejected at ingress; genuine chain attributable and non-repudiable |
| A7 Unicode smuggling | Bidi/zero-width/control chars | `reject_unsafe_string`, NFC-before-hash (§5.4) | `ILLEGAL_CHARACTER`; no visual/byte desync |
| — Forged/`none` JWT | Tamper signature; strip alg | Algorithm pinning; signature+claims verification (§5.1) | `JWT_INVALID` |
| — Cross-tenant | Ask for another tenant's alias | Tenant-scoped registry `ρ(t, a)`; tenant-scoped lock keys | `CROSS_TENANT` |
| — Error probing | Trigger errors to leak internals | Fail-closed, opaque `MCPIPDenied(cid)`; detail only in WORM (§3.5, G5) | Generic message + `cid`; no reason/path/topology leak |

### 7.2 The four-stage composition

The properties compose because each stage narrows the input to the next and no stage trusts data it did not itself establish. Bridge guarantees the intent is well-formed and smuggling-free before Obfuscator resolves it; Obfuscator guarantees the target is tenant-owned before Auth binds the payload; Auth guarantees identity is sovereign and (for risk-tiered actions) the payload is locked before dispatch; Audit records the outcome regardless of branch. A deny at any stage short-circuits to the same opaque failure, so the *observable* behavior of the gateway is invariant to which check failed — an attacker cannot use error differentiation to map the internal policy.

### 7.3 Limitations and residual risks

Honesty about residuals is part of the security argument.

- **Canonicalization edge cases.** The digest binding is only as strong as the agreement between the two encoders. Two subtleties bound the guarantee. (i) **Integer/float identity:** JSON does not distinguish `1` from `1.0`; a producer that emits `1.0` where the approver serialized `1` yields a different canonical string and thus a *fail-closed* deny — safe, but a source of false negatives if upstream layers are careless about numeric types. (ii) **Float formatting:** `C` relies on the platform's shortest-round-trip float repr; heterogeneous producers must share that behavior, which is why `strict=True` and the restriction to JSON-native scalars matter. NFC-before-everything removes the *normalization-form* ambiguity, but callers that legitimately need code points we forbid (e.g., newlines) must encode them out-of-band. The design chooses false-deny over false-allow throughout.

- **Lua string-compare timing residual.** The most sensitive comparison — the stored `SHA256(pin)` against the presented one — is performed in **constant time**: the script XOR-folds every byte of the two 64-char hex digests into a single difference accumulator with no early exit, so its running time is independent of where (or whether) the digests diverge and cannot leak the stored hash byte-by-byte. Even without this, the residual was *neutralized by what is stored*: the compared values are **SHA-256 hex digests**, not the secrets themselves; learning a prefix of `SHA256(pin)` confers no advantage in guessing the 6-digit PIN, because the hash is preimage-resistant and diffuse, and the online guessing budget is independently capped at four attempts by the self-destruct. The payload comparison retains Lua `~=`; the payload hash is not a secret (the caller supplies the payload it hashes), so its compare time carries no exploitable information. Where Python compares hex digests (WORM `verify_chain`), `secrets.compare_digest` is used to avoid even this residual on the verification path.

- **TTL trade-offs.** `PIN_TTL_SECONDS = 300` balances two failures: too long a TTL widens the window in which a captured-but-unspent lock could be brute-forced or a stale approval reused; too short a TTL breaks legitimate human-in-the-loop step-up that takes minutes. Five minutes with a four-guess online budget bounds the brute-force success probability to `4/10⁶` per lock while remaining usable. Operators for whom that is too generous can shorten the TTL or the attempt cap; the constants are the single source of truth.

- **Out-of-scope by construction.** MCPIP does not defend against compromise of the JWT or WORM signing keys, does not attest the correctness of the downstream executing system, and does not prevent a *correctly authorized* action from having undesirable business consequences — that is policy, upstream of authorization. Redis availability is assumed; a partition denies (fail-closed), trading availability for safety by design.

---

## 8. Related Work

We position MCPIP against several bodies of practice honestly and without inventing citations; references are to well-known generic technologies and standards, not to fabricated papers.

**IAM, OAuth 2.0, and token exchange.** Federated identity and delegated-authorization frameworks (OAuth 2.0 and its token-exchange extension, OpenID Connect, SPIFFE-style workload identity) authorize *principals* and *scopes*, and MCPIP reuses their strongest idea — signature-verified, claim-bearing bearer tokens with pinned algorithms — as its identity substrate (§5). Where MCPIP departs is granularity and time-binding: a scope grants a *class* of actions for a token lifetime, whereas the payload lock binds a *single specific payload* to a *single* execution. OAuth answers "may this client call this API?"; the payload lock answers "is this the exact call that was approved, and has it been used before?" The two are complementary layers, and MCPIP's identity sovereignty rule (hard-deny in-band identity, §5.2) is precisely the discipline that keeps the OAuth-style principal from being undermined by ambient payload fields.

**Capability gates are not authorization — the confused-deputy resurgence.** The classical confused-deputy problem — an over-scoped, privileged tool tricked by lower-privileged input into misusing authority it legitimately holds — re-emerged in 2026 as a top-severity agentic pattern. A Cloud Security Alliance research note on AI-agent confused-deputy prompt injection [likely] argues that *holding* a capability must not be conflated with being *authorized* to use it on a given target or payload. This is independent, third-party validation of MCPIP's thesis, point for point: identity derives exclusively from a verified JWT (§5.1); the `role` claim authorizes nothing; and — the exact point the 2026 discourse converges on — MCPIP binds the specific *payload* (§4.1), so even a correctly held capability cannot be redirected to a different target or amount without a fresh, payload-bound authorization. The framing is therefore precise and deliberate: **authorization is payload-bound, not capability-bound.** A scope- or capability-gate answers "may this principal ever call this tool?"; the payload lock answers "is *this exact call* the one that was approved?" — and it is the second question the confused-deputy attack turns on. (A separately circulating preprint advancing the same thesis was future-dated and unopenable at the time of the landscape review and is deliberately not cited; the CSA note is the sourced anchor.)

**Transaction signing and WYSIWYS in banking.** High-assurance banking has long used "What You See Is What You Sign" (WYSIWYS) transaction signing — dynamic linking of an authentication code to specific transaction data, as mandated for strong customer authentication in payment regulation, and realized by hardware tokens and out-of-band confirmation of transaction details. The payload lock is the agentic analogue: the six-digit nonce is *dynamically linked* to the canonical digest of the intent, so a code approved for one payload cannot authorize another. MCPIP generalizes WYSIWYS from a human confirming a displayed transaction to a gateway enforcing that the *bytes* of an action match the bytes that were approved, and adds exactly-once consumption and a machine-verifiable audit trail that hardware-token schemes typically leave to the backend.

**LLM guardrails and agent security.** A growing class of tooling filters LLM inputs/outputs for prompt injection, jailbreaks, and unsafe tool use via classifiers, allow/deny lists, and policy prompts. These operate probabilistically on *content* and degrade gracefully but do not *prove* anything about the executed action. MCPIP is deliberately not a classifier: it makes no judgment about whether an action is "good," only a deterministic, cryptographic judgment about whether the executed action is *identical to the authorized one* and *issued by the sovereign identity*. It is therefore composable beneath any such guardrail — the guardrail decides *whether* to approve; the payload lock enforces that approval against substitution and replay. The Unicode-smuggling defenses (§5.4) mirror mitigations popularized by source-code "Trojan Source" disclosures, applied here to tool-call arguments rather than program text.

**Pre-execution audit convergence — and what still stands alone.** Since these mechanisms were first implemented, independent efforts have arrived at MCPIP's audit *ordering*. AEGIS (arXiv 2603.12621, "No Tool Call Left Unchecked") [confirmed] describes a pre-execution firewall on the tool-execution path that holds high-risk calls for human approval and records every decision in an Ed25519 + SHA-256 hash-chained tamper-evident trail; the open-source `agentnotary` project [likely — its primary source was access-restricted at the time of the landscape review] canonicalizes the authorization decision into a tamper-evident pre-execution hash receipt. This convergence is a validation, not a threat: it confirms that committing a signed record *before* the side effect fires is the right primitive, and it means "signed pre-execution audit" is heading toward table-stakes rather than remaining a differentiator. It also exposes that "we hash before we run" *understates* what MCPIP does. Write-before-execute here is not a logging discipline but a composite of four inseparable properties: **(i) an inline, fail-closed gate** — the record is not a passive observation emitted alongside execution but the condition of execution; a failed WORM emit is a *deny*, not a dropped log line (§3.5 step 7 precedes step 8; the durable buffer is fsync'd before an action is authorized). **(ii) Payload-bound step-up** — the human approval that gates a high-risk call *is* the payload lock of §4, cryptographically bound to the exact intent bytes, not the role/action approval an AEGIS-style firewall holds. **(iii) Credential-brokering** — the gateway vends the short-lived downstream credential only on that same authorized path, so no standing credential exists for a bypassing caller to reuse. **(iv) Ordering** — the commit is *sequenced before* dispatch, never concurrently, so the log provably cannot have been fabricated after a bad outcome. Crucially, neither AEGIS nor `agentnotary` — nor, at the time of writing, any other system in the landscape review — describes the two mechanisms MCPIP leads on: the **opaque alias→target obfuscation** of §3.5/§7 (real system identifiers never cross the agent boundary, so an injected or compromised agent cannot even *name* the resource it would misuse) and the **payload-bound one-time PIN** of §4 itself. The defensible locus is therefore not "pre-execution audit" — that is converging — but obfuscation and payload-binding, which the (now-commoditizing) audit trail then renders provable.

The novel locus of MCPIP is the *intersection*: payload-level, exactly-once, atomically consumed authorization for autonomous machine-to-machine agent actions, with identity sovereignty and tamper-evident provenance, expressed as a provider-agnostic gateway.

---

## 9. Claims

The following numbered method claims describe the mechanisms in patent style. They are grounded in the reference implementation.

**Claim 1.** A computer-implemented method for authorizing an action proposed by an autonomous language-model agent, comprising: receiving a provider-formatted tool call and normalizing it into an internal intent comprising an alias and an arguments structure; resolving an acting identity *exclusively* from a cryptographically verified bearer token; computing a payload digest as a cryptographic hash over a canonical, deterministic serialization of at least the tenant identifier, agent identifier, alias, and arguments; and conditioning execution of the action on an atomic, server-side, single-operation comparison of a supplied nonce and the payload digest against previously stored values.

**Claim 2.** The method of Claim 1, wherein the canonical serialization comprises recursively normalizing every string to Unicode NFC, rejecting non-finite numbers, sorting object keys by Unicode code point, emitting without insignificant whitespace, and UTF-8 encoding, such that logically equal values produce byte-identical output across independent encoders.

**Claim 3.** The method of Claim 1, wherein said atomic comparison is performed by a single script executed on a single-threaded datastore such that a fetch of the stored record, comparison of the stored payload digest, comparison of a stored nonce hash, and deletion of the record on success occur as one indivisible unit with no intervening application-side read-then-act, thereby guaranteeing that a given stored authorization admits at most one successful execution under arbitrary concurrent invocation.

**Claim 4.** The method of Claim 3, wherein the script compares the payload digest *before* the nonce, such that a request whose payload does not match the stored digest is denied without incrementing an attempt counter and without deleting the stored authorization, while a request whose payload matches but whose nonce does not is counted toward an attempt limit and, upon reaching that limit, causes deletion of the stored authorization.

**Claim 5.** The method of Claim 1, wherein only a cryptographic hash of the nonce is persisted and the plaintext nonce is neither stored nor logged, and wherein the stored authorization is assigned a bounded time-to-live after which it is automatically invalidated.

**Claim 6.** The method of Claim 1, further comprising rejecting the request as an identity-injection attack, rather than ignoring or stripping, upon detecting — at any nesting level of the arguments structure and by case-insensitive key matching — any key drawn from a set of identity-shaped names, thereby preventing an in-band assertion from altering the acting identity established from the verified token.

**Claim 7.** The method of Claim 1, wherein verifying the bearer token comprises asserting, prior to signature verification, that the token's declared algorithm belongs to a pinned set excluding unsigned and symmetric algorithms, and requiring and verifying a fixed set of registered and private claims including expiry, issued-at, not-before, issuer, audience, tenant, agent, and role.

**Claim 8.** The method of Claim 1, further comprising validating every ingress field against a schema that forbids unknown fields at every nesting level, disables type coercion, and bounds container depth, key count, array length, per-string length, and total canonical size, and rejecting any string containing a control, bidirectional-override, isolate, or zero-width code point, with such rejection performed after Unicode NFC normalization.

**Claim 9.** The method of Claim 1, further comprising validating a delegation trace as a structurally verified chain in which the origin hop has no parent, each subsequent hop names as its parent the immediately preceding hop's agent, and each hop's index equals its position, and rejecting any request whose trace violates said structure.

**Claim 10.** The method of Claim 1, further comprising appending each authorization decision to an append-only log as a record comprising a monotonic sequence number, a previous-record hash, a redacted event, a record hash computed over the canonical serialization of the record, and a digital signature over the record hash, such that any alteration of any past record is detectable and localizable by re-verifying the hash chain and the signatures.

**Claim 11.** The method of Claim 1, wherein any parsing, validation, identity-resolution, or authorization failure denies the request and returns to the agent only a generic denial message and an opaque correlation identifier, while complete diagnostic detail including the denial reason is written solely to the append-only log of Claim 10.

**Claim 12.** The method of Claim 1, wherein all synchronization state comprising stored authorizations and log sequencing resides in a shared datastore such that the authorizing nodes hold no mutable authorization state and are horizontally interchangeable.

**Claim 13.** A system comprising one or more processors and memory storing instructions that, when executed, carry out the method of any of Claims 1–12, arranged as a four-stage pipeline that (a) normalizes provider-specific tool calls, (b) resolves tenant-scoped aliases to concrete targets while withholding said targets from the agent, (c) establishes sovereign identity and enforces the payload-bound authorization, and (d) records each decision immutably.

---

## 10. Conclusion

The gap that autonomous agents open in conventional authorization is not the ability to choose an action — models will always be able to propose — but the absence of a provable link between *what was approved* and *what executes*. MCPIP closes that gap with a single, sharp mechanism: a nonce bound to the canonical digest of an intent and consumed exactly once by an atomic, server-side operation over a single-threaded datastore. One byte of payload drift, one replayed approval, or one interleaved concurrent attempt cannot produce a second authorized execution. Around that core, identity sovereignty ensures the acting principal is never anything the agent can write; deep schema rigidity and Unicode hygiene ensure the payload is well-formed and smuggling-free before it is ever bound; and a hash-chained, signed WORM log ensures the entire decision history is non-repudiable and tamper-evident. The pipeline is provider-agnostic at ingress and transport-agnostic at egress, proven in the reference implementation across REST-cloud and legacy-mainframe targets, and stateless by construction so that authorization scales horizontally.

The philosophy is deliberately narrow: **AI Reasons. MCPIP Authorizes. Systems Execute.** MCPIP does not judge whether an action is wise — that is the province of policy and of the guardrails above it. It guarantees, cryptographically and atomically, that the action that runs is exactly the action that was authorized, by exactly the identity entitled to it, and that the fact is provable forever after. That guarantee is what makes it safe to let an autonomous agent touch a system of record at all.

---

*◐ MCPIP — Authorize every AI action before execution.*
