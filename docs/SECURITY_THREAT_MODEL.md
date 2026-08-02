# ◐ MCPIP — Security Threat Model

**The Authorization Layer for Autonomous AI**
*Authorize every AI action before execution.*
**AI Reasons. MCPIP Authorizes. Systems Execute.**

---

This document is the formal, code-anchored threat model for the shipping MCPIP engine
(`interfaces.py`, `auth/*`, `bridge/*`, `obfuscator/*`, `audit/*`) as exercised by the
standalone gateway (`main.py`, `MCPIPGateway.authorize_and_execute`) and by the FastAPI
edge (`app/main.py`, `POST /v1/authorize`). Every threat is stated as **adversary
capability → defending mechanism → the exact code that implements it**. Filenames,
functions, constants, and Lua are cited verbatim from source; nothing here describes a
control that is not in the tree.

> **Engine-accuracy note (this supersedes looser paraphrases elsewhere).** The payload
> lock is **SHA-256 over canonical JSON** for the *payload* binding and a **memory-hard
> `scrypt` digest salted per-lock** for the *PIN* — never a bare `sha256(pin)`. The
> in-Lua PIN comparison is **already constant-time** (a no-early-exit XOR-fold). Aliases
> are an **in-memory tenant-scoped map** (opaque, fail-closed), not a keyed HMAC. WORM
> signatures are **Ed25519**. There is no HMAC anywhere in the trust-critical path.

---

## 1. System under evaluation

MCPIP is a zero-trust authorization gateway that sits between an autonomous agent's
reasoning and the systems that execute. Every request walks four stages in a fixed order
— **◐ Bridge → Obfuscator → Auth → Audit** — and only an explicit ALLOW reaches a
transport. The canonical sequence is `MCPIPGateway.authorize_and_execute` (`main.py`
L186–263); the HTTP edge reproduces the identical sequence plus one staged-challenge
branch in `app/main.py` (`POST /v1/authorize`).

| Stage | Module | Guarantee |
|---|---|---|
| Bridge | `bridge/intent_parser.py` · `bridge/connectors/` | Any provider dialect → one `NormalizedIntent`; parser selected by the **declared** `source_format` / vendor (never sniffed); deep-strict schema; identity-injection hard-deny. |
| Obfuscator | `obfuscator/alias_registry.py` | Tenant-scoped `alias → target`; fail-closed on unknown / cross-tenant. |
| Auth | `auth/token_resolver.py`, `auth/pin_validator.py` | JWT-only sovereign identity; payload-bound, exactly-once PIN lock. |
| Audit | `audit/worm_logger.py`, `audit/merkle.py` | Hybrid Merkle-epoch WORM: durable Redis-Stream event buffer (write-before-execute) → per-epoch Merkle root, root-chained and Ed25519-signed once per epoch; `verify_chain` (any event OR root mutation) + O(log n) `inclusion_proof` tamper-evidence. |

### 1.1 Assets

1. **Downstream execution integrity** — no high-risk action runs unless a human-approved,
   payload-bound, single-use authorization is spent for *exactly that payload*.
2. **Identity sovereignty** — `tenant_id` / `agent_id` / `role` derive only from a verified
   token; the agent can never assert or alter them. `role` is **descriptive only** and
   authorizes nothing.
2b. **Capability/compartment authorization** — privileged actions and compartmented MCPs
   gate on **UUID capabilities/grants** (JWT `capabilities` claim + Redis grants), never a
   role string; an agent cannot enumerate or reach another team's compartment.
3. **Topology confidentiality** — real targets (`mainframe.cics.PAYR`, `aws.vpc.prod.db_drop`,
   …) never cross the agent boundary.
4. **Audit integrity** — the decision ledger is durable-before-authorize and tamper-evident
   (any event OR epoch-root mutation is detected).
5. **Availability** — a single malformed/oversized request cannot exhaust the node.

### 1.2 Trust boundaries

```
   UNTRUSTED                         │  TRUSTED (MCPIP)                    │  TRUSTED-ADJACENT
   ─────────────────────────────────┼────────────────────────────────────┼──────────────────
   LLM / agent tool-call            ═╪═► Bridge → Obfuscator → Auth        │  Redis (internal-
   (payload, trace, provider shape)  │        → Audit → Transport         ═╪═► only network)
                                     │                                     │
   JWT (bearer, agent-presented)    ═╪═► TokenResolver.resolve             │  IdP signing key
                                     │    (verify against trusted key)     │  (out-of-band)
                                     │                                     │
   PIN / OTP (step-up completion)   ═╪═► PinValidator.consume (Lua)        │  enrolled
                                     │                                     │  authenticator
```

The agent side of the double line is fully adversarial. Redis and the IdP/authenticator
are trusted components reached only over an internal-only network (`docker-compose.yml`,
`mcpip-internal: {internal: true}`); §11 covers what fails if that trust is violated.

### 1.3 Connector ingress posture

Three properties of the connector layer (`bridge/connectors/`) are load-bearing for this model:

- **Format is declared, never guessed.** The ingress selects a parser by an explicit
  `source_format` (or a vendor id resolved through the hash-pinned registry in
  `bridge/connectors/registry.py`) — never by inspecting payload bytes. Content sniffing is a
  consistency hazard (two components classifying the same bytes differently), the same
  discipline as pinning the JWT `alg`. Unknown/absent declarations are fail-closed denies
  (`unknown_format` / `unknown_vendor` in WORM; opaque on the wire).
- **Parsers are parser-only.** No connector holds an LLM/vendor key, calls an LLM/vendor API,
  or opens any outbound connection — the end user's client calls its LLM on its own
  keys/billing, and MCPIP receives only the resulting tool-call payload. This is mechanically
  enforced by the AST purity guard in `tests/test_connector_conformance.py` (fails on
  LLM-SDK / HTTP-client / `socket` / env-credential imports under `bridge/connectors/`).
- **The MCP edge is an authorization boundary, not a proxy.** `POST /v1/mcp` makes MCPIP the
  MCP server the client connects to; it never forwards to an upstream MCP server and opens no
  outbound connection — after ALLOW, dispatch uses the same internal transport table as
  `/v1/authorize`. There is no proxied third party to confuse, and gateway egress to any LLM
  vendor endpoint is by definition an incident.

---

## 1b. The security invariants

These seven hold on every request, or the request does not run. They are not guidelines: a
change that weakens one is rejected regardless of what else it improves. Every threat analyzed
in the rest of this document is ultimately a question about whether one of these still holds.

| # | Invariant | Mechanism | Enforced in |
|---|---|---|---|
| 1 | **Timing safety** | `secrets.compare_digest` for every token, hash, secret, and signature comparison. PIN and payload equality happen server-side inside the Lua `EVAL`, so there is zero Python check-then-act. | `interfaces.py`, `auth/*`, `audit/worm_logger.py` |
| 2 | **TOCTOU payload lock** | A 6-digit PIN bound to `sha256(canonical_json(tenant, agent, alias, arguments))`. Fetch, compare and delete happen in **one atomic Redis Lua `EVAL`**. Only the PIN hash is stored, never the raw PIN. One byte of payload drift is an instant `PAYLOAD_MISMATCH`. | `auth/pin_validator.py` |
| 3 | **Deep schema rigidity** | Every ingress model, including all nested ones, uses `ConfigDict(extra="forbid", strict=True)`. Depth ≤ 8, ≤ 64 keys per object, ≤ 256 elements per array, ≤ 16 KiB canonical arguments. Control characters, bidi overrides (`U+202A–202E`, `U+2066–2069`) and zero-width characters are rejected. | `interfaces.py`, `bridge/intent_parser.py` |
| 4 | **M2M identity sovereignty** | `tenant_id`, `agent_id` and `role` come exclusively from a verified JWT. `alg=none` and HMAC confusion are rejected; `exp`/`iat`/`nbf`/`iss`/`aud` plus the three identity claims are required. Any identity- or capability-shaped key in the tool-call payload is a **hard deny, not a strip**. The `role` claim is validated but descriptive only — it authorizes nothing. | `auth/token_resolver.py`, `bridge/intent_parser.py` |
| 4b | **Capabilities and compartments, never roles** | Privileged actions gate on capability **UUIDs** in the JWT `capabilities` claim (strict, size-bounded list) and Redis-held grants — never a role string. Compartmented aliases deny `compartment_denied` unless the caller holds a direct compartment claim or an active delegated grant, and `GET /v1/catalog` filters so another team's classified alias cannot even be enumerated. Grant issuance is itself an authorization-gated, payload-bound mandate. | `interfaces.py`, `auth/token_resolver.py`, `obfuscator/alias_registry.py`, `services/grant_store.py` |
| 5 | **Fail-closed, opaque errors** | Any parse, validation, lookup or lock failure denies immediately. The caller receives only a generic message plus a `correlation_id`. Full diagnostics go **only** to the WORM log — no stack traces, paths, key names, or topology leak. | `interfaces.py` (`MCPIPDenied`), `main.py` |
| 6 | **Stateless nodes** | All synchronization state — payload locks, the WORM event buffer, the monotonic sequence, the signed epoch chain, the event-location index, delegated grants, and the append/epoch locks — lives in Redis via `redis.asyncio`. No module-level mutable auth state. | `main.py`, `auth/pin_validator.py`, `audit/worm_logger.py`, `services/grant_store.py` |
| 7 | **Zero placeholders** | No TODO or FIXME, no stub bodies, no "rest of code". | entire codebase |

---

## 2. Adversary model

We assume a **strong, adaptive, in-band adversary**: a compromised, misaligned, or
prompt-injected agent that speaks the MCP/tool-call protocol fluently and controls every
byte it sends.

| Capability | Adversary HAS | Adversary does NOT have |
|---|---|---|
| Ingress payloads | Full control of `tool_call`, `arguments`, `trace`, `source_format`, `vendor`, `pin`, `challenge_id`. | Any influence over identity claims once a token is verified; any way to make the gateway *guess* a format it did not declare. |
| Tokens | Can present, replay, tamper, re-encode, or forge JWT bytes; can set any `alg`. | The IdP private key; ability to produce a valid EdDSA/RS256 signature. |
| Timing / oracles | Can measure response latency and status codes; can issue unlimited requests. | Any deny reason beyond the generic message + `correlation_id`. |
| Concurrency | Can fire many parallel/duplicate requests (replay, race). | A second valid consume of an already-spent lock. |
| Injection | Can embed bidi/zero-width/homoglyph/control text, deep/wide structures, identity-shaped keys. | A way to make the walker accept them. |
| Redis / disk | *Out of scope for the in-band model* — see §11 for the trusted-component compromise case. | Network reachability to Redis (internal-only). |

Out of scope: physical host compromise, a leaked IdP signing key, a compromised Redis with
attacker write access (addressed as residual risk in §11), and side channels below the
software layer.

---

## 3. Threat T1 — TOCTOU payload substitution between approval and execution

**Capability.** The adversary obtains a step-up approval for a benign payload
(`amount_cents: 100`), then swaps in a malicious payload (`amount_cents: 2418000`) at
execution time, hoping the approval still applies.

**Mechanism — canonical-JSON payload-bound lock, compared server-side inside one atomic
op.** The PIN is bound not to the *action* but to the *exact bytes* of the action. At
registration and at consumption the gateway computes the same
`lock_payload_hash(tenant_id, agent_id, alias, arguments)` =
`sha256_hex(canonical_json({tenant_id, agent_id, alias, arguments}))`. `canonical_json`
(`interfaces.py` L167) is byte-deterministic: recursive NFC normalization of every key and
value, `sort_keys=True`, `separators=(",",":")`, `allow_nan=False`, UTF-8. One byte of
drift anywhere in `arguments` yields a different hash. The stored `payload` hash is
compared **before** the PIN, entirely inside the Redis Lua script
(`LOCK_CONSUME_LUA`, `auth/pin_validator.py` L100): `if rec.payload ~= ARGV[2] then return
-3 end`. There is **no Python read-then-check-then-act** on lock state, so there is no
TOCTOU window: fetch → compare payload → compare PIN → delete is one server-side
transaction.

**Code.** `auth/pin_validator.py`: `lock_payload_hash` (L148), `_derive_pin_hash` (L65),
`LOCK_CONSUME_LUA` (L100), `PinValidator.register`/`consume` (L183/L236);
`interfaces.py`: `canonical_json` (L167), `sha256_hex` (L190). Gateway wiring:
`MCPIPGateway._consume_pin` maps `-3 → PAYLOAD_MISMATCH` (`main.py` L347). Demo proof:
gate 4, "payload byte-tamper", `main.py` L656–674 (and 4b proves the correct-payload retry
still consumes the surviving lock).

---

## 4. Threat T2 — Double-spend / approval replay

**Capability.** The adversary captures a valid `(pin, challenge_id, payload)` triple and
resubmits it — sequentially or as a concurrent burst — to execute the high-risk action
more than once.

**Mechanism — atomic, single-Lua, exactly-once consume.** Consumption is a single
`EVAL`/`EVALSHA` (`PinValidator.consume`, `auth/pin_validator.py` L236) of
`LOCK_CONSUME_LUA`. On a correct payload+PIN the script's terminal steps are
`redis.call('DEL', KEYS[1]); return 1` (L139–140): the lock is deleted in the *same* atomic
script that authorized it. **Redis executes each script to completion single-threaded**
(scripts are atomic w.r.t. all other Redis commands), so two concurrent consumes cannot
both observe the lock present — the first `DEL`s it, the second's `GET` returns `nil →
return -1 (NOT_FOUND)`. Exactly-once, payload-binding, and idempotency therefore all fall
out of the one primitive: the second identical call returns `-1`, mapped to
`PIN_NOT_FOUND` and an opaque 403. Registration uses `SET … nx=True` (L224) so an
astronomically unlikely `lock_id` collision fails closed rather than clobbering.

**Code.** `auth/pin_validator.py`: `consume` (L236), `LOCK_CONSUME_LUA` `DEL`/`return 1`
(L139), `register` NX guard (L224–232). Gateway: `-1 → PIN_NOT_FOUND` (`main.py` L343).
Demo proof: gate 3, "PIN replay", `main.py` L642–654. HTTP: `services/auth_engine.py`
`consume_and_execute` translates `-1 → GatewayDeny(PIN_NOT_FOUND)`.

---

## 5. Threat T3 — Prompt-injected payload mutation & smuggling

**Capability.** The adversary hides instructions or evades filters inside `arguments`:
right-to-left override / bidi text, zero-width joiners, control characters, homoglyph
identity keys, or a pathologically deep/wide/large structure that also serves as a parser
DoS.

**Mechanism — deep-strict Pydantic v2 + a recursive safety walker with hard caps.** Every
ingress model sets `ConfigDict(extra="forbid", strict=True)`, repeated on **every nested
model** (`Hop`, `SwarmTrace`, `NormalizedIntent`, `Identity`, `AuthorizedIntent`,
`TransportResult` in `interfaces.py`; the per-provider models in `bridge/intent_parser.py`).
`NormalizedIntent._validate_arguments` (`interfaces.py` L363) routes every payload through
`enforce_argument_safety` → `_walk` (`bridge/intent_parser.py` L215/L144), which enforces,
per node:

- **Depth** ≤ `MAX_ARG_DEPTH=8` → `DepthExceeded` (L165).
- **Keys/object** ≤ `MAX_ARG_KEYS=64`, **elems/array** ≤ `MAX_ARG_ARRAY=256`, aggregate
  **nodes** ≤ `MAX_ARG_NODES` → `SizeExceeded` (L169/L192/L103).
- **Canonical bytes** ≤ `MAX_CANONICAL_BYTES=16384` after the walk (L238).
- **Char safety** — every string (keys *and* values) passes `reject_unsafe_string`
  (`interfaces.py` L102): NFC-normalize, then reject C0/C1 controls (`0x00–0x1F`,
  `0x7F–0x9F`), bidi embeddings/overrides (`0x202A–202E`), bidi isolates (`0x2066–2069`),
  and the enumerated zero-width set (`_ZERO_WIDTH`), then cap `MAX_STRING_LEN=4096`.
- **Scalar-leaf typing** — only `{str,int,float,bool,None}`; `NaN`/`Inf` rejected (L205);
  any non-JSON-native leaf fail-closed (L212).

The walk **returns the NFC-normalized form**, so no non-canonical text survives downstream.
A pre-parse byte gate (`MAX_RAW_ARGUMENTS_BYTES = 4 × MAX_CANONICAL_BYTES`, enforced by the
OpenAI `arguments: str` `max_length`, L260) rejects a multi-MB raw string *before*
`json.loads` allocates it.

**Code.** `bridge/intent_parser.py`: `_walk` (L144), `enforce_argument_safety` (L215),
`_NodeCounter` (L93), `MAX_RAW_ARGUMENTS_BYTES` (L79); `interfaces.py`:
`reject_unsafe_string` (L102), `_FORBIDDEN_RANGES`/`_ZERO_WIDTH` (L72/L84). Deny mapping:
`MCPIPGateway._normalize` + `_classify_validation_error` (`main.py` L276–303) →
`SCHEMA_VIOLATION` / `DEPTH_EXCEEDED` / `SIZE_EXCEEDED` / `ILLEGAL_CHARACTER`. Demo proof:
gate 5, `main.py` L686–697.

---

## 6. Threat T4 — Confused-deputy identity injection

**Capability.** The adversary embeds identity-shaped keys in `arguments`
(`{"tenant_id":"victim-corp"}`, `{"role":"admin"}`, or a homoglyph/fullwidth variant such
as `ｔｅｎａｎｔ＿ｉｄ`) to make MCPIP act under an identity it did not verify.

**Mechanism — JWT-only identity sovereignty + hard-deny of in-band identity keys.**
`NormalizedIntent` deliberately carries **no** identity fields; the only identity in the
pipeline is the frozen `Identity` returned by `TokenResolver.resolve`. Any identity-shaped
key anywhere in `arguments` is a **hard deny, never a strip**: `_walk` tests every object
key via `_identity_fold(key) in _FORBIDDEN_IDENTITY_KEYS` **before** any other per-key
processing (`bridge/intent_parser.py` L181). `_identity_fold` (L127) applies **NFKC** then
`casefold`, so fullwidth/compatibility homoglyphs collapse onto the ASCII forbidden set —
`tenant_id, agent_id, role, tenant, actor, principal, identity, sub` plus the
authorization-claim names `capabilities, capability, entitlement, entitlements, grants` (an
agent must never smuggle its own entitlements in-band; authorization derives EXCLUSIVELY
from the verified JWT `capabilities` claim / Redis grants) — and cannot slip past
it. A match raises `IdentityInjection` → `DenyReason.IDENTITY_INJECTION`. (`compartment` is
intentionally NOT forbidden: it is a legitimate business argument — the *target*
compartment of a grant mandate — and is provably inert for identity, since the caller's own
compartment comes only from the JWT.) Because `Identity`
is `frozen=True` (`interfaces.py` L386), a verified identity cannot be mutated anywhere
downstream.

**Code.** `bridge/intent_parser.py`: `_FORBIDDEN_IDENTITY_KEYS` (L113), `_identity_fold`
(L127), the guard in `_walk` (L181); `interfaces.py`: `Identity` frozen (L379). Deny map:
`main.py` L282. Demo proof: gate 8, `main.py` L723–733.

---

## 7. Threat T5 — Forged, `alg=none`, and HMAC-confusion tokens

**Capability.** The adversary tampers with a token's payload after signing, submits an
unsigned `{"alg":"none"}` token, or mounts the classic RS256→HS256 key-confusion attack
(sign with HMAC using the RSA public key as the shared secret and set `alg=HS256`).

**Mechanism — algorithm pinning + full claim verification, defense-in-depth.**
`TokenResolver.resolve` (`auth/token_resolver.py` L105) first reads the header **without
trusting it** and rejects anything outside `ALLOWED_ALGORITHMS=("EdDSA","RS256")`
(L124–127) — this alone kills `none`, `HS256/384/512`, and any unlisted alg *before* a key
is ever selected. It then calls `jwt.decode` with `algorithms=list(self._algorithms)` (a
second, independent pin inside PyJWT), `verify_signature=True`, and a `require` list of all
eight `REQUIRED_CLAIMS` with `verify_exp/iat/nbf/aud/iss=True` matched to configured
`issuer`/`audience`. A tampered payload fails signature verification →
`InvalidTokenError → TokenError → JWT_INVALID`; a missing claim →
`MissingRequiredClaimError → TokenClaimsMissing → JWT_CLAIMS_MISSING`. Verified claims are
projected into a frozen `Identity`; `_require_str` (L180) re-asserts non-empty string type
on the three identity claims.

**Code.** `auth/token_resolver.py`: `ALLOWED_ALGORITHMS` (L34), `REQUIRED_CLAIMS` (L37),
header allow-list (L124), `jwt.decode` options (L134–150), `_require_str` (L180). Deny map:
`main.py` L267–274. Demo proof: gate 6 forged signature (L699–709) and gate 7 `alg=none`
(L711–721), both `JWT_INVALID`.

---

## 8. Threat T6 — Alias brute-force, hallucinated tool calls, cross-tenant reach

**Capability.** The adversary guesses target names, invents aliases the model
"hallucinated," or — holding a valid token for tenant A — names an alias owned only by
tenant B to reach across the tenant boundary.

**Mechanism — fail-closed, tenant-scoped registry; opaque aliases only.** The agent never
names a real target; it names an opaque alias, and `AliasRegistry.resolve(tenant_id, alias)`
(`obfuscator/alias_registry.py` L71) is the sole resolver. It looks up the alias **only in
the caller's tenant map**; a miss that exists for *someone* raises `CrossTenant`
(`CROSS_TENANT`), a miss that exists for *no one* raises `UnknownAlias` (`UNKNOWN_ALIAS`) —
and **neither reason ever crosses the boundary** (§9), so the agent cannot even distinguish
"wrong tenant" from "nonexistent," denying it a discovery oracle. Hallucinated/guessed
aliases therefore yield an opaque 403 with zero topology signal. The registry is immutable
configuration (`build_demo_registry`, L99), shared safely across stateless nodes.

**Timing-uniform denial (no latency existence oracle).** A *compartment*-denied alias reaches
`_compartment_gate`, which spends one Redis grant `GET` before denying, whereas an unknown /
cross-tenant alias short-circuits at resolution **without** that `GET`. That ~one-round-trip
gap would be a cross-compartment existence oracle — distinguishing "a classified alias exists
in a compartment I can't see" (slower) from "this alias does not exist" (faster) despite
identical opaque bodies. `app/main.py::_resolve_alias` closes it: a resolution miss performs an
equivalent **decoy** grant `GET` against a fixed synthetic compartment that can never hold a
grant (the same nil-return round trip), so both denials cost the same Redis work.

**Code.** `obfuscator/alias_registry.py`: `resolve` (L71), `_known_aliases` discrimination
(L86–89), `build_demo_registry` (L99). Deny map: `main.py` L305–312. Demo proof: gate 9
unknown alias (L735–745), gate 10 cross-tenant (globex → `skill_payroll_run`, L747–760).

---

## 9. Threat T7 — Audit tampering, deletion, or reordering

**Capability.** The adversary (or a later insider) edits a decision record, reorders lines,
inserts a forged record, or drops a line to erase evidence.

**Mechanism — hybrid Merkle-epoch WORM with a full re-verification pass.** Each decision is
first **durably buffered** to a Redis Stream (`mcpip:worm:events`) — under Redis AOF
`appendfsync always` the `XADD` is fsync-durable **before** `emit` returns, and an action is
authorized only after `emit` returns, so no authorized decision's event can be lost
(write-before-execute / fail-closed). Each buffered leaf commits to
`leaf_digest = sha256(DOMAIN_LEAF ‖ canonical_json({event_id, seq, timestamp_ns, event}))`.
A ~1s background daemon (`close_epoch`) closes an **epoch**: it builds a Merkle tree over the
epoch's *contiguous* seq range, chains the new `merkle_root` to the previous epoch's
`epoch_hash` (`"GENESIS"` at epoch 0), and **Ed25519-signs** the epoch hash — **one signature
per epoch**, not per event (2.9× emit throughput vs. the per-event chain). Domain-separated
leaf/node/epoch prefixes make a leaf digest unequal to any internal-node digest (second-
preimage / CVE-2012-2459 defense; the signed header also commits to `leaf_count` and
`[start_seq, end_seq]`, so no externally supplied tree shape is trusted).

`verify_chain` returns `(False, first_bad_epoch)` on the first epoch whose: root-chain
linkage, contiguous coverage (`start(n+1)=end(n)+1`), recomputed Merkle root, recomputed
`epoch_hash`, or Ed25519 signature fails — the recompute is wrapped so a *malformed* header or
event reports tamper at its epoch rather than crashing the verifier. A mutated event fails its
epoch's Merkle root; a mutated/removed/reordered/forged epoch header fails linkage/hash/
signature; a removed event shifts `leaf_count`/coverage.

**Rollback / tail-truncation defense (out-of-tamper-domain anchor).** An in-place mutation is
caught by the checks above, but a rollback — delete the newest signed epoch header(s) *and*
their buffered events, then rewrite the four **plaintext** in-Redis linkage counters
(`epoch:{num,head,last_seq}`, `cursor`) back to a prior *still validly-signed* epoch — leaves the
surviving prefix internally consistent. Because those counters share the tamper domain with the
headers they would otherwise anchor, an anchorless verify reports `intact`. `AnchorStore`
(`audit/anchor.py`) closes this: each `close_epoch` **also** appends one Ed25519-signed
`(epoch, epoch_hash)` line to an fsync'd, append-only file on durable storage **outside** Redis
(the volume the Redis attacker cannot rewrite), *after* the in-Redis header is durable.
`verify_chain` reads the highest validly-signed head from there and enforces it as a **monotonic
low-watermark**: the surviving chain must reach **at least** the witnessed epoch with the
identical `epoch_hash`. A chain that stops **short** (W9 rollback) or presents a **different**
hash at the witnessed epoch (substitution) is tamper; a delete-**all**-headers erasure (W8) is
tamper whenever the anchor (or the counters) witnessed any sealed epoch; a chain legitimately
**ahead** of a lagging anchor (crash between header-write and anchor-append) stays intact. The
attacker cannot forge a higher/substitute anchor (no signing key) and cannot lower the watermark
by deleting anchor lines any more than by deleting Redis headers. `inclusion_proof(event_id)` yields an
O(log n) Merkle path to the signed root (both detection cases and both proof cases are exercised
by the tamper probe). Concurrent closes serialize behind a Redis lock (`_RedisAppendLock`,
`SET NX PX` + atomic CAS release `_RELEASE_LUA`). Secrets never reach the log: `_redact`
replaces the value of any case-folded key in
`_REDACT_KEYS = {pin, jwt, token, authorization, password, secret}` with `"[REDACTED]"` before
write. The legacy per-event Ed25519 straight chain remains available behind `mode="per_event"`
for migration.

**Crash-safety.** A crash between `emit` and the next epoch close loses only the not-yet-signed
root: on restart the daemon re-reads all epoch-unassigned events (`seq > last_seq`) from the
durable stream and re-closes deterministically (the Merkle root is a pure function of the
ordered leaves, so re-close is idempotent). Coverage is contiguous seq ranges, so there is no
inter-epoch gap even across crashes.

**Code.** `audit/worm_logger.py`: `emit`, `close_epoch`, `verify_chain`, `inclusion_proof`,
`_redact`; `audit/merkle.py`: domain-separated `leaf_digest`/`node_digest`/`merkle_root`/
`inclusion_proof`/`verify_inclusion`; Redis keys `mcpip:worm:{seq,events,epochs,eventloc,
epoch:num,epoch:head,epoch:last_seq,epoch:lock}`. Gateway funnel: `_emit_deny` is the **only**
place a concrete reason is recorded (`main.py`); `_safe_emit` converts a WORM/Redis outage into
a fail-closed `MCPIPDenied` and a last-resort stderr line. Demo proof: gate **C9**
`close_epoch → verify_chain → (True, None)` plus every event's inclusion proof verifying.

---

## 10. Threat T8 — Error-oracle leakage · Threat T9 — Denial of service

### T8 — Error-oracle leakage

**Capability.** The adversary mines error text, stack traces, key names, timing, or status
codes to learn topology, why a request failed, or a stored secret.

**Mechanism — opaque, fail-closed boundary + one correlation id.** The only exception that
crosses the boundary is `MCPIPDenied` (`interfaces.py` L443), carrying **only** a `uuid4`
`correlation_id`; the agent-facing string is the fixed
`AGENT_FACING_DENY_MESSAGE = "MCPIP: request denied by policy."`. Every concrete
`DenyReason`, detail, target, and stack trace exists solely in the WORM record written by
`_emit_deny`. In `MCPIPGateway.authorize_and_execute` a single `except _Deny` choke point
(`main.py` L250) logs then raises the opaque error; a catch-all `except Exception` maps any
unforeseen error to `INTERNAL` and still denies opaquely (L258). The HTTP edge registers
exception handlers so **no** stack trace escapes: `MCPIPDenied → 403 ErrorResponse`,
`RequestValidationError → 422`, catch-all `Exception → 500`, each with only
`error` + `correlation_id`, echoed in `X-MCPIP-Correlation-Id`. The receipt returns
`executed_target_class` (the coarse transport class), **never** `entry.target`. Response
timing is not a usable oracle: identity/hash/PIN comparisons funnel through
`secrets.compare_digest` (`constant_time_equals`) and the in-Lua XOR-fold (§11).

**Code.** `interfaces.py`: `MCPIPDenied` (L443), `AGENT_FACING_DENY_MESSAGE` (L59);
`main.py`: choke point (L250–263), `_safe_emit` (L384); `app/main.py`: exception handlers +
correlation-id middleware; `models/schemas.py`: `ErrorResponse`, `executed_target_class`
transport-class-only; `core/security.py`: `map_engine_exception`, `new_correlation_id`.

### T9 — Denial of service

**Capability.** The adversary sends a huge, deeply nested, or wide payload, or many step-up
registrations, to exhaust CPU/memory or wedge the node.

**Mechanism — size/depth pre-gates and bounded TTLs.** The pre-parse `max_length` on the
OpenAI `arguments` string (`MAX_RAW_ARGUMENTS_BYTES`) rejects oversized raw input before
`json.loads`. Inside the walk, `MAX_ARG_DEPTH`, `MAX_ARG_KEYS`, `MAX_ARG_ARRAY`, and the
aggregate `MAX_ARG_NODES` counter bound total work regardless of shape, and the post-walk
`MAX_CANONICAL_BYTES` bounds the hashed payload. Locks carry `PIN_TTL_SECONDS=300` and
self-destruct after `PIN_MAX_ATTEMPTS=5` wrong PINs, so registrations cannot accumulate
unboundedly. The WORM append-lock has a 5 s fail-safe TTL and a 10 s bounded acquisition
(`_RedisAppendLock`), so a crashed holder can never wedge appends. Nodes are stateless
(all sync state in Redis), so the edge scales horizontally behind a load balancer.

**Code.** `bridge/intent_parser.py`: `MAX_RAW_ARGUMENTS_BYTES` (L79), `_NodeCounter.bump`
(L101); `interfaces.py`: the limit constants (L48–56); `auth/pin_validator.py`: TTL +
attempt lockout in `register`/`LOCK_CONSUME_LUA` (L224/L126); `audit/worm_logger.py`:
`_RedisAppendLock` TTL/bound (L261/L267).

---

## 11. Attack → defense → code-location matrix

| # | Attack | Adversary capability | Defending mechanism | Code location (file · symbol) |
|---|---|---|---|---|
| T1 | TOCTOU payload substitution | Swap payload after approval | Canonical-JSON payload hash, compared server-side before PIN in one atomic Lua | `auth/pin_validator.py` · `lock_payload_hash`, `LOCK_CONSUME_LUA` (`-3`); `interfaces.py` · `canonical_json` |
| T2 | Double-spend / replay | Resubmit valid triple (serial or concurrent) | Single-Lua consume-and-`DEL`; Redis single-threaded script atomicity; second call `-1` | `auth/pin_validator.py` · `PinValidator.consume`, `LOCK_CONSUME_LUA` (`DEL`/`return 1`) |
| T3 | Payload mutation / smuggling | Bidi/zero-width/control/deep/wide/oversize | Deep-strict Pydantic + `_walk`; NFC + char reject; depth/key/array/node/byte caps | `bridge/intent_parser.py` · `enforce_argument_safety`, `_walk`; `interfaces.py` · `reject_unsafe_string` |
| T4 | Confused-deputy identity injection | Identity-shaped keys (incl. homoglyphs) in args | JWT-only identity; NFKC-casefold hard-deny of forbidden keys; frozen `Identity` | `bridge/intent_parser.py` · `_FORBIDDEN_IDENTITY_KEYS`, `_identity_fold`; `interfaces.py` · `Identity(frozen)` |
| T5 | Forged / `none` / HMAC-confusion JWT | Tamper, unsigned, or HS-confusion tokens | Header alg allow-list + PyJWT `algorithms=` pin; 8 required claims; iss/aud/exp/iat/nbf | `auth/token_resolver.py` · `TokenResolver.resolve`, `ALLOWED_ALGORITHMS`, `REQUIRED_CLAIMS` |
| T6 | Alias brute-force / hallucination / cross-tenant | Guess targets or name another tenant's alias | Fail-closed tenant-scoped registry; opaque aliases; no discovery oracle | `obfuscator/alias_registry.py` · `AliasRegistry.resolve` (`UnknownAlias`/`CrossTenant`) |
| T6b | Cross-compartment reach / role-escalation | Reach a compartmented MCP, forge a role, or self-issue a grant | UUID compartment/capability gates (never role); direct-claim or active-grant entitlement; grant issuance is a payload-bound EXECUTE mandate requiring `CAP_COMPARTMENT_GRANT`; catalog filtering | `interfaces.py` · `Identity.capabilities`; `main.py`/`app/main.py` · `_compartment_gate`/`_mandate_gate` (`COMPARTMENT_DENIED`/`CAPABILITY_DENIED`); `services/grant_store.py` |
| T7 | Audit tamper / delete / reorder / rollback | Edit, insert, drop, reorder, or tail-truncate + counter-rewrite records | Merkle-epoch: per-epoch signed root, root-chained; `verify_chain` first-bad-epoch (event OR root mutation); **out-of-tamper-domain Ed25519-signed head anchor** (`AnchorStore`) as a monotonic low-watermark catching rollback/erasure; O(log n) inclusion proofs; durable-before-authorize buffer; Redis close-lock; secret redaction | `audit/worm_logger.py` · `WormLogger.emit`/`close_epoch`/`verify_chain`/`inclusion_proof`; `audit/anchor.py`; `audit/merkle.py` |
| T8 | Error-oracle leakage | Mine errors/timing/status/targets | `MCPIPDenied` + fixed message + `correlation_id`; opaque HTTP handlers; transport-class-only receipt; constant-time compares | `interfaces.py` · `MCPIPDenied`, `AGENT_FACING_DENY_MESSAGE`; `main.py` · choke point/`_safe_emit`; `app/main.py` · handlers; `models/schemas.py` · `executed_target_class` |
| T9 | Denial of service | Oversize/deep/wide payloads; lock flooding | Pre-parse byte gate; walk caps + node counter; canonical-byte ceiling; lock TTL + 5-attempt self-destruct; append-lock TTL | `bridge/intent_parser.py` · `MAX_RAW_ARGUMENTS_BYTES`, `_NodeCounter`; `auth/pin_validator.py` · `PIN_TTL_SECONDS`/`PIN_MAX_ATTEMPTS`; `audit/worm_logger.py` · `_RedisAppendLock` |
| T11 | Authenticator-delivery abuse — SSRF via the webhook sink **and** OTP exposure | Point the tenant webhook at an internal address (cloud metadata / loopback / RFC1918) or rebind DNS after validation to exfiltrate the pushed code; or read a raw OTP at rest | Delivery is a seam strictly DOWNSTREAM of the unchanged mint+register (never touches OTP derivation/binding). Production `WebhookAuthenticatorChannel`: **https-only**; resolve host and refuse if ANY resolved address is private/loopback/link-local (`169.254.169.254`)/reserved/multicast/unspecified (IPv4-mapped unwrapped); connection **pinned to the validated IP** (SNI/cert = original host) to defeat DNS-rebinding TOCTOU; **hermetic client (`trust_env=False`, `proxy=None`)** so an ambient `HTTPS_PROXY`/`SSL_CERT_FILE`/`SSLKEYLOGFILE` can neither reroute the OTP push through an unvalidated intermediary nor void the IP-pin/TLS-verify; `follow_redirects=False`; bounded timeout (`MIN/MAX_AUTHN_WEBHOOK_TIMEOUT_S`); 2xx-or-raise with bounded response read (`MAX_AUTHN_WEBHOOK_RESPONSE_BYTES`); HMAC-SHA256 over `ts + "." + body` (secret raw-bytes, never logged/labeled/in body). **No OTP persisted in prod** (sandbox stash is a distinct `SandboxRedisAuthenticatorChannel`, sandbox-only; `otp` also in WORM `_REDACT_KEYS`). Fail-closed: no channel / any `deliver` failure → `otp_delivery_failed` BEFORE any `202`/`challenge_id`. Prod requires BOTH url + ≥32B secret (half-config ⇒ boot refusal). | `services/authn_channel.py` · `WebhookAuthenticatorChannel.deliver`/`_resolve_and_validate`/`_is_blocked_ip`, `SandboxRedisAuthenticatorChannel`; `services/auth_engine.py` · `register_lock` (`GatewayDeny(OTP_DELIVERY_FAILED)`); `app/main.py` · `_build_authn_channel`/`_load_authn_webhook_secret`; `interfaces.py` · `AuthenticatorNotice`, `BaseAuthenticatorChannel`, `DenyReason.OTP_DELIVERY_FAILED` |
| T12 | Policy-overlay fail-open / evasion | Break the velocity/amount limiter open (Redis down, malformed stored doc, raising provider), smuggle an over-ceiling amount as a non-number, or turn a policy result into an allow | **Deny-only is structural:** `PolicyDecision` has no allow/override outcome — the gate treats only `deny` as actionable and raises `policy_denied`; `PolicyContext` is frozen with no target/identity handle (can't mint identity or mutate intent/target). Both the gate (`try/except → POLICY_DENIED`) and the engine (converts its own errors to a `deny`) **fail closed** — Redis error / malformed doc / raising provider all deny. Amount compared as `Decimal` (no float drift); a present non-numeric value is refused, not coerced; pure amount check runs before the state-mutating velocity `INCR`. No document ⇒ no limits (opt-in, no fabricated default). Keys tenant-prefixed from JWT tenant only (no cross-tenant collision). Reason is DISTINCT from `RATE_LIMITED`; concrete cause rides only in WORM `detail`, never a metric label. | `services/policy_engine.py` · `VelocityAmountPolicyEngine.evaluate`/`_check_amount`/`_check_velocity`, `PolicyDocStore.load`; `main.py` · `_policy_gate`; `app/main.py` · `_run_authorize_pipeline` step 5b; `interfaces.py` · `PolicyContext`/`PolicyDecision`/`PolicyProvider`, `DenyReason.POLICY_DENIED`, `MAX_POLICY_RULES`/`MAX_POLICY_DOC_BYTES` |
| T10 | Forensic-payload exposure vs. the opaque wire | Investigator needs the real query the opaque wire + arguments-omitting feed hide; **or** an attacker (incl. a directory-admin) reads another principal's captured payloads | Capture is a best-effort side-channel fired AFTER the authoritative WORM emit (never blocks/reorders/flips a decision); snapshot runs through WORM `_redact` and excludes pin/jwt/proof/vended-credential/identity keys (secrets never captured); AES-256-GCM at rest under a dedicated key OUTSIDE Redis with `(tenant, correlation_id)` length-prefixed AAD (ciphertext-only, no cross-tenant/exists-elsewhere oracle); retrieval is DISTINCT-capability-gated (`CAP_FORENSIC_READ` ≠ `CAP_DIRECTORY_ADMIN`, constant-time), kill-switch-enforced, tenant-scoped, opaque `404`, and WORM-audited **before** disclosure; capture OFF-by-default in prod + requires the 32-byte key file (flag-alone ⇒ absent, never plaintext); agent wire stays opaque | `services/forensic_store.py` · `ForensicCaptureStore.capture`/`retrieve`; `app/main.py` · `_capture_forensic`, `_require_forensic_read`, `forensic_read` (`GET /v1/admin/forensic/{id}`); `interfaces.py` · `CAP_FORENSIC_READ`, `FORENSIC_TTL_SECONDS`, `MAX_FORENSIC_PAYLOAD_BYTES` |
| T13 | Community-skill overlay abuse (repoint · privileged transport · restricted-AUTO exfil · rug-pull · forged approval) | A Contributor authors a manifest that repoints an existing alias, targets a privileged transport (`legacy_mainframe`/`grant_issue`/`cloud_iam`), smuggles a `restricted`-classification AUTO read (stolen-bearer exfil), poisons a reviewer with a bidi/homoglyph/identity-shaped field, swaps the manifest after approval, or forges an approval record | A community skill is inert declarative data minted only through the SAME hardened overlay path as `register_skill`, re-validated fail-closed at approve: **additive-only** (`registry.has_alias` refuses any alias that already resolves — no repoint), **`cloud_rest`-only** (transport is the pinned literal — privileged transports unreachable), `_overlay_skill_invalid` forces **`restricted ⇒ pin_required`** (no bearer-exfil AUTO read) + charset/enum shape, and the manifest self-pin over `canonical_manifest_bytes` is **distinct from the payload-lock `canonical_json`** (no lock hash recomputed). `reject_unsafe_string` + `_identity_fold` hard-deny on `id`/`author`/`alias` block tool-description poisoning + identity-shaped keys. **Approval is WORM-logged BEFORE apply** (write-before-execute → hash-chained, Ed25519-epoch-signed, non-repudiable; `verify_chain`/anchor catch forgery). **Rug-pull:** `_hydrate_catalog_overlay` re-verifies the pinned manifest AND cross-checks the overlay fields on every boot-load, skipping any mismatch (re-review required). Tenant comes only from the JWT (cross-tenant approve structurally impossible); the submitter-declared `target` is a reviewer-only surface, never on the agent wire; `CAP_CATALOG_REVIEWER` is a DISTINCT capability (`role` authorizes nothing) | `services/extension_manifest.py` · `ExtensionManifest`/`parse_manifest`/`verify_manifest_pin`; `services/extension_submissions.py` · `ExtensionSubmissionStore`; `app/main.py` · `submit_extension`, `approve_extension`/`reject_extension`, `_overlay_skill_invalid`, `_apply_overlay_skill`, `_hydrate_catalog_overlay`/`_community_pin_valid`, `_require_catalog_reviewer`; `core/integrity.py` · `canonical_manifest_bytes`; `interfaces.py` · `CAP_CATALOG_REVIEWER`, `MAX_PENDING_SUBMISSIONS` |
| T14 | Community-gate seam turned into a bypass or a topology oracle | A user-authored gate (Phase 2) tries to turn a DENY into an ALLOW, read the hidden `target`/secrets, run arbitrary code / dial out, loop / timing-oracle, or be approved and enforced without a safety proof | **Deny-only / monotonic is structural:** `GateDecision` has no allow/override outcome — the seam (step 4c′, `_community_gate`, identical in `main.py` + `app/main.py`) treats only `deny` as actionable and raises `policy_gate_denied`; it can only ever ADD a deny, never rescue an earlier one, mint identity, or mutate the intent/target/arguments. Context is the topology-free `CommunityGateContext` = exactly `GATE_CONTEXT_FIELDS` (opaque alias + coarse transport class + risk tier + classification — **no target, no secrets, no arguments, no identity handle**); a manifest's `referenced_context_fields` MUST be a subset. `evaluate()` is wrapped `try/except → policy_gate_denied` so a raising/buggy provider **fails closed**. The default `NoOpCommunityGateProvider` is a strict NO-OP — the honest "no community gate engine configured" state, never a fabricated pass. The CEL runtime is DEFERRED (no `celpy` import anywhere), so **gate APPROVAL is fail-closed: no approve-without-proof** — a gate stays PENDING and un-enforced until an engine (which bundles the static cost/whitelist prover) is registered; `POLICY_GATE_DENIED` is DISTINCT from `POLICY_DENIED`/`RATE_LIMITED` and its cause rides only in WORM `detail`, never a metric label | `services/community_gate.py` · `NoOpCommunityGateProvider`, `active_community_gate_provider`/`community_gate_engine_registered`; `services/extension_manifest.py` · `GateManifest`/`parse_gate_manifest`; `main.py`/`app/main.py` · `_community_gate` (step 4c′), `approve_extension` (gate-refuse); `interfaces.py` · `CommunityGateContext`/`GateDecision`/`CommunityGateProvider`, `GATE_CONTEXT_FIELDS`, `MAX_GATE_COST`, `DenyReason.POLICY_GATE_DENIED` |
| T15 | ReBAC relation-tuple projection weakening authorization, leaking topology, or blowing up the walk | An attacker hopes the new relation layer becomes a second (softer) authz source, that a projection blip rescues a denied call, that the console read leaks a hidden target/secret, that a wildcard tenant id widens the SCAN cross-tenant, or that a crafted/nested tuple set turns the closure `check` into an unbounded CPU/timing walk | **Strictly additive projection, never an authorization source:** the pipeline NEVER consults the tuple layer — `GrantStore.issue`/`has_active_grant`/`revoke`, the payload lock, and WORM are byte-for-byte unchanged; the capability-UUID + grant gates remain the SOLE authority. The tuple is written ONLY after the authoritative grant `.set()` succeeds and `project_member`/`remove_member` **swallow every `RedisError` and never raise into the grant path** (a projection outage degrades only the Knowledge-Graph, never a decision); `relations=None` ⇒ `GrantStore` behaves exactly as before. `EX=ttl` MIRRORS the grant so even a dropped revoke-remove self-heals at grant expiry (the projection can never outlive its grant). The read (`GET /v1/admin/directory/relations`) is `CAP_DIRECTORY_ADMIN`-gated, tenant-scoped, **glob-escaped** (`_glob_escape` — a wildcard tenant id can't widen the SCAN), bounded by `MAX_RELATION_ROSTER`, and **fail-soft** (`[]` — it backs a listing, never a decision). Tuples carry only operator-facing ids + non-secret grant metadata — never a target, secret, PIN/OTP, or alias→target mapping. `check` is a **hop-capped (`MAX_RELATION_DEPTH`) + fanout-capped (`MAX_RELATION_FANOUT`) BFS, fail-closed** on any cap hit / unknown relation / Redis error (returns `False`, never walks further) — the caps are STRUCTURAL for future nesting so the walk can never become a CPU/timing oracle; if ever promoted to the hot path the documented rule keeps it deny-only/additive. Parity untouched: `_key` is plain f-string interpolation, shares nothing with `canonical_json`/`enforce_argument_safety`/the scrypt PIN-hash. Metric `mcpip_relation_projection_total{event}` is a closed enum — no caller data in a label. | `services/relation_store.py` · `RelationTupleStore.project_member`/`remove_member`/`list_relations`/`check`/`_key`; `services/grant_store.py` · `GrantStore.issue`/`revoke` (`relations` optional, downstream-of-authoritative); `app/main.py` · `list_directory_relations` (`GET /v1/admin/directory/relations`); `interfaces.py` · `MAX_RELATION_DEPTH`/`MAX_RELATION_FANOUT`/`MAX_RELATION_ROSTER`/`RELATION_KEY_PREFIX`; `services/quarantine.py` · `_glob_escape`; `core/metrics.py` · `RELATION_PROJECTION` |
| T16 | JWKS refresh: SSRF via the key-set fetch, or an emptied/MITM-swapped verifier | Point a rotating-STS JWKS URL at an internal address (cloud metadata / loopback / RFC1918) or rebind DNS after validation; stream an unbounded body; feed an empty / malformed / private-key-bearing / oversized document to blank or poison the verification key set; or reroute the fetch through an ambient proxy to swap the keys that verify identity | The refresh is **off the hot path** (a fetch never blocks an auth decision — `resolve` delegates to the already-loaded inner provider). Per-fetch SSRF guard: **https-only**; resolve host and refuse if ANY resolved address is private/loopback/link-local (`169.254.169.254`)/reserved/multicast/unspecified (IPv4-mapped unwrapped); connection **pinned to the validated IP** (SNI/cert = original host) to defeat DNS-rebinding; `follow_redirects=False`; bounded timeout; bounded read (`MAX_JWKS_DOC_BYTES`); 2xx-or-raise; **hermetic client (`trust_env=False`, `proxy=None`)** so ambient `HTTPS_PROXY`/`SSL_CERT_FILE` can neither reroute nor MITM-swap the key set (reuses `services.authn_channel._is_blocked_ip` via a deferred import to avoid an auth↔services cycle). **Never-empty is structural:** a NEW `JWKSKeyProvider` is built + fully validated (non-empty / well-formed / no-private-material / unique-`kid` + the `MAX_JWKS_KEYS` cap) **BEFORE** the single atomic `self._current` rebind, so ANY failure raises `JWKSRefreshError` and **retains the last good set** — an unknown `kid` after a bad refresh still fails CLOSED (`TokenError`), never an open pass. `bootstrap` makes the seed a MANDATORY non-empty provider (boot fails closed rather than empty). The `TokenResolver` alg allow-list `{EdDSA, RS256}` stays the gate — a rotated set adds keys, never widens the algorithms. Opt-in: absent config ⇒ no refresher, single-IdP path unchanged. | `auth/jwks_refresher.py` · `JWKSRefresher.refresh`/`bootstrap`/`resolve`, `_fetch_jwks_provider`/`_resolve_and_validate`/`_validate_https_url`, `JWKSRefreshError`; `auth/token_resolver.py` · `JWKSKeyProvider` (authoritative per-key validator), `TokenResolver` alg allow-list; `services/authn_channel.py` · `_is_blocked_ip`; `interfaces.py` · `MAX_JWKS_KEYS`/`MAX_JWKS_DOC_BYTES` |
| T17 | Audit attestation endpoint used to mint/forge a signature, leak topology, or perturb the ledger | Hope the new attestation route signs something new, exposes a hidden target/payload/secret, mutates or closes an epoch, blocks the emit hot path, or is reachable without a JWT | **Read-only by construction:** `attestation()` reads the already-sealed chain — it **mints no key, signs nothing new, closes no epoch, touches no counter**, so it never runs on / blocks / perturbs the write-before-execute emit path (`verify_chain` takes only the epoch-close lock, never `emit`; a one-epoch header skew is harmless because each field is independently signature-verifiable). It returns ONLY signed commitments `/v1/audit/proof` + `/v1/audit/verify` already surface — the sealed epoch header, a fresh `verify_chain` result, the anchor low-watermark, and `signing_key_id` (a domain-separated fingerprint of the PUBLIC WORM key — an identifier, never secret material or a signature) — so **no hidden target, payload, PIN/OTP, or secret** is disclosed. Epoch fields are `None` before the first seal (honest empty state, never a fabricated header). It is **`CAP_DIRECTORY_ADMIN`-gated** and available **in production** (unlike the sandbox-only verify/proof routes): the attestation commits to the **global, cross-tenant** WORM head (`epoch`/`end_seq` is a single fleet-wide ledger height), so a plain agent JWT must not read it — that would leak cross-tenant activity volume and let any principal force a full `verify_chain`. `_require_directory_admin` also enforces the revocation/quarantine kill-switches. Any auth or engine/transport failure is an opaque `MCPIPDenied`. | `app/main.py` · `audit_attestation` (`GET /v1/audit/attestation`); `audit/worm_logger.py` · `WormLogger.attestation`/`signing_key_id`/`_latest_epoch_header`, `WormAttestation`, `_DOMAIN_KEYID`, `verify_chain`; `audit/anchor.py` · `AnchorStore.head` |

---

## 12. Threat T6c — Compartmented team separation (need-to-know)

MCPIP's one **defense** tenant (`aegis-dynamics`, `obfuscator/tenant_catalog.py`) separates
its teams into UUID-identified **compartments** — `project-falcon` (`FALCON`,
`f4100000-…-0000000fa1c0`), `project-aegis` (`AEGIS`), `project-sentinel` (`SENTINEL`) —
each carrying a display-only `Classification` (`CLASSIFIED`/`RESTRICTED`). The remaining
eight industry tenants (finance, healthcare, government, energy, retail, telecom, pharma)
are un-compartmented and behave exactly as before. This is a **need-to-know** overlay on the
existing tenant boundary: a same-tenant agent must additionally be *entitled* to a
compartment before it can see or invoke that compartment's MCPs.

**Authorization is UUID capability/entitlement-based — never role-based.** The coarse JWT
`role` claim STAYS validated (part of the 8-required-claim contract, `REQUIRED_CLAIMS` in
`auth/token_resolver.py`) but is a **descriptive label only** and gates **no** decision —
role-based authorization was **removed from every decision path**. A privileged action is
allowed IFF the principal holds the required **capability UUID**, carried in the strict JWT
`capabilities` claim (`_capabilities_claim`, `auth/token_resolver.py` L217 — a size-bounded
list every entry of which must parse as a well-formed `uuid4`, else fail-closed
`TokenError`) and/or an active Redis entitlement/grant. Principals, compartments, grants,
and grant-issuing authorities are all UUIDs (`interfaces.py` `CAP_COMPARTMENT_GRANT`,
`CAP_COMPARTMENT_REVOKE`, `grant_capability_for`).

| Sub-threat | Adversary capability | Defending mechanism | Code (file · symbol) |
|---|---|---|---|
| **Compartment escape** | A `project-aegis` agent names a `project-falcon` alias (`skill_falcon_telemetry`) to reach across the need-to-know line. | `_compartment_gate` denies `COMPARTMENT_DENIED` unless the caller holds a **direct** JWT `compartment`-claim match (timing-uniform `constant_time_equals`) **or** an active delegated grant. | `main.py` · `_compartment_gate` (L392); `app/main.py` · `_compartment_gate` (L625) |
| **Grant abuse — self-issue** | An agent tries to grant *itself* (or a confederate) compartment access. | Grant issuance is not an ambient privilege: it flows through the same pipeline as a payload-bound EXECUTE **mandate** (`skill_compartment_grant`, a `PIN_REQUIRED` governance alias). `_mandate_gate` requires the caller to hold `CAP_COMPARTMENT_GRANT`, else `CAPABILITY_DENIED`. | `main.py` · `_mandate_gate` (L415), `_grant_gate` (L436); `services/grant_store.py` · `GrantStore.issue` |
| **Grant abuse — cross-compartment delegation** | A holder of the coarse grant capability, scoped to FALCON, mints an **AEGIS** grant (turning the grant capability into a tenant-wide master key). | Issuing a grant for compartment `X` additionally requires `grant_capability_for(X)` (uuid5-derived, per-compartment) matched timing-uniformly; a FALCON-scoped delegator lacks `grant_capability_for(AEGIS)` → `CAPABILITY_DENIED`. | `interfaces.py` · `grant_capability_for` (L298); `main.py` · `_grant_gate` (L458); demo C10 |
| **Grant persistence / expiry** | An agent relies on a revoked or expired delegated grant. | Grants live in Redis with a TTL; `has_active_grant` treats TTL expiry / revoke as absence → next reach denies `COMPARTMENT_DENIED`. Fail-closed reads. | `services/grant_store.py` · `has_active_grant`, `revoke`; demo C7 |
| **Tool-catalog enumeration** | An unentitled agent lists `GET /v1/catalog` to learn another team's classified MCPs. | `ObfuscatorService.list_visible` surfaces an alias IFF it is un-compartmented, in the caller's own compartment, or covered by an active grant — a `project-aegis` agent literally cannot enumerate `project-falcon` aliases. Metadata only; `target` never surfaced. | `services/obfuscator.py` · `list_visible` (L36); `app/main.py` · `catalog` (L925) |
| **Cross-compartment existence oracle** | Distinguish "a classified alias exists in a compartment I can't see" (a compartment-denied `GET` costs one extra Redis round-trip) from "this alias does not exist" (short-circuits). | `_resolve_alias` performs an equivalent **decoy** grant `GET` against a fixed synthetic compartment on a resolution miss, so both denials cost the same Redis work. | `app/main.py` · `_resolve_alias` (L601) |
| **In-band capability smuggling** | Smuggle `capabilities`/`entitlement`/`grants` keys inside `arguments` to self-assert authority. | The identity-injection walker hard-denies those key names (NFKC-casefold) alongside the identity keys — authorization derives EXCLUSIVELY from the verified JWT / Redis. | `bridge/intent_parser.py` · `_FORBIDDEN_IDENTITY_KEYS`, `_identity_fold` |

`compartment` is deliberately **not** a forbidden in-band key: it is a legitimate business
argument (the *target* compartment of a grant mandate) and is provably inert for identity —
the caller's own compartment comes only from the verified JWT. Demo gates **C1–C10b**
exercise every row above; the HTTP edge reproduces the same gates and `GET /v1/catalog`
filtering.

---

## 13. Red-Team Findings & Resolutions (final challenge round)

The final challenge round produced **zero failing scenarios** (all 19 /v1/authorize
adversarial scenarios and every demo gate held; no false ALLOW was ever observed). It did
surface seven **residual** findings — all either fixed or consciously accepted with the
residual risk stated honestly below. None is an integrity or authorization bypass.

| # | Finding | Sev | Status | Residual / resolution |
|---|---|---|---|---|
| R1 | **Grant-governance alias enumerable by unprivileged same-tenant agents in `/v1/catalog`.** `ObfuscatorService.list_visible` (`services/obfuscator.py`) filters visibility by `compartment` only and never consults `entry.required_capability`, so `skill_compartment_grant` (compartment `None`, `required_capability=CAP_COMPARTMENT_GRANT`) is returned to every same-tenant agent — an uncompartmented `aegis-dynamics` agent sees `['skill_status_probe','skill_compartment_grant']`. | low | **Accepted** | Metadata-only disclosure: an unprivileged agent learns *that* a grant-issuing governance path exists. **No escalation** — execution stays UUID-capability-gated (every self-issue/smuggle attempt returned 403 `CAPABILITY_DENIED`) and no compartment UUIDs or real targets are revealed. Effectively an intended RESTRICTED operator-visible governance skill. **Optional hardening:** add a `required_capability` visibility check in `list_visible` (surface a governance alias only to holders of its capability), mirroring the compartment filter. |
| R2 | **Sandbox/demo WORM buffer runs without fsync-durable AOF.** With `MCPIP_SANDBOX_MODE=true` the boot durability check (`assert_persistence_posture` with `require=False`, `app/main.py` L378) only logs an advisory when Redis reports `appendonly=no`/`appendfsync=everysec` (the state of the shipped `mcpip-v2-redis`); `emit` then returns after an in-memory-only `XADD`, so a crash before the next AOF window could lose an already-authorized action's event. | low | **Accepted (sandbox-only)** | Only reachable in sandbox posture. **Production (`sandbox_mode=false`) fail-closes at boot** unless `appendfsync=always`, so write-before-execute is enforced where it matters. No integrity/authorization bypass. **RESOLVED (3.0.0):** `scripts/quickstart.sh` and the documented manual Redis command now both start it with `--appendonly yes --appendfsync always`, so the sandbox mirrors production durability instead of advertising it. (Same root cause as §14 finding R6.) |
| R3 | **Single-worker HTTP has no admission control (availability under load).** See §14 for the measured throughput/latency curve. | high | **Accepted (deployment gap)** | Availability, **not** security. The stateless-in-Redis design is meant to scale horizontally (N workers / N nodes); the residual is the absence of an in-process concurrency limiter that would `503`/`429` above a threshold instead of unbounded queueing. Fully documented as a capacity-planning + deployment item in §14. |
| R4 | **PIN consume runs a 16 MiB / ~41 ms scrypt on every attempt before the atomic Lua** (`auth/pin_validator.py` L294 / `_SCRYPT_MAX_CONCURRENCY=min(4,cpu)` L77). | medium | **Accepted (deliberate tradeoff)** | This is the brute-force-resistance design (§14). Per-lock 5-attempt self-destruct + per-identity register rate-limit bound it; exactly-once integrity is fully preserved. Documented as a ~100 consume/s/process capacity number in §14. |
| R5 | **Mandatory durable WORM `emit` (AOF `appendfsync=always`) serializes the AUTO allow-path on Redis fsync** (`audit/worm_logger.py` L418, `app/main.py` L819). | medium | **Accepted (inherent to write-before-execute)** | The audit-fsync, not the crypto, is the allow-path ceiling (§14). Cannot be pipelined/batched away without breaking the invariant. Scale Redis horizontally / fast NVMe; treat ~1k durable emit/s/shard as the allow-path capacity unit. |
| R6 | **Shipped sandbox Redis runs `appendonly=no`/`appendfsync=everysec`, so the advertised write-before-execute invariant does not actually hold in the shipped dev posture** (`audit/worm_logger.py` L251 `require=False` in sandbox; `deploy/redis.conf`). | low | **Accepted (dev/sandbox only)** | Production is fail-closed; only the *runnable demo* under-delivers the durability it advertises, which could mislead capacity/durability testing. **RESOLVED (3.0.0):** the quickstart and the documented manual command now start Redis with `appendonly=yes appendfsync=always`. The runnable demo now delivers the durability it demonstrates, so capacity and durability testing against it is representative. |
| R7 | **ASGI framework overhead (~8 ms/req) dwarfs the security pipeline (~1 ms); per-request serial CPU is dominated by JWT Ed25519 verify** (`services/auth_engine.py` L76 → `auth/token_resolver.py` L106). | low | **Informational — no change** | The end-to-end ceiling on one worker is framework overhead + non-overlappable JWT-verify CPU, **not** the MCPIP engine (pydantic strict ~0.06 ms/req, `canonical_json` ~0.058 ms/req are minor). Optimization headroom is in transport/worker count, not the engine. Verified-token caching is intentionally **not** done (unsafe). |

The **connector conformance round** (the bridge/connectors extension) likewise produced zero
authorization bypasses; its four residual findings — all low, all deny-preserving — are stated
honestly below:

| # | Finding | Sev | Status | Residual / resolution |
|---|---|---|---|---|
| C-R1 | **`DenyReason` classification of `ValidationError` relies on message-substring matching.** `map_engine_exception` (`core/security.py` ~L110–116) classifies a Pydantic `ValidationError` into `ILLEGAL_CHARACTER` / `SIZE_EXCEEDED` / `SCHEMA_VIOLATION` by searching the casefolded `str(exc)` for `"illegal character"` / `"max_string_len"`. A Pydantic message-format change — or an unrelated `ValidationError` whose echoed input happens to contain one of those substrings — silently reclassifies the WORM-audited deny reason. | low | **Accepted** | Taxonomy accuracy only: the decision is a DENY either way (fail-closed preserved). **Hardening path:** classify on structured data (`exc.errors()[i]['type']`/`['ctx']`) or dedicated marker exception subclasses raised by `reject_unsafe_string`. |
| C-R2 | **`parse_openai` `json.loads` accepts nonstandard `NaN`/`Infinity` tokens** (`bridge/connectors/formats.py` ~L192, default `parse_constant`). No acceptance path exists — the walker rejects NaN/Inf downstream — but the deny reason becomes `schema_violation` instead of the `unknown_format` all other malformed-JSON inputs get, so the "decoded exactly once, strict boundary" story is slightly looser than documented. | low | **Accepted** | Fail-closed either way. **Hardening path:** pass a raising `parse_constant` to `json.loads` so nonstandard constants funnel into the existing `UnknownFormat("openai arguments is not valid JSON")` branch. |
| C-R3 | **`MAX_RAW_ARGUMENTS_BYTES` is enforced as a character count, not bytes.** The §4.0 pre-parse DoS gate is a Pydantic `Field(max_length=…)` on the OpenAI `arguments` string (`bridge/connectors/formats.py` ~L59), which counts code points; 65 536 astral/multibyte characters can reach ~256 KiB of UTF-8 — 4× the documented ceiling. | low | **Accepted** | The input stays hard-bounded (the 256 KiB `BodySizeLimitMiddleware` cap and the canonical 16 KiB post-walk cap both still hold), so the DoS-gate intent substantially holds; this is a precision/drift note between the documented invariant and the mechanism. **Hardening path:** re-document as a code-point cap or add a `len(v.encode('utf-8'))` field validator. |
| C-R4 | **Cross-script confusable identity keys evade the NFKC identity fold.** `_identity_fold` (`bridge/intent_parser.py` L109) uses NFKC+casefold, which collapses compatibility variants (fullwidth, ligatures) but not cross-script confusables: an argument key `tenаnt_id` with CYRILLIC SMALL A (U+0430) is accepted in every format. | low | **Accepted** | Exploitability is very low: identity derives exclusively from the JWT, the smuggled key cannot string-equal `tenant_id` for any exact-match reader, and the guard is explicitly defense-in-depth — only a hypothetical future reader that itself applies confusable folding could be influenced. **Hardening path:** add a confusable-skeleton map (Cyrillic/Greek → Latin look-alikes) before the frozenset test, kept in sync with the Rust walker (which defers non-ASCII-NFKC keys to Python, so parity is automatic). |

---

## 14. Scalability findings & the hybrid Merkle-epoch audit (as implemented, measured)

This section states the honest measured numbers from the final scale-load round. **No
optimization weakened any security invariant** (§2); every figure below was taken with the
full fail-closed pipeline and durable WORM active. The stated goal of the stateless design
is horizontal scale, and the findings confirm the ceilings are per-process / per-Redis-shard
resources, not the security logic.

### 14.1 Hybrid Merkle-epoch WORM — the implemented design

The per-event Ed25519-signed straight hash chain was **replaced** with a hybrid Merkle-epoch
model (the per-event chain remains available behind `mode="per_event"` for migration):

1. **Durable buffer (write-before-execute).** Each audit event is durably appended to a
   Redis Stream (`mcpip:worm:events`) **before** the action is authorized. Under Redis AOF
   `appendfsync always` the `XADD` is fsync-durable before `emit` returns, and an action is
   authorized only after `emit` returns — so no authorized decision's event can be lost
   (`audit/worm_logger.py` · `emit`).
2. **Per-epoch signed Merkle root.** A ~1 s background daemon closes an **epoch**: it builds
   a Merkle tree over the epoch's contiguous seq range (domain-separated leaf/node/epoch
   prefixes — CVE-2012-2459 second-preimage defense), chains the new `merkle_root` to the
   previous epoch's `epoch_hash` (`"GENESIS"` at epoch 0), and **Ed25519-signs the epoch
   hash — one signature per epoch, not per event** (`close_epoch`).
3. **O(log n) inclusion proof.** `inclusion_proof(event_id)` yields a Merkle path from any
   event to its signed epoch root; generation reads a per-epoch **precomputed leaf-digest
   vector** plus the single target event (never a full-epoch rescan). `verify_inclusion`
   verifies in O(log n) (`audit/merkle.py`).
4. **`verify_chain()` → `(intact, first_bad)`.** A mutated event fails its epoch's recomputed
   Merkle root; a mutated/removed/reordered/forged epoch header fails root-chain linkage,
   contiguous coverage, recomputed `epoch_hash`, or the Ed25519 signature. An
   out-of-tamper-domain Ed25519-signed head anchor (`audit/anchor.py`) enforces a monotonic
   low-watermark, catching rollback/tail-truncation even when the attacker also rewrites the
   in-Redis linkage counters. Accepts a trusted `checkpoint=(epoch, epoch_hash)` to re-verify
   only newer epochs.

**Crash-safety argument (required).** (a) **No lost authorized action:** `emit` returns only
after the durable `XADD`, and the action is authorized only after `emit` returns, so every
authorized decision's event is already durable in the buffer. (b) **No inter-epoch gap:** a
crash between `emit` and the next epoch close loses only the not-yet-signed root; on restart
the daemon re-reads all epoch-unassigned events (`seq > last_seq`) from the durable stream
and re-closes deterministically (the Merkle root is a pure function of the ordered leaves, so
re-close is idempotent). Coverage is contiguous seq ranges (`start(n+1)=end(n)+1`), so there
is never a gap between epochs, even across crashes. The demo gate **C9** asserts
`close_epoch() → verify_chain() == (True, None)` **and** every emitted event's inclusion proof
verifying to a signed root.

### 14.2 Measured numbers (honest; sandbox vs. durable posture noted)

All hashing/signing is in Python (never `redis.sha256` — nonexistent — or Ed25519 in Lua).

| Metric | Measured | Notes |
|---|---|---|
| **Per-epoch signature** | 1 Ed25519 sign / epoch (~1 s) | vs. 1 sign/event in the legacy chain — the source of the throughput win below. |
| **Durable `emit` (AOF `appendfsync always`)** | **1,098 emit/s** (p50 0.758 ms) | The write-before-execute fsync. |
| **`emit` (`appendfsync everysec`, sandbox)** | 3,123 emit/s (p50 0.294 ms) | ~2.8× faster but **not** crash-durable — sandbox posture only; optimistic. |
| **Epoch-model vs. per-event chain emit** | **≈2.9× higher emit throughput** | One signature per epoch instead of per event. |
| **Inclusion-proof generation** | O(log n), precomputed leaf vector + 1 event fetch | No full-epoch rescan (was an O(epoch-size) authenticated amplification vector). |
| **Inclusion-proof verification** | O(log n) | `verify_inclusion`. |
| **In-process AUTO authorize (durable)** | **740 authz/s serial** (p50 1.25 ms) → **2,257 authz/s @conc 64** (p50 26.9 ms) | The durable `XADD` fsync serializes at Redis — the audit write, not the crypto, is the allow-path bottleneck. |

**Allow-path ceiling = Redis single-instance fsync rate (~1.1k durable emit/s on the test
box), not node count on one Redis.** This is inherent to the (correct) write-before-execute
invariant. Scaling path: shard the WORM buffer by tenant across Redis instances, or place the
AOF on fast local NVMe, keeping `appendfsync always`. Treat **~1k durable emit/s/shard** as
the allow-path capacity unit.

### 14.3 PIN-path throughput (deliberate brute-force-resistance tradeoff)

`consume` derives a memory-hard `scrypt` (n=2¹⁴, ~16 MiB, mean 41.5 ms) on **every** attempt
*before* the atomic consume Lua, and the scrypt executor is hard-capped at
`_SCRYPT_MAX_CONCURRENCY = min(4, cpu_count)` (`auth/pin_validator.py` L77). Measured: 10,000
concurrent contenders on a single lock (all presenting the correct PIN) took **100.7 s wall
(99.3 consume/s)** because each computed the full scrypt before hitting the Lua that returns
`-1` for 9,999 of them. System-wide PIN ceiling ≈ **4 / 0.041 ≈ 97 consume/s/process**,
matching the observed 99.3. This is **not** an exploitable DoS: it is bounded in practice by
the per-lock 5-attempt self-destruct and the per-identity 60/min register rate-limit, and
exactly-once integrity is fully preserved. **Capacity-planning number: ~100 PIN consume/s per
process.** `_SCRYPT_MAX_CONCURRENCY` is the per-box tuning knob.

### 14.4 HTTP admission control (availability gap — R3)

Measured against **1 uvicorn worker** + durable Redis, throughput was essentially **flat**
(single event-loop CPU-bound), and latency absorbed all backpressure:

| Concurrency | Throughput | p50 / p99 latency | Dropped |
|---|---|---|---|
| 50 | 172 rps | 153 ms / 1.6 s | 0 |
| 500 | 157 rps | 1.8 s / 15.8 s | 0 |
| 2,000 | 117 rps | 10.4 s / 79 s | 0 |
| 10,000 | 158 rps | 28 s / 118 s | **1,924 / 20,000 (9.6%) `ConnectError`** |

Security was **not** compromised (no false ALLOW; the pipeline stayed fail-closed), but
callers saw multi-minute tail latencies and silently dropped connections instead of clean
load-shedding, because there is no concurrency limiter, queue cap, or `429`/`503` fast-fail.
Per-request cProfile (3,000 in-process authorizes) attributes the dominant CPU to the JWT
path (Ed25519 verify 0.683 s / 0.228 ms per req + JWT decode ~0.35 ms/req); pydantic strict
(~0.06 ms/req) and `canonical_json` (~0.058 ms/req) are minor. A single sequential HTTP
request is 9.2 ms p50, ~8 ms of which is uvicorn/starlette/middleware overhead — the
framework costs more than the entire authorization engine.

**Resolution path (deployment, not core-engine):** run N uvicorn workers / horizontally scale
the stateless nodes (the Redis-backed design already supports it), **and** add an in-process
concurrency semaphore / ASGI concurrency-limit middleware that returns `503`/`429` above a
threshold instead of unbounded queueing, behind a bounded listen backlog + client-facing
timeout. Connection pooling is already in place (`redis_max_connections=64`,
`redis_pool_timeout_s`, `core/config.py`) and canonical-bytes/hash reuse avoids recomputation
on the hot path.

---

## 15. Residual risk & honest limitations

MCPIP is strong against the in-band adversary of §2. The following are the honest gaps and
the reasons the design tolerates them. Where the internal brief paraphrased the PIN store as
`sha256(pin)` with a "non-constant-time Lua compare," the **shipping code is stronger** —
scrypt-salted storage and a constant-time XOR-fold — and the residuals below are stated
against that real code.

1. **The in-Lua PIN compare is constant-time, but it is bespoke.** `secrets.compare_digest`
   is unavailable server-side, so `LOCK_CONSUME_LUA` XOR-folds every byte of two fixed
   64-hex-char digests with **no early exit** (`auth/pin_validator.py` L115–124); the only
   branch is on length (a fixed, non-secret 64), so no stored-digest bytes leak through
   timing. **Residual:** it depends on the Redis Lua `bit` library (present in Redis 7's
   Lua 5.1) and on the digest width invariant; a future change to `_SCRYPT_DKLEN` must keep
   the 64-char width or the length branch becomes reachable. **Mitigation:** the primary
   brute-force control is not timing at all — it is the **5-attempt self-destruct**
   (`PIN_MAX_ATTEMPTS`) plus the **300 s TTL**, which cap online guessing at 5 tries against
   a per-lock-salted secret.

2. **6-digit PIN keyspace (10⁶).** A 6-digit OTP is inherently low-entropy. **Mitigation:**
   the stored digest is `scrypt` (n=2¹⁴, ~16 MiB/guess), **salted per lock** by
   `(tenant_id, lock_id, payload_hash)` in `_derive_pin_hash` (L65), so even an attacker who
   scrapes the full Redis record faces a memory-hard offline cost with no precomputation or
   rainbow reuse; and online guessing is bounded to 5 attempts. **Residual:** an online
   attacker still has a 5 / 10⁶ ≈ 5×10⁻⁶ success probability per lock before self-destruct.

3. **`PAYLOAD_MISMATCH` (`-3`) spends no attempt.** By design, a correct-payload retry must
   survive a wrong-payload attempt (demo gate 4b). **Residual:** an attacker who *already
   knows* the exact payload could retry PINs without consuming the payload-mismatch path —
   but every *PIN* miss is still a `-2` that counts toward the 5-attempt lockout, so this
   grants no extra guesses.

4. **WORM tamper-evidence, not tamper-prevention.** `verify_chain` *detects* any event or
   epoch-root mutation, insertion, or reorder and pinpoints the first bad epoch. Dropping the
   newest signed epoch header(s) *and* rewriting the plaintext in-Redis linkage counters back to
   a prior signed epoch (a rollback that keeps the surviving prefix consistent) was the one case
   an anchorless verify could miss, since the counters share Redis's tamper domain.
   **Mitigation (implemented):** `AnchorStore` (`audit/anchor.py`) mirrors each signed epoch head
   to an Ed25519-signed, fsync'd, append-only file **outside** Redis and `verify_chain` enforces
   it as a monotonic low-watermark, so a truncation/rollback (W9) or a delete-all-headers erasure
   (W8) is caught even when the attacker also rewrites the counters — a chain that stops short of,
   or substitutes a different hash at, the durably-witnessed head fails verify (a chain merely
   *ahead* of a lagging anchor stays intact). The offline `mcpip export-audit --verify --pubkey
   … [--anchor-path …]` re-runs the same per-epoch checks **and** the same anchor low-watermark
   from the exported bytes, so the production operator (for whom `/v1/audit/verify` is
   sandbox-gated) gets the identical verdict. Production requires Redis AOF `appendfsync always`
   so every authorized decision's event is fsync-durable before the action runs, and the anchor
   file must sit on a durable volume distinct from the Redis store. **Residual:** an adversary who
   *also* compromises the gateway host's anchor volume (a strictly larger foothold than Redis
   write) could truncate consistently. **Hardening path:** additionally externalize signed epoch
   roots / anchor heads to WORM-native storage (e.g. S3 Object Lock) off-host.

5. **Redaction is key-name based.** `_redact` (`audit/worm_logger.py` L67) redacts values
   under `_REDACT_KEYS`; a secret placed under an unlisted key name would not be redacted.
   **Mitigation:** the gateway logs only a fixed, non-sensitive context envelope (`ctx` in
   `authorize_and_execute`); raw PINs/JWTs are never placed into the event in the first
   place, so redaction is defense-in-depth, not the sole control.

6. **Redis is a trusted component.** Exactly-once (T2) and WORM sequencing (T7) assume an
   uncompromised Redis. **Mitigation:** Redis runs on an **internal-only** Docker network
   with no host port (`docker-compose.yml`), unreachable from the agent or the internet; the
   gateway is the only client. **Residual:** a compromised Redis breaks exactly-once and
   append-ordering; treat Redis as in-TCB and protect it accordingly (auth, TLS, network
   policy) in production.

7. **Single verification key / no `kid` selection.** `StaticPEMKeyProvider` returns one key
   regardless of `kid` (`auth/token_resolver.py` L72). **Mitigation:** the `KeyProvider` ABC
   is the drop-in seam for a JWKS-backed, `kid`-selecting provider with rotation; it is
   documented, not stubbed. **Residual:** until then, key rotation is a redeploy.

8. **Sandbox-only surfaces are gated, not absent.** `POST /v1/dev/token` and
   `GET /v1/authenticator/{challenge_id}` exist only when `settings.sandbox_mode` is true and
   return `404` otherwise (`app/main.py`); the OTP is delivered strictly out-of-band and
   never appears in the `202` response. The raw OTP stash in Redis now lives behind the
   pluggable delivery channel: the composition root constructs `SandboxRedisAuthenticatorChannel`
   (the `mcpip:otp:*` stash + `peek`) **only** in sandbox (`_build_authn_channel`,
   `app/main.py`), while production wires the no-persistence `WebhookAuthenticatorChannel` (or
   `None` when unconfigured). So in production the parallel `mcpip:otp:*` key never exists and
   Redis holds only the salted scrypt digest — see residual 13 for the delivery surface itself.
   **Residual:** an operator who ships with `MCPIP_SANDBOX_MODE=true` in
   production would expose a token-minting endpoint — hence `Settings.sandbox_mode`
   **defaults to `false` (secure-by-default) everywhere**, including the bare `uvicorn`
   process, the shipped image, and Compose. Sandbox must be opted into EXPLICITLY with
   `MCPIP_SANDBOX_MODE=true`, a loud stderr banner is printed whenever the sandbox
   affordances are mounted, and the fail-closed boot check (`sandbox_mode=False` + missing
   key paths ⇒ refuse to start, `core/config.py` / `app/main.py`) means a misconfigured
   deployment refuses to boot rather than exposing a bypass.

9. **Pre-auth request-body ceiling.** `POST /v1/authorize` deserializes a JSON body before
   the JWT is checked, so an unauthenticated client could otherwise force full in-memory
   parsing of an arbitrarily large payload. **Mitigation:** `BodySizeLimitMiddleware`
   (`app/main.py`) is the OUTERMOST ASGI middleware and rejects any body over
   `MAX_REQUEST_BODY_BYTES` (256 KiB) with an opaque `413` — first on an oversized
   `Content-Length` without reading a byte, then via a hard-capped buffer for
   chunked/header-less requests — before any parsing, validation, or authentication runs.

10. **Audit durability enforced at boot.** Write-before-execute is only real if the buffer
    `XADD` is fsync-durable before `emit` returns, which requires Redis AOF
    `appendfsync always`. `assert_persistence_posture` (`audit/worm_logger.py`) reads the
    live `appendonly`/`appendfsync` config at boot and, in a non-sandbox deployment,
    **refuses to start** unless the posture is durable; the required profile ships in
    `deploy/redis.conf` and is enforced by `docker-compose.yml` (mounted config + durable volume).

    **Benchmark honesty (sandbox vs. durable).** The runnable sandbox intentionally uses a
    throwaway Redis with `appendonly=no`/`appendfsync=everysec` (`assert_persistence_posture`
    logs a loud advisory and continues). Any audit-append / authorize-latency figure measured
    there reflects a **non-fsynced** in-memory `XADD` and is therefore **optimistic**: it does
    NOT include the write-before-execute fsync the design's crash-safety argument depends on. A
    production `appendfsync always` deployment pays **one fsync per append** on the authorize hot
    path (commonly single- to low-double-digit milliseconds on durable storage), so real hot-path
    audit cost and ingest throughput are materially below the sandbox numbers. The crash-safety
    guarantee (no authorized action whose event is not already durable) holds **only** under the
    enforced durable posture — which is precisely why non-sandbox boot fail-closes without it.
    Any latency/throughput claim must be taken with `appendfsync always`, not against the sandbox.

11. **Audit scaling — bounded proof generation and incremental verification.** Inclusion-proof
    *verification* is O(log n); proof *generation* reads a per-epoch **precomputed leaf-digest
    vector** (persisted at close) plus the single target event fetched by its stored stream id,
    then derives the O(log n) sibling path in memory — it never re-scans or re-hashes the whole
    epoch (previously an O(epoch-size) full-buffer scan per call, an authenticated amplification
    vector). `verify_chain` still defaults to a full replay, but accepts a trusted
    `checkpoint=(epoch, epoch_hash)` (from `latest_checkpoint()` after an intact full verify) to
    re-verify **only newer epochs**, reading just the suffix of the signed epochs stream — so both
    the CPU cost and the epoch-close-daemon freeze while the close-lock is held scale with epochs
    *since the checkpoint*, not the whole service lifetime. Every persisted epoch-header field —
    including the `first_stream_id`/`last_stream_id` range that was formerly unsigned — is now
    committed to the signed `epoch_hash`, so mutating any of them fails both the recomputed-hash
    and the Ed25519-signature checks.

    **Checkpoint-compaction (bounded steady-state storage AND full-verify).** The signed epoch
    headers stream, its index/streamid hashes, and the out-of-domain anchor file otherwise grow
    one entry per epoch *forever* (unbounded Redis + disk on a long-lived busy node, and an
    O(lifetime) default full-verify). `WormLogger.compact()` (invoked periodically by the epoch
    daemon via `maybe_compact`, keeping the newest `WORM_CHECKPOINT_EPOCHS`) folds every older
    **fully-verified** epoch prefix into **one Ed25519-signed super-checkpoint** committing to
    `(epoch, epoch_hash, end_seq)`, then trims those epochs' headers/index/streamid and rotates
    the anchor file to drop subsumed lines. Compaction is fail-closed — it pre-verifies the prefix
    and refuses to sign a tampered one — and crash-safe: the checkpoint key is written *before* the
    old headers are trimmed, and `verify_chain` **skips** any still-present subsumed header, so a
    crash mid-compaction never yields a false tamper and the next compaction re-trims idempotently.
    A later `verify_chain` re-anchors on the signed super-checkpoint (sound because every
    `epoch_hash` transitively commits to `prev_epoch_hash` back to genesis) and replays only
    `epoch > checkpoint`, so even a full replay is bounded to O(epochs since the last checkpoint).
    Deleting the super-checkpoint over a compacted (non-genesis-starting) stream, mutating it, or
    rolling back the suffix are all still caught (linkage/​signature + the monotonic anchor
    low-watermark).

    **Bounded per-close Merkle build.** Epoch close builds its Merkle tree in O(leaf count). The
    hashing + tree build now run **off the serving event loop** (`asyncio.to_thread`) so they never
    stall in-flight `/v1/authorize` calls, and a single close seals at most `WORM_MAX_EPOCH_LEAVES`
    (the daemon immediately drains any remainder in bounded chunks), so one close is O(cap)
    regardless of a stalled daemon, a burst, or a forced close over a large unsealed tail.

12. **Forensic capture shares the authorize Redis pool; deny-terminal overwrites the entry.**
    The forensic side-channel (§11 T10, `services/forensic_store.py` / `_capture_forensic`) closes
    the investigator's opaque-wire gap — it captures the real query (redacted, AES-256-GCM at rest,
    `CAP_FORENSIC_READ`-gated + WORM-audited retrieval) strictly AFTER the authoritative WORM emit,
    so it can never block, reorder, or flip a decision, and secrets never enter it. Two **info-level**
    red-team follow-ups are recorded honestly, neither an integrity or authorization issue:
    **(a)** best-effort capture tasks run on the shared authorize Redis pool, so under a Redis
    slowdown the fire-and-forget captures can add backpressure to the hot path (**hardening path:**
    bound capture concurrency or give capture a dedicated pool); **(b)** on an allow→dispatch-failure
    path a second (deny) WORM record is emitted and the deny-terminal capture overwrites the same
    `correlation_id`'s forensic entry, so the persisted capture reflects the **deny terminal** — an
    accepted, honest final-state semantics rather than a bug.

13. **Out-of-band authenticator delivery — SSRF surface and delivery trust (T11).** In production
    the step-up code is pushed to a tenant-configured HTTPS sink (`WebhookAuthenticatorChannel`),
    which introduces a gateway-initiated outbound request. The SSRF guard runs **per delivery**
    (not once at config time): https-only, resolve-and-reject any private/loopback/link-local
    (`169.254.169.254`)/reserved/multicast/unspecified address (IPv4-mapped unwrapped), connection
    **pinned to the validated IP** so DNS-rebinding cannot swing a re-resolve onto an internal host,
    no redirect-following, bounded timeout, bounded response read. The notice is HMAC-SHA256-signed
    (`ts + "." + body`) so the receiver can authenticate it, and **no OTP is persisted** in
    production (the sandbox stash is a distinct sandbox-only channel; `otp` is also in the WORM
    redaction set). Any delivery failure is fail-closed `otp_delivery_failed` before a `202` exists.
    **Residual:** the confidentiality of the delivered code past the validated IP depends on the
    operator's sink — a tenant that configures a hostile or plaintext-terminating endpoint (or that
    fails to verify the HMAC signature) can leak its own codes; the gateway enforces transport,
    egress-target, and signing discipline but cannot vouch for the far end. The guard also trusts
    the resolver's answer set at delivery time; a resolver-level compromise (a strictly larger
    foothold) could return a public IP that later NATs inward. **Hardening path:** operator
    allow-listing of sink hosts and pinned receiver certificates. **Mitigation for the unconfigured
    case:** with no channel, `pin_required` actions fail closed rather than degrade — there is no
    plaintext or in-band fallback. The delivery client is **hermetic** (`trust_env=False`,
    `proxy=None`) so an ambient `HTTPS_PROXY`/`SSL_CERT_FILE`/`SSLKEYLOGFILE` cannot silently
    reroute the push through an unvalidated intermediary or void the IP-pin/TLS-verify
    (regression-guarded by `test_webhook_client_is_hermetic_ignores_ambient_proxy`).

14. **Policy overlay (G3) — two accepted info-level items, neither an authz or integrity defect.**
    **(a)** A caller that supplies the amount can binary-search a tenant's amount ceiling by
    observing the response-*type* boundary (`202`/`200` under the limit vs an opaque `403` over
    it), even though the deny body stays opaque — inherent to any per-request amount limit that
    denies synchronously; the limit *value* is not otherwise disclosed. **(b)** In production the
    webhook OTP push in `register_lock` is an external side-effect that happens *before* the
    staged-challenge WORM emit, so a crash in that window can leave a code delivered out-of-band
    with no staged-challenge record — fail-safe (the lock is unusable and expires; no action
    runs), an accepted honest ordering for an external delivery rather than a bug. A non-finite
    (`NaN`/`±Infinity`) amount is rejected as its own fail-closed deny in `_check_amount` rather
    than throwing (regression-guarded in `test_amount_ceiling_over_under_and_boundary`).

14. **Deny-only policy overlay — fail-open resistance and coarse amount semantics (T12).** The
    overlay can only ever *add* a `policy_denied`; its decision type has no allow/override path, and
    both the gate and the engine fail closed on Redis failure, a malformed stored document, or a
    raising provider — so a limiter outage denies rather than silently lifting the cap. **Residual /
    honest limitations:** (a) the engine is deliberately **stateless and schema-agnostic**, so an
    amount rule only fires when the named field is present and a real JSON number — an **absent**
    field is a no-op (an operator must attach amount rules only to skills whose schema guarantees the
    field; a renamed/removed field silently stops enforcing, though a present non-number is refused,
    not coerced); (b) the velocity cap is a **fixed window**, not a sliding window or token bucket,
    so up to `2 × max_actions` calls can clear across a window boundary — it is a coarse abuse-rate
    control, not a precise quota; (c) it is **opt-in** — a tenant with no document has no limits by
    design (honest absent state, never a fabricated default), so the control only protects tenants
    that configure it. None of these is an authorization or integrity bypass: the overlay sits after
    the entitlement/sender-constraint gates and before the risk gate, never repoints an alias, never
    mints identity, and a fixed-window over-count still cannot exceed what the entitlement + risk
    gates already permit.

15. **Community extensibility — by-construction ceilings, with two honest residuals (T13/T14).** A
    community **skill** is inert declarative data minted only through the additive-only, `cloud_rest`-only,
    `restricted ⇒ pin_required` overlay path, re-validated fail-closed at approve, hash-pinned against
    rug-pulls, and WORM-logged before apply — so it can only ever *add* a new opaque alias, never repoint,
    reach a privileged transport, or exfiltrate a restricted AUTO read. The community **gate** (Phase 2)
    ships as a deny-only seam whose decision type has no allow path and whose context is topology-free, and
    whose approval is fail-closed without a static safety proof. **Residual / honest limitations:** (a)
    **single-node self-approval** — submit is any authenticated principal and approve requires the distinct
    `CAP_CATALOG_REVIEWER`, so a plain contributor cannot approve its own work, but a single principal
    holding BOTH capabilities could self-approve on one node; true dual-control / cross-org non-repudiation
    is the deferred Phase 3 detached `authorship_sig`+`approval_sig` (a fourth Ed25519 root), and the
    reviewer console surfaces `submitter_is_reviewer` as a visible warning in the interim. (b)
    **deregistration/GC of an approved community skill is not specified in Phase 1** — removing one via the
    operator skills-deregister path leaves a dangling `mcpip:ext:approved:{tenant}` manifest entry; harmless
    (the alias no longer resolves) but untidy until Phase 3. (c) **the boot-load rug-pull pin is
    Redis-local** — `_hydrate_catalog_overlay`/`_community_pin_valid` re-verify the manifest self-pin, the
    approved-record pin, and the overlay-field pin against each other, all of which live in Redis; this
    catches a *partial/inconsistent* post-approval edit but NOT a fully-consistent rewrite by an attacker
    who already holds direct Redis write access (it does not, at load, cross-check the signed, hash-chained,
    anchored WORM `extension_approve` record). The exposure is bounded: even a consistent rewrite is
    re-run through the fail-closed hydration validation (`_overlay_skill_invalid`: additive-only,
    `cloud_rest`-only, `restricted ⇒ pin_required`), so an injected entry still cannot repoint, reach a
    privileged transport, or become a restricted bearer-exfil read — a Redis-write adversary gains only
    another bounded opaque `cloud_rest` alias. **Hardening path:** cross-check the approved manifest
    `sha256` against the signed WORM approval event at hydration (needs an alias→approval-event index),
    tracked for Phase 3. None of (a)/(b)/(c) is an authorization or integrity bypass:
    the gate seam is a deny-only no-op with no engine registered (the CEL runtime is a deferred owner
    dependency decision — no `celpy` is imported and no gate can be approved/enforced), and the skill path
    cannot exceed what the base entitlement/risk gates already permit.

16. **ReBAC relation-tuple layer is a projection, not authorization (T15).** The relation store
    backs the operator Knowledge-Graph read only; the authorization pipeline never consults it, and the
    tuple is written strictly downstream of the authoritative grant (swallowing every Redis error, never
    raising into the grant path). **Residual / honest limitations:** (a) **best-effort ⇒ under-reporting.**
    A projection blip (a swallowed `RedisError` on `project_member`/`remove_member`, or a revoke-remove
    dropped during an outage) makes the graph *under-report* edges — it is fail-safe (never *over*-reports a
    membership the grant state doesn't hold), and `EX=ttl` mirroring the grant means even a dropped remove
    self-heals at grant expiry; the console copy states the gateway/Redis grant state is authoritative. (b)
    **the `check` closure is structural, exercised shallow.** v1 tuples are direct (depth 1), so
    `MAX_RELATION_DEPTH`/`MAX_RELATION_FANOUT` are enforced but not stress-loaded by real nesting; they exist
    so a future group/role-nesting wave inherits a walk that already cannot become an unbounded CPU/timing
    oracle (every failure axis fails closed to `False`). Neither is an authz or integrity defect: the
    capability-UUID + grant gates remain the sole authority and the read is `CAP_DIRECTORY_ADMIN`-gated,
    tenant-scoped, glob-escaped, and fail-soft.

17. **JWKS refresh is opt-in and off-hot-path; the seam is present but not auto-scheduled (T16).** The
    `JWKSRefresher` never empties the verification key set — it builds and fully validates a replacement
    provider before the atomic swap and retains the last good set on any failure — and its fetch reuses the
    hardened SSRF guard + hermetic-client discipline. **Residual / honest limitations:** (a) **no built-in
    refresh scheduler or Settings wiring yet.** The helper is a standalone, opt-in `KeyProvider` (construct
    from a mounted document or via `bootstrap`); a deployment that wants periodic rotation drives `refresh()`
    from its own background loop, and there is deliberately no `MCPIP_JWKS_*` composition-root wiring in this
    wave — the default `StaticPEMKeyProvider` / single-IdP boot path is entirely unchanged, so the seam adds
    no new always-on surface. (b) **a persistently unreachable STS freezes the last good set.** Because a
    failed refresh retains (never empties) the current keys, an STS that stays down past the old key's real
    expiry would keep serving stale-but-valid keys until they naturally drop — the fail-*closed* choice
    (serve last-known-good) over fail-*open* (empty verifier). This is the intended posture: identity
    verification degrades to "no new keys" rather than "no verification."

18. **Audit attestation discloses only signed commitments (T17).** `GET /v1/audit/attestation` is read-only
    — it mints no key, signs nothing new, closes no epoch, and never runs on the emit hot path. **Residual /
    honest limitations:** (a) **it reflects, it does not independently re-derive trust.** `intact` is a fresh
    `verify_chain` over the in-Redis chain against the same WORM key; an external party still gains assurance
    by pinning `signing_key_id` to a WORM public key it obtained out-of-band and re-checking the returned
    epoch `signature` itself — the endpoint is a convenient transport for the already-signed commitments, not
    a new root of trust. (b) **it is plain-JWT-gated and production-exposed** (unlike sandbox-only
    verify/proof); this is deliberate because it leaks nothing beyond what `/v1/audit/proof` +
    `/v1/audit/verify` already surface (sealed header, chain result, anchor watermark, public key
    fingerprint) — no target, payload, PIN/OTP, or secret — so any authenticated operator/auditor of the
    tenant may fetch it. Neither is an integrity or opacity defect.

---

## 16. Verification hooks

Every control above is exercised, not merely asserted:

- **`python main.py`** runs the 29-check proof (7 allow-paths, 22 attacks) and a final
  `verify_chain`, exiting `0` only if all hold — the executable regression for T1–T9.
- **`app/main.py` end-to-end** (sandbox): `POST /v1/dev/token` → AUTO alias `200`;
  `skill_wire_transfer` no PIN → `202` → fetch OTP via `/v1/authenticator/{challenge_id}` →
  resubmit → `200` EXECUTED → replay → `403` (T2) → tamper → `403` (T1).
- **`verify_chain()`** re-runs against the persisted WORM JSONL at any time to re-prove T7.
- **`.venv/bin/python -m pytest tests/test_connector_conformance.py`** proves the connector
  posture of §1.3: golden vectors per format, cross-format parity of the resulting
  `NormalizedIntent`, registry pin integrity, and the AST purity guard (no LLM-SDK /
  HTTP-client / `socket` / env-credential import anywhere under `bridge/connectors/`).

---

## 17. ◐ ASI-2026 (OWASP Top 10 for Agentic Applications) coverage map

This section is the external-framework companion to the §11 attack→defense matrix. §11 organizes
MCPIP's defenses around **MCPIP's own primitives** (T1–T17); this crosswalk re-projects those same
T-items onto the **OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)** — now the canonical
buyer/auditor checklist (the internal strategy notes §5.1 **[verified]**). It adds **no new control**:
every cell points back to a T-item and its code in §11/§12/§15. The map is deliberately honest — it
claims dominance only where MCPIP structurally earns it and names the three categories MCPIP does
**not** cover, because a sophisticated buyer will otherwise find those gaps first.

**A word on what this map cannot do.** MCPIP is an authorization **interceptor** on the tool call —
it governs *what a verified identity is authorized to execute*, not *why the agent decided to act*.
Categories rooted in the agent's reasoning, memory, or the inter-agent bus are therefore upstream of
MCPIP's boundary. MCPIP **deliberately does not** add an in-agent probabilistic/behavioral-anomaly
detector to reach for those rows — that is the "the fox can't guard the henhouse" posture stated in
the internal strategy notes §5.7 and the the internal strategy notes §6 battlecard. Where MCPIP is out of scope, it says so and leads with the
deterministic **damage-limiting** it *does* provide (payload-bound OTP + velocity/amount engine +
write-before-execute WORM), never with a detector it refuses to build.

### 17.1 Verdict legend

- **STRONG** — home turf; a structural, deterministic control denies the class by construction.
- **PARTIAL / damage-limiting** — MCPIP does not *prevent* the class (its root is upstream), but a
  deterministic primitive **caps the blast radius** and/or makes the action forensically undeniable.
- **OUT-OF-SCOPE-BY-DESIGN** — the class lives in a plane MCPIP does not observe (the agent's
  memory, the A2A bus, multi-agent orchestration). Any listed mitigation is damage-limiting only, and
  the gap is stated plainly rather than papered over.

### 17.2 The map (ASI01–ASI10 → MCPIP primitives → §11 T-items)

| ASI | Category | MCPIP verdict | Defending primitive(s) → T-item(s) | Honest scope / gap |
|---|---|---|---|---|
| **ASI01** | Agent Goal Hijack | **PARTIAL / damage-limiting** | Payload-bound one-time PIN on every high-risk action → **T1** (`lock_payload_hash`); velocity/amount cap on per-identity blast radius → **T12** (`VelocityAmountPolicyEngine`); deep-strict arg walker rejects smuggled instruction text → **T3**. | MCPIP does **not** detect the hijack itself — the goal is corrupted upstream in the agent's reasoning. It caps consequence: a `PIN_REQUIRED` action needs a fresh out-of-band human OTP **regardless of why the agent decided to act**, and the velocity/amount engine bounds a hijacked identity. |
| **ASI02** | Tool Misuse & Exploitation | **STRONG (home turf)** | Payload-bound authorization — even a correctly-held capability cannot be redirected to a new target/amount without a fresh payload-bound approval → **T1**; opaque alias→target so the agent never names (nor can enumerate/reach cross-tenant) the real system → **T6**; deep-strict arg caps + char safety → **T3**; write-before-execute Merkle WORM records the exact payload before the side effect → **T7**. | This is MCPIP's core. "Authorization is **payload-bound, not capability-bound**" (§17.3b) is precisely the pre-execution, arguments-level tool-call authz that OAuth scopes and capability gates cannot express. |
| **ASI03** | Agent Identity & Privilege Abuse | **STRONG (home turf)** | JWT-only sovereign identity; alg-pinned, fully-claim-verified tokens → **T5**; `role` authorizes nothing — privilege is a UUID capability + active Redis grant → **T6b / §12 (T6c)**; in-band identity/capability/entitlement/grant keys are a **hard deny** (NFKC-casefold, not a strip) → **T4**; `Identity` is `frozen`. | ASI03 is the single most-reported enterprise agentic failure (`LANDSCAPE` §5.1) — and it is where MCPIP is strongest. An agent can never assert, mutate, or smuggle identity or authority; both derive **exclusively** from the verified token / Redis grants. |
| **ASI04** | Agentic Supply Chain | **PARTIAL** | Hash-pinned connector/vendor registry — an un-re-pinned edit refuses to boot (§1.3, invariants); community-skill **rug-pull re-verification** on every boot-load, additive-only + `cloud_rest`-only + `restricted ⇒ pin_required`, WORM-logged before apply → **T13** (`_hydrate_catalog_overlay`); AST-purity guard bars SDK/HTTP/socket imports (§1.3). | Covers **MCPIP's own** connector + community-skill supply chain. A **third-party MCP server MCPIP does not proxy is out of reach** — see the postmark-mcp honesty in §17.3c. |
| **ASI05** | Unexpected Code Execution | **PARTIAL (architecturally immune to the MCP subclass)** | Connectors are parser-only, AST-test-enforced; the gateway spawns **no** MCP subprocess and opens no outbound connection → §1.3 (`test_connector_conformance`). | The systemic MCP **stdio-RCE class** (OX Security, Apr 2026; `LANDSCAPE` §5.2 **[verified]**) **cannot exist by construction** (§17.3a). Out of scope: code the *agent itself* runs in its own runtime — that is upstream of MCPIP's boundary. |
| **ASI06** | Memory & Context Poisoning | **OUT-OF-SCOPE-BY-DESIGN** | Damage-limiting only: payload-bound OTP gates every high-risk action irrespective of the (poisoned) reasoning that produced it → **T1**; velocity/amount caps blast radius → **T12**; write-before-execute WORM + forensic reconstruction let an investigator trace a poisoned trajectory after the fact → **T7 / T10**. | MCPIP is stateless and sees only the individual tool-call payload — **zero visibility into the agent's memory/RAG store**, so a memory-poisoned agent's later well-formed, in-policy call is authorized normally (`LANDSCAPE` §5.7 **[likely]**). MCPIP **deliberately will not** add a per-identity behavioral detector to close this. |
| **ASI07** | Insecure Inter-Agent Communication | **OUT-OF-SCOPE-BY-DESIGN** | Damage-limiting only: MCPIP normalizes `SwarmTrace`/`Hop` structures, and payload-bound OTP still blocks the terminal side effect **iff** it is a governed `PIN_REQUIRED` alias → **T1**. | MCPIP authorizes one tool call from one governed identity; it does **not** sit on the A2A bus. Agent-session-smuggling and rogue-agent-card impersonation (Unit 42; `LANDSCAPE` §5.6 **[verified]**, §2.6 **[confirmed]**) occur in a plane MCPIP does not observe. Posture: be the **mandatory choke point for the side-effecting leg** of an A2A workflow, not the bus monitor. |
| **ASI08** | Cascading Agent Failures | **OUT-OF-SCOPE-BY-DESIGN** | Damage-limiting only: velocity/amount engine is a local per-identity circuit-breaker on the side-effecting leg → **T12**; fail-closed everywhere means a MCPIP outage **denies** rather than cascading open. | MCPIP governs the individual tool call, not multi-agent orchestration dynamics; it has **no view** of cascade propagation across agents (category is [verified] in the ASI list; MCPIP asserts no detection claim). |
| **ASI09** | Human-Agent Trust Exploitation | **PARTIAL / damage-limiting** | The payload-bound one-time PIN is the **structural circuit-breaker**: a `PIN_REQUIRED` action cannot complete without an out-of-band human OTP, whatever the agent claims → **T1**; opaque wire keeps real targets off the human's view surface → **T8**. | Forces a genuine out-of-band human step for high-risk actions (the answer to line-jumping's terminal leg; `LANDSCAPE` §5.5). But MCPIP **cannot judge whether the human approver was themselves deceived**, and does not detect the in-band social-engineering (upstream). |
| **ASI10** | Rogue Agents | **PARTIAL / damage-limiting** | A rogue/compromised agent still cannot forge identity (**T5**), self-assert capability (**T4 / T6b**), reach another tenant/compartment (**T6 / §12 T6c**), redirect a held capability to a new payload (**T1**), or double-spend an approval (**T2**); velocity/amount caps its blast radius (**T12**) and write-before-execute WORM makes its every action forensically undeniable (**T7**). | MCPIP does **not** detect *that* an agent has gone rogue — it deterministically constrains what **any** agent (rogue or not) is authorized to do, and records what it attempted. |

**Summary:** STRONG on **ASI02** and **ASI03** (deterministic, structural, home turf); PARTIAL /
damage-limiting on **ASI01, ASI04, ASI05, ASI09, ASI10** (blast-radius caps + immunity to the MCP
stdio-RCE subclass, not prevention of the root cause); OUT-OF-SCOPE-BY-DESIGN on **ASI06, ASI07,
ASI08** (memory, the inter-agent bus, and cascade dynamics all live in planes MCPIP does not observe).
The three out-of-scope rows are the honest ceiling of an interceptor that governs the tool call rather
than the agent — and MCPIP closes them with deterministic damage-limiting, never with the in-agent
probabilistic detection it rejects on principle.

### 17.3 Three positioning one-liners (carry the LANDSCAPE confidence labels)

**(a) The systemic MCP stdio-RCE class does not exist in MCPIP — `LANDSCAPE` §5.2 [verified].**
The "by design" MCP STDIO config→OS-command execution class (OX Security, Apr 2026; ~7,000 servers /
150M+ downloads) **cannot arise by construction** here: MCPIP's connectors are AST-purity-guarded,
parser-only modules — the build fails on any `socket`/subprocess/HTTP-client/LLM-SDK/env-credential
import under `bridge/connectors/` (`tests/test_connector_conformance.py`, §1.3) — and the gateway
spawns **no** MCP subprocess and opens no outbound connection. There is no "config → command" surface
to exploit. (Maps to **ASI05** above.)

**(b) Authorization is payload-bound, not capability-bound — the confused-deputy answer; cite the CSA
note, `LANDSCAPE` §5.3 [likely].**
The confused-deputy problem re-emerged as a top-severity 2026 pattern (an over-scoped tool tricked by
lower-privileged input into misusing its authority; CSA research note). MCPIP's answer is exactly the
one the discourse asks for: identity/authority derive **only** from a verified JWT (in-band identity /
capability / entitlement / grant keys are a hard deny — **T4**), `role` authorizes nothing (**T6b /
§12**), *and* MCPIP goes **beyond** capability gates by binding the exact **payload**
(`lock_payload_hash` over canonical JSON — **T1**), so even a correctly-held capability cannot be
redirected to a different target or amount without a fresh, payload-bound authorization. **Do not**
cite the future-dated arXiv id (2606.28679) that could not be opened — the CSA research note is the
source. (Maps to **ASI02 / ASI03**.)

**(c) The postmark-mcp rug pull is exactly the T13 threat MCPIP's own community-skill overlay defends —
with an honest interceptor caveat; `LANDSCAPE` §5.5 [verified].**
`postmark-mcp` (npm) was the first confirmed malicious MCP server in the wild — clean for 15 versions,
then v1.0.16 silently BCC'd every agent-sent email to an attacker domain. For **MCPIP's own** community
skills this is precisely the **T13** rug-pull threat MCPIP defends: `_hydrate_catalog_overlay`
re-verifies the pinned manifest and cross-checks the overlay fields on **every boot-load**
(additive-only, `cloud_rest`-only, `restricted ⇒ pin_required`, WORM-logged before apply), so a
post-approval swap is skipped and forces re-review. **Honest caveat:** postmark-mcp was a *third-party*
MCP server, and **MCPIP is an interceptor, not a proxy** — it would **not** have caught that package as
a raw upstream server, and (like line-jumping / tool-description injection) it does not detect the
injection itself for AUTO-classified reads. The differentiated defense holds only when **the sensitive
tool is a governed MCPIP alias**: then the covert extra BCC recipient rides in `arguments`, the
payload-bound authz binds the exact recipient set (**T1**), and write-before-execute WORM records the
real payload before it fires (**T7**) — so covert exfil is either payload-mismatch-denied or
forensically undeniable, and any `PIN_REQUIRED` action still cannot complete without an out-of-band
human OTP. The open item is a documented **deployment pattern where the sensitive tool IS an MCPIP
alias** rather than a raw third-party MCP server. (Maps to **ASI04**, with the ASI07/ASI09 upstream
caveat.)

---

*◐ MCPIP · Authorize every AI action before execution.*

## Session delegation — what it does and does not contain

Attenuated delegation (`docs/SESSION_DELEGATION_DESIGN.md`) lets a session grant
a child session a strict SUBSET of its own authority, and revocation cascades
down the subtree. Two boundaries to be clear-eyed about:

* **A copied bearer token defeats attribution, by construction.** An
  orchestrator that copies the parent's own token file to a worker instead of
  delegating is indistinguishable from the parent — same claims, same session.
  Delegation makes the governed path cheaper than the copy (one POST, and the
  child appears in the console lineage); it cannot make the copy impossible.
  Sender-constrained tokens (`cnf`/proof-of-possession) are the control that
  binds harder.
* **`session_id` is asserted, not proven.** It is a verified JWT claim — the
  IdP vouches for it — but nothing stops an IdP (or the sandbox forge) minting
  two tokens with the same session id. Attribution quality is exactly the
  IdP's issuance discipline; the delegation binding (grant → one child session
  + agent) is what the GATEWAY enforces.

### Adversarial review of delegation (closed)

An adversarial campaign against the delegation surface found and this release
closes three escalation paths — each now has a named regression in
`tests/test_redteam_regressions.py`:

* **Compartment escalation.** An un-compartmented (tenant-wide) parent — itself
  denied every compartmented alias — could pin a child *into* a compartment,
  and the authorize path overwrote the child's compartment with the grant's
  wholesale. Registration now accepts only `None` or the parent's own
  compartment, and the effective compartment is the *narrower* of the child's
  JWT and the grant — never wider than either.
* **Kill-switch evasion.** The principal kill-switch did not reach delegated
  descendants: a compromised admin could pre-position an escape delegation on a
  fresh `agent_id` and survive its own revocation. Principal revocation and
  quarantine now cascade to every ancestor agent in a delegation chain.
* **Audit-proof topology leak.** `/v1/audit/proof/{event_id}` returned the
  sealed record — carrying the obfuscator's hidden real target — to any
  authenticated caller of any tenant. It is now `CAP_DIRECTORY_ADMIN`-gated
  (the capability that already defines alias→target mappings) and tenant-scoped,
  with a cross-tenant lookup indistinguishable from an unknown event.
