# ◐ MCPIP — Community Extensibility: Author-Your-Own Skills & Gates (Design)

*Last updated: 2026-07-17. **Phase 1 (community SKILLS) is IMPLEMENTED and shipped** (see §7).
**Phase 2 (community GATES) ships here as the manifest SCHEMA + the deny-only seam** — the
`kind='gate'` manifest, the shared submit/review/WORM/hash-pin flow, `DenyReason.POLICY_GATE_DENIED`,
and a DENY-ONLY `CommunityGateProvider` seam wired at pipeline step 4c′ in BOTH entrypoints — with
the CEL **runtime DEFERRED** as an explicit owner dependency decision (see §8 for the as-built surface
and the exact transitive footprint). Phase 3 (registry/marketplace) remains design. Lets
customers/community author **skills** and **gates** with a reviewer-approval workflow, so MCPIP builds
fewer skills itself and turns users into the feature factory — without breaking the security invariants
or the revenue model. This is the highest-risk feature in the roadmap: a user-authored *gate* runs
inside a fail-closed authorizer. Companion to the internal roadmap, the internal strategy notes.*

---

## 0. Grounding — what a "skill" and a "gate" are today

- **Skill = an `AliasEntry`** (`obfuscator/alias_registry.py`): an immutable `alias→target` binding +
  `transport`, `risk_tier`, `classification`, optional `compartment`/`required_capability`/`canary`.
  Agents only ever name the opaque alias; the real target stays invisible. Skills are *declarative data*.
  The runtime add-path already exists — `CatalogOverlayStore` + `register_skill` / `_overlay_skill_invalid`
  / `_hydrate_catalog_overlay` — and is deliberately constrained: **additive-only** (refuses an alias
  that already resolves), **`cloud_rest` transport only**, **`restricted`⇒`pin_required`**, bounded
  (`MAX_OVERLAY_ENTRIES`), WORM-logged, tenant-scoped, boot-hydrated.
- **Gate = a pure deny predicate on the hot path.** Today: `_compartment_gate`, `_mandate_gate`. They
  **only raise `GatewayDeny`** (never grant), compare capability UUIDs/grants with `constant_time_equals`
  (never the `role` string), emit **closed-enum `DenyReason`s**, and run *before* the payload-lock hash.

**The load-bearing property:** MCPIP's gates are **monotonic-restrictive** (ALLOW→DENY only, never
DENY→ALLOW) — identical to the negative-grant cache and load-shedding. A community gate is just *one
more AND-term in the deny chain.* That is what makes user authorship tractable — the feature **can only
ever add denies, never subtract them.**

## 1. Two extension types — treated very differently

| | **Community Skill** (declarative catalog entry) | **Community Gate** (custom pre-exec authz) |
|---|---|---|
| What | new `alias→target` + metadata | a deny predicate on the hot path |
| Risk | **Low** (data; already modeled by `register_skill`) | **High** (runs inside the authorizer) |
| Ceiling | can only add a new opaque name onto a `cloud_rest` target; can't repoint, can't reach privileged transports | can only *add a deny*; can never bypass a gate or turn DENY→ALLOW |
| Mechanism | extend the existing overlay path | **declarative policy engine** (§2) |
| Approval | reviewer signs manifest → overlay register | reviewer signs manifest **+ static cost/whitelist proof** → policy load |

**Skills ship first; gates ship only as declarative policy.**

## 2. Running a user-authored gate without breaking fail-closed determinism

**Strong recommendation: declarative policy evaluated by a trusted engine — NOT arbitrary code. Use
CEL** (Cedar as the fuller-DSL alternative). Ranked:

1. **Declarative policy (CEL / Cedar). ADOPT.** Non-Turing-complete ⇒ termination + determinism by
   construction; ns–µs evaluation (Cedar benchmarks 42–80× faster than Rego) ⇒ sub-ms budget met with
   margin; **statically analyzable** ⇒ we can *prove* safety before approval (reject any policy whose
   static cost exceeds a fixed budget, or that references a non-whitelisted field). Canonical_json parity
   is untouched (a gate is a read-only predicate over already-normalized inputs — it never recomputes
   the lock hash or mutates `arguments`). No import surface, no `socket`, no host functions — the policy
   is *data*, so connector-purity is achieved for free. This is the Kubernetes `ValidatingAdmissionPolicy`
   shape (in-process CEL, chosen precisely to avoid external-webhook latency/trust).
2. **Sandboxed WASM (Wasmtime/Extism).** Viable but strictly worse here — safety depends on *our*
   host-boundary config being perfect, it's arbitrary code you're *containing* (vs. a predicate you can
   *read and prove*), and it adds a runtime to a codebase whose pitch is "std-lib + four pinned packages,
   air-gappable." **Reject for v1;** keep as a future escape hatch for genuinely computational gates.
3. **Signed + reviewed Python plugins. REJECT.** Even signed, arbitrary Python defeats every mechanical
   invariant at once (can import an HTTP client, run unbounded, read the real target and exfiltrate it,
   be non-deterministic). Human review does not scale to catching this — this is the option the
   invariants exist to forbid.

### The gate execution contract (normative)

A community gate is a compiled CEL/Cedar policy evaluated at a **new pipeline step 4c′** — right after
`_mandate_gate`, before the payload hash — mirroring where the base gates already sit:
1. **Deny-only / monotonic.** Decision = `base_gates_passed AND policy_gate_passed`. The base
   compartment/capability/sender-constraint/kill-switch gates run unconditionally and *first*; a policy's
   "true" is only *permission to not-deny*, never authority to execute.
2. **Whitelisted read-only context.** The policy sees only a fixed projection: `alias` (opaque),
   `risk_tier`, `classification`, caller `capabilities` (UUIDs), compartment-membership booleans,
   `tenant`, time, transport-*class*, and the *normalized* argument shape if explicitly allowed. **Never**
   `entry.target`, secrets, cross-tenant existence, or the vended credential.
3. **Fail-closed everywhere.** Compile error / missing policy / eval error / cost-overflow / timeout →
   `GatewayDeny(DenyReason.POLICY_GATE_DENIED)`. Never a silent pass. Redis-backed policy fetch fails
   closed like `is_disabled`.
4. **Closed-enum metric.** One new value `POLICY_GATE_DENIED` (no `skill_` prefix — dodges the metric-label
   guard, like the existing `alias_disabled`). *Which* policy denied goes to WORM only, never a label.
5. **Timing-uniform placement.** After the entitlement gates + a static cost bound + hard eval timeout ⇒
   a gate can't become a cross-compartment existence/timing oracle.

## 3. Approval workflow ("superior" review) — mapped to existing primitives

**Actors:** *Contributor* (any authenticated principal) → *Reviewer* (a **new `CAP_CATALOG_REVIEWER`**
capability UUID, separable from `CAP_DIRECTORY_ADMIN` so "can approve extensions" ≠ "can revoke
principals").

**Flow:**
1. **Author** — `POST /v1/extensions/submit` with an **extension manifest** (§4); stored pending
   in a new bounded, tenant-scoped `ExtensionSubmissionStore`.
2. **Review** — `GET /v1/admin/extensions/pending` shows the manifest + a rendered diff vs. the live catalog.
3. **Validate fail-closed before approve** — `POST /v1/admin/extensions/{id}/approve` re-runs the
   *authoritative* checks (skills: the shared `_overlay_skill_invalid`; gates: policy linter + static cost
   proof + context-whitelist proof). Approval is *refused* on any failure.
4. **Record tamper-evidently** — emit a WORM `admin_action="extension_approve"` with `kind`,
   `manifest_sha256`, reviewer `agent_id`, `correlation_id`. Because WORM is write-before-execute,
   hash-chained, and Ed25519-epoch-signed, **the approval itself becomes non-repudiable** — no extra
   signing root needed for local approval.
5. **Apply through the hardened path** — skills via the existing `register_skill` overlay; gates written
   to a **policy overlay** with the manifest `sha256` pinned.
6. **Hash-pin on load (rug-pull defense)** — hydration loads an approved skill/policy *only if* its stored
   `sha256` still matches; any post-approval edit changes the hash and is skipped/refused — the same
   pattern as the connector registry that "refuses to boot on unexpected edits."

For **cross-org distribution** (marketplace, Phase 3), add detached `authorship_sig` + `approval_sig`
over canonical manifest bytes (reusing `core/integrity.py`'s `canonical_signed_bytes`), verified at
import — a **fourth Ed25519 authority** (publisher/reviewer root) kept distinct from the release/license/
WORM-epoch roots. This is the OPA signed-bundle model (`.signatures.json` refuses activation unless every
hash matches).

## 4. Trust & safety — attacks and blocks

Manifest schema `mcpip-extension/1` (`kind: skill|gate`, `id`, `author`, `sha256`, optional sigs; skills:
`alias`/`target`/`transport=cloud_rest`/`risk_tier`/`classification`; gates: `language=cel`, `source`,
`referenced_context_fields ⊆ whitelist`, `max_cost ≤ budget`). Every human field runs through
`reject_unsafe_string` (rejects control/bidi/zero-width, NFKC-folds) — countering MCP tool-description
poisoning (OWASP MCP03:2025). Any identity-shaped key in a manifest field is rejected.

| Attack | Block |
|---|---|
| Gate that **always-allows a RESTRICTED action** | Impossible by algebra — gates are deny-only/monotonic; base gates run first and unconditionally. |
| Gate **leaks the real target / topology** | Whitelisted context has no `target`/secrets; the whitelist proof rejects any non-whitelisted reference; output is a boolean deny + closed-enum reason only. |
| Gate **runs arbitrary code / dials out** | It's declarative *data* — no imports, no `socket`, no host functions exposed. |
| Gate **loops / burns CPU / timing oracle** | Non-Turing-complete ⇒ terminates; static cost bound rejected at approval; hard timeout ⇒ fail-closed; placed after entitlement gates. |
| Skill **repoints an existing alias** | `register_skill` is additive-only — refuses any alias that already resolves. |
| Skill **smuggles a RESTRICTED AUTO read** (exfil via bearer) | `_overlay_skill_invalid` forces `restricted⇒pin_required`; hydrator skips offenders. |
| Skill onto a **privileged transport** | Overlay is `cloud_rest`-only; `legacy_mainframe`/`grant_issue`/`cloud_iam` unreachable from the community path. |
| **Rug-pull** (approved, then swapped) | Manifest `sha256` pinned at approval; any edit → load refused, re-review required. |
| **Forged approval / tampered audit** | Approval is a hash-chained, Ed25519-epoch-signed WORM event; `verify_chain` + anchor detect mutation/truncation. |

Every protection is **by construction**, not by reviewer vigilance — which is exactly why arbitrary code
(WASM or Python) is rejected for the gate substrate.

## 5. Business fit — "fewer skills, no lost revenue"

Anchored to the internal strategy notes (BSL core, price per governed agent identity, "mechanism open, feed paid"):

| Free / community (BSL core) | Paid enterprise |
|---|---|
| The gate **engine** (CEL/Cedar), manifest schema, validator/linter, cost/whitelist prover | **Marketplace hosting** + public **registry** (signed-bundle distribution + provenance) |
| The overlay register path + reviewer-approval workflow + WORM approval provenance | **Verified-publisher** program (with *actual* review) |
| Community can author **and self-approve within their own deployment** (inspectability is the product) | **Private registries** (a tenant's curated internal catalog) + **fleet approval control plane** |
| Single-node reviewer console | **Curated gate/skill intelligence feed** (Thinkst-Canary "mechanism open, feed paid") + compliance-evidence packs |

MCPIP stops hand-building connectors/skills — the community authors declarative skills and gates, driving
marginal cost per integration toward zero. Revenue lives not in the skills but in the **trust rails** —
review, signing, provenance, hash-pinned distribution, verified-publisher, private registries, fleet
control plane — exactly "the parts security teams pay for." More community skills = more governed surface
= more revenue (orthogonal to the per-agent metric — never a metering disincentive). The public evidence
that a marketplace *badge alone is worthless* (GitHub doesn't inspect action code; Smithery scanned MCP
servers and still leaked 3,000+ credentials) is precisely why *actual signed review + hash-pinned
provenance* is a paid differentiator, not a commodity.

## 6. Phased build plan (files/endpoints)

**Phase 1 — declarative community skills + reviewer approval + WORM record (MVP). ✅ IMPLEMENTED —
see §7 for the as-built surface.** `interfaces.py`: add `CAP_CATALOG_REVIEWER` UUID +
`MAX_PENDING_SUBMISSIONS`. New `services/extension_manifest.py` (`mcpip-extension/1` schema +
`reject_unsafe_string` + identity-fold hard-deny + a `sha256` self-pin via
`core.integrity.canonical_manifest_bytes`), `services/extension_submissions.py`
(`ExtensionSubmissionStore`). `app/main.py`: `POST /v1/extensions/submit` (Contributor —
deliberately OFF the `/v1/admin/*` prefix, see §7), `GET /v1/admin/extensions/pending`,
`POST /v1/admin/extensions/{id}/{approve,reject}` (approve re-validates via `_overlay_skill_invalid`,
WORM-records `extension_approve` BEFORE apply, applies via the shared `_apply_overlay_skill` overlay
path, hash-pins the approved manifest). NOTE: `DenyReason.POLICY_GATE_DENIED` is **NOT** reserved in
Phase 1 — it belongs to the deferred Phase 2 gate seam (§8); a skill submit/approve/reject failure is
simply the opaque `MCPIPDenied` (no new agent-facing deny string).

**Phase 2 — gates-as-policy. ✅ SEAM + SCHEMA SHIPPED (CEL runtime DEFERRED — see §8).** As-built:
`interfaces.py` adds `DenyReason.POLICY_GATE_DENIED`, the `MAX_GATE_COST` budget, the
`GATE_CONTEXT_FIELDS` whitelist, and the frozen `CommunityGateContext`/`GateDecision`/
`CommunityGateProvider` seam types. `services/extension_manifest.py` adds the `kind='gate'`
`GateManifest` variant (`language='cel'`, `source`, `referenced_context_fields ⊆ GATE_CONTEXT_FIELDS`,
`max_cost ≤ MAX_GATE_COST`, the same `sha256` self-pin) — DATA validation only, NO CEL parse.
`services/community_gate.py` ships the `NoOpCommunityGateProvider` default + the
`register_community_gate_engine`/`active_community_gate_provider` registration seam. The pipeline
inserts **step 4c′** (`_community_gate`) right after `_mandate_gate` in BOTH `main.py` and `app/main.py`,
identically ordered; the community submit/review handlers route `kind='gate'` through the SAME
flow, and the approve path REFUSES a gate while no static prover/engine is registered
(no approve-without-proof). What remains DEFERRED (owner CEL-runtime decision, §8): the trusted CEL
engine (`compile-at-load`, static cost + whitelist proof, fail-closed) that would implement
`CommunityGateProvider` AND supply the approve-time prover, the boot-lint
`_enforce_policy_gate_compilable`, and the tests `test_community_gate_monotonic.py` (proves no
DENY→ALLOW), `test_community_gate_whitelist.py` (rejects `target`/secret refs),
`test_community_gate_approval_refused.py` (no approve-without-proof). Enabling the engine is purely
additive — a single `register_community_gate_engine(...)` call activates hot-path evaluation and unlocks
gate approval.

**Phase 3 — registry / marketplace.** Fourth Ed25519 publisher/reviewer root; detached
`authorship_sig`+`approval_sig` verified at import (OPA signed-bundle + Sigstore provenance); `services/extension_registry.py`
+ `/v1/registry/*`; verified-publisher metadata; private-registry scoping; fleet signed-bundle rollout (paid).

## 7. Phase 1 as-built — community SKILLS (shipped)

Phase 1 ships FULLY and for real via the existing hardened overlay path — a community skill is just
one more additive `AliasEntry` both entrypoints resolve identically. No hot-path change; `main.py`
(the demo entrypoint) is untouched because it has no operator/admin HTTP control plane, and the two
entrypoints stay in lockstep on the authorization hot path this feature does not alter.

**Capability + limits (`interfaces.py`, single source of truth).** `CAP_CATALOG_REVIEWER`
(a fresh, frozen uuid4) is DISTINCT from `CAP_DIRECTORY_ADMIN` and `CAP_FORENSIC_READ`: "can approve
community extensions" ≠ "can revoke a principal" ≠ "can read raw forensic payloads". Matched
constant-time; the `role` claim authorizes nothing; holding either sibling capability does NOT
confer it. `MAX_PENDING_SUBMISSIONS = 256` bounds the per-tenant PENDING queue; applied skills stay
bounded by the existing `MAX_OVERLAY_ENTRIES = 512`.

**Manifest (`services/extension_manifest.py`, `mcpip-extension/1`, strict `extra='forbid'`).**
`kind='skill'` ONLY (a `kind='gate'` manifest is refused at the schema boundary until Phase 2).
Every human field (`id`/`author`/`alias`/`target`) runs through `reject_unsafe_string`;
`id`/`author`/`alias` are additionally folded with the bridge `_identity_fold` and hard-denied
against `_FORBIDDEN_IDENTITY_KEYS` (so `alias='role'` / homoglyph / bidi variants trip). `transport`
is the literal `cloud_rest`. The manifest carries a `sha256` **self-pin** computed with the
`core/integrity.py` discipline via a new sibling `canonical_manifest_bytes` (sort_keys/compact, drops
BOTH `sha256` and the reserved `signature`) — DISTINCT from the payload-lock `canonical_json`, so
`canonical_json`/`enforce_argument_safety`/the PIN-hash and their Rust parity are untouched and no
gate/lock hash is ever recomputed. The AUTHORITATIVE per-skill validity rule stays the single
`app.main._overlay_skill_invalid` predicate (charset / risk∈{auto,pin_required} /
classification∈{unclassified,restricted} / target 1..512 & newline-free / restricted⇒pin_required),
re-run by both submit and approve.

**Store (`services/extension_submissions.py`).** Two per-tenant Redis namespaces:
`mcpip:ext:pending:{tenant}` (`submission_id → record`) and `mcpip:ext:approved:{tenant}`
(`alias → {canonical manifest, pinned sha256, reviewer, approved_at}`). Writes fail CLOSED
(`LockError` on `RedisError`, like `CatalogOverlayStore.add`); listing reads fail SOFT. The tenant
comes only from the JWT, so a reviewer only ever reaches its own tenant's keyspace — cross-tenant
approve is structurally impossible.

**Endpoints (`app/main.py`).**
- `POST /v1/extensions/submit` — Contributor (`_require_authenticated`: JWT + BOTH kill-switches, NO
  capability). **Deliberately OUTSIDE `/v1/admin/*`** so the "everything under `/v1/admin` is
  admin-gated" convention holds and an operator can't misread the surface. Validates → bounds the
  queue → WORM `extension_submit` BEFORE store → PENDING. It does **not** probe `registry.has_alias`
  (submit is broadly reachable; a catalog lookup would be an alias-existence oracle for un-entitled
  contributors) — conflict resolution is deferred to the reviewer-gated approve.
- `GET /v1/admin/extensions/pending` — Reviewer, read-only, tenant-scoped, strict whitelist
  projection + a rendered `conflicts_existing_alias` diff and a `submitter_is_reviewer`
  separation-of-duties hint. The submitter-declared `target` is a reviewer-only surface — it NEVER
  crosses the agent wire.
- `POST /v1/admin/extensions/{id}/approve` — Reviewer. Re-parse + re-validate the manifest
  authoritatively (recompute+compare the `sha256` pin, re-run `_overlay_skill_invalid`, additive-only
  `has_alias`, `MAX_OVERLAY_ENTRIES` ceiling); ANY failure → opaque deny, no state change. WORM
  `extension_approve` (`kind`, `manifest_sha256`, reviewer + submitter `agent_id`, `alias`,
  `transport`, `risk_tier`, `correlation_id`) BEFORE apply → persist the pinned approved manifest →
  mint via the shared `_apply_overlay_skill` (the SAME path `register_skill` uses) → mark APPROVED.
- `POST /v1/admin/extensions/{id}/reject` — Reviewer. WORM `extension_reject` then mark REJECTED — no
  apply.

**Rug-pull defense on load.** `_hydrate_catalog_overlay` re-verifies any overlay row bearing
`source='community'`: it recomputes the manifest digest from `mcpip:ext:approved:{tenant}`,
`hmac.compare_digest`s it against the pin, AND cross-checks the overlay fields against the pinned
manifest — a post-approval edit of the manifest OR the overlay fields desyncs the digest and the
entry is SKIPPED (load refused → re-review required). Operator rows (no `source` key) hydrate exactly
as before — additive, no behavior change.

**Separation-of-duties residual (open).** Submit is any authenticated principal; approve requires the
distinct `CAP_CATALOG_REVIEWER`, so a plain contributor cannot approve its own submission. A single
principal holding BOTH could self-approve on one node — EXTENSIBILITY §5 frames single-node
self-approval as an intended community tier; true dual-control / cross-org non-repudiation is the
Phase 3 detached `authorship_sig`+`approval_sig` (a fourth Ed25519 root). The reviewer console
surfaces `submitter_is_reviewer` as a visible warning in the interim. Deregistration/GC of an
APPROVED community skill (and its `mcpip:ext:approved:{tenant}` manifest) is not specified in Phase 1;
until then an approved community alias is removable only by the operator skills-deregister path
(which would leave a dangling approved-manifest entry) — reuse `deregister_skill` or defer to Phase 3.

## 7a. Phase 3a as-built — registry-sourced skill governance (X3, shipped)

A skill sourced from an **MCP-Registry `server.json`** is now governed as a first-class community
extension by **projecting it into the already-hardened Phase-1 overlay path** — never a parallel mint
path. It therefore inherits the overlay guarantees EXACTLY (additive-only HSETNX, `cloud_rest`-only,
never-repoint, no privileged transport, no `restricted`+`auto`, `reject_unsafe_string` on every human
field, `id`/`author`/`alias` identity-fold hard-deny, boot-load rug-pull re-verify).

- **Manifest variant** (`services/extension_manifest.py`): `RegistryServerManifest`
  (`kind='registry_server'`, strict `extra='forbid'`, frozen) wraps the MCPIP-side opaque `alias` +
  reviewer/submitter-declared `risk_tier`/`classification` + a `sha256` self-pin (same
  `canonical_manifest_bytes` discipline, DISTINCT from the payload lock) and EMBEDS the pasted
  `server.json` under `server` (`RegistryServerJson`: reverse-DNS `namespace/name`, description,
  version, `_meta` provenance, bounded `remotes[]`). The cloud_rest **target is DERIVED** from the
  single `remotes[]` entry whose type is a remote-HTTP transport (`sse`/`streamable-http`) over
  **https** — a `server.json` with only local `packages` (npm/pypi/docker/stdio) and no remote is
  REFUSED (a local/stdio server can never become a governed cloud_rest alias). `.alias/.target/
  .transport(=`cloud_rest`)/`.risk_tier`/`.classification`` accessors drop it into
  `_overlay_skill_invalid` / `_apply_overlay_skill` / `_community_pin_valid` UNCHANGED.
- **Verified-publisher = a reviewer-PINNED allow-list** (`services/registry_publishers.py`,
  `VerifiedPublisherStore`, per-tenant `mcpip:ext:publishers:{tenant}`, schema
  `mcpip-registry-publishers/1`) of allowed publisher **namespaces** (the reverse-DNS prefix of the
  server name). At APPROVE the parsed publisher namespace MUST be a member — the read is **fail-CLOSED**
  (Redis error / absent / malformed ⇒ not verified ⇒ approval REFUSED). Consulted only at approve + boot,
  **never on the auth hot path**, and **never a live registry/PKI fetch** (the submitter/reviewer PASTE
  the `server.json`). The `server.json`'s own `_meta` provenance is **RECORDED to WORM but NEVER trusted**
  for authorization (the official registry is preview/unsigned).
- **Surface** (`app/main.py`): additive `kind='registry_server'` routing in `POST /v1/extensions/submit`;
  a registry branch in `POST /v1/admin/extensions/{id}/approve` enforcing the verified-publisher gate;
  and `GET`/`PUT /v1/admin/extensions/publishers` (CAP_CATALOG_REVIEWER, tenant-scoped, opaque deny,
  `PUT` emits WORM `registry_publishers_put` before the write). Boot `_community_pin_valid` is kind-aware:
  a `registry_server` row re-parses via `verify_registry_manifest_pin`, compares the projected overlay
  fields identically, AND re-confirms the publisher namespace is still allow-listed (fail-closed skip →
  re-review). The reviewer pending list gains a `registry_server` projection (alias, target [reviewer-only],
  publisher namespace, provenance, version, live `verified` flag, `conflicts_existing_alias`).
- **Operator surfaces** — the reviewer allow-list is reachable outside raw HTTP with full parity:
  `mcpip admin publishers get` / `set --namespace … | --file …` (CLI),
  `MCPIPAdminClient.verified_publishers_get()`/`verified_publishers_put()` (Python) and
  `verifiedPublishers()`/`verifiedPublishersPut()` (TypeScript). The set REPLACES the pinned
  allow-list (it does not merge); an honest empty `{schema, namespaces: []}` is returned before
  anything is pinned. No surface mints identity or repoints an alias — it is a trust-rail only.

**Deferred (next paid-rail increment, NOT shipped):** the detached-signature / "**4th Ed25519
publisher/reviewer root**" form of verified-publisher (§Phase 3, cross-org signed-bundle distribution) —
X3 ships the pinned allow-list only and adds **no new trust root**. The marketplace UI and signed-bundle
distribution remain design.

## 8. Deferred (explicit OWNER decision): the community-GATE CEL runtime

Phase 2 (community GATES) ships — **as-built in this wave** — the gate **manifest schema**, the shared
submission/review/WORM/hash-pin flow (same as skills, `kind='gate'`), a new
`DenyReason.POLICY_GATE_DENIED`, and a DENY-ONLY `CommunityGateProvider` **seam** at pipeline step 4c′
(right after the mandate gate, adjacent to the G3 policy gate), wired identically in BOTH `main.py` and
`app/main.py`. The actual CEL **parse / lint / evaluate runtime is DEFERRED** — it is a
dependency-adoption decision reserved for the owner, NOT made here.

**As-built map (this wave).**
- `interfaces.py` — `DenyReason.POLICY_GATE_DENIED = "policy_gate_denied"` (DISTINCT from the G3
  `POLICY_DENIED`; no `skill_` substring, so it clears the metric-label guard); the `MAX_GATE_COST`
  budget hard limit; the `GATE_CONTEXT_FIELDS` whitelist `{alias, risk_tier, transport_class,
  classification}`; the frozen `CommunityGateContext` (carries EXACTLY the whitelist — no target, no
  secrets, no arguments, no identity handle), `GateDecision` (deny-only: outcome ∈ {continue, deny},
  no allow), and the `CommunityGateProvider` ABC.
- `services/extension_manifest.py` — the `kind='gate'` `GateManifest` variant + `parse_gate_manifest` +
  the `manifest_kind` router. DATA validation only (schema/charset/identity-fold/whitelist-subset/
  `max_cost ≤ MAX_GATE_COST`/`sha256` self-pin) — **no CEL parse**, so submitting/validating/storing a
  gate never touches a CEL runtime.
- `services/community_gate.py` — `NoOpCommunityGateProvider` (the default; always `continue`) plus the
  `register_community_gate_engine` / `active_community_gate_provider` /
  `community_gate_engine_registered` registration seam. **No `celpy` import anywhere.**
- `main.py` + `app/main.py` — step 4c′ `_community_gate`, deny-only, fail-closed on any provider error;
  the community submit/review handlers route `kind='gate'` through the same flow; the approve path
  REFUSES a gate while no static prover/engine is registered.

**Why deferred — the exact transitive footprint.** Adopting an in-process CEL evaluator (`cel-python`
/ `celpy`) pulls a **native-extension** dependency chain into a fail-closed authorizer whose entire
pitch is "std-lib + a few pinned pure-Python packages, air-gappable":

- `cel-python` (`celpy`) →
- **`google-re2`** — a **native C++ extension** (RE2 must be built/linked; a manylinux wheel or a
  system RE2 + a compiler on the build host), which enlarges the air-gap bundle and the
  supply-chain/CVE surface of the authorizer far beyond the current pure-Python posture;
- **`pendulum`** — a datetime library that itself ships a compiled (Rust/C) extension in recent
  releases;
- **`jmespath`** — pure-Python, minor, but still one more import in the hot authorization path;
- plus `lark`/parser machinery.

That is a materially different dependency/air-gap/attestation surface than the approved design
assumed (the integrity manifest, SBOM, and offline-bundle stories all widen). Because MCPIP's
security argument rests on a small, auditable, pure-Python footprint, **whether to take on a native
CEL extension is an owner call, not an implementer default.** Therefore, in this wave:

- **No `cel-python`/`celpy` (or any CEL/Cedar lib) is added** to `requirements*`/`pyproject.toml`.
- **`celpy` is never hard-imported**; the module is not installed and importing it must not be
  required for any test to pass.
- The `CommunityGateProvider` seam functions as a strict, fail-closed **NO-OP when no gate engine is
  registered** — honestly reporting "no community gate engine configured" (there are genuinely no
  community gates enforced), never a fabricated pass. It is deny-only: it can only ever ADD a
  `POLICY_GATE_DENIED`.
- Gate **approval is fail-closed without the runtime.** A gate manifest can be submitted +
  schema-validated + stored, but since the static CEL cost/whitelist **prover** needs the deferred
  CEL runtime, an approval that cannot be statically proven safe MUST refuse — **no
  approve-without-proof.** Enabling the runtime later is purely additive (the schema, the flow, the
  seam, and the `POLICY_GATE_DENIED` member are already in place; only the engine registration turns
  it on).

**AuthZEN-shape alignment (as-built, X4 — no runtime adopted).** The Wave-8 COAZ/AuthZEN decision
surface `POST /v1/authz/decision` and the community-gate seam now share ONE evaluation model, pinned
against drift. AuthZEN models an evaluation as a SARC tuple — **S**ubject / **A**ction / **R**esource /
**C**ontext. The shared `CommunityGateContext` IS the SARC **`resource`** entity: `id = alias` (opaque),
and `properties = {risk_tier, transport_class, classification}` (the coarse whitelist). The AuthZEN
`subject` (identity) and `action` (arguments) contribute **NOTHING** to the gate context — that
topology-free / identity-free / argument-free guarantee is now expressed *as data* by
`interfaces.GATE_CONTEXT_AUTHZEN_ENTITY` (a frozen `MappingProxyType` whose keyset is test-pinned to
equal `GATE_CONTEXT_FIELDS`, every value a `resource.*` slot). The pure, read-only projection
`CommunityGateContext.as_authzen_resource()` returns the `{type, id, properties}` view a COAZ engine
consumes — whitelist-only (property keys = `GATE_CONTEXT_FIELDS − {alias}`, values the `str,Enum`
`.value`), so it can never become a topology/identity leak even if a future engine logs it. The
direction is **OUTBOUND only** (context → AuthZEN resource): there is deliberately NO inbound helper
reading a client-supplied resource into the whitelist, because at `/v1/authz/decision` the four coarse
fields are SERVER-derived from the resolved `AliasEntry` (only `resource.id` is client-authority, and it
is resolved server-side) — an inbound path would be a classification/risk downgrade-injection lane. This
adds **no** endpoint/response change (`AuthzenDecisionResponse` stays `{decision, obligations?}`), **no**
`GateDecision`/whitelist widening, and **no** dependency: the only new imports are stdlib
`types.MappingProxyType` + `typing.Mapping`. It confirms — rather than relaxes — the deferral below: the
CEL parse/lint/evaluate **runtime** is still the single deliberate owner dependency decision, activated
by exactly one additive `register_community_gate_engine(...)` call; **no `celpy` (or any CEL/Cedar/
policy-DSL lib) is imported or added to `requirements*`/`pyproject.toml`.**

Reserving `signature` in `canonical_manifest_bytes` today (dropped from the digest even though Phase 1
verifies no detached signature) likewise keeps the Phase 3 cross-org signing extension additive.

**Bottom line:** declarative policy over a trusted, statically-analyzable engine, executed as a
deny-only monotonic gate over a topology-free whitelisted context, approved by a distinct reviewer
capability, recorded in the tamper-evident WORM chain, and hash-pinned against rug-pulls — every
invariant preserved by construction. Phase 1 (skills) is that shape shipped for real; Phase 2 (gates)
awaits the owner's CEL-runtime dependency decision.
