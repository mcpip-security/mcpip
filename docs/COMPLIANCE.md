# ◐ MCPIP — Compliance Control-Mapping Pack

**Release:** 2.0.0 · **Date:** 2026-07-14

## Scope & honesty statement (read first)

This document maps MCPIP's **implemented, testable technical controls** to the control
families of SOC 2 (Trust Services Criteria) and FedRAMP (NIST SP 800-53 rev. 5). It is
an **illustrative mapping prepared by the vendor, not a certification, attestation, or
audit opinion**. SOC 2 reports and FedRAMP authorizations attest to an *operating
organization's* people, processes, and environment over time; MCPIP is a software
product. What this pack does is show an assessor, for each cited control, exactly
**which shipped mechanism** contributes evidence, and **where in the repository** the
mechanism lives so it can be independently verified.

Controls that belong to the deploying organization (personnel security, physical
security, vendor management, organizational risk assessment, …) are out of scope and
are not claimed. Where a control is only *partially* addressed by the product, the
mapping says so.

---

## 1. The control inventory (what actually ships)

| # | Control | Mechanism | Evidence / where to verify |
|---|---|---|---|
| T1 | **Signed releases** | Ed25519 signature (offline root key) over a manifest of SHA-256 artifact digests; canonical-JSON signing rule; detached + embedded signature | `release/manifest.json`, `release/manifest.sig`, `scripts/sign_release.py`, `mcpip_verify/verifier.py` |
| T2 | **Independent, fail-closed verification** | `mcpip verify` — read-only, network-free, TLS-independent; opaque failure, exit 2 | `mcpip_verify/cli.py`, `tests/test_release_tooling.py` |
| T3 | **SBOM** | CycloneDX JSON of the fully-resolved pinned dependency set; hashed and listed in the signed manifest (signed transitively); offline CVE-scan runbook | `release/sbom/mcpip-2.0.0.cdx.json`, `scripts/build_sbom.sh` |
| T4 | **Verified boot (source integrity)** | Startup re-hash of the entire shipped source set against a release-root-signed integrity manifest; any mismatch aborts before a socket binds; no remediation/self-heal path | `core/integrity.py`, `release/integrity_manifest.json`, `scripts/gen_integrity_manifest.py`, `tests/test_release_hooks.py` |
| T5 | **No runtime self-update** | No updater, no code-pull, no self-mutation exists anywhere in the product; upgrades are operator-controlled redeploys of immutable, digest-pinned images | absence is the control — T4 makes any post-deploy source change a boot failure |
| T6 | **Fail-closed posture** | Missing keys/license/manifest, unknown format/vendor/alias, any parse or dependency failure → boot refusal or opaque deny; deny reasons only in the audit log | `core/config.py`, `app/main.py`, `interfaces.py` (`MCPIPDenied`), `SECURITY_THREAT_MODEL.md` |
| T7 | **Tamper-evident audit (WORM)** | Write-before-execute durable buffer (Redis AOF `appendfsync always`); per-epoch Merkle roots, root-chained, Ed25519-signed; O(log n) inclusion proofs; out-of-tamper-domain signed head anchor detecting rollback/truncation; read-only export with independent root recomputation | `audit/worm_logger.py`, `audit/merkle.py`, `audit/anchor.py`, `mcpip_verify/audit_export.py`, `redis.conf` |
| T8 | **Cryptographic identity (M2M)** | Identity exclusively from verified JWT (EdDSA/RS256; `alg=none` and HMAC-confusion rejected; 8 required claims); identity-shaped keys in payloads are a hard deny | `auth/token_resolver.py`, `bridge/intent_parser.py` |
| T9 | **Least privilege: UUID capabilities & compartments** | Privileged actions gate on capability UUIDs (never role strings); compartmented aliases deny without a direct claim or an active delegated grant; catalog visibility filtered so other teams' assets cannot be enumerated | `interfaces.py`, `obfuscator/alias_registry.py`, `services/grant_store.py` |
| T10 | **Exactly-once approval (anti-replay/TOCTOU)** | Payload-bound one-time lock consumed in a single atomic Redis Lua EVAL; one byte of drift → `PAYLOAD_MISMATCH` | `auth/pin_validator.py` |
| T11 | **Offline license/entitlement gate** | Ed25519-signed license verified at boot only (separate root key); never consulted per-request; fail-closed | `core/licensing.py`, `scripts/gen_license.py` |
| T12 | **Key separation & rotation** | Three independent Ed25519 roots (release / license / audit-epoch); private keys offline-only and gitignored; shipped rotation manifest with key ids, status, supersession | `scripts/gen_release_keys.py`, `release/keys/rotation.json`, `.gitignore` |
| T13 | **Sanitized telemetry** | `/metrics` label vocabulary is a closed set enforced by construction — no tenant/agent/alias/compartment/capability/correlation/JWT/approval-code data in names or labels | `core/metrics.py`, `app/main.py` (`/metrics`) |
| T14 | **Overload protection** | Per-worker admission bound → opaque `503 + Retry-After`; request-size pre-check (`413` before reading an oversized body); per-request timeout; shedding structurally cannot convert DENY→ALLOW | `app/main.py` (edge middleware), `core/config.py` |
| T15 | **Hardened, minimal runtime** | Non-root UID, read-only rootfs, `cap_drop: ALL`, `no-new-privileges`, internal-only Redis network, default-deny NetworkPolicy, digest-pinned deploys, no secrets in image | `Dockerfile`, `docker-compose.yml`, `k8s/`, `chart/` |
| T16 | **No vendor egress / no vendor keys** | Connectors are pure parsers; an AST conformance test fails the build on any LLM-SDK/HTTP/socket/credential import under `bridge/connectors/`; vendor→format registry hash-pinned at import | `bridge/connectors/`, `tests/test_connector_conformance.py`, `bridge/connectors/registry.py` |

---

## 2. SOC 2 mapping (Trust Services Criteria)

Common Criteria references are to the 2017 TSC (with 2022 points of focus). "Product
contribution" states what MCPIP provides; the deploying organization still owns the
surrounding process evidence.

| TSC | Criterion (abbrev.) | Product contribution |
|---|---|---|
| CC5.2 / CC5.3 | Control activities over technology | T4/T5/T6: the product enforces its own configuration integrity at boot and fails closed on misconfiguration, turning "was the control in place?" into a boot invariant. |
| CC6.1 | Logical access security software | T8/T9/T10: JWT-only identity, capability-UUID authorization, compartment need-to-know, exactly-once approval locks on high-risk actions. |
| CC6.2 / CC6.3 | Registration, authorization, and removal of access | T9: grants are explicit, TTL-bounded, compartment-scoped, and issuance is itself an authorized, step-up-gated, audited action; revocation/expiry re-denies immediately. |
| CC6.6 | Boundary protection | T14/T15/T16: default-deny network posture, internal-only Redis, empty vendor-egress requirement, admission control at the edge. |
| CC6.7 | Restrict transmission/movement of information | T13 + the obfuscation layer: real targets never cross the agent boundary; denials are opaque; metrics carry no payload data. |
| CC6.8 | Prevent/detect unauthorized software | T1–T5: signed releases, digest-pinned deployment, verified boot rejecting any modified source, no self-update channel to subvert. |
| CC7.1 | Detect configuration changes / vulnerabilities | T3 (SBOM + offline CVE scanning) and T4 (any source drift is a detected, blocking event at next boot). |
| CC7.2 / CC7.3 | Monitor system components; evaluate events | T7/T13: every decision lands in the tamper-evident WORM log before execution; Prometheus counters expose decision/deny/shed rates; correlation ids join wire events to audit records. |
| CC7.4 / CC7.5 | Incident response and recovery | Partial — the product supplies the forensic substrate (intact-or-tampered verdicts, first-bad-epoch localization, read-only export, anchor-based rollback detection) and a documented IR runbook (`docs/OPERATIONS.md` § 9); the organization owns the IR program itself. |
| CC8.1 | Change management | T1/T2/T5: changes reach production only as new signed, verified, digest-pinned releases through operator change control; there is no in-place change path to manage exceptions for. |
| A1.2 (Availability) | Recovery infrastructure | Partial — T14 (bounded-tail overload behavior), stateless horizontal scaling, documented audit backup/restore (`docs/OPERATIONS.md` § 8). |
| PI1 (Processing integrity) | Complete, accurate, timely, authorized processing | T6/T7/T10: authorization-before-execution with a durable record emitted before the action, exactly-once semantics on approvals, fail-closed on every ambiguity. |
| C1 (Confidentiality) | Identify and protect confidential information | T9/T13 + obfuscation: compartment need-to-know, alias indirection, redaction of `pin`/`jwt`/`token` fields in audit records, sanitized metrics. |

## 3. FedRAMP mapping (NIST SP 800-53 rev. 5 families)

| Family | Representative controls | Product contribution |
|---|---|---|
| **AC** — Access Control | AC-2, AC-3, AC-4, AC-6 | T8/T9: enforcement of approved authorizations (AC-3) via capability UUIDs; least privilege (AC-6) via compartments + scoped grant issuance (no tenant-wide master key); information-flow control (AC-4) via alias indirection and catalog filtering. |
| **AU** — Audit & Accountability | AU-2, AU-4, AU-9, AU-10, AU-12 | T7: signed Merkle-epoch WORM with write-before-execute ordering; AU-9 (protection of audit information) via Ed25519-signed epoch chain + out-of-domain anchor; AU-10 (non-repudiation) via per-epoch signatures and inclusion proofs; export tooling for AU-6 review support. |
| **CM** — Configuration Management | CM-2, CM-3, CM-5, CM-6, CM-7, CM-14 | T1/T4/T5: baseline = the signed release manifest; CM-5 (access restrictions for change) enforced cryptographically — an unsigned change cannot boot; CM-14 (signed components) directly implemented; CM-7 via the minimal, parser-only, no-egress design. |
| **IA** — Identification & Authentication | IA-2/IA-9 (service auth), IA-5 | T8: cryptographic machine-to-machine identity with pinned algorithms and full claim validation; IA-5 partially — the product consumes operator-managed PEMs and documents rotation; credential lifecycle is organizational. |
| **SC** — System & Communications Protection | SC-8, SC-13, SC-28, SC-39 | T1/T7/T12: FIPS-standard primitives (SHA-256, Ed25519) via the `cryptography` library; verification independent of transport security; compartment isolation; note MCPIP does not itself terminate TLS — SC-8 in transit is the deployment's ingress concern. |
| **SI** — System & Information Integrity | SI-2, SI-3, SI-7 | **SI-7 (software/firmware integrity) is the product's core**: T4 verified boot with cryptographic integrity checks at startup and fail-closed response; SI-2 supported by SBOM-driven offline vulnerability scanning; flaw remediation itself is the redeploy process. |
| **CP** — Contingency Planning | CP-9, CP-10 | Partial — documented, verifiable backup/restore of the audit ledger (`docs/OPERATIONS.md` § 8), with restore verification that detects restoring a rolled-back ledger. Organizational CP program is out of scope. |
| **SR** — Supply Chain Risk Management | SR-3, SR-4, SR-11 | T1/T2/T3/T16: provenance (SR-4) via signed manifests + SBOM; SR-11 (component authenticity) via offline-verifiable signatures and out-of-band key fingerprints; the air-gap bundle gives acquirers a network-free acceptance-testing path. |
| **IR** — Incident Response | IR-4, IR-5 | Partial — tamper localization (first bad epoch), forensic export, and a written IR runbook ship with the product; the IR capability/organization is the deployer's. |

---

## 4. Data-flow description

### 4.1 What flows where

```
  Agent/LLM client (holds its OWN vendor keys; MCPIP never sees them)
        │  HTTPS (operator's ingress) — JWT + raw tool-call + optional pin/challenge_id
        ▼
  MCPIP gateway  ◐ Bridge → Obfuscator → Auth → Audit   (single process, stateless)
        │  1. correlation_id assigned first
        │  2. parse/normalize (declared format — never sniffed)
        │  3. alias → real target (tenant/compartment scoped)
        │  4. JWT verify; capability/compartment check; one-time payload lock
        │  5. WORM emit (fsync-durable in Redis) BEFORE execution
        ▼
  Downstream transports (operator's own systems: REST / mainframe)
```

Persistent stores and their contents:

| Store | Contains | Never contains |
|---|---|---|
| Redis (internal-only network, AOF `appendfsync always`) | Payload-lock **hashes**, delegated grants, WORM event buffer + signed epoch headers, sequence counters | Raw PINs (only salted/derived hashes), JWTs, vendor keys |
| Anchor file (gateway volume) | Ed25519-signed `(epoch, epoch_hash)` lines | Any request/tenant payload |
| WORM records | Decision, deny reason, redacted intent metadata, `payload_hash` | `pin`, `jwt`, `token` and similar fields — recursively redacted before write |
| `/metrics` | Aggregate counters/histograms/chain heights with closed-set labels | Tenant ids, agent ids, aliases, compartments, capability UUIDs, correlation ids, codes |
| Container image | Code, venv, integrity manifest, **public** keys | Private keys, licenses, tokens, `.env` (excluded by `.dockerignore`/`.gitignore`) |

### 4.2 Egress profile

The gateway requires outbound connectivity **only** to Redis and to the operator's own
downstream transports. It never calls an LLM or vendor API and holds no vendor
credentials — enforced mechanically by `tests/test_connector_conformance.py` (AST scan
failing the build on any SDK/HTTP/socket/credential import under `bridge/connectors/`).
An observed gateway connection to an AI-vendor endpoint is an incident by definition.

### 4.3 The wire is opaque; the log is complete

Callers receive only a generic denial plus `correlation_id` (uuid4, echoed in
`X-MCPIP-Correlation-Id`). Concrete reasons, redacted payload metadata, and payload
hashes exist only in the WORM log — so information disclosure to a probing agent is
minimized while auditor-grade evidence is preserved and tamper-evident.

---

## 5. Supply-chain security statement

1. **Provenance.** Every release artifact (wheel, sdist, SBOM, optionally the container
   image tar) is SHA-256-hashed into a manifest signed with an **offline Ed25519
   release-root key**. Verification (`mcpip verify`) is read-only, requires no network,
   and trust-anchors on a public-key fingerprint delivered out-of-band — independent of
   TLS, registries, and CDNs.
2. **Transparency.** A CycloneDX SBOM of the fully-resolved, pinned dependency set
   ships inside the signed manifest. Dependencies are version-pinned in
   `requirements.txt`; build/test tooling is segregated in `requirements-dev.txt` and
   never enters the runtime image.
3. **Immutability at runtime.** Verified boot (signed source-set manifest, re-hashed at
   every start, fail-closed) makes post-deployment modification of the shipped code a
   detected, blocking event. The product contains **no auto-update mechanism** — the
   compromise class "malicious update pushed to running instances" has no in-product
   surface. Any future update automation would be an external TUF/Sigstore delivery
   pipeline feeding operator-controlled redeploys (future work; explicitly not
   implemented).
4. **Key hygiene.** Three separate Ed25519 roots (release, license, audit-epoch);
   private keys are generated for production on an offline signer, are never committed
   (`.gitignore`: `.keys/`, `*.pem`, `*.key`) and never baked into images
   (`.dockerignore`); a shipped rotation manifest (`release/keys/rotation.json`)
   records key ids, status, and supersession for verifier enforcement.
5. **Air-gap delivery.** `scripts/build_bundle.sh` produces a deterministic offline
   bundle (signed manifest, public keys + rotation manifest, artifacts, SBOM,
   SHA256SUMS, install runbook) verifiable end-to-end with zero network access,
   including offline CVE scanning against a mirrored database.
6. **Internal supply-chain discipline.** The vendor→format connector registry is
   hash-pinned at import (an unpinned edit refuses to boot), connectors are
   conformance-tested to be parser-only, and the optional Rust fast-path is gated by a
   differential consistency suite (byte- and decision-identical to pure Python) before
   it may activate.

**Known limitations (honest scope):** MCPIP does not currently produce SLSA provenance
attestations or in-toto layouts; image signing (cosign) and reproducible-build
attestation are natural extensions of the existing manifest scheme but are not shipped
in 2.0.0. Dependency integrity relies on pip's hash resolution at build time plus the
SBOM record, not on a curated internal mirror — organizations with mirror requirements
should build the image from the verified sdist inside their own pipeline (the air-gap
bundle's `BUILD_RECIPE.md` documents exactly that path).

---

## 6. Regulatory cross-walk (AI-governance & records frameworks)

This section extends §2/§3 beyond SOC 2 / FedRAMP to the AI-governance and
records-retention regimes that increasingly cite the same mechanisms. Each row states the
MCPIP mechanism (and the §1 T-control it maps to) that **provides evidence FOR** the cited
clause. As everywhere in this pack, "provides evidence for" is deliberate: the mechanism is
technical evidence an assessor can verify; it is **not** a certification, authorization, or
attestation of conformity — those are external third-party processes (see §6.2).

| Framework | Clause | MCPIP mechanism (T-control) | What it provides evidence for |
|---|---|---|---|
| **EU AI Act** (Reg. (EU) 2024/1689) | Art. 12 — Record-keeping / automatic logging | Write-before-execute Merkle-epoch WORM ledger (T7) | Every decision is signed into a root-chained ledger before execution; the attestation exports the sealed head + a fresh `verify_chain` verdict as tamper-evident proof. |
| | Art. 14 — Human oversight | Payload-bound one-time PIN step-up + staged human-in-the-loop (T10) | High-risk actions require an out-of-band, payload-bound human approval before execution; staging + completion are recorded to WORM. |
| **SEC 17a-4(f) / FINRA 4511** | Non-rewritable, non-erasable (WORM) preservation | Append-only Ed25519-signed root-chained ledger (T7) | Records are append-only and root-chained; any rewrite/erasure breaks the chain and is detected by `verify_chain`. |
| | Detection of alteration/deletion | Out-of-tamper-domain anchor low-watermark (T7) | A signed anchor head outside the tamper domain detects tail truncation/rollback; the bundle surfaces the anchor watermark + `first_bad_epoch`. |
| **DORA** (Reg. (EU) 2022/2554) | Art. 9 — ICT logging integrity & retention | Durable WORM (Redis AOF `appendfsync always`) + tamper-evident retention (T7) | Prod refuses to boot without AOF `always`; the retention low-watermark ties content integrity to the retention window so recent-epoch deletion reads as tamper. |
| | Art. 17 — ICT incident management | Fail-closed boot + opaque fail-closed deny posture (T6) | Ambiguity/dependency failure fails closed; concrete reasons are preserved only in the tamper-evident log for incident reconstruction. |
| **NIST SP 800-53 r5** | AU-10 — Non-repudiation | Per-epoch Ed25519 signatures + inclusion proofs (T7) | Each epoch is signed and every event has a Merkle inclusion proof bound to the public `signing_key_id`. |
| | AC-3 — Access enforcement | Capability-UUID gating; role authorizes nothing (T8/T9) | Privileged actions gate on capability UUIDs matched constant-time. |
| | AC-6 — Least privilege | Compartments + TTL-bounded scoped grants (T9) | Compartmented aliases deny without a direct claim or an active delegated grant. |
| | IA-2 / IA-9 — Identification & service auth | JWT-only verified identity + identity-key hard deny (T8) | Identity comes only from a verified JWT (EdDSA/RS256); identity-shaped argument keys hard-deny. |
| **SOC 2** (TSC) | CC6.1 — Logical access | JWT + capability-UUID + payload-bound locks (T8/T9/T10) | JWT-only identity, capability authorization, compartment need-to-know, exactly-once approval locks. |
| | CC6.2 — Registration/authorization/removal | TTL-bounded, step-up-gated, audited grants (T9) | Grants are explicit, TTL-bounded, step-up-gated, audited; revocation/expiry re-denies immediately. |
| **ISO/IEC 42001** | Annex A — Logging & traceability | Write-before-execute WORM traceability (T7) | Every AI tool-call decision is traceable to a signed, tamper-evident, independently verifiable record. |
| | Annex A — Human oversight | Payload-bound one-time PIN oversight (T10) | High-risk AI actions require an out-of-band human-approved payload-bound PIN. |
| | Annex A — Resilience / fail-safe | Opaque fail-closed posture (T6) | Ambiguity/failure fails closed as an opaque deny; reasons live only in the tamper-evident log. |

### 6.1 Portable evidence export — `GET /v1/admin/compliance/evidence`

The gateway can export this cross-walk **together with its own live, already-signed audit
state** as a single portable bundle. The read-only, `CAP_DIRECTORY_ADMIN`-gated endpoint
`GET /v1/admin/compliance/evidence` returns:

- `attestation` — the REAL `WormAttestation`: the latest **sealed** epoch header
  (`epoch`/`end_seq`/`merkle_root`/`epoch_hash`/`signature`), the public `signing_key_id`, a
  **fresh** `verify_chain` verdict (`intact`/`first_bad_epoch`), and the anchor low-watermark.
  It reuses `WormLogger.attestation` exactly like `GET /v1/audit/attestation` — it mints no
  key, signs nothing new, closes no epoch, and never perturbs the write-before-execute emit
  path. Before the first epoch seals, the epoch fields are `null` and the bundle sets
  `sealed: false` + an `empty_state_note` (honest empty state, never a fabricated header).
- `gateway_version` + signed `release_provenance` (version, public release `signing_key_id`,
  `verified`).
- `control_mapping` — the §6 cross-walk as structured data.
- `disclaimer` — the evidence ≠ certification statement (§6.2).

The bundle contains **no** hidden target, payload, PIN/OTP, or vended credential — only
already-public signed commitments (the same set `/v1/audit/proof` + `/v1/audit/attestation`
surface) plus static mapping text. Any auth or engine failure is an opaque `MCPIPDenied`.
Implemented by `services/compliance_evidence.py`; tests in
`tests/test_compliance_evidence.py`.

Operators reach the same REAL bundle everywhere — no surface fabricates or re-derives it:

- **CLI** — `mcpip admin compliance evidence` (add `--json` to export the full signed
  artifact for an auditor / external verifier; the human view always restates *evidence, not
  a certification*).
- **SDK** — `MCPIPAdminClient.compliance_evidence()` (Python) / `complianceEvidence()`
  (TypeScript) → a typed `ComplianceEvidence` mirroring the endpoint 1:1.
- **Console** — the Audit Ledger → *Chain Integrity* tab hosts a *Compliance evidence* panel
  reading `/v1/admin/compliance/evidence` (never a fixture): the intact/first-bad verdict, the
  version + provenance, the framework mapping, the bundle's own `disclaimer` verbatim, and a
  copy-JSON export — with honest unavailable / unsealed states.

### 6.2 What this is / is NOT — evidence ≠ certification

This bundle and the §6 cross-walk are **portable technical evidence**, not a certification.
Concretely, the bundle:

- **IS** a cryptographically-verifiable snapshot of what the gateway commits to (signed WORM
  chain, fresh integrity verdict, public key ids, running version, signed release
  provenance) plus a mechanism-to-clause mapping an assessor can independently check against
  the cited code.
- **IS NOT** a SOC 2 report, a FedRAMP authorization, an ISO/DORA/EU-AI-Act certificate, a
  named customer, an auditor sign-off, or a control "pass." A control **mapping** (this
  mechanism provides evidence FOR this clause) is legitimate collateral; a **certification**
  is a third-party process performed by an accredited assessor against a deploying
  organization's people, processes, and environment over time — a process this software
  cannot perform or produce. Every framework block in the bundle repeats this in its
  `certification_note`.
