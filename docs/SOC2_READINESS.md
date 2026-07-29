# MCPIP — SOC 2 Readiness & Multi-Framework Gap Analysis

**Status:** Internal self-assessment · **Version:** 3.0.0 · **Method:** full-source review of the
actual codebase against the AICPA Trust Services Criteria (2017 TSC w/ 2022 points of focus),
mapped to ISO 27001/42001, NIST 800-53 r5, GDPR, HIPAA, PCI-DSS, EU AI Act, DORA, and FedRAMP.

## 0. Honesty statement (read this first)

This is a **self-assessment readiness estimate produced by the vendor — it is NOT a SOC 2 report,
an audit opinion, or an attestation.** A SOC 2 report can only be issued by an independent licensed
CPA firm after an examination. Consistent with MCPIP's shipped `services/compliance_evidence.py`
posture ("evidence, not certification"), nothing here claims a control is *certified* — only whether
the **code** implements it.

Critically: **no amount of source-code change makes an organization "SOC 2 ready."** SOC 2 tests an
*organization's* controls, and a large share of the criteria are satisfied by **policies, process,
personnel, and an audit engagement** that live outside this repository. This document scores and
remediates the **technical control layer the code owns**, and clearly marks everything else
`ORG-SCOPE`. Closing every code finding below is necessary but **not sufficient** for a SOC 2 report.

The three things "SOC 2 ready" actually requires:
1. **Control design** (SOC 2 Type I) — the control is built correctly. *Code can deliver this.*
2. **Operating effectiveness** (SOC 2 Type II) — evidence the control *ran over a 3–12 month period*.
   *Code enables this; only time + operation produces the evidence.*
3. **An organizational control program + an independent audit.** *Entirely outside the code.*

## 1. Headline verdict

Scores are a **vendor self-assessment**, not an audit result (§0). The **Baseline** column is the
original full-source review; **After PR #73** reflects the shipped remediation (see the
"Remediation shipped" subsection below and §4/§5). Both are point-in-time *design* estimates —
neither is Type II operating-effectiveness evidence, which only a real observation period produces.

| Dimension | Baseline | After PR #73 (self-assessed) | Read |
|---|---|---|---|
| **Control *design* (Type I lens)** | ~7.5 / 10 | **~8.5–9 / 10** | The deterministic cryptographic enforcement core was already strong; the sprint closed the operational-wrapper *design* gaps (monitoring, HA path, boot-lints, at-rest encryption, rotation). Would show well in a point-in-time design assessment. |
| **Operating *effectiveness* (Type II lens)** | ~4 / 10 | **~5 / 10** | Moved only modestly — and it always will from code alone. The *mechanisms* now exist (continuous audit-integrity monitor + alerts, WAIT-quorum HA, exercisable key rotation); what is still missing is **evidence they ran over a 3–12 month window**, which is time + operation, not code. |
| **SOC 2 Security (Common Criteria, CC1–CC9)** | ~51% | **~59%** | Change-mgmt (CC8.1), monitoring (CC7.2), and access boot-lints (CC6.x) lifted the technical share; the remainder is `ORG-SCOPE` (policies, HR, risk assessment). |
| **SOC 2 full scope (+ Availability / Confidentiality / Processing Integrity / Privacy)** | ~52% | **~60%** | Availability (HA + PDB + RTO/RPO), Confidentiality (at-rest encryption), and Privacy (pseudonymization + retention schedule) each gained a shipped control. |

**Bottom line: SOC 2 Type I is now substantially met in *design* — the operational-wrapper gaps that
held the baseline back (monitoring/alerting, an HA path, at-rest encryption, exercisable rotation)
have shipped, tested and default-off. Type II is still not yet — it needs the *evidence* those
controls ran over a 3–12 month observation period, plus an organizational control program and an
independent CPA engagement, none of which code can manufacture.** The recurring pattern has shifted
from *"excellent design, weak operational wrapper"* to *"strong design + a built operational wrapper,
awaiting an observation window and an org program."*

### Remediation shipped (PR #73)

Much of the operational wrapper above has since been implemented on the feature branch (all
tested, default-off where it changes behavior, so nothing regresses):

- **Supply-chain / change-mgmt:** Dependabot, bandit SAST + `pip-audit` in CI, CODEOWNERS, a PR
  template, and a signature-free **integrity-manifest drift check** (warn now; flip to `--strict`
  after the owner re-signs at 3.0.0). *(#23 CI half, #24, #27, #28)*
- **Access / boot:** production boot-lints (refuse demo issuer/audience & group/world-writable
  keys; warn on plaintext Redis & loose key perms) *(#3, #15, #18)*; a **vault-tier secret-read
  WORM audit record** *(#4)*.
- **Monitoring:** an always-on **audit-integrity monitor** (periodic `verify_chain` →
  `mcpip_audit_integrity_total` + CRITICAL log on tamper; the silent compaction path now warns),
  reference PrometheusRule alerts, a gateway **PodDisruptionBudget**, and SIEM-forwarding docs.
  *(#8, #9, #32)*
- **Privacy:** opt-in **pseudonymization** of `act_sub`/`delegation_chain` in WORM (crypto-shred
  the natural-person link) + the Privacy (P-series) section & retention schedule. *(#39, #40b)*
- **Availability:** an opt-in **synchronous-replication quorum** (`WAIT`) that gives HA without
  weakening the durability contract, a Redis PDB, and an RTO/RPO + fail-closed-tradeoff +
  standby-promotion runbook. *(#31, #33, #34, #36)*
- **Confidentiality:** opt-in **WORM event-body at-rest AES-256-GCM encryption** — the
  alias→target map becomes ciphertext in Redis + AOF while `verify_chain` stays byte-identical
  and key-free *(#14)* — now **rotatable**: the active key seals while retained retired keys are
  tried on read, so a long-retention ledger can rotate content keys without losing read access
  (closes the key-rotation-never-exercised gap for this control).
- **Deployment posture:** a hardened **compliance values overlay** (`chart/values-compliance.yaml`)
  turns every opt-in control above ON together (at-rest encryption, pseudonymization, WAIT quorum,
  PDBs, reference alerts), converting the *design* controls into ones that actually **run** in a
  deployment — the single biggest lever on the operating-effectiveness gap once evidence accrues.
- **Doc accuracy:** the `deny_reason` metric-label error, the stale attestation-gating claim, the
  17a-4/DORA retention over-claim, and the WORM store-contents confidentiality caveat. *(#10, #42)*

**Still open (deliberately):** the `[OWNER]` 3.0.0 re-sign; three lower-priority `[CODE]` items
that need design (operator deprovisioning email→principal binding; JWKS online-rotation wiring;
defaulting sender-constraint for classified aliases — already enforced by the boot-lint); and all
`[ORG]` items (policies, risk assessment, the audit engagement, etc.). See §5.

## 2. Scorecard — all Trust Services Criteria

Key: ✅ Met · 🟡 Partial · 🔴 Gap · ⚪ Org-scope (required for certification, not code-fixable)

### Common Criteria (Security — always in scope)

| Family | Name | Band | Score | Crux |
|---|---|---|---|---|
| CC1 | Control environment | 🟡/⚪ | 40% | Operator role labels are decorative — no responsibility→capability binding; governance is org-scope. |
| CC2 | Communication & information | 🟡 | 68% | Record-level logging integrity is MET; some control docs are stale/inaccurate. |
| CC3 | Risk assessment | 🟡/⚪ | 50% | Boot invariants turn config into fail-closed gates (product); a formal risk-assessment program is org-scope. |
| CC4 | Monitoring activities | 🔴/🟡 | 40% | No continuous control-monitoring/alerting; a silent no-alert path in compaction. |
| CC5 | Control activities | ✅/🟡 | 65% | Refuse-to-boot integrity gates are real control activities. |
| CC6 | Logical & physical access | 🟡 | 55% | CC6.1 (identity/authz) is strong-MET; CC6.2/6.3 provisioning/removal, CC6.6 boundary, CC6.7 transmission are Partial/Gap. |
| CC7 | System operations | 🟡 | 48% | Tamper-evidence primitive MET; monitoring/retention/incident wrapper Partial. |
| CC8 | Change management | 🟡 | 55% | Product integrity (verified boot, registry pin) strong; process (review/SoD, commit signing, CVE scan) weak. |
| CC9 | Risk mitigation (disruption/vendor) | ⚪/🟡 | 38% | Largely org-scope (BCP, vendor management). |

**Common-Criteria average ≈ 51%.**

### Additional categories

| Category | Band | Score | Crux |
|---|---|---|---|
| **Availability** (A1.1–A1.3) | 🟡 | 42% | Strong probes/admission-control/fsync-durability; Redis is a single point of failure, no PDB, undefined RTO/RPO, no tested restore. |
| **Confidentiality** (C1.1–C1.2) | 🟡 | 50% | Strong app-layer AES-GCM stores; **the WORM ledger stores alias→target topology in plaintext at rest**, Redis has no TLS/AUTH, backups unencrypted. |
| **Processing Integrity** (PI1) | ✅ | 75% | **The bright spot.** Payload-bound one-time PIN, exactly-once atomic Lua, canonical-JSON byte-parity (Python↔Rust), write-before-execute. |
| **Privacy** (P1–P8) | 🟡 | 54% | Strong technical substrate (payload-hash-only logging, Art. 25 by-design); **zero privacy documentation** + one un-erasable residual (identifiers in immutable WORM). |

**Full-scope average ≈ 52%.**

## 3. What is already shipped (do NOT rebuild)

MCPIP ships a substantial, deliberately-honest compliance-evidence layer. Credit it in the audit; do
not duplicate it:

- **`services/compliance_evidence.py`** — a pure, no-fabrication evidence-bundle assembler with a
  `CONTROL_MAPPING` cross-walk (EU AI Act Art. 12/14, SEC 17a-4/FINRA 4511, DORA Art. 9/17, NIST
  AU-10/AC-3/AC-6/IA-2, SOC 2 CC6.1/CC6.2, ISO 42001) and a `BUNDLE_DISCLAIMER` that asserts no
  cert/ATO/customer/auditor sign-off.
- **`GET /v1/audit/attestation`** and **`GET /v1/admin/compliance/evidence`** — portable, production-
  available, signed audit-state exports (attestation 1:1 + version + release provenance + control
  mapping), surface-synced to both SDKs, the CLI, and the console.
- **`docs/COMPLIANCE.md`** — a control-mapping pack covering Security/Availability/Processing-
  Integrity/Confidentiality + FedRAMP families, with an honest scope statement and a data-flow
  store-contents table. **Gap: the Privacy (P-series) category is entirely absent.**
- **Verified boot** (`core/integrity.py`), **hash-pinned connector registry**
  (`bridge/connectors/registry.py`), **offline license gate** (`core/licensing.py`) — real,
  fail-closed, non-bypassable-in-production change-integrity controls.
- **~660-test adversarial suite** incl. the connector-purity AST scan, fastwalk differential, and
  boot-policy lint (strong SA-11 developer-testing evidence).

## 4. Detailed findings & remediation

Each finding: control · status · evidence (file/symbol) · what an auditor flags · remediation.
`[CODE]` = fixable in this repo. `[DEPLOY]` = the product should enforce/refuse-to-boot rather than
merely document. `[ORG]` = organizational, not code. `[OWNER]` = requires the offline signing keys.

### 4.1 Access control & identity (CC6)

1. **CC6.1 Logical access software — ✅ MET (in-product).** JWT-only identity
   (`auth/token_resolver.py`); alg allow-list `{EdDSA, RS256}` checked against the untrusted header
   *before* decode (defeats `alg=none`/RS256→HS256 confusion); 8 required claims; `role` authorizes
   nothing; capability-UUID gates in constant time; secure-by-default fail-closed boot. *Provisioning
   of which capability a subject holds is external to the product (`[ORG]` — the IdP).*
2. **CC6.2 / CC6.3 Registration / authorization / removal — 🔴 GAP (in-product) / ⚪ ORG.** The
   operator roster + `admin|member|viewer` labels **authorize nothing** (`services/operator_users.py`);
   `DELETE /v1/admin/users/{email}` removes a roster row but has **no effect on that principal's
   access** — deprovisioning is entirely the IdP's. No dual-control/separation-of-duties on admin
   mutations; one JWT can carry `CAP_DIRECTORY_ADMIN` + `CAP_FORENSIC_READ` + `CAP_CATALOG_REVIEWER`
   = de-facto superuser. **Remediation `[CODE]`:** on `DELETE user`, also `RevocationStore.revoke`
   the bound principal; add an optional dual-approver mode for `revoke`/`reactivate`/`vault-write`
   (reuse the payload-bound two-step); ship a per-tenant access-review export from WORM `admin_action`
   records.
3. **CC6.6 Boundary protection — 🟡 PARTIAL.** Strong request-path perimeter (`EdgeGateMiddleware`
   413/401/503, 256 KiB cap, fail-closed prod CORS, uniform SSRF hardening on every outbound client).
   Gaps: **no in-product TLS** (binds plaintext `:8080`; ingress is the deployment's job); admin and
   agent share one socket with no segmentation/IP-allow-list/admin rate-limit; live JWKS rotation
   exists but is **not wired into the composition root** (StaticPEM only → rotation is a redeploy).
   **Remediation `[CODE]`:** wire `JWKSRefresher`/`MultiIssuerResolver` behind a flag; add an
   optional admin-path IP allow-list + per-principal admin throttle. `[DEPLOY]`: require TLS-terminating
   ingress + admin/agent network segmentation in `OPERATIONS.md`.
4. **CC6.7 Restrict transmission — 🟡 PARTIAL.** Strong opacity/redaction/at-rest crypto + sender-
   constrained (DPoP) tokens. Gaps: `require_sender_constraint` **defaults False** per alias (PoP is
   opt-in, not a baseline); **no per-access audit record for secret reads** (`SecretVault.get_material`
   is deliberately WORM-silent). **Remediation `[CODE]`:** default sender-constraint True for any
   classified/PII/PHI alias (or widen the boot-lint's sensitive-classification set); emit a redacted
   `admin_action='secret_access'` WORM record (tenant/secret_id/fingerprint/correlation — never the
   value) on each vend.
5. **CC1.x Control environment — ⚪/🟡.** Role labels are decorative; no responsibility→capability
   binding or drift detection. **Remediation `[CODE]`:** warn when a live principal's presented
   capabilities exceed its roster role, or re-label the field "informational — not an access grant"
   in the console/API to prevent auditor over-reliance.

### 4.2 Audit logging & monitoring (CC7, CC4, CC2)

6. **CC2.1 / AU-9 / AU-10 Record integrity & non-repudiation — ✅ MET at the chain level.**
   Write-before-execute `emit` (atomic INCR+XADD), per-epoch Ed25519 Merkle roots, root-chaining,
   out-of-domain fsync'd rollback anchor, crash-atomic epoch close, recursive secret redaction,
   production refuses to boot without Redis AOF `appendfsync always` + `noeviction`.
   **Scope caveat, read with item 7:** the *chain-level* claim holds over the whole retained
   history, but a *per-event* Merkle inclusion proof is producible only while that event's epoch
   is both sealed and inside the retention window — not for the still-open epoch, and not after
   `_trim_retention` drops the epoch's leaf vector. `WormLogger.proof_scope()` measures the real
   window and `GET /v1/admin/compliance/evidence` returns it as `evidence_scope.proof_window`, so
   the boundary is a reported number rather than a doc claim. See `docs/COMPLIANCE.md` §3.1.
7. **CC7.2 / AU-4 / AU-11 Retention — 🔴 GAP.** In-system records live only ~`WORM_HOT_EPOCHS=32`
   epochs before `XTRIM`; per-epoch metadata is compacted away after `WORM_CHECKPOINT_EPOCHS=128`.
   Long-term preservation depends **entirely on the operator** running
   `export-audit --verify --pubkey <worm pubkey> --require-anchor` on a cron (that invocation
   re-checks the Ed25519 epoch signatures, the `prev_epoch_hash` chain linkage, each
   `epoch_hash`, the Merkle roots, and the out-of-domain rollback watermark; epochs already
   trimmed out of the hot buffer come back verified *signature-only*, which is exactly why the
   export archive — not the in-system window — is the record of retention). `docs/COMPLIANCE.md` over-claims 17a-4/DORA retention. **Remediation `[CODE]`:** promote the
   retention windows to `Settings` (policy, not module constants); ship a first-party durable exporter
   (append to WORM-mode object store / S3 Object-Lock) as an off-hot-path daemon.
8. **CC7.3 / CC4.1 Continuous tamper-detection & alerting — 🔴 GAP.** `verify_chain` runs only
   pull-based (attestation/CLI); the compaction daemon **silently declines to compact on a non-intact
   chain with no metric/log/alert**. **Remediation `[CODE]`:** add an off-hot-path integrity monitor
   (mirror `_epoch_gauge_daemon`) that increments a closed-enum metric + CRITICAL log + routes to the
   response-playbook channels on `intact == False`; at minimum bump a metric in the silent branch.
9. **CC7.2 SIEM / alerting — 🟡/⚪.** Logging is JSON to stderr only (no shipped SIEM sink); the deny-
   response playbook is the only push-alerter and is **default-OFF**; `/metrics` deliberately omits
   `deny_reason`. **Remediation `[CODE]`:** ship a reference SIEM-forwarding config + reference
   PrometheusRule alerts (on shed rate, `/readyz` failures, epoch-close staleness); consider enabling
   the whitelist-safe `canary_tripped` single-shot trigger by default. `[ORG]`: review cadence & who-reviews.
10. **CC2.1 Doc/code discrepancy — 🔴 GAP (concrete).** `docs/OPERATIONS.md` monitoring table lists a
    `deny_reason` label on `mcpip_authorize_decisions_total` that the collector does not emit
    (`core/metrics.py` has only `decision`). An operator's alert on that label returns empty.
    **Remediation `[CODE]`:** correct the OPERATIONS.md table.
11. **AU-8 Time discipline — ⚪.** Timestamps are host `time.time_ns()`; no NTP/clock-sanity check.
    Ordering is independently protected by the monotonic seq. **Remediation `[CODE]`:** add a boot
    advisory on implausible clock; `[ORG]`: fleet NTP.
12. **CC7.2 No behavioral anomaly detector — deliberate boundary.** MCPIP detects *policy* anomalies
    (canary trips, deny bursts), not *behavioral* ones — the honest "fox can't guard the henhouse"
    stance. Acceptable for CC7.2 (which doesn't mandate UEBA); record it as a coverage boundary. If a
    customer's CC7.2 relies on UEBA, it must be an external system fed by MCPIP logs.

### 4.3 Encryption, secrets & confidentiality (CC6.1, C1)

13. **✅ MET (strong):** vault + forensic AES-256-GCM (dedicated out-of-Redis keys, tenant-bound AAD,
    write-only values, keyed HMAC fingerprints), scrypt memory-hard PIN hashing + lockout, short-lived
    scoped STS vend (no standing credentials), all outbound clients hermetic + SSRF-guarded + IP-pinned.
14. **C1.1 / SC-28 WORM stores confidential topology in plaintext at rest — 🔴 GAP.** The decision ctx
    sets `ctx["target"] = entry.target`; `_redact` scrubs secrets by key-name but not `target`/`alias`/
    `compartment`. A Redis dump or AOF backup exposes the exact alias→target de-obfuscation map the
    agent boundary exists to hide. **Remediation `[CODE]`:** encrypt WORM event *bodies* at rest under a
    dedicated key (reuse the forensic AES-GCM+AAD pattern), signing the Merkle leaf over ciphertext so
    `verify_chain` is unaffected — **this touches the most invariant-heavy path; treat as a deliberate
    design change (see §6).**
15. **SC-8 Redis in-transit — 🔴 GAP `[DEPLOY]`.** `redis://` plaintext default, no `ssl`, no
    `requirepass`/ACL, `protected-mode no`. **Remediation:** support/default `rediss://` + mTLS +
    AUTH; add a prod boot-lint refusing `redis://` when `sandbox_mode=False` (same family as
    `assert_persistence_posture`).
16. **SC-8 Agent↔gateway TLS — 🟡 PARTIAL `[DEPLOY]`.** No in-product terminator; org ingress concern.
    **Remediation:** document required TLS ingress as a control; optionally expose `--ssl-*`/mTLS.
17. **SC-12 / IA-5 Key rotation — 🔴 GAP.** `rotation.json` covers only release/license roots (both
    `not_after: null`, never rotated) and omits every operational key (WORM/IdP/vault/forensic/HMAC);
    AES blobs carry no key-id so rotation orphans ciphertext; the WORM key is rotation-hostile.
    **Remediation `[CODE]`:** add crypto-periods + full key coverage to the manifest; key-id/version
    prefix on AES blobs (decrypt-old/encrypt-new); a `signing_key_id` transition for forward-signing
    WORM while old epochs verify under the prior key.
18. **SC-12 / CC6.1 Key storage — 🟡 GAP.** Keys are raw files read with a length-check only (no prod
    file-mode/owner check); no KMS/HSM; Ed25519 privates written unencrypted PKCS8. **Remediation
    `[CODE]`:** prod boot-check that key files are 0600 + owned by the runtime UID; offer a KMS/HSM
    key-provider seam.
19. **CC6.1 / CP-9 Backups unencrypted — 🔴 GAP `[DEPLOY]`.** AOF + backups inherit the plaintext
    topology of #14. **Remediation:** require encrypted volumes/backups; document key custody.
20. **C1.2 / IA-5 Secret disposal — 🟡 PARTIAL.** Ephemeral material TTL-bounded; master keys held as
    immutable `bytes`, never zeroized. **Remediation `[CODE]`:** hold master keys in `bytearray` +
    best-effort zeroize on shutdown; document crypto-shredding as the disposal mechanism.
21. **SC-13 FIPS — 🟡/⚪.** FIPS-*approved algorithms* via `cryptography`/OpenSSL, but no FIPS-*validated
    module* pinned; scrypt is not a FIPS KDF. **Remediation:** if in scope, run FIPS OpenSSL + assert
    FIPS mode at boot; offer PBKDF2 under a FIPS flag.

### 4.4 Change management & supply chain (CC8, CC3)

22. **SI-7 / CM-5 Integrity gates — ✅ MET (non-bypassable in prod).** Verified boot + registry pin +
    license gate are real fail-closed controls; the dev bypass structurally refuses on a non-sandbox
    boot. *Caveat:* verified boot covers **first-party Python only** — the Rust `.so`, deploy manifests,
    and the venv are outside the signed set.
23. **CC8.1 / CM-2 / SI-7 Stale signed manifest — 🟡 PARTIAL (proven).** The committed signed
    integrity + release manifests are **`2.0.0` while source is `3.0.0`**; the actual `app/main.py`
    hash does not match the committed manifest, so `verify_boot_integrity` would **refuse to boot the
    repo as committed in production**. No CI catches the drift. **Remediation:** `[OWNER]` complete the
    offline `3.0.0` re-sign; `[CODE]` add a CI job that diffs `HEAD`'s file-set + per-file hashes
    against the committed manifest (fail on drift); upgrade `preflight_version_consistency.py` to hard-fail.
24. **CC7.1 / SI-2 Dependency vulnerability scanning — 🔴 GAP.** No Dependabot/CodeQL/pip-audit;
    CVE scan is a manual offline runbook. **Remediation `[CODE]`:** add Dependabot (pip/npm/actions) +
    a CI `pip-audit`/`grype` job + GitHub secret scanning/CodeQL.
25. **CM-2 / SR-4 Dependencies are ranges, not hashes — 🔴 GAP.** `requirements.txt` uses version
    ranges; the Dockerfile installs without `--require-hashes` → non-reproducible builds (contradicts
    the "pinned deps" claim). **Remediation `[CODE]`:** `pip-compile --generate-hashes` → a hashed
    lock installed with `--require-hashes`; hash the lock into the release manifest.
26. **SA-12 / SR-4 SLSA/cosign not automated — 🟡 PARTIAL.** Tooling is present and honest but never
    executed by a pipeline; desktop installers are unsigned. **Remediation:** `[CODE]` a tag-triggered
    release workflow with keyless cosign + SLSA provenance + SBOM as assets + macOS notarization /
    Windows Authenticode. `[OWNER]` if offline signing is mandatory.
27. **CC8.1 / CM-5 Review / SoD / commit signing — 🔴 GAP `[ORG]`.** No CODEOWNERS/PR-template; all
    commits unsigned; branch protection is un-verifiable from the checkout. **Remediation `[CODE]`:**
    add `.github/CODEOWNERS` (auth/, audit/, core/, registry, interfaces.py, release/) + a PR template.
    `[ORG]`: enable branch protection (≥1–2 required reviews, required checks, CODEOWNER review),
    require signed commits — *request the branch-protection export as audit evidence.*
28. **CC8.1 / SA-11 CI gate — 🟡 PARTIAL.** Strong test gate, but `mypy --strict` covers the SDK only
    (core gateway excluded), and no coverage floor / SAST / IaC lint. **Remediation `[CODE]`:** add
    repo-wide mypy (non-strict to start) + bandit/semgrep + hadolint/kubeconform + a coverage floor.
29. **CC8.1 Change documentation — ✅ MET.** Keep-a-Changelog `[3.0.0]`, a copy-runnable `RELEASE.md`
    ceremony, and a self-aware GA go/no-go in the internal roadmap.

### 4.5 Availability & resilience (A1, CC7.5)

30. **A1.2 Health/probes/load-shed/fsync-durability — ✅ MET (strong).** Dependency-free liveness,
    Redis-gated readiness, real admission control + bounded-tail shedding, RPO≈0 for acked writes.
31. **A1.2 Redis single point of failure — 🔴 GAP.** `replicas: 1`, single RWO PVC, no
    Sentinel/Cluster/replica; the durability contract (`appendfsync always`, no-lossy-failover)
    structurally forbids commodity Redis async-failover, and no reconciling HA design ships. A Redis
    loss = full governed-action outage. **Remediation `[CODE]/[DEPLOY]`:** ship an HA topology that
    preserves fsync-before-ack (synchronous replica + `WAIT 1` on WORM XADD, or the app-managed WAL in
    `docs/ARCHITECTURE.md`); document single-node RTO/RPO + a standby-promotion runbook; add Redis
    anti-affinity.
32. **A1.2 No PodDisruptionBudget — 🔴 GAP `[CODE]`.** No PDB for gateway or Redis. **Remediation:**
    add `PodDisruptionBudget` (gateway `maxUnavailable: 1`; Redis once HA exists), `pdb.enabled` chart value.
33. **A1.2 HPA-min-2 vs single RWO WORM PVC — 🔴 GAP `[CODE]`.** The shipped default is internally
    inconsistent for cross-node scheduling (Multi-Attach). **Remediation:** make the WORM/anchor volume
    RWX or per-replica, or scope the RWO PVC single-node and default HPA min 1 for that shape.
34. **A1.3 / CP-10 RTO/RPO undefined; DR/region failover deferred — 🟡/🔴.** No numeric objectives
    anywhere; multi-region is scaffolding. **Remediation:** define/publish RTO/RPO; state the acked-write
    RPO≈0 property; provide a same-region standby runbook (region-migration DR may remain a formally
    accepted deferred risk).
35. **CP-9 / A1.3 Backups documented, not automated; no tested restore — 🟡 PARTIAL.** Security-aware
    backup/restore with anchor-based rollback detection, but no shipped CronJob and no tested-restore
    artifact. **Remediation `[CODE]`:** ship an optional backup + `export-audit --verify` Job in the
    chart; `[ORG]`: record a dated restore-test result.
36. **A1.2 Fail-closed = total-outage tradeoff — 🟡.** The blast radius (any Redis/gateway outage
    denies all agent actions, by design) is nowhere stated as an accepted BC risk. **Remediation
    `[CODE]`:** add an "Availability & fail-closed tradeoff" section to `OPERATIONS.md`; `[ORG]`: formal
    risk acceptance.

### 4.6 Processing Integrity (PI1) — the bright spot

37. **PI1.1–PI1.5 — ✅ MET (strong).** Inputs are strictly validated (per-dialect `extra=forbid`
    ingress models, depth/keys/array/size caps, unicode scrub, identity-injection hard-deny); the
    one-time PIN is bound to `sha256(canonical_json({tenant,agent,alias,arguments}))` and consumed by a
    single atomic Redis Lua (payload compared before PIN, exactly-once, constant-time); canonical-JSON
    is byte-identical Python↔Rust (differential-tested or fastwalk doesn't ship); the recorded
    payload-hash provably matches the executed payload; write-before-execute guarantees the audit record
    precedes the side effect. This is the strongest category and should lead the SOC 2 narrative.

### 4.7 Privacy (P1–P8) & data governance

38. **P3 / GDPR Art. 5(1)(c) / Art. 25 Data minimization by design — ✅ MET (exemplary).** The immutable
    WORM stores a `payload_hash`, **not request arguments** — PII/PHI-bearing content never enters the
    permanent ledger. Metrics are closed-label; telemetry is aggregate-only (a HyperLogLog whose members
    are unretrievable + 8 closed fields, default-OFF). Raw content lives *only* in forensic captures:
    AES-256-GCM under a dedicated key, 1h TTL, `CAP_FORENSIC_READ`-gated, default-OFF in prod.
39. **P1 / P4 / P5 No privacy documentation — 🔴 GAP.** `docs/COMPLIANCE.md` maps Security/Availability/
    PI/Confidentiality but **no P-series**; no retention schedule; no privacy notice; no data-subject-
    access mechanism (forensic is a single-correlation-id operator lookup, not a DSAR path).
    **Remediation `[CODE]`:** add a "Privacy & data handling" section to `COMPLIANCE.md` with the
    data-footprint table + a published retention schedule (WORM: indefinite, justified by 17a-4/DORA/
    HIPAA §164.530; forensic 1h; PIN 5m; grants TTL); add privacy clauses to `CONTROL_MAPPING`; add a
    privacy test asserting the WORM ctx never contains an `arguments` key.
40. **P4 / GDPR Art. 17 Immutable WORM vs right-to-erasure — 🟡 PARTIAL (inherent tension).** Content
    erasure is satisfied by *never durably retaining* it (hash-only) + crypto-shreddable 1h forensics.
    **Residual:** the WORM permanently retains principal identifiers — `agent_id`, `act_sub`,
    `delegation_chain` (RFC 8693 actors that **can be natural persons**) — with **no crypto-shred lever
    for WORM** (signed plaintext, not per-tenant-key-encrypted). **Remediation (ranked):** (a) `[CODE]`
    document the Art. 17(3)(b) legal-obligation reconciliation (cheapest, do first); (b) `[CODE]`
    pseudonymize `act_sub`/`delegation_chain` via a keyed HMAC whose key lives in the crypto-shreddable
    key-store; (c) *design work* — per-tenant envelope encryption of WORM event bodies under a deletable
    key, preserving `verify_chain` over ciphertext leaves.
41. **P6 / GDPR Art. 33-34 Breach notification — 🟡/⚪.** Strong detection substrate (`verify_chain`,
    `first_bad_epoch`, forensic); no notification workflow (org). `SECURITY.md` covers vulnerability, not
    data-breach, disclosure. **Remediation `[CODE]`:** add an IR/breach-notification pointer to
    `OPERATIONS.md` leveraging the tamper-evidence substrate; `[ORG]`: the notification obligation.
42. **Cross-framework technical controls — largely ✅ MET:** HIPAA §164.312 access/audit/integrity;
    PCI Req 7/10; GDPR Art. 32; EU AI Act Art. 12/14; DORA Art. 9/17 (PHI/PAN never in WORM — hash only).
    Gaps to *map*: ISO 42001 data-governance, EU AI Act Art. 10, FedRAMP PT/AR privacy overlay.

### 4.8 Doc-accuracy fixes surfaced by the review `[CODE]`

- `docs/OPERATIONS.md` monitoring table lists a non-existent `deny_reason` metric label (see #10).
- `docs/COMPLIANCE.md` over-claims 17a-4/DORA retention (see #7) and asserts the anchor "never stores
  payload" without noting the WORM stream stores target/alias/tenant/agent (see #14).

## 5. Prioritized remediation roadmap

**P0 — material / blocking (do first):**
- Complete the `3.0.0` integrity/release re-sign `[OWNER]` + CI drift-check `[CODE]` (#23) — *the repo
  is not bootable in production as committed.*
- Correct the three doc inaccuracies (#10, #42, §4.8) `[CODE]`.
- Add the Privacy section + retention schedule to `COMPLIANCE.md` (#39) `[CODE]`.

**P1 — high-value technical gaps:**
- Encrypt WORM event bodies at rest / OR prod boot-lint requiring Redis TLS+AUTH+at-rest (#14, #15, #19).
- Automated dependency/CVE scanning + hashed lock file (#24, #25).
- Retention policy config + durable exporter (#7); runtime tamper-detection monitor (#8).
- Make operator `DELETE user` load-bearing + dual-control on admin mutations (#2).
- Key-rotation coverage + key-id versioning + prod key perm-check (#17, #18).
- Pseudonymize `act_sub`/`delegation_chain` in WORM (#40b).
- Reference Prometheus alerts + SIEM-forwarding config (#9); PodDisruptionBudget (#32).

**P2 — hardening & operating-effectiveness enablers:**
- Fail boot on demo issuer/audience in prod; wire JWKS refresher (#3); default sender-constraint for
  classified aliases + secret-access WORM record (#4); CODEOWNERS + PR template + CI SAST/IaC lint
  (#27, #28); RTO/RPO + backup Job + fail-closed tradeoff doc (#31–#36).

**Cannot be fixed in code (`[ORG]` — required for an actual SOC 2 report):**
- Information-security policy set, risk-assessment program, vendor/third-party management, HR/personnel
  controls, physical security, business-continuity plan, incident-response *program*, security-awareness
  training, a defined control owner + review cadence, and the **independent CPA examination over a Type
  II observation period.** Plus branch-protection enforcement, signed-commit policy, and the owner-
  offline cryptographic signing ceremony.

## 6. Notes on the two risky changes

- **WORM at-rest encryption (#14)** and **per-tenant WORM crypto-shred (#40c)** touch the most
  invariant-critical path (canonicalization, Merkle leaf construction, `verify_chain`, epoch signing).
  They are genuine design changes, not quick fixes, and must preserve byte-for-byte
  register/consume/Rust parity and the write-before-execute ordering. Recommend a dedicated design +
  review pass, not a batch edit.
- **Redis HA (#31)** conflicts with the `appendfsync always` durability contract; the correct answer
  (synchronous replica + `WAIT`, or app-managed WAL) is architectural and should be decided
  deliberately.

---

*This document is a self-assessment and contains no certification claim. It maps the codebase to the
Trust Services Criteria to guide a genuine SOC 2 engagement; the report itself can only be issued by an
independent auditor after a Type I/II examination.*
