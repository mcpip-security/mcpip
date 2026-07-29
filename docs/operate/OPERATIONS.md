# ◐ MCPIP — Operations & Deployment

*Version: `3.0.0` (the `VERSION` file — the single source of truth). Last updated: 2026-07-18.*

The consolidated operations / deployment reference for MCPIP: the single entry point for
**deploying and running** the authorization gateway. It covers the fail-closed production boot,
deployment shapes (self-host / VPC / air-gapped), the opt-in / dark-feature flags stated
honestly, the full day-2 runbook (key ceremony, rotation, release build/sign, verification,
backup/restore, incident response, audit verify/export, monitoring, upgrades), the
non-bypassability / network-enforcement story, deploying behind a service mesh or
identity-aware proxy, the operator console and its desktop packaging, and multi-region
topology with data residency. Every command below is copy-paste runnable from the repository
root (substitute your checkout path) and references only files that ship in this repository.
Deeper, still-authoritative references are linked where they stay separate:
[`ARCHITECTURE.md`](../build/ARCHITECTURE.md) (components, invariants, SPIFFE / workload-identity model,
OAuth resource-server surface), [`TELEMETRY.md`](TELEMETRY.md) (opt-in telemetry + privacy
boundary), the internal strategy notes (positioning, GA readiness), the internal roadmap,
[`COMPLIANCE.md`](COMPLIANCE.md) (auditor / attestation), and [`GETTING_STARTED.md`](../start/GETTING_STARTED.md)
(client + CLI onboarding).

---

## Operating philosophy — immutable, verifiable, operator-controlled

Three rules govern everything below. They are not conventions; they are enforced by the
shipped code.

1. **Releases are immutable.** A release is a signed set of SHA-256 digests
   (`release/manifest.json`, Ed25519-signed by an offline root key). Nothing about a
   deployed gateway changes after deploy — the running process re-hashes its own source
   set at every boot (`core/integrity.py`) and **refuses to start** on any mismatch.
2. **There is no self-update. Anywhere.** The gateway never pulls code, never patches
   itself, never mutates its own files, and ships no updater. `mcpip verify` is
   read-only by contract. An **upgrade is a redeploy**: verify a new signed release,
   pin its digest, roll it through your change-control process. If update *automation*
   is ever wanted, the documented path is TUF/Sigstore as an external delivery layer —
   future work, never in-binary.
3. **Everything fails closed.** Missing keys, a bad signature, an expired license, a
   tampered file, an unreachable Redis — each refuses boot or denies the request. The
   wire sees opaque errors (a generic error + `correlation_id`); specifics land on the
   `mcpip.boot` logger and in the WORM audit log only.

---

## Running MCPIP

### Deployment shapes

MCPIP is a stateless gateway plus a Redis backing store. Everything synchronizing state
(payload locks, the WORM buffer + signed epoch chain, grants, quarantine/revocation) lives in
Redis; the workers hold no mutable auth state, so you scale reads horizontally.

| Shape | What it is | When |
|---|---|---|
| **Single host (Compose)** | **Production:** `docker compose -f docker-compose.prod.yml up --build` — fail-closed gateway on `:8080` + bundled durable Redis (`appendfsync always`), with your keys/license/integrity files bind-mounted from `./secrets`. **Sandbox/demo:** `MCPIP_SANDBOX_MODE=true docker compose up` (default file). | Pilots, single-tenant, edge. |
| **Kubernetes (Helm / plain)** | `chart/` (name `mcpip`) or `k8s/`. 2 replicas + HPA (2→10 @ 70% CPU), non-root, read-only rootfs, default-deny NetworkPolicy, internal-only Redis, persistent WORM volume. **Deploy by image digest, never by tag.** | VPC / production. |
| **Air-gapped enclave** | `scripts/build_bundle.sh <version>` → a deterministic tarball (signed manifest, public keys, artifacts or a rebuild recipe, SBOM, `SHA256SUMS`, in-enclave `INSTALL.md`). Verify with `mcpip verify bundle` — **zero network at any step**, including CVE scan against the bundled SBOM. | Regulated / sovereign / offline. |

```bash
# Helm, by digest (never by tag):
helm upgrade --install mcpip ./chart -n mcpip \
  --set image.repository=<registry>/mcpip-gateway \
  --set image.digest=sha256:<digest-from-the-signed-release>
```

The chart **cannot** express `MCPIP_SANDBOX_MODE` or the integrity dev-bypass — production
pods always boot fail-closed. Detailed per-shape commands (Compose, Helm, plain manifests,
CI/CD secret injection) are in the Runbook → [Deployment](#deployment-compose--helm--kubernetes)
below; the ceremony that produces the digest is in
[Building & signing a release](#building--signing-a-release).

**Hardened compliance overlay.** The opt-in SOC 2 controls that ship default-OFF (WORM
at-rest encryption, principal pseudonymization, the synchronous-replication quorum, disruption
budgets, reference alerts) are turned on together by a values overlay so a compliance
deployment converts the *control design* into controls that actually RUN:

```bash
helm upgrade --install mcpip ./chart -n mcpip \
  -f chart/values.yaml -f chart/values-compliance.yaml \
  --set image.repository=<registry>/mcpip-gateway \
  --set image.digest=sha256:<digest-from-the-signed-release>
```

Enable it consciously — the overlay documents its prerequisites (two 32-byte keys added to
the keys Secret, an HA Redis with ≥2 synced replicas, a Prometheus Operator). Flag-on with a
missing key is a fail-closed boot error, by design. A default install leaves these
controls off, so it exercises fewer controls than the design describes.

### Redis in the cloud tier — who supplies it, and the managed-Redis trap

**Ours or the client's?** For the cloud tier as built today it is the **client's Redis**, running
in the client's own cloud / VPC — never ours. The WORM buffer and signed epoch chain live in
Redis, so hosting it for them would move their tamper-evident audit trail — and the
write-before-execute guarantee — onto vendor infra and break the no-egress posture the product
sells; a regulated buyer cannot outsource custody of their own audit trail. The only case where
Redis could be ours is a **fully-managed SaaS control plane** — a deliberate, later offering, not
the default — and even then the audit buffer should stay pinned to the customer's own account
(we run the gateway; the WORM Redis stays theirs). So today, Redis is supplied end-to-end but
*inside the client's perimeter*, by the shipped charts:

- **Recommended — the bundled StatefulSet.** `chart/` and `k8s/` ship a durability-hardened Redis
  (`appendonly yes`, `appendfsync always`, a persistent volume, an internal-only Service). It
  satisfies the boot durability contract out of the box and never leaves your network. This is the
  default cloud path — nothing to procure.

- **The managed-Redis trap (ElastiCache / Memorystore / Azure Cache).** Production boot runs
  `assert_persistence_posture` and **refuses to boot** unless it can read Redis `CONFIG` *and* sees
  `appendonly=yes appendfsync=always`. Most managed Redis fails one of three ways:

  | Failure | What you see | Why |
  |---|---|---|
  | `CONFIG GET` restricted | `cannot verify Redis persistence posture at boot` → fail closed | Many managed tiers block `CONFIG`, so MCPIP can't confirm durability and won't guess. |
  | No `appendfsync always` | WORM-DURABILITY boot error → fail closed | ElastiCache AOF is deprecated; Memorystore / Azure use snapshotting or async AOF, not per-write fsync. |
  | Async-replicated failover | Boots, but can silently lose an acked write on failover | Violates "durable **before** authorized" even when the primary had `appendfsync always`. |

  A managed Redis is acceptable **only** if it can (a) expose `CONFIG GET`, (b) run
  `appendfsync always`, and (c) not lose acknowledged writes on failover. Verify before deploying:
  `redis-cli -u "$MCPIP_REDIS_URL" CONFIG GET appendfsync` must return `always`. When in doubt, use
  the bundled StatefulSet — it is the supported answer.

- **No durability override exists, by design.** There is no env to skip the posture check: the WORM
  ordering guarantee *is* the product. If Redis can't prove `appendfsync always`, the gateway fails
  closed rather than degrade to a weaker audit promise.

### Availability & the fail-closed tradeoff

MCPIP fails **closed**: if Redis or the gateway is unavailable, the gateway denies rather than
degrade (there is deliberately no read-only / weaker-audit mode — degrading would break
write-before-execute). State the blast radius explicitly and design around it:

- **Blast radius.** A total loss of the gateway *or* its Redis denies **100% of governed agent
  actions** until recovery. This is a business-continuity risk to accept consciously; the
  compensating controls below are how you bound it.

- **Gateway tier.** Stateless — run ≥2 replicas (the chart default: `hpa.minReplicas: 2`) behind
  the Service, with the shipped `PodDisruptionBudget` (`pdb.enabled`) so a node drain can't evict
  every replica at once. A single gateway pod loss is transparent.

  *Caveat — the WORM anchor volume.* The anchor mirror PVC defaults to `ReadWriteOnce`
  (`persistence.accessModes`), which a single node can mount. To run gateway replicas across
  nodes, set `persistence.accessModes: [ReadWriteMany]` on an RWX StorageClass, or scope that
  deployment to one node. (The authoritative anchor is per-write fsync'd; the PVC is a
  convenience mirror.)

- **Redis tier — HA without weakening durability.** Plain async-replicated failover can silently
  lose an acked write on promotion (see the managed-Redis trap above), so it is **not** a
  supported durability posture on its own. The supported HA path is the **synchronous-replication
  quorum**: set `durability.waitReplicas: N` (env `MCPIP_WORM_WAIT_REPLICAS`) and run Redis with
  ≥N synced replicas. Every emitted audit event then also requires N replica acknowledgements
  (`WAIT`) **before** the authorize proceeds — write-before-execute extended across a replica —
  so promoting a synced replica after a master loss never drops an acked record. A quorum
  miss/timeout is **fail-closed** (the request denies), never a silent weaker promise. Enable
  `redis.pdb.enabled` so a drain can't take the master and its synced replicas together.

- **RTO / RPO.**
  - **RPO ≈ 0 for acknowledged audit writes** — the durability contract (`appendfsync always`,
    and with the quorum, replica-acknowledged) means an acked decision is never lost. This is a
    committed objective, not incidental.
  - **RTO** is deployment-specific and operator-owned. Same-region recovery = reschedule the
    gateway (seconds, stateless) + restore/promote Redis. Publish your own numeric RTO per shape.

- **Same-region standby / promotion runbook (single-writer Redis).**
  1. Detect: `/readyz` failing on all gateways, or `McpipGatewayDown` firing (Redis unreachable).
  2. Promote the synced replica to master (or restore Redis from AOF/snapshot — see
     [Backup](#backup)); repoint `MCPIP_REDIS_URL` if the endpoint changed.
  3. Verify the restored/promoted ledger did **not** roll back:
     `mcpip_verify export-audit --verify --pubkey <worm pubkey> --anchor-path <anchor>` — a
     restore older than the fsync'd anchor low-watermark is flagged as
     `audit chain: TAMPERED — anchor low-watermark failed at epoch <k>`, which is the correct
     signal to investigate, not to ignore. (The anchor file must survive the failover — it is
     the out-of-tamper-domain witness; pass `--require-anchor` so a lost anchor fails loudly
     instead of downgrading the check.)
  4. Confirm `/readyz` returns 200 and `mcpip_audit_integrity_total{event="tamper_detected"}`
     is not incrementing.

  Cross-region failover / tenant migration remains a **formally accepted deferred risk** (a
  cross-region control plane is not shipped — see [Multi-region](#the-worm-ledger--anchor-across-regions)).

- **Capacity ceiling.** The `appendfsync always` fsync rate is the true system throughput ceiling
  (the WORM emit rate = the authorize rate); horizontal gateway scaling lifts CPU, not this. Size
  Redis storage/IO accordingly and alert on `mcpip_requests_shed_total{cause="overload"}`.

### Fail-closed production boot

`sandbox_mode` defaults **`false`** everywhere (the bare `uvicorn` process, the shipped image,
Compose). A non-sandbox boot fails closed unless it is given real key material and passes every
startup gate — all *before* a socket is bound:

| Gate | Env | Behavior on failure |
|---|---|---|
| **Verified boot** | `MCPIP_INTEGRITY_MANIFEST_PATH` + `MCPIP_INTEGRITY_PUBLIC_KEY_PATH` | Re-hashes every shipped source file against the signed integrity manifest; any mismatch → opaque `integrity verification failed`, exit nonzero. No self-heal — redeploy. |
| **License gate** | `MCPIP_LICENSE_PATH` + `MCPIP_LICENSE_PUBLIC_KEY_PATH` | Ed25519-signed entitlement (separate license root), checked at boot **only**, never per-request. |
| **WORM persistence posture** | Redis AOF | Production refuses to boot unless Redis is `appendfsync always`. |
| **Sender-constraint boot-lint** | catalog | Refuses to boot if any RESTRICTED/CLASSIFIED non-`PIN_REQUIRED` alias lacks `require_sender_constraint` (a bearer could otherwise exfiltrate an AUTO-tier read). |
| **Authenticator webhook** | `MCPIP_AUTHN_WEBHOOK_URL` + `MCPIP_AUTHN_WEBHOOK_SECRET_PATH` | Production requires **both** for `PIN_REQUIRED` actions (setting exactly one is a fail-closed boot error). AUTO-only deployments leave both unset. |

Opt into the runnable demo explicitly with `MCPIP_SANDBOX_MODE=true` (a loud banner is logged
whenever the sandbox affordances are mounted). Run sandbox with a **single** uvicorn worker
(the in-process demo IdP / WORM keys are per-process); multi-worker deployments supply shared
PEM key files — the production posture.

`MCPIP_INTEGRITY_DEV_BYPASS=true` is structurally sandbox-only: it works solely with
`MCPIP_SANDBOX_MODE=true` (behind a loud banner), and a production boot
(`MCPIP_SANDBOX_MODE=false`) that sees it **refuses to start** — an injected env var cannot
disable verified boot (the Helm chart cannot even express the flag).

#### Deploy preflight (run before every deploy)

```bash
python scripts/preflight_version_consistency.py   # VERSION == chart == dashboard; signed-manifest lag reported honestly
```

Then confirm: Redis is `appendfsync always`; the integrity manifest is fresh (regenerated
after the last source edit — it is the LAST source-touching ceremony step); the image is
pinned **by digest, never by tag**; the license is present; the sender-constraint boot-lint
passes; and the dark-flag posture (forensic capture / external-PDP / telemetry / MRT —
[Opt-in / dark-feature flags](#opt-in--dark-feature-flags)) is reviewed and intended. Verify
the deploy with `mcpip verify` (see [mcpip verify](#mcpip-verify--read-only-release-verification)).

> **Version surfaces vs. signed provenance.** The running-version surfaces (`/healthz`,
> `/v1/version` `running`, MCP `serverInfo`) read `VERSION` dynamically via `core/version.py`;
> the **signed** `release/manifest.json` provenance legitimately lags until the owner re-signs
> offline. The ceremony examples below use `<version>` / concrete numbers interchangeably —
> always cut from the `VERSION` file.

### Opt-in / dark-feature flags — stated honestly

Four features are dark-by-default. Each is off for a reason and each surfaces **why it is off +
how to turn it on** on `GET /v1/admin/stats` (the `features` block) and in the operator console
— never a silent 404, never a fabricated "on". The operator enable-summary:

| Feature | Default | Enable |
|---|---|---|
| **Forensic capture** (payload reconstruction) | ON in sandbox / **OFF in production** (fail-safe) | `MCPIP_FORENSIC_CAPTURE=true` **and** a 32-byte `MCPIP_FORENSIC_KEY_PATH`, then redeploy. Flag-on/key-off = ABSENT (fail-closed, never plaintext). Retrieval is `CAP_FORENSIC_READ`-gated + WORM-audited. |
| **External PDP** (outbound COAZ PEP) | OFF | Set **both** `MCPIP_EXTERNAL_PDP_ENABLED=true` + `MCPIP_EXTERNAL_PDP_URL` (half-config fails boot). Deny-only, monotonic, fail-closed — it can only add a deny, never grant. |
| **Telemetry beacon** | OFF; **air-gap/sandbox never phone home** | `MCPIP_TELEMETRY_ENABLED=true` + `MCPIP_TELEMETRY_URL` in a non-sandbox deploy (half-config fails boot). Closed 8-field aggregate body; no tenant/agent/alias/target/correlation id ever. See [`TELEMETRY.md`](TELEMETRY.md). |
| **MRT / SEP-2322 step-up** | Opt-in on `/v1/mcp` only | Per-request `stepUp:"mrt"`; advertised live via `initialize` → `capabilities.experimental.mcpipStepUp`. Without the MRT keys the branch is byte-identical classic staged-text. |

Optional off-hot-path **license refresh** (`MCPIP_LICENSE_REFRESH_URL`) is also opt-in and
fail-open: it verifies a candidate against the EXISTING license-root only and swaps in a
strictly-newer valid license atomically — it never widens trust, never bricks, never fails open
to unlicensed. Absent the URL ⇒ byte-identical offline behavior.

The **honest posture** these features report at runtime (states / reason codes, and the
forensic-capture troubleshooting flow) is detailed under
[Reading honest dark-feature posture](#reading-honest-dark-feature-posture) in Incident response.

### No LLM egress, by design

The gateway needs no outbound route to any LLM/vendor — the client calls its model directly on
its own keys, and every connector is a pure parser with no network capability (test-enforced by
`tests/test_connector_conformance.py`). The MCP edge is an authorization boundary, not a proxy.
Its egress allowlist can be **empty except for Redis and your own downstream transports** — a
gateway dialing an LLM endpoint is an incident, not a config (see
[Incident response §9.6](#gateway-egress-to-an-llmvendor-endpoint-observed)).

---

## Runbook (day-2 operations)

**Audience:** the operators, release engineers, and security officers who deploy and run the
MCPIP authorization gateway. **Release under operation:** `3.0.0` (the `VERSION` file — read at
runtime by `core/version.py` and at build time by `pyproject.toml`).

### Prerequisites

| Requirement | Detail |
|---|---|
| Python | 3.12 (`/opt/homebrew/bin/python3.12` on the dev host); venv at `.venv/` |
| Redis | Redis 7 with **AOF `appendfsync always`** (see `redis.conf`). Dev container: `mcpip-v2-redis`, host port `63790` → `6379`. |
| Docker / compose | For the image + compose deployment |
| Helm 3 / kubectl | For the Kubernetes deployment (`chart/` or `k8s/`) |
| Offline signer | A machine (HSM-backed or air-gapped laptop) that holds the private root keys. Private keys never touch a deployment host. |

```bash
# One-time dev environment (idempotent):
docker run -d --name mcpip-v2-redis -p 63790:6379 redis:7-alpine || docker start mcpip-v2-redis
/opt/homebrew/bin/python3.12 -m venv .venv
./.venv/bin/pip install -r requirements.txt -r requirements-dev.txt
```

`requirements-dev.txt` adds the release-only tooling (`build`, `cyclonedx-bom`,
`pytest`, `mypy==1.13.0`). None of it enters the runtime image.

### Key generation & rotation (offline Ed25519 roots)

#### The three-key separation

MCPIP uses **three separate Ed25519 keypairs**, never conflated:

| Role | Private key (never committed) | Public key (shipped) | Signs |
|---|---|---|---|
| **Release root** | `.keys/release_root_ed25519.pem` | `release/keys/release_root_ed25519.pub.pem` | Release manifests + boot integrity manifests |
| **License root** | `.keys/license_root_ed25519.pem` | `release/keys/license_root_ed25519.pub.pem` | License/entitlement files |
| **Audit epoch** | Operator-supplied (`MCPIP_WORM_SIGNING_KEY_PATH`) | Operator-managed | WORM epoch roots + anchor lines |

`.gitignore` excludes `.keys/`, `*.pem`, and `*.key` — a private key cannot be committed
by accident, and `.dockerignore` keeps it out of the image. Only public keys plus the
rotation manifest live under `release/keys/`.

#### Generate (dev ceremony)

```bash
./.venv/bin/python scripts/gen_release_keys.py
```

This writes the two private keys `0600` into the gitignored `.keys/`, the two public
PEMs into `release/keys/`, and `release/keys/rotation.json` (schema
`mcpip-key-rotation/1`) recording each key's `key_id`
(`ed25519:` + first 16 hex of SHA-256 over the raw public key), role, and status. It
**refuses to overwrite an existing private key** unless you pass `--force`.
`--keys-dir` / `--public-dir` relocate the outputs (e.g. onto the offline signer's
encrypted volume).

**Production:** run the same script on the offline signer. The private keys never leave
it; every signing script below accepts `--private-key <path>` so the identical tooling
runs there.

#### Rotation procedure (release or license root)

1. **Generate the successor** on the offline signer:
   `scripts/gen_release_keys.py --force --keys-dir <offline-path> --public-dir <staging>`.
2. **Update `release/keys/rotation.json`**: mark the old entry `"status": "retired"`
   with a `not_after` timestamp; add the new entry `"status": "active"` with
   `"supersedes": "<old key_id>"`. Ship the new public PEM alongside it.
3. **Re-sign** the current release artifacts with the new key
   (`scripts/sign_release.py`, [§ Sign the release manifest](#building--signing-a-release)) and
   regenerate + re-sign the integrity manifest (`scripts/gen_integrity_manifest.py`).
4. **Publish the new fingerprint out-of-band** (a channel separate from artifact
   delivery — verifiers trust-anchor on it).
5. **Redeploy** through change control. Verifiers reject any key whose rotation status
   is not `"active"` — the air-gap `INSTALL.md` instructs enclave operators to check
   `keys/rotation.json` explicitly.

The audit epoch key rotates independently through your secret-management process
(update the `mcpip-keys` Secret / mounted PEM and redeploy); previously sealed epochs
remain verifiable because each epoch header records its signature at sealing time.

**WORM content key (opt-in at-rest encryption).** When `MCPIP_ENCRYPT_WORM_AT_REST` is
on, each event body is sealed with AES-256-GCM under a fresh random 96-bit nonce
(`MCPIP_WORM_CONTENT_KEY_PATH`, a 32-byte key). Random-nonce GCM is safe up to roughly
2³² seals under one key before nonce-collision risk becomes non-negligible (NIST SP
800-38D); a collision would leak only the XOR of two encrypted *bodies* and can **never**
defeat `verify_chain` (chain integrity is Merkle + Ed25519, independent of the content
key). To stay well inside that bound on a high-volume ledger, **rotate the content key
periodically** — annually, or sooner if sustained emit volume would approach ~10⁹ events
under one key. Rotation is a plain secret-management step: add the new key file, point
`MCPIP_WORM_CONTENT_KEY_PATH` at it, and redeploy. The self-describing `encv1:` envelope
means new events seal under the new key while records written under the retired key stay
readable **as long as you keep the retired key available** to the content readers — so
retain superseded content keys for the audit-retention window rather than destroying them
(destroying a key crypto-shreds every body sealed under it, which is the erasure lever,
not a rotation step). `verify_chain` needs no content key either way.

**Suspected root-key compromise** is [Incident response §9.4](#suspected-signing-key-compromise).

#### Gateway master keys & principal minting

The release/license roots above are distinct from the two keys the *gateway* consumes.
Generate those with `scripts/provision_gateway_keys.py` — Ed25519 keypairs made in
memory, private PEM written `0600` to a gitignored keys dir, only public fingerprints
printed (private bytes never touch stdout/logs), refuses overwrite without `--force`:

```bash
python scripts/provision_gateway_keys.py --keys-dir <offline> --public-dir <staging>
#  worm_signing_ed25519.key  -> MCPIP_WORM_SIGNING_KEY_PATH  (private, gateway-held)
#  worm_signing_ed25519.pub  -> auditors (mcpip export-audit --verify --pubkey ...)
#  idp_signing_ed25519.key   -> the token minter / KMS (NEVER the gateway)
#  idp_signing_ed25519.pub   -> MCPIP_JWT_PUBLIC_KEY_PATH   (public, gateway verifies)
```

Mint a client **principal** — the production analog of the sandbox `/v1/dev/token`:
an EdDSA JWT scoping an agent to a tenant plus the capability/compartment entitlements
the gateway enforces (identity is verify-only; `role` authorizes nothing):

```bash
python scripts/mint_principal.py --idp-key <idp_private> \
  --tenant tenant-acme --agent agent-hero-1 --role ops \
  --issuer "$MCPIP_JWT_ISSUER" --audience "$MCPIP_JWT_AUDIENCE" --ttl 900 \
  --capability <capability-uuid> --compartment <compartment-uuid>
```

Keep TTLs short; for fleets, mint sender-constrained tokens (`--cnf-jkt`) over ephemeral
per-session keys instead of long-lived bearers (the SPIFFE / workload-identity provisioning
model — runtime attestation → RFC 8693 exchange → ephemeral per-session keys — is in
[`ARCHITECTURE.md`](../build/ARCHITECTURE.md)). The whole ceremony → mint → verify → tamper cycle is
regression-gated by `tests/test_provisioning.py`. Secret injection into the running system is
`scripts/deploy_hero.sh` + `.env.production.example`
(see [CI/CD secret injection](#cicd-secret-injection--the-hero-deploy-script)).

### Building & signing a release

Run in this order — each step feeds the next.

#### 1. Version

```bash
cat VERSION          # e.g. 2.0.0 — strict MAJOR.MINOR.PATCH
```

Bump `VERSION` (and `CHANGELOG.md`) first; `core/version.py` fails boot on a missing or
malformed value, and both manifests are keyed by it.

#### 2. Build artifacts + SBOM

```bash
# Wheel + sdist -> dist/
./.venv/bin/python -m build

# CycloneDX SBOM -> release/sbom/mcpip-<version>.cdx.json
# (environment mode: the fully-resolved pinned set in .venv; falls back to requirements mode)
bash scripts/build_sbom.sh
```

The SBOM is hashed and listed in the signed release manifest, so it is **signed
transitively** with everything else.

#### 3. Sign the release manifest (offline root)

```bash
./.venv/bin/python scripts/sign_release.py \
  --version 2.0.0 \
  --private-key .keys/release_root_ed25519.pem \
  --artifact dist/mcpip-2.0.0-py3-none-any.whl \
  --artifact dist/mcpip-2.0.0.tar.gz \
  --artifact release/sbom/mcpip-2.0.0.cdx.json
```

Outputs `release/manifest.json` (embedded base64 signature) and the detached
`release/manifest.sig`, written atomically. Optionally include the container image:
`--image-tar dist/mcpip-gateway-2.0.0-image.tar --image-ref mcpip-gateway:2.0.0`
(`--image-id` is read via `docker image inspect` when omitted).

**The normative signing rule** (shared verbatim by the signer, `mcpip verify`, and
`core/integrity.py`): the signed message is the manifest JSON object **without** its
`"signature"` key, serialized `json.dumps(obj, sort_keys=True, separators=(",", ":"))`
as UTF-8; the signature is a raw 64-byte Ed25519 signature over those bytes,
base64-encoded. Verification is pure local cryptography — independent of TLS, PKI, or
any network service.

#### 4. Generate the boot-integrity manifest — *last step before `docker build`*

```bash
./.venv/bin/python scripts/gen_integrity_manifest.py \
  --private-key .keys/release_root_ed25519.pem
```

Hashes (SHA-256, streamed) the normative shipped source set — every `*.py` under
`app/ core/ auth/ audit/ bridge/ services/ models/ obfuscator/ mcpip_verify/` plus
`interfaces.py`, `main.py`, and `VERSION` — and signs
`release/integrity_manifest.json` with the release root. Run it **after** the final
source edit so the image hashes match what boot re-verifies.

#### 5. Build the image

```bash
docker build -t mcpip-gateway:2.0.0 .
docker images --digests mcpip-gateway     # record the sha256: digest for deploy pinning
```

The image is multi-stage (3.12-slim builder venv → non-root 3.12-slim runtime), carries
no secrets, and ships the integrity manifest + public keys so verified boot works with
zero extra mounts.

### `mcpip verify` — read-only release verification

`mcpip` is the console script installed by the wheel (`pyproject.toml`
`[project.scripts] mcpip = "mcpip_verify.cli:main"`); from a source checkout use
`./.venv/bin/python -m mcpip_verify.cli` interchangeably.

**Fail-closed contract:** on ANY *release* verification failure the tool prints exactly
`verification failed` to stderr (opaque — no reason, no path, no hash) and exits `2`.
Success prints `verified: mcpip <version> (<n> artifacts)` and exits `0`. `export-audit
--verify` is the one operator-facing exception to the opacity: it names the failed
integrity check and the first bad epoch (see [Verify & export](#verify--export)) — that
output goes to the operator running the tool, never to an agent — and also exits `2`.
The tool never writes anything except the explicit `--out` file of `export-audit`, and
never self-updates anything.

```bash
# Verify a release manifest + every listed artifact on disk:
./.venv/bin/python -m mcpip_verify.cli verify \
  --manifest release/manifest.json \
  --pubkey release/keys/release_root_ed25519.pub.pem \
  --base-dir .

# Verify an offline air-gap bundle end-to-end (no network):
./.venv/bin/python -m mcpip_verify.cli verify bundle dist/mcpip-airgap-2.0.0.tar.gz \
  --pubkey release/keys/release_root_ed25519.pub.pem
```

Gate every deployment on exit code `0`. Treat exit `2` as a hard stop.

### The offline (air-gap) bundle

#### Build

```bash
bash scripts/build_bundle.sh 2.0.0
```

The builder **re-verifies every artifact against the signed manifest before packing**
(fail-closed pre-check via `mcpip verify`), then assembles a deterministic tarball
`dist/mcpip-airgap-2.0.0.tar.gz`:

```
mcpip-airgap-2.0.0/
├── manifest.json            signed release manifest
├── manifest.sig             detached Ed25519 signature
├── keys/                    PUBLIC keys + rotation.json (never private material)
├── artifacts/               wheel, sdist, image tar (or BUILD_RECIPE.md if no tar)
├── sbom/                    CycloneDX SBOM
├── SHA256SUMS               defense-in-depth digests (the SIGNED manifest is authoritative)
└── INSTALL.md               the in-enclave verify + deploy runbook
```

#### Install inside the enclave (summary — the full text ships as `INSTALL.md`)

1. **Check the public-key fingerprint against your out-of-band copy** (delivered on a
   channel separate from the bundle). For release `2.0.0` it is
   `ed25519:e445d00ee49a6e78`. Mismatch = stop.
2. `mcpip verify bundle mcpip-airgap-2.0.0.tar.gz --pubkey keys/release_root_ed25519.pub.pem`
   — exit 0 or stop.
3. `docker load -i artifacts/mcpip-gateway-2.0.0-image.tar` (or rebuild from the
   verified sdist per `artifacts/BUILD_RECIPE.md`), then **deploy by digest**.
4. Offline CVE scan against the bundled SBOM with an out-of-band-mirrored DB:
   `grype sbom:sbom/mcpip-2.0.0.cdx.json` or
   `trivy sbom sbom/mcpip-2.0.0.cdx.json --skip-db-update`.

No step requires a network. MCPIP itself never phones home.

### Deployment (Compose / Helm / Kubernetes)

#### docker compose (single-node)

**Production — `docker-compose.prod.yml`.** The default `docker-compose.yml` wires no key
material (it is the sandbox/demo surface), so a non-sandbox `docker compose up` on it fails
closed at boot by design. For a real single-host production gateway use the prod file, which
hard-pins `MCPIP_SANDBOX_MODE=false`, bundles the durable Redis, and bind-mounts a host
secret dir (`./secrets` → `/etc/mcpip:ro`) wiring **every** startup gate:

```bash
# 1) Place these SIX files in ./secrets (never commit it):
#    idp_signing_ed25519.pub.pem    PUBLIC IdP key (verifies principal JWTs)   [secret store]
#    worm_signing_ed25519.key       PRIVATE Ed25519 WORM epoch signer          [secret store]
#    license.json                   your signed MCPIP license                  [vendor]
#    integrity_manifest.json        copy of release/integrity_manifest.json
#    release_root_ed25519.pub.pem   copy of release/keys/release_root_ed25519.pub.pem
#    license_root_ed25519.pub.pem   copy of release/keys/license_root_ed25519.pub.pem
# 2) Set your IdP issuer (must match the `iss` of your minted tokens), e.g. in ./.env:
echo 'MCPIP_JWT_ISSUER=prod-idp.example' > .env
# 3) Bring it up (durable Redis + fail-closed gateway):
docker compose -f docker-compose.prod.yml up --build
curl -s http://localhost:8080/healthz             # {"status":"live","glyph":"◐",...}
docker compose -f docker-compose.prod.yml logs -f gateway
docker compose -f docker-compose.prod.yml down    # add -v to also drop the WORM + Redis volumes (back up audit first)
```

Files in `./secrets` must be readable by the gateway's non-root uid (10001): keep the
private `worm_signing_ed25519.key` tight (e.g. `chown 10001:10001` + `chmod 0640`) and the
public `.pub.pem` / manifest / license world-readable. The WORM ledger persists on the
`worm-data` named volume (`/var/lib/mcpip`); the durable Redis AOF on `redis-data`.

**Sandbox / demo — the default file.** `MCPIP_SANDBOX_MODE=true docker compose up --build`
runs the runnable end-to-end demo (mounts the dev-token forge + OTP peek behind a loud
banner); a bare `docker compose up` on the default file boots fail-closed with no keys.

Both files are **two-network by design**: `redis` is on an `internal: true` network with no
host port (unreachable from outside the compose project), and the gateway straddles
`mcpip-internal` + a bridge `mcpip-edge` that publishes ONLY 8080. That is the gateway-side
lock (see [Deploying behind a service mesh §4](#4-docker-compose--the-behind-a-proxy-example)
for the single-host mesh-posture overlay).

#### Helm (Kubernetes)

The chart (`chart/`, name `mcpip`, `appVersion: 2.0.0`) **never creates or embeds
secret material** and deliberately has **no value** that maps to `MCPIP_SANDBOX_MODE`
or `MCPIP_INTEGRITY_DEV_BYPASS` — production pods always boot fail-closed.

```bash
# 1) Pre-create the Secret the chart mounts read-only at /etc/mcpip/keys:
kubectl create namespace mcpip
kubectl -n mcpip create secret generic mcpip-keys \
  --from-file=jwt_public.pem=/secure/path/jwt_public.pem \
  --from-file=worm_signing.pem=/secure/path/worm_signing.pem \
  --from-file=license.json=/secure/path/license.json

# 2) Install, pinning the IMMUTABLE digest recorded at release time (never a mutable tag):
helm upgrade --install mcpip ./chart -n mcpip \
  --set image.repository=<your-registry>/mcpip-gateway \
  --set image.digest=sha256:<digest-from-release>
```

What the chart deploys: 2 replicas (HPA 2→10 at 70% CPU), non-root, read-only rootfs,
default-deny NetworkPolicy (ingress on `:8080` from `ingress.allowedNamespaceSelector`;
`/metrics` scrapes from `metrics.prometheusNamespaceSelector`, default `monitoring`),
a durability-hardened Redis StatefulSet (`appendfsync always`), and a persistent volume
for the WORM path. Non-secret env goes in `env: {}`; **never** put keys or license
bodies there.

Plain manifests are the equivalent no-Helm path: `kubectl apply -f k8s/` (namespace
`mcpip`; `k8s/secret.example.yaml` documents the same three Secret keys —
structure only, populate out-of-band).

#### Verified boot wiring (both k8s paths, preconfigured)

`k8s/configmap.yaml` / `chart/templates/configmap.yaml` already point the gateway at
the in-image manifests:

```
MCPIP_INTEGRITY_MANIFEST_PATH:   /app/release/integrity_manifest.json
MCPIP_INTEGRITY_PUBLIC_KEY_PATH: /app/release/keys/release_root_ed25519.pub.pem
MCPIP_LICENSE_PATH:              /etc/mcpip/keys/license.json
MCPIP_LICENSE_PUBLIC_KEY_PATH:   /app/release/keys/license_root_ed25519.pub.pem
```

At startup the gateway re-hashes every shipped source file against the signed
integrity manifest **before a socket is bound**; any mismatch raises the opaque
`integrity verification failed` and exits nonzero (the specific file is logged only at
CRITICAL on `mcpip.boot`). There is **no remediation or self-heal path** — redeploy a
verified image.

#### Kernel note for burst traffic

`--backlog 2048` is silently clamped to `net.core.somaxconn` (Linux, often `128`).
Raise it (`sysctl -w net.core.somaxconn=2048`, or a k8s sysctl/initContainer) or a
connection storm is refused by the kernel before app-layer shedding can engage. See
README § Scaling.

#### CI/CD secret injection — the Hero deploy script

For compose / bare-metal (the Helm path uses the `mcpip-keys` Secret, above),
`scripts/deploy_hero.sh` performs zero-trust injection: secret **material** arrives
ONLY as env vars from the pipeline's secret store (never committed, never in the
image), is written `0600` onto a tmpfs, the in-memory copies are scrubbed, and the
gateway is exec'd fail-closed. Non-secret config + **paths** come from
`.env.production` (copy `.env.production.example` — the only committed `.env*` variant,
containing zero secret values):

```bash
# In the pipeline, AFTER the secret store exports MCPIP_*_PEM / MCPIP_LICENSE_JSON:
set -a; . ./.env.production; set +a          # non-secret config + paths
scripts/deploy_hero.sh                        # materializes 0600, scrubs, execs uvicorn
```

Required injected secrets: `MCPIP_WORM_SIGNING_KEY_PEM`, `MCPIP_JWT_PUBLIC_KEY_PEM`,
`MCPIP_LICENSE_JSON`. If any is absent — or `MCPIP_SANDBOX_MODE` is not `false` — the
script aborts before boot; and even past it, the gateway's composition root refuses to
boot without a valid license + integrity manifest. That layered refusal is the safety net.

### License install

Licenses gate **process boot only** — the verified document is never consulted by the
per-request authorization pipeline (entitlement is a change-control matter; per-request
authorization is the engine's). Verification is pure local Ed25519 — no license server,
no phone-home — so air-gapped enclaves validate identically. Expiry is checked at boot
only; your redeploy cadence re-verifies it.

```bash
# Dev license (signed by the dev license root, lands in gitignored .keys/):
./.venv/bin/python scripts/gen_license.py \
  --customer "Acme Corp" --tier self-hosted --days 365 \
  --entitlements authorize,mcp_edge,audit_export,metrics

# Wire it up (bare-process example; k8s mounts it via the mcpip-keys Secret):
export MCPIP_LICENSE_PATH=.keys/dev_license.json
export MCPIP_LICENSE_PUBLIC_KEY_PATH=release/keys/license_root_ed25519.pub.pem
```

Tiers are a closed set — `cloud`, `self-hosted`, `air-gapped`; anything else fails
closed. Production licenses are minted on the offline signer
(`--private-key <offline path>`) and delivered to the customer out-of-band. Boot logs
record only `license_id`, `tier`, and expiry — never customer-sensitive detail — and a
failed gate raises the opaque `license verification failed`.
Setting only one of the two license env vars is a misconfiguration and refuses boot.

### The audit log — verification, export, backup, restore

#### What lives where

| Component | Location | Property |
|---|---|---|
| Durable event buffer + signed epoch headers | Redis (`mcpip:worm:*`), AOF `appendfsync always` | Every event fsync-durable **before** the action is authorized |
| Head anchor (rollback/truncation watermark) | Append-only file next to `MCPIP_WORM_PATH` (default `<worm_path>.anchor`, i.e. `/var/lib/mcpip/mcpip_worm.jsonl.anchor` in the image), or `MCPIP_WORM_ANCHOR_PATH` | **Must** sit on a durable volume distinct from the Redis store — it is the out-of-tamper-domain witness |
| Legacy JSONL ledger | `MCPIP_WORM_PATH` (only in `mode="per_event"` migration) | Not used by the default Merkle-epoch model |

#### Verify & export (read-only, production-safe)

```bash
# Export the WORM stream + epoch headers to JSONL and independently re-verify the
# whole signed chain (Merkle roots, epoch_hash, prev_epoch_hash linkage, the Ed25519
# epoch signatures, and the out-of-tamper-domain anchor low-watermark):
./.venv/bin/python -m mcpip_verify.cli export-audit \
  --redis-url redis://localhost:63790/0 \
  --out audit_export.jsonl \
  --verify \
  --pubkey /path/to/worm_signing_ed25519.pub.pem \
  --anchor-path /var/lib/mcpip/mcpip_worm.jsonl.anchor \
  --require-anchor
```

`--verify` performs five checks, and the verdict line NAMES every one it ran:

| Check | Catches |
|---|---|
| `prev_epoch_hash linkage` (+ monotonic epoch numbers, contiguous `seq` coverage) | a dropped, duplicated or reordered epoch — even when every surviving signature verifies |
| `Merkle roots` (leaves recomputed from the exported records, cross-checked against the stored `leaf_hash`) | a mutated or partially-deleted event body |
| `epoch_hash recomputation` (over **every** persisted header field) | any header-field mutation |
| `Ed25519 epoch signatures` (against `--pubkey`) | forgery / signature substitution |
| `anchor low-watermark` (against `--anchor-path`) | rollback / tail-truncation, including the case where the in-Redis counters were rewritten too |

`--pubkey` is the `worm_signing_ed25519.pub.pem` half of the key ceremony and is
**required** by `--verify` — without it the epoch signatures cannot be checked at all,
so the tool refuses to print a verdict rather than a green one no signature backed.
`--anchor-path` defaults to `MCPIP_WORM_ANCHOR_PATH`, else `<MCPIP_WORM_PATH>.anchor`;
if no signed watermark is found the success line says so explicitly (`NOT checked:
anchor low-watermark …`), and `--require-anchor` turns that into a failure — use it for
scheduled checks, where a silently-missing rollback witness is itself the incident.

Success prints the event/epoch counts plus
`audit chain: intact — <n> epochs fully verified, <m> signature-only (events trimmed),
anchor low-watermark epoch <k> matched` followed by the `checked:` list; a tampered
chain prints `audit chain: TAMPERED — <check> failed at epoch <k>` to stderr and exits
`2`. Epochs whose events have aged out of the hot buffer are verified **signature-only**
against their signed root and are reported separately — never folded into the verified
count. In sandbox mode the same checks are reachable over HTTP (`GET /v1/audit/verify`,
`GET /v1/audit/proof/{event_id}`); those endpoints return `404` in production —
use `export-audit` there. The self-contained proof also runs as part of
`./.venv/bin/python main.py` (gate C9), which exits `0` only with the chain INTACT.

One deliberate difference from the in-gateway `verify_chain`: the exporter takes **no
epoch lock** (that is what makes it production-safe), so it cannot distinguish a
whole-epoch event deletion inside the hot retention window from a trim the close daemon
performed while the export was streaming — those epochs are accepted signature-only.
Everything above the retention watermark must have its events present, and a *partial*
epoch is tamper at any depth. The gateway's own `verify_chain` (`GET /v1/audit/verify`
in sandbox, the background integrity monitor in production) is the surface that makes
that last distinction.

Schedule `export-audit --verify --pubkey … --require-anchor` (cron/CI) as your
continuous tamper check, and archive the JSONL exports as offline evidence. (For a
cross-region "one pane of glass" auditor
view, see [Multi-region — the deferred global auditor view](#the-worm-ledger--anchor-across-regions)
and [`COMPLIANCE.md`](COMPLIANCE.md).)

#### Backup

Back up **both** halves — they deliberately live in different tamper domains:

1. **Redis AOF** — snapshot the Redis data directory (compose: the `redis-data`
   volume; k8s: the Redis StatefulSet PVC). `BGREWRITEAOF` then copy, or use your
   volume-snapshot mechanism.
2. **The anchor file** — copy `/var/lib/mcpip/mcpip_worm.jsonl.anchor` (the `worm-data`
   volume / gateway PVC). Store it separately from the Redis backup.
3. Keep the WORM **epoch-signing public key** with the backups so an auditor can verify
   the archive years later without the live system.

#### Restore

1. Restore the Redis AOF into a stopped Redis, start it, confirm
   `redis-cli CONFIG GET appendfsync` → `always`.
2. Restore the anchor file to the gateway's anchor path **before** starting the
   gateway.
3. Verify before serving traffic:
   `./.venv/bin/python -m mcpip_verify.cli export-audit --redis-url <url> --out /tmp/restore_check.jsonl --verify --pubkey <worm pubkey> --anchor-path <anchor> --require-anchor`
4. The anchor is a **monotonic low-watermark**: if the restored Redis chain stops short
   of the anchored head (someone restored an older Redis backup than the anchor
   witnessed), verification reports tamper. That is correct behavior — restore a
   matching pair, or accept and document the gap through your incident process. Never
   "fix" a mismatch by deleting the anchor.

### Incident response

Standing rule for every scenario: the wire stays opaque (generic error +
`correlation_id`); diagnosis happens from the WORM log and `mcpip.boot` logs, keyed by
correlation id.

#### Boot refuses: `integrity verification failed`

The running source set differs from what the release root signed — a tampered/patched
file, or a stale integrity manifest (source edited after the integrity-manifest step).

1. Do **not** bypass. Capture the pod/container logs — the CRITICAL `mcpip.boot` line
   names the cause; the crash surface deliberately does not.
2. Compare the image digest against `release/manifest.json`. If they differ, someone
   deployed an unverified image → treat as a supply-chain incident.
3. Redeploy the last known-good digest through change control. There is no self-heal
   path by design.

#### `export-audit --verify` reports TAMPERED

1. Freeze: stop writes if feasible, snapshot the Redis volume and anchor file
   immediately (evidence).
2. The output names the failed CHECK and the first bad epoch — read it directly:
   `Ed25519 epoch signatures` / `epoch_hash recomputation` / `Merkle roots` are
   **forgery/mutation**; `anchor low-watermark` is **rollback/truncation** (the chain
   stops short of, or substitutes, the fsync'd witnessed head); `prev_epoch_hash
   linkage` is a **dropped/reordered epoch**.
3. Export everything (`export-audit`, no `--verify`, to a second copy) before any
   remediation. Rotate Redis credentials, rebuild the Redis host, restore from the
   last intact backup pair (see [Restore](#restore)), and file through your security process.

#### `license verification failed` at boot

Expired, forged, wrong tier grammar, or wrong public key. Check `mcpip.boot` CRITICAL
logs; install a currently-valid signed license (see [License install](#license-install)) and
redeploy. The gate never stops a *running* process — expiry only bites at the next boot, so
plan renewals with your redeploy cadence.

#### Suspected signing-key compromise

1. Treat every artifact signed after the suspected compromise time as untrusted.
2. Execute the rotation procedure (see
   [Rotation procedure](#rotation-procedure-release-or-license-root)) from a clean offline
   signer; mark the old key `"status": "retired"` in `rotation.json` with `not_after` set
   to the compromise window start.
3. Publish the new fingerprint out-of-band; instruct all enclaves to re-verify their
   deployed bundles against it and hard-stop on the old key.
4. Audit-epoch key compromise does **not** let an attacker rewrite history silently:
   sealed epochs are chained and anchored; rotate the key and re-verify the chain against
   the anchor.

#### Sustained `503` shedding / overload

`mcpip_requests_shed_total{cause="overload"}` climbing means arrivals exceed
`MCPIP_MAX_IN_FLIGHT` per worker. That is the system protecting its tail latency, not a
fault. Scale horizontally (workers/replicas — the gateway is stateless), verify Redis
headroom (`workers × max_in_flight ≤ maxclients`), and check the somaxconn note
([Kernel note for burst traffic](#kernel-note-for-burst-traffic)). Shedding is structurally
incapable of converting a DENY into an ALLOW — a shed request never reaches `authorize()`.

#### Gateway egress to an LLM/vendor endpoint observed

**That is an incident, not a configuration.** MCPIP holds no vendor keys and every
connector is a parser (AST-enforced by `tests/test_connector_conformance.py`). Isolate
the pod, verify the image digest and boot-integrity status, and treat as the integrity /
tamper scenarios above.

#### "Reconstruct payload does not work" — forensic capture is OFF by default

This is almost never a fault. **Forensic payload capture is default-OFF in production**
(the fail-safe default — raw-query reconstruction is a high-sensitivity capability). When
it is off, `GET /v1/admin/forensic/{correlation_id}` returns `404` for *every*
correlation id, and the console's per-id reconstruct shows an honest "no reconstructed
payload" outcome. That `404` is **deliberately opaque** — feature-off, unknown id,
expired capture, and cross-tenant all look identical, on purpose (no exists-elsewhere
oracle). So the per-id result alone cannot tell you *why* nothing came back.

To see the real reason, read the **deployment-wide posture** (below), not the per-id
route. The console surfaces it proactively: a banner in the WORM-Ledger forensic
inspector (shown *before* the reconstruct button) and a "Forensic capture" row in
Gateway → Software → Deployment · License & Usage. Both read the coarse posture — they
never make the per-id `404` distinguishable.

To turn capture ON in production: set `MCPIP_FORENSIC_CAPTURE=true` **and** provide a
dedicated 32-byte key at `MCPIP_FORENSIC_KEY_PATH`, then **redeploy** (upgrades are always
a redeploy). Flag-on *without* a key is the fail-closed **ABSENT** state
(capture no-ops, retrieval `404`s, never a plaintext fallback). Retrieval always stays
`CAP_FORENSIC_READ`-gated (a distinct capability directory-admin does not confer) and
WORM-audits a `forensic_read` before disclosing anything.

#### Reading honest dark-feature posture (`GET /v1/admin/stats` → `features`)

The opt-in / dark features report an **honest** disabled/why/how-to-enable posture in
the `features` block of `GET /v1/admin/stats` (`CAP_DIRECTORY_ADMIN`, tenant-scoped,
aggregates-only — the same privacy boundary as the rest of the stats surface). The block
is **posture-only**: booleans + reason codes + a human `detail` string, and it carries
**no** url, key path, target, tenant, or install id. The `mcpip admin stats` CLI and the
operator console render the same states; none of them ever fabricates a "connected"/live
state for a feature that is off.

| Feature | States (`status` / `reason`) | Meaning |
|---|---|---|
| `forensic_capture` | `enabled` | Capture is live; each authorize's real query is encrypted at rest, readable only via `CAP_FORENSIC_READ` + a WORM-audited read. |
| | `disabled` / `production-default` | Unset flag in production — the fail-safe off. |
| | `disabled` / `explicit-opt-out` | `MCPIP_FORENSIC_CAPTURE=false` — intentionally off. |
| | `absent` / `flag-on-no-key` | Flag on but no `MCPIP_FORENSIC_KEY_PATH` — fail-closed, never plaintext. |
| `external_pdp` | `off` | Neither `MCPIP_EXTERNAL_PDP_ENABLED` nor `MCPIP_EXTERNAL_PDP_URL` set — the shipped no-op seam; hot path unchanged. |
| | `staged` | URL set, flag off — staged but NOT enforcing (no decision consulted). Set the flag + redeploy to enforce. |
| | `enforcing` | Both set — every authorization also consults an external AuthZEN PDP as a **deny-only, monotonic, fail-closed** term (can only add a deny, never grant). |

Two related surfaces round out the honest treatment:

- **Vendor telemetry** stays a top-level `telemetry` key (the reference model):
  `enabled` / `disabled` / `air-gap` (sandbox is structurally air-gapped and never phones
  home) + a coarse `last_sent`/`last_result`. See [`TELEMETRY.md`](TELEMETRY.md).
- **MCP MRT step-up (SEP-2322)** is *not* a disabled feature — it is always advertised
  and opt-in per call. The console reads it **live** from the unauthenticated MCP
  `initialize` reply (`capabilities.experimental.mcpipStepUp`) and shows `advertised` vs
  `not advertised` from the actual response — never a static string, so a gateway that
  predates the surface reads honestly as not-advertised.

### Monitoring

`GET /metrics` (Prometheus exposition; exempt from shedding; network exposure confined
by the NetworkPolicy, not the process):

| Metric | Labels | Meaning |
|---|---|---|
| `mcpip_authorize_decisions_total` | `decision` ∈ {allow, deny, staged} — the concrete `deny_reason` is DELIBERATELY NOT a metric label (it stays in the WORM log / structured logs only, so `/metrics`, which is unauthenticated, cannot be scraped as a low-cost deny-reason oracle) | Decision counts |
| `mcpip_authorize_latency_seconds` | `decision` | End-to-end `/v1/authorize` latency histogram |
| `mcpip_requests_shed_total` | `cause` ∈ {overload, timeout, oversized, unauthorized} | Edge-shed requests |
| `mcpip_worm_epoch` / `mcpip_worm_sequence` | — | Audit chain heights (alert if they stall while decisions flow) |
| `mcpip_audit_integrity_total` | `event` ∈ {verified, tamper_detected, verify_error} | Off-hot-path audit-integrity monitor: a periodic (~5 min) fresh `verify_chain`. **Alert on `tamper_detected`** — it also emits a CRITICAL `mcpip.audit` log naming `first_bad_epoch`. |

Label discipline is enforced by construction (`core/metrics.py`): every label value in
the codebase is a string literal or a closed-enum value — **no** tenant, agent, alias,
compartment, capability UUID, correlation id, JWT material, or approval code can appear
in a metric name or label. Multi-worker aggregation uses `PROMETHEUS_MULTIPROC_DIR`
(set by the Dockerfile); a scrape of any worker returns the fleet-of-workers aggregate.

**Continuous audit-integrity monitoring (shipped).** The gateway runs an always-on,
off-hot-path monitor (`_audit_integrity_daemon`) that re-runs `verify_chain` every ~5
minutes and turns the result into the `mcpip_audit_integrity_total{event}` counter plus a
CRITICAL `mcpip.audit` log on tamper — so a non-verifiable chain is detected continuously,
not only when an operator asks. The compaction path likewise no longer declines silently
on a non-intact prefix (it logs an audit warning). Route the `mcpip.audit` CRITICAL logs to
your incident channel.

**Reference alerts (shipped, opt-in).** Starter Prometheus rules ship as
`k8s/prometheus-rules.yaml` (plain) and the Helm `prometheusRule` template
(`prometheusRule.enabled=true`): gateway-down, sustained overload shed, p99 authorize
latency, WORM epoch stalled, and `mcpip_audit_integrity_total{event="tamper_detected"}`.
Tune them to your SLA. A gateway `PodDisruptionBudget` (`k8s/pdb.yaml` / `pdb.enabled`)
keeps ≥1 gateway serving through node drains — important because MCPIP fails closed, so
losing every gateway denies all agent actions.

**Log forwarding (SIEM).** Structured JSON logs go to stderr (`core/logging_setup.py`).
Ship them with your platform's log collector (e.g. a Fluent Bit / Vector sidecar or the
node agent) to your SIEM; there is no built-in remote sink. The WORM ledger is the
authoritative audit record — forward the `export-audit --verify` JSONL to immutable
long-term storage (WORM-mode object store / S3 Object-Lock) for retention beyond the
in-system hot window (see [Verify & export](#verify--export)).

Suggested alerts: `readyz` failing (Redis down); `mcpip_worm_epoch` flat while
`mcpip_authorize_decisions_total` rises; shed-rate > a few %; a scheduled
`export-audit --verify --pubkey … --require-anchor` exiting nonzero (it names the failed
check on stderr); any `mcpip_audit_integrity_total{event="tamper_detected"}`.

### Upgrades = redeploy (never in-place)

1. Build + sign the new release (see [Building & signing a release](#building--signing-a-release)),
   producing a new signed manifest, integrity manifest, SBOM, and image digest.
2. Verify it (`mcpip verify`) — gate on exit 0.
3. Roll through change control: compose — `docker compose up -d --build` with the new
   tag; Helm — `helm upgrade mcpip ./chart -n mcpip --set image.digest=sha256:<new>`;
   air-gap — deliver + verify a new bundle, load, re-pin, roll.
4. Post-deploy: `curl -s http://<host>:8080/healthz` shows the new `version`;
   `export-audit --verify --pubkey …` confirms the audit chain carried across intact.
5. Rollback is the same operation with the previous digest — previous releases stay
   valid because their signatures never expire with the deployment.

**There is no auto-update channel to disable, because none exists.** The gateway
contains no updater, no code-pull, no runtime mutation of its own files, and verified
boot fails closed on any change. If automated *delivery* is ever added, it will be an
external TUF/Sigstore pipeline feeding the same operator-controlled redeploy — never an
in-binary mechanism.

---

## Network Enforcement & Non-Bypassability

*The answer to "an app-layer authorizer can be bypassed — do we need to be a layer on VPN?"
Short answer: **no VPN; this is a packaging concern, not a design flaw.** Companion to
the internal roadmap and the positioning in the internal strategy notes. The two
packaging artifacts this called for now ship: `k8s/agent-egress-lockdown.networkpolicy.yaml`
(agent-side egress lock) and the mesh reference in
[Deploying behind a service mesh](#deploying-behind-a-service-mesh--identity-aware-proxy-compose).*

### The concern (legitimate)

MCPIP authorizes at L7: an agent sends its tool call to `POST /v1/authorize` or `POST /v1/mcp`.
If the agent *chooses* not to, it could call the real target directly and skip the gate — and
the market is explicit that this matters: *"application-layer controls sit inside the trust
boundary an attacker already occupies"*; a direct call *"doesn't appear in your SIEM, isn't
captured by DLP, and the audit trail simply doesn't exist."* For a product whose crown jewel is
a tamper-evident WORM log, a bypass doesn't just skip authz — it silently voids the audit story.
Non-bypassability is a hard procurement gate.

### Two enforcement shapes already ship

MCPIP is **not** purely voluntary today — it's two shapes depending on transport:

- **`cloud_rest` / `legacy_mainframe` / `grant_issue`:** MCPIP *itself dispatches* the call — it
  is an **inline reverse proxy / data plane**; the agent's payload never leaves MCPIP and MCPIP
  holds the real target. Bypass here is purely a *network* question (can the agent reach the
  target on its own?).
- **`cloud_iam`:** MCPIP does **not** proxy — it **vends a short-lived scoped STS/impersonation
  credential** and the agent makes the call. Bypass is defeated by **"no standing key"**: the
  target is unreachable without a per-call credential only MCPIP mints
  (`services/cloud_broker.py` — "NO STANDING SECRETS AT REST"). This is exactly the enforcement
  wedge Aembit, HashiCorp Vault+Boundary, and Oasis sell as their core.

So the "voluntary bypass" worry really only bites for the *proxy-transport* case where the org
hasn't also locked network egress — a narrower gap than "we need to be a VPN."

### The two competitor families — and where MCPIP sits

- **Network-capture family** (Cloudflare Portals+Tunnel, Pomerium, HashiCorp Boundary,
  Tetrate/Solo mesh, Operant's eBPF LSM): make the target physically unreachable except through
  the enforcement point (tunnel/ZTNA, mesh mTLS, session broker, kernel hook).
- **Credential-wedge family** (Aembit, Vault, Oasis, **and MCPIP `cloud_iam`**): make the target
  unreachable except with a short-lived cred the broker vends — "no standing key" is de-facto
  non-bypassability *without touching the network path*.

MCPIP already lives in the credential-wedge family for cloud, and is a network-capture-style
inline proxy for its other transports. **It is not the outlier the intuition feared.**

### The three enforcement layers (ranked by effort ÷ payoff — best first)

**1. Lean on `cloud_iam` "no standing key" as the flagship non-bypass claim (already built).**
The downstream target is unreachable without a short-lived credential only MCPIP mints after an
ALLOW is WORM-recorded; the agent never holds a resident credential. The correct deployment
gives the underlying cloud role **no principal other than MCPIP's host identity**
(IRSA/workload-identity) can assume it — so there is literally no standing path. Extend the same
pattern to non-cloud targets (DB/SaaS/mainframe) via the existing `SecretVault`
(`services/secret_vault.py`) broker, so those creds are vended per-call and never resident in
the agent. This makes the credential wedge MCPIP's **universal** non-bypass story — the
strongest non-bypass primitive MCPIP ships.

**2. Agent-side egress-lockdown template + "MCPIP is the only accepted client" reference (shipped).**
A hardened NetworkPolicy template for the *agent* namespace allowing egress **only** to MCPIP —
today's `k8s/networkpolicy.yaml` + `chart/templates/` lock the *gateway's* egress but not the
*agent's* reach; that asymmetry is the concrete gap. **Shipped:**
`k8s/agent-egress-lockdown.networkpolicy.yaml` — default-deny egress on the agent pods, allowing
only (a) cluster DNS and (b) the MCPIP gateway Service, with `<PLACEHOLDERS>` for the site's
agent namespace/labels; every rule commented and the closed asymmetry named. An optional
egress-proxy mode for `cloud_rest` that allowlists outbound tool HTTP stays deferred (not needed
once egress is default-deny to MCPIP only).

**3. "Compose behind Pomerium / Cloudflare Access / Istio" guides (shipped).**
MCPIP is the L7 authz + credential-vend + WORM brain; the ZTNA/mesh is the L3/L4 "can't reach
it" enforcer. Zero new network code, immediate enterprise credibility — the compose-don't-fight
posture. **Shipped:** the mesh reference below —
concrete Istio (SPIFFE mTLS `PeerAuthentication` + `AuthorizationPolicy` keyed on the gateway
SVID), Pomerium, and Cloudflare (Tunnel + Access) reference snippets, plus a single-host Docker
Compose overlay example.

**Full VPN / WireGuard overlay — DO NOT BUILD.** That's a different company
(Tailscale/Zscaler territory), a different ops burden, and it *dilutes* the deterministic-L7
authz moat. Even Pomerium, which markets "replace the VPN," is a reverse proxy, not an overlay.
The "layer on VPN" instinct is correctly *pointing at* non-bypassability — but the answer is the
credential wedge + egress lockdown + partner-mesh, not owning a tunnel.

### What buyers require to believe "every action goes through the gate"

1. **Egress lockdown** — the agent's network can reach only MCPIP (default-deny + allowlist).
2. **Target unreachability** — the real system rejects any caller that isn't MCPIP: mesh
   mTLS/SPIFFE, ZTNA tunnel, or **credential-broker-only access (no standing secret)**.
3. **Audience-bound / sender-constrained tokens** so a leaked token can't be replayed off-path
   (shipped — `auth/pop.py`, `require_sender_constraint`, boot-lint).
4. **Evidence the path can't be skipped** — SIEM shows 100% of calls through the gate (the WORM
   log + egress lockdown together).

MCPIP has strong answers to 2 and 3 today, and requirement 1 is now packaged:
`k8s/agent-egress-lockdown.networkpolicy.yaml` makes the agent's network reach only MCPIP, and
the mesh reference below is the "make MCPIP the only accepted client identity" reference
architecture (Istio/Pomerium/Cloudflare). What remains is genuinely the **operator's** job, not
a shipping gap: the templates carry `<PLACEHOLDERS>` for the site's trust domain, namespaces,
agent labels, and mesh/proxy credentials, and they enforce only once applied to a real cluster
with a NetworkPolicy-enforcing CNI (verified with an egress-deny smoke test).

### Verdict

The architecture is sound and differentiated — deterministic authorization belongs at L7, in an
independent gate, and every serious 2025–2026 design (Cisco, Cloudflare, Tetrate, Operant) pairs
a *network* enforcer with an *L7 authz brain* as **separate layers**. MCPIP is the brain, with
two primitives the network layer can't produce (opaque alias→target obfuscation and
write-before-execute WORM ordering). **Don't pivot to being a VPN.** Ship the credential-wedge
positioning + egress-lockdown reference + partner-mesh guides, and MCPIP has a complete,
defensible "every action goes through the gate" story for GA — with a stronger no-standing-key
primitive than most network-capture competitors.

---

## Deploying Behind a Service Mesh / Identity-Aware Proxy (Compose)

*The reference-architecture half of [Network Enforcement](#network-enforcement--non-bypassability)
(the egress-lockdown + "MCPIP is the only accepted client" moves). Companion to
`k8s/agent-egress-lockdown.networkpolicy.yaml` (the agent-side egress half) and the SPIFFE /
sender-constraint model in [`ARCHITECTURE.md`](../build/ARCHITECTURE.md).*

### Lead claim: "no standing key" first, mesh second

The strongest non-bypass primitive MCPIP ships needs **no mesh at all**: for the `cloud_iam`
transport the real target is unreachable without a **short-lived scoped credential MCPIP mints
per call** — there is no standing key resident in the agent to replay
(`services/cloud_broker.py` — "NO STANDING SECRETS AT REST"; the same wedge Aembit / HashiCorp
Vault+Boundary / Oasis sell). Prefer that primitive wherever a target can be fronted by a broker;
extend it to non-cloud targets (DB/SaaS/mainframe) via the existing `SecretVault`
(`services/secret_vault.py`) so those creds are vended per call and never live in the agent.

**Honest residual — why this guide exists.** For the *proxy* transports (`cloud_rest` /
`legacy_mainframe` / `grant_issue`) the real target IS a reachable host. There, MCPIP is an
app-layer authorizer the agent **chooses** to call: **without the network controls in this guide,
an agent could skip the gate and hit the target directly, and that direct call never appears in
the WORM log** — it voids the audit story, not just the authz. The fix is not to make MCPIP a VPN
(see [Network Enforcement — do-not-build](#the-three-enforcement-layers-ranked-by-effort--payoff--best-first)).
The fix is the **compose-don't-fight** posture:

> **MCPIP is the L7 authz + credential-vend + WORM brain. The mesh / identity-aware proxy is the
> L3/L4 "you can't reach it except as MCPIP" enforcer. Two layers, separate jobs — every serious
> 2025–2026 design (Cisco, Cloudflare, Tetrate, Operant) pairs a network enforcer with an L7 authz
> brain rather than collapsing them.**

Two independent teeth, deployed together, make "every action goes through the gate" true:

1. **Agent egress lockdown** — the agent's network can reach *only* MCPIP. Shipped as
   `k8s/agent-egress-lockdown.networkpolicy.yaml`; the mesh equivalents are below.
2. **Target unreachability** — the real system accepts *only MCPIP's identity* and rejects every
   other caller. That is the mesh AuthorizationPolicy / IdP-proxy policy work in this guide.

### The SPIFFE identity — reuse the workload-identity model, don't reinvent

MCPIP already **verifies** SPIFFE ([`ARCHITECTURE.md`](../build/ARCHITECTURE.md) describes the agent
presenting a SPIFFE SVID, among other attestations, to the org STS, which mints a short-lived
MCPIP-audience JWT whose `cnf.jkt` binds the agent's ephemeral key). This guide adds the **other
direction**: making MCPIP's *own* SPIFFE identity the **only** client identity the downstream
targets will accept.

- **Gateway identity.** In a mesh, the MCPIP gateway workload gets a SPIFFE ID from the mesh CA,
  e.g. `spiffe://<TRUST_DOMAIN>/ns/mcpip/sa/mcpip-gateway` (derived from its Kubernetes
  namespace+ServiceAccount — bind the gateway Deployment to a dedicated ServiceAccount so the ID
  is stable and unshared). This is a **mesh-issued workload identity**, distinct from the three
  Ed25519 roots MCPIP manages internally (release / license / WORM) and distinct from the agent's
  `cnf`-bound JWT identity. Don't conflate them: the mesh SVID authenticates *the gateway process
  to the target*; the JWT + DPoP authenticates *the agent to the gateway*.
- **The chain.** agent → (mTLS, agent SVID) → MCPIP → (L7 authz + vend + WORM) → (mTLS, **gateway
  SVID**) → target. The target's AuthorizationPolicy trusts exactly one source principal: MCPIP's
  gateway SVID. Any other client — including the agent trying to go direct — presents a different
  principal (or none) and is refused at L4/L7 by the mesh, before the target app runs.
- **Gateway egress must reach the target for the PROXY transports.** The `MCPIP → target` hop
  only exists for the inline-proxy transports (`cloud_rest` / `legacy_mainframe` / `grant_issue`),
  where MCPIP dispatches the call and holds the real target. The shipped `k8s/networkpolicy.yaml`
  locks the gateway's egress to Redis + DNS only (no phone-home); when you use a proxy transport
  you must ADD a narrow egress rule there for those specific target hosts/ports (mesh-mediated),
  and the mesh sidecar then presents the gateway SVID. The `cloud_iam` "no standing key" transport
  needs **no** gateway→target egress at all — MCPIP only vends a short-lived scoped credential and
  the target is reached out-of-band under the agent's own egress policy — which is why it is the
  strongest non-bypass posture.

Everything below is a **reference snippet**: real, apply-able shape with `<PLACEHOLDERS>` for
site-specific trust domains, hostnames, and namespaces. None of it is invented cluster state.

### 1. Istio — SPIFFE mTLS + AuthorizationPolicy ("MCPIP is the only accepted client")

Istio issues every workload a SPIFFE SVID off the mesh trust domain and can enforce STRICT mTLS +
identity-based authorization at the sidecar. Two objects on the **target's** namespace do the work.

**(a) Require mTLS on the target** — no plaintext bypass, every caller must present a mesh SVID:

```yaml
apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: target-require-mtls
  namespace: <TARGET_NAMESPACE>        # the namespace of the fronted cloud_rest/mainframe target
spec:
  mtls:
    mode: STRICT                        # reject any non-mTLS (plaintext) connection outright
```

**(b) Allow ONLY MCPIP's gateway identity** — the load-bearing rule. `principals` is matched
against the peer's verified SPIFFE ID from its client cert; a request from any other workload (or
the agent going direct) fails closed:

```yaml
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: target-allow-only-mcpip
  namespace: <TARGET_NAMESPACE>
spec:
  selector:
    matchLabels:
      app: <TARGET_APP_LABEL>          # the target workload these rules protect
  action: ALLOW                         # default-deny: with an ALLOW policy present, anything
                                        # not matched by a rule is denied by Istio.
  rules:
    - from:
        - source:
            principals:
              # The ONE accepted client identity: MCPIP's gateway SVID.
              # Format: <trust-domain>/ns/<namespace>/sa/<serviceaccount>.
              - "<TRUST_DOMAIN>/ns/mcpip/sa/mcpip-gateway"
```

Notes:
- Bind the gateway Deployment to a dedicated ServiceAccount (`serviceAccountName: mcpip-gateway`)
  so the SVID above is unique to MCPIP and not shared with a sidecar-injected neighbor.
- This is **L4/L7 identity** enforcement — it does not, and should not, inspect the agent's
  tool-call payload. Payload authorization stays MCPIP's job (opaque alias resolution + PIN +
  policy overlay); the mesh only answers "is the caller MCPIP?". Keep the layers separate.
- Pair with the agent-side egress lock: `k8s/agent-egress-lockdown.networkpolicy.yaml` stops the
  agent reaching the target's IP at all; the AuthorizationPolicy stops it even if it did. Belt and
  suspenders — either alone is weaker.

### 2. Pomerium — identity-aware reverse proxy in front of the target

Pomerium is a reverse proxy that makes the target reachable **only through Pomerium**, and
Pomerium forwards only requests carrying a verified identity. Front the real target with a
Pomerium route and authorize on MCPIP's service identity (a mesh SVID via SPIFFE, or a dedicated
mTLS client cert / service account you issue to the gateway).

```yaml
# Pomerium route: the target is published ONLY via this proxy; its own address
# is not routable by the agent (enforce that with the egress NetworkPolicy +
# putting the target on a private network Pomerium fronts).
routes:
  - from: https://target.internal.<YOUR_DOMAIN>     # the only address callers use
    to:   http://<TARGET_SERVICE>:<PORT>             # the real, otherwise-unreachable backend
    name: mcpip-fronted-target
    policy:
      - allow:
          and:
            # Accept ONLY MCPIP's gateway identity. With SPIFFE, match the SVID;
            # otherwise pin the gateway's client-cert SPKI / a dedicated SA claim.
            - spiffe_id:
                is: "spiffe://<TRUST_DOMAIN>/ns/mcpip/sa/mcpip-gateway"
    # Require the caller to present a client certificate (mutual TLS) — a bare
    # bearer request with no cert is rejected before policy eval.
    tls_downstream_client_ca_file: /etc/pomerium/mcpip-client-ca.pem
```

The MCPIP surface is unchanged: MCPIP still does alias→target obfuscation, PIN, policy, and
write-before-execute WORM at L7. Pomerium only guarantees the target has no route that isn't
MCPIP. Because the agent's egress is locked to MCPIP anyway, Pomerium here mainly hardens the
**target's** side (defence in depth + a clean audit choke point for the network team).

### 3. Cloudflare — Tunnel + Access ("no public route except as MCPIP")

Cloudflare's model is complementary: a `cloudflared` **Tunnel** gives the target **no inbound
public IP at all** (it dials out to Cloudflare; nothing can reach it directly), and **Access**
service-auth policies admit only a named service token / mTLS client identity — MCPIP's.

- **Tunnel (target has no listening public address).** Run `cloudflared` next to the target so the
  origin is reachable only over the tunnel — there is no direct route for an agent to hit:

  ```yaml
  # cloudflared config.yaml (runs alongside the target; the target binds localhost only)
  tunnel: <TUNNEL_UUID>
  credentials-file: /etc/cloudflared/<TUNNEL_UUID>.json
  ingress:
    - hostname: target.internal.<YOUR_DOMAIN>
      service: http://localhost:<TARGET_PORT>    # origin listens on loopback — no external route
    - service: http_status:404                    # default-deny any other hostname
  ```

- **Access service-token / mTLS policy (only MCPIP admitted).** Attach an Access application to
  that hostname whose policy `Allow` block includes **only** MCPIP's service token (or MCPIP's
  mTLS client cert). MCPIP presents the token/cert on its outbound proxy call; any other caller is
  bounced by Access before it reaches the origin. Mint the service token scoped to the MCPIP
  gateway workload and inject it the same fail-closed way secrets already reach the gateway
  (`scripts/deploy_hero.sh` materializes store-provided secrets 0600 onto tmpfs — put the
  Cloudflare service-token pair there, never in the image or the agent).

Framing stays identical: Cloudflare provides L3/L4 unreachability-except-as-MCPIP; MCPIP provides
the L7 authz + vend + WORM brain. Zero new MCPIP code.

### 4. Docker Compose — the "behind a proxy" example

The shipped `docker-compose.yml` is already **two-network by design**: `redis` is on an
`internal: true` network with no host port (unreachable from outside the compose project), and the
gateway straddles `mcpip-internal` + a bridge `mcpip-edge` that publishes ONLY 8080. That is the
gateway-side lock. Compose has **no built-in agent-egress or mesh-mTLS primitive** (those are
Kubernetes/mesh/Cloudflare features), so rather than mutate the hardened shipped file, here is the
documented overlay pattern for a single-host demo of the *mesh* posture — an identity-aware proxy
in front of a fronted target, with the target on an internal-only network:

```yaml
# docker-compose.mesh-example.yml  — illustrative overlay, adapt to your proxy.
# Goal: the `demo-target` has NO published port and lives on an internal network;
# the only ingress to it is the identity-aware proxy, which admits only MCPIP.
services:
  demo-target:
    image: <YOUR_TARGET_IMAGE>
    networks: [target-internal]        # internal: true below -> no host/agent route
    # NO `ports:` — deliberately unpublished; reachable only by co-attached proxy.

  identity-proxy:                       # Pomerium / Envoy / cloudflared, configured per §1–3
    image: <YOUR_IDENTITY_AWARE_PROXY_IMAGE>
    networks: [target-internal, mcpip-edge]
    volumes:
      - <YOUR_PROXY_POLICY>:/etc/proxy/policy:ro   # the "only MCPIP" policy from §1–3
    # Publishes the ONLY route to demo-target; enforces mTLS/SVID = mcpip-gateway.

networks:
  target-internal:
    driver: bridge
    internal: true                      # blocks host/egress routing to the target
  mcpip-edge:
    external: true                      # the gateway's existing edge network
```

For real multi-host or Kubernetes deployments, prefer the mesh/NetworkPolicy artifacts above —
Compose is a single-host demonstration surface, not the production enforcement plane.

### Deploy-together checklist

To honestly claim "every action goes through the gate" for a **proxy-transport** target, you need
BOTH teeth — either alone leaves a lane open:

1. **Agent egress locked to MCPIP** — `k8s/agent-egress-lockdown.networkpolicy.yaml` (or the mesh
   egress equivalent). The agent has no route to the target's IP.
2. **Target admits only MCPIP** — an Istio `AuthorizationPolicy` / Pomerium policy / Cloudflare
   Access policy keyed on the gateway's SPIFFE SVID (or mTLS client identity). Even a routing
   mistake can't turn into a bypass, because the target rejects a non-MCPIP principal.
3. **Sender-constrained tokens** so a leaked agent token can't be replayed off-path — already
   shipped (`auth/pop.py`, `require_sender_constraint`, boot-lint; provisioning in
   [`ARCHITECTURE.md`](../build/ARCHITECTURE.md)).
4. **The WORM log as the evidence** that the path wasn't skipped — 100% of calls appear in the
   tamper-evident ledger, which is true precisely *because* of teeth 1+2.

For a **`cloud_iam`** target you already have the strongest tooth (no standing key) without any of
this — but layering egress lockdown on top costs nothing and closes the residual "what else can
this agent reach" question for the whole namespace.

### Owner boundary — what these guides can NOT do for you

These snippets are correct shapes with `<PLACEHOLDERS>`; they become enforcing only when **you**
fill in real, site-specific values and apply them to **your** cluster/mesh. Specifically the
operator must: mint/attach MCPIP's gateway SPIFFE identity (dedicated ServiceAccount) or its mTLS
client cert; supply the real trust domain, target namespaces/hostnames, and agent pod labels;
install a NetworkPolicy-enforcing CNI and verify enforcement with an egress-deny smoke test; and
configure the chosen proxy (Istio/Pomerium/Cloudflare) with its real credentials. MCPIP ships no
mesh CA, no tunnel, and no cluster — by design (do-not-build-a-VPN).

---

## Operator Console & Desktop Packaging

The operator console (`dashboard/`, Vite + React + TS + Tailwind, lean 6-tab IA) ships three ways
from **one** codebase:

1. **Web portal** — `npm run build` → `dashboard/dist/`, served over HTTPS. The zero-install
   emergency-access fallback.
2. **Native desktop app** — a **Tauri v2** shell bundling the same `dist/` into `.dmg`/`.app`
   (macOS), `.msi` (Windows, WiX), `.deb` + `.AppImage` (Linux).
3. *(mobile is out of scope but the lib target leaves the door open.)*

The console runs entirely on **real gateway data** — offline renders honest empty states, no mock
data. It probes `/healthz`, drives real `/v1/authorize`, scrapes `/metrics` for real p50/p95, and
independently re-verifies WORM inclusion proofs in-browser. The **Deployment · License & Usage**
panel (Gateway → Updates & License) reads `GET /v1/admin/stats` for the real governed-agent count,
decision totals, license state, and the honest dark-feature posture (see
[Reading honest dark-feature posture](#reading-honest-dark-feature-posture)).

```bash
cd dashboard && npm install && npm run dev     # Vite dev server on :5173
npm run build                                  # tsc --noEmit && vite build → dashboard/dist
```

### Why Tauri (not Slint / cargo-packager)

- **Reuse, not rewrite.** The console is already a production React app. Tauri wraps it as-is;
  there is no second UI framework to maintain.
- **Minimal attack surface (Tier-1).** The Rust shell registers **no** plugins — no
  shell/fs/process/http. It renders the bundled frontend and nothing else; the frontend reaches
  the gateway itself over HTTPS/WSS. A native install grants an attacker no capability the browser
  didn't already have. Uses the OS WebView (no bundled Chromium).
- **Native multi-target bundler.** Tauri's own bundler emits every requested installer, so
  `cargo-packager`/`Packager.toml` is unnecessary for this stack.
- **Small, stripped binary.** `[profile.release]` uses `strip = true`, thin LTO,
  `opt-level = "s"`, `codegen-units = 1`, `panic = "abort"`.

### Layout

```
dashboard/
  src/…                     the React operator console (+ IAM & Knowledge-Graph views)
  dist/                     the built web bundle (frontend for BOTH web + desktop)
  src-tauri/
    Cargo.toml              Rust shell manifest + stripped release profile
    tauri.conf.json         product/window/bundle/security config (targets, CSP)
    capabilities/default.json  minimal permission set (core:default; no plugins)
    src/{main.rs,lib.rs}    inert shell entry point
    build.rs                tauri-build codegen
    app-icon.png            source ◐ mark (the platform icon set is generated, not committed)
```

### Build

Prereqs: Rust ≥ 1.77, Node 20, the Tauri system deps for your OS (macOS: Xcode CLT;
Windows: WiX + WebView2; Linux: `libwebkit2gtk-4.1-dev libgtk-3-dev librsvg2-dev patchelf`).

All build commands run from **`dashboard/`** (not the repo root — running there gives
`npm error Missing script`). Use the per-OS scripts below; they regenerate the platform
icon set first (an npm `pre` hook) so a stale icon can never ship, and they carry no
hand-typed `--target` (a stray character there is what produces `cargo: unexpected
argument`):

Run each line on its own. **Do not paste a trailing `#` comment into the shell** — macOS
zsh does not treat `#` as a comment by default, so it would be passed through `npm` → `tauri`
→ `cargo` and fail with `error: unexpected argument '#' found`.

```bash
cd dashboard
npm ci
npm run desktop:dev
```

Release build + bundle — each installer is produced **only** on its own OS:

| OS | Command | Emits |
|---|---|---|
| any (native single-arch) | `npm run desktop:build` | `…/release/bundle/…` for your OS |
| macOS (universal) | `npm run desktop:build:mac` | `…/bundle/dmg/*.dmg` + `…/bundle/macos/*.app` |
| Windows | `npm run desktop:build:win` | `…/bundle/msi/*.msi` (WiX) |
| Linux | `npm run desktop:build:linux` | `…/bundle/deb/*.deb` + `…/bundle/appimage/*.AppImage` |

macOS universal builds need both Rust targets once:
`rustup target add x86_64-apple-darwin aarch64-apple-darwin`. If you only want to *see*
the app on your own Mac, `npm run desktop:build` (native, no `--target`) is simplest and
always works.

Cross-platform CI that produces all of them: `.github/workflows/desktop-release.yml`
(matrix over `macos-latest` / `windows-latest` / `ubuntu-22.04`; trigger via
`workflow_dispatch` or a `desktop-v*` tag).

### Live data vs. honest empty state (no mock)

The console probes `GET /healthz` at the connected gateway every few seconds (default
`http://localhost:8080`; pin any endpoint at runtime via **Admin & Infrastructure →
Connection**, persisted — no rebuild):

- **A gateway answers → `live` mode**: every panel runs on **real gateway data** — Command
  Center, Decision Stream, WORM Ledger, Skills & Tools, Tenants, Knowledge Graph, Gateway
  Health. The probe flips within seconds of the gateway coming up.
- **No gateway → honest empty state**: panels show an explicit "no gateway connected"
  message with a **Connect** action — **nothing is fabricated** (the old mock-data mode was
  removed; the console never invents a catalog, stream, or metric it can't get from a real
  node).

The first launch of a fresh install shows the **setup flow** (Welcome → Connect → Company →
Workspace → Launch), which pins the gateway and writes the company config; re-run or wipe it
from **Company Settings → Danger zone** (Re-run setup / Delete profile) for a clean demo.

**IAM admin views act on the real gateway.** The console drives live, WORM-logged,
CAP_DIRECTORY_ADMIN-gated write APIs — directory persistence (`/v1/directory`), the skill
kill-switch and runtime skill registration (`/v1/admin/skills/*`), principal revocation
(`/v1/admin/principals/*`), and cloud-IAM environment bindings
(`/v1/admin/cloud/environments`). MCPIP stays **IdP-sovereign**: these endpoints persist
policy/metadata and DENY requests; they never mint a credential (real principals come from
`scripts/mint_principal.py`). A temporary grant runs the real `skill_compartment_grant`
step-up ceremony (Redis `GrantStore` TTL grant).

### The web fallback (the "Wasm" ask)

The console is already a web application, so the zero-install portal is simply the
standard build — `npm run build` → `dist/`, served over HTTPS. **No `wasm-pack` step is
needed**: `wasm-pack` only applies to compiling *Rust/Slint* UI to WebAssembly, which is
the path we did not take. Serving the same `dist/` the desktop app bundles guarantees the
web and desktop UIs are byte-identical.

### Security posture

- **CSP** (in `tauri.conf.json`): `default-src 'self'`; `connect-src` limited to `self`,
  `https:`, `wss:`, and the dev gateway; `object-src 'none'`; `frame-ancestors 'none'`;
  `base-uri 'self'`. No remote script origins.
- **Identical crypto to the web portal.** The gateway is remote; the shell adds no
  credential handling — token/mTLS to `/v1/authorize`, `/v1/mcp`, and the WSS stream are
  the frontend's job, unchanged between web and desktop.
- **No auto-updater / no remote code.** Releases are immutable, signed artifacts
  (mirror the gateway's supply-chain discipline — an upgrade is a redeploy).

### Checking for updates (notifier, never installer)

Console updates are **notifier-only** — MCPIP downloads and executes nothing. The
**Admin & Infrastructure → Updates & License** sub-tab surfaces a "Check for updates" flow, but
MCPIP is a Tier-1 zero-trust appliance, so it **notifies**, it never auto-installs. Nothing is
downloaded or executed; the panel just compares three honest signals and tells the operator when
a signed redeploy is due:

1. **This console build** — `__APP_VERSION__`, baked into the bundle at build time
   from `dashboard/package.json` (Vite `define`).
2. **The connected gateway** — the running release from the JWT-gated
   `GET /v1/version` (single-source `VERSION`).
3. **The signed release manifest** — provenance (`signing_key_id`, verified against
   the release-root key when configured), also from `/v1/version`.

Optionally, the gateway reports a newer approved release from a **signed update
feed** (`MCPIP_UPDATE_MANIFEST_PATH` → a `latest.json` the operator's change-control
drops in; no network call). Its Ed25519 signature is verified against the release-root
public key — an unverifiable feed is ignored. When the console build is ahead of the
gateway (the exact "you built the new DMG but haven't redeployed yet" case), the panel
flags a **redeploy-pending** state. Applying an update is always a redeploy of the
immutable, signed artifact (`update_policy: "redeploy"`) — the console shows *that a redeploy
is due*, never performs one.

### Bumping the desktop/console version

The console + desktop shell version is single-sourced across
`dashboard/package.json`, `dashboard/src-tauri/tauri.conf.json`, and
`dashboard/src-tauri/Cargo.toml`. Bump all three (they are `3.0.0` today), rebuild
(`npm run build` bakes the new `__APP_VERSION__`; `npm run desktop:build` re-bundles
the DMG/MSI/DEB), and redeploy the gateway to the matching signed `VERSION`. A DMG
built from an older tree keeps showing its own baked version until it is rebuilt.

---

## Multi-Region Topology & Data Residency

*The answer to "can MCPIP run region-pinned tenants with data residency?" Short answer: **yes as
a deployment topology today — one MCPIP + Redis stack per region — because every Redis key is
already tenant-prefixed; a cross-region control plane is deliberately DEFERRED.** Companion to
the internal roadmap ("keep every Redis key tenant-prefixed so multi-region stays an edge
concern"). This wave ships this design plus a **behavior-neutral `MCPIP_REGION` observability
tag** (`core/config.py`, surfaced read-only on `/healthz` + `/v1/version`); it changes NO routing,
authorization, key, or storage behavior.*

### TL;DR

- **Region pinning is a deployment shape, not new gateway code.** A region is a self-contained
  MCPIP stack (gateway workers + its own Redis + its own WORM anchor volume + its own signing
  keys). A tenant is "pinned" to a region by *where its traffic is routed*, not by any field this
  process stores.
- **Tenant-prefixed keys make it an edge concern.** Every synchronization datum — grants, payload
  locks, quarantine/revocation, policy docs, forensic captures, OTP stashes, relation tuples — is
  keyed `mcpip:<kind>:{tenant}:…`. A region is just a Redis (and WORM ledger) that holds a
  *subset* of tenants. There is no global key that must span regions.
- **The WORM ledger and its anchor are per-region and MUST stay per-region.** Each region owns an
  independent Ed25519-signed Merkle-epoch chain + out-of-domain anchor. There is **no cross-region
  chain** and this wave does not build one — chaining across regions would either weaken the
  durable-before-authorize guarantee or invent a new distributed durable substrate (explicitly out
  of scope, same boundary as the group-commit WORM wave).
- **What ships now:** this design + a read-only `MCPIP_REGION` tag. **What stays deferred:** an
  actual cross-region *control plane* (tenant→region directory, residency enforcement at the edge,
  cross-region WORM aggregation for a global auditor view, region failover/migration).

### 1. Topology: region = a self-contained cell

The unit of regional deployment is a **cell**: one complete MCPIP stack.

```
        ┌─────────────────────── region: us-east-1 ───────────────────────┐
        │  MCPIP gateway workers (MCPIP_REGION=us-east-1)                  │
        │      │                                                          │
        │      ├── Redis (AOF appendfsync=always)  ── grants, locks,      │
        │      │                                      quarantine, policy, │
        │      │                                      forensic, OTP, rel  │
        │      ├── WORM epoch chain (Ed25519 signing key #us-east-1)      │
        │      └── WORM anchor volume (out-of-tamper-domain, fsync'd)     │
        └──────────────────────────────────────────────────────────────────┘

        ┌─────────────────────── region: eu-frankfurt ────────────────────┐
        │  MCPIP gateway workers (MCPIP_REGION=eu-frankfurt)               │
        │      ├── Redis (independent)                                     │
        │      ├── WORM epoch chain (Ed25519 signing key #eu-frankfurt)    │
        │      └── WORM anchor volume (independent)                        │
        └──────────────────────────────────────────────────────────────────┘
```

Each cell is **the same image and the same code** — nothing in the authorization pipeline is
region-aware. The only differences are configuration (a distinct `MCPIP_REDIS_URL`, distinct
`MCPIP_WORM_SIGNING_KEY_PATH` / anchor volume, and the observability-only `MCPIP_REGION`) and
*which tenants' traffic reaches it*.

Because a tenant's entire state (`mcpip:*:{tenant}:*`) lives in exactly one cell's Redis, a tenant
is region-pinned the moment its callers are routed to that cell. No data leaves the region. There
is no shared write path across cells, so there is no cross-region consistency, replication, or
split-brain question to solve inside the process — it is genuinely an **edge routing concern**,
exactly as the internal roadmap claims.

#### Why tenant-prefixed keys are the whole argument

The invariant "every Redis key stays tenant-prefixed" (see [`ARCHITECTURE.md`](../build/ARCHITECTURE.md))
is what makes this trivial. A region holds a *partition of tenants*, and the partition is
expressed purely by which Redis the cell points at. Concretely, the tenant-scoped key families
are:

| Key family | Owner | Region-locality |
| --- | --- | --- |
| `mcpip:grant:{tenant}:{compartment}:{subject}` | `services/grant_store.py` | in-cell |
| `mcpip:pinlock:{tenant}:{lock_id}` | `auth/pin_validator.py` | in-cell |
| `mcpip:quarantine:{tenant}:{agent_id}` | `services/quarantine.py` | in-cell |
| `mcpip:otp:{tenant}:{challenge}` | `services/authn_channel.py` (sandbox) | in-cell |
| `mcpip:policy:doc:{tenant}` / `…:vel:{tenant}:…` | `services/policy_engine.py` | in-cell |
| `mcpip:forensic:{tenant}:{corr}` | `services/forensic_store.py` | in-cell |
| `mcpip:rel:{tenant}:{object}#{relation}@{subject}` | `services/relation_store.py` | in-cell |
| `mcpip:ext:pending|approved:{tenant}` | `services/extension_submissions.py` | in-cell |

None of these is global. A tenant that must live in `eu-frankfurt` has *all* of its rows in that
cell's Redis and nowhere else — that is data residency by construction (see
[Data residency posture](#3-data-residency-posture)).

### 2. The WORM ledger + anchor across regions

This is the load-bearing part of the design, and the part with the firmest boundary.

**Each region runs its own, fully independent WORM ledger.** Concretely, per cell:

- Its own monotonic sequence counter and epoch chain (`audit/worm_logger.py` — atomic INCR+XADD
  `emit`, root-chained Ed25519-signed Merkle epochs).
- Its own **signing key** (a distinct Ed25519 WORM key per region — never shared, so a per-region
  key compromise is contained to that region's ledger).
- Its own **out-of-domain anchor** (`audit/anchor.py`) on durable storage the region's Redis
  attacker cannot rewrite — the monotonic rollback low-watermark that lets `verify_chain` detect
  tail-truncation.

**There is deliberately NO cross-region chain.** The tamper-evidence guarantee is per-cell:
`verify_chain` proves *this region's* ledger is intact and un-rolled-back. It does **not** — and
in this wave must not — attempt to prove a global ordering across regions. Two reasons this
boundary is non-negotiable:

1. **Durability.** The production guarantee is that an authorized decision's event is fsync-durable
   *before any effect*, resting on Redis `appendfsync=always` (`assert_persistence_posture`). A
   cross-region chain would need each region's `emit` to also durably commit into a *shared*
   substrate before returning — i.e. a synchronous cross-region fsync on the hot path. That either
   destroys authorize latency or weakens durability. Neither is acceptable, and building a
   distributed durable substrate is exactly the "new durable substrate" change ruled out for the
   group-commit WORM wave. **This wave does not touch `audit/worm_logger.py`'s emit/durability
   path.**
2. **Blast radius.** Independent chains + independent keys + independent anchors mean a region is a
   clean audit boundary. An auditor verifies each region's chain on its own; there is no global
   root whose compromise or unavailability stalls every region.

#### The deferred piece: a global auditor view

A cross-region auditor who wants "one pane of glass" is served by **aggregating attestations, not
by chaining ledgers**. The read-only attestation endpoint already exists per region
(`GET /v1/audit/attestation` → `WormLogger.attestation`: latest sealed epoch header +
`signing_key_id` + a fresh `verify_chain` result + anchor watermark; it mints no key and signs
nothing new). A future control plane can *poll each region's attestation* and present the set —
each independently signature-verifiable — as a portfolio. That is an **additive, read-only
aggregation of already-signed commitments**, never a new chain and never a change to any region's
emit path. It is **not built in this wave** (auditor-facing framing in
[`COMPLIANCE.md`](COMPLIANCE.md)).

### 3. Data residency posture

The residency claim MCPIP can honestly make today is **residency-by-partition**:

- A tenant's *authorization state and its audit trail never leave the cell its traffic is routed
  to.* Grants, locks, quarantine/revocation, policy documents, forensic captures, OTP material,
  relation tuples, and every WORM event for that tenant are physically in one region's Redis + one
  region's WORM volumes. This holds by construction from the tenant-prefixed-key invariant — not
  from a residency feature bolted on top.
- **MCPIP holds no target payload content and vends, not proxies, for cloud** — so for the
  `cloud_iam` transport the *downstream data* never transits MCPIP at all (the agent makes the call
  with a vended short-lived credential; see
  [Network Enforcement](#network-enforcement--non-bypassability)). For the proxy transports
  (`cloud_rest`/`legacy_mainframe`), residency of the *downstream target* is a property of where
  that backend lives, which is outside MCPIP's control surface — MCPIP's own record of the call
  still stays in-region.

What residency-by-partition does **not** yet give you, and what a real residency *enforcement*
feature would add (all deferred, see [What stays deferred](#4-what-stays-deferred-explicitly-unbuilt)):

- **Edge enforcement that a `eu-*` tenant can never be served by a `us-*` cell.** Today that
  guarantee is operational — correct routing at the edge (per-region ingress, DNS/geo steering, or
  a tenant→region map in the load balancer). MCPIP does not *reject* a mis-routed tenant, because
  it has no authoritative tenant→region directory and (by the "region tag changes no behavior"
  rule) must not gain one this wave. A mis-routed tenant would simply have *empty* state in the
  wrong cell (no grants, no locks) and fail closed — safe, but not an explicit residency assertion.
- **A residency attestation** ("tenant T's data provably resided only in region R for period P").
  That requires the deferred cross-region control plane + the aggregated attestation view above.

### 4. What stays deferred (explicitly unbuilt)

Per the internal roadmap ("None of the deferred set should be built speculatively — they are
enterprise procurement features, built on demand"), the following are **design intent, not code**:

1. **A cross-region control plane.** An authoritative tenant→region directory, region-aware edge
   admission (reject/redirect a tenant that reaches the wrong cell), and a residency policy engine.
   This wave ships neither the directory nor any enforcement — routing stays an operational edge
   concern.
2. **Cross-region WORM aggregation for a global auditor.** The additive, read-only
   attestation-polling view described in [§2](#the-deferred-piece-a-global-auditor-view). No shared
   chain, ever.
3. **Region failover / tenant migration.** Moving a tenant's `mcpip:*:{tenant}:*` state (and its
   WORM history) from one cell to another, with a verifiable hand-off that preserves the audit
   chain's tamper-evidence. This is genuinely hard (the anchor low-watermark and epoch chain are
   per-cell) and is not attempted here.
4. **Any change to the durable substrate.** The WORM emit/durability path
   (`audit/worm_logger.py`) is untouched. Multi-region does not weaken, reorder, or distribute
   `appendfsync=always` durability.

### 5. What this wave actually ships (scaffold, not behavior)

- **`MCPIP_REGION` — a behavior-neutral observability tag.** `core/config.py` adds
  `region: str | None = None` (env `MCPIP_REGION`). It is a free-form operator string (e.g.
  `us-east-1`, `eu-frankfurt`, `gov-cloud`) surfaced **read-only** on `/healthz` (`"region": …`)
  and `/v1/version` (`"region": …`) for console/SDK display and log correlation.
  - It is **never** consulted for routing, authorization, Redis key derivation, or storage. Grep
    for `settings.region` — it appears only in those two read-only response bodies.
  - It is deliberately **NOT a metric label**: a free-form operator string would violate the
    closed-enum label discipline in `core/metrics.py` (no tenant/agent/free-form value may ever be
    a label). Region correlation for metrics is done the standard way — via an external/relabel
    label applied by the scraper per deployment, not by this process.
  - **Boot is byte-for-byte unchanged when it is unset.** `None` is the honest "no region
    configured" state; the field defaults to `None` and no code branches on it, so an existing
    deployment behaves exactly as before.

A cross-region control plane stays **deferred** (an owner decision). This is the same "scaffold the
seam, defer the engine" discipline the repo already uses for `PolicyProvider`,
`BaseAuthenticatorChannel`, and the ReBAC relation projection: ship the honest, observable label
now so the future control plane is additive, not a rewrite — and be explicit that the control plane
itself is unbuilt.
