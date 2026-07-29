# ◐ MCPIP — Release Ceremony Runbook

**Audience:** the release engineer cutting a signed, verifiable MCPIP release, and the
customer verifying a deploy. Every command is copy-paste runnable from the repository
root and references only files that ship in this repository.

**What a release IS:** a set of SHA-256 artifact digests signed with an **offline
Ed25519 release-root key**, plus a signed **source integrity manifest** the gateway
re-hashes at every boot. There is **no updater** — MCPIP never pulls code, never patches
itself. Upgrading is the operator's change-control action: verify a new signed release,
pin its image digest, redeploy.

**The three roots, never conflated** (`scripts/gen_release_keys.py` mints the first two;
the third is the operator's existing WORM key):

| Root | Signs | Lives |
|---|---|---|
| **release-root** | release manifest + integrity manifest | offline signer / HSM; dev copy in gitignored `.keys/release_root_ed25519.pem` |
| **license-root** | entitlement/license files | offline signer; dev copy in `.keys/license_root_ed25519.pem` |
| **audit epoch** | WORM epoch chain (`MCPIP_WORM_SIGNING_KEY_PATH`) | operator-supplied; untouched by this ceremony |

Private key material lives ONLY in `.keys/` (gitignored — `.gitignore` excludes `.keys/`
and all `*.pem`/`*.key`) and NEVER enters the image. Only the **public** PEMs and
`release/keys/rotation.json` are committed and shipped (`.gitignore` re-includes
`!release/keys/*.pub.pem`).

> **The real 2.x roots are the OWNER's offline keys.** `gen_release_keys.py` writes
> DEMO/DEV roots. The production release-root and license-root keys are generated and
> held on an air-gapped signer (HSM / offline laptop); every signing script accepts
> `--private-key <path>` so the identical tooling runs there. **Cutting the real signed
> release requires those offline keys — it is an owner action and cannot be performed
> from this repo checkout.**

---

## 0. The 3.0.0 GA cut (this release)

`VERSION` is `3.0.0` — the General-Availability milestone. Two notes for the engineer
running this ceremony:

- **Semver nuance (a deliberate choice, not a breaking-change claim).** Every wave since
  `2.1.0` was strictly ADDITIVE and backward-compatible: default-OFF opt-ins, new
  endpoints, and audit-only identity fields. The authorization hot path, the payload lock
  (`canonical_json` / `enforce_argument_safety` / scrypt PIN-hash / Rust mirror), the WORM
  epoch-header signed bytes, and the `{EdDSA, RS256}` alg gate are byte-for-byte unchanged.
  By strict SemVer that is a MINOR bump (`2.2.0`); the owner has deliberately chosen `3.0.0`
  as the GA milestone. There is **no** removed/renamed API and **no** breaking change — the
  major-version number is a product-milestone decision, mirrored in `CHANGELOG.md`.
- **The in-tree signed manifests legitimately LAG `VERSION` until the owner's offline
  re-sign.** After bumping `VERSION` to `3.0.0`, every `get_version()`-derived surface
  (`/healthz`, `/v1/version` `running`, MCP `serverInfo`, the compliance-evidence
  `gateway_version`, `mcpip version`) reconciles immediately with zero code edits. But
  `release/manifest.json` + `release/integrity_manifest.json` + `release/manifest.sig` +
  the `release/sbom/mcpip-<version>.cdx.json` are produced and SIGNED only on the owner's
  air-gapped signer (§1 steps 3–4, §5). Those files stay at the last owner-signed version
  (`2.0.0`) in-tree until that offline cut, so `/v1/version` `release.version` reconciles to
  `3.0.0` **only after** the owner re-signs. This is the honest boundary — never hand-fake a
  signature/digest and never commit an unsigned/ephemeral manifest as if it were the signed
  release (the release + integrity checks in `tests/test_authorize_api.py` compare
  `release.version` to the SHIPPED manifest, never to `get_version()`, precisely because of
  this lag).

---

## 1. Ceremony order

Run from the repo root, in this exact order. `<version>` is whatever the `VERSION` file
holds (strict `MAJOR.MINOR.PATCH`) — bump `VERSION` **first**, in the same commit as the
`CHANGELOG.md` release section and the lockstep version stamps (`deploy/chart/Chart.yaml`
`version`/`appVersion`, README version badge, the `mcpip-gateway:<version>` image tag
example in `deploy/k8s/deployment.yaml`).

```bash
# 0) ONE-TIME (per keyset): mint the two offline roots.
#    Private -> .keys/ (gitignored, 0600); public -> release/keys/ (committed).
#    For a REAL release, skip this and pass the owner's offline --private-key instead.
./.venv/bin/python scripts/gen_release_keys.py

# 1) Build the wheel + sdist -> dist/
./.venv/bin/python -m build

# 2) CycloneDX SBOM of the resolved pinned set -> release/sbom/mcpip-<version>.cdx.json
bash scripts/build_sbom.sh

# 3) Sign the release manifest over the artifact digests (offline release-root key)
#    -> release/manifest.json  +  release/manifest.sig
./.venv/bin/python scripts/sign_release.py \
  --version <version> \
  --private-key .keys/release_root_ed25519.pem \
  --artifact dist/mcpip-<version>-py3-none-any.whl \
  --artifact dist/mcpip-<version>.tar.gz \
  --artifact release/sbom/mcpip-<version>.cdx.json

# 4) Sign the boot-integrity manifest — THE LAST SOURCE-TOUCHING STEP BEFORE docker build.
#    Hashes the normative shipped source set (see below) as it will ship.
#    -> release/integrity_manifest.json
./.venv/bin/python scripts/gen_integrity_manifest.py \
  --private-key .keys/release_root_ed25519.pem

# 5) Generate the SLSA v1 / in-toto provenance predicate over the SAME artifact
#    digests sign_release just signed (subjects taken verbatim from manifest.json;
#    materials = the pinned git commit + requirements*.txt + VERSION).
#    --builder-id is the OWNER's real build-platform identity — it is never
#    defaulted or fabricated. Writes to release/ only (outside the hashed source
#    set), so it does not perturb step 4.  -> release/provenance.intoto.json
#    This tool SIGNS NOTHING — cosign attestation is the owner offline-key step below.
./.venv/bin/python scripts/gen_slsa_provenance.py \
  --manifest release/manifest.json \
  --builder-id "<owner build-platform identity URI — see step 5b below>"

# 5b) OWNER ACTION (offline cosign key — NOT runnable from a normal checkout):
#     attest the artifacts with the provenance predicate. See §6.
#       cosign attest-blob --key <offline-cosign.key> \
#         --type slsaprovenance1 \
#         --predicate release/provenance.intoto.json \
#         dist/mcpip-<version>-py3-none-any.whl   # (repeat per subject)
#     Do NOT commit a fabricated signature or the generated predicate.

# 6) Build the image and record the immutable digest for deploy pinning.
docker build -t mcpip-gateway:<version> .
docker images --digests mcpip-gateway

# 7) (optional) Deterministic offline air-gap bundle -> dist/mcpip-airgap-<version>.tar.gz
bash scripts/build_bundle.sh <version>
```

**Why step 4 is last.** `gen_integrity_manifest.py` hashes every `*.py` under
`app/ core/ auth/ audit/ bridge/ services/ models/ obfuscator/ mcpip_verify/`
(excluding `__pycache__`) plus `interfaces.py`, `main.py`, and `VERSION`. Verified boot
(`core/integrity.py`) re-hashes exactly that set read-only at startup and **refuses to
boot** on any mismatch. If any source file changes after step 4, the manifest is stale
and the image will not boot — so it must run **after** every source edit and immediately
before `docker build`. Steps 1–3 and step 5 (provenance) write only to `dist/` and
`release/` (outside the hashed set), so they do not perturb the source hash; step 5 runs
after step 4 because it references the integrity manifest as a byproduct.

---

## 2. What each step produces, and where

| Artifact | Path | Committed? | Signed by |
|---|---|---|---|
| Offline root PRIVATE keys | `.keys/release_root_ed25519.pem`, `.keys/license_root_ed25519.pem` | **NO** (gitignored) | — |
| Root PUBLIC keys | `release/keys/release_root_ed25519.pub.pem`, `release/keys/license_root_ed25519.pub.pem` | yes | — |
| Key rotation manifest | `release/keys/rotation.json` | yes | — |
| Wheel + sdist | `dist/mcpip-<version>-py3-none-any.whl`, `dist/mcpip-<version>.tar.gz` | no (`dist/` gitignored) | release manifest (transitively) |
| SBOM (CycloneDX) | `release/sbom/mcpip-<version>.cdx.json` | yes | release manifest (transitively) |
| Release manifest + signature | `release/manifest.json`, `release/manifest.sig` | yes | **release-root** |
| Boot integrity manifest | `release/integrity_manifest.json` | yes | **release-root** |
| SLSA provenance predicate | `release/provenance.intoto.json` | **no** (gitignored) | **owner cosign key**, offline (§6) |
| Air-gap bundle | `dist/mcpip-airgap-<version>.tar.gz` | no | (packs the signed manifest) |

The release + integrity manifests share one normative signing rule (also implemented in
`core/integrity.py` and the `mcpip verify` CLI): drop the `signature` key, then
`json.dumps(obj, sort_keys=True, separators=(",", ":"))` UTF-8, raw 64-byte Ed25519,
base64-encoded.

---

## 3. Verified boot — how the running gateway proves itself

The gateway wires the integrity check via two env vars (both required in production;
`sandbox_mode=False` boot without them **fails closed**):

```bash
MCPIP_INTEGRITY_MANIFEST_PATH=release/integrity_manifest.json
MCPIP_INTEGRITY_PUBLIC_KEY_PATH=release/keys/release_root_ed25519.pub.pem
```

At boot, before a socket is ever bound, `core/integrity.py`:

1. loads and Ed25519-verifies the manifest against the release-root public key;
2. stream-hashes every listed source file under the base dir;
3. `hmac.compare_digest`s each against the signed value.

Any unreadable/malformed manifest, bad signature, missing file, or hash mismatch raises
the **opaque** `RuntimeError("integrity verification failed")` — the specific cause is
logged CRITICAL to `mcpip.boot` only, never surfaced. There is **no remediation, no
self-heal, no self-update**. The dev-only `MCPIP_INTEGRITY_DEV_BYPASS` is structurally
refused on a production boot; the Dockerfile, Helm chart, and k8s manifests never expose
it.

---

## 4. How a customer verifies a deploy by signed digest

Verification is pure local cryptography — no network, no TLS dependency.

```bash
# 1) Confirm the release public-key fingerprint against your out-of-band copy
#    (the key id printed by the signer, e.g. ed25519:<16 hex>).

# 2) Verify the release manifest + every listed artifact on disk:
./.venv/bin/python -m mcpip_verify.cli verify \
  --manifest release/manifest.json \
  --pubkey release/keys/release_root_ed25519.pub.pem \
  --base-dir .
# success -> "verified: mcpip <version> (N artifacts)", exit 0
# any failure -> "verification failed" (opaque), exit 2

# 3) Air-gap bundle path (verifies the packed manifest before unpacking):
./.venv/bin/python -m mcpip_verify.cli verify bundle dist/mcpip-airgap-<version>.tar.gz \
  --pubkey release/keys/release_root_ed25519.pub.pem
```

**Deploy by image digest, never by tag.** Pin the immutable
`mcpip-gateway@sha256:<hex>` digest recorded from step 6 into `deploy/k8s/deployment.yaml` /
`deploy/chart/values.yaml`; the `:<version>` tag is a human label only. The running gateway
then re-proves its own source set at every boot (§3), so a digest-pinned deploy is
end-to-end verifiable: signed artifacts → signed source → self-checking boot.

---

## 5. The honest boundary — real vs self-test signing

- **Self-test (any engineer, ephemeral keys):** `gen_release_keys.py` mints throwaway
  roots into `.keys/`, and the ceremony proves the *tooling* works end-to-end (see the
  differential in `tests/test_release_tooling.py` / `tests/test_release_hooks.py`).
  Self-test outputs are NOT the release — never commit `.keys/`, ephemeral
  `release/manifest.json`, or an ephemeral `release/integrity_manifest.json`.
- **The real signed release:** requires the **owner's offline release-root and
  license-root keys**. Run the identical scripts on the air-gapped signer with
  `--private-key <offline path>`, then commit only the resulting public metadata and the
  signed `release/manifest.json` + `release/manifest.sig` + `release/integrity_manifest.json`.
  This step **cannot** be performed from a normal repo checkout and is deliberately left
  to the owner.

---

## Homebrew stable stanza (tag-time fill-in — never a fabricated digest)

`packaging/homebrew/mcpip.rb` is a real, valid virtualenv formula. It works
**today** from git (`brew install --HEAD mcpip/tap/mcpip`) with no published
release. Its **stable** `url` + `sha256` are a **documented placeholder** — the
`sha256` is 64 zeros marked `RELEASE-FILL-IN`, deliberately NOT a fabricated
digest. Fill it in at tag time, from the REAL published tarball only:

```bash
# After `python -m build` (ceremony step 1) publishes the mcpip-sdk sdist to PyPI:
VERSION=$(cat VERSION)
# Compute the digest from the REAL tarball (either freshly built or fetched):
shasum -a 256 dist/mcpip_sdk-${VERSION}.tar.gz          # local build, OR
brew fetch --build-from-source packaging/homebrew/mcpip.rb  # after url points at PyPI

# Paste the true 64-hex digest + version into packaging/homebrew/mcpip.rb:
#   url     "https://files.pythonhosted.org/.../mcpip_sdk-${VERSION}.tar.gz"
#   sha256  "<the real digest>"
#   version "${VERSION}"
# Then verify and audit before pushing to the tap:
brew style packaging/homebrew/mcpip.rb
brew audit --new --formula packaging/homebrew/mcpip.rb
```

The httpx `resource` blocks in the formula carry REAL PyPI sdist digests
(generated the way `brew update-python-resources` would). Regenerate them with
`brew update-python-resources packaging/homebrew/mcpip.rb` whenever the httpx pin
moves. **Never** commit a fabricated `sha256` or claim `brew install mcpip` works
from a tap that is not yet published — the `--HEAD` path is the honest
today-state; the stable tap goes live only once the sdist and tap repo exist.

---

## 6. SLSA provenance + cosign attestation (owner action)

`scripts/gen_slsa_provenance.py` (ceremony step 5) emits an **in-toto Statement**
(`https://in-toto.io/Statement/v1`) carrying a **SLSA v1 provenance predicate**
(`https://slsa.dev/provenance/v1`). It is a description of *how* the release was built,
bound to *what* was built:

- **`subject`** — the release artifacts (name + SHA-256), copied **verbatim** from the
  digests `sign_release.py` already computed and signed in `release/manifest.json`. The
  generator never re-hashes or re-derives a digest, so the provenance can never disagree
  with the signed release.
- **`predicate.buildDefinition.resolvedDependencies`** — the pinned inputs (the git
  source commit when a repo is present, `requirements.txt`, `requirements-dev.txt`,
  `VERSION`), each hashed from disk. A missing input is a fail-closed error.
- **`predicate.runDetails`** — the `builder.id`, the invocation metadata (git commit +
  the release-manifest / generation timestamps), and the ceremony byproducts (the signed
  release + integrity manifests, by digest).

**The generator SIGNS NOTHING.** Like release-root and license-root signing, provenance
attestation uses the **owner's offline key** — here a **cosign** key held on the
air-gapped signer. The generated predicate is **gitignored and never committed**; the
attestation is produced offline and published to the transparency log / OCI registry the
owner controls:

```bash
# OWNER, offline signer — attest each artifact subject with the predicate:
cosign attest-blob \
  --key <offline-cosign.key> \
  --type slsaprovenance1 \
  --predicate release/provenance.intoto.json \
  --bundle release/mcpip-<version>-<artifact>.cosign.bundle \
  dist/mcpip-<version>-py3-none-any.whl
# repeat per subject (sdist, SBOM); verify with:
cosign verify-blob-attestation --key <cosign.pub> --type slsaprovenance1 \
  --bundle release/mcpip-<version>-<artifact>.cosign.bundle <artifact>
```

**Never fabricate a cosign signature or commit signed provenance from a normal checkout.**
Self-test (any engineer) runs the *generator* end-to-end against the current
`release/manifest.json` to prove the predicate is well-formed JSON; it does **not**
attest.

**`BUILD_SCHEMA` — owner decision (required before the first attested release).** Two
provenance fields name identities the owner must pin to real, published values, because
MCPIP will never invent them:

- **`builder.id`** (`--builder-id`, a **required** argument — the generator refuses to run
  without it): the URI of the owner's build platform / offline signer identity
  (e.g. `https://github.com/<org>/<repo>/.github/workflows/release.yml@refs/tags/v<x>`,
  or a stable offline-signer id). This is what a downstream SLSA verifier trusts.
- **`buildType`** (`--build-type`, defaults to
  `https://mcpip.dev/slsa/buildtypes/release-ceremony/v1`): the schema tag naming the
  *shape* of this ceremony. Override it to a URI the owner publishes if they document
  their build process externally.

Decide and register both once; thereafter pass the canonical `--builder-id` on every
release cut.

---

## 7. The public distribution package (`mcpip-security/mcpip`)

The working repository carries maintainer material the public repository must not:
the strategy, roadmap, pricing, narrative-deck, competitive-review and
managed-cloud documents, plus the agent context lake and its instruction file.
The exact held-back set is declared at the top of the builder and restated in
every package it produces. The public cut is produced by that builder, never by
hand:

```bash
python scripts/build_production_package.py            # -> dist/mcpip-<version>-production.zip + sha256
python scripts/build_production_package.py --check    # verify only, writes nothing
python scripts/build_production_package.py --keep-tree  # leave dist/mcpip-<version>/ to inspect
```

**What it does.** Stages an *allowlisted* copy of the tree (product source, tests,
SDKs, console, deploy manifests, operator/security/compliance docs, the policy
set, `release/` with its public verification keys), holds back the internal
material, rewrites every citation of a held-back document into plain prose, drops
the declared pointer lines and sections, normalizes the repository slug to
`mcpip-security/mcpip`, and writes `PACKAGE_MANIFEST.json` (per-file SHA-256,
source commit, and the exclusion list stated openly).

**What it guarantees, by failing rather than degrading.**

| Guarantee | Failure mode it prevents |
|---|---|
| Allowlist, not denylist | A new top-level file silently shipping because an ignore rule was not updated. It is held back and printed as `NOT ALLOWLISTED`. |
| Zero mentions of held-back material | A public document citing a file the reader cannot open. |
| Every relative Markdown link resolves in-package | Broken navigation in the published docs. |
| Each declared rewrite anchor matches exactly one line | A half-edited sentence shipping after upstream prose moved. The build stops and names the anchor. |
| Deterministic archive (sorted order, fixed timestamps) | An unreviewable package hash. The same tree always produces the same ZIP. |
| Private key material pruned; `release/keys/*.pub.pem` deliberately kept | Shipping a `.pem`/`.key` that should never leave the signer. |

**The working tree is never mutated** — the builder stages a copy. A red build
means "update the rewrite table in the script", not "the packager is broken".

This step is independent of the signing ceremony above: package *after* the
release artifacts are signed, so the public cut carries the current signed
`release/manifest.json`.
