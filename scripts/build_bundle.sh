#!/usr/bin/env bash
# MCPIP offline air-gap bundle builder.
#
#   scripts/build_bundle.sh 2.0.0
#   scripts/build_bundle.sh 2.0.0 --image mcpip-gateway:2.0.0
#   MCPIP_IMAGE=mcpip-gateway:2.0.0 scripts/build_bundle.sh 2.0.0 --sign-key .keys/release_root_ed25519.pem
#
# Assembles dist/mcpip-airgap-<version>.tar.gz — a self-contained INSTALL medium
# (not merely a verification package): the signed release manifest, detached
# signature, PUBLIC keys (release-root AND license-root) + rotation manifest, the
# source artifacts, an optional loadable container image tar, a vendored runtime
# wheelhouse, the deploy assets (deploy/chart/ + deploy/k8s/ + deploy/redis.conf), the SBOM,
# SHA256SUMS, and the offline install+boot runbook. Verification inside the
# enclave needs NO network — trust anchors on the out-of-band public-key
# fingerprint. Every source artifact is re-verified against the SIGNED manifest
# BEFORE packing (fail-closed).
#
# Capability-gated, opt-in extras (the script still SUCCEEDS if the tool is
# absent — it prints a clear note and falls back):
#   * docker  + an image ref (env MCPIP_IMAGE or --image REF) -> `docker save`
#     a gzip'd image tar into artifacts/ so the enclave `docker load`s it
#     directly (the primary install path). With --sign-key / MCPIP_RELEASE_
#     SIGNING_KEY (the OFFLINE release-root PRIVATE key) the image digest is
#     folded into the re-signed manifest so verify_bundle's SIGNATURE check
#     covers it; without a key it is covered by the bundle-wide SHA256SUMS only.
#   * pip -> a vendored wheelhouse (artifacts/wheels/) so the verifier's
#     `cryptography` + the runtime deps install with `pip install --no-index`.
#
# No runtime updates exist: operators redeploy through change control.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# ---- 0. Arguments: positional <version>, plus opt-in --image / --sign-key.
#     Env fallbacks: MCPIP_IMAGE, MCPIP_RELEASE_SIGNING_KEY.
VERSION=""
IMAGE="${MCPIP_IMAGE:-}"
SIGN_KEY="${MCPIP_RELEASE_SIGNING_KEY:-}"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)     IMAGE="${2:-}"; shift 2 ;;
        --image=*)   IMAGE="${1#*=}"; shift ;;
        --sign-key)  SIGN_KEY="${2:-}"; shift 2 ;;
        --sign-key=*) SIGN_KEY="${1#*=}"; shift ;;
        -h|--help)
            echo "usage: scripts/build_bundle.sh <version> [--image REF] [--sign-key PATH]" >&2
            exit 0 ;;
        -*) echo "unknown option: $1" >&2; exit 1 ;;
        *)  if [[ -z "$VERSION" ]]; then VERSION="$1"; shift
            else echo "unexpected argument: $1" >&2; exit 1; fi ;;
    esac
done

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "usage: scripts/build_bundle.sh <version> [--image REF] [--sign-key PATH]   (e.g. 2.0.0)" >&2
    exit 1
fi

# Prefer the repo venv, but do not REQUIRE it. The air-gap tab documents this as
# the first command an Administer-track reader runs, and that reader has not been
# told to create a venv — hardcoding the path made the script die on a clean
# clone with a bare "no such file or directory" that named neither cause nor fix.
PY="$REPO_ROOT/.venv/bin/python"
if [[ ! -x "$PY" ]]; then
    PY="$(command -v python3 || command -v python || true)"
    if [[ -z "$PY" ]]; then
        echo "no python found — install Python 3.10+, or create the repo venv:" >&2
        echo "  python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt" >&2
        exit 1
    fi
    echo "note: $REPO_ROOT/.venv not found — using $PY" >&2
fi
MANIFEST="$REPO_ROOT/release/manifest.json"
SIG="$REPO_ROOT/release/manifest.sig"
PUBKEY="$REPO_ROOT/release/keys/release_root_ed25519.pub.pem"
LICENSE_PUBKEY="$REPO_ROOT/release/keys/license_root_ed25519.pub.pem"
ROTATION="$REPO_ROOT/release/keys/rotation.json"

for f in "$MANIFEST" "$SIG" "$PUBKEY" "$ROTATION"; do
    if [[ ! -f "$f" ]]; then
        echo "missing release input: $f" >&2
        exit 1
    fi
done

# ---- 1. Fail-closed pre-check: signature + every artifact hash must verify.
"$PY" -m mcpip_verify.cli verify \
    --manifest "$MANIFEST" \
    --pubkey "$PUBKEY" \
    --base-dir "$REPO_ROOT"

# ---- 2. Stage the bundle layout.
BUNDLE_NAME="mcpip-airgap-$VERSION"
STAGE="$REPO_ROOT/dist/$BUNDLE_NAME"
rm -rf "$STAGE"
mkdir -p "$STAGE/keys" "$STAGE/artifacts" "$STAGE/artifacts/wheels" "$STAGE/sbom" "$STAGE/deploy"

cp "$MANIFEST" "$STAGE/manifest.json"
cp "$SIG" "$STAGE/manifest.sig"
cp "$PUBKEY" "$STAGE/keys/release_root_ed25519.pub.pem"
cp "$ROTATION" "$STAGE/keys/rotation.json"

# The license root signs the entitlement/license files; ship its PUBLIC half so
# MCPIP_LICENSE_PUBLIC_KEY_PATH is satisfiable in-enclave (distinct root from the
# release root — never conflate the two).
if [[ -f "$LICENSE_PUBKEY" ]]; then
    cp "$LICENSE_PUBKEY" "$STAGE/keys/license_root_ed25519.pub.pem"
else
    echo "NOTE: $LICENSE_PUBKEY absent — license-root pubkey not bundled (the license" >&2
    echo "      gate will be unverifiable in-enclave until it is provided out-of-band)." >&2
fi

# Copy every manifest-listed artifact: SBOMs -> sbom/, the rest -> artifacts/.
while IFS=$'\t' read -r rel name; do
    src="$REPO_ROOT/$rel"
    if [[ ! -f "$src" ]]; then
        echo "artifact listed in manifest but missing on disk: $rel" >&2
        exit 1
    fi
    case "$name" in
        *.cdx.json) cp "$src" "$STAGE/sbom/$name" ;;
        *)          cp "$src" "$STAGE/artifacts/$name" ;;
    esac
done < <("$PY" - "$MANIFEST" <<'PYEOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    manifest = json.load(fh)
for entry in manifest["artifacts"]:
    print(f"{entry['path']}\t{entry['name']}")
PYEOF
)

# ---- 2b. Deploy assets so the operator can stand the gateway + durable Redis up
#     in the enclave (the appendfsync=always / noeviction Redis StatefulSet, the
#     Helm chart, and the raw redis.conf). Copied under deploy/.
for d in chart k8s; do
    if [[ -d "$REPO_ROOT/deploy/$d" ]]; then
        rm -rf "$STAGE/deploy/$d"
        cp -R "$REPO_ROOT/deploy/$d" "$STAGE/deploy/$d"
    else
        echo "NOTE: deploy/$d/ absent — not bundled under deploy/." >&2
    fi
done
if [[ -f "$REPO_ROOT/deploy/redis.conf" ]]; then
    cp "$REPO_ROOT/deploy/redis.conf" "$STAGE/deploy/redis.conf"
else
    echo "NOTE: deploy/redis.conf absent — durable-Redis profile not bundled under deploy/." >&2
fi

# ---- 3. Container image: `docker save` into a loadable tar when possible.
#     Opt-in on an image ref (MCPIP_IMAGE / --image) AND docker being available.
IMAGE_TAR_NAME="mcpip-gateway-$VERSION-image.tar.gz"
IMAGE_TAR="$STAGE/artifacts/$IMAGE_TAR_NAME"
IMAGE_VENDORED=0
if [[ -n "$IMAGE" ]]; then
    if command -v docker >/dev/null 2>&1; then
        if docker image inspect "$IMAGE" >/dev/null 2>&1; then
            echo "staging image: docker save '$IMAGE' -> artifacts/$IMAGE_TAR_NAME"
            # -n: reproducible gzip (no name/mtime in the header).
            docker save "$IMAGE" | gzip -n > "$IMAGE_TAR"
            IMAGE_VENDORED=1
        else
            echo "NOTE: image '$IMAGE' not present locally (docker image inspect failed);" >&2
            echo "      build/pull it first (docker build -t '$IMAGE' .) or omit --image to" >&2
            echo "      ship the rebuild recipe. Shipping the recipe fallback for now." >&2
        fi
    else
        echo "NOTE: docker not available — cannot 'docker save' the image; shipping the" >&2
        echo "      rebuild recipe fallback instead of a loadable image tar." >&2
    fi
else
    echo "NOTE: no image ref (MCPIP_IMAGE / --image) provided; shipping the rebuild recipe." >&2
fi

# When a loadable image was staged AND the offline release-root PRIVATE key is
# supplied, fold the image digest into the manifest and RE-SIGN, so verify_bundle
# roots the install medium in the Ed25519 release signature (not just SHA256SUMS).
# The image tar lives FLAT in artifacts/ precisely so verify_bundle can locate it
# (it resolves manifest entries only under artifacts/ or sbom/, never a subdir).
if [[ "$IMAGE_VENDORED" -eq 1 ]]; then
    if [[ -n "$SIGN_KEY" && -f "$SIGN_KEY" ]]; then
        echo "re-signing bundle manifest to include the image (release-root key: $SIGN_KEY)"
        "$PY" - \
            "$STAGE/manifest.json" \
            "$STAGE/manifest.sig" \
            "$SIGN_KEY" \
            "$STAGE/keys/release_root_ed25519.pub.pem" \
            "$IMAGE_TAR" \
            "$IMAGE_TAR_NAME" \
            "$IMAGE" <<'PYEOF'
import base64, hashlib, json, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

(
    manifest_path,
    sig_path,
    key_path,
    pubkey_path,
    image_path,
    image_name,
    image_ref,
) = sys.argv[1:8]

with open(manifest_path, encoding="utf-8") as fh:
    manifest = json.load(fh)

# Streaming sha256 + size of the image tar.
digest = hashlib.sha256()
size = 0
with open(image_path, "rb") as fh:
    while True:
        chunk = fh.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)

artifacts = manifest.setdefault("artifacts", [])
if not any(isinstance(a, dict) and a.get("name") == image_name for a in artifacts):
    entry = {
        "name": image_name,
        "path": f"artifacts/{image_name}",
        "sha256": digest.hexdigest(),
        "size_bytes": size,
    }
    if image_ref:
        entry["image_ref"] = image_ref
    artifacts.append(entry)

# Load the offline release-root private key and re-sign the canonical bytes.
key = serialization.load_pem_private_key(open(key_path, "rb").read(), password=None)
if not isinstance(key, Ed25519PrivateKey):
    print("release signing key is not Ed25519", file=sys.stderr)
    raise SystemExit(1)

# Keep signing_key_id honest w.r.t. the key that actually signed.
raw_pub = key.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)
manifest["signing_key_id"] = "ed25519:" + hashlib.sha256(raw_pub).hexdigest()[:16]

# Canonical signing rule (byte-identical to sign_release.py / verifier.py):
# drop "signature", sort_keys, compact separators, UTF-8; raw 64-byte Ed25519.
unsigned = {k: v for k, v in manifest.items() if k != "signature"}
message = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
signature = key.sign(message)
manifest["signature"] = base64.b64encode(signature).decode("ascii")

# Fail closed unless the freshly re-signed manifest verifies against the BUNDLED
# public trust anchor (catches a wrong / mismatched --sign-key immediately).
pub = serialization.load_pem_public_key(open(pubkey_path, "rb").read())
if not isinstance(pub, Ed25519PublicKey):
    print("bundled public key is not Ed25519", file=sys.stderr)
    raise SystemExit(1)
pub.verify(signature, message)  # raises InvalidSignature -> nonzero exit -> abort

with open(manifest_path, "w", encoding="utf-8") as fh:
    fh.write(json.dumps(manifest, indent=2) + "\n")
with open(sig_path, "wb") as fh:
    fh.write(base64.b64encode(signature) + b"\n")
print(f"  manifest re-signed: +{image_name} ({size} bytes)")
PYEOF
    else
        echo "NOTE: image staged but no --sign-key / MCPIP_RELEASE_SIGNING_KEY given —" >&2
        echo "      the image tar is covered by the bundle SHA256SUMS but NOT by the" >&2
        echo "      offline Ed25519 signature. Re-run on the offline signer with" >&2
        echo "      --sign-key <release-root private PEM> to root it in the signature." >&2
    fi
fi

# Ship the exact rebuild recipe whenever no loadable image was staged.
if [[ "$IMAGE_VENDORED" -ne 1 ]]; then
    {
        echo "# MCPIP $VERSION — image build recipe (image tar not bundled)"
        echo
        echo "Rebuild the gateway image from the verified source release:"
        echo
        echo '```'
        echo "# 1. Verify the source artifacts first (see INSTALL.md), then:"
        echo "tar -xzf artifacts/mcpip-$VERSION.tar.gz"
        echo "cd mcpip-$VERSION"
        echo "docker build -t mcpip-gateway:$VERSION ."
        echo '```'
        echo
        echo "Expected source artifact digests (from the SIGNED manifest.json):"
        echo
        "$PY" - "$STAGE/manifest.json" <<'PYEOF'
import json, sys
with open(sys.argv[1], encoding="utf-8") as fh:
    manifest = json.load(fh)
for entry in manifest["artifacts"]:
    print(f"    sha256:{entry['sha256']}  {entry['name']}")
PYEOF
        echo
        echo "Deploy the built image BY DIGEST through change control. MCPIP has"
        echo "no runtime self-update: any post-deploy change to the shipped source"
        echo "set makes verified boot fail closed."
    } > "$STAGE/artifacts/BUILD_RECIPE.md"
fi

# ---- 3b. Runtime wheelhouse: vendor the pinned deps so `pip install --no-index`
#     works offline (the verifier itself needs `cryptography`). Best-effort — a
#     failed download keeps the (empty) dir + a note; the script still succeeds.
WHEELS_DIR="$STAGE/artifacts/wheels"
if command -v pip >/dev/null 2>&1; then PIP_BIN="pip"
elif command -v pip3 >/dev/null 2>&1; then PIP_BIN="pip3"
else PIP_BIN=""; fi

if [[ -n "$PIP_BIN" && -f "$REPO_ROOT/requirements.txt" ]]; then
    echo "vendoring runtime wheelhouse -> artifacts/wheels/ (from requirements.txt)"
    if "$PIP_BIN" download -r "$REPO_ROOT/requirements.txt" --dest "$WHEELS_DIR" 1>&2; then
        # Convenience digest list for `pip install --require-hashes` / manual audit.
        ( cd "$WHEELS_DIR"
          shopt -s nullglob
          files=( *.whl *.tar.gz )
          if [[ ${#files[@]} -gt 0 ]]; then
              for f in "${files[@]}"; do
                  "$PY" -c 'import hashlib,sys
h=hashlib.sha256()
with open(sys.argv[1],"rb") as fh:
    for b in iter(lambda: fh.read(1048576), b""):
        h.update(b)
print(f"{h.hexdigest()}  {sys.argv[1]}")' "$f"
              done > wheels.sha256
          fi
        )
    else
        echo "NOTE: 'pip download' could not resolve the runtime set (no source/network" >&2
        echo "      at build time). artifacts/wheels/ is present but EMPTY — populate it" >&2
        echo "      on a networked host (pip download -r requirements.txt -d wheels/) or" >&2
        echo "      provide cryptography + the runtime deps to the enclave out-of-band." >&2
        {
            echo "# MCPIP $VERSION — runtime wheelhouse (NOT populated at build time)"
            echo
            echo "'pip download' could not resolve the pinned runtime set when this bundle"
            echo "was built. Populate this directory on a networked host BEFORE air-gap"
            echo "delivery so the offline enclave can 'pip install --no-index':"
            echo
            echo '```'
            echo "pip download -r requirements.txt --dest artifacts/wheels/"
            echo "# (add --platform / --python-version / --only-binary=:all: to target the"
            echo "#  enclave's exact interpreter + OS/arch if it differs from this host)"
            echo '```'
        } > "$WHEELS_DIR/README.md"
    fi
else
    echo "NOTE: pip not available (or requirements.txt missing) — artifacts/wheels/ left" >&2
    echo "      empty; the enclave must obtain cryptography + the runtime deps otherwise." >&2
    {
        echo "# MCPIP $VERSION — runtime wheelhouse (empty)"
        echo
        echo "This build host had no pip; the wheelhouse was not vendored. Populate it"
        echo "on a networked host so the offline enclave can 'pip install --no-index':"
        echo
        echo '```'
        echo "pip download -r requirements.txt --dest artifacts/wheels/"
        echo '```'
    } > "$WHEELS_DIR/README.md"
fi

# ---- 4. INSTALL.md — offline verify + install + provision/boot runbook.
FPR="$("$PY" - "$PUBKEY" <<'PYEOF'
import hashlib, sys
from cryptography.hazmat.primitives import serialization
with open(sys.argv[1], "rb") as fh:
    key = serialization.load_pem_public_key(fh.read())
raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
print("ed25519:" + hashlib.sha256(raw).hexdigest()[:16])
PYEOF
)"

# Written from a QUOTED heredoc (nothing shell-expands inside) with two build-time
# values interpolated afterwards, so backticks / $ / env-var names in the runbook
# stay literal.
cat > "$STAGE/INSTALL.md" <<'INSTEOF'
# MCPIP __VERSION__ — offline (air-gap) install runbook

Everything needed to VERIFY, INSTALL, and BOOT this release is inside this
bundle. NO network is required at any step. Trust anchors on the release public
key, which you MUST check against the fingerprint you received out-of-band (a
separate channel from this bundle).

Bundle layout:

    manifest.json / manifest.sig   signed release manifest + detached signature
    keys/                          release-root + license-root PUBLIC keys, rotation.json
    artifacts/                     source sdist+wheel, SBOM's sibling, the image tar (if bundled)
    artifacts/wheels/              vendored runtime wheelhouse (pip --no-index)
    sbom/                          CycloneDX SBOM (offline CVE scan)
    deploy/                        chart/ (Helm) + k8s/ + redis.conf (durable Redis)
    SHA256SUMS                     digest of EVERY bundled file (defense in depth)

## 1. Verify the public key fingerprint (out-of-band trust anchor)

    python3 - keys/release_root_ed25519.pub.pem <<'EOF'
    import hashlib, sys
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_public_key(open(sys.argv[1], "rb").read())
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    print("ed25519:" + hashlib.sha256(raw).hexdigest()[:16])
    EOF

Expected fingerprint for this release: `__FPR__`
If it does not match your out-of-band copy, STOP — do not deploy.
Key rotation status is in `keys/rotation.json`; only `"status": "active"` keys
are acceptable.

## 2. Verify the bundle (signature + every artifact digest + SHA256SUMS)

Two different packages both ship a `mcpip` entrypoint, so invoke the verifier
UNAMBIGUOUSLY as a module (never a bare `mcpip verify bundle`):

    python -m mcpip_verify.cli verify bundle mcpip-airgap-__VERSION__.tar.gz \
        --pubkey keys/release_root_ed25519.pub.pem

Exit 0 and `verified: mcpip __VERSION__ (...)` = good. ANY other outcome is a
hard stop (the tool is deliberately opaque about why — fail closed).

What verify_bundle covers: the Ed25519-signed manifest (embedded + detached
`manifest.sig`) over the source artifacts and — when this bundle was re-signed on
the offline signer — the container image tar; AND `SHA256SUMS` over EVERY bundled
file, including `artifacts/wheels/` and `deploy/`. The SIGNED manifest is
authoritative; `SHA256SUMS` is breadth (it covers the whole tree but is not
itself signed). To root the image in the signature, the bundle must be built with
`--sign-key` on the offline release-root signer.

## 3. Install the runtime

PRIMARY — load the bundled image (no registry, no rebuild):

    docker load < artifacts/mcpip-gateway-__VERSION__-image.tar.gz
    docker images --digests mcpip-gateway

Pin that digest in your Kubernetes manifests / Helm values (`image.digest`) —
never deploy by mutable tag.

FALLBACK — if no image tar is bundled, rebuild it from the verified sdist per
`artifacts/BUILD_RECIPE.md`, then deploy BY DIGEST.

Verifier + runtime Python deps come from the vendored wheelhouse (no PyPI):

    python -m venv .venv && . .venv/bin/activate
    pip install --no-index --find-links artifacts/wheels \
        artifacts/mcpip-__VERSION__-py3-none-any.whl
    # (installs cryptography etc. from artifacts/wheels/ — offline)

If `artifacts/wheels/` is empty, see `artifacts/wheels/README.md`: it was not
resolvable at build time and must be populated from a networked host (or the deps
supplied out-of-band) before the enclave can `pip install --no-index`.

## 4. Provision & boot

MCPIP is fail-closed at boot: in production (`MCPIP_SANDBOX_MODE=false`) it
REFUSES to start unless every required key, the license, the integrity manifest,
and durable Redis are all in place. Provision in this order.

### 4a. License (MCPIP_LICENSE_PATH) + license-root pubkey

Place the signed license JSON and point the gateway at it plus the bundled
license-root public key (a DISTINCT root from the release root):

    export MCPIP_LICENSE_PATH=/etc/mcpip/license.json
    export MCPIP_LICENSE_PUBLIC_KEY_PATH=/etc/mcpip/license_root_ed25519.pub.pem
    # copy keys/license_root_ed25519.pub.pem from this bundle to that path

The license is minted offline by the owner (`scripts/gen_license.py --customer …
--tier …`, signed with the license-root PRIVATE key). Both path vars are REQUIRED
in production; the license gates BOOT only (never the per-request hot path).

### 4b. JWT IdP pubkey + WORM signing-key ceremony

Run the gateway key ceremony ONCE to mint the two Product-side Ed25519 keys
(`scripts/provision_gateway_keys.py`). Private halves are written 0600 to the
gitignored `.keys/`; only the public halves reach the gateway:

    python scripts/provision_gateway_keys.py
    #   worm_signing_ed25519.key   (PRIVATE) -> MCPIP_WORM_SIGNING_KEY_PATH
    #   idp_signing_ed25519.pub.pem (PUBLIC) -> MCPIP_JWT_PUBLIC_KEY_PATH

    export MCPIP_WORM_SIGNING_KEY_PATH=/run/secrets/mcpip/worm_signing_ed25519.key
    export MCPIP_JWT_PUBLIC_KEY_PATH=/run/secrets/mcpip/idp_signing_ed25519.pub.pem

The gateway NEVER holds the IdP PRIVATE key — identity is verify-only. Mint agent
principal JWTs on the IdP/minting host with `scripts/mint_principal.py --idp-key
idp_signing_ed25519.key --tenant … --agent … --issuer <MCPIP_JWT_ISSUER>
--audience <MCPIP_JWT_AUDIENCE>` (the `iss`/`aud` MUST match the two boot vars
below; `role` authorizes nothing — entitlements are capability UUIDs).

### 4c. Verified-boot integrity manifest + pubkey

    export MCPIP_INTEGRITY_MANIFEST_PATH=/etc/mcpip/integrity_manifest.json
    export MCPIP_INTEGRITY_PUBLIC_KEY_PATH=/etc/mcpip/release_root_ed25519.pub.pem
    export MCPIP_INTEGRITY_DEV_BYPASS=false      # MUST be false in production

Use the bundled `keys/release_root_ed25519.pub.pem` for the integrity pubkey and
the signed `integrity_manifest.json` from the release. The gateway re-hashes the
shipped source set at every boot and refuses to run on any mismatch.

### 4d. Durable `appendfsync always` Redis (write-before-execute)

The WORM audit emit must be fsync-durable BEFORE an allow returns, and the replay
guard requires no eviction. Stand Redis up from the bundled deploy assets:

    kubectl apply -f deploy/k8s/redis-configmap.yaml -f deploy/k8s/redis-statefulset.yaml
    # or: helm install mcpip deploy/chart --set … (chart mirrors k8s/)
    # raw profile: deploy/redis.conf (appendonly yes / appendfsync always / noeviction)

Then CONFIRM the live posture (production boot asserts this and fails closed if
it is not met):

    redis-cli CONFIG GET appendfsync       # expect: appendfsync always
    redis-cli CONFIG GET maxmemory-policy  # expect: maxmemory-policy noeviction

The AOF must sit on a DURABLE volume (never tmpfs).

### 4e. The MCPIP_* boot environment

Copy `deploy/.env.production.example` from the release and fill in the paths. The full
production boot set (all `MCPIP_`-prefixed; the six starred are REQUIRED in
production — a missing one fails boot closed):

    MCPIP_SANDBOX_MODE=false                    # never true in production
    MCPIP_REDIS_URL=redis://mcpip-redis.internal:6379/0
    MCPIP_REDIS_MAX_CONNECTIONS=64
    MCPIP_JWT_ISSUER=<your-idp>                 # must equal the token iss
    MCPIP_JWT_AUDIENCE=<your-gateway-aud>       # must equal the token aud
    MCPIP_JWT_PUBLIC_KEY_PATH=…                 # * (4b)
    MCPIP_WORM_PATH=/var/lib/mcpip/mcpip_worm.jsonl
    MCPIP_WORM_ANCHOR_PATH=/var/lib/mcpip/mcpip_worm.jsonl.anchor
    MCPIP_WORM_SIGNING_KEY_PATH=…               # * (4b)
    MCPIP_INTEGRITY_MANIFEST_PATH=…             # * (4c)
    MCPIP_INTEGRITY_PUBLIC_KEY_PATH=…           # * (4c)
    MCPIP_INTEGRITY_DEV_BYPASS=false
    MCPIP_LICENSE_PATH=…                        # * (4a)
    MCPIP_LICENSE_PUBLIC_KEY_PATH=…             # * (4a)
    MCPIP_API_HOST=0.0.0.0
    MCPIP_API_PORT=8080

Step-up OTP delivery (REQUIRED only if any skill is PIN_REQUIRED — set BOTH or
neither; exactly one is a fail-closed boot error):

    MCPIP_AUTHN_WEBHOOK_URL=https://…           # https, non-private host
    MCPIP_AUTHN_WEBHOOK_SECRET_PATH=…           # >=32 raw bytes, 0600
    MCPIP_AUTHN_WEBHOOK_TIMEOUT_S=5.0

Secret MATERIAL (private keys, the license, the webhook secret) is injected at
deploy time from your secret store into the referenced paths — never baked into
the image, never committed.

## 5. Offline CVE scan (SBOM)

Mirror a vulnerability DB into the enclave out-of-band, then:

    grype sbom:sbom/mcpip-__VERSION__.cdx.json          # grype db import <db.tar.gz> first
    trivy sbom sbom/mcpip-__VERSION__.cdx.json --skip-db-update

## 6. Operational invariants

- **No runtime updates.** MCPIP never self-updates, never pulls code, never
  mutates its own files. Verified boot re-hashes the shipped source set on
  every start and refuses to run on any mismatch.
- Redeployments go through your change-control process: verify a new bundle,
  load, pin the new digest, roll.
- The release signing key, the license signing key, and the audit
  epoch-signing key are three separate Ed25519 roots.
INSTEOF

# Interpolate the two build-time values into the quoted runbook.
"$PY" - "$STAGE/INSTALL.md" "$VERSION" "$FPR" <<'PYEOF'
import pathlib, sys
path, version, fpr = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(path)
text = p.read_text(encoding="utf-8").replace("__VERSION__", version).replace("__FPR__", fpr)
p.write_text(text, encoding="utf-8")
PYEOF

# ---- 5. SHA256SUMS over every staged file (relative paths, sorted).
(
    cd "$STAGE"
    find . -type f ! -name SHA256SUMS | sed 's|^\./||' | sort | while read -r rel; do
        "$PY" -c 'import hashlib,sys;h=hashlib.sha256();fh=open(sys.argv[1],"rb")
while True:
    b=fh.read(1048576)
    if not b: break
    h.update(b)
print(f"{h.hexdigest()}  {sys.argv[1]}")' "$rel"
    done > SHA256SUMS
)

# ---- 6. Deterministic tarball (ustar, name-sorted; GNU tar and bsdtar).
OUT="$REPO_ROOT/dist/$BUNDLE_NAME.tar.gz"
rm -f "$OUT"
if tar --version 2>/dev/null | grep -q "GNU tar"; then
    tar --format=ustar --sort=name -czf "$OUT" -C "$REPO_ROOT/dist" "$BUNDLE_NAME"
else
    (
        cd "$REPO_ROOT/dist"
        find "$BUNDLE_NAME" -type f | sort | tar --format=ustar -czf "$OUT" -T -
    )
fi

echo "bundle written: $OUT"
echo "verify with: python -m mcpip_verify.cli verify bundle $OUT --pubkey release/keys/release_root_ed25519.pub.pem"
