#!/usr/bin/env bash
# MCPIP SBOM generation (CycloneDX JSON).
#
# Describes the RUNTIME dependency closure — what the image actually contains —
# by resolving requirements.txt into a throwaway virtualenv exactly the way the
# Dockerfile builder stage does, and inventorying that. It deliberately does NOT
# inventory the development .venv: that carries pytest, mypy, bandit, the SBOM
# generator itself and the opt-in Rust accelerator, none of which are installed
# in the image. An SBOM of the dev environment overstates the shipped attack
# surface, and a CVE scan against it triages findings for packages that are not
# there while saying nothing about the ones that are.
#
# The SBOM is hashed + listed in the signed release manifest, so it is signed
# transitively.
#
# Offline CVE scan (inside the enclave, DB mirrored out-of-band):
#   grype sbom:release/sbom/mcpip-<version>.cdx.json
#   trivy sbom release/sbom/mcpip-<version>.cdx.json --skip-db-update
# MCPIP itself never phones home.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

VERSION="$(tr -d '[:space:]' < VERSION)"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "VERSION file missing or malformed" >&2
    exit 1
fi

VENV="$REPO_ROOT/.venv"
CDX="$VENV/bin/cyclonedx-py"
if [[ ! -x "$CDX" ]]; then
    echo "cyclonedx-py not found in $VENV — install requirements-dev.txt first" >&2
    exit 1
fi

OUT_DIR="$REPO_ROOT/release/sbom"
OUT="$OUT_DIR/mcpip-$VERSION.cdx.json"
mkdir -p "$OUT_DIR"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Where the runtime closure comes from.
#
# Default: resolve requirements.txt into a clean venv, mirroring Dockerfile stage 1
# — no dev extras, no editable local packages. This needs an index, so it does NOT
# work on an air-gapped signer.
#
# MCPIP_SBOM_RUNTIME_VENV: inventory an existing runtime venv instead. On the
# offline signer, point it at /opt/venv copied out of the built image — which is
# not merely a workaround but the more accurate source, since it is the venv that
# actually ships rather than a re-resolution of the same requirements.
if [[ -n "${MCPIP_SBOM_RUNTIME_VENV:-}" ]]; then
    RUNTIME_VENV="$MCPIP_SBOM_RUNTIME_VENV"
    if [[ ! -x "$RUNTIME_VENV/bin/python" ]]; then
        echo "MCPIP_SBOM_RUNTIME_VENV=$RUNTIME_VENV has no bin/python" >&2
        exit 1
    fi
    echo "inventorying runtime venv: $RUNTIME_VENV (no network)"
else
    RUNTIME_VENV="$WORK/runtime"
    echo "resolving runtime closure (requirements.txt) into a clean venv..."
    "$VENV/bin/python" -m venv "$RUNTIME_VENV"
    "$RUNTIME_VENV/bin/python" -m pip install --quiet --disable-pip-version-check \
        --require-virtualenv -r "$REPO_ROOT/requirements.txt"
fi

"$CDX" environment "$RUNTIME_VENV/bin/python" \
    --output-format JSON --output-file "$WORK/raw.cdx.json"

# Stamp the root component and refuse to emit an SBOM that leaks a build path.
"$VENV/bin/python" "$REPO_ROOT/scripts/sbom_finalize.py" \
    --input "$WORK/raw.cdx.json" --output "$OUT" --version "$VERSION"

echo "SBOM written: $OUT"
