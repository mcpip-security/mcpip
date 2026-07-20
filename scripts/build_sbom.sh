#!/usr/bin/env bash
# MCPIP SBOM generation (CycloneDX JSON).
#
# Environment mode captures the fully-resolved pinned set installed in .venv —
# the same set the image venv installs — falling back to requirements mode if
# environment mode is unavailable. The SBOM is hashed + listed in the signed
# release manifest, so it is signed transitively.
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
TMP="$OUT.tmp"
mkdir -p "$OUT_DIR"

if "$CDX" environment "$VENV/bin/python" --output-format JSON --output-file "$TMP"; then
    :
else
    echo "environment mode unavailable — falling back to requirements mode" >&2
    "$CDX" requirements "$REPO_ROOT/requirements.txt" --output-format JSON --output-file "$TMP"
fi

mv "$TMP" "$OUT"
echo "SBOM written: $OUT"
