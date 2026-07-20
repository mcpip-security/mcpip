#!/usr/bin/env bash
# =============================================================================
# ◐ MCPIP — Hero production deploy: secure credential injection + fail-closed boot
# =============================================================================
# Zero-trust secret injection for CI/CD. Secret MATERIAL arrives ONLY as env vars
# populated by the pipeline's secret store (GitHub Actions secrets / Vault / KMS /
# k8s Secret) — NEVER hardcoded, NEVER committed. This script materializes each into
# a 0600 file on a tmpfs, points the gateway's MCPIP_*_PATH vars at it, scrubs the
# in-memory copies, then execs the gateway. Non-sensitive config + paths come from
# .env.production (see .env.production.example).
#
# Required secret env vars (injected by the secret store, masked in logs):
#   MCPIP_WORM_SIGNING_KEY_PEM   - Ed25519 PKCS8 PEM (WORM epoch signer, PRIVATE)
#   MCPIP_JWT_PUBLIC_KEY_PEM     - IdP SubjectPublicKeyInfo PEM (identity, PUBLIC)
#   MCPIP_LICENSE_JSON           - the signed license document
# Optional (recommended): MCPIP_REDIS_URL may itself be a secret (embedded auth).
#
# Shipped NON-SECRET assets are staged AUTOMATICALLY (step 5) from THIS checkout's
# release/ dir to the /etc/mcpip/* paths .env.production points at — the operator does
# NOT hand-copy them:
#   release/integrity_manifest.json            -> MCPIP_INTEGRITY_MANIFEST_PATH
#   release/keys/release_root_ed25519.pub.pem  -> MCPIP_INTEGRITY_PUBLIC_KEY_PATH
#   release/keys/license_root_ed25519.pub.pem  -> MCPIP_LICENSE_PUBLIC_KEY_PATH
#
# Companion — a DURABLE Redis (appendonly yes / appendfsync always) MUST be reachable
# before boot, or the gateway's persistence-posture gate fails closed. This script does
# NOT start Redis; bring up the bundled durable service first:
#   docker compose -f docker-compose.prod.yml up -d redis
#
# Usage (in the pipeline, AFTER secrets are exported):
#   docker compose -f docker-compose.prod.yml up -d redis   # durable Redis companion
#   set -a; . ./.env.production; set +a      # non-secret config + paths
#   scripts/deploy_hero.sh
# =============================================================================
set -euo pipefail
umask 077                       # every file this script creates is owner-only.

log()  { printf '[deploy-hero] %s\n' "$*" >&2; }         # NEVER pass secret bytes here.
die()  { printf '[deploy-hero] FATAL: %s\n' "$*" >&2; exit 1; }

# Resolve this script's own checkout so the shipped release/ assets can be staged
# (step 5) regardless of the caller's working directory.
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
release_dir="$(cd "$script_dir/.." && pwd)/release"

# --- 0) Refuse to deploy anything but a fail-closed production posture. -------
[ "${MCPIP_SANDBOX_MODE:-false}" = "false" ] || die "MCPIP_SANDBOX_MODE must be false in production"

# --- 1) The paths the gateway reads (from .env.production; NOT secrets). ------
: "${MCPIP_WORM_SIGNING_KEY_PATH:?set MCPIP_WORM_SIGNING_KEY_PATH (see .env.production)}"
: "${MCPIP_JWT_PUBLIC_KEY_PATH:?set MCPIP_JWT_PUBLIC_KEY_PATH}"
: "${MCPIP_LICENSE_PATH:?set MCPIP_LICENSE_PATH}"
: "${MCPIP_LICENSE_PUBLIC_KEY_PATH:?set MCPIP_LICENSE_PUBLIC_KEY_PATH}"
: "${MCPIP_INTEGRITY_MANIFEST_PATH:?set MCPIP_INTEGRITY_MANIFEST_PATH}"
: "${MCPIP_INTEGRITY_PUBLIC_KEY_PATH:?set MCPIP_INTEGRITY_PUBLIC_KEY_PATH}"

# --- 2) The secret material (from the secret store; MUST be present). ---------
: "${MCPIP_WORM_SIGNING_KEY_PEM:?WORM signing key not injected by the secret store}"
: "${MCPIP_JWT_PUBLIC_KEY_PEM:?IdP public key not injected by the secret store}"
: "${MCPIP_LICENSE_JSON:?license not injected by the secret store}"

# --- 3) Materialize secrets 0600 onto a tmpfs (never the image, never git). ---
secret_dir="$(dirname "$MCPIP_WORM_SIGNING_KEY_PATH")"
mkdir -p "$secret_dir"
# On Linux, prefer a tmpfs mount for the secret dir (RAM-backed, never persisted):
#   mount -t tmpfs -o size=1m,mode=0700 tmpfs "$secret_dir"   # (done by the orchestrator)

write_secret() {  # $1=target path  $2=env var name holding the material
  local target="$1" var="$2"
  ( set +x; printf '%s' "${!var}" > "$target" )   # no trace, no echo of the bytes
  chmod 0600 "$target"
  [ -s "$target" ] || die "materialized secret $target is empty"
}
write_secret "$MCPIP_WORM_SIGNING_KEY_PATH" MCPIP_WORM_SIGNING_KEY_PEM
write_secret "$MCPIP_JWT_PUBLIC_KEY_PATH"   MCPIP_JWT_PUBLIC_KEY_PEM
write_secret "$MCPIP_LICENSE_PATH"          MCPIP_LICENSE_JSON

# --- 4) Scrub the in-memory secret copies before the gateway inherits the env. -
unset MCPIP_WORM_SIGNING_KEY_PEM MCPIP_JWT_PUBLIC_KEY_PEM MCPIP_LICENSE_JSON

# --- 5) Stage the shipped NON-SECRET assets (integrity manifest + the license-root
#        and release-root PUBLIC keys) from THIS checkout's release/ dir to the
#        /etc/mcpip/* paths .env.production points at. They ship with the release and
#        are NOT injected by the secret store; without this step the step-6 sanity
#        check (and verified boot) hard-fails. Idempotent — installs a fresh 0644 copy.
place_public() {  # $1=source under release/  $2=destination path
  local src="$1" dest="$2"
  [ -s "$src" ] || die "release asset missing from checkout: $src (run from a full MCPIP release tree)"
  mkdir -p "$(dirname "$dest")"
  install -m 0644 "$src" "$dest"                 # public, world-readable, non-secret
  [ -s "$dest" ] || die "failed to stage public asset at $dest"
}
place_public "$release_dir/integrity_manifest.json"           "$MCPIP_INTEGRITY_MANIFEST_PATH"
place_public "$release_dir/keys/release_root_ed25519.pub.pem" "$MCPIP_INTEGRITY_PUBLIC_KEY_PATH"
place_public "$release_dir/keys/license_root_ed25519.pub.pem" "$MCPIP_LICENSE_PUBLIC_KEY_PATH"

# --- 6) Sanity: every required path must now exist non-empty (fail-closed). ---
for f in "$MCPIP_WORM_SIGNING_KEY_PATH" "$MCPIP_JWT_PUBLIC_KEY_PATH" "$MCPIP_LICENSE_PATH" \
         "$MCPIP_LICENSE_PUBLIC_KEY_PATH" "$MCPIP_INTEGRITY_MANIFEST_PATH" \
         "$MCPIP_INTEGRITY_PUBLIC_KEY_PATH"; do
  [ -s "$f" ] || die "required file missing/empty: $f"
done
log "credentials materialized 0600; public release assets staged 0644"

# --- 7) Redis companion (durability gate). Production requires a DURABLE Redis
#        (appendonly yes / appendfsync always) or the gateway's persistence-posture
#        gate refuses to boot. This script does NOT run Redis — start the bundled
#        durable service first:  docker compose -f docker-compose.prod.yml up -d redis
#        Best-effort verify when redis-cli is present: a reachable-but-non-durable
#        Redis aborts here; unreachable / absent tooling only warns (the gateway's own
#        boot-time assertion is the hard, fail-closed gate).
redis_url="${MCPIP_REDIS_URL:-redis://localhost:63790/0}"
if command -v redis-cli >/dev/null 2>&1; then
  if fsync="$(redis-cli -u "$redis_url" CONFIG GET appendfsync 2>/dev/null | tail -n1)"; then
    case "$fsync" in
      always)      log "Redis durability verified: appendfsync=always" ;;
      everysec|no) die "Redis at $redis_url has appendfsync='$fsync' (need 'always'); start the durable companion: docker compose -f docker-compose.prod.yml up -d redis" ;;
      "")          log "WARNING: could not read Redis appendfsync (CONFIG restricted?) — the gateway asserts durability at boot" ;;
      *)           log "WARNING: unexpected Redis appendfsync='$fsync' — the gateway asserts durability at boot" ;;
    esac
  else
    log "WARNING: Redis at $redis_url unreachable now — start it first (docker compose -f docker-compose.prod.yml up -d redis); the gateway fails closed if it stays down"
  fi
else
  log "NOTE: redis-cli absent — ensure a DURABLE Redis (appendfsync always) is reachable at $redis_url before boot (docker compose -f docker-compose.prod.yml up -d redis)"
fi
log "booting fail-closed gateway (sandbox=false)"

# --- 8) Exec the gateway. Its composition root REFUSES to boot if the license /
#        integrity manifest / keys are missing or invalid, or Redis is not durably
#        persisted — the final safety net.
exec uvicorn app.main:app \
  --host "${MCPIP_API_HOST:-0.0.0.0}" --port "${MCPIP_API_PORT:-8080}" \
  --no-server-header --proxy-headers
