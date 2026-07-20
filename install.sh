#!/usr/bin/env bash
# MCPIP — one-line installer for the `mcpip` CLI (macOS / Linux).
#
#   curl -fsSL https://raw.githubusercontent.com/mcpip-security/mcpip/main/install.sh | bash
#
# Installs the client CLI (`mcpip`) — the tool you point at a gateway to log in,
# check health, and authorize actions. It does NOT run a gateway; bringing up the
# gateway itself is `docker compose up` (printed at the end).
#
# SECURITY NOTE — this is a security product, so the installer earns its trust:
#   • It is short and readable. INSPECT IT before piping to a shell:
#         curl -fsSL https://raw.githubusercontent.com/mcpip-security/mcpip/main/install.sh | less
#   • It needs NO root; everything installs into your user space (pipx / pip --user).
#   • It pins nothing by magic: set MCPIP_INSTALL_REF=vX.Y.Z to install a specific
#     tag, or MCPIP_REPO=<git-url> to install from your own mirror.
#   • It runs only well-known package managers (pipx/pip) — no opaque binary drop.
set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; RED=$'\033[31m'; RESET=$'\033[0m'
say()  { printf '%s\n' "${BOLD}◐ $*${RESET}"; }
note() { printf '%s\n' "${DIM}  $*${RESET}"; }
warn() { printf '%s\n' "${YELLOW}! $*${RESET}" >&2; }
die()  { printf '%s\n' "${RED}✕ $*${RESET}" >&2; exit 1; }

# --- config (all overridable via env) ----------------------------------------
PKG="${MCPIP_PKG:-mcpip-sdk}"                                   # PyPI distribution name
REPO="${MCPIP_REPO:-https://github.com/mcpip-security/mcpip.git}"  # git fallback source
REF="${MCPIP_INSTALL_REF:-}"                                     # optional tag/branch to pin
SUBDIR="sdk/python"                                              # SDK lives in a subdirectory

say "installing the mcpip CLI"

# --- 1. python (>= 3.10, the SDK floor) --------------------------------------
PY="$(command -v python3 || command -v python || true)"
[ -n "$PY" ] || die "python3 not found — install Python 3.10+ (macOS: brew install python)"
"$PY" - <<'PYCHK' || die "Python 3.10+ required (the mcpip CLI floor)"
import sys
raise SystemExit(0 if sys.version_info[:2] >= (3, 10) else 1)
PYCHK
note "python: $("$PY" --version 2>&1) ✓"

# --- 2. choose an isolated installer -----------------------------------------
# pipx is the right tool for a CLI (its own venv, on PATH). Fall back to
# `pip install --user` when pipx is absent. Never touch system site-packages.
install_with() {
  # $1 = source spec (PyPI name or a pip VCS URL)
  local src="$1"
  if command -v pipx >/dev/null 2>&1; then
    note "via pipx: $src"
    pipx install --force "$src"
  else
    note "via pip --user: $src (install 'pipx' for an isolated CLI)"
    "$PY" -m pip install --user --upgrade "$src"
  fi
}

# --- 3. install: PyPI first, git subdirectory as the resilient fallback -------
vcs_url() {
  # pip VCS form for a package in a subdirectory, optionally pinned to a ref.
  local ref="${REF:+@$REF}"
  printf 'git+%s%s#subdirectory=%s' "$REPO" "$ref" "$SUBDIR"
}

pypi_spec="$PKG"
[ -n "$REF" ] && pypi_spec="$PKG==${REF#v}"   # allow MCPIP_INSTALL_REF=v0.1.0 or 0.1.0

if install_with "$pypi_spec" 2>/dev/null; then
  note "installed $PKG from PyPI ✓"
else
  warn "PyPI install unavailable — falling back to source ($REPO)"
  install_with "$(vcs_url)" || die "install failed from both PyPI and $REPO"
  note "installed $PKG from source ✓"
fi

# --- 4. verify the entry point resolves --------------------------------------
BIN="$(command -v mcpip || true)"
if [ -z "$BIN" ]; then
  warn "'mcpip' is installed but not on your PATH yet."
  if command -v pipx >/dev/null 2>&1; then
    note "run:  pipx ensurepath   then open a new shell"
  else
    note "add your user bin to PATH, e.g.:  export PATH=\"\$HOME/.local/bin:\$PATH\""
  fi
else
  note "mcpip: $BIN"
  "$BIN" version 2>/dev/null || "$BIN" --help >/dev/null 2>&1 || true
fi

# --- 5. what next ------------------------------------------------------------
cat <<NEXT

${GREEN}${BOLD}◐ mcpip CLI installed.${RESET}

${BOLD}Point it at a gateway${RESET}
  ${DIM}mcpip login    --gateway https://your-gateway:8080${RESET}   authenticate
  ${DIM}mcpip health   --gateway https://your-gateway:8080${RESET}   liveness
  ${DIM}mcpip whoami${RESET}                                        show the current identity

${BOLD}No gateway yet? Bring one up (Docker)${RESET}
  ${DIM}docker compose up${RESET}                                   gateway on :8080 + Redis
  ${DIM}# or a full local walkthrough from a checkout:${RESET}
  ${DIM}./scripts/quickstart_demo.sh${RESET}

${DIM}Docs: https://github.com/mcpip-security/mcpip · run 'mcpip --help' for every command.${RESET}
NEXT
