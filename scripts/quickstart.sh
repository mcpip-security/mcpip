#!/usr/bin/env bash
# MCPIP — one-shot local quickstart (macOS / Linux).
#
#   ./scripts/quickstart.sh
#
# Checks prerequisites (with install hints), creates/activates a venv, installs
# deps, starts Redis (:63790) and a SANDBOX gateway (:8080), waits for liveness,
# then runs the live company walkthrough (scripts/live_company.py). Idempotent:
# anything already running is detected and reused, never restarted.
set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
say()  { printf '%s\n' "${BOLD}◐ $*${RESET}"; }
note() { printf '%s\n' "${DIM}  $*${RESET}"; }
die()  { printf '%s\n' "${RED}✕ $*${RESET}" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

REDIS_PORT=63790
GATEWAY_PORT=8080
HEALTH_URL="http://localhost:${GATEWAY_PORT}/healthz"

# North-star DX metric: zero -> first governed call, printed at the end.
START_S=$SECONDS

# --- 1. prerequisites --------------------------------------------------------
say "checking prerequisites"

command -v python3 >/dev/null 2>&1 || die "python3 not found — install Python 3.12 (macOS: brew install python@3.12)"

# Redis is required. If it's missing, auto-install it via Homebrew on macOS (the
# one dependency a Mac usually lacks) so this really is a single command; otherwise
# print the exact install line for the platform.
if ! command -v redis-server >/dev/null 2>&1; then
  if command -v brew >/dev/null 2>&1; then
    say "redis not found — installing it with Homebrew (one-time)"
    brew install redis || die "brew install redis failed — install Redis manually, then re-run"
  elif [[ "$(uname)" == "Darwin" ]]; then
    die "redis-server not found. Install Homebrew (https://brew.sh) then:  brew install redis"
  else
    die "redis-server not found — install it (debian/ubuntu:  sudo apt-get install redis-server)"
  fi
fi
note "python3 · redis-server ✓"

# --- 2. venv + deps ----------------------------------------------------------
if [[ -z "${VIRTUAL_ENV:-}" ]]; then
  if [[ ! -d .venv ]]; then
    say "creating virtualenv .venv"
    python3 -m venv .venv
  fi
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi
if ! python -c 'import uvicorn, fastapi, redis' >/dev/null 2>&1; then
  say "installing dependencies (requirements.txt)"
  pip install -q -r requirements.txt
fi
note "venv: ${VIRTUAL_ENV} ✓"

# --- 3. redis ----------------------------------------------------------------
if redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1; then
  note "redis already answering on :${REDIS_PORT} — reusing it"
else
  say "starting redis on :${REDIS_PORT}"
  redis-server --port "$REDIS_PORT" --daemonize yes --dir "${TMPDIR:-/tmp}"
  sleep 1
  redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 || die "redis failed to start"
fi

# --- 4. gateway (sandbox) ----------------------------------------------------
if curl -sf "$HEALTH_URL" >/dev/null 2>&1; then
  note "gateway already live on :${GATEWAY_PORT} — reusing it"
else
  say "starting sandbox gateway on :${GATEWAY_PORT}"
  MCPIP_SANDBOX_MODE=true MCPIP_REDIS_URL="redis://localhost:${REDIS_PORT}/0" \
    nohup python -m uvicorn app.main:app --port "$GATEWAY_PORT" \
    > "${TMPDIR:-/tmp}/mcpip-gateway.log" 2>&1 &
  note "log: ${TMPDIR:-/tmp}/mcpip-gateway.log"
  for _ in $(seq 1 30); do
    curl -sf "$HEALTH_URL" >/dev/null 2>&1 && break
    sleep 0.5
  done
  curl -sf "$HEALTH_URL" >/dev/null 2>&1 || die "gateway did not become live — see the log above"
fi
printf '%s' "${GREEN}"
curl -s "$HEALTH_URL"; printf '%s\n' "${RESET}"

# --- 5. the live walkthrough --------------------------------------------------
say "running the live company walkthrough (mcpip-inc)"
python scripts/live_company.py --base "http://localhost:${GATEWAY_PORT}"

# --- 6. what next -------------------------------------------------------------
ELAPSED=$((SECONDS - START_S))
say "zero → first governed calls: ${ELAPSED}s (north star: < 300s)"

cat <<NEXT

${BOLD}Next steps${RESET}
  ${DIM}Live MCP terminal:${RESET}  python scripts/mcp_terminal.py
                      (an interactive MCP session — login per team, tools, call; allow/deny live)
  ${DIM}Operator console:${RESET}   cd dashboard && npm install && npm run dev   → http://localhost:5173
                      (first run shows the setup flow; Test & Connect → http://localhost:${GATEWAY_PORT})
  ${DIM}Claude Code MCP:${RESET}    just run 'claude' inside this repo — .mcp.json registers the
                      mcpip stdio bridge (auto token refresh). Guide: docs/start/GETTING_STARTED.md
  ${DIM}Workspace model:${RESET}   ./scripts/provision_workspace_model.sh
                      (slim, local, air-gapped model for workspace generation — needs Ollama; training/README.md)
  ${DIM}Stop everything:${RESET}    kill %1 2>/dev/null; redis-cli -p ${REDIS_PORT} shutdown nosave
NEXT
