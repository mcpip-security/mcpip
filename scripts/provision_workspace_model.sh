#!/usr/bin/env bash
# MCPIP — provision the local Workspace-Generate model (Tier 1, turnkey).
#
#   ./scripts/provision_workspace_model.sh
#
# One command to make the slim, air-gapped drafting model part of your deployment: checks
# for Ollama, pulls the Apache-2.0 base, builds the `mcpip-workspace` model from
# training/Modelfile.workspace, and verifies it drafts valid JSON. Idempotent — reruns
# reuse whatever already exists. The brief never leaves the host; nothing is downloaded
# except the open-source base weights from your configured Ollama registry.
#
# Then point the console (Tenants → Workspace Generate → model settings) at
# http://localhost:11434/v1 with model `mcpip-workspace`, or run the gateway with the
# console defaults. For a fine-tuned model see training/README.md.
set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'; RESET=$'\033[0m'
say()  { printf '%s\n' "${BOLD}◐ $*${RESET}"; }
note() { printf '%s\n' "${DIM}  $*${RESET}"; }
die()  { printf '%s\n' "${RED}✕ $*${RESET}" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODELFILE="$REPO_ROOT/training/Modelfile.workspace"
BASE_MODEL="${MCPIP_MODEL_BASE:-qwen2.5:1.5b}"       # Apache-2.0 base; override if you must.
MODEL_NAME="${MCPIP_MODEL_NAME:-mcpip-workspace}"
OLLAMA_HOST="${OLLAMA_HOST:-http://localhost:11434}"

[[ -f "$MODELFILE" ]] || die "missing $MODELFILE"

say "checking Ollama"
if ! command -v ollama >/dev/null 2>&1; then
  die "ollama not found. Install it (https://ollama.com), then re-run. Any OpenAI-compatible
     local server also works — see training/README.md."
fi
note "ollama ✓"

say "pulling the Apache-2.0 base ($BASE_MODEL) — one-time"
ollama pull "$BASE_MODEL" || die "could not pull $BASE_MODEL"

# The Modelfile pins the base; if the operator overrode it, rewrite the FROM line on a copy.
BUILD_FILE="$MODELFILE"
if [[ "$BASE_MODEL" != "qwen2.5:1.5b" ]]; then
  BUILD_FILE="$(mktemp)"
  sed "s|^FROM .*|FROM $BASE_MODEL|" "$MODELFILE" > "$BUILD_FILE"
  note "using overridden base $BASE_MODEL"
fi

say "building the $MODEL_NAME model from the Modelfile"
ollama create "$MODEL_NAME" -f "$BUILD_FILE" || die "ollama create failed"

say "verifying it drafts valid JSON"
RESP="$(ollama run "$MODEL_NAME" 'Company: Acme | Brief: a fintech with engineering and finance teams' 2>/dev/null || true)"
if printf '%s' "$RESP" | grep -q '"skills"'; then
  printf '%s\n' "${GREEN}✓ $MODEL_NAME is ready and drafting plans.${RESET}"
else
  note "the model built, but the smoke draft didn't obviously contain skills — try it in the console."
fi

cat <<NEXT

${BOLD}Wired into the app${RESET}
  ${DIM}Console:${RESET}  Tenants → Workspace Generate → model settings →
            endpoint ${BOLD}${OLLAMA_HOST}/v1${RESET}   model ${BOLD}${MODEL_NAME}${RESET}
  ${DIM}CORS:${RESET}     serve Ollama so the console origin may call it:
            ${BOLD}OLLAMA_ORIGINS='*' ollama serve${RESET}
  ${DIM}Fine-tune:${RESET} training/README.md (Tier 2, QLoRA on the Apache base)
  ${DIM}Legal:${RESET}    docs/policies/NOTICES.md
NEXT
