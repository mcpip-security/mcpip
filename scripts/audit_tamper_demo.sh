#!/usr/bin/env bash
# MCPIP — delete an audit record and watch the chain notice.
#
#   ./scripts/quickstart.sh          # first, so there is a gateway and a ledger
#   ./scripts/audit_tamper_demo.sh
#
# "Our agent actions are logged" is the answer everyone gives. The question that
# actually decides whether the log is worth anything is the next one: if someone
# with production access edits or deletes a record, does anything notice?
#
# This script answers it the only way worth accepting — by doing it. It reaches
# past the gateway entirely and deletes a sealed record straight out of Redis,
# as whoever owns the box, then asks the gateway to verify its own chain again.
#
# Nothing here is privileged trickery: the epoch's Merkle root is recomputed from
# the surviving records and compared against the root that was Ed25519-signed when
# the epoch closed. The signing key is not in Redis, so the deleter cannot re-sign
# a root that matches what they left behind.
#
# DESTRUCTIVE, by design: it really does delete a record. Sandbox only — /v1/audit/verify
# is 404 outside sandbox mode. Reset afterwards with the two lines this prints.
set -euo pipefail

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[32m'; RED=$'\033[31m'; CYAN=$'\033[36m'; RESET=$'\033[0m'
GATEWAY=${MCPIP_GATEWAY:-http://localhost:8080}
REDIS_PORT=${MCPIP_REDIS_PORT:-63790}
EVENTS_STREAM="mcpip:worm:events"

step() { printf '\n%s\n' "${BOLD}$*${RESET}"; }
cmd()  { printf '%s\n' "  ${DIM}\$${RESET} ${CYAN}$*${RESET}"; }
out()  { printf '%s\n' "  $*"; }
die()  { printf '%s\n' "${RED}✕ $*${RESET}" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || die "jq not found"
curl -sf "${GATEWAY}/healthz" >/dev/null 2>&1 || die "no gateway on ${GATEWAY} — run ./scripts/quickstart.sh first"
redis-cli -p "$REDIS_PORT" ping >/dev/null 2>&1 || die "no redis on :${REDIS_PORT}"

JWT=$(curl -s -X POST "${GATEWAY}/v1/dev/token" -H 'content-type: application/json' \
  -d '{"tenant_id":"tenant-acme","agent_id":"auditor-1"}' | jq -r .jwt)
[[ -n "$JWT" && "$JWT" != "null" ]] || die "could not mint a sandbox token — is the gateway in sandbox mode?"

verify() { curl -s "${GATEWAY}/v1/audit/verify" -H "authorization: Bearer ${JWT}" | jq -c; }

printf '%s\n' "${BOLD}MCPIP — can you tell if someone deleted an audit record?${RESET}"
printf '%s\n' "${DIM}The gateway signs a Merkle root per epoch. The key is not in Redis.${RESET}"

step "1. Verify the signed chain as it stands"
cmd "curl -s ${GATEWAY}/v1/audit/verify"
BEFORE=$(verify)
out "${GREEN}${BEFORE}${RESET}"
if [[ "$BEFORE" != *'"intact":true'* ]]; then
  printf '\n%s\n' "${RED}The chain is already reporting tamper, so this demo has nothing left to show.${RESET}"
  printf '%s\n' "${DIM}Reset it and re-run:  redis-cli -p ${REDIS_PORT} flushall && rm -f mcpip_worm.jsonl.anchor${RESET}"
  printf '%s\n' "${DIM}then ./scripts/quickstart.sh${RESET}"
  exit 1
fi

# Pick a record inside the newest sealed epoch — hot, so its absence cannot be
# mistaken for legitimate retention trimming.
EPOCH=$(redis-cli -p "$REDIS_PORT" GET mcpip:worm:epoch:num)
HEADER=$(redis-cli -p "$REDIS_PORT" HGET mcpip:worm:epoch:index "$EPOCH")
[[ -n "$HEADER" ]] || die "no sealed epoch to tamper with — run scripts/live_company.py first"
FIRST_ID=$(printf '%s' "$HEADER" | jq -r .first_stream_id)

step "2. Delete one sealed record — straight in Redis, bypassing the gateway"
cmd "redis-cli -p ${REDIS_PORT} XDEL ${EVENTS_STREAM} ${FIRST_ID}"
DELETED=$(redis-cli -p "$REDIS_PORT" XDEL "$EVENTS_STREAM" "$FIRST_ID")
out "(integer) ${DELETED}"
[[ "$DELETED" == "1" ]] || die "the record was not there to delete — nothing was proven"

step "3. Ask the gateway to verify the chain again"
cmd "curl -s ${GATEWAY}/v1/audit/verify"
AFTER=$(verify)
out "${RED}${AFTER}${RESET}"

printf '\n'
if [[ "$AFTER" == *'"intact":false'* ]]; then
  printf '%s\n' "${GREEN}${BOLD}✓ Caught.${RESET} ${BOLD}The gateway names the epoch the missing record was in.${RESET}"
  printf '%s\n' "${DIM}The root is recomputed from the surviving records and compared against the one"
  printf '%s\n' "Ed25519-signed at epoch close. Re-signing a root that matches what was left behind"
  printf '%s\n' "needs the signing key, which is not in Redis — so deletion is detectable, not deniable.${RESET}"
else
  printf '%s\n' "${RED}${BOLD}✕ NOT caught — this is a real finding, not a demo glitch.${RESET}"
  printf '%s\n' "${DIM}A sealed record was deleted and verify_chain still reports intact. Please open an"
  printf '%s\n' "issue with the output above; audit/worm_logger.py::_verify_epoch is the place to look.${RESET}"
  exit 1
fi

printf '\n%s\n' "${DIM}Reset:  redis-cli -p ${REDIS_PORT} flushall && rm -f mcpip_worm.jsonl.anchor${RESET}"
printf '%s\n' "${DIM}        then ./scripts/quickstart.sh${RESET}"
