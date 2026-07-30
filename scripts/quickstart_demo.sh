#!/usr/bin/env bash
# Compatibility forwarder — this script was renamed to `quickstart.sh`.
#
# What it runs is real: a live gateway, real /v1/mcp round-trips, real verdicts
# sealed into the signed WORM chain before they execute. Calling that a "demo"
# undersold it, so the name went. The old path stays because it is published in
# the README, on the website, and in links people have already shared — breaking
# those would strand exactly the readers this repo is trying to serve.
#
# Delete this file only once the old name has stopped appearing in the wild.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

printf '\033[33mnote:\033[0m scripts/quickstart_demo.sh is now \033[1mscripts/quickstart.sh\033[0m — forwarding.\n' >&2

exec "$here/quickstart.sh" "$@"
