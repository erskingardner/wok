#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 LOCAL_API_SOCKET REMOTE_NPUB:PORT" >&2
  exit 2
fi

socket=$1
remote=$2
payload='["REQ","fips-smoke",{"limit":1}]'

output=$(cargo run --quiet --locked -p wok-fips --example native-client -- \
  "$socket" "$remote" "$payload")
printf '%s\n' "$output"
grep -Fq '"EOSE"' <<<"$output"
