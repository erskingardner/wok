#!/usr/bin/env bash
set -euo pipefail

socket=/run/fips/api.sock
relay=npub10xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqpkge6d:7777

native-event-matrix "$socket" "$relay"
