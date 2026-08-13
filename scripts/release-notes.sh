#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "version must match MAJOR.MINOR.PATCH, got: ${version:-<empty>}" >&2
  exit 1
fi

notes=$(
  awk -v version="$version" '
    $0 ~ "^## \\[" version "\\] - " { found = 1; next }
    found && /^## \[/ { exit }
    found && /^\[Unreleased\]:/ { exit }
    found { print }
    END { if (!found) exit 2 }
  ' CHANGELOG.md
) || {
  echo "CHANGELOG.md has no release notes for $version" >&2
  exit 1
}

if [[ -z "${notes//[[:space:]]/}" ]]; then
  echo "CHANGELOG.md release notes for $version are empty" >&2
  exit 1
fi
printf '%s\n' "$notes"
