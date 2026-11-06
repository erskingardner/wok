#!/usr/bin/env bash
set -euo pipefail

version=${1:-}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
python3 "$script_dir/release-version.py" "$version" >/dev/null

notes=$(
  awk -v version="$version" '
    index($0, "## [" version "] - ") == 1 { found = 1; next }
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
