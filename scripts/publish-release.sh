#!/usr/bin/env bash
# Publish only an existing tag, with explicit stable/prerelease latest policy.
set -euo pipefail

tag=${1:-}
if [[ "$tag" != v* ]]; then
  echo "release tag must be v followed by a SemVer version" >&2
  exit 1
fi
version=${tag#v}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
prerelease=$(python3 "$script_dir/release-version.py" "$version")
dist=${2:-dist}
notes=${3:-release-notes.md}
flags=(--latest)
if [[ "$prerelease" == true ]]; then
  flags=(--prerelease --latest=false)
fi
gh release create "$tag" "$dist"/*.tar.gz "$dist/SHA256SUMS" \
  --verify-tag --title "Wok $version" --notes-file "$notes" "${flags[@]}"
