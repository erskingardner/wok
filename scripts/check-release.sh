#!/usr/bin/env bash
set -euo pipefail

tag=${1:-}
if [[ "$tag" != v* ]]; then
  echo "release tag must be v followed by a SemVer version, got: ${tag:-<empty>}" >&2
  exit 1
fi
version=${tag#v}
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
prerelease=$(python3 "$script_dir/release-version.py" "$version")

workspace_version=$(
  awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version = "/ {
      value = $0
      sub(/^version = "/, "", value)
      sub(/".*$/, "", value)
      print value
      exit
    }
  ' Cargo.toml
)
if [[ -z "$workspace_version" ]]; then
  echo "could not read [workspace.package].version from Cargo.toml" >&2
  exit 1
fi
if [[ "$version" != "$workspace_version" ]]; then
  echo "tag $tag does not match workspace version $workspace_version" >&2
  exit 1
fi

python3 - "$version" <<'PY'
import json
from pathlib import Path
import re
import subprocess
import sys

expected = sys.argv[1]
metadata = json.loads(
    subprocess.check_output(
        ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
        text=True,
    )
)
wrong = sorted(
    (package["name"], package["version"])
    for package in metadata["packages"]
    if package["version"] != expected
)
if wrong:
    rendered = ", ".join(f"{name}={version}" for name, version in wrong)
    raise SystemExit(f"workspace packages do not match {expected}: {rendered}")
heading = re.compile(rf"## \[{re.escape(expected)}\] - [0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}}")
if not any(heading.fullmatch(line) for line in Path("CHANGELOG.md").read_text().splitlines()):
    raise SystemExit(f"CHANGELOG.md has no dated [{expected}] release section")
PY

if git rev-parse --verify --quiet "refs/tags/$tag^{commit}" >/dev/null; then
  tag_commit=$(git rev-parse "refs/tags/$tag^{commit}")
  head_commit=$(git rev-parse HEAD)
  if [[ "$tag_commit" != "$head_commit" ]]; then
    echo "tag $tag resolves to $tag_commit but checkout is $head_commit" >&2
    exit 1
  fi
elif [[ "${WOK_RELEASE_ALLOW_MISSING_TAG:-0}" != "1" ]]; then
  echo "tag $tag is absent from this checkout" >&2
  exit 1
fi

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "version=$version" >> "$GITHUB_OUTPUT"
  echo "prerelease=$prerelease" >> "$GITHUB_OUTPUT"
fi
printf 'release contract valid: %s\n' "$tag"
