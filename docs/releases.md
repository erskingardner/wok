# Releases

Wok uses Semantic Versioning and `vMAJOR.MINOR.PATCH` Git tags. The workspace
version in `Cargo.toml`, the tag without its `v` prefix, and the dated section
in `CHANGELOG.md` must agree.

## Preparing a release

1. Move the relevant entries from `Unreleased` into a new dated changelog
   section, then add a fresh `Unreleased` section.
2. Set `[workspace.package].version` in `Cargo.toml`. Every crate inherits this
   single version.
3. Run the normal CI commands and merge or push the release commit.
4. Wait for CI and distribution-platform builds to pass for that exact commit.
5. Tag the exact release commit and push only that tag:

   ```bash
   version=0.2.0
   git tag -a "v$version" <release-commit> -m "Wok $version"
   git push origin "v$version"
   ```

The tag push starts `.github/workflows/release.yml`. It independently validates
the tag/version/changelog contract, runs the release gate, builds both lean and
`native-fips` Wok binaries for Linux x86-64 and ARM64 plus macOS Intel and Apple
Silicon, creates checksums, and publishes a GitHub Release for that tag. It
never moves or creates a tag itself.

## Release assets

Each archive contains `wok`, `README.md`, `CHANGELOG.md`, `LICENSE`, the
example `wok.toml`, and the complete `docs/` tree so README links and the Wok
logo remain available offline. Standard `wok-VERSION-TARGET` archives exclude
the native FIPS dependency. Archives ending in `-native-fips` contain the
feature-enabled binary. `SHA256SUMS` covers all published archives. Wok
currently uses Unix-specific process, signal, and socket APIs, so Windows
artifacts are not published.

Do not reuse or move a published version tag. If a release needs correction,
prepare a new patch version and changelog entry.
