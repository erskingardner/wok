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
   git tag -a v0.1.0 <release-commit> -m "Wok 0.1.0"
   git push origin v0.1.0
   ```

The tag push starts `.github/workflows/release.yml`. It independently validates
the tag/version/changelog contract, runs the release gate, builds native Wok
binaries for Linux x86-64 and ARM64 plus macOS Intel and Apple Silicon, creates
checksums, and publishes a GitHub Release for that tag. It never moves or
creates a tag itself.

## Release assets

Each archive contains `wok`, `README.md`, `CHANGELOG.md`, `LICENSE`, and the
example `wok.toml`. `SHA256SUMS` covers all published archives. Wok currently
uses Unix-specific process, signal, and socket APIs, so Windows artifacts are
not published.

Do not reuse or move a published version tag. If a release needs correction,
prepare a new patch version and changelog entry.
