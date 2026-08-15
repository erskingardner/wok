# .github/

GitHub Actions for this repo. Workflow YAML lives in `workflows/`.

Permissions default to `contents: read` unless a job needs to publish a release. Concurrency groups cancel in-progress runs on the same ref except for release.
