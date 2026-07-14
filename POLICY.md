# Engineering Policy

These rules are mandatory for commits and releases in this repository.

## Commit And Release Rules

- MUST: Run `make guardrails` before committing or opening a pull request.
- MUST: Write commit subjects as `Prefix: Concise headline` using only `Add`,
  `Change`, `Fix`, `Remove`, `Refactor`, `Test`, `Docs`, `Build`, `Ci`, `Vendor`,
  `Security`, or `Chore`.
- MUST: Use the subject as the headline for what was fundamentally done and a
  short bullet-list body for the essential implementation, validation,
  user-facing, configuration, packaging, or dependency details.
- MUST: Split unrelated work into separate commits when one approved prefix and
  headline cannot describe the change cleanly.
- MUST: Stage only files belonging to the intended commit and preserve
  unrelated working-tree state.
- MUST: Run `make release-guardrails` before publishing `main` or a `v*` version
  tag, either directly or through the pre-push hook installed by
  `make install-hooks`.
- MUST: Treat `govulncheck` findings as release blockers unless a documented
  maintainer exception is made.
- MUST: Publish release-sensitive refs from a clean checkout whose `HEAD`
  matches the pushed `main` or version-tag commit.
- MUST: Use release tags in the form `vMAJOR.MINOR.PATCH` with an optional valid
  SemVer prerelease suffix.
- MUST: Keep prereleases from updating stable `latest`, major, or minor
  container aliases.
- MUST: Keep `go.mod`, `go.sum`, and `vendor/` synchronized after dependency
  changes.
- MUST: Keep release notes useful by choosing the commit prefix that matches the
  user-visible purpose of the change.
- MUST: Publish release archives with the project policy and license, an SPDX
  SBOM, and build-provenance attestation.

## Definition Of Done

- [ ] The commit contains only the intended files.
- [ ] The subject uses an approved capitalized prefix and concise headline.
- [ ] Non-trivial commits have a short bullet-list body.
- [ ] `make guardrails` passes locally.
- [ ] Dependency changes were followed by `go mod tidy` and `go mod vendor`.
- [ ] `make release-guardrails` passes before publishing `main` or a release
      tag.
- [ ] The release tag passes `scripts/release-semver-metadata.sh`.
- [ ] Stable and prerelease container aliases have the correct scope.
- [ ] GitHub release notes contain the categorized commit summary and generated
      pull-request notes.
- [ ] Release archives, SPDX SBOMs, and provenance attestations are attached.
