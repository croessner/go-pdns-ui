# go-pdns-ui Development Guidelines

This repository is a Go 1.26.5 web application for managing PowerDNS zones.
Keep `go.mod`, `Dockerfile`, GitHub Actions, vendored dependencies, and project
documentation aligned when toolchain details change.

## Required Workflow

- Read this file before repository changes and preserve unrelated dirty-tree
  state.
- Prefer Makefile targets over ad hoc command variants.
- Run focused tests while iterating and `make guardrails` before every commit or
  pull request unless the user explicitly narrows or defers validation.
- Run `make release-guardrails` before publishing `main` or a `v*` release tag.
  Treat `govulncheck` findings as release blockers unless a maintainer records
  an explicit exception.
- Use regression-test-first development for reproducible bugs where practical.
- After dependency changes, run `go mod tidy`, `go mod vendor`, and the full
  guardrails.
- Keep code comments and technical documentation in English.
- Keep local specifications, plans, prompts, and scratch artifacts under the
  ignored `temp/` directory. Move rewritten durable documentation to `docs/`.
- Do not commit, push, tag, deploy, or mutate external PowerDNS state unless the
  user explicitly requests that scope.

## Architecture Boundaries

- `internal/domain` owns zone, draft, record, template, validation, and service
  invariants. Keep HTTP and PowerDNS transport details out of domain behavior.
- `internal/pdns` owns PowerDNS API transport, DTO mapping, RRset grouping, and
  backend error translation.
- `internal/http` owns routes, authorization middleware, CSRF enforcement,
  request parsing, HTMX response behavior, view state, and audit calls.
- `internal/auth` owns sessions, password authentication, and OIDC flows.
- `internal/access` owns principals, companies, memberships, zone assignments,
  and their PostgreSQL persistence.
- `internal/audit` owns bounded audit persistence and retention.
- `internal/app` owns dependency composition, configuration, startup, and
  graceful shutdown.
- `internal/assets` owns embedded templates, scripts, and localization files.

Keep these boundaries narrow. Reuse domain services rather than duplicating
record, RRset, access, or draft behavior in handlers.

## DNS and Draft Safety

- Treat a DNS RRset as all records with the same owner name and type. Preserve
  multiple distinct RRset members end to end.
- Mutations in the editor change the server-side draft first. Only the explicit
  apply action may write the draft to PowerDNS.
- Import, preview, export, and template creation must not implicitly apply a
  zone.
- Validate a complete replacement before changing the draft; invalid input
  must not leave partial state.
- Keep DNS names, trailing-dot handling, TTL behavior, SOA invariants, and RDATA
  parsing in shared domain/parser helpers with focused tests.
- Do not silently collapse RRset members, choose conflicting TTLs, or overwrite
  an existing zone or template.

## Security Boundaries

- Require the existing session CSRF token on every unsafe authenticated route.
- Keep role and zone-access checks on both preview/readback and mutation paths.
- Default ambiguous authentication, authorization, OIDC, proxy, and backend
  states to fail closed.
- Never log or audit passwords, session values, API keys, bearer tokens, raw
  imported zone text, or full TXT record content.
- Keep cookies, forwarded-header trust, security headers, and redirect targets
  covered by focused tests when touched.
- Render bounded HTMX validation errors into the intended target. Do not turn
  server-side input rejection into an invisible browser no-op.
- Keep audit details bounded and useful without copying secret-bearing payloads.

## Frontend and Localization

- Keep application JavaScript in embedded static files so the CSP remains
  enforceable.
- Preserve HTMX target/swap contracts and relevant form state across partial
  renders.
- Add matching German and English locale entries for user-visible text.
- Test security-sensitive or regression-prone HTML attributes and response
  behavior at the HTTP handler boundary.

## Quality Gates

`make guardrails` runs:

- `make fix`
- `make vet`
- `make lint`
- `make test`
- `make race`
- `make build-check`

`make release-guardrails` additionally runs `govulncheck`. The GitHub
Guardrails workflow installs the pinned golangci-lint v2 release and verifies
that guardrails do not leave tracked generated or formatting drift.

## Release Workflow

- Release tags must use `vMAJOR.MINOR.PATCH` with an optional SemVer prerelease
  suffix such as `v1.6.0-rc.1`.
- Publish release-sensitive refs only from a clean checkout whose `HEAD` is the
  exact commit referenced by the pushed `main` branch or version tag.
- Use `make install-hooks` to install the optional pre-push vulnerability gate.
- Stable tags may update `latest`, major, and minor container aliases.
  Prerelease tags must publish only their exact version alias.
- GitHub release notes use the commit prefixes below to create the categorized
  commit summary. Keep subjects meaningful to users and operators.
- Release artifacts include the binary, README, license, policy, SPDX SBOM, and
  GitHub build-provenance attestation.

## Commit Log Format

Use structured commit messages with a fixed, capitalized prefix and a concise
headline:

```text
Prefix: Summarize the main change

- Detail the most relevant implementation work
- Mention tests, guardrails, or generated files when relevant
- Call out user-facing behavior, configuration, packaging, or dependencies
```

Allowed prefixes:

- `Add`: new functionality, files, or supported behavior
- `Change`: behavior changes that are not primarily bug fixes
- `Fix`: bug fixes and regressions
- `Remove`: deleted behavior, files, or obsolete paths
- `Refactor`: internal restructuring without intended behavior changes
- `Test`: test-only changes
- `Docs`: documentation-only changes
- `Build`: Makefile, Docker, packaging, release, or toolchain changes
- `Ci`: GitHub Actions or other automation changes
- `Vendor`: dependency and vendored module updates
- `Security`: hardening or vulnerability-related changes
- `Chore`: repository maintenance that does not fit another prefix

The subject states what was fundamentally done. Use a short bullet-list body to
capture essential implementation and validation details. Split unrelated work
when one prefix and headline cannot describe it cleanly, and stage explicit
paths only.
