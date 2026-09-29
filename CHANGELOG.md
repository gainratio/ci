# Changelog

## Unreleased — Dagger-only control plane

### Added

- Publisher lineage is now required: every publisher job must open with the central
  `release-lineage` / `release-provenance` step. A publisher without it, or with it after the
  download, is a `publisher-lineage` finding (`central lineage step required first`).
- Publisher lineage as a module function (hseshadr/ci#49): `portfolio-foundation` gains
  `release-lineage` and `release-provenance`. They fail unless the candidate run is a
  successful `release-candidate.yml` dispatch for exactly the expected SHA and `main`
  contains that SHA. This blocks a dispatch on a tag named `main` from publishing its own
  bytes. `release-provenance` also returns npm's GitHub Actions provenance context, built from
  the publish run record. The fleet policy accepts this as a leading publisher step
  (`publisher-lineage` for anything weaker), and accepts a consumer publisher loaded at
  `@${{ github.sha }}`. Publishers no longer need a `run:` step for lineage.
- `dagger-args-expression`: the fleet policy rejects `${{ inputs.* }}`,
  `${{ github.event.* }}` and `${{ github.head_ref }}` in any `dagger-for-github` input the
  action pastes into bash. Pass the value through `env:` and quote it. Test fixtures that
  pasted `${{ github.event.workflow_run.head_sha }}` into args as "compliant" now use
  `--expected-sha="$HEAD_SHA"`.
- Per-module required-minimum pin floors: the fleet scan reports
  `pin-below-required-minimum` for any consumer whose central module pin is not on `main` at
  or after the reviewed floor (`portfolio-foundation` ≥ `dd19871`, hseshadr/ci#46).
- Reusable `portfolio-foundation` and `cloudflare-pages` Dagger modules for exact source
  identity, repository safety, deterministic artifact evidence, exact-green authorization,
  and fail-closed Pages delivery.
- An exact-SHA dependency policy and generated-client composition fixtures for both Python and
  TypeScript consumers, including isolated cold-engine proof. This change creates no package,
  version tag, or registry release.
- A typed Dagger module for central quality, dependency, workflow-security, secret, and
  fleet-policy checks.
- An authoritative GitHub evidence adapter that fails closed on unreadable source,
  effective branch protection, exact-SHA checks, or CodeQL metadata.
- Behavioral policy for thin pinned Dagger ingress and the two narrow artifact transport
  and source-free OIDC publisher exceptions.
- Hosted fleet scanning against exact `main` identities for all seven consumers and
  this repository.
- Regression coverage for explicit Workspace source, generated SDK separation, typed
  Secrets, app-bound protection, stale checks, privileged publishers, and incomplete API
  evidence.
- Optional typed Git authorization for exact private-repository history in
  `portfolio-foundation`, kept inside Dagger's secret boundary.
- Fleet coverage: `agentic-saga` and `agentic-context-service` join the fleet scan, and every
  scan now discovers `hseshadr/ci` consumers from default-branch `dagger.json` and fails with
  `uncovered-consumer` for any that are not listed. Unreadable repositories become an
  `evidence-unreadable` finding, so they no longer stop the scan.

### Changed

- GitHub Actions is now pinned event transport only. Repository-authored execution runs
  inside Dagger.
- Scheduled dependency/security work and full-history secret scanning run in Dagger.
- Branch protection converges on strict, app-bound, sole `Dagger`.
- `python-package` dependency audits forward private-history authorization to Foundation
  instead of refetching protected source anonymously.

### Removed

- Seven legacy reusable workflows.
- Five composite-action packages.
- Seventeen consumer example workflows.
- The Ruby/shell classifier, fingerprint allowlists, example-fidelity stack, and their
  legacy security workflow.
- All remaining consumer execution references to `hseshadr/ci`.

Older reusable-workflow releases remain available in Git history and existing tags. They
are retired and are not part of the current architecture.
