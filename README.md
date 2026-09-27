# hseshadr/ci

**TL;DR:** GitHub delivers events; Dagger owns execution. This repository contains the
fleet policy used to prove that all eight repositories follow that boundary, plus typed
reusable Dagger modules for repository safety and Cloudflare Pages delivery. It does not
publish reusable workflows, composite actions, or copyable CI templates.

A **Dagger lego** is a typed reusable Dagger module installed at an immutable commit SHA.
The exact commit makes the shared behavior reviewable and prevents a consumer from changing
when central `main` moves.

## Run it now

Prerequisites: Docker, Dagger 0.21.8, and a GitHub token that can read the fleet.

```bash
cd /path/to/ci
export GITHUB_TOKEN="$(gh auth token)"
dagger call ci --github-token=env:GITHUB_TOKEN
dagger call fleet --github-token=env:GITHUB_TOKEN --include-central
```

The first command runs central quality and security checks. The second reads exact
`main` state from GitHub for:

- `almamesh`
- `aml-filter`
- `assay`
- `edge-proc`
- `edge-reco`
- `edgeproc-core`
- `privacy-core`
- `ci`

Any inaccessible or incomplete evidence is an error. A scan that inspected nothing
cannot report success.

## Reuse the Dagger legos

The shared modules are:

- `portfolio-foundation`: exact source identity, full-history repository guard, deterministic
  artifact envelopes, envelope verification, and exact-current-`main` GitHub evidence;
- `cloudflare-pages`: fail-closed Pages preflight, one pinned Wrangler direct upload,
  deployment/live convergence bound to the created deployment ID, and an opt-in compiler for
  authenticated Pages Functions sources that stage validated advanced-mode module trees.
- `python-package`: frozen dependency audit, non-root pure-Python wheel and sdist build,
  metadata-derived tag verification, and a Foundation envelope for a separate source-free
  official PyPA publisher job. The module never publishes to a registry.

Start with the [exact-SHA consumer quickstart](docs/dagger-modules.md#quickstart). It captures
the central `main` SHA, validates all 40 lowercase hexadecimal characters, and commits that
literal dependency. The guide also includes a realistic Python composition, typed secret and
GitHub Environment rules, Python/TypeScript fixture proofs, and cold-engine verification.

The modules and their cross-language composition fixtures are implemented in this repository.
The guarded central merge establishes the remotely installable SHA. EdgeReco adoption and its
production canary are separate pending rollout steps; this change does not claim a production
deployment or fleet-wide module adoption.

## Architecture

Explore the [interactive runtime map](docs/architecture/index.html).

## Execution model

Only four workflows remain:

| Workflow | Event ingress | Dagger function |
|---|---|---|
| `dagger.yml` | pull request, push to `main`, manual | `ci` |
| `consumer-drift.yml` | push to `main`, daily, manual | `fleet` |
| `dagger-security.yml` | weekly, manual | `security` |
| `module-canary.yml` | weekly, manual | `module-fixtures` |

Each job has exactly two pinned actions:

1. `actions/checkout` with `persist-credentials: false`
2. `dagger/dagger-for-github` pinned to a full commit SHA and Dagger 0.21.8

The module receives source through an explicit typed `dagger.Workspace` and stores an
explicit `dagger.Directory`. Credentials cross public Dagger functions as
`dagger.Secret`. Generated SDK bytes are mounted separately as toolchain data, so they
cannot silently expand the caller-selected source snapshot.

## What the central gate proves

`dagger call ci` runs:

- Ruff formatting and linting
- strict mypy
- Xenon Grade A complexity
- pytest with at least 90% core coverage
- locked dependency audit
- actionlint
- Zizmor, failing on medium or high findings
- Gitleaks over both the exact source snapshot and complete Git history

The same graph runs locally and in GitHub. Hosted calls bind full-history scanning to
`${{ github.sha }}`.

## What fleet policy proves

For every exact consumer `main`, the scanner requires:

- every repository-authored workflow job is thin pinned Dagger ingress;
- source is an explicit typed `Directory` or `Workspace`;
- Dagger-exposed credential arguments are typed `Secret`;
- branch protection is strict and requires only `Dagger`, bound to GitHub Actions app
  ID `15368`;
- the required `Dagger` check succeeded on the exact current `main` SHA;
- managed CodeQL default setup is disabled;
- no independent execution app controls the build or deploy path;
- no live workflow executes a retired `hseshadr/ci` reusable control.
- every pinned central module is on `hseshadr/ci` `main` and at or after its reviewed
  required-minimum floor ([details](docs/dagger-modules.md#required-minimum-pins)).

GitGuardian is allowed only as a non-required advisory observer.

### Approved transport exceptions

The policy recognizes only two non-Dagger transports around a release candidate:

- a pinned `upload-artifact` step after a successful unprivileged Dagger candidate;
- a source-free privileged job that downloads that exact run/SHA artifact, then either
  invokes the official PyPI OIDC action with attestations or an exact-SHA remote Dagger
  npm publisher with typed GitHub OIDC URL and token inputs.

Publisher bridges reject checkout, setup, install, build, test, free-form shell, mutable
references, excess permissions, wrong artifact identity, and missing provenance.

This repository does not publish packages and its CI never dispatches a registry
mutation.

## Fleet token

`CONSUMER_DRIFT_TOKEN` must be able to read all eight repositories. The authoritative
reader needs:

- Contents: read
- Administration: read
- Checks: read
- Pull requests: read

Administration read is required for effective branch protection and CodeQL default-setup
metadata. Checks read is required for exact-SHA app-bound integration evidence. The
scanner fails closed with a permission-specific message when either is unavailable.

## Develop

Use TDD and run the same enforced gate:

```bash
uv run --directory .dagger poe gate
uv run --directory .dagger poe audit
export GITHUB_TOKEN="$(gh auth token)"
dagger call ci --github-token=env:GITHUB_TOKEN
dagger call fleet --github-token=env:GITHUB_TOKEN
```

Core policy lives in `.dagger/src/ci/fleet_policy.py`; GitHub's typed evidence adapter
lives in `.dagger/src/ci/github_fleet.py`. Behavioral tests live in `.dagger/tests/`.

## Scope

This is a control-plane repository, not a template catalog. Consumer-specific application builds
stay local; consumers compose Foundation, Pages, and the closed Python package candidate Lego
instead of copying shared trust mechanics. Privileged publisher jobs stay source-free and use
official registry actions outside Dagger. Dependabot may propose dependency updates, but its pull
requests are never auto-merged.
