# Architecture

This repo is the shared CI for Harish's repositories. It has two jobs:

1. Ship reusable Dagger modules that other repos install at an exact commit.
2. Check, every day, that each of those repos still runs its CI the agreed way.

The rule behind both: **GitHub Actions only delivers events; Dagger runs everything.** A
workflow file checks out the code and calls one Dagger function. Tests, builds, scans and
deploys all happen inside Dagger, so the same steps run on a laptop and in GitHub.

For an interactive picture, open the [runtime map](architecture/index.html) (its data is in
[runtime.architecture.json](architecture/runtime.architecture.json)).

## The pieces

| Path | What it is |
|---|---|
| `.dagger/src/ci/main.py` | The root Dagger module. Public functions: `ci`, `security`, `fleet`, `module-fixtures`. |
| `.dagger/src/ci/fleet_policy.py` | The rules every consumer repo must follow (pure Python, no network). |
| `.dagger/src/ci/github_fleet.py` | Reads the real state of each repo from the GitHub API and feeds it to the rules. |
| `.dagger/src/ci/fleet.py` | The list of consumer repos and what each must have (branch protection, deadlines). |
| `.dagger/src/ci/fleet_coverage.py` | Finds every repo that pins a module from here, so none is left unchecked. |
| `modules/portfolio-foundation/` | Shared module: exact source identity, repo safety checks, artifact envelopes, "is `main` green at this SHA" evidence, and release lineage checks for publisher jobs. |
| `modules/cloudflare-pages/` | Shared module: checks and deploys a Cloudflare Pages site, then confirms the live site serves that deployment. |
| `modules/python-package/` | Shared module: audits, builds and checks a Python wheel and sdist. It never uploads to PyPI. |
| `tests/dagger/python_consumer/`, `tests/dagger/typescript_consumer/` | Tiny consumer modules that prove the shared modules work from Python and TypeScript code. |
| `.github/workflows/` | Four thin workflows that only call Dagger. |

## Why consumers pin an exact commit

A consumer installs a shared module at a full 40-character commit SHA, for example
`github.com/hseshadr/ci/modules/portfolio-foundation@<sha>`. Dagger writes both `source` and
`pin` into the consumer's `dagger.json`. The exact commit means a reviewer approved exactly
those bytes, and a consumer does not change behavior when this repo's `main` moves. Upgrading
is a deliberate pull request in the consumer. `main`, `latest`, tags and short SHAs are
rejected by the policy check.

This repo itself uses its foundation module as a local, same-tree dependency (see
[`dagger.json`](../dagger.json)), so central CI always tests the module bytes in the current
commit.

The full install steps, a realistic consumer flow, secrets rules and rollback are in
[dagger-modules.md](dagger-modules.md).

## Workflows

Only four workflows exist:

| Workflow | Triggered by | Dagger function |
|---|---|---|
| `dagger.yml` | pull request, push to `main`, manual | `ci` (and `fleet` after a push to `main`) |
| `consumer-drift.yml` | push to `main`, daily, manual | `fleet` |
| `dagger-security.yml` | weekly, manual | `security` |
| `module-canary.yml` | weekly, manual | `module-fixtures` |

Each job uses exactly two pinned actions:

1. `actions/checkout` with `persist-credentials: false`
2. `dagger/dagger-for-github` pinned to a full commit SHA and Dagger 0.21.8

The module receives source through an explicit typed `dagger.Workspace` and stores an explicit
`dagger.Directory`. Credentials cross public Dagger functions as `dagger.Secret`. Generated SDK
bytes are mounted separately as toolchain data, so they cannot silently expand the
caller-selected source snapshot.

## What `dagger call ci` checks

- Ruff formatting and linting
- strict mypy
- Xenon Grade A complexity
- pytest with at least 90% core coverage (and 90% branch coverage)
- locked dependency audit
- actionlint
- Zizmor, failing on medium or high findings
- Gitleaks over both the exact source snapshot and complete Git history

The same graph runs locally and in GitHub. Hosted calls bind full-history scanning to
`${{ github.sha }}`.

## What `dagger call fleet` checks

`fleet` reads the exact current `main` of every consumer repo from GitHub (plus this repo
with `--include-central`). The consumers are:

- `agentic-context-service`
- `agentic-saga`
- `almamesh`
- `aml-filter`
- `assay`
- `edge-proc`
- `edge-reco`
- `edgeproc-core`
- `privacy-core`

It also fails if any other `hseshadr` repository pins a `github.com/hseshadr/ci` module but
is missing from that list (`uncovered-consumer`; see
[Fleet coverage](dagger-modules.md#fleet-coverage)). Any inaccessible or incomplete evidence
is an error: an unreadable repository becomes an `evidence-unreadable` finding rather than
stopping the scan, and a scan that inspected nothing cannot report success.

For every consumer it requires:

- every repository-authored workflow job is thin pinned Dagger ingress;
- source is an explicit typed `Directory` or `Workspace`;
- Dagger-exposed credential arguments are typed `Secret`;
- branch protection is strict and requires only `Dagger`, bound to GitHub Actions app ID
  `15368`;
- the required `Dagger` check succeeded on the exact current `main` SHA;
- managed CodeQL default setup is disabled;
- no independent execution app controls the build or deploy path;
- no live workflow executes a retired `hseshadr/ci` reusable control;
- every pinned central module is on `hseshadr/ci` `main` and at or after its reviewed
  required-minimum floor ([details](dagger-modules.md#required-minimum-pins));
- no `dagger-for-github` input pastes `${{ inputs.* }}`, `${{ github.event.* }}` or
  `${{ github.head_ref }}` into the shell (`dagger-args-expression`); pass it through `env:`.

GitGuardian is allowed only as a non-required advisory observer.

The consumer list lives in `.dagger/src/ci/fleet.py`.

### Approved transport exceptions

The policy recognizes only two non-Dagger transports around a release candidate:

- a pinned `upload-artifact` step after a successful unprivileged Dagger candidate;
- a source-free privileged job that downloads that exact run/SHA artifact, then either invokes
  the official PyPI OIDC action with attestations or an exact-SHA remote Dagger npm publisher
  with typed GitHub OIDC URL and token inputs.

Every publisher job must open with the central `release-lineage` / `release-provenance`
step from `portfolio-foundation` (`publisher-lineage` finding otherwise; see
[Publisher lineage](dagger-modules.md#publisher-lineage)). Publisher bridges reject checkout, setup, install, build, test, free-form shell, mutable
references, excess permissions, wrong artifact identity, and missing provenance.

This repository does not publish packages and its CI never dispatches a registry mutation.

## The `fleet` token

`CONSUMER_DRIFT_TOKEN` must be able to read every consumer repository. It needs:

- Contents: read
- Administration: read
- Checks: read
- Pull requests: read

Administration read is required for effective branch protection and CodeQL default-setup
metadata. Checks read is required for exact-SHA app-bound check evidence. The scanner stops
with a permission-specific message when either is unavailable.

Locally, `gh auth token` usually works for your own repos.

## Scope

This is a control-plane repository, not a template catalog. It publishes no reusable
workflows, composite actions or copyable CI templates (older ones were retired; they remain in
Git history and old tags, see [CHANGELOG](../CHANGELOG.md)). Consumer-specific application
builds stay in each consumer; consumers compose the foundation, Pages and Python package
modules instead of copying shared release mechanics. Privileged publisher jobs stay source-free
and use official registry actions outside Dagger. Dependabot may propose dependency updates,
but its pull requests are never auto-merged.

## Design history

- [Architecture design (2026-08-27)](superpowers/specs/2026-08-27-dagger-lego-architecture-design.md):
  why the shared modules exist and how they are versioned.
- [Foundation and EdgeReco canary plan (2026-08-27)](superpowers/plans/2026-08-27-dagger-lego-edge-reco-canary.md):
  the first rollout plan.
