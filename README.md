# hseshadr/ci

The shared CI code for Harish Seshadri's own repositories: three Dagger modules they install, and a daily check that each repo still runs its CI the same way.

**Try it without cloning:** `dagger -m github.com/hseshadr/ci/modules/portfolio-foundation@faf55ac51dfeb6bad274988941e9215117e5259e functions`

[Dagger](https://dagger.io) runs CI steps as code inside containers, so the same steps run on
a laptop and in GitHub Actions. Harish's projects (almamesh, aml-filter, assay, edge-proc,
edge-reco and others) all need the same few things: check the source is safe, build a
Python package, deploy a static site to Cloudflare Pages. Copying that code into each repo
means many copies drifting apart. This repo holds one copy, as Dagger modules each repo
installs at an exact commit.

It also watches the other repos. Once a day it reads the `main` branch of each repo on its
list from GitHub, and fails if a workflow runs anything outside Dagger, branch protection
has drifted, a repo pins a module older than the minimum version allowed, or the latest
`main` commit is not green. It also fails if a repo installs one of these modules but is
missing from that list.

**Technical docs:** [Architecture](docs/ARCHITECTURE.md) · [Getting started](docs/GETTING_STARTED.md) · [Using the modules](docs/dagger-modules.md)

## How a repo uses it

A repo adds a module to its own `dagger.json`, pinned to one commit of this repo. This is
aml-filter's, as it is today:

```json
"dependencies": [
  {
    "name": "cloudflare-pages",
    "source": "github.com/hseshadr/ci/modules/cloudflare-pages@dd19871486588b1582e432b7bc1f2cfffb296340",
    "pin": "dd19871486588b1582e432b7bc1f2cfffb296340"
  },
  {
    "name": "foundation",
    "source": "github.com/hseshadr/ci/modules/portfolio-foundation@dd19871486588b1582e432b7bc1f2cfffb296340",
    "pin": "dd19871486588b1582e432b7bc1f2cfffb296340"
  }
]
```

Its own Dagger code then calls the modules like any other function, for example
`dag.foundation().guard(...)` before a build and `dag.cloudflare_pages().deploy(...)` to
ship the site. Its GitHub workflow stays tiny: check out the code, then call Dagger.

The three modules:

| Module | What it does | Used by |
|---|---|---|
| `portfolio-foundation` | Ties a build to one exact commit, runs secret and workflow scans over the full Git history, and wraps build output with a record of where it came from. | all nine repos |
| `cloudflare-pages` | Deploys a built site to Cloudflare Pages once, then checks the live site is serving that exact deployment. | almamesh, aml-filter, edge-reco |
| `python-package` | Audits dependencies, builds the wheel and sdist, and checks the version matches the tag. It does not upload to PyPI; a separate job does that with PyPI's official action. | edge-proc, edgeproc-core, agentic-context-service, agentic-saga |

Upgrading is a pull request in the consumer that changes the commit in both `source` and
`pin`. Nothing changes for a consumer when this repo's `main` moves.

## Try it

You need Docker and [Dagger 0.21.8](https://docs.dagger.io/install).

1. List what the foundation module offers, straight from GitHub (about 15 seconds):

   ```bash
   dagger -m github.com/hseshadr/ci/modules/portfolio-foundation@faf55ac51dfeb6bad274988941e9215117e5259e functions
   ```

   ```text
   Name              Description
   envelope          Wrap a typed artifact with deterministic evidence.
   green-main        Resolve exact-green main evidence using a typed secret.
   guard             Apply repository security checks to a bound source.
   source            Bind a supplied workspace to a repository identity.
   verify-envelope   Revalidate and return only a closed envelope's artifact subtree.
   ```

2. Ask it whether a repo's `main` is green right now. This is the same call aml-filter
   makes before it deploys:

   ```bash
   export GITHUB_TOKEN="$(gh auth token)"
   dagger -m github.com/hseshadr/ci/modules/portfolio-foundation@faf55ac51dfeb6bad274988941e9215117e5259e \
     call green-main --github-token=env:GITHUB_TOKEN --repository=hseshadr/aml-filter serialization
   ```

   Real output from 25 Sep 2026, trimmed:

   ```json
   {"app_id":15368,"branch":"main","check_name":"Dagger",
    "commit_sha":"4392391bde505a8367fea87723e4ee8ef7bc4895",
    "repository":"hseshadr/aml-filter","workflow_path":".github/workflows/dagger.yml",
    "workflow_run_id":"36177431244", ...}
   ```

   `commit_sha` is aml-filter's current `main`, and the `Dagger` check passed on it. If the
   check had not passed, the call would fail instead of returning.

3. Run this repo's own checks from a clone (about 8 minutes):

   ```bash
   git clone https://github.com/hseshadr/ci && cd ci
   dagger call ci --github-token=env:GITHUB_TOKEN
   ```

   Success ends with `central Dagger gate passed`.

## How it works

Every workflow in this repo and in the consumer repos does two things: check out the code,
and call one Dagger function. All the real work happens in Dagger. `dagger call ci` runs
linting, strict type checks, tests with a 90% coverage floor, a dependency audit, workflow
security scans, and a secret scan over the full Git history. It also builds two tiny consumer
modules, one in Python and one in TypeScript, to prove the shared modules install and run
from both. `dagger call fleet` reads every consumer repo's `main` through the GitHub API and
applies the rules in `.dagger/src/ci/fleet_policy.py`. If any repo cannot be read, that is a
failure, not a skip.

## What it does not do

- **It is for Harish's repos.** The modules assume his setup: GitHub, Cloudflare Pages,
  PyPI, Dagger 0.21.8. You can read and borrow from them, but there is no support promise.
- **No reusable GitHub workflows or composite actions.** The old ones were removed; they
  are in Git history and old tags only.
- **It never publishes anything.** No package, tag or registry upload comes from this repo.
  `python-package` builds a package; publishing is a separate job in the consumer.
- **No automatic upgrades.** Consumers stay on their pinned commit until someone opens a PR.
- **Dependabot PRs are never auto-merged.**

## Develop

The quick local loop (about 1 minute once Dagger has generated the SDK):

```bash
dagger develop
uv run --directory .dagger poe gate
```

The full check, the same one CI runs, is `dagger call ci --github-token=env:GITHUB_TOKEN`.
On a branch, push first and add `--commit-sha=$(git rev-parse HEAD)`.
Each module under `modules/` has its own `poe gate` too. See
[Getting started](docs/GETTING_STARTED.md) for versions, the code map, and a worked first
change.

## More detail

- [Getting started](docs/GETTING_STARTED.md): set up, run the checks, make a first change,
  open a PR.
- [Architecture](docs/ARCHITECTURE.md): the four workflows, exactly what `ci` and `fleet`
  check, the allowed publishing exceptions, and the token `fleet` needs.
- [Interactive runtime map](docs/architecture/index.html).
- [Using the modules](docs/dagger-modules.md): installing at an exact commit, a full
  consumer example, secrets, Pages safety and rollback.
- [Design (2026-08-27)](docs/superpowers/specs/2026-08-27-dagger-lego-architecture-design.md)
  and the [first rollout plan](docs/superpowers/plans/2026-08-27-dagger-lego-edge-reco-canary.md):
  why the shared modules exist.
- [CHANGELOG](CHANGELOG.md): what changed, including what was removed.

## License

MIT. See [LICENSE](LICENSE).
