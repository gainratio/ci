# Getting started

From a fresh clone to a green local build and your first change. Every command here was run
from a fresh clone on 25 Sep 2026 (macOS, Apple silicon); times are from that run.

## 1. Prerequisites

| Tool | Version | How to get it |
|---|---|---|
| Docker (or another engine Dagger supports) | any recent; tested with 29.2 | [Docker Desktop](https://docs.docker.com/get-docker/) |
| Dagger CLI | **exactly 0.21.8** (CI and every `dagger.json` pin `v0.21.8`) | `curl -fsSL https://dl.dagger.io/dagger/install.sh \| DAGGER_VERSION=0.21.8 BIN_DIR=/usr/local/bin sh` |
| uv | 0.8 or later; tested with 0.8.5 | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Python | 3.13 (uv downloads it for you) | nothing to do |
| GitHub CLI | any; used for a token | `brew install gh`, then `gh auth login` |

Traps we hit:

- **`uv run` fails on a fresh clone** with `Failed to generate package metadata for
  dagger-io==0.0.0 @ editable+sdk ... Distribution not found at: .../.dagger/sdk`. The Python
  projects depend on a generated Dagger SDK in `.dagger/sdk/`, which is not committed. Run
  `dagger develop` once in the repo root (and once in each module you work on) first.
- **Dagger prints "A new release of dagger is available".** Ignore it. Do not upgrade past
  0.21.8 unless you are upgrading every pin on purpose. `export DAGGER_NO_NAG=1` hides it.
- **`dagger call ci` on a branch fails with `SourceMismatchError: workspace does not match
  exact commit`.** Without `--commit-sha`, the history scan checks your files against
  GitHub's `main`, so any change fails. Commit, push your branch, then pass
  `--commit-sha=$(git rev-parse HEAD)`. The working tree must be clean and match that commit.
- **`ci` also runs files you have not committed yet**, including new tests. A test that
  fails there but not in your editor is usually a new file you forgot about.

## 2. Clone, set up, run the tests

```bash
git clone https://github.com/hseshadr/ci
cd ci
dagger develop                          # generates .dagger/sdk (about 10 s)
uv run --directory .dagger poe gate     # lint, types, complexity, tests, coverage
```

Success ends with a line like `224 passed` and a coverage table with `TOTAL ... 96%`, and no
`Error:` line. Took 1 min 12 s on the fresh clone (most of it is uv installing packages the
first time).

## 3. The full check (what CI runs)

```bash
export GITHUB_TOKEN="$(gh auth token)"
dagger call ci --github-token=env:GITHUB_TOKEN
```

On a clean clone of `main` that is all you need. On a branch, commit and push first, then
add `--commit-sha=$(git rev-parse HEAD)` (see the traps above).

This is the same call the `Dagger` job in `.github/workflows/dagger.yml` makes. It runs the
root `poe gate`, the dependency audit, the foundation module's repository checks (actionlint,
Zizmor, Gitleaks over the full history), and both consumer fixtures under `tests/dagger/`.
Success prints `central Dagger gate passed`. Took 8 min 11 s on the fresh clone.

The daily cross-repo check is `dagger call fleet --github-token=env:GITHUB_TOKEN`. It needs a
token that can read the admin settings of every consumer repo (see
[Architecture](ARCHITECTURE.md#the-fleet-token)), so most contributors never run it locally.

## 4. Map of the code

| Path | What it is |
|---|---|
| `.dagger/src/ci/main.py` | Root Dagger module: `ci`, `security`, `fleet`, `module-fixtures`. |
| `.dagger/src/ci/fleet_policy.py` | The rules consumer repos must follow. Pure Python, easy to test. |
| `.dagger/src/ci/github_fleet.py` | Reads each repo's real state from the GitHub API. |
| `.dagger/src/ci/fleet.py` | The list of consumer repos and their expected branch protection. |
| `.dagger/src/ci/fleet_coverage.py` | Finds every repo that pins a module from here, so none is left off that list. |
| `.dagger/tests/` | Tests for all of the above, plus contract tests for docs and workflows. |
| `modules/portfolio-foundation/` | Shared module: exact-commit identity, repo checks, artifact envelopes, green-main evidence. |
| `modules/cloudflare-pages/` | Shared module: Cloudflare Pages deploy, live check and rollback. |
| `modules/python-package/` | Shared module: Python wheel and sdist build and checks. |
| `tests/dagger/*_consumer/` | Tiny Python and TypeScript modules that install the shared modules, to prove they work from both languages. |
| `.github/workflows/` | Four thin workflows; each only checks out and calls Dagger. |

Each module under `modules/` is its own Python project with its own `.dagger/pyproject.toml`,
tests and `poe gate`.

## 5. Make your first change

A typical change is a small fix inside one shared module. PR #53 is a real example: it taught
`python-package` to accept ZIP64 wheels. It touched two files:

- `modules/python-package/.dagger/src/python_package/distribution_probe.py`
- `modules/python-package/.dagger/tests/test_distribution_probe.py`

The steps:

1. Branch: `git switch -c fix/python-package-<short-name>`.
2. Set up the module once (about 10 s):

   ```bash
   (cd modules/python-package && dagger develop)
   ```

3. Write the failing test first in the module's `tests/` folder, and run just that file:

   ```bash
   uv run --directory modules/python-package/.dagger pytest tests/test_distribution_probe.py -q --no-cov
   ```

   Watch it fail for the reason you expect, then make the smallest change in `src/` that
   makes it pass. A single file runs in under a second.

4. Run the module's full check (about 1 minute):

   ```bash
   uv run --directory modules/python-package/.dagger poe gate
   ```

   Each module has a 90% line and branch coverage floor and Radon grade A complexity, like
   the root.

5. Commit, push the branch, and run the root check. It also builds the Python and
   TypeScript consumer fixtures against your changed module (about 4 minutes with a warm
   cache):

   ```bash
   git push -u origin HEAD
   dagger call ci --github-token=env:GITHUB_TOKEN --commit-sha=$(git rev-parse HEAD)
   ```

6. After your PR merges, consumers do **not** pick it up automatically. In each consumer repo
   that needs the change, reinstall the module at the new `main` commit so both `source` and
   `pin` in its `dagger.json` change, then open a PR there. The exact commands are in
   [Using the modules](dagger-modules.md#quickstart).

Changing a rule for consumer repos works the same way, with the code in
`.dagger/src/ci/fleet_policy.py` and the tests in `.dagger/tests/test_fleet_policy.py`.

## 6. Open a PR

- **Branch names** follow the change type: `feat/...`, `fix/...`, `docs/...`, `ci/...`.
  Keep the branch short-lived; delete it after merge.
- **Commit and PR titles** use Conventional Commits with the module as scope, for example
  `fix(python-package): accept ZIP64 wheels`.
- **CI** runs one required check, `Dagger` (`dagger call ci`). Branch protection requires it
  to pass. After merge, `main` also runs the cross-repo check.
- **Reviewers look for:** a test that failed before the change; no drop in coverage or
  complexity grade; typed inputs (`dagger.Directory`, `dagger.Secret`) at every public Dagger
  function; no new workflow steps outside Dagger; and a CHANGELOG line for anything a
  consumer would notice.
- Dependabot PRs are reviewed by hand and never auto-merged.
