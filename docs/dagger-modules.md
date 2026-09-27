# Reusable Dagger modules

**TL;DR:** Install each shared module at one exact central commit, pass source and credentials
through typed Dagger boundaries, and let the module fail closed before deployment.

A **Dagger lego** is a typed reusable Dagger module installed at an immutable commit SHA. The
SHA is the trust boundary: reviewers approve exact module bytes, and every consumer runs those
same bytes until it deliberately upgrades.

## Quickstart

Prerequisites: Git, Bash, Dagger 0.21.8, and an existing Dagger module in the consumer repository.
After the guarded central release is merged, run this from the consumer module root:

```bash
set -euo pipefail

FOUNDATION_SHA="$(
  git ls-remote https://github.com/hseshadr/ci.git refs/heads/main | cut -f1
)"
if [[ ! "$FOUNDATION_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'central main did not resolve to one lowercase 40-character SHA\n' >&2
  exit 1
fi

dagger install \
  "github.com/hseshadr/ci/modules/portfolio-foundation@$FOUNDATION_SHA" \
  --name foundation
dagger develop
```

Review the captured SHA before committing. The resulting dependency in `dagger.json` has this
shape (the example SHA is illustrative):

```json
{
  "dependencies": [
    {
      "name": "foundation",
      "source": "github.com/hseshadr/ci/modules/portfolio-foundation@0123456789abcdef0123456789abcdef01234567",
      "pin": "0123456789abcdef0123456789abcdef01234567"
    }
  ]
}
```

`dagger install` generates both fields. Review and commit them together: `pin` must equal the
40-lowercase-hex suffix of `source`. Fleet policy rejects a missing or different generated pin,
plus `main`, `latest`, version tags, shortened SHAs, uppercase hexadecimal, and every other
mutable or non-canonical dependency reference.

### Required minimum pins

An exact pin is not enough on its own: a consumer can stay pinned below a fix it must have, and
nothing breaks until a release gate trips on the old bug. Fleet policy therefore keeps a
reviewed floor per central module in `REQUIRED_MINIMUM` (`.dagger/src/ci/fleet_policy.py`):

| Module | Floor | Why |
| --- | --- | --- |
| `portfolio-foundation` | `dd19871486588b1582e432b7bc1f2cfffb296340` | `greenMain` tolerates GitHub rerun `created_at` skew (#46); older pins can block a release. |

`cloudflare-pages` and `python-package` load `portfolio-foundation` from their own revision, so
the foundation floor also applies to pins of those modules.

For every floored module revision in a consumer's resolved Dagger graph, the scanner asks
GitHub `compare/<floor>...<pin>` and `compare/<pin>...main` on `hseshadr/ci`. Both must answer
`ahead` or `identical`: the pin is at or after the floor **and** on central `main`. Anything
else (`behind`, `diverged`, no common history, or missing evidence) is a
`pin-below-required-minimum` finding that fails the check.

**When you ship a fix every consumer must run, raise the floor in the same PR.** Set the
module's `REQUIRED_MINIMUM` entry to the fix commit, update the literal pinned in
`.dagger/tests/test_fleet_minimum_pin.py`, and add a row above. Non-mandatory changes do not
move the floor. After merge, the fleet scan names every consumer still below it, and each one
needs a bump PR.

This remote-pin rule applies to consumers. Central CI intentionally keeps its foundation as a
local same-tree dependency so it validates the module bytes in the current commit; a remote
self-pin would instead validate an older published copy.

Pages consumers install the provider from the **same reviewed commit** and regenerate once:

```bash
dagger install \
  "github.com/hseshadr/ci/modules/cloudflare-pages@$FOUNDATION_SHA" \
  --name cloudflare-pages
dagger develop
```

Python package consumers install the candidate builder from that same reviewed commit:

```bash
dagger install \
  "github.com/hseshadr/ci/modules/python-package@$FOUNDATION_SHA" \
  --name python-package
dagger develop
```

The public module accepts only source, repository, commit, canonical project, central module,
workflow run, and run-attempt identities. There is no public image, path, command, tag, registry,
or publisher input. It derives `vMAJOR.MINOR.PATCH` from the built wheel and sdist metadata,
requires that exact public Git tag to resolve to the requested commit, and produces a Foundation
envelope containing only `dist/` plus `metadata/python-candidate.json`.

The build is dependency-frozen and backend-agnostic: the consumer locks its PEP 517 backend in a
dependency group, the Lego installs that frozen graph without installing the project, and the
build then runs without network-resolved isolation. For Hatchling, add this before `uv lock`:

```toml
[dependency-groups]
build = ["hatchling==1.27.0"]
```

Use the equivalent exact backend requirement for Flit, setuptools, or another backend. Merely
declaring the backend under `[build-system].requires` is insufficient because that declaration
does not place it in the frozen project environment.

Candidate construction must name the exact successful Dagger run attempt that made the commit
green. From a consumer module that exposes the same closed function, this manual proof fetches
that identity and runs the candidate locally:

```bash
set -euo pipefail
export GITHUB_TOKEN="$(gh auth token)"
REPOSITORY="owner/python-project"
PROJECT="python-project"
WORKFLOW="dagger.yml"
CENTRAL_SHA="$(jq -er '.dependencies[] | select(.name == "python-package") | .pin' dagger.json)"
CONSUMER_SHA="$(git rev-parse HEAD)"
GREEN_JSON="$(
  gh api --method GET "repos/$REPOSITORY/actions/workflows/$WORKFLOW/runs" \
    -f branch=main -f head_sha="$CONSUMER_SHA" -f status=success -f per_page=1
)"
GREEN_RUN_ID="$(jq -er '.workflow_runs[0].id' <<<"$GREEN_JSON")"
GREEN_RUN_ATTEMPT="$(jq -er '.workflow_runs[0].run_attempt' <<<"$GREEN_JSON")"
test "$(jq -er '.workflow_runs[0].head_sha' <<<"$GREEN_JSON")" = "$CONSUMER_SHA"

dagger call candidate \
  --source=. \
  --github-token=env:GITHUB_TOKEN \
  --repository="$REPOSITORY" \
  --commit-sha="$CONSUMER_SHA" \
  --project-name="$PROJECT" \
  --central-module-sha="$CENTRAL_SHA" \
  --workflow-run-id="$GREEN_RUN_ID" \
  --run-attempt="$GREEN_RUN_ATTEMPT" \
  envelope export --path=release-candidate
```

The Dagger job is unprivileged: it receives a read-only GitHub token only for exact-green
evidence, never an OIDC token or PyPI credential. The unprivileged candidate workflow uploads the
envelope as
`python-candidate-${{ github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}`. A separate
`workflow_run` bridge then binds its download to that producing run and SHA. This privileged
GitHub Environment job has no checkout, setup, install, build, test, shell, or Dagger step:

```yaml
name: Publish Python candidate
on:
  workflow_run:
    workflows: [Python package candidate]
    types: [completed]
permissions: {}
jobs:
  publish:
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'workflow_dispatch' &&
      github.event.workflow_run.head_branch == github.event.repository.default_branch
    environment: release
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      id-token: write
    steps:
      - uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0
        with:
          name: python-candidate-${{ github.event.workflow_run.head_sha }}-${{ github.event.workflow_run.id }}-${{ github.event.workflow_run.run_attempt }}
          path: candidate
          github-token: ${{ github.token }}
          run-id: ${{ github.event.workflow_run.id }}
      - uses: pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33 # v1.14.2
        with:
          packages-dir: candidate/artifact/dist
          attestations: true
```

GitHub/PyPI Trusted Publishing remains configured against this concrete consumer workflow and
environment. Do not put the OIDC publication boundary in a reusable workflow or Dagger module.

## One realistic consumer flow

This complete Python Dagger object shows the trust chain without hiding any identity. Its release
function is async and non-cacheable; every credential remains a typed `dagger.Secret`. Replace the
illustrative constants with the exact consumer and Pages target before running it.

```python
import dagger
from dagger import dag, function, object_type

REPOSITORY = "owner/service"
REPOSITORY_URL = "https://github.com/owner/service.git"
COMMIT_SHA = "0123456789abcdef0123456789abcdef01234567"
CONSUMER = f"{REPOSITORY}@{COMMIT_SHA}"
ALLOWED_ROOTS = ["dist"]


@object_type
class Delivery:
    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]
    async def release(
        self,
        artifact: dagger.Directory,
        github_token: dagger.Secret,
        cloudflare_api_token: dagger.Secret,
        cloudflare_account_id: dagger.Secret,
        workflow_run_id: str,
        run_attempt: int,
    ) -> str:
        producing_identity = f"{COMMIT_SHA}:{workflow_run_id}"
        history = dag.git(REPOSITORY_URL).commit(COMMIT_SHA).tree(
            depth=0, include_tags=True
        )
        source = dag.foundation().source(history, REPOSITORY, COMMIT_SHA)
        await dag.foundation().guard(source, REPOSITORY, COMMIT_SHA).sync()
        envelope = dag.foundation().envelope(
            artifact, CONSUMER, producing_identity, ALLOWED_ROOTS
        )
        verified = dag.foundation().verify_envelope(
            envelope, CONSUMER, producing_identity, ALLOWED_ROOTS
        )
        await verified.directory("dist").digest()
        evidence = dag.cloudflare_pages().deploy(
            envelope=envelope,
            github_token=github_token,
            cloudflare_api_token=cloudflare_api_token,
            cloudflare_account_id=cloudflare_account_id,
            workflow_run_id=workflow_run_id,
            run_attempt=run_attempt,
            repository=REPOSITORY,
            project="service-production",
            production_branch="main",
            live_domain="service.example.com",
            deploy_root="dist",
            domains=["www.service.example.com"],
            consumer_identity=CONSUMER,
            producing_identity=producing_identity,
            allowed_roots=ALLOWED_ROOTS,
        )
        return await evidence.deployment_id()
```

Do not call `plaintext()`, put a token in a string argument, or reconstruct provider authorization
from JSON. The returned deployment ID forces evaluation of the typed provider result.

The provider resolves exact-current-`main` green Dagger evidence internally. A caller cannot
authorize a deployment with stale or caller-authored evidence.

### Opt in to Pages Functions

Static consumers keep the call above unchanged. A Functions consumer authenticates exactly two
ordered roots, sets the deploy root to `dist`, and opts in on the same deploy transaction:

```python
ALLOWED_ROOTS = ["dist", "functions"]

evidence = dag.cloudflare_pages().deploy(
    # The other required arguments are identical to the complete flow above.
    envelope=envelope,
    deploy_root="dist",
    allowed_roots=ALLOWED_ROOTS,
    pages_functions=True,
)
evidence_id = await evidence.id()
reloaded = dag.load_cloudflare_pages_deployment_evidence_from_id(evidence_id)
return await reloaded.deployment_id()
```

Materialize the typed evidence ID once and reload that object for downstream fields; do not add
separate caller-side `preflight` or `verify` transactions. TypeScript uses the generated final
option `{ pagesFunctions: true }` and reloads with
`dag.loadCloudflarePagesDeploymentEvidenceFromID(evidenceId)`.

The authenticated `functions` root must be self-contained. Before any Cloudflare API request or
upload, the provider removes consumer package-manager inputs, `node_modules`, and Wrangler config;
compiles with pinned Wrangler 4.103.0 from fixed `/project/functions`; and rejects missing imports,
build failures, or a pre-existing `dist/_worker.js` or `dist/_routes.json`. Wrangler emits esbuild
metadata into private scratch space; the provider rejects any resolved input outside authenticated
`dist` and `functions`, its private generated-route scratch directory, and the one fixed Wrangler
template plus its exact pinned router input. Wrangler emits directory-mode module output; the
provider requires a bounded `_worker.js/index.js`, rejects multipart upload serialization and any
module path that escapes the generated tree, and requires every auxiliary module's content to match
an authenticated `dist` or `functions` input. It stages only that `_worker.js` module directory plus
`_routes.json` into authenticated `dist`. It then performs the same single direct upload and
deployment-ID convergence used for static sites. Static mode retains its exact arguments and
ordering.

## Secrets and the production environment

GitHub Actions injects credentials into Dagger as typed `Secret` arguments. After a repository
adopts the Pages provider, put `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ACCOUNT_ID` in a
main-restricted `production` GitHub Environment and bind the deploy job to that environment.
Keep the workflow's `GITHUB_TOKEN` permission-minimal and pass it through the same typed boundary.

Fleet policy validates only secret **names**, environment binding, and typed use. It never reads
secret values. GitHub does not reveal existing secret values, so moving repository secrets into
the Environment requires secure re-entry; delete the old repository secrets only after an
environment-backed production proof succeeds.

Secret values never belong in command-line arguments, logs, Dagger outputs, artifacts, or
persistent caches. The modules mount provider credentials and responses only in ephemeral Dagger
storage and return non-secret evidence.

## Pages delivery safety and ordering

Every provider entrypoint requires a foundation-verified envelope and exact-current-`main` green
Dagger evidence for the requested GitHub Actions `run_id` and `run_attempt`. The envelope is
revalidated before provider transport, so changed bytes, modes, roots, identities, or checksums
fail locally.

A deployment then follows one bounded sequence:

1. Require exact-current-`main` green Dagger evidence and the verified artifact envelope.
2. Read the Pages project and recent production deployments, disable Git integration with one
   non-retried update, and immediately read the project back.
3. Run one direct upload with pinned Wrangler 4.103.0, using only the verified `deploy_root`.
4. Bind convergence to the deployment ID created by that upload; an older same-SHA deployment
   cannot satisfy the attempt.
5. Verify the created Pages hostname, source SHA, and required project-domain bindings before
   returning non-secret evidence.

Wrangler has no Pages dry-run. Tests therefore use a local TLS mock that exercises the real
request and Wrangler boundaries without access to Cloudflare and cannot mutate Cloudflare. The
cross-language fixtures also tamper with an envelope and prove rejection occurs before GitHub or
Cloudflare transport.

## Roll back after a failed live smoke check

**TL;DR:** record what production serves before you deploy. If the post-deploy smoke check fails,
call `rollback` with that ID, then fail the job anyway. Production recovers, and the red run still
tells you the release was bad.

Two module functions cover this. Both take the same typed credentials as `deploy`:

| Function | Writes? | Returns |
| --- | --- | --- |
| `previous-production-deployment(cloudflare-api-token, cloudflare-account-id, project)` | No | `project`, `deployment-id`, `deployment-url` of the deployment production serves **now** |
| `rollback(cloudflare-api-token, cloudflare-account-id, project, deployment-id="")` | One `POST .../deployments/{id}/rollback` | `project`, `from-deployment-id`, `to-deployment-id`, `live-deployment-id`, `live-deployment-url` |

`previous-production-deployment` is "previous" from the point of view of the deploy you are about
to run: call it before `deploy`, and the ID it returns is what `rollback` should restore. With no
`deployment-id`, `rollback` picks the newest successful production deployment older than the one
live now.

`rollback` fails closed. It refuses, before any write, when:

- the project has no live production deployment, or the target is not in the 10 most recent
  production deployments;
- the target is a preview deployment, is not a successful `deploy` stage, or belongs to another
  project;
- the target is already live (a no-op must be explicit, so this raises instead of passing);
- no `deployment-id` is given and there is no older successful production deployment.

After the POST it requires the response to name the target, then re-reads the project until its
live (`canonical_deployment`) ID equals the target, with 1, 2, 4, 8 second delays under a 60-second
deadline. If production never serves the target, it raises. A Cloudflare 4xx or 5xx raises a
sanitized `CloudflareApiError`, and the POST is never retried.

Wire it in the consumer's Dagger release function:

```python
pages = dag.cloudflare_pages()
before = pages.previous_production_deployment(
    cloudflare_api_token=cloudflare_api_token,
    cloudflare_account_id=cloudflare_account_id,
    project=PROJECT,
)
target = await before.deployment_id()  # 1. record the rollback target

evidence = pages.deploy(...)  # 2. deploy exactly as above
deployed = await evidence.deployment_id()

if not await live_smoke_passes(LIVE_URL):  # 3. the consumer's own smoke check
    rolled = pages.rollback(  # 4. restore the recorded target
        cloudflare_api_token=cloudflare_api_token,
        cloudflare_account_id=cloudflare_account_id,
        project=PROJECT,
        deployment_id=target,
    )
    live = await rolled.live_deployment_id()
    # 5. fail the job: the release was bad even though production recovered
    raise RuntimeError(f"live smoke failed for {deployed}; production rolled back to {live}")
```

Record the target before `deploy`, not after: once the new deployment is live, "the one before it"
is only a guess. If `rollback` itself raises, the job must still fail. Production then needs a
human, and the error names the reason.

What the module does not prove: it checks the rollback through the Cloudflare API (the project's
live deployment ID), the same way `deploy` checks convergence. It does not fetch the custom
domain. The consumer's smoke check should run again after a rollback if it needs that proof.

## Composition proofs

Warm proof from a repository checkout:

```bash
set -euo pipefail
(cd tests/dagger/python_consumer && DAGGER_NO_NAG=1 dagger call contract)
(cd tests/dagger/typescript_consumer && DAGGER_NO_NAG=1 dagger call contract)
DAGGER_NO_NAG=1 dagger call module-fixtures
```

The first two commands exercise the generated Python and TypeScript clients independently. The
root command dynamically loads both consumer modules through Dagger's typed module API.

For an isolated cold proof, start an engine with its own empty state volume, run the same root
graph, and remove only those named resources:

```bash
set -euo pipefail
COLD_ENGINE='registry.dagger.io/engine@sha256:c9c1a0a6546380983d42e8d75adde070a2a0935c54b498d8bc9045d9cb2ee336'
COLD_NAME="dagger-module-cold-$$"
COLD_VOLUME="${COLD_NAME}-state"

cleanup() {
  docker rm --force "$COLD_NAME" >/dev/null 2>&1 || true
  docker volume rm "$COLD_VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$COLD_VOLUME" >/dev/null
docker run --detach --privileged --name "$COLD_NAME" \
  --volume "$COLD_VOLUME:/var/lib/dagger" \
  "$COLD_ENGINE" >/dev/null
_EXPERIMENTAL_DAGGER_RUNNER_HOST="container://$COLD_NAME" \
  DAGGER_NO_NAG=1 dagger call module-fixtures
```

Do not prune or reset a shared engine, cache, image, container, or volume to simulate cold state.

## Quality gates

Run the root and both module contracts before proposing an upgrade:

```bash
set -euo pipefail
uv run --directory .dagger poe gate
uv run --directory .dagger poe audit
uv run --directory modules/portfolio-foundation/.dagger poe gate
uv run --directory modules/portfolio-foundation/.dagger poe audit
uv run --directory modules/cloudflare-pages/.dagger poe gate
uv run --directory modules/cloudflare-pages/.dagger poe audit
uv run --directory modules/python-package/.dagger poe gate
uv run --directory modules/python-package/.dagger poe audit
DAGGER_NO_NAG=1 dagger call module-fixtures
git diff --check
```

The hosted release additionally requires exact-head root CI, module fixtures, security, and
authoritative fleet evidence before merge, followed by exact-main evidence after merge. Revalidate
the merged SHA against `^[0-9a-f]{40}$` and record it in the durable release ledger; a temporary
file alone is not release evidence.

## Fleet coverage

The fleet scan checks only the repositories named in `repository_expectations`
(`.dagger/src/ci/fleet.py`). That list is written by hand, so a new consumer would otherwise
escape every fleet check. To close that gap, each hosted scan first lists every public
`hseshadr` repository, reads its default-branch `dagger.json`, and reports
`uncovered-consumer` for any active repository that pins a `github.com/hseshadr/ci` module but is
missing from the list. The scan then fails.

- **When you onboard a consumer, add it to `repository_expectations` in the same PR.** Also add
  it to `KNOWN_CONSUMERS` in `.dagger/tests/test_fleet_coverage.py`.
- Archived repositories are skipped. Private repositories are not listed, so they are not
  discovered.
- A repository whose evidence cannot be read (for example, `main` has no branch protection)
  gets an `evidence-unreadable` finding. The scan keeps going and still fails.

## Publisher lineage

**TL;DR:** before a `workflow_run` publisher trusts a candidate artifact, it calls
`portfolio-foundation`'s `release-lineage` (PyPI) or `release-provenance` (npm) at a literal
`hseshadr/ci` SHA. The call fails unless GitHub's own run records show the candidate came
from `main`.

**Why:** the publisher's `head_branch == default_branch` gate also passes for a
`workflow_dispatch` on a *tag* named `main`. That tag's commit, and the
`release-candidate.yml` it runs, are whatever the tagger wrote. Without a lineage check,
the `main` publisher would publish those bytes over OIDC (hseshadr/ci#49).

The function reads the triggering run and the running publish run, then requires all of:

- the candidate run is a successful `workflow_dispatch` of `release-candidate.yml` in this
  repository, for exactly `HEAD_SHA`;
- the publish run is this repository's in-progress `publish.yml` `workflow_run` on `main`;
- `compare/HEAD_SHA...publish_sha` and `compare/publish_sha...branches/main` are `ahead` or
  `identical`. The branch SHA comes from the `branches/main` endpoint, so a tag named `main`
  cannot stand in for the branch.

`release-provenance` then returns `github-context.json`, the GitHub Actions context npm writes
into its SLSA provenance. It is built from the publish run record, not from caller text.

The fleet policy accepts exactly this leading step and nothing weaker (`publisher-lineage`):

```yaml
      - uses: dagger/dagger-for-github@27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77 # v8.4.1
        env:
          GH_TOKEN: ${{ github.token }}
          RUN_ID: ${{ github.event.workflow_run.id }}
          HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
        with:
          version: "0.21.8"
          verb: call
          module: github.com/hseshadr/ci/modules/portfolio-foundation@<40-hex ci SHA>
          args: release-lineage --github-token=env:GH_TOKEN --repository="$GITHUB_REPOSITORY" --run-id="$RUN_ID" --head-sha="$HEAD_SHA" --publish-run-id="$GITHUB_RUN_ID"
```

For npm, use `release-provenance` with the same arguments plus
`export --path=github-context.json`, then load the repository's own publisher at
`github.com/hseshadr/<repo>@${{ github.sha }}` (the `main` commit the workflow runs on, never
the candidate's SHA). The steps are then lineage → download → publish, with no `run:` step.

**Expressions in Dagger inputs.** `dagger-for-github` pastes `args`, `call`, `shell`,
`dagger-flags`, `workdir`, and `cloud-token` into bash. The policy reports
`dagger-args-expression` for any `${{ inputs.* }}`, `${{ github.event.* }}` or
`${{ github.head_ref }}` there. Pass the value through `env:` and quote it: `--tag="$TAG"`.
`module` is exempt because the action passes it as the `INPUT_MODULE` environment variable.

Not yet enforced: the policy accepts the lineage step but does not require it, so a
publisher without it still passes. Requiring it waits until every publisher has migrated.

## Release status

Shipped in this central change:

- reusable foundation and Pages module implementations;
- opt-in authenticated Pages Functions compilation within the existing one-upload Pages
  transaction;
- reusable Python package candidate implementation with source-free official PyPA boundary;
- exact-SHA dependency and production-environment policy;
- deterministic Python and TypeScript composition fixtures;
- real local-TLS provider tests and isolated cold-engine proof.

Still pending in the EdgeReco canary rollout (Tasks 10–14): consumer hardening, foundation shadow
adoption, provider shadow adoption, secure Environment secret migration, exact live deployment
proof, and removal of proven duplicate local mechanics. No fleet-wide adoption, production
deployment, package publication, version tag, or registry release is claimed here.
