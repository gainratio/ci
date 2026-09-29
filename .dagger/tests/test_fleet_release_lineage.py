"""Fleet policy: script-free Dagger args and the central publisher-lineage shape (#49)."""

from __future__ import annotations

import json

import pytest

from ci.fleet_policy import SourceFile, validate_workflow

DAGGER = "27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77"
CHECKOUT = "1" * 40
DOWNLOAD = "4" * 40
PYPI = "5" * 40
CI_PIN = "e" * 40
LINEAGE_MODULE = f"github.com/hseshadr/ci/modules/portfolio-foundation@{CI_PIN}"
LINEAGE_ARGUMENTS = (
    '--github-token=env:GH_TOKEN --repository="$GITHUB_REPOSITORY" --run-id="$RUN_ID" '
    '--head-sha="$HEAD_SHA" --publish-run-id="$GITHUB_RUN_ID"'
)
LINEAGE_CALL = f"release-lineage {LINEAGE_ARGUMENTS}"
PROVENANCE_CALL = f"release-provenance {LINEAGE_ARGUMENTS} export --path=github-context.json"
LINEAGE_ENV = """        env:
          GH_TOKEN: ${{ github.token }}
          RUN_ID: ${{ github.event.workflow_run.id }}
          HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
"""
HEADER = """name: Publish
on:
  workflow_run:
    workflows: [Dagger release candidate]
    types: [completed]
permissions:
  contents: read
jobs:
  publish:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      id-token: write
    steps:
"""
DOWNLOAD_STEP = f"""      - uses: actions/download-artifact@{DOWNLOAD}
        with:
          name: example-${{{{ github.event.workflow_run.head_sha }}}}
          path: release
          github-token: ${{{{ github.token }}}}
          run-id: ${{{{ github.event.workflow_run.id }}}}
"""
PYPI_STEP = f"""      - uses: pypa/gh-action-pypi-publish@{PYPI}
        with:
          packages-dir: release/dist
          attestations: true
"""
NPM_PUBLISHER = f"""      - uses: dagger/dagger-for-github@{DAGGER}
        env:
          HEAD_SHA: ${{{{ github.event.workflow_run.head_sha }}}}
        with:
          version: "0.21.8"
          verb: call
          module: github.com/hseshadr/example@${{{{ github.sha }}}}
          args: >-
            publish --candidate=release --expected-sha="$HEAD_SHA"
            --oidc-url=env:ACTIONS_ID_TOKEN_REQUEST_URL
            --oidc-token=env:ACTIONS_ID_TOKEN_REQUEST_TOKEN
            --github-context=github-context.json
"""


def _lineage(call: str, *, module: str = LINEAGE_MODULE, env: str = LINEAGE_ENV) -> str:
    return f"""      - uses: dagger/dagger-for-github@{DAGGER}
{env}        with:
          version: "0.21.8"
          verb: call
          module: {module}
          args: {call}
"""


def _codes(text: str) -> tuple[str, ...]:
    source = SourceFile(path=".github/workflows/publish.yml", text=text)
    return tuple(item.code for item in validate_workflow(source, "v0.21.8", "example"))


def _ingress(args: str, extra: str = "") -> str:
    return f"""name: Dagger
on: [push]
permissions:
  contents: read
jobs:
  dagger:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{CHECKOUT}
        with:
          persist-credentials: false
      - uses: dagger/dagger-for-github@{DAGGER}
        env:
          TAG: ${{{{ inputs.tag }}}}
        with:
          version: "0.21.8"
          verb: call
          args: {args}
{extra}"""


@pytest.mark.parametrize(
    "args",
    [
        "release-candidate --tag=${{ inputs.tag }}",
        "release-candidate --tag=${{inputs.tag}}",
        "release-candidate --tag=${{ INPUTS.tag }}",
        "release-candidate --tag=${{ github.event.inputs.tag }}",
        "publish --expected-sha=${{ github.event.workflow_run.head_sha }}",
        "publish --title=${{ github.event['pull_request'].title }}",
        "publish --context=${{ toJSON(github.event) }}",
        "ci --ref=${{ github.head_ref }}",
        "ci --ref=${{ format('{0}', inputs.tag) }}",
    ],
)
def test_should_reject_attacker_controlled_expressions_in_dagger_args(args: str) -> None:
    # Given dagger-for-github args (pasted into bash) carrying a caller-controlled expression
    codes = _codes(_ingress(json.dumps(args)))

    # Then the fleet policy reports the script-injection sink
    assert "dagger-args-expression" in codes


@pytest.mark.parametrize("key", ["call", "shell", "dagger-flags", "workdir", "cloud-token"])
def test_should_reject_attacker_expressions_in_every_script_pasted_input(key: str) -> None:
    # Given an expression in another dagger-for-github input the action pastes into bash
    workflow = _ingress("ci", f"          {key}: x ${{{{ inputs.tag }}}}\n")

    # Then it is the same injection
    assert "dagger-args-expression" in _codes(workflow)


@pytest.mark.parametrize(
    "args",
    [
        'release-candidate --tag="$TAG" --commit-sha="$GITHUB_SHA"',
        "ci --commit-sha=${{ github.sha }}",
        "ci --event=${{ github.event_name }}",
        "ci --inputs-file=inputs.json",
    ],
)
def test_should_accept_env_quoted_values_and_runner_owned_expressions(args: str) -> None:
    # Given args whose only values are quoted env vars or GitHub-owned identities
    codes = _codes(_ingress(json.dumps(args)))

    # Then no injection finding is reported
    assert "dagger-args-expression" not in codes


def test_should_accept_the_module_input_which_the_action_passes_through_env() -> None:
    # Given the reviewed candidate-bound module expression (INPUT_MODULE env, not script)
    workflow = (
        HEADER
        + DOWNLOAD_STEP
        + NPM_PUBLISHER.replace("${{ github.sha }}", "${{ github.event.workflow_run.head_sha }}")
    )

    # Then it is not an args expression
    assert "dagger-args-expression" not in _codes(workflow)


def test_should_accept_central_lineage_before_official_pypi() -> None:
    # Given edgeproc-core's shape: prove lineage, download the exact candidate, publish
    workflow = HEADER + _lineage(LINEAGE_CALL) + DOWNLOAD_STEP + PYPI_STEP

    # Then the policy reports nothing: no shell step, no exemption
    assert _codes(workflow) == ()


def test_should_accept_central_provenance_before_a_main_pinned_npm_publisher() -> None:
    # Given privacy-core's shape: lineage-gated provenance file, download, main publisher
    workflow = HEADER + _lineage(PROVENANCE_CALL) + DOWNLOAD_STEP + NPM_PUBLISHER

    # Then the policy reports nothing
    assert _codes(workflow) == ()


@pytest.mark.parametrize(
    ("call", "module", "env"),
    [
        # A hard-coded run id proves some other, older run instead of the triggering one.
        (LINEAGE_CALL.replace('"$RUN_ID"', "123"), LINEAGE_MODULE, LINEAGE_ENV),
        # The candidate's own SHA would let the tagged commit vouch for itself.
        (
            LINEAGE_CALL,
            LINEAGE_MODULE,
            LINEAGE_ENV.replace("workflow_run.id", "workflow_run.run_number"),
        ),
        (LINEAGE_CALL.replace('"$HEAD_SHA"', '"$GITHUB_SHA"'), LINEAGE_MODULE, LINEAGE_ENV),
        (LINEAGE_CALL, "github.com/hseshadr/ci/modules/portfolio-foundation@main", LINEAGE_ENV),
        (f"green-main {LINEAGE_ARGUMENTS}", LINEAGE_MODULE, LINEAGE_ENV),
        (LINEAGE_CALL, LINEAGE_MODULE, ""),
    ],
)
def test_should_reject_any_lineage_step_that_is_not_the_exact_central_call(
    call: str, module: str, env: str
) -> None:
    # Given a first Dagger step that looks like lineage but proves something weaker
    workflow = HEADER + _lineage(call, module=module, env=env) + DOWNLOAD_STEP + PYPI_STEP

    # Then the publisher is rejected
    assert "publisher-lineage" in _codes(workflow)


def test_should_reject_a_lineage_step_with_extra_script_inputs() -> None:
    # Given the exact call plus an extra input the action would paste into bash
    step = _lineage(LINEAGE_CALL) + "          dagger-flags: --progress plain\n"

    # Then it is not the exact central call
    assert "publisher-lineage" in _codes(HEADER + step + DOWNLOAD_STEP + PYPI_STEP)


def test_should_not_treat_a_lookalike_module_as_the_central_lineage() -> None:
    # Given the lineage call loaded from a fork of hseshadr/ci
    module = f"github.com/attacker/ci/modules/portfolio-foundation@{CI_PIN}"
    workflow = HEADER + _lineage(LINEAGE_CALL, module=module) + DOWNLOAD_STEP + PYPI_STEP

    # Then it is an unapproved Dagger step in the PyPI bridge
    assert "pypi-shape" in _codes(workflow)


def test_should_still_reject_a_repository_publisher_loaded_from_an_arbitrary_sha() -> None:
    # Given the consumer publisher loaded from a literal SHA rather than main's own commit
    workflow = HEADER + DOWNLOAD_STEP + NPM_PUBLISHER.replace("${{ github.sha }}", CI_PIN)

    # Then the publisher module identity is still rejected
    assert "publisher-module-identity" in _codes(workflow)


def test_should_reject_a_shell_lineage_step_as_before() -> None:
    # Given the pre-#49 shell lineage step
    shell = """      - name: Verify the candidate's lineage
        shell: bash
        run: gh api "repos/$GITHUB_REPOSITORY/actions/runs/$RUN_ID"
"""
    # Then shell stays forbidden: the module function is the only compliant shape
    assert "shell-step" in _codes(HEADER + shell + DOWNLOAD_STEP + PYPI_STEP)
