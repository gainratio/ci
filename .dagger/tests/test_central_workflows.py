from __future__ import annotations

from pathlib import Path

from ci.fleet_policy import SourceFile, validate_workflow

ROOT = Path(__file__).parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"


def _source(name: str) -> SourceFile:
    path = WORKFLOWS / name
    return SourceFile(path=str(path.relative_to(ROOT)), text=path.read_text())


def test_should_keep_all_central_execution_behind_thin_dagger_ingress() -> None:
    # Given the four workflows that remain after central cutover
    names = ("dagger.yml", "consumer-drift.yml", "dagger-security.yml", "module-canary.yml")

    # When every authored job is evaluated by the fleet policy itself
    findings = tuple(item for name in names for item in validate_workflow(_source(name)))

    # Then GitHub contains transport only; Dagger owns execution
    assert findings == ()


def test_should_bind_hosted_tokens_and_exact_commit_to_typed_dagger_calls() -> None:
    # Given the protected, fleet, and scheduled-security entry points
    dagger = _source("dagger.yml").text
    fleet = _source("consumer-drift.yml").text
    security = _source("dagger-security.yml").text

    # When their Dagger arguments and event boundaries are inspected
    exact_commit = "--commit-sha=${{ github.sha }}"

    # Then CI/security scan exact source and fleet secrets never cross a PR event
    assert all("--github-token=env:GITHUB_TOKEN" in text for text in (dagger, fleet, security))
    assert exact_commit in dagger and exact_commit in security
    assert "pull_request:" in dagger
    assert "pull_request:" not in fleet
    assert "secrets.CONSUMER_DRIFT_TOKEN" in fleet
    assert "--include-central" in fleet


def test_should_run_main_fleet_only_after_exact_dagger_success() -> None:
    # Given central protection requires the Dagger check for the new main commit
    dagger = _source("dagger.yml").text
    fleet = _source("consumer-drift.yml").text

    # When the fleet proof is triggered after a merge
    required_boundaries = (
        "fleet:",
        "needs: dagger",
        "github.event_name == 'push'",
        "github.ref == 'refs/heads/main'",
        "secrets.CONSUMER_DRIFT_TOKEN",
        "fleet --github-token=env:GITHUB_TOKEN --include-central",
    )

    # Then the scheduled/manual ingress cannot race the exact-main Dagger check
    assert "push:" not in fleet
    assert "workflow_run:" not in fleet
    assert all(boundary in dagger for boundary in required_boundaries)


def test_should_delete_every_retired_central_execution_surface() -> None:
    # Given the fleet no longer executes a central reusable control
    remaining = {path.name for path in WORKFLOWS.glob("*.yml")}

    # When central execution surfaces are inventoried
    expected = {
        "dagger.yml",
        "consumer-drift.yml",
        "dagger-security.yml",
        "image-mirror.yml",
        "module-canary.yml",
    }

    # Then only thin Dagger ingress remains; classifiers/templates are gone
    assert remaining == expected
    retired = (ROOT / ".github" / "actions", ROOT / "examples")
    authored = (
        path for root in retired for path in root.rglob("*") if "__pycache__" not in path.parts
    )
    assert not any(path.is_file() for path in authored)
    assert {path.name for path in (ROOT / "tests").iterdir()} == {"dagger"}


def test_should_keep_module_canary_shadowed_and_dagger_owned() -> None:
    # Given the scheduled/manual cross-language canary ingress
    canary = _source("module-canary.yml")

    # When its complete workflow is checked by fleet policy
    findings = validate_workflow(canary)

    # Then it remains non-required transport for only the root fixture graph
    assert findings == ()
    assert "schedule:" in canary.text and "workflow_dispatch:" in canary.text
    assert "module-fixtures" in canary.text
    assert "pull_request:" not in canary.text and "push:" not in canary.text
    assert canary.text.count("- uses:") == 2
    assert canary.text.index("actions/checkout@") < canary.text.index("dagger/dagger-for-github@")
    assert "persist-credentials: false" in canary.text
    assert all(item not in canary.text for item in ("- run:", "actions/setup-", "actions/cache@"))


def test_should_write_the_mirror_only_from_main_through_dagger() -> None:
    # Given the GHCR mirror ingress
    mirror = _source("image-mirror.yml")
    jobs = mirror.text.split("\n  sync:\n")

    # When its jobs are checked by fleet policy and their boundaries inspected
    findings = validate_workflow(mirror)

    # Then PRs get a read-only upstream check; only main, schedule, or dispatch can write
    assert findings == ()
    assert len(jobs) == 2
    verify, sync = jobs
    assert "image-mirror-verify" in verify and "packages:" not in verify
    assert "if: github.event_name == 'pull_request'" in verify
    assert "packages: write" in sync and "image-mirror --github-token=env:GITHUB_TOKEN" in sync
    assert "github.event_name != 'pull_request' && github.ref == 'refs/heads/main'" in sync
    assert all(item in mirror.text for item in ("schedule:", "workflow_dispatch:", "mirror/**"))
    assert "pull_request_target" not in mirror.text
