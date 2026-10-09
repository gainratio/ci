from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from portfolio_foundation.guard import ACTIONLINT_IMAGE, GITLEAKS_IMAGE, actionlint_command


@dataclass(frozen=True)
class GuardFixture:
    repository: str
    commit_sha: str


SUCCESS = GuardFixture("hseshadr/ci", "9a4830a3d8444e49d32e2408ef31ea592f2087b0")
INVALID_WORKFLOW = GuardFixture(
    "toomcruz/cemiterio-santana-5b3-test",
    "5e7a3baf9507a22913bc2fb9048281d8c58d2ce6",
)
HISTORY_SECRET = GuardFixture(
    "kristof-mattei/km-crates-publish-test",
    "711c3b50ce63192b88f22215793ca7f1eeb7b439",
)
ALMA_FIXTURES = GuardFixture("hseshadr/almamesh", "55dba578dde057d1dd6d680b5f978280498ef0ea")
MODULE = Path(__file__).parents[2]
DAGGER_GUARD = ("dagger", "--progress=logs", "-m", ".", "call", "guard")
FIXTURE_PATHS = (
    Path("backend/tests/test_predictive_golden.py"),
    Path("frontend/packages/browser/integration/parity.mjs"),
)
CUSTOM_RUNNER_WORKFLOW = (
    "on: push\njobs:\n  build:\n    runs-on: custom-runner-4\n    steps:\n      - run: echo ok\n"
)
CUSTOM_RUNNER_CONFIG = "self-hosted-runner:\n  labels:\n    - custom-runner-4\n"
PAYLOAD_PARTS = (
    "616c6d616d6573682d7061726974792d",
    "666978747572652d7369676e65723030",
)


def _run(*args: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False, text=True
    )


def _require(result: subprocess.CompletedProcess[str], step: str) -> None:
    assert result.returncode == 0, f"fixture {step} failed before guard validation: {result.stdout}"


def _materialize(tmp_path: Path, fixture: GuardFixture) -> Path:
    source = tmp_path / fixture.repository.replace("/", "-")
    source.mkdir()
    _require(_run("git", "init", "-q", cwd=source), "initialization")
    remote = f"https://github.com/{fixture.repository}.git"
    _require(_run("git", "remote", "add", "origin", remote, cwd=source), "remote setup")
    _require(_run("git", "fetch", "--depth=1", "origin", fixture.commit_sha, cwd=source), "fetch")
    _require(_run("git", "checkout", "--detach", fixture.commit_sha, cwd=source), "checkout")
    return source


def _guard(source: Path, fixture: GuardFixture) -> subprocess.CompletedProcess[str]:
    return _run(
        *DAGGER_GUARD,
        f"--source={source}",
        f"--repository={fixture.repository}",
        f"--commit-sha={fixture.commit_sha}",
        "sync",
        cwd=MODULE,
    )


def _output(result: subprocess.CompletedProcess[str]) -> str:
    return result.stdout


def _write_alma_fixtures(root: Path) -> None:
    seed = "".join(PAYLOAD_PARTS)
    python, javascript = (root / path for path in FIXTURE_PATHS)
    python.parent.mkdir(parents=True, exist_ok=True)
    javascript.parent.mkdir(parents=True, exist_ok=True)
    python.write_text(f'FIXTURE_KEY_SEED_HEX = "{seed}"\n')
    javascript.write_text(f'const PREDICTIVE_FIXTURE_KEY_SEED_HEX =\n  "{seed}";\n')


def _git(root: Path, *arguments: str) -> str:
    result = _run("git", *arguments, cwd=root)
    _require(result, "git " + " ".join(arguments))
    return result.stdout.strip()


def _commit(root: Path, message: str) -> str:
    _git(root, "add", ".")
    _git(root, "commit", "-qm", message)
    return _git(root, "rev-parse", "HEAD")


def _configure_author(root: Path) -> None:
    _git(root, "config", "user.email", "fixture@example.invalid")
    _git(root, "config", "user.name", "Fixture")


def _policy_prefix(baseline: Path | None) -> str:
    if baseline is None:
        return 'title = "AlmaMesh fixture policy"\n[extend]\nuseDefault = true\n'
    return baseline.read_text().replace("\n[allowlist]\n", "\n[[allowlists]]\n")


def _write_allowlist(root: Path, commit_sha: str, baseline: Path | None = None) -> None:
    lines = (
        "[[allowlists]]",
        'targetRules = ["generic-api-key"]',
        'condition = "AND"',
        f'commits = ["{commit_sha}"]',
        "paths = [",
        "  '''^backend/tests/test_predictive_golden\\.py$''',",
        "  '''^frontend/packages/browser/integration/parity\\.mjs$''',",
        "]",
    )
    policy = _policy_prefix(baseline).rstrip() + "\n\n" + "\n".join(lines) + "\n"
    (root / ".gitleaks.toml").write_text(policy)


def _alma_policy(root: Path, repository: Path) -> Path:
    policy = root / "policy"
    policy.mkdir()
    _write_allowlist(policy, ALMA_FIXTURES.commit_sha, repository / ".gitleaks.toml")
    return policy / ".gitleaks.toml"


def _fresh_copy_repository(root: Path) -> Path:
    repository = _materialize(root, ALMA_FIXTURES)
    _configure_author(repository)
    for path in FIXTURE_PATHS:
        (repository / path).unlink()
    _commit(repository, "remove historical fixtures")
    _write_alma_fixtures(repository)
    _commit(repository, "fresh fixture copies")
    return repository


def _detector_arguments(history: bool, config: Path | None) -> tuple[str, ...]:
    mode = ("--log-opts=--all",) if history else ("--no-git",)
    options = ("--config", "/policy/.gitleaks.toml") if config else ()
    return (
        "detect",
        "--source",
        "/repo",
        *mode,
        *options,
        "--redact",
        "--no-banner",
        "--verbose",
    )


def _detect(
    root: Path, *, history: bool, config: Path | None = None
) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    assert docker is not None, "Docker is required for the real detector contract"
    command = (docker, "run", "--rm", "-v", f"{root}:/repo:ro", GITLEAKS_IMAGE)
    config_mount = ("-v", f"{config}:/policy/.gitleaks.toml:ro") if config else ()
    return subprocess.run(  # noqa: S603
        (*command[:-1], *config_mount, command[-1], *_detector_arguments(history, config)),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )


def _assert_two_generic_api_keys(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode != 0, result.stdout
    assert "leaks found: 2" in result.stdout
    assert len(re.findall(r"RuleID:\s+generic-api-key", result.stdout)) == 2


def _assert_success_evidence(result: subprocess.CompletedProcess[str]) -> None:
    output = _output(result)
    assert result.returncode == 0, output
    markers = ("guard-canary-detected", "guard-snapshot-nonempty", "guard-history-verified")
    assert all(output.count(marker) >= 2 for marker in markers)
    positions = tuple(output.rindex(marker) for marker in markers)
    assert positions == tuple(sorted(positions))
    assert "57 commits scanned." in output
    assert output.count("no leaks found") >= 2


def _assert_invalid_workflow(result: subprocess.CompletedProcess[str]) -> None:
    output = _output(result)
    assert result.returncode != 0, "invalid workflow unexpectedly passed"
    assert "could not parse as YAML" in output
    assert "guard-canary-detected" not in output


def _assert_history_secret(result: subprocess.CompletedProcess[str]) -> None:
    output = _output(result)
    assert result.returncode != 0, "retained-history secret unexpectedly passed"
    snapshot = output.rindex("guard-snapshot-nonempty")
    history = output.rindex("guard-history-verified")
    assert output.index("no leaks found", snapshot) < history
    assert output.index("leaks found: 1", history) > history


def test_should_run_canary_snapshot_and_exact_retained_history(tmp_path: Path) -> None:
    # Given
    source = _materialize(tmp_path, SUCCESS)

    # When
    result = _guard(source, SUCCESS)

    # Then
    _assert_success_evidence(result)


def test_should_reject_invalid_workflow_before_secret_scanning(tmp_path: Path) -> None:
    # Given
    source = _materialize(tmp_path, INVALID_WORKFLOW)

    # When
    result = _guard(source, INVALID_WORKFLOW)

    # Then
    _assert_invalid_workflow(result)


def test_should_reject_secret_retained_only_in_history(tmp_path: Path) -> None:
    # Given
    source = _materialize(tmp_path, HISTORY_SECRET)

    # When
    result = _guard(source, HISTORY_SECRET)

    # Then
    _assert_history_secret(result)


def test_should_detect_both_alma_fixture_patterns_without_allowlist(tmp_path: Path) -> None:
    # Given
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _write_alma_fixtures(snapshot)

    # When
    result = _detect(snapshot, history=False)

    # Then
    _assert_two_generic_api_keys(result)


def test_should_allow_only_the_exact_historical_alma_matches(tmp_path: Path) -> None:
    # Given
    repository = _materialize(tmp_path, ALMA_FIXTURES)
    policy = _alma_policy(tmp_path, repository)

    # When
    result = _detect(repository, history=True, config=policy)

    # Then
    assert result.returncode == 0, result.stdout
    assert "no leaks found" in result.stdout


def test_should_reject_a_fresh_commit_copy_despite_historical_allowlist(tmp_path: Path) -> None:
    # Given
    repository = _fresh_copy_repository(tmp_path)
    policy = _alma_policy(tmp_path, repository)

    # When
    result = _detect(repository, history=True, config=policy)

    # Then
    _assert_two_generic_api_keys(result)


def test_should_reject_a_snapshot_copy_despite_historical_allowlist(tmp_path: Path) -> None:
    # Given
    repository = _materialize(tmp_path, ALMA_FIXTURES)
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    _write_alma_fixtures(snapshot)
    policy = _alma_policy(tmp_path, repository)

    # When
    result = _detect(snapshot, history=False, config=policy)

    # Then
    _assert_two_generic_api_keys(result)


def _custom_runner_consumer(tmp_path: Path, *, config: bool) -> Path:
    snapshot = tmp_path / "snapshot"
    (snapshot / ".github" / "workflows").mkdir(parents=True)
    (snapshot / ".github" / "workflows" / "ci.yml").write_text(CUSTOM_RUNNER_WORKFLOW)
    if config:
        (snapshot / ".github" / "actionlint.yaml").write_text(CUSTOM_RUNNER_CONFIG)
    return snapshot


def _actionlint(snapshot: Path) -> subprocess.CompletedProcess[str]:
    docker = shutil.which("docker")
    assert docker is not None, "Docker is required for the real actionlint contract"
    mount = ("-v", f"{snapshot}:/snapshot:ro", "--entrypoint", "sh", ACTIONLINT_IMAGE)
    return _run(docker, "run", "--rm", *mount, "-ceu", actionlint_command(), cwd=snapshot)


def test_should_accept_self_hosted_label_declared_in_consumer_config(tmp_path: Path) -> None:
    # Given
    snapshot = _custom_runner_consumer(tmp_path, config=True)

    # When
    result = _actionlint(snapshot)

    # Then
    assert result.returncode == 0, result.stdout


def test_should_reject_unknown_self_hosted_label_without_consumer_config(tmp_path: Path) -> None:
    # Given
    snapshot = _custom_runner_consumer(tmp_path, config=False)

    # When
    result = _actionlint(snapshot)

    # Then
    assert result.returncode != 0, "unknown runner label unexpectedly passed"
    assert 'label "custom-runner-4" is unknown' in result.stdout
