from __future__ import annotations

import asyncio
import base64
import json
import re
import subprocess
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import dagger
import pytest

from portfolio_foundation import guard as guard_module
from portfolio_foundation import main as main_module
from portfolio_foundation.guard import (
    ACTIONLINT_IMAGE,
    FOUNDATION_CONFIG_PATH,
    FOUNDATION_GITLEAKS_CONFIG,
    GITLEAKS_IMAGE,
    STATELESS_GITHUB_RULE_ID,
    actionlint_command,
    build_guard,
    canary_command,
    scan_config_variable,
    secret_scan_command,
)
from portfolio_foundation.identity import CommitIdentity, FullSha, RepositoryRef
from portfolio_foundation.source import SourceBinding


class FakeDirectory:
    def __init__(self, snapshot: dagger.Directory | None = None) -> None:
        self.snapshot = snapshot

    def without_directory(self, path: str) -> dagger.Directory:
        assert path == ".git"
        assert self.snapshot is not None
        return self.snapshot


class FakeContainer:
    def __init__(self, operations: list[tuple[object, ...]]) -> None:
        self.operations = operations

    def from_(self, image: str) -> FakeContainer:
        self.operations.append(("from", image))
        return self

    def file(self, path: str) -> dagger.File:
        self.operations.append(("file", path))
        return cast(dagger.File, object())

    def with_entrypoint(self, entrypoint: list[str]) -> FakeContainer:
        self.operations.append(("entrypoint", tuple(entrypoint)))
        return self

    def with_file(self, path: str, file: dagger.File) -> FakeContainer:
        self.operations.append(("with_file", path, file))
        return self

    def with_new_file(self, path: str, contents: str) -> FakeContainer:
        self.operations.append(("with_new_file", path, contents))
        return self

    def with_mounted_directory(
        self, path: str, directory: dagger.Directory, *, read_only: bool
    ) -> FakeContainer:
        self.operations.append(("mount", path, directory, read_only))
        return self

    def with_exec(self, command: list[str]) -> FakeContainer:
        self.operations.append(("exec", tuple(command)))
        return self


class FakeDag:
    def __init__(self, operations: list[tuple[object, ...]]) -> None:
        self.operations = operations

    def container(self) -> FakeContainer:
        return FakeContainer(self.operations)


def test_should_scan_both_workflow_extensions() -> None:
    # Given
    command = actionlint_command()

    # When
    workflow_patterns = tuple(re.findall(r"\*\.ya?ml", command))

    # Then
    assert frozenset(workflow_patterns) == frozenset(("*.yml", "*.yaml"))


def test_should_require_nonempty_workflow_input() -> None:
    # Given
    command = actionlint_command()

    # When / Then
    assert "test -n" in command
    assert command.index("test -n") < command.index("actionlint")


FAKE_ACTIONLINT = '#!/bin/sh\nprintf \'%s\\n\' "$@" > "$(dirname "$0")/argv"\n'
WORKFLOW = (
    "on: push\njobs:\n  build:\n    runs-on: custom-runner-4\n    steps:\n      - run: true\n"
)


def _consumer(tmp_path: Path, config_name: str | None) -> Path:
    root = tmp_path / "snapshot"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    if config_name is not None:
        (root / ".github" / config_name).write_text("self-hosted-runner:\n  labels: [custom-*]\n")
    return root


def _run_actionlint_program(tmp_path: Path, root: Path) -> tuple[str, ...]:
    tools = tmp_path / "bin"
    tools.mkdir()
    fake = tools / "actionlint"
    fake.write_text(FAKE_ACTIONLINT)
    fake.chmod(0o755)
    program = actionlint_command(str(root))
    environment = {"PATH": f"{tools}:/usr/bin:/bin"}
    subprocess.run(("/bin/sh", "-ceu", program), check=True, env=environment)  # noqa: S603
    return tuple((tools / "argv").read_text().splitlines())


@pytest.mark.parametrize("config_name", ["actionlint.yaml", "actionlint.yml"])
def test_should_pass_consumer_actionlint_config_explicitly(
    tmp_path: Path, config_name: str
) -> None:
    # Given
    root = _consumer(tmp_path, config_name)

    # When
    argv = _run_actionlint_program(tmp_path, root)

    # Then
    config = str(root / ".github" / config_name)
    assert argv == ("-config-file", config, str(root / ".github" / "workflows" / "ci.yml"))


def test_should_prefer_yaml_config_when_both_extensions_exist(tmp_path: Path) -> None:
    # Given
    root = _consumer(tmp_path, "actionlint.yaml")
    (root / ".github" / "actionlint.yml").write_text("self-hosted-runner:\n  labels: []\n")

    # When
    argv = _run_actionlint_program(tmp_path, root)

    # Then
    assert argv[:2] == ("-config-file", str(root / ".github" / "actionlint.yaml"))


def test_should_run_actionlint_without_config_when_consumer_has_none(tmp_path: Path) -> None:
    # Given
    root = _consumer(tmp_path, None)

    # When
    argv = _run_actionlint_program(tmp_path, root)

    # Then
    assert argv == (str(root / ".github" / "workflows" / "ci.yml"),)


def test_should_require_runtime_canary_detection_before_real_scan() -> None:
    # Given
    command = secret_scan_command("a" * 40)

    # When / Then
    assert command.index("guard-canary-detected") < command.index("find /snapshot")
    assert "--redact" in command
    assert "--exit-code" in command


def test_should_generate_canary_without_committing_detector_value() -> None:
    # Given
    command = secret_scan_command("a" * 40)

    # When
    committed = [re.search(pattern, command) for pattern in (CLASSIC_PAT, STATELESS_GHS)]

    # Then
    assert committed == [None, None]
    assert "git init" in command


def test_should_reject_empty_or_shallow_canonical_history() -> None:
    # Given
    command = secret_scan_command("b" * 40)

    # When / Then
    assert "test -d /repo/.git" in command
    assert "--is-shallow-repository" in command
    assert "rev-list --all" in command
    assert "b" * 40 in command


def test_should_scan_nonempty_snapshot_and_all_canonical_history() -> None:
    # Given
    command = secret_scan_command("c" * 40)

    # When / Then
    assert "find /snapshot -type f -print -quit" in command
    assert "--source /snapshot --no-git" in command
    assert "--source /repo --log-opts=--all" in command


def test_should_apply_each_canaried_config_to_its_own_scan() -> None:
    # Given
    command = secret_scan_command("c" * 40)
    snapshot, history = (scan_config_variable(root) for root in ("/snapshot", "/repo"))

    # When
    real = ("gitleaks detect --source /snapshot ", "gitleaks detect --source /repo ")
    scans = [line for line in command.splitlines() if line.startswith(real)]

    # Then
    assert (
        f'if test -f /snapshot/.gitleaks.toml; then {snapshot}="/snapshot/.gitleaks.toml"'
        in command
    )
    assert f'if test -f /repo/.gitleaks.toml; then {history}="/repo/.gitleaks.toml"' in command
    assert scans[0].startswith(
        f'gitleaks detect --source /snapshot --no-git --config "${snapshot}"'
    )
    assert scans[1].startswith(
        f'gitleaks detect --source /repo --log-opts=--all --config "${history}"'
    )


CLASSIC_PAT = r"ghp_[A-Za-z0-9]{36}"
CLASSIC_APP_PATTERN = r"(?:ghu|ghs)_[0-9a-zA-Z]{36}"  # gitleaks 8.30.1 github-app-token
STATELESS_GHS = r"ghs_[A-Za-z0-9._-]{36,}"  # GitHub's documented stateless-token pattern
STATELESS_SHAPE = (
    r"ghs_[1-9][0-9]{2,8}_eyJ[A-Za-z0-9_-]{33}\.eyJ[A-Za-z0-9_-]{128,159}\.[A-Za-z0-9_-]{342}"
)
PROBED_FILES = ("canary.py", "canary.ts", "canary.txt", "canary.env", "canary")
FAKE_GITLEAKS = """#!/bin/sh
while test "$#" -gt 0; do
  case "$1" in
    --source) source="$2"; shift ;;
    --config) config="$2"; shift ;;
  esac
  shift
done
file="$(ls "$source")"
token="$(cat "$source/$file")"
printf '%s %s %s\\n' "$config" "$file" "$token" >> "$(dirname "$0")/calls"
case "$file" in
  $FAKE_SKIPS) exit 0 ;;
esac
case "$token" in
  *"$FAKE_DETECTS"*) exit 86 ;;
esac
exit 0
"""


def _segment(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _stateless_token() -> str:
    # Built at runtime: the repository never holds a detector-shaped literal.
    header = _segment({"alg": "RS256", "typ": "JWT", "kid": "s2s"})
    claims = _segment(
        {"iat": 1792000000, "exp": 1792003600, "iss": "github", "app": 1234567, "inst": 87654321}
    )
    return "ghs" + "_1234567_" + ".".join((header, claims, ("Ab9-Cd8_Ef7" * 32)[:342]))


def _foundation_rule() -> dict[str, object]:
    config = tomllib.loads(FOUNDATION_GITLEAKS_CONFIG)
    rules = [rule for rule in config["rules"] if rule["id"] == STATELESS_GITHUB_RULE_ID]
    assert len(rules) == 1
    return cast(dict[str, object], rules[0])


@dataclass(frozen=True)
class CanaryCall:
    config: str
    file: str
    token: str


def _run_canary(
    tmp_path: Path, *, repo_config: bool, detects: str, skips: str = "none"
) -> tuple[subprocess.CompletedProcess[str], tuple[CanaryCall, ...]]:
    snapshot, tools = tmp_path / "snapshot", tmp_path / "bin"
    snapshot.mkdir()
    tools.mkdir()
    if repo_config:
        (snapshot / ".gitleaks.toml").write_text("[extend]\nuseDefault = true\n")
    fake = tools / "gitleaks"
    fake.write_text(FAKE_GITLEAKS)
    fake.chmod(0o755)
    program = canary_command(str(snapshot), str(tmp_path / "canary"))
    environment = {"PATH": f"{tools}:/usr/bin:/bin", "FAKE_DETECTS": detects, "FAKE_SKIPS": skips}
    result = subprocess.run(  # noqa: S603
        ("/bin/sh", "-ceu", program), env=environment, capture_output=True, text=True, check=False
    )
    calls = tools / "calls"
    lines = calls.read_text().splitlines() if calls.exists() else []
    return result, tuple(CanaryCall(*line.split(" ", 2)) for line in lines)


def _canaried_tokens(tmp_path: Path) -> tuple[str, str]:
    result, calls = _run_canary(tmp_path, repo_config=False, detects="gh")
    assert result.returncode == 0, result.stderr
    classic = {call.token for call in calls if call.token.startswith("ghp_")}
    stateless = {call.token for call in calls if call.token.startswith("ghs_")}
    assert len(classic) == len(stateless) == 1
    return classic.pop(), stateless.pop()


def test_should_keep_upstream_rules_in_foundation_config() -> None:
    # Given
    config = tomllib.loads(FOUNDATION_GITLEAKS_CONFIG)

    # When
    extend = config["extend"]

    # Then
    assert extend == {"useDefault": True}


def test_should_detect_stateless_github_tokens_with_foundation_rule() -> None:
    # Given
    token = _stateless_token()
    rule = _foundation_rule()

    # When
    match = re.search(str(rule["regex"]), f"export GITHUB_TOKEN={token}\n")

    # Then
    assert len(token) > 500
    assert match is not None and match.group(0) == token
    assert rule["keywords"] == ["ghs_"]
    assert re.search(CLASSIC_APP_PATTERN, token) is None


def test_should_probe_every_file_type_with_both_github_token_kinds(tmp_path: Path) -> None:
    # Given / When
    result, calls = _run_canary(tmp_path, repo_config=False, detects="gh")

    # Then
    assert result.returncode == 0, result.stderr
    probed = sorted((call.token[:4], call.file) for call in calls)
    assert probed == sorted((kind, file) for kind in ("ghp_", "ghs_") for file in PROBED_FILES)
    assert "guard-canary-detected" in result.stderr


def test_should_generate_realistic_github_tokens_at_runtime(tmp_path: Path) -> None:
    # Given / When
    classic, stateless = _canaried_tokens(tmp_path)

    # Then
    assert re.fullmatch(CLASSIC_PAT, classic)
    assert re.fullmatch(STATELESS_SHAPE, stateless)
    assert re.fullmatch(str(_foundation_rule()["regex"]), stateless)
    assert re.search(CLASSIC_APP_PATTERN, stateless) is None
    assert 500 <= len(stateless) <= 560


def test_should_draw_fresh_canary_values_on_every_run(tmp_path: Path) -> None:
    # Given
    runs = [tmp_path / str(index) for index in range(4)]
    for run in runs:
        run.mkdir()

    # When
    tokens = [_canaried_tokens(run) for run in runs]

    # Then
    assert len({classic for classic, _ in tokens}) == len(runs)
    assert len({stateless.split("_")[1] for _, stateless in tokens}) > 1
    assert len({stateless.split("_", 2)[2] for _, stateless in tokens}) == len(runs)


@pytest.mark.parametrize("skipped", PROBED_FILES)
def test_should_fail_when_the_scan_config_skips_one_probed_file_type(
    tmp_path: Path, skipped: str
) -> None:
    # Given / When
    result, _ = _run_canary(tmp_path, repo_config=True, detects="gh", skips=skipped)

    # Then
    assert result.returncode != 0
    assert f"guard-canary-missed: classic GitHub token in {skipped} not detected" in result.stderr
    assert "guard-canary-detected" not in result.stderr


@pytest.mark.parametrize("repo_config", [True, False])
def test_should_run_canary_against_the_config_the_real_scan_uses(
    tmp_path: Path, *, repo_config: bool
) -> None:
    # Given / When
    result, calls = _run_canary(tmp_path, repo_config=repo_config, detects="gh")

    # Then
    expected = str(tmp_path / "snapshot" / ".gitleaks.toml") if repo_config else None
    assert result.returncode == 0, result.stderr
    assert {call.config for call in calls} == {expected or FOUNDATION_CONFIG_PATH}


@pytest.mark.parametrize(
    ("detects", "missed"),
    [("no-rule-matches", "classic"), ("ghp_", "stateless")],
    ids=["config-with-zero-rules", "config-without-stateless-rule"],
)
def test_should_fail_when_the_scan_config_misses_a_canary(
    tmp_path: Path, detects: str, missed: str
) -> None:
    # Given / When
    result, _ = _run_canary(tmp_path, repo_config=True, detects=detects)

    # Then
    assert result.returncode != 0
    assert f"guard-canary-missed: {missed}" in result.stderr
    assert "guard-canary-detected" not in result.stderr


def test_should_apply_foundation_config_when_repository_has_none() -> None:
    # Given
    command = secret_scan_command("c" * 40)

    # When / Then
    for root in ("/snapshot", "/repo"):
        assert f'{scan_config_variable(root)}="{FOUNDATION_CONFIG_PATH}"' in command
    assert re.search(r"gitleaks detect(?:(?!--config)[^\n])*$", command, re.MULTILINE) is None


def test_should_pin_every_guard_tool_image_by_digest() -> None:
    # Given
    images = (ACTIONLINT_IMAGE, GITLEAKS_IMAGE)

    # When
    immutable = tuple("@sha256:" in image for image in images)

    # Then
    assert all(immutable)


def test_should_build_guard_from_complete_verified_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    operations: list[tuple[object, ...]] = []
    snapshot = cast(dagger.Directory, object())
    source = cast(dagger.Directory, FakeDirectory(snapshot))
    history = cast(dagger.Directory, object())
    identity = CommitIdentity(RepositoryRef("owner", "repository"), FullSha("d" * 40))
    binding = SourceBinding(source, history, identity, "e" * 64)
    monkeypatch.setattr(guard_module, "dag", FakeDag(operations))

    # When
    result = build_guard(binding)

    # Then
    assert isinstance(result, FakeContainer)
    assert ("mount", "/snapshot", snapshot, True) in operations
    assert ("mount", "/repo", history, True) in operations
    assert ("with_new_file", FOUNDATION_CONFIG_PATH, FOUNDATION_GITLEAKS_CONFIG) in operations
    assert "d" * 40 in str(operations[-1])


def test_should_delegate_public_guard_with_full_source_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    source = cast(dagger.Directory, object())
    history = cast(dagger.Directory, object())
    identity = CommitIdentity(RepositoryRef("owner", "repository"), FullSha("f" * 40))
    binding = SourceBinding(source, history, identity, "0" * 64)
    expected = cast(dagger.Container, object())

    async def bind(
        _: dagger.Directory, __: str, ___: str, http_auth_header: dagger.Secret | None
    ) -> object:
        assert http_auth_header is None
        return binding

    def guard(actual: object) -> dagger.Container:
        assert actual is binding
        return expected

    monkeypatch.setattr(main_module, "_source_binding", bind)
    monkeypatch.setattr(main_module, "build_guard", guard)

    # When
    result: dagger.Container = asyncio.run(
        main_module.PortfolioFoundation().guard(source, "owner/repository", "f" * 40)
    )

    # Then
    assert result is expected


def test_should_abort_guard_before_product_execution_when_private_history_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    source = cast(dagger.Directory, object())
    header = cast(dagger.Secret, object())

    async def bind(_: dagger.Directory, __: str, ___: str, ____: dagger.Secret | None) -> object:
        raise RuntimeError("private history unavailable")

    def guard(_: object) -> dagger.Container:
        raise AssertionError("product execution must not follow history failure")

    monkeypatch.setattr(main_module, "_source_binding", bind)
    monkeypatch.setattr(main_module, "build_guard", guard)

    # When / Then
    with pytest.raises(RuntimeError, match="private history unavailable"):
        asyncio.run(
            main_module.PortfolioFoundation().guard(source, "owner/repository", "f" * 40, header)
        )
