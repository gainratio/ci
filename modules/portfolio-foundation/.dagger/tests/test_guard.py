from __future__ import annotations

import asyncio
import re
import subprocess
from pathlib import Path
from typing import cast

import dagger
import pytest

from portfolio_foundation import guard as guard_module
from portfolio_foundation import main as main_module
from portfolio_foundation.guard import (
    ACTIONLINT_IMAGE,
    GITLEAKS_IMAGE,
    actionlint_command,
    build_guard,
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
    "on: push\njobs:\n  build:\n    runs-on: depot-ubuntu-24.04-4\n    steps:\n      - run: true\n"
)


def _consumer(tmp_path: Path, config_name: str | None) -> Path:
    root = tmp_path / "snapshot"
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / ".github" / "workflows" / "ci.yml").write_text(WORKFLOW)
    if config_name is not None:
        (root / ".github" / config_name).write_text("self-hosted-runner:\n  labels: [depot-*]\n")
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
    assert command.index("/canary") < command.index("/snapshot")
    assert "--redact" in command
    assert "--exit-code" in command


def test_should_generate_canary_without_committing_detector_value() -> None:
    # Given
    command = secret_scan_command("a" * 40)

    # When
    committed_canary = re.search(r"ghp_[A-Za-z0-9]{36}", command)

    # Then
    assert committed_canary is None
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


def test_should_apply_repository_config_to_snapshot_and_history() -> None:
    # Given
    command = secret_scan_command("c" * 40)

    # When / Then
    assert "test -f /snapshot/.gitleaks.toml" in command
    assert "--config /snapshot/.gitleaks.toml" in command
    assert "test -f /repo/.gitleaks.toml" in command
    assert "--config /repo/.gitleaks.toml" in command


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
