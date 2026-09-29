from __future__ import annotations

import asyncio
import inspect
import json
import tomllib
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import cast

import dagger
import pytest

from ci import main as main_module
from ci.fleet_policy import (
    SourceFile,
    WorkflowJob,
    WorkflowStep,
    normalize_on_key,
    validate_checkout,
    validate_dagger,
    validate_module_source,
    validate_publisher_permissions,
    validate_typescript_secrets,
    validate_workflow,
)
from ci.github_fleet import AppPayload, CheckPayload, required_scope, to_check_run
from ci.main import PYTHON_IMAGE, SOURCE_EXCLUDES, UV_IMAGE, Ci

ROOT = Path(__file__).parents[2]


class FakeSync:
    def __init__(self, events: list[str] | None = None, label: str = "") -> None:
        self.events = events
        self.label = label

    async def sync(self) -> None:
        if self.events is not None:
            self.events.append(self.label)


class FakeFoundation:
    def __init__(self, events: list[str] | None = None) -> None:
        self.events = events
        self.guard_call: tuple[dagger.Directory, str, str] | None = None

    def guard(self, source: dagger.Directory, repository: str, commit_sha: str) -> FakeSync:
        self.guard_call = (source, repository, commit_sha)
        return FakeSync(self.events, "foundation.guard")


class FakeGitRef:
    async def commit(self) -> str:
        return "b" * 40


class FakeGitRepository:
    def branch(self, name: str) -> FakeGitRef:
        assert name == "main"
        return FakeGitRef()


class FakeDag:
    def __init__(
        self, foundation: FakeFoundation, operations: list[tuple[object, ...]] | None = None
    ) -> None:
        self._foundation = foundation
        self.operations = operations if operations is not None else []
        self.git_calls: list[str] = []

    def foundation(self) -> FakeFoundation:
        return self._foundation

    def git(self, url: str) -> FakeGitRepository:
        self.git_calls.append(url)
        assert url == "https://github.com/hseshadr/ci.git"
        return FakeGitRepository()

    def container(self, platform: dagger.Platform | None = None) -> FakeGraphContainer:
        self.operations.append(("container", platform))
        return FakeGraphContainer(self.operations)

    def current_module(self) -> FakeCurrentModule:
        return FakeCurrentModule()

    def cache_volume(self, name: str) -> object:
        self.operations.append(("cache", name))
        return object()


class FakeCurrentModule:
    def source(self) -> FakeModuleSource:
        return FakeModuleSource()


class FakeModuleSource:
    def directory(self, path: str) -> dagger.Directory:
        assert path == "sdk"
        return cast(dagger.Directory, object())


class FakeGraphContainer:
    def __init__(self, operations: list[tuple[object, ...]]) -> None:
        self.operations = operations

    def from_(self, image: str) -> FakeGraphContainer:
        self.operations.append(("from", image))
        return self

    def file(self, path: str) -> dagger.File:
        self.operations.append(("file", path))
        return cast(dagger.File, object())

    def with_exec(self, command: list[str]) -> FakeGraphContainer:
        self.operations.append(("exec", tuple(command)))
        return self

    def with_secret_variable(self, name: str, secret: dagger.Secret) -> FakeGraphContainer:
        self.operations.append(("secret", name, secret))
        return self

    def with_file(self, path: str, file: dagger.File) -> FakeGraphContainer:
        self.operations.append(("with-file", path, file))
        return self

    def with_directory(self, path: str, directory: dagger.Directory) -> FakeGraphContainer:
        self.operations.append(("directory", path, directory))
        return self

    def with_workdir(self, path: str) -> FakeGraphContainer:
        self.operations.append(("workdir", path))
        return self

    def with_mounted_cache(self, path: str, cache: object) -> FakeGraphContainer:
        self.operations.append(("mounted-cache", path, cache))
        return self

    async def sync(self) -> None:
        self.operations.append(("sync",))


class FakeWorkspace:
    def __init__(self, source: dagger.Directory) -> None:
        self.source = source
        self.arguments: tuple[str, tuple[str, ...]] | None = None

    def directory(self, path: str, *, exclude: list[str]) -> dagger.Directory:
        self.arguments = (path, tuple(exclude))
        return self.source


def test_should_require_explicit_workspace_and_typed_fleet_secret() -> None:
    # Given the public central Dagger object
    create, ci, fleet = (inspect.signature(item) for item in (Ci.create, Ci.ci, Ci.fleet))

    # When its source and hosted credential boundaries are inspected
    workspace_type = str(create.parameters["workspace"].annotation)
    token_type = str(fleet.parameters["github_token"].annotation)
    ci_token_type = str(ci.parameters["github_token"].annotation)

    # Then workspace bytes and the fleet credential are explicit typed inputs
    assert "Workspace" in workspace_type
    assert "Secret" in token_type
    assert "Secret" in ci_token_type
    assert "include_central" in fleet.parameters


def test_should_create_central_graph_from_explicit_workspace() -> None:
    # Given
    source = cast(dagger.Directory, object())
    workspace = FakeWorkspace(source)

    # When
    central = Ci.create(cast(dagger.Workspace, workspace))

    # Then
    assert central.source is source
    assert workspace.arguments == ("/", tuple(SOURCE_EXCLUDES))


def test_should_pin_every_base_image_by_digest() -> None:
    # Given every container image executing repository-authored policy
    images = (PYTHON_IMAGE, UV_IMAGE)

    # When immutable identity is checked
    pinned = tuple("@sha256:" in image for image in images)

    # Then no mutable image tag controls CI execution
    assert all(pinned)


def test_should_give_zizmor_explicit_workflow_inputs() -> None:
    # Given Zizmor's Dagger adapter
    adapter = inspect.getsource(Ci._zizmor)

    # When its audit inputs are inspected
    required_inputs = ("../.github/workflows", "../.github/dependabot.yml")

    # Then collection cannot silently depend on repository-root discovery
    assert all(path in adapter for path in required_inputs)
    assert '"--min-severity", "medium"' in " ".join(adapter.split())


def test_should_not_require_generated_sdk_inside_explicit_source() -> None:
    # Given hosted Workspace bytes, which never contain Dagger's generated SDK
    repository = inspect.getsource(Ci._repository)

    # When the inner Python environment is assembled
    generated_sdk = ("current_module", 'directory("sdk")', '"/src/.dagger/sdk"')

    # Then caller source stays explicit while Dagger supplies its generated toolchain
    assert ".dagger/sdk" in SOURCE_EXCLUDES
    assert all(fragment in repository for fragment in generated_sdk)
    assert '"--frozen"' in repository
    assert '"--all-groups"' in repository


def test_should_install_foundation_from_exact_local_module() -> None:
    # Given
    config = json.loads((ROOT / "dagger.json").read_text())

    # When
    dependency = next(
        item for item in config.get("dependencies", ()) if item["name"] == "foundation"
    )

    # Then
    assert dependency == {"name": "foundation", "source": "modules/portfolio-foundation"}
    assert "@" not in dependency["source"]


def test_should_enforce_branch_coverage_over_central_composition() -> None:
    # Given
    project = tomllib.loads((ROOT / ".dagger" / "pyproject.toml").read_text())
    coverage = project["tool"]["coverage"]["run"]
    tasks = project["tool"]["poe"]["tasks"]

    # When / Then
    assert coverage["branch"] is True
    assert "src/ci/main.py" not in coverage["omit"]
    assert "--cov-branch" in tasks["test"]
    assert "branchrate" in tasks["gate"]
    assert "path.startswith('src/ci/')" in tasks["branchrate"]["shell"]


def test_should_delegate_security_guard_with_exact_source_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    events: list[str] = []
    central, source, shared, fake_dag = _guarded_central(monkeypatch, events)

    # When
    asyncio.run(central._security("a" * 40, cast(dagger.Secret, object())))

    # Then
    assert shared.guard_call == (source, "hseshadr/ci", "a" * 40)
    assert events == ["dependency-audit", "foundation.guard", "zizmor"]
    assert fake_dag.git_calls == []


def test_should_run_public_ci_in_protected_order(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    events: list[str] = []
    central = Ci.__new__(Ci)
    monkeypatch.setattr(central, "_quality", lambda: FakeSync(events, "quality"))
    monkeypatch.setattr(central, "_security", _security_recorder(events))
    monkeypatch.setattr(central, "_module_gates", _gates_recorder(events))
    monkeypatch.setattr(central, "_module_fixtures", _fixture_recorder(events))

    # When
    result: str = asyncio.run(central.ci(cast(dagger.Secret, object()), "a" * 40))

    # Then
    assert result == "central Dagger gate passed"
    assert events == ["quality", "module-gates", "security:" + "a" * 40, "module-fixtures"]


def test_should_run_public_security_without_quality(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    events: list[str] = []
    central = Ci.__new__(Ci)
    monkeypatch.setattr(central, "_security", _security_recorder(events))

    # When
    result: str = asyncio.run(central.security(cast(dagger.Secret, object())))

    # Then
    assert result == "central Dagger security gate passed"
    assert events == ["security:"]


def test_should_build_all_retained_central_graph_lanes(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    operations: list[tuple[object, ...]] = []
    central = Ci.__new__(Ci)
    central.source = cast(dagger.Directory, object())
    token = cast(dagger.Secret, object())
    monkeypatch.setattr(main_module, "dag", FakeDag(FakeFoundation(), operations))

    # When
    central._quality()
    central._dependency_audit()
    central._zizmor(token)

    # Then
    _assert_graph_lanes(operations, token)


def test_should_forward_optional_central_fleet_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    operations: list[tuple[object, ...]] = []
    central = Ci.__new__(Ci)
    monkeypatch.setattr(central, "_repository", lambda: FakeGraphContainer(operations))
    token = cast(dagger.Secret, object())

    # When
    first: str = asyncio.run(central.fleet(token))
    second: str = asyncio.run(central.fleet(token, include_central=True))

    # Then
    assert first == second == "authoritative Dagger fleet policy passed"
    _assert_fleet_commands(operations)


@pytest.mark.parametrize("commit_sha", ["a" * 39, "A" * 40])
def test_should_reject_noncanonical_commit_sha(commit_sha: str) -> None:
    # Given / When / Then
    with pytest.raises(ValueError, match="lowercase 40-character Git SHA"):
        Ci._require_sha(commit_sha)


def test_should_leave_documents_without_boolean_on_key_unchanged() -> None:
    # Given
    document = {"name": "workflow"}

    # When / Then
    assert normalize_on_key(document) is document


def test_should_return_finding_for_invalid_workflow_schema() -> None:
    # Given / When
    result = validate_workflow(SourceFile(path="broken.yml", text="["))

    # Then
    assert tuple(item.code for item in result) == ("workflow-schema",)


def test_should_reject_incomplete_checkout_and_dagger_steps() -> None:
    # Given
    step = WorkflowStep()

    # When
    findings = validate_checkout("workflow.yml", step) + validate_dagger("workflow.yml", step)

    # Then
    assert tuple(item.code for item in findings) == (
        "checkout-credentials",
        "dagger-version",
        "dagger-verb",
    )


def test_should_reject_excess_publisher_permissions() -> None:
    # Given
    job = WorkflowJob(steps=(), permissions={"contents": "write"})

    # When / Then
    assert validate_publisher_permissions("workflow.yml", job)[0].code == "publisher-permissions"


def test_should_reject_missing_module_source_boundary() -> None:
    # Given / When / Then
    assert validate_module_source((), ())[0].code == "explicit-source"


def test_should_reject_plaintext_typescript_secret_boundary() -> None:
    # Given
    module = SourceFile(path="dagger/src/index.ts", text="token: string")

    # When / Then
    assert validate_typescript_secrets((module,))[0].code == "untyped-secret"


def test_should_name_checks_and_contents_read_scopes() -> None:
    # Given / When / Then
    assert required_scope("repos/o/r/commits/x/check-runs") == "Checks:read"
    assert required_scope("repos/o/r/contents/file") == "Contents:read"


def test_should_reject_unfinished_check_conversion() -> None:
    # Given
    check = CheckPayload(
        name="Dagger", head_sha="a" * 40, conclusion=None, app=AppPayload(1, "app")
    )

    # When / Then
    with pytest.raises(ValueError, match="in-progress check"):
        to_check_run(check)


def test_should_preserve_main_resolution_when_commit_is_omitted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    source = cast(dagger.Directory, object())
    shared = FakeFoundation()
    central = Ci.__new__(Ci)
    central.source = source
    monkeypatch.setattr(main_module, "dag", FakeDag(shared))

    # When
    asyncio.run(central._repository_guard(""))

    # Then
    assert shared.guard_call == (source, "hseshadr/ci", "b" * 40)


def _security_recorder(events: list[str]) -> Callable[[str, dagger.Secret], Awaitable[None]]:
    async def record(commit_sha: str, _: dagger.Secret) -> None:
        events.append("security:" + commit_sha)

    return record


def _gates_recorder(events: list[str]) -> Callable[[], Awaitable[None]]:
    async def record() -> None:
        events.append("module-gates")

    return record


def _fixture_recorder(events: list[str]) -> Callable[[], Awaitable[str]]:
    async def record() -> str:
        events.append("module-fixtures")
        return "cross-language Dagger module fixtures passed"

    return record


def _guarded_central(
    monkeypatch: pytest.MonkeyPatch, events: list[str]
) -> tuple[Ci, dagger.Directory, FakeFoundation, FakeDag]:
    source = cast(dagger.Directory, object())
    shared = FakeFoundation(events)
    fake_dag = FakeDag(shared)
    central = Ci.__new__(Ci)
    central.source = source
    monkeypatch.setattr(main_module, "dag", fake_dag)
    monkeypatch.setattr(central, "_dependency_audit", lambda: FakeSync(events, "dependency-audit"))
    monkeypatch.setattr(central, "_zizmor", lambda _: FakeSync(events, "zizmor"))
    return central, source, shared, fake_dag


def _assert_graph_lanes(operations: list[tuple[object, ...]], token: dagger.Secret) -> None:
    commands = _commands(operations)
    assert ("from", PYTHON_IMAGE) in operations
    assert ("from", UV_IMAGE) in operations
    assert ("secret", "GH_TOKEN", token) in operations
    assert any("gate" in command for command in commands)
    assert any("audit" in command for command in commands)
    assert any("zizmor" in command for command in commands)


def _assert_fleet_commands(operations: list[tuple[object, ...]]) -> None:
    commands = _commands(operations)
    assert len(commands) == 2
    assert "--include-central" not in commands[0]
    assert commands[1][-1] == "--include-central"


def _commands(operations: list[tuple[object, ...]]) -> tuple[tuple[str, ...], ...]:
    return tuple(cast(tuple[str, ...], item[1]) for item in operations if item[0] == "exec")
