"""Hosted central CI runs every shared module's own quality gate."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

import dagger
import pytest

from ci import main as main_module
from ci.main import ENGINE_IMAGE, HOSTED_SKIPPED_TESTS, MODULE_GATES, MODULE_IMAGE, UV_IMAGE, Ci

ROOT = Path(__file__).parents[2]


class FakeGenerated:
    def __init__(self, path: str) -> None:
        self.path = path

    def generated_context_directory(self) -> dagger.Directory:
        return cast(dagger.Directory, f"generated:{self.path}")


class FakeSource:
    def as_module_source(self, *, source_root_path: str) -> FakeGenerated:
        return FakeGenerated(source_root_path)


class FakeContainer:
    def __init__(self, operations: list[tuple[object, ...]]) -> None:
        self.operations = operations

    def from_(self, image: str) -> FakeContainer:
        self.operations.append(("from", image))
        return self

    def file(self, path: str) -> dagger.File:
        return cast(dagger.File, f"file:{path}")

    def with_file(self, path: str, file: dagger.File) -> FakeContainer:
        self.operations.append(("with-file", path, file))
        return self

    def with_directory(self, path: str, directory: dagger.Directory) -> FakeContainer:
        self.operations.append(("directory", path, directory))
        return self

    def with_workdir(self, path: str) -> FakeContainer:
        self.operations.append(("workdir", path))
        return self

    def with_mounted_cache(self, path: str, cache: object) -> FakeContainer:
        return self

    def with_env_variable(self, name: str, value: str) -> FakeContainer:
        self.operations.append(("env", name, value))
        return self

    def with_exec(
        self, command: list[str], *, experimental_privileged_nesting: bool = False
    ) -> FakeContainer:
        self.operations.append(("exec", tuple(command), experimental_privileged_nesting))
        return self


class FakeDag:
    def __init__(self, operations: list[tuple[object, ...]]) -> None:
        self.operations = operations

    def container(self, platform: dagger.Platform | None = None) -> FakeContainer:
        return FakeContainer(self.operations)

    def cache_volume(self, name: str) -> object:
        return name


class FailingGate:
    async def sync(self) -> None:
        raise RuntimeError("module gate failed")


class PassingGate:
    def __init__(self, events: list[str], path: str) -> None:
        self.events = events
        self.path = path

    async def sync(self) -> PassingGate:
        # Like dagger.Container.sync, a passing gate returns the (truthy) synced object.
        self.events.append(self.path)
        return self


def _gate_operations(monkeypatch: pytest.MonkeyPatch, path: str) -> list[tuple[object, ...]]:
    operations: list[tuple[object, ...]] = []
    central = Ci.__new__(Ci)
    central.source = cast(dagger.Directory, FakeSource())
    monkeypatch.setattr(main_module, "dag", FakeDag(operations))
    central._module_gate(path)
    return operations


def _execs(operations: list[tuple[object, ...]]) -> list[tuple[object, ...]]:
    return [item for item in operations if item[0] == "exec"]


def test_should_gate_every_central_module_in_the_repository() -> None:
    # Given every Dagger module shipped under modules/
    shipped = tuple(
        sorted(str(path.parent.relative_to(ROOT)) for path in ROOT.glob("modules/*/dagger.json"))
    )

    # Then hosted CI gates each one, so a new module cannot skip its gate
    assert shipped == (
        "modules/cloudflare-pages",
        "modules/portfolio-foundation",
        "modules/python-package",
    )
    assert shipped == MODULE_GATES


def test_should_run_the_module_poe_gate_with_nested_engine_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given the foundation module
    operations = _gate_operations(monkeypatch, "modules/portfolio-foundation")

    # Then /src is marked as the repository root, so nested Dagger resolves sibling
    # modules, and the module's own frozen environment runs its own `poe gate`
    assert _execs(operations) == [
        ("exec", ("git", "init", "--quiet", "/src"), False),
        ("exec", ("uv", "sync", "--frozen", "--all-groups"), False),
        ("exec", ("uv", "run", "poe", "gate"), True),
    ]
    assert ("workdir", "/src/modules/portfolio-foundation/.dagger") in operations


def test_should_overlay_the_module_generated_sdk_on_the_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given the cloudflare-pages module
    operations = _gate_operations(monkeypatch, "modules/cloudflare-pages")

    # Then the engine-generated client for that module lands on top of the explicit source
    directories = [item for item in operations if item[0] == "directory"]
    assert directories[-1] == ("directory", "/src", "generated:modules/cloudflare-pages")


def test_should_provide_git_uvx_and_the_pinned_dagger_cli(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given any module gate
    operations = _gate_operations(monkeypatch, "modules/python-package")

    # Then the tools its integration tests need come from digest-pinned images
    assert ("from", MODULE_IMAGE) in operations
    assert ("with-file", "/usr/local/bin/uvx", "file:/uvx") in operations
    assert ("with-file", "/usr/local/bin/dagger", "file:/usr/local/bin/dagger") in operations
    assert UV_IMAGE in {item[1] for item in operations if item[0] == "from"}
    assert ENGINE_IMAGE in {item[1] for item in operations if item[0] == "from"}
    assert "@sha256:" in MODULE_IMAGE and "@sha256:" in ENGINE_IMAGE


FOUNDATION_HOST_TESTS = (
    "tests/test_guard_integration.py",
    "tests/test_artifact.py::test_should_envelope_nested_directory_and_reject_unexpected_input",
    "tests/test_artifact.py::test_should_reject_symlink_and_preserve_control_filename_in_evidence",
    "tests/test_bootstrap.py::test_should_bootstrap_clean_module_before_frozen_sync",
    "tests/test_source_integration.py::test_should_bind_exact_nested_public_tree_and_reject_tampering",
)
PAGES_HOST_TESTS = (
    "tests/test_deploy_contract.py::test_should_run_real_dagger_mock_provider_contract",
)


def test_should_deselect_only_the_named_host_engine_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given every module gate
    foundation = _gate_operations(monkeypatch, "modules/portfolio-foundation")
    pages = _gate_operations(monkeypatch, "modules/cloudflare-pages")
    package = _gate_operations(monkeypatch, "modules/python-package")

    # Then only tests that need host Docker or a host Dagger CLI working in a temp
    # directory are left out, each by exact node id, and python-package keeps every test
    assert HOSTED_SKIPPED_TESTS == {
        "modules/portfolio-foundation": FOUNDATION_HOST_TESTS,
        "modules/cloudflare-pages": PAGES_HOST_TESTS,
    }
    expected = " ".join(f"--deselect={test}" for test in FOUNDATION_HOST_TESTS)
    assert ("env", "PYTEST_ADDOPTS", expected) in foundation
    assert ("env", "PYTEST_ADDOPTS", f"--deselect={PAGES_HOST_TESTS[0]}") in pages
    assert ("env", "PYTEST_ADDOPTS", "") in package


def test_should_name_only_tests_that_exist(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given each deselected node id
    for path, tests in HOSTED_SKIPPED_TESTS.items():
        for test in tests:
            file_name, _, name = test.partition("::")
            source = (ROOT / path / ".dagger" / file_name).read_text(encoding="utf-8")

            # Then it names a real test, so a rename cannot silently widen the skip
            assert not name or f"def {name}(" in source


def test_should_run_every_module_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given passing gates
    events: list[str] = []
    central = Ci.__new__(Ci)
    monkeypatch.setattr(central, "_module_gate", lambda path: PassingGate(events, path))

    # When
    asyncio.run(central._module_gates())

    # Then each module was gated
    assert sorted(events) == list(MODULE_GATES)


def test_should_run_every_gate_and_name_each_failed_module(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given the foundation gate fails and the other gates pass
    events: list[str] = []
    central = Ci.__new__(Ci)
    failing = "modules/portfolio-foundation"
    monkeypatch.setattr(
        central,
        "_module_gate",
        lambda path: FailingGate() if path == failing else PassingGate(events, path),
    )

    # When / Then the central gate fails and names the failed module
    with pytest.raises(RuntimeError, match=r"module gates failed: modules/portfolio-foundation"):
        asyncio.run(central._module_gates())
    assert sorted(events) == [path for path in MODULE_GATES if path != failing]
