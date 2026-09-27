from __future__ import annotations

import asyncio
from typing import cast

import dagger
import pytest
from dagger._exceptions import QueryErrorValue
from gql import GraphQLRequest

from portfolio_foundation import change_scope as scope_module
from portfolio_foundation import main as main_module
from portfolio_foundation.change_scope import (
    ChangedPath,
    diff_command,
    is_docs_only,
    parse_raw_diff,
)
from portfolio_foundation.guard import GITLEAKS_IMAGE

BASE = "a" * 40
HEAD = "b" * 40
REGULAR = "100644"
ABSENT = "000000"


def _raw(*entries: tuple[str, str, str]) -> str:
    """Encode `git diff --raw -z` records: (old mode, new mode, path)."""
    blob = "0" * 40
    return "".join(f":{old} {new} {blob} {blob} M\0{path}\0" for old, new, path in entries)


def _changes(*paths: str) -> tuple[ChangedPath, ...]:
    return tuple(ChangedPath(path, REGULAR, REGULAR) for path in paths)


def test_should_fast_path_markdown_only_changes() -> None:
    assert is_docs_only(_changes("README.md", "CHANGELOG.md", "docs/guide/setup.md"))


def test_should_run_full_gate_when_markdown_is_mixed_with_code() -> None:
    assert not is_docs_only(_changes("README.md", "src/app.py"))


@pytest.mark.parametrize(
    "path",
    [
        ".github/workflows/dagger.yml",
        ".github/PULL_REQUEST_TEMPLATE.md",
        "package-lock.json",
        "uv.lock",
        "pyproject.toml",
        "dagger.json",
        "docs/architecture/index.html",
        "docs/architecture/runtime.architecture.json",
        "frontend/README.md",
        "src/content/legal/privacy.md",
        "docs/page.mdx",
        "notes.markdown",
        "README.MD",
        "docs/../src/app.md",
    ],
)
def test_should_run_full_gate_for_non_docs_paths(path: str) -> None:
    assert not is_docs_only(_changes(path))


def test_should_run_full_gate_for_an_empty_diff() -> None:
    assert not is_docs_only(())


@pytest.mark.parametrize(
    ("old", "new"),
    [("120000", "120000"), (REGULAR, "120000"), ("160000", ABSENT), (REGULAR, "100755")],
)
def test_should_run_full_gate_for_symlinks_submodules_and_executables(old: str, new: str) -> None:
    assert not is_docs_only((ChangedPath("README.md", old, new),))


def test_should_fast_path_added_and_deleted_markdown() -> None:
    changes = (ChangedPath("docs/new.md", ABSENT, REGULAR), ChangedPath("OLD.md", REGULAR, ABSENT))
    assert is_docs_only(changes)


def test_should_parse_raw_nul_separated_records_including_odd_names() -> None:
    output = _raw((REGULAR, REGULAR, "README.md"), (ABSENT, REGULAR, "docs/a b\ttab.md"))
    assert parse_raw_diff(output) == (
        ChangedPath("README.md", REGULAR, REGULAR),
        ChangedPath("docs/a b\ttab.md", ABSENT, REGULAR),
    )


def test_should_parse_an_empty_diff_as_no_changes() -> None:
    assert parse_raw_diff("") == ()


@pytest.mark.parametrize(
    "output",
    [
        "README.md\0",
        ":100644 100644 x y M\0",
        ":100644 100644 x y R100\0old.md\0new.md\0",
        ":100644 100644 x y R100\0new.md\0",
        ":100644 100644 x y T\0README.md\0",
        ":100644 100644 x y C75\0README.md\0",
        "100644 100644 x y M\0README.md\0",
        "M\0README.md\0",
    ],
)
def test_should_reject_malformed_or_rename_records(output: str) -> None:
    with pytest.raises(ValueError, match="diff"):
        parse_raw_diff(output)


def test_should_diff_merge_base_to_head_without_rename_folding() -> None:
    command = diff_command(BASE, HEAD)
    assert command[:3] == ["git", "-C", "/repo"]
    assert "--no-renames" in command
    assert "--raw" in command
    assert "-z" in command
    assert command[-1] == f"{BASE}...{HEAD}"


class FakeContainer:
    def __init__(self, stdout: str | Exception) -> None:
        self.result = stdout
        self.operations: list[tuple[object, ...]] = []

    def from_(self, image: str) -> FakeContainer:
        self.operations.append(("from", image))
        return self

    def with_entrypoint(self, entrypoint: list[str]) -> FakeContainer:
        return self

    def with_mounted_directory(
        self, path: str, directory: dagger.Directory, *, read_only: bool
    ) -> FakeContainer:
        self.operations.append(("mount", path, read_only))
        return self

    def with_exec(self, command: list[str]) -> FakeContainer:
        self.operations.append(("exec", tuple(command)))
        return self

    async def stdout(self) -> str:
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FakeDag:
    def __init__(self, container: FakeContainer) -> None:
        self._container = container

    def container(self) -> FakeContainer:
        return self._container


def _classify(monkeypatch: pytest.MonkeyPatch, container: FakeContainer, base: str) -> bool:
    monkeypatch.setattr(scope_module, "dag", FakeDag(container))
    monkeypatch.setattr(scope_module, "dagger_history", lambda *_: cast(dagger.Directory, object()))
    foundation = main_module.PortfolioFoundation()
    return asyncio.run(foundation.docs_only("hseshadr/ci", HEAD, base))


def test_should_fast_path_a_docs_only_pull_request_through_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = FakeContainer(_raw((REGULAR, REGULAR, "README.md")))
    assert _classify(monkeypatch, container, BASE)
    assert ("from", GITLEAKS_IMAGE) in container.operations
    assert ("mount", "/repo", True) in container.operations
    assert ("exec", tuple(diff_command(BASE, HEAD))) in container.operations


def test_should_run_full_gate_for_a_code_pull_request_through_git(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = FakeContainer(_raw((REGULAR, REGULAR, "README.md"), (REGULAR, REGULAR, "a.py")))
    assert not _classify(monkeypatch, container, BASE)


def test_should_run_full_gate_without_touching_git_when_no_base_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = FakeContainer(_raw((REGULAR, REGULAR, "README.md")))
    assert not _classify(monkeypatch, container, "")
    assert container.operations == []


def _exec_error() -> dagger.ExecError:
    extensions = {
        "_type": "EXEC_ERROR",
        "cmd": ["git"],
        "exitCode": 128,
        "stdout": "",
        "stderr": "fatal: bad object",
    }
    value = QueryErrorValue("process did not complete successfully", extensions=extensions)
    request = GraphQLRequest("query { container { id } }")
    error = dagger.QueryError([value], request)
    assert isinstance(error, dagger.ExecError)
    return error


def test_should_run_full_gate_when_git_cannot_diff(monkeypatch: pytest.MonkeyPatch) -> None:
    assert not _classify(monkeypatch, FakeContainer(_exec_error()), BASE)


def test_should_run_full_gate_when_git_output_is_malformed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not _classify(monkeypatch, FakeContainer("README.md\0"), BASE)


@pytest.mark.parametrize(("head", "base"), [("HEAD", BASE), (HEAD, "main"), (HEAD, "A" * 40)])
def test_should_reject_non_canonical_shas(head: str, base: str) -> None:
    foundation = main_module.PortfolioFoundation()
    with pytest.raises(ValueError, match="SHA"):
        asyncio.run(foundation.docs_only("hseshadr/ci", head, base))
