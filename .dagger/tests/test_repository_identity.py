"""ci's own repository identity comes from the run, never from a hardcoded owner.

During the hseshadr -> gainratio move the central repository may be exactly one of two
identities. Every gate is handed `github.repository`; there is no default to go stale.
"""

from __future__ import annotations

import asyncio
import inspect
from pathlib import Path
from typing import cast

import dagger
import pytest

from ci import fleet, github_fleet
from ci import main as main_module
from ci.main import Ci

ROOT = Path(__file__).parents[2]
SHA = "a" * 40
MAIN_SHA = "b" * 40


class _Guarded:
    async def sync(self) -> None:
        return None


class _Foundation:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def guard(self, source: dagger.Directory, repository: str, commit_sha: str) -> _Guarded:
        del source
        self.calls.append((repository, commit_sha))
        return _Guarded()


class _Ref:
    async def commit(self) -> str:
        return MAIN_SHA


class _Remote:
    def branch(self, name: str) -> _Ref:
        assert name == "main"
        return _Ref()


class _Dag:
    def __init__(self) -> None:
        self.shared = _Foundation()
        self.git_urls: list[str] = []

    def foundation(self) -> _Foundation:
        return self.shared

    def git(self, url: str) -> _Remote:
        self.git_urls.append(url)
        return _Remote()


def _central(monkeypatch: pytest.MonkeyPatch) -> tuple[Ci, _Dag]:
    fake = _Dag()
    central = Ci.__new__(Ci)
    central.source = cast(dagger.Directory, object())
    monkeypatch.setattr(main_module, "dag", fake)
    return central, fake


@pytest.mark.parametrize("gate", ["ci", "security"])
def test_should_require_the_runs_repository_with_no_stale_default_owner(gate: str) -> None:
    # Given a public central gate
    parameter = inspect.signature(getattr(Ci, gate)).parameters.get("repository")

    # Then the caller must name the repository, and no owner constant can go stale
    assert parameter is not None
    assert parameter.default is inspect.Parameter.empty
    assert not hasattr(main_module, "REPOSITORY")
    assert not hasattr(main_module, "REPOSITORY_URL")


def test_should_read_the_reviewed_fleet_under_the_gainratio_org() -> None:
    # Given the fleet moved to gainratio, reads must not lean on a transfer redirect
    # Then reviewed repositories and central pin ancestry resolve under gainratio directly
    assert fleet.OWNER == "gainratio"
    assert github_fleet.CENTRAL_REPOSITORY == "repos/gainratio/ci"


def test_should_allow_exactly_the_two_migration_identities() -> None:
    assert main_module.ALLOWED_REPOSITORIES == ("gainratio/ci", "hseshadr/ci")


@pytest.mark.parametrize("repository", ["gainratio/ci", "hseshadr/ci"])
def test_should_guard_the_named_repository_at_the_exact_commit(
    monkeypatch: pytest.MonkeyPatch, repository: str
) -> None:
    # Given ci running under either migration owner
    central, fake = _central(monkeypatch)

    # When the repository guard runs for an exact commit
    asyncio.run(central._repository_guard(SHA, repository))

    # Then the guard binds that identity and never consults a remote branch
    assert fake.shared.calls == [(repository, SHA)]
    assert fake.git_urls == []


def test_should_resolve_main_from_the_named_repository(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given a manual run with no commit after the move
    central, fake = _central(monkeypatch)

    # When the guard resolves main
    asyncio.run(central._repository_guard("", "gainratio/ci"))

    # Then main is read from the run's own repository, not a hardcoded owner
    assert fake.git_urls == ["https://github.com/gainratio/ci.git"]
    assert fake.shared.calls == [("gainratio/ci", MAIN_SHA)]


@pytest.mark.parametrize(
    "repository",
    ["attacker/ci", "gainratio-evil/ci", "hseshadrx/ci", "Gainratio/ci", "gainratio/edge-reco", ""],
)
def test_should_refuse_any_other_repository_before_any_graph_work(
    monkeypatch: pytest.MonkeyPatch, repository: str
) -> None:
    # Given a run claiming a repository outside the allow-list
    central, fake = _central(monkeypatch)

    # When / Then the guard refuses before resolving or guarding anything
    with pytest.raises(ValueError, match="not an allowed repository"):
        asyncio.run(central._repository_guard("", repository))
    assert fake.git_urls == []
    assert fake.shared.calls == []


@pytest.mark.parametrize("name", ["dagger.yml", "dagger-security.yml"])
def test_should_hand_every_gate_the_runs_own_repository(name: str) -> None:
    # Given a workflow that runs the central gate
    text = (ROOT / ".github" / "workflows" / name).read_text()

    # Then the repository comes from GitHub's run context, beside the exact commit
    assert "--repository=${{ github.repository }}" in text
    assert "--commit-sha=${{ github.sha }}" in text
