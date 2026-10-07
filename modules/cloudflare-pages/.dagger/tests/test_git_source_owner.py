"""A declared Git-source owner lets a transferred repo keep its Git-linked Pages project."""

from __future__ import annotations

import json

import pytest

import cloudflare_pages.main as main_module
from cloudflare_pages.api import (
    CloudflarePolicyError,
    parse_project_response,
    require_project_binding,
)
from cloudflare_pages.models import MIGRATION_OWNERS, PagesProject, PagesTarget


def _target(repository: str, git_source_owner: str = "") -> PagesTarget:
    return PagesTarget(
        repository,
        "edge-reco",
        "main",
        "edge-reco.com",
        "dist",
        git_source_owner=git_source_owner,
    )


def _project(owner: str, repo_name: str = "edge-reco") -> PagesProject:
    config = {
        "owner": owner,
        "repo_name": repo_name,
        "production_branch": "main",
        "production_deployments_enabled": False,
        "preview_deployment_setting": "none",
    }
    result = {
        "id": "7b162ea7-7367-4d4a-a28a-cb84f88f6",
        "name": "edge-reco",
        "production_branch": "main",
        "domains": ["edge-reco.pages.dev", "edge-reco.com"],
        "source": {"type": "github", "config": config},
        "created_on": "2026-08-27T20:00:00Z",
    }
    payload = {"errors": [], "messages": [], "result": result, "success": True}
    return parse_project_response(json.dumps(payload))


def test_should_pin_migration_owners_to_exactly_two_literal_owners() -> None:
    # Then the only cross-owner declaration allowed is between these two owners
    assert MIGRATION_OWNERS == ("hseshadr", "gainratio")


def test_should_default_git_source_owner_to_the_target_owner() -> None:
    # Given a target with no declared Git-source owner
    target = _target("hseshadr/edge-reco")

    # Then the source owner is the repository owner, exactly as before this field existed
    assert target.git_source_owner == "hseshadr"
    require_project_binding(_project("hseshadr"), target)


def test_should_accept_declared_source_owner_after_transfer() -> None:
    # Given edge-reco moved to gainratio but its Pages project still says hseshadr
    target = _target("gainratio/edge-reco", git_source_owner="hseshadr")

    # When the project binding is checked
    # Then the declared owner and exact repo name are accepted
    require_project_binding(_project("hseshadr"), target)


def test_should_refuse_undeclared_old_owner_after_transfer() -> None:
    # Given a gainratio target that did not declare the old Git-source owner
    target = _target("gainratio/edge-reco")

    # Then a project still bound to hseshadr is refused
    with pytest.raises(CloudflarePolicyError, match="target binding"):
        require_project_binding(_project("hseshadr"), target)


@pytest.mark.parametrize("owner", ["attacker", "gainratio-evil", "hseshadrx", "gainratio"])
def test_should_refuse_project_bound_to_an_owner_other_than_the_declared_one(owner: str) -> None:
    # Given a declared hseshadr source owner
    target = _target("gainratio/edge-reco", git_source_owner="hseshadr")

    # Then any other stored owner is refused, including the target owner itself
    with pytest.raises(CloudflarePolicyError, match="target binding"):
        require_project_binding(_project(owner), target)


def test_should_refuse_project_bound_to_another_repository_of_the_declared_owner() -> None:
    # Given a declared hseshadr source owner
    target = _target("gainratio/edge-reco", git_source_owner="hseshadr")

    # Then the repository name must still match exactly
    with pytest.raises(CloudflarePolicyError, match="target binding"):
        require_project_binding(_project("hseshadr", "other"), target)


@pytest.mark.parametrize("owner", ["attacker", "gainratio-evil", "hseshadrx", "Hseshadr"])
def test_should_refuse_declaring_a_third_owner_as_git_source(owner: str) -> None:
    # Given a gainratio target declaring a source owner outside the migration pair
    # Then the target cannot be constructed
    with pytest.raises(ValueError, match="git source owner"):
        _target("gainratio/edge-reco", git_source_owner=owner)


def test_should_refuse_cross_owner_declaration_for_a_target_outside_the_pair() -> None:
    # Given a target owned by someone outside the migration pair
    # Then it cannot borrow a migration owner's Git-linked project
    with pytest.raises(ValueError, match="git source owner"):
        _target("attacker/edge-reco", git_source_owner="hseshadr")


@pytest.mark.parametrize("owner", ["bad owner", "-x", "a" * 40])
def test_should_refuse_non_canonical_git_source_owner(owner: str) -> None:
    # Then a malformed owner never reaches the comparison
    with pytest.raises(ValueError, match="git source owner"):
        _target("hseshadr/edge-reco", git_source_owner=owner)


def test_should_thread_git_source_owner_from_dagger_inputs_to_target() -> None:
    # Given the public Dagger function inputs with a declared Git-source owner
    inputs = main_module._target_inputs(
        "gainratio/edge-reco", "edge-reco", "main", "edge-reco.com", "dist", [], False, "hseshadr"
    )

    # When the target is built
    target = main_module._pages_target(inputs)

    # Then the declared owner reaches the binding check
    assert target.git_source_owner == "hseshadr"
    require_project_binding(_project("hseshadr"), target)


def test_should_default_dagger_inputs_to_the_target_owner() -> None:
    # Given the public Dagger function inputs without a declared owner (the empty default)
    inputs = main_module._target_inputs(
        "gainratio/edge-reco", "edge-reco", "main", "edge-reco.com", "dist", [], False, ""
    )

    # Then the target owner is used, so a stale hseshadr project is refused
    target = main_module._pages_target(inputs)
    assert target.git_source_owner == "gainratio"
    with pytest.raises(CloudflarePolicyError, match="target binding"):
        require_project_binding(_project("hseshadr"), target)
