"""Dual-owner prep for the hseshadr -> gainratio move: exactly two owners, never a pattern."""

from __future__ import annotations

from dataclasses import replace

import pytest
from test_fleet_policy import (
    HEAD_SHA,
    INGRESS,
    NPM_BRIDGE,
    _codes,
    _shared_codes,
    _shared_configs,
    _snapshot,
)
from test_fleet_policy import (
    SHA as POLICY_SHA,
)
from test_fleet_release_lineage import (
    CI_PIN,
    DOWNLOAD_STEP,
    HEADER,
    LINEAGE_CALL,
    NPM_PUBLISHER,
    PROVENANCE_CALL,
    PYPI_STEP,
    _lineage,
)
from test_fleet_release_lineage import _codes as _workflow_codes

from ci.fleet_policy import (
    ALLOWED_OWNERS,
    DaggerConfig,
    DaggerDependency,
    SourceFile,
    validate_minimum_pins,
)
from ci.github_fleet import legacy_references

ALLOWED = ("hseshadr", "gainratio")
# Lookalikes a pattern such as [a-z-]+ or a prefix/suffix match would let through.
REFUSED = ("attacker", "gainratio-evil", "hseshadrx", "xgainratio", "Gainratio", "HSESHADR")
# Case variants are excluded here: legacy detection is a deny rule, so it must not assert a miss.
NON_CENTRAL = ("attacker", "gainratio-evil", "hseshadrx", "xgainratio")


def test_should_pin_the_owner_allow_list_to_exactly_two_literal_owners() -> None:
    # Given the reviewed migration plan (ops/docs/org-migration-gainratio.md)
    # Then the allow-list is exactly these two owners, in this order, and nothing else
    assert ALLOWED_OWNERS == ("hseshadr", "gainratio")


@pytest.mark.parametrize("owner", ALLOWED)
def test_should_accept_shared_module_pinned_at_either_allowed_owner(owner: str) -> None:
    # Given a consumer config pinned at the central foundation under an allowed owner
    source = f"github.com/{owner}/ci/modules/portfolio-foundation@" + "b" * 40
    snapshot = replace(_snapshot(INGRESS), dagger_configs=_shared_configs(source))

    # When shared dependency identity is evaluated
    # Then the publisher is accepted
    assert "shared-module-publisher" not in _shared_codes(snapshot)


@pytest.mark.parametrize("owner", REFUSED)
def test_should_refuse_shared_module_pinned_at_any_third_owner(owner: str) -> None:
    # Given a lookalike owner publishes the same module path at an exact SHA
    source = f"github.com/{owner}/ci/modules/portfolio-foundation@" + "b" * 40
    snapshot = replace(_snapshot(INGRESS), dagger_configs=_shared_configs(source))

    # Then an exact SHA cannot compensate for the wrong owner
    assert "shared-module-publisher" in _shared_codes(snapshot)


def _bridge_codes(module: str) -> tuple[str, ...]:
    bridge = NPM_BRIDGE.replace(f"github.com/hseshadr/example@{HEAD_SHA}", module)
    return _codes(_snapshot(bridge))


@pytest.mark.parametrize("owner", ALLOWED)
def test_should_accept_central_npm_publisher_from_either_allowed_owner(owner: str) -> None:
    # Given the approved central npm publisher at a literal SHA under an allowed owner
    codes = _bridge_codes(f"github.com/{owner}/ci/modules/npm-publisher@" + "b" * 40)

    # Then it is accepted
    assert "publisher-module-identity" not in codes
    assert "remote-module-identity" not in codes


@pytest.mark.parametrize("owner", REFUSED)
def test_should_refuse_central_npm_publisher_from_any_third_owner(owner: str) -> None:
    # Given a lookalike npm publisher at a literal SHA
    codes = _bridge_codes(f"github.com/{owner}/ci/modules/npm-publisher@" + "b" * 40)

    # Then the publisher identity is refused
    assert "publisher-module-identity" in codes


def _publisher_under(owner: str) -> str:
    return NPM_PUBLISHER.replace("github.com/hseshadr/", f"github.com/{owner}/")


@pytest.mark.parametrize("owner", ALLOWED)
def test_should_accept_consumer_publisher_at_main_sha_under_either_owner(owner: str) -> None:
    # Given the consumer's own publisher at github.sha, addressed under an allowed owner
    publisher = _publisher_under(owner)
    workflow = HEADER + _lineage(PROVENANCE_CALL) + DOWNLOAD_STEP + publisher

    # Then the policy reports nothing
    assert _workflow_codes(workflow) == ()


@pytest.mark.parametrize("owner", REFUSED)
def test_should_refuse_consumer_publisher_at_main_sha_under_third_owner(owner: str) -> None:
    # Given the same publisher addressed under a fork owner
    publisher = _publisher_under(owner)
    workflow = HEADER + _lineage(PROVENANCE_CALL) + DOWNLOAD_STEP + publisher

    # Then the fork's code is never trusted to publish
    refused = {"publisher-module-identity", "remote-module-identity"}
    assert refused & set(_workflow_codes(workflow))


@pytest.mark.parametrize("owner", ALLOWED)
def test_should_accept_central_lineage_from_either_allowed_owner(owner: str) -> None:
    # Given the literal-pinned lineage proof loaded from an allowed owner's central repo
    module = f"github.com/{owner}/ci/modules/portfolio-foundation@{CI_PIN}"
    workflow = HEADER + _lineage(LINEAGE_CALL, module=module) + DOWNLOAD_STEP + PYPI_STEP

    # Then the policy reports nothing
    assert _workflow_codes(workflow) == ()


@pytest.mark.parametrize("owner", REFUSED)
def test_should_refuse_central_lineage_from_any_third_owner(owner: str) -> None:
    # Given the lineage call loaded from a lookalike owner
    module = f"github.com/{owner}/ci/modules/portfolio-foundation@{CI_PIN}"
    workflow = HEADER + _lineage(LINEAGE_CALL, module=module) + DOWNLOAD_STEP + PYPI_STEP

    # Then it is an unapproved Dagger step in the PyPI bridge
    assert "pypi-shape" in _workflow_codes(workflow)


def _provider_ingress_codes(owner: str) -> tuple[str, ...]:
    provider = f"github.com/{owner}/ci/modules/cloudflare-pages@" + "b" * 40
    direct_call = f"          verb: call\n          module: {provider}"
    workflow = INGRESS.replace("          verb: call", direct_call)
    snapshot = replace(_snapshot(workflow), repository_secret_names=("CLOUDFLARE_API_TOKEN",))
    return _codes(snapshot)


@pytest.mark.parametrize("owner", ALLOWED)
def test_should_accept_direct_provider_ingress_from_either_allowed_owner(owner: str) -> None:
    # Given a direct call to the exact central Cloudflare provider under an allowed owner
    codes = _provider_ingress_codes(owner)

    # Then it is recognised as the provider (environment scoping applies) and not refused
    assert "publisher-module-identity" not in codes
    assert "unscoped-production-secret" in codes


@pytest.mark.parametrize("owner", REFUSED)
def test_should_refuse_direct_provider_ingress_from_any_third_owner(owner: str) -> None:
    # Given the same provider path published by a lookalike owner
    # Then the remote module identity is refused
    assert "publisher-module-identity" in _provider_ingress_codes(owner)


def _central_graph(root_owner: str, child_owner: str) -> tuple[DaggerConfig, ...]:
    dependency = DaggerDependency(name="foundation", source="modules/portfolio-foundation")
    root = DaggerConfig(
        identity=f"github.com/{root_owner}/ci@{POLICY_SHA}",
        path="dagger.json",
        name="ci",
        engine_version="v0.21.8",
        dependencies=(dependency,),
    )
    child = DaggerConfig(
        identity=f"github.com/{child_owner}/ci/modules/portfolio-foundation@{POLICY_SHA}",
        path="modules/portfolio-foundation/dagger.json",
        name="portfolio-foundation",
        engine_version="v0.21.8",
    )
    return root, child


@pytest.mark.parametrize("owner", ALLOWED)
def test_should_accept_central_local_edge_under_either_allowed_owner(owner: str) -> None:
    # Given the central root and foundation read from one snapshot under an allowed owner
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=_central_graph(owner, owner))

    # Then the same-tree local edge is accepted
    assert "shared-module-publisher" not in _codes(snapshot)


@pytest.mark.parametrize("owner", REFUSED)
def test_should_refuse_central_local_edge_under_any_third_owner(owner: str) -> None:
    # Given the same graph read from a lookalike owner's repository
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=_central_graph(owner, owner))

    # Then it is not the central tree
    assert "shared-module-publisher" in _codes(snapshot)


def test_should_refuse_central_local_edge_that_mixes_owners() -> None:
    # Given a gainratio root whose local foundation edge resolved under hseshadr
    configs = _central_graph("gainratio", "hseshadr")
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=configs)

    # Then the edge is not one exact snapshot and is refused
    assert "shared-module-publisher" in _codes(snapshot)


def _floor_codes(owner: str) -> tuple[str, ...]:
    config = DaggerConfig(
        identity=f"github.com/{owner}/ci/modules/portfolio-foundation@" + "e" * 40,
        path="modules/portfolio-foundation/dagger.json",
        name="shared",
        engine_version="v0.21.8",
    )
    return tuple(item.code for item in validate_minimum_pins((config,), ()))


@pytest.mark.parametrize("owner", ALLOWED)
def test_should_floor_central_pin_under_either_allowed_owner(owner: str) -> None:
    # Given a central foundation pin with no ancestry evidence under an allowed owner
    # Then the required floor still applies and fails closed
    assert _floor_codes(owner) == ("pin-below-required-minimum",)


@pytest.mark.parametrize("owner", REFUSED)
def test_should_not_treat_third_owner_pin_as_central_floor_evidence(owner: str) -> None:
    # Given the same pin under a lookalike owner (refused by shared-module-publisher instead)
    # Then it is not mistaken for the central module
    assert _floor_codes(owner) == ()


@pytest.mark.parametrize("owner", ALLOWED)
def test_should_flag_legacy_central_workflow_call_under_either_owner(owner: str) -> None:
    # Given a consumer workflow that still calls a retired central reusable workflow
    text = f"jobs:\n  scan:\n    uses: {owner}/ci/.github/workflows/secret-scan.yml@{'a' * 40}\n"
    workflows = (SourceFile(path=".github/workflows/ci.yml", text=text),)

    # Then it is reported as a legacy central reference
    assert legacy_references(workflows) == (".github/workflows/ci.yml",)


@pytest.mark.parametrize("owner", NON_CENTRAL)
def test_should_not_flag_third_owner_workflow_as_central(owner: str) -> None:
    # Given a workflow that calls a lookalike owner's reusable workflow
    text = f"jobs:\n  scan:\n    uses: {owner}/ci/.github/workflows/secret-scan.yml@{'a' * 40}\n"
    workflows = (SourceFile(path=".github/workflows/ci.yml", text=text),)

    # Then it is not the central repository
    assert legacy_references(workflows) == ()
