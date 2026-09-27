from __future__ import annotations

import base64
import json
from dataclasses import dataclass

import pytest
from test_github_fleet import FakeTransport as ExactMainTransport
from test_github_fleet import _responses as exact_main_responses

import ci.fleet
from ci.fleet import (
    expectation,
    expectation_for,
    repository_expectations,
    scan_fleet,
    scan_fleet_with,
    scan_repository,
)
from ci.fleet_coverage import (
    UNCOVERED_CODE,
    coverage_results,
    discover_consumers,
    uncovered_consumers,
)
from ci.github_fleet import FleetAccessError, HttpResponse

OWNER = "hseshadr"
CI_SOURCE = "github.com/hseshadr/ci/modules/portfolio-foundation@" + "a" * 40
OTHER_SOURCE = "github.com/dagger/dagger/modules/wolfi@" + "b" * 40
LISTING = "users/hseshadr/repos?type=owner&per_page=100&page={page}"

# The live 2026-09-25 scan's exact set of hseshadr repos whose default-branch
# dagger.json references github.com/hseshadr/ci. A new consumer must be added here
# and to repository_expectations in the same change.
KNOWN_CONSUMERS = (
    "agentic-context-service",
    "agentic-saga",
    "almamesh",
    "aml-filter",
    "assay",
    "edge-proc",
    "edge-reco",
    "edgeproc-core",
    "privacy-core",
)


@dataclass(frozen=True)
class FakeTransport:
    """Return exact fixture responses; every unknown path is a 404."""

    responses: dict[str, HttpResponse]

    def get(self, path: str) -> HttpResponse:
        return self.responses.get(path, HttpResponse(status=404, body="{}"))


def _json(value: object, status: int = 200) -> HttpResponse:
    return HttpResponse(status=status, body=json.dumps(value))


def _repo(name: str, *, archived: bool = False) -> dict[str, object]:
    return {"name": name, "archived": archived, "default_branch": "main"}


def _config(name: str, *sources: str) -> HttpResponse:
    dependencies = [{"name": f"dep{index}", "source": item} for index, item in enumerate(sources)]
    sdk = {"source": "python"}
    config = {"name": name, "engineVersion": "v0.21.8", "sdk": sdk, "dependencies": dependencies}
    text = json.dumps(config)
    encoded = base64.b64encode(text.encode()).decode()
    return _json({"type": "file", "path": "dagger.json", "encoding": "base64", "content": encoded})


def _config_path(name: str) -> str:
    return f"repos/hseshadr/{name}/contents/dagger.json?ref=main"


def _fleet_responses() -> dict[str, HttpResponse]:
    first_page = [_repo(f"filler-{index}") for index in range(98)]
    first_page += [_repo("consumer"), _repo("unrelated")]
    second_page = [_repo("no-dagger"), _repo("retired", archived=True), _repo("covered")]
    return {
        LISTING.format(page=1): _json(first_page),
        LISTING.format(page=2): _json(second_page),
        _config_path("consumer"): _config("consumer", CI_SOURCE),
        _config_path("unrelated"): _config("unrelated", OTHER_SOURCE),
        _config_path("retired"): _config("retired", CI_SOURCE),
        _config_path("covered"): _config("covered", OTHER_SOURCE, CI_SOURCE),
    }


def test_should_discover_every_active_ci_consumer_across_listing_pages() -> None:
    # Given a two-page owner listing with consumers, non-consumers and an archived consumer
    transport = FakeTransport(_fleet_responses())

    # When consumers are discovered from default-branch dagger.json evidence
    discovered = discover_consumers(transport, OWNER)

    # Then only active repositories that pin hseshadr/ci modules are returned
    assert discovered == ("consumer", "covered")


def test_should_report_consumer_missing_from_fleet_expectations() -> None:
    # Given a discovered consumer that the reviewed fleet contract does not name
    transport = FakeTransport(_fleet_responses())
    reviewed = ("assay", "covered")

    # When coverage is evaluated against discovery
    results = coverage_results(transport, OWNER, reviewed)

    # Then only the uncovered consumer fails the scan, with an actionable finding
    assert [(item.name, [f.code for f in item.findings]) for item in results] == [
        ("consumer", [UNCOVERED_CODE])
    ]
    assert results[0].findings[0].path == "dagger.json"
    assert "repository_expectations" in results[0].findings[0].message


def test_should_fail_closed_when_owner_listing_is_unreadable() -> None:
    # Given a listing endpoint that refuses the read
    transport = FakeTransport({LISTING.format(page=1): _json({}, status=403)})

    # When discovery runs
    # Then the scan cannot claim complete coverage
    with pytest.raises(FleetAccessError, match="403"):
        discover_consumers(transport, OWNER)


def test_should_fail_closed_when_consumer_config_is_unreadable() -> None:
    # Given a repository whose dagger.json read fails with something other than 404
    responses = {
        LISTING.format(page=1): _json([_repo("flaky")]),
        _config_path("flaky"): _json({}, status=500),
    }

    # When discovery runs
    # Then the unreadable config is an error, never a silent non-consumer
    with pytest.raises(FleetAccessError, match="500"):
        discover_consumers(FakeTransport(responses), OWNER)


def test_should_cover_every_known_ci_consumer_in_reviewed_expectations() -> None:
    # Given the live-discovered consumer set (stubbed; the hosted scan rediscovers it)
    names = tuple(item.name for item in repository_expectations(True))

    # When coverage is computed against the reviewed fleet contract
    missing = uncovered_consumers(KNOWN_CONSUMERS, names)

    # Then no consumer escapes the fleet scan
    assert missing == ()


@pytest.mark.parametrize("name", ["agentic-context-service", "agentic-saga"])
def test_should_hold_agentic_consumers_to_the_sole_dagger_contract(name: str) -> None:
    # Given an agentic consumer that already declares shared foundation
    # When its reviewed expectation is selected
    item = expectation_for(name)

    # Then it gets the full consumer contract with no rollout exception
    assert item.required_contexts == ("Dagger",)
    assert item.conversation_resolution is True
    assert item.linear_history is False
    assert item.shared_foundation_required is True
    assert item.grandfathered_until is None


def test_should_report_unreadable_repository_as_finding_and_keep_scanning() -> None:
    # Given a consumer whose protection endpoint 404s (for example, unprotected main)
    transport = FakeTransport({})

    # When that one repository is scanned
    result = scan_repository(transport, expectation_for("agentic-context-service"))

    # Then the failure is a named finding, so later repositories are still evaluated
    assert result.name == "agentic-context-service"
    assert [item.code for item in result.findings] == ["evidence-unreadable"]
    assert "404" in result.findings[0].message


def test_should_fail_hosted_scan_for_uncovered_consumer_before_reviewed_repositories() -> None:
    # Given a live listing where one consumer is unknown to the reviewed contract
    responses = {
        LISTING.format(page=1): _json([_repo("newcomer"), _repo("assay")]),
        _config_path("newcomer"): _config("newcomer", CI_SOURCE),
        _config_path("assay"): _config("assay", CI_SOURCE),
    }

    # When the whole fleet scan runs (reviewed repositories are unreadable here)
    results = scan_fleet_with(FakeTransport(responses), include_central=False)

    # Then the uncovered consumer is reported and every reviewed repository still runs
    assert results[0].name == "newcomer"
    assert [item.code for item in results[0].findings] == [UNCOVERED_CODE]
    reviewed = tuple(item.name for item in repository_expectations(False))
    assert tuple(item.name for item in results[1:]) == reviewed
    assert all(item.findings for item in results)


def test_should_evaluate_readable_repository_against_its_contract() -> None:
    # Given complete exact-main evidence for one reviewed repository
    transport = ExactMainTransport(exact_main_responses())

    # When that repository is scanned
    result = scan_repository(transport, expectation("example"))

    # Then its identity is the exact main SHA and no evidence error is reported
    assert (result.name, result.sha) == ("example", "a" * 40)
    assert "evidence-unreadable" not in {item.code for item in result.findings}


def test_should_reject_unknown_fleet_repository_name() -> None:
    # Given a name the reviewed contract does not contain
    # When its expectation is requested
    # Then the caller is told instead of receiving a default contract
    with pytest.raises(ValueError, match="unknown fleet repository: nope"):
        expectation_for("nope")


def test_should_scan_hosted_fleet_through_authenticated_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a hosted run that supplies only a token
    seen: list[object] = []

    def fake_scan(transport: object, include_central: bool) -> tuple[()]:
        seen.append((type(transport).__name__, include_central))
        return ()

    monkeypatch.setattr(ci.fleet, "scan_fleet_with", fake_scan)

    # When the fleet is scanned
    scan_fleet("token", include_central=True)

    # Then the real GitHub transport performs discovery and every repository read
    assert seen == [("GitHubHttpTransport", True)]
