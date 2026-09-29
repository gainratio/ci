from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping

import pytest

from portfolio_foundation.github import (
    ApiTarget,
    GitHubCredentialError,
    GitHubPolicyError,
    GitHubResponseError,
    HttpPage,
)
from portfolio_foundation.lineage import (
    LineageEvidence,
    LineageRequest,
    provenance_context,
    release_lineage,
    release_provenance,
    verify_release_lineage_from_api,
)

REPOSITORY = "owner/repository"
BASE = f"/repos/{REPOSITORY}"
CANDIDATE_RUN = 111
PUBLISH_RUN = 222
HEAD = "a" * 40
MAIN = "b" * 40
BRANCH = "c" * 40
ATTACKER = "d" * 40

type Json = dict[str, object]


def _repository(full_name: str = REPOSITORY) -> Json:
    return {"id": 42, "full_name": full_name, "owner": {"id": 7}}


def _candidate(**overrides: object) -> Json:
    run: Json = {
        "id": CANDIDATE_RUN,
        "name": "Dagger release candidate",
        "path": ".github/workflows/release-candidate.yml",
        "head_branch": "main",
        "head_sha": HEAD,
        "status": "completed",
        "conclusion": "success",
        "event": "workflow_dispatch",
        "run_attempt": 1,
        "repository": _repository(),
        "head_repository": {"full_name": REPOSITORY},
    }
    return run | overrides


def _publisher(**overrides: object) -> Json:
    run: Json = {
        "id": PUBLISH_RUN,
        "name": "Publish (npm, OIDC)",
        "path": ".github/workflows/publish.yml",
        "head_branch": "main",
        "head_sha": MAIN,
        "status": "in_progress",
        "conclusion": None,
        "event": "workflow_run",
        "run_attempt": 2,
        "repository": _repository(),
        "head_repository": {"full_name": REPOSITORY},
    }
    return run | overrides


class FakeApi:
    def __init__(self, pages: Mapping[str, object]) -> None:
        self._pages = pages
        self.requested: list[str] = []

    async def get(self, target: ApiTarget) -> HttpPage:
        self.requested.append(target.value)
        return HttpPage(json.dumps(self._pages[target.value]))


class FakeSecret:
    def __init__(self, plaintext: str) -> None:
        self._plaintext = plaintext

    async def plaintext(self) -> str:
        return self._plaintext


def _pages(
    *,
    candidate: Json | None = None,
    publisher: Json | None = None,
    head_status: str = "ahead",
    main_status: str = "identical",
    head: str = HEAD,
) -> dict[str, object]:
    return {
        f"{BASE}/actions/runs/{CANDIDATE_RUN}": candidate or _candidate(),
        f"{BASE}/actions/runs/{PUBLISH_RUN}": publisher or _publisher(),
        f"{BASE}/compare/{head}...{MAIN}": {"status": head_status},
        f"{BASE}/branches/main": {"name": "main", "commit": {"sha": BRANCH}},
        f"{BASE}/compare/{MAIN}...{BRANCH}": {"status": main_status},
    }


def _request(head: str = HEAD) -> LineageRequest:
    return LineageRequest.parse(REPOSITORY, CANDIDATE_RUN, head, PUBLISH_RUN)


def _verify(pages: Mapping[str, object], head: str = HEAD) -> LineageEvidence:
    return asyncio.run(verify_release_lineage_from_api(FakeApi(pages), _request(head)))


def test_should_accept_a_candidate_dispatched_on_main_and_contained_in_main() -> None:
    # Given a successful dispatch whose commit main already contains
    api = FakeApi(_pages())

    # When lineage is verified
    evidence = asyncio.run(verify_release_lineage_from_api(api, _request()))

    # Then the evidence binds the candidate, the publisher commit, and live main
    assert (evidence.head_sha, evidence.main_sha, evidence.branch_sha) == (HEAD, MAIN, BRANCH)
    assert json.loads(evidence.to_json()) == {
        "repository": REPOSITORY,
        "candidate_run_id": CANDIDATE_RUN,
        "publish_run_id": PUBLISH_RUN,
        "head_sha": HEAD,
        "main_sha": MAIN,
        "branch_sha": BRANCH,
    }
    assert f"{BASE}/compare/{HEAD}...{MAIN}" in api.requested


@pytest.mark.parametrize("status", ["diverged", "behind"])
def test_should_reject_a_tag_named_main_whose_commit_is_not_on_main(status: str) -> None:
    # Given a dispatch on a TAG named `main`: head_branch reads "main" and the run
    # succeeded, but the tagged commit is attacker-authored and not in main's history
    pages = _pages(candidate=_candidate(head_sha=ATTACKER), head=ATTACKER, head_status=status)

    # When / Then the publisher refuses before any artifact is trusted
    with pytest.raises(GitHubPolicyError, match="not contained in main"):
        _verify(pages, head=ATTACKER)


def test_should_reject_a_candidate_run_for_a_different_sha() -> None:
    # Given the event names one SHA but the run record built another
    pages = _pages(candidate=_candidate(head_sha=ATTACKER))

    # When / Then
    with pytest.raises(GitHubPolicyError, match="candidate run"):
        _verify(pages)


def test_should_reject_a_publisher_commit_that_main_does_not_contain() -> None:
    # Given a publisher commit that has left (or never joined) main
    pages = _pages(main_status="diverged")

    # When / Then
    with pytest.raises(GitHubPolicyError, match="not contained in main"):
        _verify(pages)


@pytest.mark.parametrize(
    "override",
    [
        {"event": "push"},
        {"status": "in_progress"},
        {"conclusion": "failure"},
        {"conclusion": None},
        {"path": ".github/workflows/other.yml"},
        {"path": ".github/workflows/release-candidate.yml.evil"},
        {"repository": _repository("attacker/repository")},
        {"head_repository": {"full_name": "attacker/repository"}},
        {"id": CANDIDATE_RUN + 1},
    ],
)
def test_should_reject_any_candidate_run_that_is_not_a_successful_release_dispatch(
    override: Json,
) -> None:
    # Given a candidate run record that differs in one identity field
    pages = _pages(candidate=_candidate(**override))

    # When / Then
    with pytest.raises(GitHubPolicyError, match="candidate run"):
        _verify(pages)


def test_should_accept_a_dispatch_path_carrying_its_ref_suffix() -> None:
    # Given GitHub's `path@ref` form for a dispatched run
    pages = _pages(candidate=_candidate(path=".github/workflows/release-candidate.yml@main"))

    # When / Then
    assert _verify(pages) is not None


@pytest.mark.parametrize(
    "override",
    [
        {"event": "workflow_dispatch"},
        {"status": "completed"},
        {"path": ".github/workflows/release-candidate.yml"},
        {"head_branch": "feature"},
        {"repository": _repository("attacker/repository")},
        {"id": PUBLISH_RUN + 1},
    ],
)
def test_should_reject_a_publish_run_that_is_not_this_repositorys_running_publisher(
    override: Json,
) -> None:
    # Given a publish run record that is not the live main publish.yml workflow_run
    pages = _pages(publisher=_publisher(**override))

    # When / Then
    with pytest.raises(GitHubPolicyError, match="publish run"):
        _verify(pages)


def test_should_reject_a_publish_run_whose_sha_is_not_a_full_sha() -> None:
    pages = _pages(publisher=_publisher(head_sha="B" * 40))

    with pytest.raises(GitHubPolicyError, match="publish run"):
        _verify(pages)


def test_should_reject_a_response_that_omits_an_identity_field() -> None:
    candidate = _candidate()
    del candidate["head_repository"]

    with pytest.raises(GitHubResponseError):
        _verify(_pages(candidate=candidate))


@pytest.mark.parametrize(
    ("repository", "run_id", "head", "publish_run"),
    [
        ("owner", CANDIDATE_RUN, HEAD, PUBLISH_RUN),
        (REPOSITORY, 0, HEAD, PUBLISH_RUN),
        (REPOSITORY, CANDIDATE_RUN, HEAD[:7], PUBLISH_RUN),
        (REPOSITORY, CANDIDATE_RUN, "A" * 40, PUBLISH_RUN),
        (REPOSITORY, CANDIDATE_RUN, HEAD, -1),
    ],
)
def test_should_reject_malformed_lineage_inputs_before_any_request(
    repository: str, run_id: int, head: str, publish_run: int
) -> None:
    with pytest.raises(ValueError, match="lineage"):
        LineageRequest.parse(repository, run_id, head, publish_run)


def test_should_derive_the_npm_provenance_context_from_the_publish_run_record() -> None:
    # Given verified lineage and the authoritative publish run record
    evidence = _verify(_pages())

    # When the npm provenance context is rendered
    context = json.loads(provenance_context(evidence))

    # Then it carries exactly the GitHub Actions values npm writes into provenance
    assert context == {
        "GITHUB_EVENT_NAME": "workflow_run",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": "42",
        "GITHUB_REPOSITORY_OWNER_ID": "7",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_RUN_ID": str(PUBLISH_RUN),
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_SHA": MAIN,
        "GITHUB_WORKFLOW": "Publish (npm, OIDC)",
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/publish.yml@refs/heads/main",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }


def test_should_read_the_typed_token_and_verify_through_the_rest_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given the REST adapter is replaced by the fake provider
    tokens: list[str] = []

    def adapter(token: str) -> FakeApi:
        tokens.append(token)
        return FakeApi(_pages())

    monkeypatch.setattr("portfolio_foundation.lineage._GitHubRestApi", adapter)
    secret = FakeSecret("token-value")

    # When both public entry points run
    lineage = asyncio.run(release_lineage(secret, _request()))  # type: ignore[arg-type]
    context = asyncio.run(release_provenance(secret, _request()))  # type: ignore[arg-type]

    # Then each read the typed secret once and returned its rendered evidence
    assert tokens == ["token-value", "token-value"]
    assert json.loads(lineage)["head_sha"] == HEAD
    assert json.loads(context)["GITHUB_SHA"] == MAIN


def test_should_refuse_an_empty_token() -> None:
    with pytest.raises(GitHubCredentialError):
        asyncio.run(release_lineage(FakeSecret(""), _request()))  # type: ignore[arg-type]
