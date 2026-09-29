"""Fail-closed release lineage: a publisher ships only a candidate that main contains.

A `workflow_run` publisher gated on `head_branch == default_branch` also fires for a
dispatch on a TAG named `main`, whose tagged commit (and its release workflow) the
tagger wrote. Before any publisher trusts the candidate artifact, this proves from
GitHub's own run records that:

- the candidate run is a successful `workflow_dispatch` of `release-candidate.yml` in
  this repository for exactly the expected SHA;
- the publish run is this repository's running `publish.yml` `workflow_run` on `main`;
- main's history contains the candidate SHA and the publisher's commit.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Final

import dagger
from pydantic import Field, JsonValue

from .github import (
    ApiTarget,
    ClosedPayload,
    GitHubApi,
    GitHubCredentialError,
    GitHubPolicyError,
    _GitHubRestApi,
    _json_object,
    _main_sha,
    _model,
    _object,
    _project,
    _required,
)
from .identity import FullSha, RepositoryRef

CANDIDATE_WORKFLOW: Final = ".github/workflows/release-candidate.yml"
PUBLISH_WORKFLOW: Final = ".github/workflows/publish.yml"
DESCENDANT_STATUSES: Final = frozenset(("ahead", "identical"))
SERVER_URL: Final = "https://github.com"
RUN_FIELDS: Final = (
    "id",
    "name",
    "path",
    "head_branch",
    "head_sha",
    "status",
    "conclusion",
    "event",
    "run_attempt",
)


class OwnerPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected repository owner identity."""

    id: int = Field(gt=0)


class RunRepositoryPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected repository identity of a workflow run."""

    id: int = Field(gt=0)
    full_name: str
    owner: OwnerPayload


class HeadRepositoryPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected repository that supplied a run's head commit."""

    full_name: str


class LineageRunPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected workflow-run identity for candidate and publish runs."""

    id: int = Field(gt=0)
    name: str
    path: str
    head_branch: str
    head_sha: str
    status: str
    conclusion: str | None
    event: str
    run_attempt: int = Field(gt=0)
    repository: RunRepositoryPayload
    head_repository: HeadRepositoryPayload


class ComparePayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected ancestry relation between two commits."""

    status: str


@dataclass(frozen=True)
class LineageRequest:
    """Typed lineage inputs: one repository, candidate run, SHA, and publish run."""

    repository: RepositoryRef
    candidate_run_id: int
    head_sha: FullSha
    publish_run_id: int

    @classmethod
    def parse(
        cls, repository: str, candidate_run_id: int, head_sha: str, publish_run_id: int
    ) -> LineageRequest:
        """Reject malformed identities before any provider request."""
        if min(candidate_run_id, publish_run_id) <= 0:
            raise ValueError("lineage run ids must be positive")
        try:
            parsed = RepositoryRef.parse(repository), FullSha(head_sha)
        except ValueError:
            raise ValueError("lineage repository and head SHA must be canonical") from None
        return cls(parsed[0], candidate_run_id, parsed[1], publish_run_id)

    @property
    def base(self) -> str:
        """Return the repository API path."""
        return f"/repos/{self.repository.owner}/{self.repository.name}"

    @property
    def full_name(self) -> str:
        """Return canonical owner/repository text."""
        return f"{self.repository.owner}/{self.repository.name}"


@dataclass(frozen=True)
class LineageEvidence:
    """Proven lineage plus the authoritative publish run it was proven for."""

    repository: str
    candidate_run_id: int
    publish_run_id: int
    head_sha: str
    main_sha: str
    branch_sha: str
    publisher: LineageRunPayload

    def to_json(self) -> str:
        """Render the proven identities without the raw run record."""
        values = {
            "repository": self.repository,
            "candidate_run_id": self.candidate_run_id,
            "publish_run_id": self.publish_run_id,
            "head_sha": self.head_sha,
            "main_sha": self.main_sha,
            "branch_sha": self.branch_sha,
        }
        return json.dumps(values)


async def release_lineage(github_token: dagger.Secret, request: LineageRequest) -> str:
    """Verify lineage with a typed secret and return the evidence as JSON."""
    return (await _verified(github_token, request)).to_json()


async def release_provenance(github_token: dagger.Secret, request: LineageRequest) -> str:
    """Verify lineage, then render npm's provenance context from the publish run."""
    return provenance_context(await _verified(github_token, request))


async def _verified(github_token: dagger.Secret, request: LineageRequest) -> LineageEvidence:
    token = await github_token.plaintext()
    if not token:
        raise GitHubCredentialError
    return await verify_release_lineage_from_api(_GitHubRestApi(token), request)


async def verify_release_lineage_from_api(
    api: GitHubApi, request: LineageRequest
) -> LineageEvidence:
    """Apply the lineage policy to a read-only API adapter."""
    candidate = await _run(api, request, request.candidate_run_id)
    _require_candidate(candidate, request)
    publisher = await _run(api, request, request.publish_run_id)
    _require_publisher(publisher, request)
    main_sha = publisher.head_sha
    await _require_contained(api, request, request.head_sha.value, main_sha)
    branch_sha = await _main_sha(api, request.repository)
    await _require_contained(api, request, main_sha, branch_sha)
    return _evidence(request, branch_sha, publisher)


def _evidence(
    request: LineageRequest, branch_sha: str, publisher: LineageRunPayload
) -> LineageEvidence:
    runs = (request.candidate_run_id, request.publish_run_id)
    shas = (request.head_sha.value, publisher.head_sha, branch_sha)
    return LineageEvidence(request.full_name, *runs, *shas, publisher)


def provenance_context(evidence: LineageEvidence) -> str:
    """Render the GitHub Actions context npm writes into its SLSA provenance."""
    run = evidence.publisher
    ref = f"refs/heads/{run.head_branch}"
    context = _repository_context(run) | {
        "GITHUB_EVENT_NAME": run.event,
        "GITHUB_REF": ref,
        "GITHUB_RUN_ATTEMPT": str(run.run_attempt),
        "GITHUB_RUN_ID": str(run.id),
        "GITHUB_SHA": run.head_sha,
        "GITHUB_WORKFLOW": run.name,
        "GITHUB_WORKFLOW_REF": f"{run.repository.full_name}/{PUBLISH_WORKFLOW}@{ref}",
    }
    return json.dumps(dict(sorted(context.items())), indent=2) + "\n"


def _repository_context(run: LineageRunPayload) -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": run.repository.full_name,
        "GITHUB_REPOSITORY_ID": str(run.repository.id),
        "GITHUB_REPOSITORY_OWNER_ID": str(run.repository.owner.id),
        "GITHUB_SERVER_URL": SERVER_URL,
        "RUNNER_ENVIRONMENT": "github-hosted",
    }


async def _run(api: GitHubApi, request: LineageRequest, run_id: int) -> LineageRunPayload:
    page = await api.get(ApiTarget(f"{request.base}/actions/runs/{run_id}"))
    return _model(LineageRunPayload, _project_run(_json_object(page.body)))


def _project_run(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    repository = _object(_required(payload, "repository"))
    owner = _project(_object(_required(repository, "owner")), ("id",))
    projected = _project(repository, ("id", "full_name")) | {"owner": owner}
    head = _project(_object(_required(payload, "head_repository")), ("full_name",))
    return _project(payload, RUN_FIELDS) | {"repository": projected, "head_repository": head}


def _candidate_identity(run: LineageRunPayload) -> tuple[object, ...]:
    return (
        run.id,
        run.head_sha,
        run.event,
        run.status,
        run.conclusion,
        run.path.partition("@")[0],
        run.repository.full_name,
        run.head_repository.full_name,
    )


def _require_candidate(run: LineageRunPayload, request: LineageRequest) -> None:
    expected = (
        request.candidate_run_id,
        request.head_sha.value,
        "workflow_dispatch",
        "completed",
        "success",
        CANDIDATE_WORKFLOW,
        request.full_name,
        request.full_name,
    )
    if _candidate_identity(run) != expected:
        raise GitHubPolicyError("candidate run is not a successful release dispatch of this SHA")


def _publisher_identity(run: LineageRunPayload) -> tuple[object, ...]:
    return (
        run.id,
        run.event,
        run.status,
        run.head_branch,
        run.path.partition("@")[0],
        run.repository.full_name,
        run.head_repository.full_name,
    )


def _require_publisher(run: LineageRunPayload, request: LineageRequest) -> None:
    expected = (
        request.publish_run_id,
        "workflow_run",
        "in_progress",
        "main",
        PUBLISH_WORKFLOW,
        request.full_name,
        request.full_name,
    )
    if _publisher_identity(run) != expected or not _is_full_sha(run.head_sha):
        raise GitHubPolicyError("publish run is not this repository's running main publisher")


def _is_full_sha(value: str) -> bool:
    try:
        return FullSha(value).value == value
    except ValueError:
        return False


async def _require_contained(
    api: GitHubApi, request: LineageRequest, ancestor: str, descendant: str
) -> None:
    page = await api.get(ApiTarget(f"{request.base}/compare/{ancestor}...{descendant}"))
    compare = _model(ComparePayload, _project(_json_object(page.body), ("status",)))
    if compare.status not in DESCENDANT_STATUSES:
        raise GitHubPolicyError(f"commit {ancestor} is not contained in main")
