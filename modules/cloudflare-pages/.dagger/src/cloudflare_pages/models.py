"""Immutable deployment identities and strict Cloudflare response models."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

OWNER_PATTERN: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
REPOSITORY_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
PROJECT_PATTERN: Final = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,56}[a-z0-9])?")
BRANCH_PATTERN: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,253}[A-Za-z0-9])?")
DOMAIN_PATTERN: Final = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}"
)
CLOSED_MODEL: Final = ConfigDict(extra="forbid", frozen=True, strict=True)
BUILD_METADATA_MODEL: Final = ConfigDict(extra="ignore", frozen=True, strict=True)
FULL_SHA_TEXT: Final = r"\A[0-9a-f]{40}\z"
PAGES_COMMIT_SHA_TEXT: Final = r"\A(?:[0-9a-f]{40})?\z"
NUMERIC_ID_TEXT: Final = r"\A[1-9][0-9]*\z"
TIMESTAMP_TEXT: Final = r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\z"
DEPLOY_ROOT_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
DEPLOYMENT_ID_PATTERN: Final = re.compile(r"[0-9a-f][0-9a-f-]{0,63}")


class ClosedModel(BaseModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Reject unknown or coerced fields at every external response boundary."""

    model_config = CLOSED_MODEL


class WranglerBuildInput(BaseModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """One esbuild-resolved input emitted by pinned Wrangler."""

    model_config = BUILD_METADATA_MODEL
    bytes: int = Field(ge=0)


class WranglerBuildMetadata(BaseModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Typed subset of pinned Wrangler's esbuild metadata."""

    model_config = BUILD_METADATA_MODEL
    inputs: dict[str, WranglerBuildInput]


class GitHubEvidence(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """The complete non-secret exact-green serialization from foundation."""

    app_id: Literal[15368]
    branch: Literal["main"]
    check_completed_at: str = Field(pattern=TIMESTAMP_TEXT)
    check_name: Literal["Dagger"]
    check_run_id: str = Field(pattern=NUMERIC_ID_TEXT)
    check_started_at: str = Field(pattern=TIMESTAMP_TEXT)
    check_suite_id: str = Field(pattern=NUMERIC_ID_TEXT)
    commit_sha: str = Field(pattern=FULL_SHA_TEXT)
    repository: str
    run_attempt: int = Field(gt=0)
    workflow_created_at: str = Field(pattern=TIMESTAMP_TEXT)
    workflow_job_id: str = Field(pattern=NUMERIC_ID_TEXT)
    workflow_name: Literal["Dagger"]
    workflow_path: Literal[".github/workflows/dagger.yml"]
    workflow_run_id: str = Field(pattern=NUMERIC_ID_TEXT)
    workflow_started_at: str = Field(pattern=TIMESTAMP_TEXT)
    workflow_updated_at: str = Field(pattern=TIMESTAMP_TEXT)

    @property
    def attempt_identity(self) -> tuple[str, int]:
        """Return the exact Actions run and attempt that authorized delivery."""
        return self.workflow_run_id, self.run_attempt

    @model_validator(mode="after")
    def require_chronology(self) -> GitHubEvidence:
        check = _ordered(self.check_started_at, self.check_completed_at)
        workflow = _ordered(
            self.workflow_created_at, self.workflow_started_at, self.workflow_updated_at
        )
        if not check or not workflow:
            raise ValueError("foundation evidence timestamps are incoherent")
        return self


class PagesSourceConfig(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected documented Git source binding relevant to direct upload."""

    owner: str
    repo_name: str
    production_branch: str
    production_deployments_enabled: bool
    preview_deployment_setting: Literal["all", "none", "custom"]


class PagesSource(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected Cloudflare Pages Git provider configuration."""

    type: Literal["github", "gitlab"]
    config: PagesSourceConfig


class PagesProject(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected Cloudflare Pages project identity used by preflight."""

    id: str
    name: str
    production_branch: str
    domains: tuple[str, ...]
    source: PagesSource | None


class ApiProblemSource(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Non-sensitive Cloudflare error location."""

    pointer: str


class ApiProblem(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Documented Cloudflare problem details with ignored request context."""

    code: int
    message: str
    documentation_url: str | None = None
    source: ApiProblemSource | None = None
    request: str | None = None


class DeploymentStage(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Latest documented Pages deployment stage."""

    name: str
    status: Literal["idle", "active", "success", "failure", "canceled"]


class DeploymentMetadata(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Exact source metadata attached to a direct Pages upload."""

    branch: str
    commit_hash: str = Field(pattern=FULL_SHA_TEXT)
    commit_dirty: bool


class ListedDeploymentMetadata(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Provider-list metadata including Cloudflare's historical empty hash."""

    branch: str
    commit_hash: str = Field(pattern=PAGES_COMMIT_SHA_TEXT)
    commit_dirty: bool


class DeploymentTrigger(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Documented direct-upload trigger and source metadata."""

    type: str
    metadata: DeploymentMetadata


class ListedDeploymentTrigger(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected trigger for a Pages deployment-list row."""

    type: str
    metadata: ListedDeploymentMetadata


class PagesDeployment(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected raw deployment fields needed for exact verification."""

    id: str
    short_id: str = Field(pattern=r"\A[a-f0-9]{8}\z")
    url: str
    project_id: str
    project_name: str
    environment: Literal["production", "preview"]
    latest_stage: DeploymentStage
    deployment_trigger: DeploymentTrigger


class ListedPagesDeployment(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Strict provider-list row awaiting exact-SHA candidate promotion."""

    id: str
    short_id: str = Field(pattern=r"\A[a-f0-9]{8}\z")
    url: str
    project_id: str
    project_name: str
    environment: Literal["production", "preview"]
    latest_stage: DeploymentStage
    deployment_trigger: ListedDeploymentTrigger


class ResultInfo(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Cloudflare list pagination returned for the fixed first page."""

    count: int = Field(ge=0)
    page: int = Field(gt=0)
    per_page: int = Field(gt=0)
    total_count: int = Field(ge=0)
    total_pages: int = Field(ge=0)


class ProjectResponse(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Strict projected Cloudflare response for one Pages project."""

    errors: tuple[ApiProblem, ...]
    messages: tuple[ApiProblem, ...]
    result: PagesProject
    success: bool


class DeploymentsResponse(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Strict projected Cloudflare response for the production deployment page."""

    errors: tuple[ApiProblem, ...]
    messages: tuple[ApiProblem, ...]
    result: tuple[ListedPagesDeployment, ...]
    success: bool
    result_info: ResultInfo


class DeploymentResponse(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Strict projected Cloudflare response for one Pages deployment."""

    errors: tuple[ApiProblem, ...]
    messages: tuple[ApiProblem, ...]
    result: ListedPagesDeployment
    success: bool


class WranglerOutput(ClosedModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Pinned Wrangler 4.103.0 pages-deploy JSONL record."""

    type: Literal["pages-deploy"]
    version: Literal[1]
    pages_project: str
    deployment_id: str
    url: str
    timestamp: str = Field(pattern=TIMESTAMP_TEXT)


@dataclass(frozen=True)
class RepositoryIdentity:
    """Canonical GitHub owner and repository components."""

    owner: str
    name: str

    def __post_init__(self) -> None:
        if not _valid_repository(self.owner, self.name):
            raise ValueError("repository must use canonical GitHub components")

    @classmethod
    def parse(cls, value: str) -> RepositoryIdentity:
        """Parse exact owner/repository text without accepting a mutable URL."""
        if value.count("/") != 1:
            raise ValueError("repository must be owner/repository")
        return cls(*value.split("/", maxsplit=1))


@dataclass(frozen=True, init=False)
class PagesTarget:
    """One repository-bound Pages production target and its required domains."""

    repository: RepositoryIdentity
    project: str
    branch: str
    live_domain: str
    deploy_root: str
    domains: tuple[str, ...]
    pages_functions: bool

    def __init__(
        self,
        repository: str,
        project: str,
        branch: str,
        live_domain: str,
        deploy_root: str,
        domains: tuple[str, ...] = (),
        pages_functions: bool = False,
    ) -> None:
        identity = RepositoryIdentity.parse(repository)
        required_domains = _canonical_domains(live_domain, domains)
        _require_target_binding(identity, project, branch)
        if DEPLOY_ROOT_PATTERN.fullmatch(deploy_root) is None:
            raise ValueError("deploy root must be one canonical directory name")
        object.__setattr__(self, "repository", identity)
        object.__setattr__(self, "project", project)
        object.__setattr__(self, "branch", branch)
        object.__setattr__(self, "live_domain", live_domain)
        object.__setattr__(self, "deploy_root", deploy_root)
        object.__setattr__(self, "domains", required_domains)
        object.__setattr__(self, "pages_functions", pages_functions)


@dataclass(frozen=True)
class AttemptIdentity:
    """Exact GitHub Actions run and positive attempt number."""

    workflow_run_id: str
    run_attempt: int

    def __post_init__(self) -> None:
        valid_run = re.fullmatch(r"[1-9][0-9]*", self.workflow_run_id) is not None
        if not valid_run or self.run_attempt <= 0:
            raise ValueError("attempt identity must use a numeric run and positive attempt")


@dataclass(frozen=True)
class ProviderDeploymentEvidence:
    """Non-secret deployment result bound to exact source and attempt identity."""

    deployment_id: str
    deployment_url: str
    project_id: str
    project: str
    repository: str
    branch: str
    source_sha: str
    attempt_identity: AttemptIdentity


@dataclass(frozen=True)
class RollbackEvidence:
    """Non-secret proof that production moved from one deployment to another."""

    project: str
    from_deployment_id: str
    to_deployment_id: str
    live_deployment_id: str
    live_deployment_url: str


@dataclass(frozen=True)
class CreatedDeployment:
    """The immutable deployment identity returned by this Wrangler upload."""

    deployment_id: str
    deployment_url: str


def _valid_repository(owner: str, name: str) -> bool:
    owner_valid = OWNER_PATTERN.fullmatch(owner) is not None
    name_valid = REPOSITORY_PATTERN.fullmatch(name) is not None and not name.endswith(".git")
    return owner_valid and name_valid


def _ordered(*values: str) -> bool:
    timestamps = tuple(datetime.fromisoformat(value.replace("Z", "+00:00")) for value in values)
    return timestamps == tuple(sorted(timestamps))


def _canonical_domains(primary: str, aliases: tuple[str, ...]) -> tuple[str, ...]:
    domains = (primary, *aliases)
    if len(domains) != len(frozenset(domains)):
        raise ValueError("target domains must be unique")
    if any(DOMAIN_PATTERN.fullmatch(domain) is None for domain in domains):
        raise ValueError("target domains must be canonical DNS names")
    return tuple(sorted(domains))


def _require_target_binding(repository: RepositoryIdentity, project: str, branch: str) -> None:
    project_valid = PROJECT_PATTERN.fullmatch(project) is not None
    branch_valid = BRANCH_PATTERN.fullmatch(branch) is not None
    if not project_valid or not branch_valid or repository.name != project:
        raise ValueError("target binding must match repository, project, and branch")
