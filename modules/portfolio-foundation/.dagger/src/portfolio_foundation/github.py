"""Read-only, fail-closed GitHub evidence for an exact green default branch."""

from __future__ import annotations

import asyncio
import http.client
import json
import re
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol
from urllib.parse import parse_qs, urlsplit

import dagger
from dagger import field, function, object_type
from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter, ValidationError

from .identity import FullSha, RepositoryRef

API_HOST: Final = "api.github.com"
API_ORIGIN: Final = f"https://{API_HOST}"
API_VERSION: Final = "2022-11-28"
APP_ID: Final = 15368
CHECK_NAME: Final = "Dagger"
DEFAULT_BRANCH: Final = "main"
MAX_PAGES: Final = 10
MAX_RETRIES: Final = 3
# GitHub stamps a rerun attempt's created_at up to a second after its run_started_at
# (observed: hseshadr/aml-filter run 36033566429 attempt 2). Tolerate only that clock
# skew; run_started_at still bounds every check and job time.
MAX_RUN_START_SKEW_SECONDS: Final = 5
MAX_CONTEXTS: Final = 20
MAX_RATE_LIMIT_HINT_SECONDS: Final = 1.0
MAX_TOTAL_WAIT_SECONDS: Final = 2.0
PAGE_SIZE: Final = 100
REQUEST_TIMEOUT_SECONDS: Final = 10.0
RETRY_DELAY_SECONDS: Final = 0.25
WORKFLOW_EVENT: Final = "push"
WORKFLOW_NAME: Final = "Dagger"
WORKFLOW_PATH: Final = ".github/workflows/dagger.yml"
TARGET_PATTERN: Final = re.compile(
    r"/repos/[A-Za-z0-9-]{1,39}/[A-Za-z0-9_.-]+(?:"
    r"|/branches/main"
    r"|/commits/[0-9a-f]{40}/check-runs\?filter=all&per_page=100&page=[1-9][0-9]*"
    r"|/actions/jobs/[1-9][0-9]*"
    r"|/actions/runs/[1-9][0-9]*"
    r"|/actions/runs/[1-9][0-9]*/attempts/[1-9][0-9]*"
    r"|/compare/[0-9a-f]{40}\.\.\.[0-9a-f]{40}"
    r")"
)
NEXT_LINK_PATTERN: Final = re.compile(r'<([^>]+)>;\s*rel="next"')
DETAILS_PATTERN: Final = re.compile(
    r"https://github\.com/([^/]+)/([^/]+)/actions/runs/([1-9][0-9]*)/job/([1-9][0-9]*)"
)
CLOSED_MODEL: Final = ConfigDict(extra="forbid", frozen=True, strict=True)
JSON_ADAPTER: Final[TypeAdapter[JsonValue]] = TypeAdapter(JsonValue)


class GitHubError(RuntimeError):
    """Base error for sanitized GitHub evidence failures."""


class GitHubApiError(GitHubError):
    """Raised when GitHub returns an unusable response."""

    def __init__(self) -> None:
        super().__init__("GitHub API request failed")


class GitHubNetworkError(GitHubError):
    """Raised when the bounded provider request cannot complete."""

    def __init__(self) -> None:
        super().__init__("GitHub network request failed")


class GitHubCredentialError(GitHubError):
    """Raised when GitHub rejects the supplied typed secret."""

    def __init__(self) -> None:
        super().__init__("GitHub credential was rejected")


class GitHubResponseError(GitHubError):
    """Raised when a provider payload violates the closed response contract."""

    def __init__(self) -> None:
        super().__init__("GitHub response did not match the required schema")


class GitHubPolicyError(GitHubError):
    """Raised when provider state is valid but not exact-green evidence."""


class DuplicateGreenCheckError(GitHubPolicyError):
    """Raised when more than one check could authorize the same commit."""


@dataclass(frozen=True)
class ApiTarget:
    """A validated relative path for one of the fixed read-only GitHub queries."""

    value: str

    def __post_init__(self) -> None:
        if TARGET_PATTERN.fullmatch(self.value) is None:
            raise GitHubPolicyError("GitHub API target is outside the read-only contract")


@dataclass(frozen=True)
class HttpPage:
    """One response body and its optional pagination header."""

    body: str
    link: str | None = None


class GitHubApi(Protocol):
    """Read-only provider behavior injected into deterministic policy logic."""

    async def get(self, target: ApiTarget) -> HttpPage:
        """Fetch one validated official API target."""


class ClosedPayload(BaseModel):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Strict immutable base for projected provider response contracts."""

    model_config = CLOSED_MODEL


class RepositoryPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected canonical repository fields from the GitHub REST response."""

    full_name: str
    default_branch: str


class BranchCommitPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected exact branch commit identity."""

    sha: str


class BranchPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected default branch state."""

    name: str
    commit: BranchCommitPayload


class GitHubAppPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected check publisher identity."""

    id: int = Field(gt=0)


class CheckSuitePayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected check-suite identity for an Actions check run."""

    id: int = Field(gt=0)


class GitHubCheckRun(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected check-run state; conclusion is nullable while work is active."""

    id: int = Field(gt=0)
    name: str
    head_sha: str
    status: str
    conclusion: str | None
    details_url: str
    started_at: str
    completed_at: str | None
    app: GitHubAppPayload
    check_suite: CheckSuitePayload


class CheckRunsPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """One strict projected check-runs page."""

    total_count: int = Field(ge=0)
    check_runs: tuple[GitHubCheckRun, ...]


class WorkflowRepositoryPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected workflow repository identity."""

    full_name: str


class WorkflowRunPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected workflow-run binding for the accepted check job."""

    id: int = Field(gt=0)
    name: str
    path: str
    head_branch: str
    head_sha: str
    status: str
    conclusion: str | None
    event: str
    run_attempt: int = Field(gt=0)
    created_at: str
    updated_at: str
    run_started_at: str
    repository: WorkflowRepositoryPayload


class WorkflowJobPayload(ClosedPayload):  # type: ignore[explicit-any]  # Pydantic v2 base stub
    """Projected Actions job identity bound to one check and run attempt."""

    id: int = Field(gt=0)
    run_id: int = Field(gt=0)
    run_attempt: int = Field(gt=0)
    workflow_name: str
    head_branch: str
    head_sha: str
    status: str
    conclusion: str | None
    name: str
    check_run_url: str
    started_at: str
    completed_at: str | None


@object_type
class CheckEvidence:
    """Non-secret exact-green evidence safe to pass between Dagger modules."""

    repository: str = field()
    branch: str = field()
    commit_sha: str = field()
    workflow_name: str = field()
    workflow_path: str = field()
    check_name: str = field()
    check_run_id: str = field()
    check_suite_id: str = field()
    workflow_job_id: str = field()
    run_attempt: int = field()
    check_started_at: str = field()
    check_completed_at: str | None = field()
    workflow_run_id: str = field()
    workflow_started_at: str = field()
    workflow_created_at: str = field()
    workflow_updated_at: str = field()
    app_id: int = field()

    @function
    def serialization(self) -> str:
        """Return one canonical non-secret serialization of this evidence object."""
        payload = self._source_payload() | self._check_payload() | self._workflow_payload()
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)

    def _source_payload(self) -> dict[str, str]:
        return {"branch": self.branch, "commit_sha": self.commit_sha, "repository": self.repository}

    def _check_payload(self) -> dict[str, str | int | None]:
        return {
            "app_id": self.app_id,
            "check_completed_at": self.check_completed_at,
            "check_name": self.check_name,
            "check_run_id": self.check_run_id,
            "check_started_at": self.check_started_at,
            "check_suite_id": self.check_suite_id,
            "workflow_job_id": self.workflow_job_id,
        }

    def _workflow_payload(self) -> dict[str, str | int]:
        return {
            "run_attempt": self.run_attempt,
            "workflow_created_at": self.workflow_created_at,
            "workflow_name": self.workflow_name,
            "workflow_path": self.workflow_path,
            "workflow_run_id": self.workflow_run_id,
            "workflow_started_at": self.workflow_started_at,
            "workflow_updated_at": self.workflow_updated_at,
        }


@dataclass(frozen=True)
class _SourceEvidence:
    repository: str
    branch: str
    commit_sha: str


@dataclass(frozen=True)
class _CheckEvidenceData:
    name: str
    run_id: int
    suite_id: int
    job_id: int
    started_at: str
    completed_at: str | None
    app_id: int


@dataclass(frozen=True)
class _WorkflowEvidenceData:
    name: str
    path: str
    run_id: int
    run_attempt: int
    started_at: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class _AttemptContext:
    check: GitHubCheckRun
    job: WorkflowJobPayload
    workflow: WorkflowRunPayload
    started_at: datetime


@dataclass(frozen=True)
class _CheckCollection:
    total_count: int | None
    checks: tuple[GitHubCheckRun, ...]


@dataclass(frozen=True)
class _RateLimitHeaders:
    retry_after: str | None
    remaining: str | None
    reset: str | None


class _RetryableStatusError(RuntimeError):
    def __init__(self, status: int, wait_hint: float = RETRY_DELAY_SECONDS) -> None:
        self.status = status
        self.wait_hint = wait_hint


class _GitHubRestApi:
    """Bounded GET-only adapter for the fixed official GitHub API host."""

    def __init__(self, token: str) -> None:
        self._token = token

    async def get(self, target: ApiTarget) -> HttpPage:
        return await asyncio.to_thread(self._get_with_retries, target)

    def _get_with_retries(self, target: ApiTarget) -> HttpPage:
        waited = 0.0
        for attempt in range(MAX_RETRIES):
            try:
                return self._get_once(target)
            except _RetryableStatusError as error:
                waited = _retry_api(attempt, error.wait_hint, waited)
            except (OSError, TimeoutError, http.client.HTTPException):
                _retry_network(attempt)
        raise GitHubNetworkError

    def _get_once(self, target: ApiTarget) -> HttpPage:
        connection = http.client.HTTPSConnection(API_HOST, timeout=REQUEST_TIMEOUT_SECONDS)
        try:
            connection.request("GET", target.value, headers=self._headers())
            response = connection.getresponse()
            body = response.read().decode("utf-8")
            limits = _rate_limit_headers(response)
            return _accepted_page(response.status, body, response.getheader("Link"), limits)
        finally:
            connection.close()

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "User-Agent": "portfolio-foundation",
            "X-GitHub-Api-Version": API_VERSION,
        }


def _rate_limit_headers(response: http.client.HTTPResponse) -> _RateLimitHeaders:
    return _RateLimitHeaders(
        response.getheader("Retry-After"),
        response.getheader("X-RateLimit-Remaining"),
        response.getheader("X-RateLimit-Reset"),
    )


def _accepted_page(status: int, body: str, link: str | None, limits: _RateLimitHeaders) -> HttpPage:
    if status == http.client.OK:
        return HttpPage(body, link)
    _raise_status(status, limits)
    raise GitHubApiError


def _raise_status(status: int, limits: _RateLimitHeaders) -> None:
    if status == http.client.UNAUTHORIZED:
        raise GitHubCredentialError
    if status == http.client.FORBIDDEN:
        _raise_forbidden(limits)
    if status == http.client.TOO_MANY_REQUESTS or status >= http.client.INTERNAL_SERVER_ERROR:
        raise _RetryableStatusError(status, _rate_limit_hint(limits))
    raise GitHubApiError


def _raise_forbidden(limits: _RateLimitHeaders) -> None:
    if not _is_rate_limit(limits):
        raise GitHubCredentialError
    raise _RetryableStatusError(http.client.FORBIDDEN, _rate_limit_hint(limits))


def _is_rate_limit(limits: _RateLimitHeaders) -> bool:
    return limits.retry_after is not None or limits.remaining == "0"


def _rate_limit_hint(limits: _RateLimitHeaders) -> float:
    if limits.retry_after is not None:
        return _bounded_hint(limits.retry_after, False)
    if limits.remaining == "0" and limits.reset is not None:
        return _bounded_hint(limits.reset, True)
    return RETRY_DELAY_SECONDS


def _bounded_hint(value: str, epoch: bool) -> float:
    try:
        hint = float(value) - (time.time() if epoch else 0.0)
    except ValueError:
        return RETRY_DELAY_SECONDS
    return min(MAX_RATE_LIMIT_HINT_SECONDS, max(0.0, hint))


def _retry_api(attempt: int, wait_hint: float, waited: float) -> float:
    total = waited + wait_hint
    if attempt == MAX_RETRIES - 1 or total > MAX_TOTAL_WAIT_SECONDS:
        raise GitHubApiError from None
    time.sleep(wait_hint)
    return total


def _retry_network(attempt: int) -> None:
    if attempt == MAX_RETRIES - 1:
        raise GitHubNetworkError from None
    time.sleep(RETRY_DELAY_SECONDS * (attempt + 1))


def parse_repository_response(raw: str) -> RepositoryPayload:
    """Project and validate canonical repository fields from a real response."""
    payload = _json_object(raw)
    return _model(RepositoryPayload, _project(payload, ("full_name", "default_branch")))


def parse_branch_response(raw: str) -> BranchPayload:
    """Project and validate the exact default-branch commit."""
    payload = _json_object(raw)
    commit = _project(_object(_required(payload, "commit")), ("sha",))
    projected = {"name": _required(payload, "name"), "commit": commit}
    return _model(BranchPayload, projected)


def parse_check_runs_response(raw: str) -> CheckRunsPayload:
    """Project and validate a check-runs page, including nullable conclusions."""
    payload = _json_object(raw)
    runs = tuple(_project_check(item) for item in _array(_required(payload, "check_runs")))
    projected = {"total_count": _required(payload, "total_count"), "check_runs": runs}
    return _model(CheckRunsPayload, projected)


def parse_workflow_response(raw: str) -> WorkflowRunPayload:
    """Project and validate the workflow run bound to an accepted check."""
    payload = _json_object(raw)
    repository = _project(_object(_required(payload, "repository")), ("full_name",))
    fields = _workflow_fields()
    projected = _project(payload, fields) | {"repository": repository}
    return _model(WorkflowRunPayload, projected)


def parse_job_response(raw: str) -> WorkflowJobPayload:
    """Project and validate the exact Actions job behind a check run."""
    payload = _json_object(raw)
    return _model(WorkflowJobPayload, _project(payload, _job_fields()))


def _workflow_fields() -> tuple[str, ...]:
    return (
        "id",
        "name",
        "path",
        "head_branch",
        "head_sha",
        "status",
        "conclusion",
        "event",
        "run_attempt",
        "created_at",
        "updated_at",
        "run_started_at",
    )


def _job_fields() -> tuple[str, ...]:
    return (
        "id",
        "run_id",
        "run_attempt",
        "workflow_name",
        "head_branch",
        "head_sha",
        "status",
        "conclusion",
        "name",
        "check_run_url",
        "started_at",
        "completed_at",
    )


def _project_check(value: JsonValue) -> dict[str, JsonValue]:
    payload = _object(value)
    app = _project(_object(_required(payload, "app")), ("id",))
    suite = _project(_object(_required(payload, "check_suite")), ("id",))
    fields = _check_fields()
    return _project(payload, fields) | {"app": app, "check_suite": suite}


def _check_fields() -> tuple[str, ...]:
    return (
        "id",
        "name",
        "head_sha",
        "status",
        "conclusion",
        "details_url",
        "started_at",
        "completed_at",
    )


def _json_object(raw: str) -> dict[str, JsonValue]:
    try:
        return _object(JSON_ADAPTER.validate_json(raw))
    except (ValidationError, ValueError, UnicodeError):
        raise GitHubResponseError from None


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise GitHubResponseError
    return value


def _array(value: JsonValue) -> list[JsonValue]:
    if not isinstance(value, list):
        raise GitHubResponseError
    return value


def _required(payload: dict[str, JsonValue], name: str) -> JsonValue:
    try:
        return payload[name]
    except KeyError:
        raise GitHubResponseError from None


def _project(payload: dict[str, JsonValue], names: tuple[str, ...]) -> dict[str, JsonValue]:
    return {name: _required(payload, name) for name in names}


def _model[T: BaseModel](model: type[T], payload: object) -> T:
    try:
        return model.model_validate(payload)
    except ValidationError:
        raise GitHubResponseError from None


def select_green_dagger(
    checks: tuple[GitHubCheckRun, ...], commit_sha: str
) -> GitHubCheckRun | None:
    """Evaluate only the newest unambiguous applicable Dagger check."""
    candidates = tuple(check for check in checks if _is_applicable(check, commit_sha))
    latest = _latest_check(candidates)
    return latest if latest is not None and _is_green(latest) else None


def _is_applicable(check: GitHubCheckRun, commit_sha: str) -> bool:
    return check.name == CHECK_NAME and check.head_sha == commit_sha and check.app.id == APP_ID


def _latest_check(checks: tuple[GitHubCheckRun, ...]) -> GitHubCheckRun | None:
    if not checks:
        return None
    timestamps = tuple(_timestamp(check.started_at) for check in checks)
    return _unique_latest_check(checks, timestamps)


def _unique_latest_check(
    checks: tuple[GitHubCheckRun, ...], timestamps: tuple[datetime, ...]
) -> GitHubCheckRun:
    latest = max(timestamps)
    pairs = zip(checks, timestamps, strict=True)
    candidates = tuple(check for check, stamp in pairs if stamp == latest)
    if len(candidates) != 1:
        raise DuplicateGreenCheckError("latest Dagger check identity is ambiguous")
    return candidates[0]


def _is_green(check: GitHubCheckRun) -> bool:
    return check.status == "completed" and check.conclusion == "success"


async def resolve_green_main(
    github_token: dagger.Secret, repository: RepositoryRef
) -> CheckEvidence:
    """Resolve exact-green main using only a typed GitHub secret and canonical repository."""
    try:
        token = await github_token.plaintext()
    except dagger.QueryError:
        raise GitHubCredentialError from None
    if not token:
        raise GitHubCredentialError
    return await resolve_green_main_from_api(_GitHubRestApi(token), repository)


async def resolve_green_main_from_api(api: GitHubApi, repository: RepositoryRef) -> CheckEvidence:
    """Apply deterministic exact-green policy to a read-only API adapter."""
    await _repository(api, repository)
    commit_sha = await _main_sha(api, repository)
    checks = await _check_runs(api, repository, commit_sha)
    contexts = await _attempt_contexts(api, repository, checks, commit_sha)
    context = _authoritative_context(contexts, commit_sha)
    _require_stable_main(commit_sha, await _main_sha(api, repository))
    return _evidence(repository, commit_sha, context)


async def _repository(api: GitHubApi, expected: RepositoryRef) -> RepositoryPayload:
    target = ApiTarget(f"/repos/{expected.owner}/{expected.name}")
    actual = parse_repository_response((await api.get(target)).body)
    if actual.full_name != _repository_name(expected):
        raise GitHubPolicyError("GitHub repository identity differs")
    if actual.default_branch != DEFAULT_BRANCH:
        raise GitHubPolicyError("GitHub default branch is not main")
    return actual


async def _main_sha(api: GitHubApi, repository: RepositoryRef) -> str:
    base = _repository_path(repository)
    branch = parse_branch_response((await api.get(ApiTarget(f"{base}/branches/main"))).body)
    if branch.name != DEFAULT_BRANCH:
        raise GitHubPolicyError("GitHub branch identity differs")
    try:
        return FullSha(branch.commit.sha).value
    except ValueError:
        raise GitHubPolicyError("GitHub main commit is not a full SHA") from None


def _require_stable_main(before: str, after: str) -> None:
    if before != after:
        raise GitHubPolicyError("GitHub main moved during evidence resolution")


async def _check_runs(
    api: GitHubApi, repository: RepositoryRef, commit_sha: str
) -> tuple[GitHubCheckRun, ...]:
    target = _first_check_target(repository, commit_sha)
    collection = _CheckCollection(None, ())
    for _ in range(MAX_PAGES):
        page = await api.get(target)
        collection = _merge_checks(collection, parse_check_runs_response(page.body))
        next_target = _next_target(page.link, target)
        if next_target is None:
            return _complete_checks(collection)
        target = next_target
    raise GitHubPolicyError("GitHub pagination exceeded the bounded page limit")


def _merge_checks(collection: _CheckCollection, page: CheckRunsPayload) -> _CheckCollection:
    expected = page.total_count if collection.total_count is None else collection.total_count
    if expected != page.total_count:
        raise GitHubPolicyError("GitHub check count differs across pages")
    checks = collection.checks + page.check_runs
    if len({check.id for check in checks}) != len(checks):
        raise GitHubPolicyError("GitHub pagination contains duplicate check runs")
    return _CheckCollection(expected, checks)


def _complete_checks(collection: _CheckCollection) -> tuple[GitHubCheckRun, ...]:
    if collection.total_count != len(collection.checks):
        raise GitHubPolicyError("GitHub check count differs from paginated results")
    return collection.checks


def _first_check_target(repository: RepositoryRef, commit_sha: str) -> ApiTarget:
    query = f"filter=all&per_page={PAGE_SIZE}&page=1"
    return ApiTarget(f"{_repository_path(repository)}/commits/{commit_sha}/check-runs?{query}")


def _next_target(link: str | None, current: ApiTarget) -> ApiTarget | None:
    if link is None:
        return None
    match = NEXT_LINK_PATTERN.search(link)
    if match is None:
        return None
    parsed = urlsplit(match.group(1))
    candidate = ApiTarget(f"{parsed.path}?{parsed.query}")
    _require_next_page(parsed.scheme, parsed.netloc, current, candidate)
    return candidate


def _require_next_page(scheme: str, host: str, current: ApiTarget, candidate: ApiTarget) -> None:
    if scheme != "https" or host != API_HOST:
        raise GitHubPolicyError("GitHub pagination origin differs")
    current_path, current_page = _page_identity(current)
    candidate_path, candidate_page = _page_identity(candidate)
    if current_path != candidate_path or candidate_page != current_page + 1:
        raise GitHubPolicyError("GitHub pagination sequence differs")


def _page_identity(target: ApiTarget) -> tuple[str, int]:
    parsed = urlsplit(target.value)
    query = parse_qs(parsed.query, strict_parsing=True)
    if set(query) != {"filter", "per_page", "page"}:
        raise GitHubPolicyError("GitHub pagination query differs")
    if query["filter"] != ["all"] or query["per_page"] != [str(PAGE_SIZE)]:
        raise GitHubPolicyError("GitHub pagination policy differs")
    return parsed.path, int(query["page"][0])


async def _attempt_contexts(
    api: GitHubApi,
    repository: RepositoryRef,
    checks: tuple[GitHubCheckRun, ...],
    commit_sha: str,
) -> tuple[_AttemptContext, ...]:
    applicable = tuple(check for check in checks if _is_applicable(check, commit_sha))
    _require_context_count(applicable)
    return tuple(
        [await _attempt_context(api, repository, check, commit_sha) for check in applicable]
    )


def _require_context_count(checks: tuple[GitHubCheckRun, ...]) -> None:
    if not checks or len(checks) > MAX_CONTEXTS:
        raise GitHubPolicyError("GitHub applicable Dagger check count is outside bounds")


async def _attempt_context(
    api: GitHubApi, repository: RepositoryRef, check: GitHubCheckRun, commit_sha: str
) -> _AttemptContext:
    run_id, job_id = _details_identity(check.details_url, repository)
    job = await _job(api, repository, job_id)
    _require_job_binding(job, check, repository, run_id, commit_sha)
    workflow = await _workflow_attempt(api, repository, job)
    _require_workflow_binding(workflow, job, repository, commit_sha)
    _require_timestamps(check, job, workflow)
    return _AttemptContext(check, job, workflow, _timestamp(workflow.run_started_at))


def _details_identity(details_url: str, repository: RepositoryRef) -> tuple[int, int]:
    match = DETAILS_PATTERN.fullmatch(details_url)
    if match is None or match.group(1, 2) != (repository.owner, repository.name):
        raise GitHubPolicyError("GitHub check details URL differs")
    return int(match.group(3)), int(match.group(4))


async def _job(api: GitHubApi, repository: RepositoryRef, job_id: int) -> WorkflowJobPayload:
    target = ApiTarget(f"{_repository_path(repository)}/actions/jobs/{job_id}")
    return parse_job_response((await api.get(target)).body)


def _require_job_binding(
    job: WorkflowJobPayload,
    check: GitHubCheckRun,
    repository: RepositoryRef,
    run_id: int,
    commit_sha: str,
) -> None:
    expected_url = f"{API_ORIGIN}{_repository_path(repository)}/check-runs/{check.id}"
    actual = _job_identity(job)
    expected = (check.id, run_id, CHECK_NAME, DEFAULT_BRANCH, commit_sha, expected_url)
    if actual != expected or not _same_check_state(check, job):
        raise GitHubPolicyError("GitHub Actions job identity differs from check")


def _job_identity(job: WorkflowJobPayload) -> tuple[int, int, str, str, str, str]:
    return (job.id, job.run_id, job.name, job.head_branch, job.head_sha, job.check_run_url)


def _same_check_state(check: GitHubCheckRun, job: WorkflowJobPayload) -> bool:
    state = (check.status, check.conclusion, check.started_at, check.completed_at)
    job_state = (job.status, job.conclusion, job.started_at, job.completed_at)
    return state == job_state and job.workflow_name == WORKFLOW_NAME


async def _workflow_attempt(
    api: GitHubApi, repository: RepositoryRef, job: WorkflowJobPayload
) -> WorkflowRunPayload:
    base = _repository_path(repository)
    target = ApiTarget(f"{base}/actions/runs/{job.run_id}/attempts/{job.run_attempt}")
    return parse_workflow_response((await api.get(target)).body)


def _require_workflow_binding(
    workflow: WorkflowRunPayload,
    job: WorkflowJobPayload,
    repository: RepositoryRef,
    commit_sha: str,
) -> None:
    identity = _workflow_identity(workflow)
    expected = (job.run_id, job.run_attempt, WORKFLOW_NAME, WORKFLOW_PATH, commit_sha)
    policy = workflow.head_branch == DEFAULT_BRANCH and workflow.event == WORKFLOW_EVENT
    policy = policy and workflow.repository.full_name == _repository_name(repository)
    if identity != expected or not policy:
        raise GitHubPolicyError("GitHub workflow attempt identity differs")


def _workflow_identity(workflow: WorkflowRunPayload) -> tuple[int, int, str, str, str]:
    return (
        workflow.id,
        workflow.run_attempt,
        workflow.name,
        workflow.path,
        workflow.head_sha,
    )


def _require_timestamps(
    check: GitHubCheckRun, job: WorkflowJobPayload, workflow: WorkflowRunPayload
) -> None:
    check_times = (_timestamp(check.started_at), _optional_timestamp(check.completed_at))
    job_times = (_timestamp(job.started_at), _optional_timestamp(job.completed_at))
    run_times = _workflow_times(workflow)
    if check_times != job_times or not _valid_check_times(check, check_times, run_times):
        raise GitHubPolicyError("GitHub Actions timestamps differ")


def _valid_check_times(
    check: GitHubCheckRun,
    check_times: tuple[datetime, datetime | None],
    run_times: tuple[datetime, datetime],
) -> bool:
    started, completed = check_times
    if not run_times[0] <= started <= run_times[1]:
        return False
    if completed is None:
        return check.status != "completed"
    return check.status == "completed" and started <= completed <= run_times[1]


def _workflow_times(workflow: WorkflowRunPayload) -> tuple[datetime, datetime]:
    created = _timestamp(workflow.created_at)
    started = _timestamp(workflow.run_started_at)
    updated = _timestamp(workflow.updated_at)
    skew = timedelta(seconds=MAX_RUN_START_SKEW_SECONDS)
    if not created - skew <= started <= updated:
        raise GitHubPolicyError("GitHub workflow timestamps are inconsistent")
    return started, updated


def _optional_timestamp(value: str | None) -> datetime | None:
    return None if value is None else _timestamp(value)


def _timestamp(value: str) -> datetime:
    if not value.endswith("Z"):
        raise GitHubPolicyError("GitHub timestamp is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError:
        raise GitHubPolicyError("GitHub timestamp is malformed") from None
    if parsed.tzinfo != UTC:
        raise GitHubPolicyError("GitHub timestamp is not UTC")
    return parsed


def _authoritative_context(
    contexts: tuple[_AttemptContext, ...], commit_sha: str
) -> _AttemptContext:
    context = _latest_context(contexts)
    _require_green_context(context, contexts, commit_sha)
    return context


def _latest_context(contexts: tuple[_AttemptContext, ...]) -> _AttemptContext:
    latest = max(context.started_at for context in contexts)
    candidates = tuple(context for context in contexts if context.started_at == latest)
    if len(candidates) != 1:
        raise DuplicateGreenCheckError("latest GitHub workflow attempt is ambiguous")
    return candidates[0]


def _require_green_context(
    context: _AttemptContext, contexts: tuple[_AttemptContext, ...], commit_sha: str
) -> None:
    selected = select_green_dagger(tuple(item.check for item in contexts), commit_sha)
    if selected is None or selected.id != context.check.id or not _context_is_green(context):
        raise GitHubPolicyError("latest GitHub workflow attempt is not successful")


def _context_is_green(context: _AttemptContext) -> bool:
    check = (context.check.status, context.check.conclusion)
    job = (context.job.status, context.job.conclusion)
    workflow = (context.workflow.status, context.workflow.conclusion)
    return check == job == workflow == ("completed", "success")


def _evidence(
    repository: RepositoryRef, commit_sha: str, context: _AttemptContext
) -> CheckEvidence:
    source = _SourceEvidence(_repository_name(repository), DEFAULT_BRANCH, commit_sha)
    check = _check_evidence(context)
    workflow = _workflow_evidence(context.workflow)
    evidence = CheckEvidence.__new__(CheckEvidence)
    _set_source_evidence(evidence, source)
    _set_check_evidence(evidence, check)
    _set_workflow_evidence(evidence, workflow)
    return evidence


def _set_source_evidence(evidence: CheckEvidence, source: _SourceEvidence) -> None:
    evidence.repository = source.repository
    evidence.branch = source.branch
    evidence.commit_sha = source.commit_sha


def _set_check_evidence(evidence: CheckEvidence, check: _CheckEvidenceData) -> None:
    evidence.check_name = check.name
    evidence.check_run_id = str(check.run_id)
    evidence.check_suite_id = str(check.suite_id)
    evidence.workflow_job_id = str(check.job_id)
    evidence.check_started_at = check.started_at
    evidence.check_completed_at = check.completed_at
    evidence.app_id = check.app_id


def _set_workflow_evidence(evidence: CheckEvidence, workflow: _WorkflowEvidenceData) -> None:
    evidence.workflow_name = workflow.name
    evidence.workflow_path = workflow.path
    evidence.workflow_run_id = str(workflow.run_id)
    evidence.run_attempt = workflow.run_attempt
    evidence.workflow_started_at = workflow.started_at
    evidence.workflow_created_at = workflow.created_at
    evidence.workflow_updated_at = workflow.updated_at


def _check_evidence(context: _AttemptContext) -> _CheckEvidenceData:
    check = context.check
    return _CheckEvidenceData(
        check.name,
        check.id,
        check.check_suite.id,
        context.job.id,
        check.started_at,
        check.completed_at,
        check.app.id,
    )


def _workflow_evidence(workflow: WorkflowRunPayload) -> _WorkflowEvidenceData:
    return _WorkflowEvidenceData(
        workflow.name,
        workflow.path,
        workflow.id,
        workflow.run_attempt,
        workflow.run_started_at,
        workflow.created_at,
        workflow.updated_at,
    )


def _repository_path(repository: RepositoryRef) -> str:
    return f"/repos/{repository.owner}/{repository.name}"


def _repository_name(repository: RepositoryRef) -> str:
    return f"{repository.owner}/{repository.name}"
