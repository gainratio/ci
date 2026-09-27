"""Closed Cloudflare Pages REST paths, parsing, and convergence policy."""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from typing import Final, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, JsonValue, TypeAdapter, ValidationError

from .models import (
    DEPLOYMENT_ID_PATTERN,
    ApiProblem,
    AttemptIdentity,
    CreatedDeployment,
    DeploymentResponse,
    DeploymentsResponse,
    GitHubEvidence,
    ListedPagesDeployment,
    PagesDeployment,
    PagesProject,
    PagesTarget,
    ProjectResponse,
    ProviderDeploymentEvidence,
    RollbackEvidence,
)

API_ORIGIN: Final = "https://api.cloudflare.com/client/v4"
DEPLOYMENT_PAGE_SIZE: Final = 10
PRE_DEPLOYMENT_STAGES: Final = frozenset({"queued", "initialize", "clone_repo", "build"})
ACCOUNT_REF_PATTERN: Final = re.compile(r"[A-Za-z0-9]{1,32}")
CONTROL_PATTERN: Final = re.compile(r"[\x00-\x1f\x7f]+")
BEARER_PATTERN: Final = re.compile(r"(?i)bearer\s+\S+")
JSON_ADAPTER: Final[TypeAdapter[JsonValue]] = TypeAdapter(JsonValue)
ROLLBACK_DELAYS: Final = (1, 2, 4, 8)
ROLLBACK_DEADLINE_SECONDS: Final = 60


class CloudflareError(RuntimeError):
    """Base sanitized Cloudflare provider failure."""


class CloudflareApiError(CloudflareError):
    """Raised when Cloudflare reports an API problem."""


class CloudflarePolicyError(CloudflareError):
    """Raised when provider state cannot authorize the requested delivery."""


class PagesOperations[ArtifactT](Protocol):
    """One-writer provider operations injected into deterministic policy."""

    async def get_project(self) -> str: ...

    async def get_deployments(self) -> str: ...

    async def disable_git(self) -> str: ...

    async def wrangler_preflight(self) -> None: ...

    async def upload(self, artifact: ArtifactT, source_sha: str) -> CreatedDeployment: ...

    async def sleep(self, seconds: int) -> None: ...


class RollbackOperations(Protocol):
    """Read-and-rollback provider operations for one Pages project."""

    async def get_project(self) -> str: ...

    async def get_deployments(self) -> str: ...

    async def rollback(self, deployment_id: str) -> str: ...

    async def sleep(self, seconds: int) -> None: ...


@dataclass(frozen=True)
class ProductionState:
    """The bound project, its live deployment id, and recent production history."""

    project: PagesProject
    live_id: str
    history: tuple[ListedPagesDeployment, ...]


def project_path(account_ref: str, target: PagesTarget) -> str:
    """Return the only supported project API path."""
    _require_account_ref(account_ref)
    return f"/accounts/{account_ref}/pages/projects/{target.project}"


def deployment_path(account_ref: str, target: PagesTarget) -> str:
    """Return the fixed production deployment convergence query."""
    path = project_path(account_ref, target)
    return f"{path}/deployments?env=production&per_page={DEPLOYMENT_PAGE_SIZE}"


def disable_git_payload(target: PagesTarget) -> dict[str, object]:
    """Disable Git production and preview delivery in one idempotent PATCH."""
    config = {
        "production_deployments_enabled": False,
        "preview_deployment_setting": "none",
    }
    return {
        "production_branch": target.branch,
        "source": {"type": "github", "config": config},
    }


def parse_project_response(raw: str) -> PagesProject:
    """Parse a strict projection of the documented Get Project response."""
    payload = _json_object(raw)
    projected = _response_fields(payload) | {"result": _project_result(payload)}
    response = _model(ProjectResponse, projected)
    _require_success(response.success, response.errors)
    return response.result


def parse_deployments_response(raw: str) -> DeploymentsResponse:
    """Parse a strict projection of the documented deployments response."""
    payload = _json_object(raw)
    results: list[JsonValue] = [
        _deployment_result(item) for item in _array(_required(payload, "result"))
    ]
    projected: dict[str, JsonValue] = _response_fields(payload)
    projected["result"] = results
    projected["result_info"] = _result_info(payload)
    response = _model(DeploymentsResponse, projected)
    _require_success(response.success, response.errors)
    return response


def require_project_binding(project: PagesProject, target: PagesTarget) -> None:
    """Require repository, project, production branch, and domain coherence."""
    _require_project_identity(project, target)
    _require_domains(project.domains, target)
    source = project.source
    if source is None:
        return
    _require_source_binding(source.config.owner, source.config.repo_name, target)
    _require_source_policy(source.type, source.config.production_branch, target)


def _require_project_identity(project: PagesProject, target: PagesTarget) -> None:
    if (project.name, project.production_branch) != (target.project, target.branch):
        raise CloudflarePolicyError("Cloudflare project target binding differs")


def _require_source_policy(source_type: str, branch: str, target: PagesTarget) -> None:
    if (source_type, branch) != ("github", target.branch):
        raise CloudflarePolicyError("Cloudflare project target binding differs")


def _require_domains(domains: tuple[str, ...], target: PagesTarget) -> None:
    if not frozenset(target.domains).issubset(domains):
        raise CloudflarePolicyError("Cloudflare project target binding differs")


def select_deployment(
    response: DeploymentsResponse,
    target: PagesTarget,
    expected_sha: str,
    expected_project_id: str,
    expected_deployment_id: str | None = None,
) -> PagesDeployment | None:
    """Select one exact successful direct upload or signal convergence."""
    _require_pagination(response)
    candidate = _matching_candidate(response.result, expected_sha, expected_deployment_id)
    if candidate is None:
        return None
    return _qualified_deployment(_strict_deployment(candidate), target, expected_project_id)


def sanitize_error(error: ApiProblem) -> str:
    """Expose only bounded provider code and message, never source/request data."""
    message = CONTROL_PATTERN.sub(" ", error.message)
    message = BEARER_PATTERN.sub("Bearer [redacted]", message).strip()
    return f"Cloudflare {error.code}: {message[:160]}"


def require_evidence_binding(
    target: PagesTarget, evidence: GitHubEvidence, attempt: AttemptIdentity
) -> None:
    """Bind exact foundation evidence to the explicit caller attempt."""
    repository = f"{target.repository.owner}/{target.repository.name}"
    if (evidence.repository, evidence.branch) != (repository, target.branch):
        raise CloudflarePolicyError("GitHub source identity differs from target")
    if evidence.attempt_identity != (attempt.workflow_run_id, attempt.run_attempt):
        raise CloudflarePolicyError("GitHub attempt identity differs")


async def deploy_verified_artifact[ArtifactT](
    operations: PagesOperations[ArtifactT],
    artifact: ArtifactT,
    target: PagesTarget,
    github: GitHubEvidence,
    attempt: AttemptIdentity,
) -> ProviderDeploymentEvidence:
    """Run one ordered direct-upload transaction on an already verified tree."""
    require_evidence_binding(target, github, attempt)
    await operations.wrangler_preflight()
    project = await _read_preflight(operations, target)
    await _disable_git(operations, target, project)
    await _revalidate_disabled_project(operations, target, project)
    created = await operations.upload(artifact, github.commit_sha)
    deployment = await _converge(
        operations, target, github.commit_sha, project.id, created.deployment_id
    )
    if deployment.url != created.deployment_url:
        raise CloudflarePolicyError("Cloudflare created deployment identity differs")
    return _deployment_evidence(deployment, target, github, attempt)


async def preflight_provider[ArtifactT](
    operations: PagesOperations[ArtifactT], target: PagesTarget
) -> None:
    """Run all read-only provider and pinned CLI checks."""
    await _read_preflight(operations, target)
    await operations.wrangler_preflight()


async def verify_current_deployment[ArtifactT](
    operations: PagesOperations[ArtifactT],
    target: PagesTarget,
    github: GitHubEvidence,
    attempt: AttemptIdentity,
) -> ProviderDeploymentEvidence:
    """Read and converge exact production deployment evidence without mutation."""
    require_evidence_binding(target, github, attempt)
    project = parse_project_response(await operations.get_project())
    require_project_binding(project, target)
    deployment = await _converge(operations, target, github.commit_sha, project.id)
    return _deployment_evidence(deployment, target, github, attempt)


async def _read_preflight[ArtifactT](
    operations: PagesOperations[ArtifactT], target: PagesTarget
) -> PagesProject:
    project = parse_project_response(await operations.get_project())
    require_project_binding(project, target)
    deployments = parse_deployments_response(await operations.get_deployments())
    _require_pagination(deployments)
    return project


async def _disable_git[ArtifactT](
    operations: PagesOperations[ArtifactT], target: PagesTarget, expected: PagesProject
) -> None:
    if expected.source is None:
        return
    project = parse_project_response(await operations.disable_git())
    require_project_binding(project, target)
    _require_same_project_state(project, expected)
    _require_same_delivery_mode(project, expected)
    _require_git_disabled(project)


async def _revalidate_disabled_project[ArtifactT](
    operations: PagesOperations[ArtifactT], target: PagesTarget, expected: PagesProject
) -> None:
    project = parse_project_response(await operations.get_project())
    require_project_binding(project, target)
    _require_same_project_state(project, expected)
    _require_same_delivery_mode(project, expected)
    _require_git_disabled(project)


def _require_same_project_state(project: PagesProject, expected: PagesProject) -> None:
    if project.id != expected.id:
        raise CloudflarePolicyError("Cloudflare project identity changed before upload")
    if frozenset(project.domains) != frozenset(expected.domains):
        raise CloudflarePolicyError("Cloudflare project domains changed before upload")


def _require_same_delivery_mode(project: PagesProject, expected: PagesProject) -> None:
    if (project.source is None) != (expected.source is None):
        raise CloudflarePolicyError("Cloudflare project delivery mode changed before upload")


def _require_git_disabled(project: PagesProject) -> None:
    source = project.source
    if source is None:
        return
    if source.config.production_deployments_enabled:
        raise CloudflarePolicyError("Cloudflare Git production deployment remains enabled")
    if source.config.preview_deployment_setting != "none":
        raise CloudflarePolicyError("Cloudflare Git preview deployment remains enabled")


async def _converge[ArtifactT](
    operations: PagesOperations[ArtifactT],
    target: PagesTarget,
    source_sha: str,
    project_id: str,
    deployment_id: str | None = None,
) -> PagesDeployment:
    try:
        async with asyncio.timeout(60):
            return await _bounded_convergence(
                operations, target, source_sha, project_id, deployment_id
            )
    except TimeoutError:
        raise CloudflarePolicyError(
            "Cloudflare deployment did not converge within 60 seconds"
        ) from None


async def _bounded_convergence[ArtifactT](
    operations: PagesOperations[ArtifactT],
    target: PagesTarget,
    source_sha: str,
    project_id: str,
    deployment_id: str | None,
) -> PagesDeployment:
    for delay in (1, 2, 4, 8):
        deployment = await _current_deployment(
            operations, target, source_sha, project_id, deployment_id
        )
        if deployment is not None:
            return deployment
        await operations.sleep(delay)
    deployment = await _current_deployment(
        operations, target, source_sha, project_id, deployment_id
    )
    if deployment is None:
        raise CloudflarePolicyError("Cloudflare deployment did not converge within 60 seconds")
    return deployment


def provider_error_message(raw: str) -> str:
    """Return one sanitized message from a failed API response."""
    try:
        payload = _json_object(raw)
        problems = _array(_required(payload, "errors"))
        return sanitize_error(_model(ApiProblem, _problem(problems[0]))) if problems else _generic()
    except (CloudflarePolicyError, IndexError):
        return _generic()


def _generic() -> str:
    return "Cloudflare API request failed"


async def _current_deployment[ArtifactT](
    operations: PagesOperations[ArtifactT],
    target: PagesTarget,
    source_sha: str,
    project_id: str,
    deployment_id: str | None = None,
) -> PagesDeployment | None:
    response = parse_deployments_response(await operations.get_deployments())
    return select_deployment(response, target, source_sha, project_id, deployment_id)


def _deployment_evidence(
    deployment: PagesDeployment,
    target: PagesTarget,
    github: GitHubEvidence,
    attempt: AttemptIdentity,
) -> ProviderDeploymentEvidence:
    repository = f"{target.repository.owner}/{target.repository.name}"
    return ProviderDeploymentEvidence(
        deployment.id,
        deployment.url,
        deployment.project_id,
        target.project,
        repository,
        target.branch,
        github.commit_sha,
        attempt,
    )


def _qualified_deployment(
    deployment: PagesDeployment, target: PagesTarget, project_id: str
) -> PagesDeployment | None:
    _require_deployment_identity(deployment, target, project_id)
    stage = deployment.latest_stage
    if stage.status in ("failure", "canceled"):
        raise CloudflarePolicyError("Cloudflare deployment failed")
    if stage.name in PRE_DEPLOYMENT_STAGES:
        return None
    if stage.name != "deploy":
        raise CloudflarePolicyError("Cloudflare deployment identity differs")
    return deployment if stage.status == "success" else None


def _require_deployment_identity(
    deployment: PagesDeployment, target: PagesTarget, project_id: str
) -> None:
    identity = _deployment_identity(deployment, target)
    expected = (target.project, "production", target.branch, "ad_hoc", project_id, False, True)
    if identity != expected:
        raise CloudflarePolicyError("Cloudflare deployment identity differs")


def _deployment_identity(deployment: PagesDeployment, target: PagesTarget) -> tuple[object, ...]:
    metadata = deployment.deployment_trigger.metadata
    return (
        deployment.project_name,
        deployment.environment,
        metadata.branch,
        deployment.deployment_trigger.type,
        deployment.project_id,
        metadata.commit_dirty,
        _valid_deployment_url(deployment.url, target.project, deployment.short_id),
    )


def _valid_deployment_url(value: str, project: str, short_id: str) -> bool:
    parsed = urlsplit(value)
    hostname = f"{short_id}.{project}.pages.dev"
    identity = (
        parsed.scheme,
        parsed.hostname,
        parsed.username,
        parsed.password,
        parsed.path,
        parsed.query,
        parsed.fragment,
        parsed.port,
    )
    return identity == ("https", hostname, None, None, "", "", "", None)


def _deployment_matches(
    deployment: ListedPagesDeployment, source_sha: str, deployment_id: str | None
) -> bool:
    sha_matches = _deployment_sha(deployment) == source_sha
    return sha_matches and (deployment_id is None or deployment.id == deployment_id)


def _matching_candidate(
    deployments: tuple[ListedPagesDeployment, ...], source_sha: str, deployment_id: str | None
) -> ListedPagesDeployment | None:
    matching = tuple(
        item for item in deployments if _deployment_matches(item, source_sha, deployment_id)
    )
    return _one_matching_deployment(matching, deployment_id) if matching else None


def _one_matching_deployment(
    matching: tuple[ListedPagesDeployment, ...], deployment_id: str | None
) -> ListedPagesDeployment:
    if deployment_id is not None and len(matching) != 1:
        raise CloudflarePolicyError("Cloudflare deployment identity differs")
    return matching[0]


def _require_source_binding(owner: str, repository: str, target: PagesTarget) -> None:
    expected = (target.repository.owner, target.repository.name)
    if (owner, repository) != expected:
        raise CloudflarePolicyError("Cloudflare project target binding differs")


def _require_pagination(response: DeploymentsResponse) -> None:
    info = response.result_info
    valid = info.page == 1 and info.per_page == DEPLOYMENT_PAGE_SIZE
    valid = valid and info.count == len(response.result)
    if not valid:
        raise CloudflarePolicyError("Cloudflare deployment pagination differs")


def _deployment_sha(deployment: ListedPagesDeployment) -> str:
    return deployment.deployment_trigger.metadata.commit_hash


def _strict_deployment(deployment: ListedPagesDeployment) -> PagesDeployment:
    try:
        return PagesDeployment.model_validate_json(deployment.model_dump_json())
    except (ValidationError, ValueError, TypeError):
        raise CloudflarePolicyError("Cloudflare response schema mismatch") from None


def _require_account_ref(value: str) -> None:
    if ACCOUNT_REF_PATTERN.fullmatch(value) is None:
        raise CloudflarePolicyError("Cloudflare account identity is malformed")


def _require_success(success: bool, errors: tuple[ApiProblem, ...]) -> None:
    if success and not errors:
        return
    if errors:
        raise CloudflareApiError(sanitize_error(errors[0]))
    raise CloudflareApiError("Cloudflare API request failed")


def _project_result(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    project = _object(_required(payload, "result"))
    fields = _project(project, ("id", "name", "production_branch", "domains"))
    source = _required(project, "source")
    return fields | {"source": None if source is None else _source_result(source)}


def _source_result(value: JsonValue) -> dict[str, JsonValue]:
    source = _object(value)
    config = _object(_required(source, "config"))
    names = (
        "owner",
        "repo_name",
        "production_branch",
        "production_deployments_enabled",
        "preview_deployment_setting",
    )
    return {"type": _required(source, "type"), "config": _project(config, names)}


def _deployment_result(value: JsonValue) -> dict[str, JsonValue]:
    deployment = _object(value)
    names = ("id", "short_id", "url", "project_id", "project_name", "environment")
    fields = _project(deployment, names)
    fields["latest_stage"] = _stage_result(deployment)
    fields["deployment_trigger"] = _trigger_result(deployment)
    return fields


def _stage_result(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    stage = _object(_required(payload, "latest_stage"))
    return _project(stage, ("name", "status"))


def _trigger_result(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    trigger = _object(_required(payload, "deployment_trigger"))
    metadata = _object(_required(trigger, "metadata"))
    names = ("branch", "commit_hash", "commit_dirty")
    return {"type": _required(trigger, "type"), "metadata": _project(metadata, names)}


def _result_info(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    info = _object(_required(payload, "result_info"))
    return _project(info, ("count", "page", "per_page", "total_count", "total_pages"))


def _response_fields(payload: dict[str, JsonValue]) -> dict[str, JsonValue]:
    return {
        "errors": [_problem(item) for item in _array(_required(payload, "errors"))],
        "messages": [_problem(item) for item in _array(_required(payload, "messages"))],
        "success": _required(payload, "success"),
    }


def _problem(value: JsonValue) -> dict[str, JsonValue]:
    problem = _object(value)
    fields = _project_optional(problem, ("code", "message", "documentation_url", "request"))
    source = problem.get("source")
    return fields | {"source": None if source is None else _problem_source(source)}


def _problem_source(value: JsonValue) -> dict[str, JsonValue]:
    return _project(_object(value), ("pointer",))


def _json_object(raw: str) -> dict[str, JsonValue]:
    try:
        return _object(JSON_ADAPTER.validate_json(raw))
    except (ValidationError, ValueError, UnicodeError):
        raise CloudflarePolicyError("Cloudflare response schema mismatch") from None


def _object(value: JsonValue) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise CloudflarePolicyError("Cloudflare response schema mismatch")
    return value


def _array(value: JsonValue) -> list[JsonValue]:
    if not isinstance(value, list):
        raise CloudflarePolicyError("Cloudflare response schema mismatch")
    return value


def _required(payload: dict[str, JsonValue], name: str) -> JsonValue:
    if name not in payload:
        raise CloudflarePolicyError("Cloudflare response schema mismatch")
    return payload[name]


def _project(payload: dict[str, JsonValue], names: tuple[str, ...]) -> dict[str, JsonValue]:
    if any(name not in payload for name in names):
        raise CloudflarePolicyError("Cloudflare response schema mismatch")
    return {name: payload[name] for name in names}


def _project_optional(
    payload: dict[str, JsonValue], names: tuple[str, ...]
) -> dict[str, JsonValue]:
    return {name: payload[name] for name in names if name in payload}


def _model[ModelT: BaseModel](model: type[ModelT], payload: dict[str, JsonValue]) -> ModelT:
    try:
        return model.model_validate_json(json.dumps(payload))
    except (ValidationError, ValueError, TypeError):
        raise CloudflarePolicyError("Cloudflare response schema mismatch") from None


def parse_live_deployment_id(raw: str) -> str | None:
    """Return the project's canonical (currently served) production deployment id."""
    parse_project_response(raw)
    result = _object(_required(_json_object(raw), "result"))
    live = _required(result, "canonical_deployment")
    if live is None:
        return None
    value = _required(_object(live), "id")
    if not isinstance(value, str) or DEPLOYMENT_ID_PATTERN.fullmatch(value) is None:
        raise CloudflarePolicyError("Cloudflare response schema mismatch")
    return value


def parse_deployment_response(raw: str) -> ListedPagesDeployment:
    """Parse a strict projection of one documented deployment response."""
    payload = _json_object(raw)
    fields = _response_fields(payload)
    if fields["success"] is not True:
        raise CloudflareApiError(provider_error_message(raw))
    projected = fields | {"result": _deployment_result(_required(payload, "result"))}
    response = _model(DeploymentResponse, projected)
    _require_success(response.success, response.errors)
    return response.result


async def live_production_deployment(
    operations: RollbackOperations, project: str
) -> ListedPagesDeployment:
    """Read-only: the deployment production serves now, to record as a rollback target."""
    state = await read_production_state(operations, project)
    return _history_row(state.history, state.live_id)


async def rollback_production(
    operations: RollbackOperations, project: str, deployment_id: str | None
) -> RollbackEvidence:
    """Roll production back to one eligible deployment and verify it is served."""
    state = await read_production_state(operations, project)
    target = _rollback_target(state, deployment_id)
    response = parse_deployment_response(await operations.rollback(target.id))
    if response.id != target.id:
        raise CloudflarePolicyError("Cloudflare rollback response identity differs")
    live_id = await _await_live(operations, target.id)
    return RollbackEvidence(project, state.live_id, target.id, live_id, target.url)


async def read_production_state(operations: RollbackOperations, project: str) -> ProductionState:
    """Read the bound project, its live deployment, and the recent production page."""
    raw = await operations.get_project()
    pages = parse_project_response(raw)
    if pages.name != project:
        raise CloudflarePolicyError("Cloudflare project binding differs")
    live_id = parse_live_deployment_id(raw)
    if live_id is None:
        raise CloudflarePolicyError("Cloudflare project has no live production deployment")
    deployments = parse_deployments_response(await operations.get_deployments())
    _require_pagination(deployments)
    return ProductionState(pages, live_id, deployments.result)


def _rollback_target(state: ProductionState, deployment_id: str | None) -> ListedPagesDeployment:
    if deployment_id is None:
        return _previous_successful(state)
    target = _history_row(state.history, deployment_id)
    if target.id == state.live_id:
        raise CloudflarePolicyError("Rollback target is already live; refusing a no-op rollback")
    _require_rollback_target(target, state.project)
    return target


def _previous_successful(state: ProductionState) -> ListedPagesDeployment:
    live = _history_row(state.history, state.live_id)
    older = state.history[state.history.index(live) + 1 :]
    for row in older:
        if _rollback_eligible(row, state.project):
            return row
    raise CloudflarePolicyError("Cloudflare has no previous successful production deployment")


def _history_row(
    history: tuple[ListedPagesDeployment, ...], deployment_id: str
) -> ListedPagesDeployment:
    for row in history:
        if row.id == deployment_id:
            return row
    raise CloudflarePolicyError("Cloudflare deployment is not in recent production history")


def _rollback_eligible(row: ListedPagesDeployment, project: PagesProject) -> bool:
    try:
        _require_rollback_target(row, project)
    except CloudflarePolicyError:
        return False
    return True


def _require_rollback_target(row: ListedPagesDeployment, project: PagesProject) -> None:
    if row.environment != "production":
        raise CloudflarePolicyError("Rollback target is not a production deployment")
    if (row.latest_stage.name, row.latest_stage.status) != ("deploy", "success"):
        raise CloudflarePolicyError("Rollback target is not a successful deployment")
    identity = (row.project_name, row.project_id)
    url_valid = _valid_deployment_url(row.url, project.name, row.short_id)
    if identity != (project.name, project.id) or not url_valid:
        raise CloudflarePolicyError("Cloudflare deployment identity differs")


async def _await_live(operations: RollbackOperations, expected: str) -> str:
    try:
        async with asyncio.timeout(ROLLBACK_DEADLINE_SECONDS):
            return await _bounded_live(operations, expected)
    except TimeoutError:
        raise _not_serving() from None


async def _bounded_live(operations: RollbackOperations, expected: str) -> str:
    for delay in ROLLBACK_DELAYS:
        if await _live_id(operations) == expected:
            return expected
        await operations.sleep(delay)
    if await _live_id(operations) == expected:
        return expected
    raise _not_serving()


async def _live_id(operations: RollbackOperations) -> str | None:
    return parse_live_deployment_id(await operations.get_project())


def _not_serving() -> CloudflarePolicyError:
    return CloudflarePolicyError("Cloudflare production does not serve the rollback target")
