"""Public Dagger API for exact Cloudflare Pages direct delivery."""

from __future__ import annotations

import asyncio
import json
import posixpath
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final, Literal
from uuid import uuid4

import dagger
from dagger import dag, field, function, object_type
from pydantic import ValidationError

from .api import (
    CloudflareApiError,
    CloudflarePolicyError,
    deploy_verified_artifact,
    disable_git_payload,
    live_production_deployment,
    preflight_provider,
    provider_error_message,
    require_evidence_binding,
    rollback_production,
    verify_current_deployment,
)
from .models import (
    DEPLOYMENT_ID_PATTERN,
    PROJECT_PATTERN,
    AttemptIdentity,
    CreatedDeployment,
    GitHubEvidence,
    ListedPagesDeployment,
    PagesTarget,
    ProviderDeploymentEvidence,
    RollbackEvidence,
    WranglerBuildMetadata,
    WranglerOutput,
)

CURL_IMAGE: Final = (
    "curlimages/curl:8.16.0@sha256:463eaf6072688fe96ac64fa623fe73e1dbe25d8ad6c34404a669ad3ce1f104b6"
)
NODE_IMAGE: Final = (
    "node:24.6.0-bookworm-slim@sha256:"
    "9b741b28148b0195d62fa456ed84dd6c953c1f17a3761f3e6e6797a754d9edff"
)
JQ_IMAGE: Final = (
    "ghcr.io/jqlang/jq:1.8.1@sha256:"
    "95de8f005ca027686a1ca3b0853e2bb219062438015862816159f3f25a4d4230"
)
WRANGLER_VERSION: Final = "4.103.0"
WRANGLER_NODE_RANGE: Final = ">=22.0.0"
WRANGLER_WORKERD_VERSION: Final = "1.20260617.1"
WRANGLER_MINIFLARE_VERSION: Final = "4.20260617.1"
API_RESPONSE_PATH: Final = "/work/cloudflare-response.json"
CURL_CONFIG_PATH: Final = "/work/cloudflare-curl.cfg"
REQUEST_PATH: Final = "/work/cloudflare-request.json"
CURL_DEADLINE_SECONDS: Final = 20
WRANGLER_PREFLIGHT_SECONDS: Final = 60
WRANGLER_FUNCTIONS_SECONDS: Final = 120
WRANGLER_UPLOAD_SECONDS: Final = 300
HTTP_STATUS_LENGTH: Final = 3
API_RESPONSE_BYTES: Final = 262_144
API_ERROR_BYTES: Final = 16_384
WRANGLER_OUTPUT_PATH: Final = "/run/provider-output/output.jsonl"
WRANGLER_REQUIRED_FLAGS: Final = (
    "--project-name",
    "--branch",
    "--commit-hash",
    "--commit-dirty",
    "--no-bundle",
    "--skip-caching",
)
WRANGLER_FUNCTIONS_REQUIRED_FLAGS: Final = (
    "--outdir",
    "--output-routes-path",
    "--project-directory",
    "--build-output-directory",
    "--metafile",
)
FUNCTIONS_METADATA_NAME: Final = "_build-metadata.json"
FUNCTIONS_WORKER_NAME: Final = "_worker.js"
FUNCTIONS_ENTRYPOINT_NAME: Final = "index.js"
FUNCTIONS_CONFLICT_ENTRIES: Final = frozenset(
    {"_routes.json", "_routes.json/", "_worker.js", "_worker.js/"}
)
FUNCTIONS_DERIVED_ENTRIES: Final = frozenset(
    {FUNCTIONS_METADATA_NAME, "_routes.json", "_worker.js/"}
)
FUNCTIONS_METADATA_BYTES: Final = 1_048_576
FUNCTIONS_ENTRYPOINT_BYTES: Final = 67_108_864
FUNCTIONS_DIGEST_BATCH_SIZE: Final = 32
FUNCTIONS_AUTHENTICATED_ROOTS: Final = (
    PurePosixPath("/project/dist"),
    PurePosixPath("/project/functions"),
)
FUNCTIONS_GENERATED_ROOT: Final = PurePosixPath("/project/.wrangler/tmp")
FUNCTIONS_TOOLCHAIN_INPUTS: Final = frozenset(
    {
        PurePosixPath(
            "/usr/local/lib/node_modules/wrangler/node_modules/path-to-regexp/dist.es2015/index.js"
        ),
        PurePosixPath("/usr/local/lib/node_modules/wrangler/templates/pages-template-worker.ts"),
    }
)
type CurlMethod = Literal["GET", "PATCH", "POST"]
FUNCTIONS_SOURCE_EXCLUDES: Final = [
    "**/node_modules",
    "**/package.json",
    "**/package-lock.json",
    "**/pnpm-lock.yaml",
    "**/yarn.lock",
    "**/wrangler.toml",
    "**/wrangler.json",
    "**/wrangler.jsonc",
]


@dataclass(frozen=True)
class ProviderContext:
    """Validated immutable target, foundation evidence, and caller attempt."""

    target: PagesTarget
    github: GitHubEvidence
    attempt: AttemptIdentity


@dataclass(frozen=True)
class TargetInputs:
    """Unparsed scalar target values from the explicit Dagger boundary."""

    repository: str
    project: str
    branch: str
    live_domain: str
    deploy_root: str
    domains: tuple[str, ...]
    pages_functions: bool = False


@object_type
class DeploymentEvidence:
    """Non-secret Cloudflare deployment proof safe for downstream policy."""

    provider: str = field()
    deployment_id: str = field()
    deployment_url: str = field()
    project_id: str = field()
    project: str = field()
    repository: str = field()
    branch: str = field()
    source_sha: str = field()
    workflow_run_id: str = field()
    run_attempt: int = field()


@object_type
class ProductionDeployment:
    """The production deployment served now: the rollback target to record."""

    project: str = field()
    deployment_id: str = field()
    deployment_url: str = field()


@object_type
class ProductionRollbackEvidence:
    """Non-secret proof that production now serves the rollback target."""

    project: str = field()
    from_deployment_id: str = field()
    to_deployment_id: str = field()
    live_deployment_id: str = field()
    live_deployment_url: str = field()


@dataclass(frozen=True)
class CurlPagesOperations:
    """Pinned, secret-safe Dagger adapters for one Pages target."""

    api_token: dagger.Secret
    account_id: dagger.Secret
    target: PagesTarget
    api_service: dagger.Service | None = None
    ca_certificate: dagger.File | None = None

    async def get_project(self) -> str:
        return await self._request("GET", self._project_suffix())

    async def get_deployments(self) -> str:
        suffix = f"{self._project_suffix()}/deployments?env=production&per_page=10"
        return await self._request("GET", suffix)

    async def disable_git(self) -> str:
        body = json.dumps(disable_git_payload(self.target), separators=(",", ":"), sort_keys=True)
        return await self._request("PATCH", self._project_suffix(), body)

    async def wrangler_preflight(self) -> None:
        output = await _wrangler_help(["wrangler", "pages", "deploy", "--help"])
        _require_wrangler_help(output)
        if self.target.pages_functions:
            command = ["wrangler", "pages", "functions", "build", "--help"]
            _require_functions_help(await _wrangler_help(command))

    async def upload(self, artifact: dagger.Directory, source_sha: str) -> CreatedDeployment:
        container = self._upload_container(artifact, source_sha)
        try:
            raw = await asyncio.wait_for(container.stdout(), WRANGLER_UPLOAD_SECONDS)
        except (TimeoutError, dagger.QueryError):
            raise CloudflarePolicyError("Cloudflare Pages direct upload failed") from None
        return _parse_wrangler_output(raw, self.target)

    async def sleep(self, seconds: int) -> None:
        await asyncio.sleep(seconds)

    async def _request(self, method: CurlMethod, suffix: str, body: str = "") -> str:
        return await _send_request(self._request_container(method, suffix, body))

    def _request_container(self, method: CurlMethod, suffix: str, body: str) -> dagger.Container:
        transport = CurlTransport(
            self.api_token, self.account_id, self.api_service, self.ca_certificate
        )
        return _curl_request_container(transport, method, suffix, body)

    def _upload_container(self, artifact: dagger.Directory, source_sha: str) -> dagger.Container:
        base = _wrangler_base().with_mounted_directory("/artifact", artifact, read_only=True)
        base = base.with_mounted_temp("/run/provider-output")
        base = base.with_mounted_temp("/run/provider-cache")
        base = base.with_mounted_temp("/run/provider-config")
        base = base.with_env_variable("WRANGLER_CACHE_DIR", "/run/provider-cache")
        base = base.with_env_variable("XDG_CONFIG_HOME", "/run/provider-config")
        base = base.with_env_variable("WRANGLER_OUTPUT_FILE_PATH", WRANGLER_OUTPUT_PATH)
        base = base.with_secret_variable("CLOUDFLARE_API_TOKEN", self.api_token)
        base = base.with_secret_variable("CLOUDFLARE_ACCOUNT_ID", self.account_id)
        base = base.with_mounted_file("/run/jq", _jq_binary())
        command = ["/bin/sh", "-euc", _wrangler_script(), "--"]
        return _uncached(base).with_exec([*command, *wrangler_deploy_args(self.target, source_sha)])

    def _project_suffix(self) -> str:
        return f"/pages/projects/{self.target.project}"


@dataclass(frozen=True)
class CurlTransport:
    """Secret-safe credentials and optional test-only mock bindings for curl."""

    api_token: dagger.Secret
    account_id: dagger.Secret
    api_service: dagger.Service | None = None
    ca_certificate: dagger.File | None = None


@dataclass(frozen=True)
class CurlRollbackOperations:
    """Pinned curl adapter for read-only history reads and one rollback POST."""

    api_token: dagger.Secret
    account_id: dagger.Secret
    project: str
    api_service: dagger.Service | None = None
    ca_certificate: dagger.File | None = None

    def __post_init__(self) -> None:
        if PROJECT_PATTERN.fullmatch(self.project) is None:
            raise CloudflarePolicyError("Cloudflare Pages project name is malformed")

    async def get_project(self) -> str:
        return await self._request("GET", self._project_suffix())

    async def get_deployments(self) -> str:
        suffix = f"{self._project_suffix()}/deployments?env=production&per_page=10"
        return await self._request("GET", suffix)

    async def rollback(self, deployment_id: str) -> str:
        if DEPLOYMENT_ID_PATTERN.fullmatch(deployment_id) is None:
            raise CloudflarePolicyError("Cloudflare Pages deployment id is malformed")
        suffix = f"{self._project_suffix()}/deployments/{deployment_id}/rollback"
        return await self._request("POST", suffix)

    async def sleep(self, seconds: int) -> None:
        await asyncio.sleep(seconds)

    async def _request(self, method: CurlMethod, suffix: str, body: str = "") -> str:
        transport = CurlTransport(
            self.api_token, self.account_id, self.api_service, self.ca_certificate
        )
        return await _send_request(_curl_request_container(transport, method, suffix, body))

    def _project_suffix(self) -> str:
        return f"/pages/projects/{self.project}"


@object_type
class CloudflarePages:
    """Deploy only foundation-verified artifacts to one bound Pages target."""

    # fmt: off
    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]  # SDK stub gap
    async def preflight(
        self, envelope: dagger.Directory, github_token: dagger.Secret,
        cloudflare_api_token: dagger.Secret, cloudflare_account_id: dagger.Secret,
        workflow_run_id: str, run_attempt: int, repository: str, project: str,
        production_branch: str, live_domain: str, deploy_root: str, domains: list[str],
        consumer_identity: str, producing_identity: str, allowed_roots: list[str],
        pages_functions: bool = False,
    ) -> str:
        """Verify the envelope and run read-only project, deployment, and CLI checks."""
        inputs = _target_inputs(repository, project, production_branch, live_domain,
                                deploy_root, domains, pages_functions)
        return await _preflight(envelope, github_token, cloudflare_api_token,
                                cloudflare_account_id, workflow_run_id, run_attempt,
                                inputs, consumer_identity, producing_identity, allowed_roots)
    # fmt: on

    # fmt: off
    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]  # SDK stub gap
    async def deploy(
        self, envelope: dagger.Directory, github_token: dagger.Secret,
        cloudflare_api_token: dagger.Secret, cloudflare_account_id: dagger.Secret,
        workflow_run_id: str, run_attempt: int, repository: str, project: str,
        production_branch: str, live_domain: str, deploy_root: str, domains: list[str],
        consumer_identity: str, producing_identity: str, allowed_roots: list[str],
        pages_functions: bool = False,
    ) -> DeploymentEvidence:
        """Direct-upload one verified artifact and return exact deployment evidence."""
        inputs = _target_inputs(repository, project, production_branch, live_domain,
                                deploy_root, domains, pages_functions)
        return await _deploy(envelope, github_token, cloudflare_api_token,
                             cloudflare_account_id, workflow_run_id, run_attempt,
                             inputs, consumer_identity, producing_identity, allowed_roots)
    # fmt: on

    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]  # SDK stub gap
    async def previous_production_deployment(
        self,
        cloudflare_api_token: dagger.Secret,
        cloudflare_account_id: dagger.Secret,
        project: str,
    ) -> ProductionDeployment:
        """Read-only: record the deployment production serves now, before a new deploy."""
        operations = CurlRollbackOperations(cloudflare_api_token, cloudflare_account_id, project)
        return _public_production(project, await live_production_deployment(operations, project))

    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]  # SDK stub gap
    async def rollback(
        self,
        cloudflare_api_token: dagger.Secret,
        cloudflare_account_id: dagger.Secret,
        project: str,
        deployment_id: str = "",
    ) -> ProductionRollbackEvidence:
        """Roll production back to deployment_id, or the previous successful one."""
        operations = CurlRollbackOperations(cloudflare_api_token, cloudflare_account_id, project)
        evidence = await rollback_production(operations, project, deployment_id or None)
        return _public_rollback(evidence)

    # fmt: off
    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]  # SDK stub gap
    async def verify(
        self, envelope: dagger.Directory, github_token: dagger.Secret,
        cloudflare_api_token: dagger.Secret, cloudflare_account_id: dagger.Secret,
        workflow_run_id: str, run_attempt: int, repository: str, project: str,
        production_branch: str, live_domain: str, deploy_root: str, domains: list[str],
        consumer_identity: str, producing_identity: str, allowed_roots: list[str],
        pages_functions: bool = False,
    ) -> DeploymentEvidence:
        """Converge read-only production evidence for an exact source attempt."""
        inputs = _target_inputs(repository, project, production_branch, live_domain,
                                deploy_root, domains, pages_functions)
        return await _verify(envelope, github_token, cloudflare_api_token,
                             cloudflare_account_id, workflow_run_id, run_attempt,
                             inputs, consumer_identity, producing_identity, allowed_roots)
    # fmt: on


def _target_inputs(
    repository: str,
    project: str,
    branch: str,
    domain: str,
    deploy_root: str,
    domains: list[str],
    pages_functions: bool,
) -> TargetInputs:
    return TargetInputs(
        repository, project, branch, domain, deploy_root, tuple(domains), pages_functions
    )


# fmt: off
async def _preflight(
    envelope: dagger.Directory, github_token: dagger.Secret, api_token: dagger.Secret,
    account_id: dagger.Secret, run_id: str, attempt: int, inputs: TargetInputs,
    consumer: str, producer: str, roots: list[str],
) -> str:
    artifact, context = await _verified_context(
        envelope, github_token, run_id, attempt, inputs, consumer, producer, roots)
    operations = CurlPagesOperations(api_token, account_id, context.target)
    await _prepare_deploy_artifact(artifact, context.target)
    await preflight_provider(operations, context.target)
    return "Cloudflare Pages preflight passed"
# fmt: on


# fmt: off
async def _deploy(
    envelope: dagger.Directory, github_token: dagger.Secret, api_token: dagger.Secret,
    account_id: dagger.Secret, run_id: str, attempt: int, inputs: TargetInputs,
    consumer: str, producer: str, roots: list[str],
) -> DeploymentEvidence:
    artifact, context = await _verified_context(
        envelope, github_token, run_id, attempt, inputs, consumer, producer, roots)
    operations = CurlPagesOperations(api_token, account_id, context.target)
    artifact = await _prepare_deploy_artifact(artifact, context.target)
    evidence = await deploy_verified_artifact(
        operations, artifact, context.target, context.github, context.attempt)
    return _public_evidence(evidence)
# fmt: on


# fmt: off
async def _verify(
    envelope: dagger.Directory, github_token: dagger.Secret, api_token: dagger.Secret,
    account_id: dagger.Secret, run_id: str, attempt: int, inputs: TargetInputs,
    consumer: str, producer: str, roots: list[str],
) -> DeploymentEvidence:
    _, context = await _verified_context(
        envelope, github_token, run_id, attempt, inputs, consumer, producer, roots)
    operations = CurlPagesOperations(api_token, account_id, context.target)
    evidence = await verify_current_deployment(
        operations, context.target, context.github, context.attempt)
    return _public_evidence(evidence)
# fmt: on


async def _provider_context(
    github_token: dagger.Secret, workflow_run_id: str, run_attempt: int, inputs: TargetInputs
) -> ProviderContext:
    target = _pages_target(inputs)
    attempt = AttemptIdentity(workflow_run_id, run_attempt)
    github = await _green_evidence(github_token, inputs.repository)
    require_evidence_binding(target, github, attempt)
    return ProviderContext(target, github, attempt)


async def _green_evidence(token: dagger.Secret, repository: str) -> GitHubEvidence:
    value = (
        await dag.foundation().green_main(github_token=token, repository=repository).serialization()
    )
    try:
        return GitHubEvidence.model_validate_json(value)
    except ValidationError:
        raise CloudflarePolicyError("Foundation GitHub evidence schema differs") from None


def _pages_target(inputs: TargetInputs) -> PagesTarget:
    return PagesTarget(
        inputs.repository,
        inputs.project,
        inputs.branch,
        inputs.live_domain,
        inputs.deploy_root,
        inputs.domains,
        inputs.pages_functions,
    )


# fmt: off
async def _verified_context(
    envelope: dagger.Directory, github_token: dagger.Secret, workflow_run_id: str,
    run_attempt: int, inputs: TargetInputs, consumer_identity: str,
    producing_identity: str, allowed_roots: list[str],
) -> tuple[dagger.Directory, ProviderContext]:
    target = _pages_target(inputs)
    _require_deploy_root(target, allowed_roots)
    verified = await _verify_envelope(
        envelope, consumer_identity, producing_identity, allowed_roots)
    await _require_pages_functions_source(verified, target)
    context = await _provider_context(github_token, workflow_run_id, run_attempt, inputs)
    _require_consumer_binding(consumer_identity, inputs.repository, context.github)
    artifact = verified if target.pages_functions else verified.directory(target.deploy_root)
    await artifact.digest()
    return artifact, context
# fmt: on


def _require_consumer_binding(consumer: str, repository: str, github: GitHubEvidence) -> None:
    if consumer != f"{repository}@{github.commit_sha}":
        raise CloudflarePolicyError("Envelope source identity differs from GitHub evidence")


def _require_deploy_root(target: PagesTarget, allowed_roots: list[str]) -> None:
    if target.pages_functions:
        _require_functions_roots(target.deploy_root, allowed_roots)
        return
    if allowed_roots != [target.deploy_root]:
        raise CloudflarePolicyError("Pages deploy root must be the only envelope root")


def _require_functions_roots(deploy_root: str, allowed_roots: list[str]) -> None:
    if deploy_root != "dist" or allowed_roots != ["dist", "functions"]:
        raise CloudflarePolicyError("Pages Functions roots must be exactly dist then functions")


async def _require_pages_functions_source(verified: dagger.Directory, target: PagesTarget) -> None:
    if not target.pages_functions:
        return
    try:
        static = await verified.directory(target.deploy_root).entries()
        functions = await verified.directory("functions").entries()
    except dagger.QueryError:
        raise CloudflarePolicyError("Pages Functions roots could not be read") from None
    conflicts = FUNCTIONS_CONFLICT_ENTRIES.intersection(static)
    if conflicts:
        name = sorted(conflicts)[0]
        raise CloudflarePolicyError(f"{name} conflicts with Pages functions delivery")
    if not functions:
        raise CloudflarePolicyError("Pages functions root must not be empty")


async def _prepare_deploy_artifact(
    artifact: dagger.Directory, target: PagesTarget
) -> dagger.Directory:
    if not target.pages_functions:
        return artifact
    container = _functions_build_container(artifact)
    return await _compiled_pages_artifact(artifact, container, target.deploy_root)


async def _compiled_pages_artifact(
    source: dagger.Directory, container: dagger.Container, deploy_root: str
) -> dagger.Directory:
    derived = container.directory("/derived")
    try:
        entries = await asyncio.wait_for(derived.entries(), WRANGLER_FUNCTIONS_SECONDS)
    except (TimeoutError, dagger.QueryError):
        raise CloudflarePolicyError("Pages Functions build failed") from None
    if frozenset(entries) != FUNCTIONS_DERIVED_ENTRIES:
        raise CloudflarePolicyError("Pages Functions derived outputs differ")
    await _require_closed_functions_build(source, derived)
    worker = derived.directory(FUNCTIONS_WORKER_NAME)
    staged = source.directory(deploy_root).with_directory(FUNCTIONS_WORKER_NAME, worker)
    staged = staged.with_file("_routes.json", derived.file("_routes.json"))
    await staged.digest()
    return staged


def _functions_build_container(artifact: dagger.Directory) -> dagger.Container:
    base = _wrangler_base().with_mounted_directory(
        "/project", _functions_source(artifact), read_only=True
    )
    base = base.with_mounted_temp("/project/.wrangler/tmp")
    base = base.with_directory("/derived", _empty_directory())
    base = base.with_mounted_temp("/run/functions-cache")
    base = base.with_mounted_temp("/run/functions-config")
    base = base.with_env_variable("WRANGLER_CACHE_DIR", "/run/functions-cache")
    base = base.with_env_variable("XDG_CONFIG_HOME", "/run/functions-config")
    return base.with_workdir("/project").with_exec(functions_build_args())


def _functions_source(artifact: dagger.Directory) -> dagger.Directory:
    source = artifact.filter(exclude=FUNCTIONS_SOURCE_EXCLUDES)
    return source.with_new_directory(".wrangler/tmp")


def _empty_directory() -> dagger.Directory:
    return dag.directory()


async def _require_closed_functions_build(
    source: dagger.Directory, derived: dagger.Directory
) -> None:
    metadata = await _functions_build_metadata(derived)
    inputs = tuple(_resolved_functions_input(value) for value in metadata.inputs)
    _require_closed_functions_inputs(inputs)
    await _require_worker_modules(source, derived)


async def _require_worker_modules(source: dagger.Directory, derived: dagger.Directory) -> None:
    worker = derived.directory(FUNCTIONS_WORKER_NAME)
    try:
        entries = await asyncio.wait_for(worker.entries(), WRANGLER_FUNCTIONS_SECONDS)
        paths = await asyncio.wait_for(worker.glob("**"), WRANGLER_FUNCTIONS_SECONDS)
    except (TimeoutError, dagger.QueryError):
        raise CloudflarePolicyError("Pages Functions module output differs") from None
    _require_worker_inventory(tuple(entries), tuple(paths))
    await _require_worker_entrypoint(worker.file(FUNCTIONS_ENTRYPOINT_NAME))
    await _require_worker_provenance(source, worker, tuple(paths))


async def _require_worker_provenance(
    source: dagger.Directory, worker: dagger.Directory, paths: tuple[str, ...]
) -> None:
    modules = _auxiliary_worker_paths(paths)
    if not modules:
        return
    allowed = await _authenticated_source_digests(source)
    emitted = await _file_digests(worker, modules)
    if not set(emitted).issubset(allowed):
        raise CloudflarePolicyError("Pages Functions module provenance differs")


def _auxiliary_worker_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(
        path for path in paths if path != FUNCTIONS_ENTRYPOINT_NAME and not path.endswith("/")
    )


async def _authenticated_source_digests(source: dagger.Directory) -> frozenset[str]:
    paths = await _authenticated_source_paths(source)
    return frozenset(await _file_digests(source, paths))


async def _authenticated_source_paths(source: dagger.Directory) -> tuple[str, ...]:
    patterns = ("dist/**", "functions/**")
    try:
        groups = await asyncio.wait_for(
            asyncio.gather(*(source.glob(pattern) for pattern in patterns)),
            WRANGLER_FUNCTIONS_SECONDS,
        )
    except (TimeoutError, dagger.QueryError):
        raise CloudflarePolicyError("Pages Functions module provenance differs") from None
    return _regular_source_paths(groups)


def _regular_source_paths(groups: Sequence[Sequence[str]]) -> tuple[str, ...]:
    return tuple(path for group in groups for path in group if not path.endswith("/"))


async def _file_digests(directory: dagger.Directory, paths: tuple[str, ...]) -> tuple[str, ...]:
    try:
        values = await asyncio.wait_for(
            _batched_file_digests(directory, paths),
            WRANGLER_FUNCTIONS_SECONDS,
        )
    except (TimeoutError, dagger.QueryError):
        raise CloudflarePolicyError("Pages Functions module provenance differs") from None
    return values


async def _batched_file_digests(
    directory: dagger.Directory, paths: tuple[str, ...]
) -> tuple[str, ...]:
    values: list[str] = []
    for start in range(0, len(paths), FUNCTIONS_DIGEST_BATCH_SIZE):
        batch = paths[start : start + FUNCTIONS_DIGEST_BATCH_SIZE]
        digests = await asyncio.gather(
            *(directory.file(path).digest(exclude_metadata=True) for path in batch)
        )
        values.extend(digests)
    return tuple(values)


def _require_worker_inventory(entries: tuple[str, ...], paths: tuple[str, ...]) -> None:
    _require_worker_entrypoint_path(entries, paths)
    _require_closed_worker_paths(paths)


def _require_worker_entrypoint_path(entries: tuple[str, ...], paths: tuple[str, ...]) -> None:
    if FUNCTIONS_ENTRYPOINT_NAME not in entries or FUNCTIONS_ENTRYPOINT_NAME not in paths:
        raise CloudflarePolicyError("Pages Functions module output differs")


def _require_closed_worker_paths(paths: tuple[str, ...]) -> None:
    if not paths or not all(_closed_worker_path(value) for value in paths):
        raise CloudflarePolicyError("Pages Functions module output differs")


def _closed_worker_path(value: str) -> bool:
    path = PurePosixPath(value)
    normalized = path.as_posix()
    return bool(value) and not path.is_absolute() and ".." not in path.parts and normalized == value


async def _require_worker_entrypoint(entrypoint: dagger.File) -> None:
    try:
        size = await asyncio.wait_for(entrypoint.size(), WRANGLER_FUNCTIONS_SECONDS)
        if not 0 < size <= FUNCTIONS_ENTRYPOINT_BYTES:
            raise CloudflarePolicyError("Pages Functions module output differs")
        value = await asyncio.wait_for(entrypoint.contents(), WRANGLER_FUNCTIONS_SECONDS)
    except (TimeoutError, dagger.QueryError):
        raise CloudflarePolicyError("Pages Functions module output differs") from None
    if _serialized_multipart(value):
        raise CloudflarePolicyError("Pages Functions module output differs")


def _serialized_multipart(value: str) -> bool:
    lines = value.splitlines()
    return (
        len(lines) > 1
        and lines[0].startswith("--")
        and lines[1].casefold().startswith("content-disposition: form-data")
    )


def _require_closed_functions_inputs(inputs: tuple[PurePosixPath, ...]) -> None:
    _require_only_closed_functions_inputs(inputs)
    _require_authenticated_function_input(inputs)


def _require_only_closed_functions_inputs(inputs: tuple[PurePosixPath, ...]) -> None:
    if not inputs or not all(_closed_functions_input(value) for value in inputs):
        raise CloudflarePolicyError("Pages Functions inputs escaped authenticated roots")


def _require_authenticated_function_input(inputs: tuple[PurePosixPath, ...]) -> None:
    functions = FUNCTIONS_AUTHENTICATED_ROOTS[1]
    if not any(value.is_relative_to(functions) for value in inputs):
        raise CloudflarePolicyError("Pages Functions metadata omitted authenticated source")


async def _functions_build_metadata(derived: dagger.Directory) -> WranglerBuildMetadata:
    file = derived.file(FUNCTIONS_METADATA_NAME)
    try:
        size = await asyncio.wait_for(file.size(), WRANGLER_FUNCTIONS_SECONDS)
    except (TimeoutError, ValidationError, dagger.QueryError):
        raise CloudflarePolicyError("Pages Functions build metadata differs") from None
    if size > FUNCTIONS_METADATA_BYTES:
        raise CloudflarePolicyError("Pages Functions build metadata differs")
    try:
        value = await asyncio.wait_for(file.contents(), WRANGLER_FUNCTIONS_SECONDS)
        return WranglerBuildMetadata.model_validate_json(value)
    except (TimeoutError, ValidationError, dagger.QueryError):
        raise CloudflarePolicyError("Pages Functions build metadata differs") from None


def _resolved_functions_input(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    candidate = path if path.is_absolute() else PurePosixPath("/project/functions", path)
    return PurePosixPath(posixpath.normpath(candidate.as_posix()))


def _closed_functions_input(value: PurePosixPath) -> bool:
    roots = (*FUNCTIONS_AUTHENTICATED_ROOTS, FUNCTIONS_GENERATED_ROOT)
    return any(value.is_relative_to(root) for root in roots) or value in FUNCTIONS_TOOLCHAIN_INPUTS


async def _verify_envelope(
    envelope: dagger.Directory,
    consumer_identity: str,
    producing_identity: str,
    allowed_roots: list[str],
) -> dagger.Directory:
    artifact = dag.foundation().verify_envelope(
        envelope=envelope,
        consumer_identity=consumer_identity,
        producing_identity=producing_identity,
        allowed_roots=allowed_roots,
    )
    await artifact.digest()
    return artifact


def wrangler_deploy_args(target: PagesTarget, source_sha: str) -> list[str]:
    """Return the fixed direct-upload command over the verified mount only."""
    return [
        "wrangler",
        "pages",
        "deploy",
        "/artifact",
        f"--project-name={target.project}",
        f"--branch={target.branch}",
        f"--commit-hash={source_sha}",
        "--commit-dirty=false",
        "--no-bundle",
        "--skip-caching",
    ]


def functions_build_args() -> list[str]:
    """Build Functions from only the authenticated closed project mount."""
    return [
        "wrangler",
        "pages",
        "functions",
        "build",
        "functions",
        "--outdir=/derived/_worker.js",
        "--output-routes-path=/derived/_routes.json",
        "--project-directory=/project",
        "--build-output-directory=/project/dist",
        "--metafile=/derived/_build-metadata.json",
    ]


def _wrangler_base() -> dagger.Container:
    install = [
        "npm",
        "install",
        "--global",
        "--omit=dev",
        "--no-audit",
        "--no-fund",
        "--loglevel=error",
        f"wrangler@{WRANGLER_VERSION}",
    ]
    base = dag.container(platform=dagger.Platform("linux/amd64")).from_(NODE_IMAGE)
    return base.with_env_variable("WRANGLER_SEND_METRICS", "false").with_exec(install)


def _curl_request_container(
    transport: CurlTransport, method: CurlMethod, suffix: str, body: str
) -> dagger.Container:
    base = dag.container(platform=dagger.Platform("linux/amd64")).from_(CURL_IMAGE)
    base = base.with_entrypoint([]).with_user("0").with_mounted_temp("/work")
    base = base.with_workdir("/work")
    base = base.with_mounted_secret("/run/secrets/token", transport.api_token)
    base = base.with_mounted_secret("/run/secrets/account", transport.account_id)
    base = base.with_mounted_file("/run/jq", _jq_binary())
    if transport.api_service is not None:
        base = base.with_service_binding("api.cloudflare.com", transport.api_service)
    if transport.ca_certificate is not None:
        base = base.with_mounted_file("/run/mock-ca.pem", transport.ca_certificate)
    command = ["/bin/sh", "-euc", _curl_script(), "--", method, suffix]
    return _uncached(base).with_exec(command, stdin=body)


async def _send_request(request: dagger.Container) -> str:
    try:
        result = await asyncio.wait_for(_request_result(request), CURL_DEADLINE_SECONDS)
    except (TimeoutError, dagger.QueryError):
        raise CloudflareApiError("Cloudflare network request failed") from None
    return _require_http_success(*result)


def _jq_binary() -> dagger.File:
    image = dag.container(platform=dagger.Platform("linux/amd64")).from_(JQ_IMAGE)
    return image.file("/jq")


def _uncached(container: dagger.Container) -> dagger.Container:
    return container.with_env_variable("DAGGER_CLOUDFLARE_REQUEST_NONCE", uuid4().hex)


async def _request_result(request: dagger.Container) -> tuple[str, str]:
    status, separator, response = (await request.stdout()).partition("\n")
    if not separator:
        raise CloudflareApiError("Cloudflare API response framing differed")
    limit = API_RESPONSE_BYTES if status.startswith("2") else API_ERROR_BYTES
    if len(response.encode()) > limit:
        raise CloudflareApiError("Cloudflare API response exceeded byte limit")
    return status.strip(), response.strip()


def _require_http_success(status: str, response: str) -> str:
    if len(status) == HTTP_STATUS_LENGTH and status.startswith("2"):
        return response
    raise CloudflareApiError(provider_error_message(response))


def _require_wrangler_help(output: str) -> None:
    if not all(flag in output for flag in WRANGLER_REQUIRED_FLAGS):
        raise CloudflarePolicyError("Pinned Wrangler Pages flags differ")


def _require_functions_help(output: str) -> None:
    if not all(flag in output for flag in WRANGLER_FUNCTIONS_REQUIRED_FLAGS):
        raise CloudflarePolicyError("Pinned Wrangler Pages Functions flags differ")


async def _wrangler_help(command: list[str]) -> str:
    container = _wrangler_base().with_exec(command)
    try:
        return await asyncio.wait_for(container.stdout(), WRANGLER_PREFLIGHT_SECONDS)
    except (TimeoutError, dagger.QueryError):
        raise CloudflarePolicyError("Pinned Wrangler preflight failed") from None


def _parse_wrangler_output(raw: str, target: PagesTarget) -> CreatedDeployment:
    records = _wrangler_records(raw)
    matching = tuple(record for record in records if record.pages_project == target.project)
    record = _one_wrangler_record(matching)
    return CreatedDeployment(record.deployment_id, record.url)


def _wrangler_records(raw: str) -> tuple[WranglerOutput, ...]:
    try:
        return tuple(WranglerOutput.model_validate_json(line) for line in raw.splitlines())
    except ValidationError:
        raise CloudflarePolicyError("Pinned Wrangler output schema differs") from None


def _one_wrangler_record(matching: tuple[WranglerOutput, ...]) -> WranglerOutput:
    if len(matching) != 1:
        raise CloudflarePolicyError("Pinned Wrangler created deployment identity differs")
    return matching[0]


def _public_evidence(source: ProviderDeploymentEvidence) -> DeploymentEvidence:
    evidence = DeploymentEvidence.__new__(DeploymentEvidence)
    evidence.provider = "cloudflare-pages"
    evidence.deployment_id = source.deployment_id
    evidence.deployment_url = source.deployment_url
    evidence.project_id = source.project_id
    evidence.project = source.project
    evidence.repository = source.repository
    evidence.branch = source.branch
    evidence.source_sha = source.source_sha
    evidence.workflow_run_id = source.attempt_identity.workflow_run_id
    evidence.run_attempt = source.attempt_identity.run_attempt
    return evidence


def _public_production(project: str, source: ListedPagesDeployment) -> ProductionDeployment:
    deployment = ProductionDeployment.__new__(ProductionDeployment)
    deployment.project = project
    deployment.deployment_id = source.id
    deployment.deployment_url = source.url
    return deployment


def _public_rollback(source: RollbackEvidence) -> ProductionRollbackEvidence:
    evidence = ProductionRollbackEvidence.__new__(ProductionRollbackEvidence)
    evidence.project = source.project
    evidence.from_deployment_id = source.from_deployment_id
    evidence.to_deployment_id = source.to_deployment_id
    evidence.live_deployment_id = source.live_deployment_id
    evidence.live_deployment_url = source.live_deployment_url
    return evidence


def _curl_script() -> str:
    projection = _jq_projection()
    return f"""
method="$1"
suffix="$2"
token="$(tr -d '\\r\\n' < /run/secrets/token)"
account="$(tr -d '\\r\\n' < /run/secrets/account)"
case "$token" in ''|*[!A-Za-z0-9._-]*) exit 64;; esac
case "$account" in *[!A-Fa-f0-9]*) exit 64;; esac
[ "${{#account}}" -eq 32 ] || exit 64
umask 077
cat > {REQUEST_PATH}
{{
  printf 'url = "https://api.cloudflare.com/client/v4/accounts/%s%s"\\n' "$account" "$suffix"
  printf 'header = "Authorization: Bearer %s"\\n' "$token"
  printf 'request = "%s"\\n' "$method"
  printf 'output = "{API_RESPONSE_PATH}"\\n'
  printf 'write-out = "%%{{http_code}}"\\n'
  printf 'connect-timeout = 3\\nmax-time = 8\\nmax-filesize = {API_RESPONSE_BYTES}\\nsilent\\n'
  if [ "$method" = GET ]; then
    printf 'retry = 1\\nretry-all-errors\\nretry-delay = 1\\n'
  else
    printf 'retry = 0\\n'
  fi
  if [ -f /run/mock-ca.pem ]; then printf 'cacert = "/run/mock-ca.pem"\\n'; fi
  if [ "$method" = PATCH ] || [ "$method" = POST ]; then
    printf 'header = "Content-Type: application/json"\\n'
    printf 'data-binary = "@{REQUEST_PATH}"\\n'
  fi
}} > {CURL_CONFIG_PATH}
status="$(curl --config {CURL_CONFIG_PATH})"
case "$status" in 2*) limit={API_RESPONSE_BYTES};; *) limit={API_ERROR_BYTES};; esac
[ "$(wc -c < {API_RESPONSE_PATH})" -le "$limit" ] || exit 65
printf '%s\n' "$status"
if [ "${{status#2}}" != "$status" ]; then
  exec /run/jq -c '{projection}' {API_RESPONSE_PATH}
fi
printf '%s\n' '{{"errors":[],"messages":[],"success":false}}'
"""


def _jq_projection() -> str:
    problem = r'{code:.code,message:"Provider error",documentation_url:null,source:null}'
    deployment = _jq_deployment()
    result = r'if (.result|type)=="array" then [.result[]|' + deployment + r"] "
    result += r'elif (.result|type)=="object" and (.result|has("latest_stage")) then (.result|'
    result += deployment + r") else (.result|" + _jq_project() + r") end"
    info = r"result_info:(.result_info|{count,page,per_page,total_count,total_pages})"
    prefix = r"{errors:[.errors[]|" + problem + r"],messages:[.messages[]|" + problem
    return prefix + r"],success,result:(" + result + r")," + info + r"}"


def _jq_project() -> str:
    source = (
        r"{type:.type,config:(.config|{owner,repo_name,production_branch,"
        r"production_deployments_enabled,preview_deployment_setting})}"
    )
    project = r"{id,name,production_branch,domains,source:(.source|if .==null then null else "
    project += source + r" end),canonical_deployment:(.canonical_deployment|"
    return project + r"if .==null then null else {id} end)}"


def _jq_deployment() -> str:
    trigger = r"{type,metadata:(.metadata|{branch,commit_hash,commit_dirty})}"
    deployment = r"{id,short_id,url,project_id,project_name,environment,latest_stage:"
    deployment += r"(.latest_stage|{name,status}),deployment_trigger:(.deployment_trigger|"
    return deployment + trigger + r")}"


def _wrangler_script() -> str:
    projection = "{type,version,pages_project,deployment_id,url,timestamp}"
    return f"""
"$@" > /run/provider-output/stdout 2> /run/provider-output/stderr
exec /run/jq -c 'select(.type=="pages-deploy")|{projection}' {WRANGLER_OUTPUT_PATH}
"""
