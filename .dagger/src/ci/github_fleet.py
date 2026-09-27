"""Authoritative, fail-closed GitHub evidence reader for the Dagger fleet."""

from __future__ import annotations

import base64
import posixpath
from dataclasses import dataclass
from functools import partial
from types import TracebackType
from typing import Final, Protocol, Self, cast
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, build_opener

from pydantic import ConfigDict, Field, TypeAdapter, ValidationError
from pydantic.dataclasses import dataclass as validated_dataclass

from ci.fleet_policy import (
    CheckRun,
    DaggerConfig,
    DaggerDependency,
    DeploymentEnvironment,
    PinAncestry,
    Protection,
    RepositorySnapshot,
    RequiredCheck,
    SourceFile,
    local_dependency_path,
    parse_pinned_remote,
    required_minimum_pins,
)

BOUNDARY_CONFIG: Final = ConfigDict(frozen=True, extra="ignore", strict=True)
WORKFLOW_PREFIX: Final = ".github/workflows/"
MODULE_PREFIXES: Final = (".dagger/src/", "dagger/src/")
HTTP_OK: Final = 200
HTTP_NOT_FOUND: Final = 404
CENTRAL_REPOSITORY: Final = "repos/hseshadr/ci"


@dataclass(frozen=True)
class HttpResponse:
    """One complete HTTP response returned by an injected transport."""

    status: int
    body: str


class GitHubTransport(Protocol):
    """Minimal behavior required from an authenticated GitHub transport."""

    def get(self, path: str) -> HttpResponse:
        """Read one repository-relative API path."""


class CompletePage(Protocol):
    """Structural contract shared by bounded GitHub list payloads."""

    total_count: int


class OpenedResponse(Protocol):
    """Response behavior used by the standard-library transport."""

    @property
    def status(self) -> int:
        """Return the HTTP response status."""

    def read(self) -> bytes:
        """Return the complete response body."""

    def __enter__(self) -> Self:
        """Enter the response resource scope."""

    def __exit__(
        self,
        error_type: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        """Close the response resource scope."""


class HttpOpener(Protocol):
    """Injectable HTTP request boundary."""

    def open(self, request: Request) -> OpenedResponse:
        """Open one fully-authenticated request."""


class DefaultHttpOpener:
    """Open GitHub API requests with a bounded timeout."""

    def open(self, request: Request) -> OpenedResponse:
        """Return one standard-library response resource."""
        if not request.full_url.startswith("https://api.github.com/"):
            raise FleetAccessError("GitHub transport requires the canonical HTTPS API origin")
        response = build_opener().open(request, timeout=30)
        return cast(OpenedResponse, response)


class GitHubHttpTransport:
    """Authenticate and execute exact GitHub REST API reads."""

    def __init__(self, token: str, opener: HttpOpener | None = None) -> None:
        self._token = token
        self._opener = DefaultHttpOpener() if opener is None else opener

    def get(self, path: str) -> HttpResponse:
        """Read one API path without exposing the bearer credential."""
        request = Request(f"https://api.github.com/{path}", headers=self._headers())
        try:
            with self._opener.open(request) as response:
                return HttpResponse(response.status, response.read().decode())
        except HTTPError as error:
            return HttpResponse(error.code, error.read().decode())

    def _headers(self) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self._token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }


class FleetAccessError(RuntimeError):
    """Authoritative fleet evidence could not be read or proved complete."""


@dataclass(frozen=True)
class SnapshotParts:
    """Validated evidence required to assemble one repository snapshot."""

    evidence: SourceEvidence
    protection: Protection
    checks: CheckRunsPayload
    codeql: CodeqlPayload
    environments: tuple[DeploymentEnvironment, ...]
    repository_secrets: tuple[str, ...]


@dataclass(frozen=True)
class ModuleLocation:
    """One exact GitHub-hosted Dagger configuration location."""

    base: str
    sha: str
    path: str
    identity: str


@dataclass(frozen=True)
class SourceEvidence:
    """Exact-main repository source evidence assembled before metadata reads."""

    name: str
    sha: str
    sources: tuple[SourceFile, ...]
    configs: tuple[DaggerConfig, ...]
    missing: tuple[str, ...]
    ancestry: tuple[PinAncestry, ...]


@dataclass(frozen=True)
class SnapshotProjection:
    """Derived source and check evidence for snapshot assembly."""

    workflows: tuple[SourceFile, ...]
    modules: tuple[SourceFile, ...]
    runs: tuple[CheckRun, ...]
    apps: tuple[str, ...]
    legacy_references: tuple[str, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class CommitPayload:
    """GitHub commit identity response."""

    sha: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class ComparePayload:
    """GitHub compare ancestry status (ahead, behind, identical, or diverged)."""

    status: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class TreeEntry:
    """One recursive Git tree entry."""

    path: str
    type: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class TreePayload:
    """A complete recursive exact-commit tree."""

    sha: str
    truncated: bool
    tree: tuple[TreeEntry, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class ContentPayload:
    """One exact-commit file body."""

    type: str
    path: str
    encoding: str
    content: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class DaggerDependencyPayload:
    """One dependency entry generated into dagger.json."""

    name: str
    source: str
    pin: str | None = None


@validated_dataclass(config=BOUNDARY_CONFIG)
class DaggerSdkPayload:
    """The generated language SDK selected by Dagger."""

    source: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class DaggerConfigPayload:
    """The policy-relevant dagger.json vocabulary."""

    name: str
    sdk: DaggerSdkPayload
    engine_version: str = Field(alias="engineVersion")
    source: str = "."
    dependencies: tuple[DaggerDependencyPayload, ...] = Field(default_factory=tuple)


@validated_dataclass(config=BOUNDARY_CONFIG)
class DeploymentBranchPolicyPayload:
    """GitHub's environment branch-policy mode."""

    protected_branches: bool
    custom_branch_policies: bool


@validated_dataclass(config=BOUNDARY_CONFIG)
class EnvironmentPayload:
    """One environment and its deployment policy mode."""

    name: str
    deployment_branch_policy: DeploymentBranchPolicyPayload | None


@validated_dataclass(config=BOUNDARY_CONFIG)
class EnvironmentsPayload:
    """One complete environment page."""

    total_count: int
    environments: tuple[EnvironmentPayload, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class BranchPolicyPayload:
    """One exact custom deployment branch pattern."""

    name: str
    type: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class BranchPoliciesPayload:
    """One complete deployment branch-policy page."""

    total_count: int
    branch_policies: tuple[BranchPolicyPayload, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class SecretPayload:
    """One GitHub Actions secret name without its value."""

    name: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class SecretsPayload:
    """One complete name-only secret page."""

    total_count: int
    secrets: tuple[SecretPayload, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class EnabledPayload:
    """One enabled branch-protection flag."""

    enabled: bool


@validated_dataclass(config=BOUNDARY_CONFIG)
class ReviewsPayload:
    """Required review count for the protected branch."""

    required_approving_review_count: int


@validated_dataclass(config=BOUNDARY_CONFIG)
class RequiredCheckPayload:
    """One strict external app-bound required status check."""

    context: str
    app_id: int


@validated_dataclass(config=BOUNDARY_CONFIG)
class StatusChecksPayload:
    """Strict app-bound required status checks."""

    strict: bool
    checks: tuple[RequiredCheckPayload, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class ProtectionPayload:
    """Effective classic branch-protection response."""

    required_status_checks: StatusChecksPayload
    enforce_admins: EnabledPayload
    required_pull_request_reviews: ReviewsPayload
    required_conversation_resolution: EnabledPayload
    required_linear_history: EnabledPayload
    allow_force_pushes: EnabledPayload
    allow_deletions: EnabledPayload


@validated_dataclass(config=BOUNDARY_CONFIG)
class AppPayload:
    """GitHub App identity attached to a check run."""

    id: int
    slug: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class CheckPayload:
    """One exact-commit check run."""

    name: str
    head_sha: str
    conclusion: str | None
    app: AppPayload


@validated_dataclass(config=BOUNDARY_CONFIG)
class CheckRunsPayload:
    """One complete page of exact-commit check runs."""

    total_count: int
    check_runs: tuple[CheckPayload, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class CodeqlPayload:
    """Managed CodeQL default-setup state."""

    state: str


def read_repository(transport: GitHubTransport, owner: str, name: str) -> RepositorySnapshot:
    """Read one fleet member exclusively from authoritative exact-main endpoints."""
    base = f"repos/{owner}/{name}"
    commit = read_model(transport, f"{base}/commits/main", CommitPayload)
    evidence = read_source_evidence(transport, base, owner, name, commit.sha)
    snapshot = build_snapshot(read_snapshot_parts(transport, base, evidence))
    assert_main_stable(transport, base, commit.sha)
    return snapshot


def read_source_evidence(
    transport: GitHubTransport, base: str, owner: str, name: str, sha: str
) -> SourceEvidence:
    """Read exact source bytes and dependency graph for one starting main identity."""
    tree = read_tree(transport, base, sha)
    paths = source_paths(tree)
    sources = tuple(read_source(transport, base, sha, path) for path in paths)
    identity = f"github.com/{owner}/{name}@{sha}"
    location = ModuleLocation(base, sha, "dagger.json", identity)
    configs, missing = read_dagger_graph(transport, location, tree)
    ancestry = read_pin_ancestry(transport, configs)
    return SourceEvidence(name, sha, sources, configs, missing, ancestry)


def read_pin_ancestry(
    transport: GitHubTransport, configs: tuple[DaggerConfig, ...]
) -> tuple[PinAncestry, ...]:
    """Compare every floored central pin against its floor and central main."""
    return tuple(
        PinAncestry(
            floor=floor,
            pin=pin,
            floor_status=read_compare_status(transport, floor, pin),
            main_status=read_compare_status(transport, pin, "main"),
        )
        for floor, pin in required_minimum_pins(configs)
    )


def read_compare_status(transport: GitHubTransport, base: str, head: str) -> str:
    """Return GitHub's ancestry status; a 404 means no common history."""
    path = f"{CENTRAL_REPOSITORY}/compare/{base}...{head}?per_page=1"
    response = transport.get(path)
    if response.status == HTTP_NOT_FOUND:
        return "unrelated"
    return parse_model(response, path, ComparePayload).status


def assert_main_stable(transport: GitHubTransport, base: str, expected_sha: str) -> None:
    """Close the exact-main TOCTOU window after every other evidence read."""
    current = read_model(transport, f"{base}/commits/main", CommitPayload)
    if current.sha != expected_sha:
        raise FleetAccessError(f"main moved during authoritative scan for {base}")


def read_snapshot_parts(
    transport: GitHubTransport, base: str, evidence: SourceEvidence
) -> SnapshotParts:
    """Read non-source evidence and assemble immutable snapshot parts."""
    protection = read_protection(transport, base)
    checks = read_checks(transport, base, evidence.sha)
    codeql = read_model(transport, f"{base}/code-scanning/default-setup", CodeqlPayload)
    environments = read_environments(transport, base)
    repository_secrets = read_secret_names(transport, f"{base}/actions/secrets?per_page=100")
    return SnapshotParts(evidence, protection, checks, codeql, environments, repository_secrets)


def read_model[T](transport: GitHubTransport, path: str, model: type[T]) -> T:
    """Validate one successful GitHub response against its exact schema."""
    return parse_model(transport.get(path), path, model)


def parse_model[T](response: HttpResponse, path: str, model: type[T]) -> T:
    """Validate one already-read GitHub response against its exact schema."""
    if response.status != HTTP_OK:
        raise access_error(path, response.status)
    try:
        return TypeAdapter(model).validate_json(response.body)
    except ValidationError as error:
        raise FleetAccessError(f"invalid authoritative response for {path}: {error}") from error


def access_error(path: str, status: int) -> FleetAccessError:
    """Name the minimum fine-grained PAT permission for one failed endpoint."""
    scope = required_scope(path)
    return FleetAccessError(f"GitHub {status} for {path}; token requires {scope}")


def required_scope(path: str) -> str:
    """Map each authoritative endpoint to GitHub's minimum read permission."""
    if is_environment_secret_path(path):
        return "Environments:read"
    scopes = (
        ("/actions/secrets", "Secrets:read"),
        ("/environments", "Actions:read"),
        ("/protection", "Administration:read"),
        ("/code-scanning/default-setup", "Administration:read"),
        ("/check-runs", "Checks:read"),
    )
    return next((scope for marker, scope in scopes if marker in path), "Contents:read")


def is_environment_secret_path(path: str) -> bool:
    """Return whether one endpoint reads environment-scoped secret names."""
    return "/environments/" in path and "/secrets" in path


def read_tree(transport: GitHubTransport, base: str, sha: str) -> TreePayload:
    """Read and prove a complete recursive tree for the exact commit."""
    path = f"{base}/git/trees/{sha}?recursive=1"
    tree = read_model(transport, path, TreePayload)
    if tree.truncated or tree.sha != sha:
        raise FleetAccessError(f"incomplete authoritative source tree for {base}@{sha}")
    return tree


def source_paths(tree: TreePayload) -> tuple[str, ...]:
    """Select all authored workflow and Dagger module source files."""
    return tuple(entry.path for entry in tree.tree if is_policy_source(entry))


def read_dagger_graph(
    transport: GitHubTransport, root: ModuleLocation, tree: TreePayload
) -> tuple[tuple[DaggerConfig, ...], tuple[str, ...]]:
    """Resolve the exact root configuration and every resolvable dependency."""
    if not tree_has_config(tree, root.path):
        return (), (root.identity,)
    return visit_config(transport, root, ())


def tree_has_config(tree: TreePayload, path: str) -> bool:
    """Return whether the authoritative tree contains one config blob."""
    return any(entry.path == path and entry.type == "blob" for entry in tree.tree)


def visit_config(
    transport: GitHubTransport, location: ModuleLocation, ancestors: tuple[str, ...]
) -> tuple[tuple[DaggerConfig, ...], tuple[str, ...]]:
    """Resolve one config recursively while preserving cycles for policy."""
    if location.identity in ancestors:
        return (), ()
    config = read_dagger_config(transport, location)
    if config is None:
        return (), (location.identity,)
    children = child_locations(location, config.dependencies)
    next_ancestors = (*ancestors, location.identity)
    results = tuple(visit_config(transport, child, next_ancestors) for child in children)
    return (config, *merge_configs(results)), merge_missing(results)


def merge_configs(
    results: tuple[tuple[tuple[DaggerConfig, ...], tuple[str, ...]], ...],
) -> tuple[DaggerConfig, ...]:
    """Deduplicate recursively resolved config identities in traversal order."""
    configs = tuple(config for found, _ in results for config in found)
    return tuple({config.identity: config for config in configs}.values())


def merge_missing(
    results: tuple[tuple[tuple[DaggerConfig, ...], tuple[str, ...]], ...],
) -> tuple[str, ...]:
    """Deduplicate unresolved config identities in traversal order."""
    return tuple(dict.fromkeys(item for _, missing in results for item in missing))


def read_dagger_config(transport: GitHubTransport, location: ModuleLocation) -> DaggerConfig | None:
    """Read and validate one exact dependency configuration."""
    source = read_optional_source(transport, location)
    if source is None:
        return None
    payload = parse_dagger_config(source)
    lock = read_generated_lock(transport, location, payload)
    return build_dagger_config(location, payload, lock)


def build_dagger_config(
    location: ModuleLocation, payload: DaggerConfigPayload, lock: SourceFile | None
) -> DaggerConfig:
    """Translate exact external config and lock metadata into domain evidence."""
    return DaggerConfig(
        location.identity,
        location.path,
        payload.name,
        payload.engine_version,
        build_dependencies(payload),
        payload.sdk.source,
        payload.source,
        lock,
    )


def build_dependencies(payload: DaggerConfigPayload) -> tuple[DaggerDependency, ...]:
    """Translate strict generated dependency metadata into domain evidence."""
    return tuple(
        DaggerDependency(item.name, item.source, item.pin) for item in payload.dependencies
    )


def read_generated_lock(
    transport: GitHubTransport, location: ModuleLocation, payload: DaggerConfigPayload
) -> SourceFile | None:
    """Read the committed generated language lock at the same exact revision."""
    path = generated_lock_path(location.path, payload.source, payload.sdk.source)
    if path is None:
        return None
    lock_location = ModuleLocation(location.base, location.sha, path, location.identity)
    return read_optional_source(transport, lock_location)


def generated_lock_path(config_path: str, source: str, sdk: str) -> str | None:
    """Return the Dagger-generated lock location for a supported language SDK."""
    filename = {"python": "uv.lock", "typescript": "yarn.lock"}.get(sdk)
    if filename is None:
        return None
    module_root = posixpath.dirname(config_path)
    return posixpath.normpath(posixpath.join(module_root, source, filename))


def parse_dagger_config(source: SourceFile) -> DaggerConfigPayload:
    """Validate exact dagger.json bytes at the GitHub boundary."""
    try:
        return TypeAdapter(DaggerConfigPayload).validate_json(source.text)
    except ValidationError as error:
        raise FleetAccessError(f"invalid Dagger config for {source.path}: {error}") from error


def read_optional_source(transport: GitHubTransport, location: ModuleLocation) -> SourceFile | None:
    """Read a dependency config, representing an authoritative 404 as missing."""
    path = f"{location.base}/contents/{location.path}?ref={location.sha}"
    response = transport.get(path)
    if response.status == HTTP_NOT_FOUND:
        return None
    payload = parse_content_response(response, path)
    return decode_source(payload, location.path, location.base)


def child_locations(
    parent: ModuleLocation, dependencies: tuple[DaggerDependency, ...]
) -> tuple[ModuleLocation, ...]:
    """Resolve fetchable exact remote or in-repository dependency locations."""
    locations = tuple(dependency_location(parent, item.source) for item in dependencies)
    return tuple(item for item in locations if item is not None)


def dependency_location(parent: ModuleLocation, source: str) -> ModuleLocation | None:
    """Translate one immutable remote or local source into GitHub coordinates."""
    remote = parse_pinned_remote(source)
    if remote is not None:
        return remote_location(remote)
    path = local_dependency_path(parent.path, source)
    if path is None:
        return None
    identity = location_identity(parent.base, parent.sha, path)
    return ModuleLocation(parent.base, parent.sha, path, identity)


def remote_location(remote: tuple[str, str, str, str]) -> ModuleLocation:
    """Build one exact remote config location from a validated reference."""
    owner, repo, subpath, sha = remote
    path = posixpath.join(subpath, "dagger.json")
    identity = f"github.com/{owner}/{repo}" + (f"/{subpath}" if subpath else "") + f"@{sha}"
    return ModuleLocation(f"repos/{owner}/{repo}", sha, path, identity)


def location_identity(base: str, sha: str, config_path: str) -> str:
    """Build a canonical module identity for an in-repository config path."""
    repository = base.removeprefix("repos/")
    subpath = posixpath.dirname(config_path)
    suffix = "" if subpath in {"", "."} else f"/{subpath}"
    return f"github.com/{repository}{suffix}@{sha}"


def is_policy_source(entry: TreeEntry) -> bool:
    """Return whether one blob is executable policy source."""
    authored = any((is_workflow_path(entry.path), is_module_path(entry.path)))
    return entry.type == "blob" and authored


def is_workflow_path(path: str) -> bool:
    """Return whether one path is an authored GitHub workflow."""
    return path.startswith(WORKFLOW_PREFIX) and path.endswith((".yml", ".yaml"))


def is_module_path(path: str) -> bool:
    """Return whether one path is an authored Dagger module source."""
    module_root = any(path.startswith(prefix) for prefix in MODULE_PREFIXES)
    return module_root and path.endswith((".py", ".ts"))


def read_source(transport: GitHubTransport, base: str, sha: str, path: str) -> SourceFile:
    """Decode one exact-commit GitHub contents response."""
    payload = read_model(transport, f"{base}/contents/{path}?ref={sha}", ContentPayload)
    return decode_source(payload, path, base)


def parse_content_response(response: HttpResponse, path: str) -> ContentPayload:
    """Validate one already-read contents response."""
    if response.status != HTTP_OK:
        raise access_error(path, response.status)
    try:
        return TypeAdapter(ContentPayload).validate_json(response.body)
    except ValidationError as error:
        raise FleetAccessError(f"invalid authoritative response for {path}: {error}") from error


def decode_source(payload: ContentPayload, path: str, base: str) -> SourceFile:
    """Decode and identity-check one base64 GitHub contents payload."""
    if payload.type != "file" or payload.encoding != "base64" or payload.path != path:
        raise FleetAccessError(f"invalid exact source identity for {base}/{path}")
    try:
        encoded = "".join(payload.content.splitlines())
        text = base64.b64decode(encoded, validate=True).decode()
    except (ValueError, UnicodeDecodeError) as error:
        raise FleetAccessError(f"invalid exact source bytes for {base}/{path}") from error
    return SourceFile(path=path, text=text)


def read_protection(transport: GitHubTransport, base: str) -> Protection:
    """Translate effective REST protection without losing app identity."""
    payload = read_model(transport, f"{base}/branches/main/protection", ProtectionPayload)
    checks = build_required_checks(payload.required_status_checks.checks)
    return Protection(
        strict=payload.required_status_checks.strict,
        enforce_admins=payload.enforce_admins.enabled,
        approvals=payload.required_pull_request_reviews.required_approving_review_count,
        conversation_resolution=payload.required_conversation_resolution.enabled,
        linear_history=payload.required_linear_history.enabled,
        allow_force_pushes=payload.allow_force_pushes.enabled,
        allow_deletions=payload.allow_deletions.enabled,
        checks=checks,
    )


def build_required_checks(checks: tuple[RequiredCheckPayload, ...]) -> tuple[RequiredCheck, ...]:
    """Translate strict external app identities into immutable domain checks."""
    return tuple(RequiredCheck(item.context, item.app_id) for item in checks)


def read_checks(transport: GitHubTransport, base: str, sha: str) -> CheckRunsPayload:
    """Read one complete exact-main check-run page."""
    path = f"{base}/commits/{sha}/check-runs?per_page=100"
    payload = read_model(transport, path, CheckRunsPayload)
    if payload.total_count != len(payload.check_runs):
        raise FleetAccessError(f"incomplete authoritative check runs for {base}@{sha}")
    return payload


def read_environments(transport: GitHubTransport, base: str) -> tuple[DeploymentEnvironment, ...]:
    """Read every environment, branch policy, and secret name."""
    path = f"{base}/environments?per_page=100"
    payload = read_complete_page(transport, path, EnvironmentsPayload, "environments")
    return tuple(read_environment(transport, base, item) for item in payload.environments)


def read_environment(
    transport: GitHubTransport, base: str, payload: EnvironmentPayload
) -> DeploymentEnvironment:
    """Read one environment's name-only policy evidence."""
    encoded = quote(payload.name, safe="")
    branch_names = read_branch_names(transport, base, encoded, payload)
    secret_path = f"{base}/environments/{encoded}/secrets?per_page=100"
    secret_names = read_secret_names(transport, secret_path)
    policy = payload.deployment_branch_policy
    protected = False if policy is None else policy.protected_branches
    custom = False if policy is None else policy.custom_branch_policies
    return DeploymentEnvironment(payload.name, protected, custom, branch_names, secret_names)


def read_branch_names(
    transport: GitHubTransport, base: str, name: str, environment: EnvironmentPayload
) -> tuple[str, ...]:
    """Read custom deployment branches only when GitHub enables them."""
    policy = environment.deployment_branch_policy
    if policy is None or not policy.custom_branch_policies:
        return ()
    path = f"{base}/environments/{name}/deployment-branch-policies?per_page=100"
    payload = read_complete_page(transport, path, BranchPoliciesPayload, "branch_policies")
    return tuple(item.name for item in payload.branch_policies if item.type == "branch")


def read_secret_names(transport: GitHubTransport, path: str) -> tuple[str, ...]:
    """Read only secret names and prove the page is complete."""
    payload = read_complete_page(transport, path, SecretsPayload, "secrets")
    return tuple(sorted(item.name for item in payload.secrets))


def read_complete_page[T: CompletePage](
    transport: GitHubTransport, path: str, model: type[T], collection: str
) -> T:
    """Read one bounded page and fail when GitHub reports omitted entries."""
    payload = read_model(transport, path, model)
    total = payload.total_count
    items = cast(tuple[object, ...], getattr(payload, collection))
    if total != len(items):
        raise FleetAccessError(f"incomplete authoritative page for {path}")
    return payload


def build_snapshot(parts: SnapshotParts) -> RepositorySnapshot:
    """Assemble validated API evidence into the domain snapshot."""
    workflows = select_sources(parts.evidence.sources, WORKFLOW_PREFIX)
    modules = select_modules(parts.evidence.sources)
    runs = build_check_runs(parts.checks)
    apps = build_check_apps(parts.checks)
    references = legacy_references(workflows)
    projection = SnapshotProjection(workflows, modules, runs, apps, references)
    return create_snapshot(parts, projection)


def create_snapshot(parts: SnapshotParts, projection: SnapshotProjection) -> RepositorySnapshot:
    """Create the final typed domain snapshot from grouped evidence."""
    evidence = parts.evidence
    builder = snapshot_base(evidence, projection)
    builder = snapshot_controlled(builder, parts, projection)
    return builder(
        legacy_references=projection.legacy_references,
        dagger_configs=evidence.configs,
        missing_dagger_configs=evidence.missing,
        environments=parts.environments,
        repository_secret_names=parts.repository_secrets,
        pin_ancestry=evidence.ancestry,
    )


def snapshot_base(
    evidence: SourceEvidence, projection: SnapshotProjection
) -> partial[RepositorySnapshot]:
    """Bind exact source evidence to a typed snapshot constructor."""
    return partial(
        RepositorySnapshot,
        name=evidence.name,
        sha=evidence.sha,
        workflows=projection.workflows,
        modules=projection.modules,
    )


def snapshot_controlled(
    builder: partial[RepositorySnapshot],
    parts: SnapshotParts,
    projection: SnapshotProjection,
) -> partial[RepositorySnapshot]:
    """Bind protection and exact-main integration evidence."""
    return partial(
        builder,
        protection=parts.protection,
        check_runs=projection.runs,
        check_apps=projection.apps,
        codeql_default_state=parts.codeql.state,
    )


def select_sources(sources: tuple[SourceFile, ...], prefix: str) -> tuple[SourceFile, ...]:
    """Select one reviewed source family from exact-main bytes."""
    return tuple(item for item in sources if item.path.startswith(prefix))


def select_modules(sources: tuple[SourceFile, ...]) -> tuple[SourceFile, ...]:
    """Select authored module sources from either Dagger SDK layout."""
    return tuple(
        item for item in sources if any(item.path.startswith(prefix) for prefix in MODULE_PREFIXES)
    )


def build_check_runs(checks: CheckRunsPayload) -> tuple[CheckRun, ...]:
    """Translate only concluded checks into greenable domain evidence."""
    return tuple(to_check_run(item) for item in checks.check_runs if item.conclusion is not None)


def build_check_apps(checks: CheckRunsPayload) -> tuple[str, ...]:
    """Return the distinct check applications observed on exact main."""
    return tuple(sorted({item.app.slug for item in checks.check_runs}))


def to_check_run(payload: CheckPayload) -> CheckRun:
    """Preserve app and exact-commit identity for one check run."""
    if payload.conclusion is None:
        raise ValueError("an in-progress check cannot become domain evidence")
    return CheckRun(
        name=payload.name,
        app_id=payload.app.id,
        head_sha=payload.head_sha,
        conclusion=payload.conclusion,
    )


def legacy_references(workflows: tuple[SourceFile, ...]) -> tuple[str, ...]:
    """Locate live execution references to the retiring central controls."""
    return tuple(source.path for source in workflows if "uses: hseshadr/ci/" in source.text)
