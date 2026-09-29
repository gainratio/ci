"""Typed behavioral policy for the seven Dagger consumer repositories."""

from __future__ import annotations

import ast
import json
import posixpath
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from itertools import chain
from types import MappingProxyType
from typing import Final, TypeIs

import tree_sitter_typescript as ts_typescript
import yaml
from pydantic import ConfigDict, Field, TypeAdapter, ValidationError
from pydantic.dataclasses import dataclass as validated_dataclass
from tree_sitter import Language, Node, Parser

PINNED_ACTION: Final = re.compile(r"^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$")
REMOTE_MODULE_SHAPE: Final = re.compile(
    r"^github\.com/(?P<owner>[^/]+)/(?P<repo>[^/@]+)"
    r"(?:/(?P<subpath>[^@]*))?@(?P<sha>[0-9a-f]{40})$"
)
RAW_PINNED_REMOTE: Final = re.compile(r"^github\.com/.+@[0-9a-f]{40}$")
GITHUB_OWNER: Final = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
GITHUB_REPOSITORY: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
GITHUB_PATH_SEGMENT: Final = re.compile(r"[A-Za-z0-9._-]+")
REMOTE_LIKE: Final = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|[^/]+\.[^/]+/)|@")
PROVIDER_REMOTE: Final = re.compile(
    r"^github\.com/hseshadr/ci/modules/cloudflare-pages@[0-9a-f]{40}$"
)
SENSITIVE_ARGUMENT: Final = re.compile(
    r"(?:token|secret|password|private_key|api_key|signing_key|oidc_url)$"
)
CHECKOUT: Final = "actions/checkout"
DAGGER_ACTION: Final = "dagger/dagger-for-github"
UPLOAD_ACTION: Final = "actions/upload-artifact"
DOWNLOAD_ACTION: Final = "actions/download-artifact"
PYPI_ACTION: Final = "pypa/gh-action-pypi-publish"
APP_ID: Final = 15368
ENGINE_VERSION: Final = "v0.21.8"
ACTION_VERSION: Final = "0.21.8"
COMPATIBLE_DAGGER_ACTIONS: Final = frozenset(
    (
        "496f1b3d8b0d823834c13e67cf8a8e08ca3b9602",
        "27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77",
    )
)
PRODUCTION_SECRETS: Final = frozenset(
    (
        "BUNDLE_PRIVATE_KEY_B64",
        "BUNDLE_PUBLIC_KEY_B64",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_API_TOKEN",
        "WATCHLIST_SIGNING_KEY",
    )
)
ARBITRARY_COMMAND_ARGUMENTS: Final = frozenset(
    (
        "arguments",
        "argv",
        "cmd",
        "command",
        "commands",
        "executable",
        "program",
        "script",
        "shell",
    )
)
PROCESS_CAPABILITIES: Final = frozenset(
    ("exec", "execute", "invoke", "launch", "process", "run", "spawn")
)
TYPESCRIPT_DAGGER_FUNCTION: Final = re.compile(
    r"@(?:func|function)\s*\([^)]*\)\s*(?:async\s+)?"
    r"(?P<name>\w+)\s*\((?P<arguments>[^)]*)\)"
)
TYPESCRIPT_ASSIGNMENT: Final = re.compile(
    r"(?:\b(?:const|let|var)\s+)?"
    r"(?P<target>\[[^\]]+\]|[A-Za-z_$][\w$]*)\s*(?::[^=;\n]+)?=\s*(?P<value>[^;\n]+)"
)
TYPESCRIPT_EXECUTION_SINK: Final = re.compile(
    r"\b(?:withExec|withEntrypoint|exec|execute|run|spawn)\s*\("
)
TYPESCRIPT_IDENTIFIER: Final = re.compile(r"[A-Za-z_$][\w$]*")
TYPESCRIPT_INERT_NODES: Final = frozenset(("comment", "regex", "string"))
TYPESCRIPT_LANGUAGE: Final = Language(ts_typescript.language_typescript())
ALIAS_FLOW_PASSES: Final = 4
SHARED_MODULES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "cloudflare-pages": "github.com/hseshadr/ci/modules/cloudflare-pages@",
        "foundation": "github.com/hseshadr/ci/modules/portfolio-foundation@",
        "portfolio-foundation": "github.com/hseshadr/ci/modules/portfolio-foundation@",
        "python-package": "github.com/hseshadr/ci/modules/python-package@",
    }
)
SECRET_REFERENCE: Final = re.compile(
    r"secrets(?:\.([A-Z][A-Z0-9_]*)|\s*\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\])",
    re.IGNORECASE,
)
DYNAMIC_SECRET_REFERENCE: Final = re.compile(r"secrets\s*\[\s*(?!['\"])")
# Oldest hseshadr/ci commit each central module may be pinned at. Raise a floor in the same PR
# that ships a fix every consumer must run. cloudflare-pages and python-package embed
# portfolio-foundation at their own revision, so the foundation floor covers them too.
REQUIRED_MINIMUM: Final[Mapping[str, str]] = MappingProxyType(
    {"portfolio-foundation": "dd19871486588b1582e432b7bc1f2cfffb296340"}
)
DESCENDANT_STATUSES: Final = frozenset(("ahead", "identical"))
APPROVED_PUBLISHER_MODULES: Final = frozenset(("github.com/hseshadr/ci/modules/npm-publisher",))
# dagger-for-github pastes every `with:` input except `module` (passed as INPUT_MODULE env)
# into bash, so a caller-controlled expression there is script injection (#49).
ATTACKER_EXPRESSION: Final = re.compile(
    r"\$\{\{(?:(?!\}\}).)*?(?<![\w.])"
    r"(?:inputs\b|github\s*(?:\.\s*|\[\s*['\"])(?:event|head_ref)\b)",
    re.IGNORECASE | re.DOTALL,
)
# The central, literal-SHA-pinned lineage proof a publisher runs before it trusts a
# candidate (#49). Exact text: a hard-coded run id or SHA would prove a different run.
LINEAGE_MODULE: Final = re.compile(
    r"^github\.com/hseshadr/ci/modules/portfolio-foundation@[0-9a-f]{40}$"
)
LINEAGE_MODULE_PREFIX: Final = "github.com/hseshadr/ci/modules/portfolio-foundation@"
LINEAGE_ARGUMENTS: Final = (
    '--github-token=env:GH_TOKEN --repository="$GITHUB_REPOSITORY" --run-id="$RUN_ID" '
    '--head-sha="$HEAD_SHA" --publish-run-id="$GITHUB_RUN_ID"'
)
LINEAGE_CALLS: Final = frozenset(
    (
        f"release-lineage {LINEAGE_ARGUMENTS}",
        f"release-provenance {LINEAGE_ARGUMENTS} export --path=github-context.json",
    )
)
LINEAGE_ENV: Final[Mapping[str, str]] = MappingProxyType(
    {
        "GH_TOKEN": "${{ github.token }}",
        "RUN_ID": "${{ github.event.workflow_run.id }}",
        "HEAD_SHA": "${{ github.event.workflow_run.head_sha }}",
    }
)
type Scalar = str | bool | int
type RemoteIdentity = tuple[str, str, str, str]
type ByteRange = tuple[int, int]
BOUNDARY_CONFIG: Final = ConfigDict(frozen=True, extra="forbid")
LOCK_CONFIG: Final = ConfigDict(frozen=True, extra="ignore", strict=True)


@validated_dataclass(config=BOUNDARY_CONFIG)
class SourceFile:
    """One exact-main source file returned by GitHub."""

    path: str
    text: str


@dataclass(frozen=True)
class TypeScriptDocument:
    """One grammar-parsed position-preserving TypeScript code view."""

    code: str
    valid: bool


@validated_dataclass(config=BOUNDARY_CONFIG)
class RequiredCheck:
    """One app-bound required status check."""

    context: str
    app_id: int


@validated_dataclass(config=BOUNDARY_CONFIG)
class CheckRun:
    """One exact-commit integration result."""

    name: str
    app_id: int
    head_sha: str
    conclusion: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class Protection:
    """Effective classic branch protection returned by GitHub."""

    strict: bool
    enforce_admins: bool
    approvals: int
    conversation_resolution: bool
    linear_history: bool
    allow_force_pushes: bool
    allow_deletions: bool
    checks: tuple[RequiredCheck, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class DaggerDependency:
    """One declared direct Dagger module dependency."""

    name: str
    source: str
    pin: str | None = None


@validated_dataclass(config=BOUNDARY_CONFIG)
class DaggerConfig:
    """One recursively resolved Dagger module configuration."""

    identity: str
    path: str
    name: str
    engine_version: str
    dependencies: tuple[DaggerDependency, ...] = Field(default_factory=tuple)
    sdk: str | None = None
    source: str | None = None
    generated_lock: SourceFile | None = None


@dataclass(frozen=True)
class LocalDependencyRule:
    """One exact same-tree edge in the central shared-module repository."""

    parent_path: str
    parent_name: str
    dependency_name: str
    source: str
    target_path: str
    target_name: str


CENTRAL_LOCAL_DEPENDENCIES: Final[tuple[LocalDependencyRule, ...]] = (
    LocalDependencyRule(
        "dagger.json",
        "ci",
        "foundation",
        "modules/portfolio-foundation",
        "modules/portfolio-foundation/dagger.json",
        "portfolio-foundation",
    ),
    LocalDependencyRule(
        "dagger.json",
        "ci",
        "python-package",
        "modules/python-package",
        "modules/python-package/dagger.json",
        "python-package",
    ),
    LocalDependencyRule(
        "dagger.json",
        "ci",
        "cloudflare-pages",
        "modules/cloudflare-pages",
        "modules/cloudflare-pages/dagger.json",
        "cloudflare-pages",
    ),
    LocalDependencyRule(
        "modules/python-package/dagger.json",
        "python-package",
        "foundation",
        "../portfolio-foundation",
        "modules/portfolio-foundation/dagger.json",
        "portfolio-foundation",
    ),
    LocalDependencyRule(
        "modules/cloudflare-pages/dagger.json",
        "cloudflare-pages",
        "foundation",
        "../portfolio-foundation",
        "modules/portfolio-foundation/dagger.json",
        "portfolio-foundation",
    ),
)


@validated_dataclass(config=LOCK_CONFIG)
class PythonLockSource:
    """Policy-relevant source identity from one uv lock package."""

    editable: str | None = None


@validated_dataclass(config=LOCK_CONFIG)
class PythonLockPackage:
    """Policy-relevant package identity from a generated uv lock."""

    name: str
    source: PythonLockSource | None = None


@validated_dataclass(config=LOCK_CONFIG)
class PythonLockPayload:
    """The strict generated uv lock vocabulary needed by fleet policy."""

    version: int
    package: tuple[PythonLockPackage, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class DeploymentEnvironment:
    """Name-only GitHub deployment environment evidence."""

    name: str
    protected_branches: bool
    custom_branch_policies: bool
    branch_names: tuple[str, ...]
    secret_names: tuple[str, ...]


@validated_dataclass(config=BOUNDARY_CONFIG)
class RepositoryExpectation:
    """The reviewed protection contract for one fleet member."""

    name: str
    required_contexts: tuple[str, ...]
    linear_history: bool
    conversation_resolution: bool
    shared_foundation_required: bool = False
    grandfathered_until: date | None = None


@validated_dataclass(config=BOUNDARY_CONFIG)
class PinAncestry:
    """GitHub compare evidence for one central module pin.

    ``floor_status`` is ``compare/<floor>...<pin>`` and ``main_status`` is
    ``compare/<pin>...main``; ``unrelated`` records a compare without a common ancestor.
    """

    floor: str
    pin: str
    floor_status: str
    main_status: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class RepositorySnapshot:
    """All authoritative source, protection, and integration evidence."""

    name: str
    sha: str
    workflows: tuple[SourceFile, ...]
    modules: tuple[SourceFile, ...]
    protection: Protection
    check_runs: tuple[CheckRun, ...]
    check_apps: tuple[str, ...]
    codeql_default_state: str
    legacy_references: tuple[str, ...]
    dagger_configs: tuple[DaggerConfig, ...] = Field(default_factory=tuple)
    missing_dagger_configs: tuple[str, ...] = Field(default_factory=tuple)
    environments: tuple[DeploymentEnvironment, ...] = Field(default_factory=tuple)
    repository_secret_names: tuple[str, ...] = Field(default_factory=tuple)
    pin_ancestry: tuple[PinAncestry, ...] = Field(default_factory=tuple)


@dataclass(frozen=True)
class PolicyFinding:
    """One actionable failure with a stable machine-readable code."""

    code: str
    path: str
    message: str


@validated_dataclass(config=BOUNDARY_CONFIG)
class WorkflowStep:
    """The complete step vocabulary accepted by the fleet policy."""

    name: str | None = None
    id: str | None = None
    if_: str | None = Field(default=None, alias="if")
    uses: str | None = None
    run: str | None = None
    with_: dict[str, Scalar] = Field(default_factory=dict, alias="with")
    env: dict[str, Scalar] = Field(default_factory=dict)
    shell: str | None = None
    working_directory: str | None = Field(default=None, alias="working-directory")
    continue_on_error: str | None = Field(default=None, alias="continue-on-error")
    timeout_minutes: Scalar | None = Field(default=None, alias="timeout-minutes")


@validated_dataclass(config=BOUNDARY_CONFIG)
class WorkflowJob:
    """The complete job vocabulary accepted by thin fleet workflows."""

    steps: tuple[WorkflowStep, ...]
    name: str | None = None
    if_: str | None = Field(default=None, alias="if")
    runs_on: str | None = Field(default=None, alias="runs-on")
    timeout_minutes: Scalar | None = Field(default=None, alias="timeout-minutes")
    permissions: dict[str, Scalar] = Field(default_factory=dict)
    environment: str | None = None
    needs: str | list[str] | None = None
    outputs: dict[str, Scalar] = Field(default_factory=dict)
    concurrency: object | None = None


@validated_dataclass(config=BOUNDARY_CONFIG)
class WorkflowDocument:
    """The root vocabulary for repository-authored workflows."""

    name: str
    jobs: dict[str, WorkflowJob]
    on_: object = Field(alias="on")
    permissions: dict[str, Scalar] = Field(default_factory=dict)
    concurrency: object | None = None


def finding(code: str, path: str, message: str) -> PolicyFinding:
    """Build one immutable policy finding."""
    return PolicyFinding(code=code, path=path, message=message)


def action_name(step: WorkflowStep) -> str:
    """Return an action reference without its immutable revision."""
    return "" if step.uses is None else step.uses.partition("@")[0]


def scalar_text(value: Scalar | None) -> str:
    """Normalize a validated YAML scalar for exact policy comparison."""
    if isinstance(value, bool):
        return str(value).lower()
    return "" if value is None else str(value)


def parse_workflow(source: SourceFile) -> WorkflowDocument | PolicyFinding:
    """Parse and validate one complete workflow document."""
    try:
        document = normalize_on_key(yaml.safe_load(source.text))
        return TypeAdapter(WorkflowDocument).validate_python(document)
    except (yaml.YAMLError, ValidationError) as error:
        return finding("workflow-schema", source.path, str(error))


def normalize_on_key(document: object) -> object:
    """Restore GitHub's `on` key after YAML 1.1 boolean decoding."""
    if not isinstance(document, dict) or True not in document:
        return document
    document["on"] = document.pop(True)
    return document


def validate_repository(
    snapshot: RepositorySnapshot, expectation: RepositoryExpectation
) -> tuple[PolicyFinding, ...]:
    """Validate source, protection, and exact-main integration as one contract."""
    engine = root_engine(snapshot.dagger_configs) or ENGINE_VERSION
    findings = list(validate_workflows(snapshot, engine))
    findings.extend(validate_modules(snapshot.modules))
    findings.extend(validate_dagger_graph(snapshot, expectation))
    findings.extend(validate_production_boundaries(snapshot))
    findings.extend(validate_protection(snapshot, expectation))
    findings.extend(validate_control_plane(snapshot))
    findings.extend(validate_legacy(snapshot))
    return tuple(findings)


def validate_workflows(snapshot: RepositorySnapshot, engine: str) -> tuple[PolicyFinding, ...]:
    """Validate every exact-main workflow in repository identity context."""
    return tuple(
        item
        for source in snapshot.workflows
        for item in validate_workflow(source, engine, snapshot.name)
    )


def root_engine(configs: tuple[DaggerConfig, ...]) -> str | None:
    """Return the exact root module engine when its config was resolved."""
    root = next((item for item in configs if item.path == "dagger.json"), None)
    return None if root is None else root.engine_version


def validate_dagger_graph(
    snapshot: RepositorySnapshot, expectation: RepositoryExpectation
) -> tuple[PolicyFinding, ...]:
    """Validate immutable dependency, publisher, engine, and graph identity."""
    findings = list(validate_config_dependencies(snapshot.dagger_configs))
    findings.extend(validate_missing_configs(snapshot.missing_dagger_configs))
    findings.extend(validate_config_engines(snapshot.dagger_configs))
    findings.extend(validate_generated_locks(snapshot.dagger_configs))
    if graph_has_cycle(snapshot.dagger_configs):
        findings.append(finding("dagger-dependency-cycle", "dagger.json", "dependency cycle"))
    findings.extend(validate_shared_requirement(snapshot.dagger_configs, expectation))
    findings.extend(validate_minimum_pins(snapshot.dagger_configs, snapshot.pin_ancestry))
    return tuple(findings)


def validate_config_dependencies(
    configs: tuple[DaggerConfig, ...],
) -> tuple[PolicyFinding, ...]:
    """Require immutable remotes and approved shared-module publishers."""
    return tuple(
        item
        for config in configs
        for dependency in config.dependencies
        for item in validate_dependency(config, dependency, configs)
    )


def validate_dependency(
    config: DaggerConfig,
    dependency: DaggerDependency,
    configs: tuple[DaggerConfig, ...],
) -> tuple[PolicyFinding, ...]:
    """Validate one direct dependency without conflating consumer identity."""
    findings = list(validate_dependency_source(config, dependency, configs))
    findings.extend(validate_dependency_pin(config.path, dependency))
    expected = SHARED_MODULES.get(dependency.name)
    if expected is not None and not shared_publisher_is_valid(
        config, dependency, configs, expected
    ):
        findings.append(finding("shared-module-publisher", config.path, dependency.source))
    return tuple(findings)


def validate_dependency_pin(path: str, dependency: DaggerDependency) -> tuple[PolicyFinding, ...]:
    """Require Dagger's generated pin to repeat an exact remote revision."""
    remote = parse_pinned_remote(dependency.source)
    if remote is None:
        return ()
    if dependency.pin is None:
        return (finding("missing-generated-pin", path, dependency.source),)
    if dependency.pin != remote[3]:
        return (finding("invalid-generated-pin", path, dependency.pin),)
    return ()


def validate_dependency_source(
    config: DaggerConfig,
    dependency: DaggerDependency,
    configs: tuple[DaggerConfig, ...],
) -> tuple[PolicyFinding, ...]:
    """Classify mutable GitHub refs separately from unsupported dependency syntax."""
    source = dependency.source
    if source.startswith("github.com/") and RAW_PINNED_REMOTE.fullmatch(source) is None:
        return (finding("mutable-dagger-dependency", config.path, source),)
    if parse_pinned_remote(source) is not None:
        return ()
    if local_dependency_is_valid(config, dependency, configs):
        return ()
    return (finding("invalid-dagger-dependency", config.path, source),)


def shared_publisher_is_valid(
    config: DaggerConfig,
    dependency: DaggerDependency,
    configs: tuple[DaggerConfig, ...],
    expected: str,
) -> bool:
    """Allow exact consumers and local edges inside the exact central module tree."""
    if dependency.source.startswith(expected):
        return True
    return local_dependency_is_valid(config, dependency, configs)


def local_dependency_is_valid(
    config: DaggerConfig, dependency: DaggerDependency, configs: tuple[DaggerConfig, ...]
) -> bool:
    """Accept one reviewed central edge only when both configs share a revision."""
    rule = matching_local_rule(config, dependency)
    revision = central_config_revision(config)
    if rule is None or revision is None:
        return False
    target = next((item for item in configs if item.path == rule.target_path), None)
    return target_matches_rule(target, rule, revision)


def matching_local_rule(
    config: DaggerConfig, dependency: DaggerDependency
) -> LocalDependencyRule | None:
    """Select an exact parent, dependency name, and raw local source tuple."""
    return next(
        (
            rule
            for rule in CENTRAL_LOCAL_DEPENDENCIES
            if local_rule_matches(rule, config, dependency)
        ),
        None,
    )


def local_rule_matches(
    rule: LocalDependencyRule, config: DaggerConfig, dependency: DaggerDependency
) -> bool:
    """Compare one edge without normalizing aliases into approved paths."""
    parent = config.path == rule.parent_path and config.name == rule.parent_name
    child = dependency.name == rule.dependency_name and dependency.source == rule.source
    return parent and child


def central_config_revision(config: DaggerConfig) -> str | None:
    """Return the revision only for an exact hseshadr/ci config identity."""
    remote = parse_pinned_remote(config.identity)
    if remote is None or remote[:2] != ("hseshadr", "ci"):
        return None
    expected = central_config_identity(config.path, remote[3])
    return remote[3] if config.identity == expected else None


def central_config_identity(config_path: str, revision: str) -> str:
    """Build the sole central identity for an exact config path and revision."""
    subpath = posixpath.dirname(config_path)
    suffix = "" if subpath in {"", "."} else f"/{subpath}"
    return f"github.com/hseshadr/ci{suffix}@{revision}"


def target_matches_rule(
    target: DaggerConfig | None, rule: LocalDependencyRule, revision: str
) -> bool:
    """Bind loaded target path, name, and identity to the parent's revision."""
    if target is None or target.name != rule.target_name:
        return False
    expected = central_config_identity(rule.target_path, revision)
    return target.identity == expected


def parse_pinned_remote(source: str) -> RemoteIdentity | None:
    """Parse one byte-for-byte canonical GitHub module identity."""
    match = REMOTE_MODULE_SHAPE.fullmatch(source)
    if match is None:
        return None
    remote = remote_identity_parts(match)
    return remote if canonical_remote_text(remote) == source else None


def remote_identity_parts(match: re.Match[str]) -> RemoteIdentity:
    """Validate canonical repository and module-path components."""
    owner, repo, sha = (match.group(name) for name in ("owner", "repo", "sha"))
    subpath = match.group("subpath") or ""
    if not canonical_repository(owner, repo) or not canonical_subpath(subpath):
        return ("", "", "", "")
    return owner, repo, subpath, sha


def canonical_repository(owner: str, repo: str) -> bool:
    """Apply the reviewed GitHub owner and repository component rules."""
    owner_valid = GITHUB_OWNER.fullmatch(owner) is not None
    repo_valid = GITHUB_REPOSITORY.fullmatch(repo) is not None and not repo.endswith(".git")
    return owner_valid and repo_valid


def canonical_subpath(subpath: str) -> bool:
    """Reject empty, traversal, encoded, and alternate-separator path segments."""
    if not subpath:
        return True
    segments = subpath.split("/")
    return all(canonical_path_segment(item) for item in segments)


def canonical_path_segment(segment: str) -> bool:
    """Recognize one byte-stable GitHub module path segment."""
    return segment not in {"", ".", ".."} and GITHUB_PATH_SEGMENT.fullmatch(segment) is not None


def canonical_remote_text(remote: RemoteIdentity) -> str:
    """Render one validated remote identity for raw/canonical comparison."""
    owner, repo, subpath, sha = remote
    suffix = f"/{subpath}" if subpath else ""
    return f"github.com/{owner}/{repo}{suffix}@{sha}"


def validate_missing_configs(missing: tuple[str, ...]) -> tuple[PolicyFinding, ...]:
    """Report every exact dependency whose config could not be read."""
    return tuple(
        finding("missing-dagger-config", item, "dagger.json unavailable") for item in missing
    )


def validate_config_engines(configs: tuple[DaggerConfig, ...]) -> tuple[PolicyFinding, ...]:
    """Require one compatible engine across the complete graph."""
    return tuple(
        finding("incompatible-dagger-engine", item.path, item.engine_version)
        for item in configs
        if item.engine_version != ENGINE_VERSION
    )


def validate_generated_locks(configs: tuple[DaggerConfig, ...]) -> tuple[PolicyFinding, ...]:
    """Validate every configured language SDK's exact committed generated lock."""
    return tuple(
        item
        for config in configs
        if config.sdk is not None
        for item in validate_generated_lock(config)
    )


def validate_generated_lock(config: DaggerConfig) -> tuple[PolicyFinding, ...]:
    """Validate a present authoritative language lock without inventing one."""
    expected = expected_lock_path(config)
    if expected is None:
        return (finding("unsupported-dagger-sdk", config.path, config.sdk or "missing"),)
    if config.generated_lock is None:
        return ()
    if generated_lock_is_invalid(config, expected):
        return (finding("invalid-generated-lock", expected, "generated SDK lock is stale"),)
    return ()


def generated_lock_is_invalid(config: DaggerConfig, expected: str) -> bool:
    """Return whether present generated metadata has wrong identity or semantics."""
    lock = config.generated_lock
    return lock is None or lock.path != expected or not generated_lock_is_valid(config)


def expected_lock_path(config: DaggerConfig) -> str | None:
    """Return the reviewed generated language lock location for one module."""
    filename = {"python": "uv.lock", "typescript": "yarn.lock"}.get(config.sdk or "")
    if filename is None:
        return None
    root = posixpath.dirname(config.path)
    return posixpath.normpath(posixpath.join(root, config.source or ".", filename))


def generated_lock_is_valid(config: DaggerConfig) -> bool:
    """Dispatch generated lock semantics by configured SDK language."""
    lock = config.generated_lock
    if lock is None:
        return False
    if config.sdk == "python":
        return python_lock_is_valid(lock.text)
    return typescript_lock_is_valid(lock.text)


def python_lock_is_valid(source: str) -> bool:
    """Require uv lock v1 and its generated editable Dagger SDK package."""
    try:
        raw = json.dumps(tomllib.loads(source))
        payload = TypeAdapter(PythonLockPayload).validate_json(raw)
    except (tomllib.TOMLDecodeError, ValidationError):
        return False
    return payload.version == 1 and any(dagger_sdk_package(item) for item in payload.package)


def dagger_sdk_package(package: PythonLockPackage) -> bool:
    """Recognize Dagger's generated local Python SDK lock entry."""
    source = package.source
    return package.name == "dagger-io" and source is not None and source.editable == "sdk"


def typescript_lock_is_valid(source: str) -> bool:
    """Require generated Yarn v1 metadata with immutable resolution and integrity."""
    header = "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n# yarn lockfile v1"
    pinned = re.search(r'^  resolved "https://[^"#]+#[0-9a-f]{40}"$', source, re.MULTILINE)
    integrity = re.search(r"^  integrity sha512-[A-Za-z0-9+/=]+$", source, re.MULTILINE)
    return source.startswith(header) and pinned is not None and integrity is not None


def validate_shared_requirement(
    configs: tuple[DaggerConfig, ...], expectation: RepositoryExpectation
) -> tuple[PolicyFinding, ...]:
    """Require shared foundation unless one explicit rollout allowance is active."""
    if not expectation.shared_foundation_required or has_shared_foundation(configs):
        return ()
    if grandfather_is_active(expectation.grandfathered_until):
        return ()
    return (finding("missing-shared-module", expectation.name, "foundation dependency absent"),)


def has_shared_foundation(configs: tuple[DaggerConfig, ...]) -> bool:
    """Return whether the root declares the central foundation dependency."""
    root = next((item for item in configs if item.path == "dagger.json"), None)
    if root is None:
        return False
    return any(item.name in {"foundation", "portfolio-foundation"} for item in root.dependencies)


def grandfather_is_active(expiry: date | None) -> bool:
    """Keep a rollout exception active only through its explicit date."""
    return expiry is not None and expiry >= date.today()


def graph_has_cycle(configs: tuple[DaggerConfig, ...]) -> bool:
    """Return whether any recursively resolved dependency closes a cycle."""
    graph = {config.identity: dependency_targets(config, configs) for config in configs}
    return any(cycle_from(identity, graph, frozenset()) for identity in graph)


def dependency_targets(config: DaggerConfig, configs: tuple[DaggerConfig, ...]) -> tuple[str, ...]:
    """Resolve graph edges against exact remote and local config identities."""
    targets = tuple(dependency_identity(config, item, configs) for item in config.dependencies)
    return tuple(item for item in targets if item is not None)


def dependency_identity(
    config: DaggerConfig, dependency: DaggerDependency, configs: tuple[DaggerConfig, ...]
) -> str | None:
    """Resolve one dependency source to a loaded config identity."""
    if parse_pinned_remote(dependency.source) is not None:
        return dependency.source
    if dependency_is_remote(dependency.source):
        return None
    return local_dependency_identity(config, dependency, configs)


def dependency_is_remote(source: str) -> bool:
    """Return whether a source claims remote rather than repository-local identity."""
    return parse_pinned_remote(source) is not None or remote_source_is_invalid(source)


def remote_source_is_invalid(source: str) -> bool:
    """Recognize remote-like syntax outside the one supported exact form."""
    return "@" in source or REMOTE_LIKE.match(source) is not None


def local_dependency_path(config_path: str, source: str) -> str | None:
    """Resolve a local dependency only when it remains inside the repository tree."""
    if local_source_is_invalid(source):
        return None
    path = posixpath.normpath(posixpath.join(posixpath.dirname(config_path), source, "dagger.json"))
    return None if path == ".." or path.startswith("../") else path


def local_source_is_invalid(source: str) -> bool:
    """Reject empty, absolute, and remote-like syntax before path normalization."""
    if not source or source.startswith("/"):
        return True
    return remote_source_is_invalid(source)


def local_dependency_identity(
    config: DaggerConfig, dependency: DaggerDependency, configs: tuple[DaggerConfig, ...]
) -> str | None:
    """Resolve one repository-local dependency config path."""
    path = local_dependency_path(config.path, dependency.source)
    if path is None:
        return None
    return next((item.identity for item in configs if item.path == path), None)


def cycle_from(identity: str, graph: dict[str, tuple[str, ...]], ancestors: frozenset[str]) -> bool:
    """Walk one immutable dependency branch with an active-path fence."""
    if identity in ancestors:
        return True
    active = ancestors | {identity}
    return any(cycle_from(child, graph, active) for child in graph.get(identity, ()))


def validate_production_boundaries(snapshot: RepositorySnapshot) -> tuple[PolicyFinding, ...]:
    """Join secret names, workflow use, and the main-only production boundary."""
    if not provider_scope_applies(snapshot):
        return ()
    repository_names = frozenset(snapshot.repository_secret_names) & PRODUCTION_SECRETS
    jobs = production_jobs(snapshot.workflows)
    referenced = frozenset(name for _, _, names in jobs for name in names) & PRODUCTION_SECRETS
    repository = repository_secret_findings(snapshot.name, repository_names)
    jobs_findings = validate_job_environments(jobs)
    environment = validate_production_environment(snapshot, referenced)
    return repository + jobs_findings + environment


def provider_scope_applies(snapshot: RepositorySnapshot) -> bool:
    """Activate provider policy only after typed provider adoption begins."""
    return has_provider_dependency(snapshot.dagger_configs) or has_provider_ingress(
        snapshot.workflows
    )


def has_provider_dependency(configs: tuple[DaggerConfig, ...]) -> bool:
    """Return whether the root installs the approved Cloudflare provider."""
    root = next((item for item in configs if item.path == "dagger.json"), None)
    if root is None:
        return False
    return any(PROVIDER_REMOTE.fullmatch(item.source) for item in root.dependencies)


def has_provider_ingress(workflows: tuple[SourceFile, ...]) -> bool:
    """Return whether a workflow directly calls the exact shared provider module."""
    return any(provider_ingress_in_workflow(source) for source in workflows)


def provider_ingress_in_workflow(source: SourceFile) -> bool:
    """Recognize one exact remote Cloudflare provider action call."""
    document = parse_workflow(source)
    if not isinstance(document, WorkflowDocument):
        return False
    steps = tuple(step for job in document.jobs.values() for step in job.steps)
    return any(step_invokes_provider(step) for step in steps)


def step_invokes_provider(step: WorkflowStep) -> bool:
    """Recognize only an exact provider import on the reviewed Dagger action."""
    module = scalar_text(step.with_.get("module"))
    return action_name(step) == DAGGER_ACTION and PROVIDER_REMOTE.fullmatch(module) is not None


def repository_secret_findings(
    name: str, secret_names: frozenset[str]
) -> tuple[PolicyFinding, ...]:
    """Report production authority retained at repository scope."""
    return tuple(
        finding("unscoped-production-secret", name, secret) for secret in sorted(secret_names)
    )


def production_jobs(
    workflows: tuple[SourceFile, ...],
) -> tuple[tuple[str, WorkflowJob, tuple[str, ...]], ...]:
    """Return jobs that reference a known production secret name."""
    return tuple(item for source in workflows for item in production_jobs_for_workflow(source))


def production_jobs_for_workflow(
    source: SourceFile,
) -> tuple[tuple[str, WorkflowJob, tuple[str, ...]], ...]:
    """Return production-authority jobs from one valid workflow."""
    document = parse_workflow(source)
    if not isinstance(document, WorkflowDocument):
        return ()
    records = tuple(production_job_record(source.path, job) for job in document.jobs.values())
    return tuple(item for item in records if item is not None)


def production_job_record(
    path: str, job: WorkflowJob
) -> tuple[str, WorkflowJob, tuple[str, ...]] | None:
    """Build one production-authority job record when secrets are referenced."""
    names = job_secret_names(job)
    dynamic = job_has_dynamic_secret(job)
    provider = any(step_invokes_provider(step) for step in job.steps)
    if not production_authority_exists(names, dynamic, provider):
        return None
    evidence = production_authority_evidence(names, dynamic)
    return path, job, evidence


def production_authority_exists(names: tuple[str, ...], dynamic: bool, provider: bool) -> bool:
    """Return whether one job can exercise production provider authority."""
    return bool(names) or dynamic or provider


def production_authority_evidence(names: tuple[str, ...], dynamic: bool) -> tuple[str, ...]:
    """Name the evidence that made one job production-authoritative."""
    if names:
        return names
    return ("dynamic-secret",) if dynamic else ("provider-deployment",)


def job_secret_names(job: WorkflowJob) -> tuple[str, ...]:
    """Return known production secret names referenced by one job."""
    names = {
        next(item for item in match.groups() if item is not None).upper()
        for value in job_expression_values(job)
        for match in SECRET_REFERENCE.finditer(value)
    }
    return tuple(sorted(names & PRODUCTION_SECRETS))


def job_expression_values(job: WorkflowJob) -> tuple[str, ...]:
    """Return every action input and environment expression in one job."""
    return tuple(
        scalar_text(value)
        for step in job.steps
        for value in (*step.env.values(), *step.with_.values())
    )


def job_has_dynamic_secret(job: WorkflowJob) -> bool:
    """Fail closed on computed GitHub secret selection after provider adoption."""
    return any(DYNAMIC_SECRET_REFERENCE.search(value) for value in job_expression_values(job))


def validate_job_environments(
    jobs: tuple[tuple[str, WorkflowJob, tuple[str, ...]], ...],
) -> tuple[PolicyFinding, ...]:
    """Require every production-secret consumer to declare production."""
    return tuple(
        finding("unscoped-production-secret", path, ", ".join(names))
        for path, job, names in jobs
        if job.environment != "production"
    )


def validate_production_environment(
    snapshot: RepositorySnapshot, referenced: frozenset[str]
) -> tuple[PolicyFinding, ...]:
    """Require an exact main-only environment containing referenced names."""
    environment = next((item for item in snapshot.environments if item.name == "production"), None)
    if environment is None:
        return (finding("production-environment", snapshot.name, "production missing"),)
    findings = list(validate_production_branches(snapshot.name, environment))
    missing = referenced - frozenset(environment.secret_names)
    findings.extend(
        finding("missing-production-secret", snapshot.name, name) for name in sorted(missing)
    )
    return tuple(findings)


def validate_production_branches(
    name: str, environment: DeploymentEnvironment
) -> tuple[PolicyFinding, ...]:
    """Require one custom deployment branch pattern naming only main."""
    valid = all(
        (
            not environment.protected_branches,
            environment.custom_branch_policies,
            environment.branch_names == ("main",),
        )
    )
    return () if valid else (finding("production-branch-policy", name, "main only required"),)


def validate_workflow(
    source: SourceFile, engine_version: str | None = None, repository: str = ""
) -> tuple[PolicyFinding, ...]:
    """Validate every job in one real workflow."""
    parsed = parse_workflow(source)
    if isinstance(parsed, PolicyFinding):
        return (parsed,)
    engine = engine_version or ENGINE_VERSION
    findings = [
        item
        for job in parsed.jobs.values()
        for item in validate_job(source.path, job, engine, repository)
    ]
    return tuple(findings)


def validate_job(
    path: str, job: WorkflowJob, engine_version: str | None = None, repository: str = ""
) -> tuple[PolicyFinding, ...]:
    """Dispatch a job to its only accepted execution shape."""
    common = (
        validate_steps(path, job.steps)
        + validate_action_steps(path, job.steps, engine_version)
        + validate_dagger_expressions(path, job.steps)
    )
    names = tuple(map(action_name, job.steps))
    if UPLOAD_ACTION in names:
        return common + validate_candidate(path, job.steps)
    if DOWNLOAD_ACTION in names or scalar_text(job.permissions.get("id-token")) == "write":
        return common + validate_publisher(path, job, repository)
    return common + validate_ingress(path, job.steps, engine_version)


def validate_action_steps(
    path: str, steps: tuple[WorkflowStep, ...], engine_version: str | None
) -> tuple[PolicyFinding, ...]:
    """Validate every Dagger action against the config-selected engine tuple."""
    return tuple(
        item
        for step in steps
        if action_name(step) == DAGGER_ACTION
        for item in validate_action_compatibility(path, step, engine_version)
    )


def validate_steps(path: str, steps: tuple[WorkflowStep, ...]) -> tuple[PolicyFinding, ...]:
    """Reject mutable actions and shell execution in every shape."""
    findings: list[PolicyFinding] = []
    for step in steps:
        if step.uses and not PINNED_ACTION.fullmatch(step.uses):
            findings.append(finding("mutable-action", path, step.uses))
        if step.run is not None:
            findings.append(finding("shell-step", path, "run steps are forbidden"))
    return tuple(findings)


def validate_dagger_expressions(
    path: str, steps: tuple[WorkflowStep, ...]
) -> tuple[PolicyFinding, ...]:
    """Reject caller-controlled expressions in any Dagger input pasted into bash."""
    return tuple(
        finding("dagger-args-expression", path, f"{key} carries a caller-controlled expression")
        for step in steps
        if action_name(step) == DAGGER_ACTION
        for key in script_inputs_with_expressions(step)
    )


def script_inputs_with_expressions(step: WorkflowStep) -> tuple[str, ...]:
    """Return every script-pasted input that carries a caller-controlled expression."""
    return tuple(
        key
        for key, value in sorted(step.with_.items())
        if key != "module" and ATTACKER_EXPRESSION.search(scalar_text(value))
    )


def validate_ingress(
    path: str, steps: tuple[WorkflowStep, ...], engine_version: str | None = None
) -> tuple[PolicyFinding, ...]:
    """Accept exactly pinned checkout followed by a Dagger call."""
    names = tuple(map(action_name, steps))
    findings: list[PolicyFinding] = []
    if names != (CHECKOUT, DAGGER_ACTION):
        findings.append(finding("non-dagger-ingress", path, "expected checkout then Dagger"))
        return tuple(findings)
    findings.extend(validate_checkout(path, steps[0]))
    findings.extend(validate_dagger(path, steps[1], engine_version))
    findings.extend(validate_ingress_module(path, steps[1]))
    return tuple(findings)


def validate_ingress_module(path: str, step: WorkflowStep) -> tuple[PolicyFinding, ...]:
    """Allow local source or the one exact shared provider direct import."""
    module = scalar_text(step.with_.get("module"))
    if not module or PROVIDER_REMOTE.fullmatch(module):
        return ()
    code = (
        "publisher-module-identity"
        if parse_pinned_remote(module) is not None
        else "remote-module-identity"
    )
    return (finding(code, path, module),)


def validate_checkout(path: str, step: WorkflowStep) -> tuple[PolicyFinding, ...]:
    """Require checkout to leave no credential behind."""
    if scalar_text(step.with_.get("persist-credentials")) == "false":
        return ()
    return (finding("checkout-credentials", path, "persist-credentials must be false"),)


def validate_dagger(
    path: str, step: WorkflowStep, engine_version: str | None = None
) -> tuple[PolicyFinding, ...]:
    """Require the reviewed immutable Dagger call boundary."""
    findings: list[PolicyFinding] = []
    if engine_version is None and scalar_text(step.with_.get("version")) != ACTION_VERSION:
        findings.append(finding("dagger-version", path, "Dagger 0.21.8 required"))
    if not dagger_invocation_is_owned(step):
        findings.append(finding("dagger-verb", path, "Dagger call/check input required"))
    return tuple(findings)


def validate_action_compatibility(
    path: str, step: WorkflowStep, engine_version: str | None
) -> tuple[PolicyFinding, ...]:
    """Require one reviewed action revision compatible with the config engine."""
    findings: list[PolicyFinding] = []
    revision = action_revision(step)
    if not engine_action_versions_match(step, engine_version):
        findings.append(finding("incompatible-dagger-engine", path, "engine/action mismatch"))
    if revision not in COMPATIBLE_DAGGER_ACTIONS:
        findings.append(finding("incompatible-dagger-action", path, revision))
    return tuple(findings)


def action_revision(step: WorkflowStep) -> str:
    """Return the immutable action revision or no revision."""
    return "" if step.uses is None else step.uses.partition("@")[2]


def engine_action_versions_match(step: WorkflowStep, engine_version: str | None) -> bool:
    """Return whether config and action select the reviewed engine version."""
    expected = "" if engine_version is None else engine_version.removeprefix("v")
    return expected == ACTION_VERSION and scalar_text(step.with_.get("version")) == expected


def dagger_invocation_is_owned(step: WorkflowStep) -> bool:
    """Accept the action's explicit call and check invocation encodings."""
    verb = scalar_text(step.with_.get("verb"))
    call = scalar_text(step.with_.get("call"))
    check_input = scalar_text(step.with_.get("check"))
    return verb in {"call", "check"} or bool(call) or bool(check_input)


def validate_candidate(path: str, steps: tuple[WorkflowStep, ...]) -> tuple[PolicyFinding, ...]:
    """Accept only Dagger-proven candidate bytes persisted after Dagger."""
    names = tuple(map(action_name, steps))
    findings: list[PolicyFinding] = []
    if names != (CHECKOUT, DAGGER_ACTION, UPLOAD_ACTION):
        findings.append(finding("candidate-order", path, "expected checkout, Dagger, upload"))
    if steps and action_name(steps[0]) == CHECKOUT:
        findings.extend(validate_checkout(path, steps[0]))
    findings.extend(validate_candidate_module(path, steps))
    findings.extend(validate_candidate_identity(path, steps))
    return tuple(findings)


def validate_candidate_module(
    path: str, steps: tuple[WorkflowStep, ...]
) -> tuple[PolicyFinding, ...]:
    """Require candidate bytes to come from the credential-free checkout source."""
    step = next((item for item in steps if action_name(item) == DAGGER_ACTION), None)
    module = "" if step is None else scalar_text(step.with_.get("module"))
    return () if not module else (finding("candidate-module-identity", path, module),)


def validate_candidate_identity(
    path: str, steps: tuple[WorkflowStep, ...]
) -> tuple[PolicyFinding, ...]:
    """Bind the uploaded directory and name to the Dagger candidate SHA."""
    upload = next((step for step in steps if action_name(step) == UPLOAD_ACTION), None)
    if upload is None or candidate_identity_is_weak(upload):
        return (finding("artifact-identity", path, "candidate artifact is not exact"),)
    return ()


def candidate_identity_is_weak(step: WorkflowStep) -> bool:
    """Report whether an upload can persist bytes outside the exact candidate."""
    name = scalar_text(step.with_.get("name"))
    candidate_path = scalar_text(step.with_.get("path")).rstrip("/")
    return (
        "${{ github.sha }}" not in name
        or candidate_path not in {"candidate", "release"}
        or scalar_text(step.with_.get("if-no-files-found")) != "error"
        or scalar_text(step.with_.get("retention-days")) != "1"
    )


def validate_publisher(path: str, job: WorkflowJob, repository: str) -> tuple[PolicyFinding, ...]:
    """Accept only source-free artifact transport into one OIDC publisher."""
    lineage, steps = split_lineage(job.steps)
    findings: list[PolicyFinding] = []
    findings.extend(validate_publisher_permissions(path, job))
    findings.extend(validate_publisher_source(path, job.steps))
    findings.extend(() if lineage is None else validate_lineage(path, lineage))
    findings.extend(validate_download(path, steps))
    names = tuple(map(action_name, steps))
    if PYPI_ACTION in names:
        findings.extend(validate_pypi(path, steps, repository))
    else:
        findings.extend(validate_npm(path, steps, repository))
    return tuple(findings)


def split_lineage(
    steps: tuple[WorkflowStep, ...],
) -> tuple[WorkflowStep | None, tuple[WorkflowStep, ...]]:
    """Separate a leading central lineage proof from the publisher transport."""
    if steps and is_lineage_step(steps[0]):
        return steps[0], steps[1:]
    return None, steps


def is_lineage_step(step: WorkflowStep) -> bool:
    """Return whether a step loads the central lineage module."""
    module = scalar_text(step.with_.get("module"))
    return action_name(step) == DAGGER_ACTION and module.startswith(LINEAGE_MODULE_PREFIX)


def validate_lineage(path: str, step: WorkflowStep) -> tuple[PolicyFinding, ...]:
    """Require the exact literal-pinned lineage call bound to the triggering run."""
    environment = {key: scalar_text(value) for key, value in step.env.items()}
    if lineage_call_is_exact(step) and environment == LINEAGE_ENV:
        return ()
    return (finding("publisher-lineage", path, "exact central lineage call required"),)


def lineage_call_is_exact(step: WorkflowStep) -> bool:
    """Return whether the step is the literal-pinned central lineage call."""
    values = {key: scalar_text(value) for key, value in step.with_.items()}
    if set(values) != {"version", "verb", "module", "args"}:
        return False
    module = LINEAGE_MODULE.fullmatch(values["module"]) is not None
    return (values["verb"], module, values["args"] in LINEAGE_CALLS) == ("call", True, True)


def validate_publisher_permissions(path: str, job: WorkflowJob) -> tuple[PolicyFinding, ...]:
    """Limit publisher authority to artifact read and OIDC minting."""
    minimal = {"actions": "read", "id-token": "write"}
    current = {"actions": "read", "contents": "read", "id-token": "write"}
    if job.permissions in (minimal, current):
        return ()
    return (finding("publisher-permissions", path, "only read transport plus id-token:write"),)


def validate_publisher_source(
    path: str, steps: tuple[WorkflowStep, ...]
) -> tuple[PolicyFinding, ...]:
    """Reject checkout and setup actions inside a privileged bridge."""
    forbidden = (CHECKOUT, "actions/setup-", "pnpm/action-setup", "astral-sh/setup-uv")
    names = tuple(map(action_name, steps))
    if any(name == forbidden[0] or name.startswith(forbidden[1:]) for name in names):
        return (finding("privileged-source", path, "publisher must remain source-free"),)
    return ()


def validate_download(path: str, steps: tuple[WorkflowStep, ...]) -> tuple[PolicyFinding, ...]:
    """Bind downloaded bytes to the triggering candidate run and SHA."""
    download = next((step for step in steps if action_name(step) == DOWNLOAD_ACTION), None)
    if download is None or download_identity_is_weak(download):
        return (finding("artifact-identity", path, "download is not bound to candidate run"),)
    return ()


def download_identity_is_weak(step: WorkflowStep) -> bool:
    """Report whether a download can select unrelated artifact bytes."""
    values = step.with_
    return (
        "${{ github.event.workflow_run.head_sha }}" not in scalar_text(values.get("name"))
        or scalar_text(values.get("run-id")) != "${{ github.event.workflow_run.id }}"
        or scalar_text(values.get("github-token")) != "${{ github.token }}"
        or scalar_text(values.get("path")) not in {"candidate", "release"}
    )


def validate_pypi(
    path: str, steps: tuple[WorkflowStep, ...], repository: str
) -> tuple[PolicyFinding, ...]:
    """Require exact download followed by official attested PyPI publication."""
    names = tuple(map(action_name, steps))
    findings = list(validate_pypi_shape(path, names))
    pypi = next(step for step in steps if action_name(step) == PYPI_ACTION)
    findings.extend(validate_pypi_attestation(path, pypi))
    findings.extend(validate_pypi_remote(path, names, steps, repository))
    return tuple(findings)


def validate_pypi_shape(path: str, names: tuple[str, ...]) -> tuple[PolicyFinding, ...]:
    """Require one of the two reviewed source-free PyPI shapes."""
    if pypi_shape_is_allowed(names):
        return ()
    return (finding("pypi-shape", path, "expected exact source-free PyPI bridge"),)


def validate_pypi_attestation(path: str, step: WorkflowStep) -> tuple[PolicyFinding, ...]:
    """Require official PyPI attestations for every publication."""
    if scalar_text(step.with_.get("attestations")) == "true":
        return ()
    return (finding("pypi-attestation", path, "attestations must be true"),)


def validate_pypi_remote(
    path: str, names: tuple[str, ...], steps: tuple[WorkflowStep, ...], repository: str
) -> tuple[PolicyFinding, ...]:
    """Bind an optional pre-publication Dagger decision to the candidate SHA."""
    return validate_remote_dagger(path, steps, repository) if DAGGER_ACTION in names else ()


def pypi_shape_is_allowed(names: tuple[str, ...]) -> bool:
    """Accept official PyPI directly or after an exact remote Dagger decision."""
    direct = (DOWNLOAD_ACTION, PYPI_ACTION)
    planned = (DOWNLOAD_ACTION, DAGGER_ACTION, PYPI_ACTION)
    return names in (direct, planned)


def validate_npm(
    path: str, steps: tuple[WorkflowStep, ...], repository: str
) -> tuple[PolicyFinding, ...]:
    """Require exact remote Dagger npm publication with typed OIDC addresses."""
    names = tuple(map(action_name, steps))
    findings: list[PolicyFinding] = []
    if names != (DOWNLOAD_ACTION, DAGGER_ACTION):
        findings.append(finding("npm-shape", path, "expected download then remote Dagger"))
    findings.extend(validate_remote_dagger(path, steps, repository))
    if not has_typed_oidc_publisher_step(steps):
        findings.append(finding("typed-oidc", path, "typed OIDC URL and token required"))
    return tuple(findings)


def has_typed_oidc_publisher_step(steps: tuple[WorkflowStep, ...]) -> bool:
    """Return whether the only Dagger publisher receives both OIDC addresses."""
    step = next((item for item in steps if action_name(item) == DAGGER_ACTION), None)
    return False if step is None else oidc_arguments_are_typed(step)


def validate_remote_dagger(
    path: str, steps: tuple[WorkflowStep, ...], repository: str
) -> tuple[PolicyFinding, ...]:
    """Bind remote publisher code to the triggering candidate SHA."""
    module = remote_dagger_module(steps)
    if publisher_module_is_authorized(module, repository):
        return ()
    dynamic = module.endswith("@${{ github.event.workflow_run.head_sha }}")
    if parse_pinned_remote(module) is not None or dynamic:
        return (finding("publisher-module-identity", path, module),)
    return (finding("remote-module-identity", path, "remote Dagger module is not exact"),)


def remote_dagger_module(steps: tuple[WorkflowStep, ...]) -> str:
    """Return the configured module on the only Dagger publisher step."""
    step = next((item for item in steps if action_name(item) == DAGGER_ACTION), None)
    return "" if step is None else scalar_text(step.with_.get("module"))


def publisher_module_is_authorized(module: str, repository: str) -> bool:
    """Accept the consumer at the candidate or main SHA, or an approved central publisher."""
    own = (
        f"github.com/hseshadr/{repository}@${{{{ github.event.workflow_run.head_sha }}}}",
        f"github.com/hseshadr/{repository}@${{{{ github.sha }}}}",
    )
    base, separator, revision = module.rpartition("@")
    literal = separator == "@" and base in APPROVED_PUBLISHER_MODULES
    return module in own or (literal and re.fullmatch(r"[0-9a-f]{40}", revision) is not None)


def oidc_arguments_are_typed(step: WorkflowStep) -> bool:
    """Require both GitHub OIDC addresses to cross the Dagger Secret boundary."""
    arguments = scalar_text(step.with_.get("args"))
    return (
        "--oidc-url=env:ACTIONS_ID_TOKEN_REQUEST_URL" in arguments
        and "--oidc-token=env:ACTIONS_ID_TOKEN_REQUEST_TOKEN" in arguments
    )


def validate_modules(modules: tuple[SourceFile, ...]) -> tuple[PolicyFinding, ...]:
    """Require explicit source construction and typed credential arguments."""
    python, typescript = split_modules(modules)
    trees = parse_python_modules(python)
    findings = validate_module_source(trees, typescript)
    findings.extend(validate_python_secrets(trees))
    findings.extend(validate_typescript_secrets(typescript))
    findings.extend(validate_python_commands(trees))
    findings.extend(validate_typescript_commands(typescript))
    return tuple(findings)


def split_modules(
    modules: tuple[SourceFile, ...],
) -> tuple[tuple[SourceFile, ...], tuple[SourceFile, ...]]:
    """Split authored module sources by supported SDK language."""
    python = tuple(module for module in modules if module.path.endswith(".py"))
    typescript = tuple(module for module in modules if module.path.endswith(".ts"))
    return python, typescript


def parse_python_modules(
    modules: tuple[SourceFile, ...],
) -> tuple[tuple[SourceFile, ast.Module], ...]:
    """Parse every authored Python module against its exact path."""
    return tuple((module, ast.parse(module.text, filename=module.path)) for module in modules)


def validate_python_secrets(
    trees: tuple[tuple[SourceFile, ast.Module], ...],
) -> tuple[PolicyFinding, ...]:
    """Validate every credential-shaped Python argument."""
    return tuple(
        item for module, tree in trees for item in validate_secret_arguments(module.path, tree)
    )


def validate_python_commands(
    trees: tuple[tuple[SourceFile, ast.Module], ...],
) -> tuple[PolicyFinding, ...]:
    """Reject generic command arguments on Python Dagger functions."""
    return tuple(item for module, tree in trees for item in command_findings(module.path, tree))


def command_findings(path: str, tree: ast.Module) -> tuple[PolicyFinding, ...]:
    """Return arbitrary-command findings for one parsed Python module."""
    return tuple(
        finding("arbitrary-command", path, node.name)
        for node in ast.walk(tree)
        if is_dagger_function(node) and python_command_capability(node)
    )


def python_command_capability(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Detect generic process capability by schema or executable sink use."""
    arguments = function_arguments(node)
    names = frozenset(item.arg for item in arguments if item.arg not in {"self", "cls"})
    checks = (
        node.name in PROCESS_CAPABILITIES and bool(names),
        bool(names & ARBITRARY_COMMAND_ARGUMENTS),
        uses_executable_sink(node, propagated_python_names(node, names)),
    )
    return any(checks)


def propagated_python_names(
    node: ast.FunctionDef | ast.AsyncFunctionDef, names: frozenset[str]
) -> frozenset[str]:
    """Propagate caller control through a bounded number of local assignments."""
    tainted = names
    for _ in range(ALIAS_FLOW_PASSES):
        tainted |= python_aliases(node, tainted)
    return tainted


def python_aliases(node: ast.AST, tainted: frozenset[str]) -> frozenset[str]:
    """Return assignment targets whose value references caller-controlled data."""
    return frozenset(
        name for item in ast.walk(node) for name in tainted_assignment_names(item, tainted)
    )


def tainted_assignment_names(node: ast.AST, tainted: frozenset[str]) -> frozenset[str]:
    """Return local names tainted by one supported Python assignment."""
    targets, value = assignment_parts(node)
    if value is None or not assignment_value_controls_command(value, tainted):
        return frozenset()
    return assigned_names(targets)


def assignment_value_controls_command(node: ast.expr, tainted: frozenset[str]) -> bool:
    """Separate fixed list data positions from executable and spread control."""
    if isinstance(node, (ast.List, ast.Tuple)):
        return bool(command_element_names(node.elts) & tainted)
    return bool(expression_names(node) & tainted)


def assignment_parts(node: ast.AST) -> tuple[tuple[ast.expr, ...], ast.expr | None]:
    """Extract targets and value from bounded Python assignment forms."""
    if isinstance(node, ast.Assign):
        return tuple(node.targets), node.value
    if isinstance(node, ast.AnnAssign):
        return (node.target,), node.value
    if isinstance(node, ast.NamedExpr):
        return (node.target,), node.value
    return (), None


def expression_names(node: ast.expr) -> frozenset[str]:
    """Return identifiers read anywhere in one assignment expression."""
    return frozenset(item.id for item in ast.walk(node) if isinstance(item, ast.Name))


def assigned_names(targets: tuple[ast.expr, ...]) -> frozenset[str]:
    """Return simple or destructured local assignment identities."""
    return frozenset(
        item.id for target in targets for item in ast.walk(target) if isinstance(item, ast.Name)
    )


def uses_executable_sink(
    node: ast.FunctionDef | ast.AsyncFunctionDef, argument_names: frozenset[str]
) -> bool:
    """Detect caller arguments forwarded into generic execution primitives."""
    sinks = frozenset(("exec", "execute", "run", "spawn", "with_exec", "with_entrypoint"))
    return any(call_uses_arguments(item, sinks, argument_names) for item in ast.walk(node))


def call_uses_arguments(
    node: ast.AST, sinks: frozenset[str], argument_names: frozenset[str]
) -> bool:
    """Return whether one call forwards a public argument into an execution sink."""
    if not isinstance(node, ast.Call):
        return False
    return call_name(node) in sinks and bool(command_structure_names(node) & argument_names)


def call_name(node: ast.Call) -> str:
    """Return one executable call's simple function or method name."""
    return node.func.attr if isinstance(node.func, ast.Attribute) else ast.unparse(node.func)


def command_structure_names(node: ast.Call) -> frozenset[str]:
    """Return public identifiers that can control executable or command-vector structure."""
    if not node.args:
        return frozenset()
    command = node.args[0]
    if isinstance(command, (ast.List, ast.Tuple)):
        return command_element_names(command.elts)
    return expression_names(command)


def command_element_names(elements: list[ast.expr]) -> frozenset[str]:
    """Return a variable executable or splatted argument-vector identity."""
    if not elements:
        return frozenset()
    first = elements[0]
    names = {first.id} if isinstance(first, ast.Name) else set()
    names.update(filter(None, map(starred_name, elements)))
    return frozenset(names)


def starred_name(node: ast.expr) -> str | None:
    """Return a splatted public argument-vector name when present."""
    if isinstance(node, ast.Starred) and isinstance(node.value, ast.Name):
        return node.value.id
    return None


def function_arguments(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[ast.arg, ...]:
    """Return every positional and keyword argument on one function."""
    return (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)


def validate_module_source(
    trees: tuple[tuple[SourceFile, ast.Module], ...], typescript: tuple[SourceFile, ...]
) -> list[PolicyFinding]:
    """Require one explicit Directory boundary in either supported SDK language."""
    python_source = any(has_explicit_source(tree) for _, tree in trees)
    typescript_source = any(has_typescript_source(module.text) for module in typescript)
    if not any((python_source, typescript_source)):
        return [finding("explicit-source", "dagger.json", "typed source is absent")]
    return []


def parse_typescript(source: str) -> TypeScriptDocument:
    """Parse TypeScript once and return its executable position-preserving view."""
    encoded = source.encode()
    root = Parser(TYPESCRIPT_LANGUAGE).parse(encoded).root_node
    code = masked_typescript(encoded, root)
    return TypeScriptDocument(code, not root.has_error)


def masked_typescript(source: bytes, root: Node) -> str:
    """Mask grammar-classified inert syntax without changing byte offsets."""
    output = bytearray(source)
    for start, end in typescript_inert_ranges(root):
        mask_typescript_range(output, source, start, end)
    return output.decode()


def typescript_inert_ranges(node: Node) -> tuple[ByteRange, ...]:
    """Return inert syntax ranges while retaining template interpolation code."""
    if node.is_named and node.type in TYPESCRIPT_INERT_NODES:
        return (node.byte_range,)
    if node.type == "template_string":
        return template_inert_ranges(node)
    return tuple(chain.from_iterable(typescript_inert_ranges(child) for child in node.children))


def template_inert_ranges(node: Node) -> tuple[ByteRange, ...]:
    """Mask template static spans and recurse into executable substitutions."""
    substitutions = tuple(
        child for child in node.named_children if child.type == "template_substitution"
    )
    ranges: list[ByteRange] = []
    cursor = node.start_byte
    for substitution in substitutions:
        ranges.append((cursor, substitution.start_byte))
        ranges.extend(typescript_inert_ranges(substitution))
        cursor = substitution.end_byte
    return (*ranges, (cursor, node.end_byte))


def mask_typescript_range(output: bytearray, source: bytes, start: int, end: int) -> None:
    """Replace one inert syntax range with spaces while preserving newlines."""
    for index in range(start, end):
        if source[index] not in (10, 13):
            output[index] = 32


def has_typescript_source(source: str) -> bool:
    """Recognize a typed Workspace constructor assigning an explicit Directory."""
    source_field = re.search(r"\bsource\s*:\s*Directory\b", source) is not None
    workspace = re.search(r"constructor\s*\([^)]*:\s*Workspace\b", source) is not None
    directory = re.search(r"\bworkspace\.directory\s*\(", source) is not None
    return all((source_field, workspace, directory))


def validate_typescript_secrets(modules: tuple[SourceFile, ...]) -> tuple[PolicyFinding, ...]:
    """Reject credential-shaped TypeScript arguments typed as plain strings."""
    findings: list[PolicyFinding] = []
    pattern = re.compile(r"\b(?:token|secret|password|privateKey|apiKey)\??\s*:\s*string\b")
    for module in modules:
        if pattern.search(module.text):
            findings.append(finding("untyped-secret", module.path, "credential typed string"))
    return tuple(findings)


def validate_typescript_commands(modules: tuple[SourceFile, ...]) -> tuple[PolicyFinding, ...]:
    """Reject generic command arguments on TypeScript Dagger functions."""
    return tuple(
        finding("arbitrary-command", module.path, "generic command argument")
        for module in modules
        if typescript_has_command_capability(module.text)
    )


def typescript_has_command_capability(source: str) -> bool:
    """Return whether any exposed TypeScript function is a generic process API."""
    document = parse_typescript(source)
    if not document.valid:
        return True
    matches = TYPESCRIPT_DAGGER_FUNCTION.finditer(document.code)
    return any(typescript_command_capability(document.code, match) for match in matches)


def typescript_command_capability(source: str, match: re.Match[str]) -> bool:
    """Detect generic TypeScript process schema or bounded sink data flow."""
    name = match.group("name")
    arguments = typescript_arguments(match)
    schema = (name in PROCESS_CAPABILITIES and bool(arguments)) or bool(
        arguments & ARBITRARY_COMMAND_ARGUMENTS
    )
    return schema or typescript_uses_executable_sink(source, match, arguments)


def typescript_arguments(match: re.Match[str]) -> frozenset[str]:
    """Return typed public argument names from one Dagger function signature."""
    return frozenset(
        item.strip().split("?", maxsplit=1)[0]
        for item in re.findall(r"\b([A-Za-z_$][\w$]*\??)\s*:", match.group("arguments"))
    )


def typescript_uses_executable_sink(
    source: str, match: re.Match[str], arguments: frozenset[str]
) -> bool:
    """Detect caller-controlled TypeScript command structure after local aliases."""
    body = typescript_function_body(source, match.end())
    tainted = propagated_typescript_names(body, arguments)
    commands = typescript_sink_commands(body)
    return any(bool(typescript_command_names(item) & tainted) for item in commands)


def typescript_sink_commands(source: str) -> tuple[str, ...]:
    """Return balanced first arguments from TypeScript execution sinks."""
    return tuple(
        typescript_call_argument(source, match.end())
        for match in TYPESCRIPT_EXECUTION_SINK.finditer(source)
    )


def typescript_call_argument(source: str, start: int) -> str:
    """Return one call argument list without truncating nested expressions."""
    return typescript_balanced_contents(source, start, "(", ")")


def typescript_function_body(source: str, start: int) -> str:
    """Return the balanced body following one matched TypeScript signature."""
    opening = source.find("{", start)
    if opening < 0:
        return ""
    return typescript_balanced_contents(source, opening + 1, "{", "}")


def typescript_balanced_contents(source: str, start: int, opening: str, closing: str) -> str:
    """Return source up to the closing token matching an already-open token."""
    depth = 1
    for index, character in enumerate(source[start:], start):
        depth += (character == opening) - (character == closing)
        if depth == 0:
            return source[start:index]
    return source[start:]


def propagated_typescript_names(body: str, names: frozenset[str]) -> frozenset[str]:
    """Propagate caller control through bounded TypeScript local assignments."""
    tainted = names
    assignments = tuple(TYPESCRIPT_ASSIGNMENT.finditer(body))
    for _ in range(ALIAS_FLOW_PASSES):
        tainted |= typescript_aliases(assignments, tainted)
    return tainted


def typescript_aliases(
    assignments: tuple[re.Match[str], ...], tainted: frozenset[str]
) -> frozenset[str]:
    """Return TypeScript assignment targets reached by caller-controlled data."""
    return frozenset(
        name
        for item in assignments
        if typescript_assignment_is_tainted(item.group("value"), tainted)
        for name in typescript_names(item.group("target"))
    )


def typescript_assignment_is_tainted(source: str, tainted: frozenset[str]) -> bool:
    """Separate fixed array data positions from executable and spread control."""
    source = source.strip()
    names = (
        typescript_array_command_names(source[1:-1])
        if source.startswith("[")
        else typescript_expression_names(source)
    )
    return bool(names & tainted)


def typescript_names(source: str) -> frozenset[str]:
    """Return identifier tokens from one bounded TypeScript expression."""
    return frozenset(TYPESCRIPT_IDENTIFIER.findall(source))


def typescript_expression_names(source: str) -> frozenset[str]:
    """Return identifier tokens outside static string literals."""
    return typescript_names(source)


def typescript_command_names(command: str) -> frozenset[str]:
    """Return variable command identities from one TypeScript execution call."""
    command = command.strip()
    if command.startswith("["):
        return typescript_array_command_names(command[1:-1])
    return typescript_expression_names(command)


def typescript_array_command_names(source: str) -> frozenset[str]:
    """Return a variable executable or spread vector from one array literal."""
    first = source.split(",", maxsplit=1)[0].strip()
    names = {first} if TYPESCRIPT_IDENTIFIER.fullmatch(first) else set()
    names.update(re.findall(r"\.\.\.\s*([A-Za-z_$][\w$]*)", source))
    return frozenset(names)


def has_explicit_source(tree: ast.Module) -> bool:
    """Accept DefaultPath fields or modern typed Workspace constructors."""
    source_field = any(is_source_field(node) for node in ast.walk(tree))
    workspace = any(is_workspace_directory(node) for node in ast.walk(tree))
    default_path = any(is_default_path_source(node) for node in ast.walk(tree))
    constructor = any((workspace, default_path))
    return all((source_field, constructor))


def is_source_field(node: ast.AST) -> bool:
    """Recognize an object field whose declared type is Dagger Directory."""
    if not isinstance(node, ast.AnnAssign):
        return False
    if not isinstance(node.target, ast.Name):
        return False
    annotation = ast.unparse(node.annotation)
    value = "" if node.value is None else ast.unparse(node.value)
    return all((node.target.id == "source", "Directory" in annotation, value.endswith("field()")))


def is_workspace_directory(node: ast.AST) -> bool:
    """Recognize construction from a typed Dagger Workspace snapshot."""
    if not is_create_function(node):
        return False
    typed = any(
        "Workspace" in ast.unparse(argument.annotation)
        for argument in node.args.args
        if argument.annotation
    )
    directory = any("workspace.directory" in ast.unparse(item) for item in ast.walk(node))
    return all((typed, directory))


def is_create_function(
    node: ast.AST,
) -> TypeIs[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Narrow one AST node to the modern source constructor."""
    return isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "create"


def is_default_path_source(node: ast.AST) -> bool:
    """Recognize the older explicit DefaultPath Directory form."""
    return isinstance(node, ast.AnnAssign) and "DefaultPath" in ast.unparse(node.annotation)


def validate_secret_arguments(path: str, tree: ast.Module) -> tuple[PolicyFinding, ...]:
    """Reject credential-like Dagger function arguments not typed as Secret."""
    findings: list[PolicyFinding] = []
    for node in ast.walk(tree):
        if is_dagger_function(node):
            findings.extend(validate_function_secrets(path, node))
    return tuple(findings)


def is_dagger_function(
    node: ast.AST,
) -> TypeIs[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Recognize a function exposed through the Dagger API boundary."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    decorators = tuple(ast.unparse(item) for item in node.decorator_list)
    return any(item in {"function", "dagger.function"} for item in decorators)


def validate_function_secrets(
    path: str, node: ast.FunctionDef | ast.AsyncFunctionDef
) -> tuple[PolicyFinding, ...]:
    """Validate one function's credential-shaped arguments."""
    findings: list[PolicyFinding] = []
    for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
        annotation = "" if argument.annotation is None else ast.unparse(argument.annotation)
        if SENSITIVE_ARGUMENT.search(argument.arg) and "Secret" not in annotation:
            findings.append(finding("untyped-secret", path, argument.arg))
    return tuple(findings)


def validate_protection(
    snapshot: RepositorySnapshot, expectation: RepositoryExpectation
) -> tuple[PolicyFinding, ...]:
    """Require effective app-bound protection and matching exact-main checks."""
    findings: list[PolicyFinding] = []
    protection = snapshot.protection
    actual = tuple(check.context for check in protection.checks)
    if not contexts_are_strict(actual, expectation, protection):
        findings.append(finding("required-checks", snapshot.name, "strict contexts differ"))
    if any(check.app_id != APP_ID for check in protection.checks):
        findings.append(finding("required-check-app", snapshot.name, "wrong check app"))
    findings.extend(validate_protection_flags(snapshot.name, protection, expectation))
    findings.extend(validate_integrations(snapshot, expectation))
    return tuple(findings)


def contexts_are_strict(
    actual: tuple[str, ...], expectation: RepositoryExpectation, protection: Protection
) -> bool:
    """Require the exact reviewed status contexts in strict mode."""
    return all((actual == expectation.required_contexts, protection.strict))


def validate_protection_flags(
    name: str, protection: Protection, expectation: RepositoryExpectation
) -> tuple[PolicyFinding, ...]:
    """Require the reviewed solo-maintainer protection flags."""
    valid = all(
        (
            protection.enforce_admins,
            protection.approvals == 0,
            protection.conversation_resolution == expectation.conversation_resolution,
            protection.linear_history == expectation.linear_history,
            not protection.allow_force_pushes,
            not protection.allow_deletions,
        )
    )
    return () if valid else (finding("protection-flags", name, "flags differ"),)


def validate_integrations(
    snapshot: RepositorySnapshot, expectation: RepositoryExpectation
) -> tuple[PolicyFinding, ...]:
    """Require each protected context green from GitHub Actions on exact main."""
    for context in expectation.required_contexts:
        if not has_green_integration(snapshot, context):
            return (finding("main-integration", snapshot.name, context),)
    return ()


def has_green_integration(snapshot: RepositorySnapshot, context: str) -> bool:
    """Return whether one exact-main app-bound check is successful."""
    return any(
        run.name == context
        and run.app_id == APP_ID
        and run.head_sha == snapshot.sha
        and run.conclusion == "success"
        for run in snapshot.check_runs
    )


def validate_legacy(snapshot: RepositorySnapshot) -> tuple[PolicyFinding, ...]:
    """Block central deletion while a live consumer executes a legacy control."""
    return tuple(
        finding("legacy-central-reference", reference, "retired hseshadr/ci execution")
        for reference in snapshot.legacy_references
    )


def validate_control_plane(snapshot: RepositorySnapshot) -> tuple[PolicyFinding, ...]:
    """Reject managed CodeQL and independent non-advisory check applications."""
    findings: list[PolicyFinding] = []
    if snapshot.codeql_default_state == "configured":
        findings.append(finding("managed-codeql", snapshot.name, "default setup is configured"))
    external = tuple(app for app in snapshot.check_apps if app not in allowed_check_apps())
    if external:
        findings.append(finding("independent-check-app", snapshot.name, ", ".join(external)))
    return tuple(findings)


def allowed_check_apps() -> frozenset[str]:
    """Return execution ownership plus the reviewed advisory-only integration."""
    return frozenset(("github-actions", "gitguardian"))


def required_minimum_pins(configs: tuple[DaggerConfig, ...]) -> tuple[tuple[str, str], ...]:
    """Return each distinct (floor, pin) pair that needs ancestry evidence."""
    pairs = (floored_pin(config) for config in configs)
    return tuple(dict.fromkeys(pair for pair in pairs if pair is not None))


def floored_pin(config: DaggerConfig) -> tuple[str, str] | None:
    """Return (floor, pin) for one exact hseshadr/ci module config with a floor."""
    remote = parse_pinned_remote(config.identity)
    if remote is None or remote[:2] != ("hseshadr", "ci"):
        return None
    floor = REQUIRED_MINIMUM.get(remote[2].removeprefix("modules/"))
    return None if floor is None else (floor, remote[3])


def validate_minimum_pins(
    configs: tuple[DaggerConfig, ...], ancestry: tuple[PinAncestry, ...]
) -> tuple[PolicyFinding, ...]:
    """Require every floored central pin to be on main and descend from its floor."""
    evidence = {(item.floor, item.pin): item for item in ancestry}
    pairs = required_minimum_pins(configs)
    return tuple(
        minimum_finding(floor, pin, evidence.get((floor, pin)))
        for floor, pin in pairs
        if not pin_meets_floor(evidence.get((floor, pin)))
    )


def minimum_finding(floor: str, pin: str, item: PinAncestry | None) -> PolicyFinding:
    """Name the stale central pin and the ancestry fact that failed."""
    return finding("pin-below-required-minimum", pin, minimum_message(floor, item))


def pin_meets_floor(item: PinAncestry | None) -> bool:
    """Accept only a pin at or after its floor that main also contains."""
    if item is None:
        return False
    return {item.floor_status, item.main_status} <= DESCENDANT_STATUSES


def minimum_message(floor: str, item: PinAncestry | None) -> str:
    """Explain which ancestry fact failed without guessing missing evidence."""
    if item is None:
        return f"no ancestry evidence against required minimum {floor}"
    return (
        f"must descend from required minimum {floor} on main "
        f"(floor...pin={item.floor_status}, pin...main={item.main_status})"
    )
