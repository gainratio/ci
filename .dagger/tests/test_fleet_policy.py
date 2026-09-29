from __future__ import annotations

from dataclasses import replace
from datetime import date, timedelta

import pytest

from ci.fleet_policy import (
    REQUIRED_MINIMUM,
    CheckRun,
    DaggerConfig,
    DaggerDependency,
    DeploymentEnvironment,
    PinAncestry,
    Protection,
    RepositoryExpectation,
    RepositorySnapshot,
    RequiredCheck,
    SourceFile,
    parse_typescript,
    validate_repository,
)

SHA = "a" * 40
ACTION = "1" * 40
DAGGER = "27b130bf0f79a7f6fbbbe0fbca6760dc9bb40a77"
UPLOAD = "3" * 40
DOWNLOAD = "4" * 40
PYPI = "5" * 40
HEAD_SHA = "${{ github.event.workflow_run.head_sha }}"
CURRENT_PINS = tuple(
    PinAncestry(
        floor=REQUIRED_MINIMUM["portfolio-foundation"],
        pin=pin,
        floor_status="ahead",
        main_status="ahead",
    )
    for pin in ("b" * 40, SHA)
)

MODULE = """
@object_type
class Example:
    source: dagger.Directory = field()

    @classmethod
    def create(cls, workspace: dagger.Workspace) -> Self:
        instance = cls.__new__(cls)
        instance.source = workspace.directory("/", exclude=[".git", ".env"])
        return instance

    @function
    def publish_npm(
        self, oidc_url: dagger.Secret, oidc_token: dagger.Secret
    ) -> str:
        return "ready"
"""

INGRESS = f"""
name: Dagger
on: [push, pull_request]
permissions:
  contents: read
jobs:
  dagger:
    name: Dagger
    runs-on: ubuntu-latest
    timeout-minutes: 30
    concurrency:
      group: example
      cancel-in-progress: false
    steps:
      - uses: actions/checkout@{ACTION}
        with:
          persist-credentials: false
      - uses: dagger/dagger-for-github@{DAGGER}
        with:
          version: "0.21.8"
          verb: call
          args: ci --commit-sha=${{{{ github.sha }}}}
"""

CANDIDATE = f"""
name: Dagger release candidate
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  candidate:
    name: Dagger release candidate
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{ACTION}
        with:
          persist-credentials: false
      - uses: dagger/dagger-for-github@{DAGGER}
        with:
          version: "0.21.8"
          verb: call
          args: release-candidate --commit-sha=${{{{ github.sha }}}} export --path=release
      - uses: actions/upload-artifact@{UPLOAD}
        with:
          name: example-${{{{ github.sha }}}}
          path: release/
          if-no-files-found: error
          retention-days: 1
"""

PYPI_BRIDGE = f"""
name: Publish trusted artifacts
on:
  workflow_run:
    workflows: [Dagger release candidate]
    types: [completed]
permissions: {{}}
jobs:
  publish-python:
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'workflow_dispatch' &&
      github.event.workflow_run.head_branch == github.event.repository.default_branch
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      id-token: write
    steps:
      - uses: actions/download-artifact@{DOWNLOAD}
        with:
          name: example-${{{{ github.event.workflow_run.head_sha }}}}
          path: release
          github-token: ${{{{ github.token }}}}
          run-id: ${{{{ github.event.workflow_run.id }}}}
      - uses: pypa/gh-action-pypi-publish@{PYPI}
        with:
          packages-dir: release/dist
          attestations: true
"""

# Event values reach dagger-for-github's bash only as quoted env vars (#49). This fixture
# used to paste `--expected-sha=${{ github.event.workflow_run.head_sha }}` into args and
# call it compliant; the policy now reports that as `dagger-args-expression`.
NPM_ARGS = (
    'publish-npm --candidate=candidate --expected-sha="$HEAD_SHA" '
    "--oidc-url=env:ACTIONS_ID_TOKEN_REQUEST_URL "
    "--oidc-token=env:ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)
NPM_BRIDGE = f"""
name: Publish trusted artifacts
on: workflow_run
permissions: {{}}
jobs:
  publish-npm:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      id-token: write
    steps:
      - uses: actions/download-artifact@{DOWNLOAD}
        with:
          name: example-{HEAD_SHA}
          path: release
          github-token: ${{{{ github.token }}}}
          run-id: ${{{{ github.event.workflow_run.id }}}}
      - uses: dagger/dagger-for-github@{DAGGER}
        env:
          HEAD_SHA: {HEAD_SHA}
        with:
          version: "0.21.8"
          verb: call
          module: github.com/hseshadr/example@{HEAD_SHA}
          args: {NPM_ARGS}
"""


def _snapshot(
    *workflows: str,
    module: str = MODULE,
    module_path: str = ".dagger/src/example/main.py",
) -> RepositorySnapshot:
    protection = Protection(
        strict=True,
        enforce_admins=True,
        approvals=0,
        conversation_resolution=True,
        linear_history=True,
        allow_force_pushes=False,
        allow_deletions=False,
        checks=(RequiredCheck(context="Dagger", app_id=15368),),
    )
    check = CheckRun(name="Dagger", app_id=15368, head_sha=SHA, conclusion="success")
    sources = tuple(
        SourceFile(path=f".github/workflows/{index}.yml", text=text)
        for index, text in enumerate(workflows)
    )
    return RepositorySnapshot(
        name="example",
        sha=SHA,
        workflows=sources,
        modules=(SourceFile(path=module_path, text=module),),
        protection=protection,
        check_runs=(check,),
        check_apps=("github-actions",),
        codeql_default_state="not-configured",
        legacy_references=(),
        pin_ancestry=CURRENT_PINS,
    )


def _codes(snapshot: RepositorySnapshot) -> tuple[str, ...]:
    expectation = RepositoryExpectation(
        name="example",
        required_contexts=("Dagger",),
        linear_history=True,
        conversation_resolution=True,
    )
    return tuple(finding.code for finding in validate_repository(snapshot, expectation))


def _shared_configs(source: str, *, engine: str = "v0.21.8") -> tuple[DaggerConfig, ...]:
    pin = source.rpartition("@")[2] if "@" in source else None
    root = DaggerConfig(
        identity=f"github.com/hseshadr/example@{SHA}",
        path="dagger.json",
        name="example",
        engine_version=engine,
        dependencies=(DaggerDependency(name="foundation", source=source, pin=pin),),
    )
    shared = DaggerConfig(
        identity=source,
        path="modules/portfolio-foundation/dagger.json",
        name="portfolio-foundation",
        engine_version="v0.21.8",
    )
    return (root, shared)


def _provider_configs() -> tuple[DaggerConfig, ...]:
    revision = "b" * 40
    foundation = f"github.com/hseshadr/ci/modules/portfolio-foundation@{revision}"
    provider = f"github.com/hseshadr/ci/modules/cloudflare-pages@{revision}"
    root, shared = _shared_configs(foundation)
    root = replace(
        root,
        dependencies=(
            *root.dependencies,
            DaggerDependency(name="cloudflare-pages", source=provider, pin=revision),
        ),
    )
    provider_config = DaggerConfig(
        identity=provider,
        path="modules/cloudflare-pages/dagger.json",
        name="cloudflare-pages",
        engine_version="v0.21.8",
        dependencies=(DaggerDependency(name="foundation", source="../portfolio-foundation"),),
    )
    return root, shared, provider_config


def _central_root(*dependencies: DaggerDependency) -> DaggerConfig:
    return DaggerConfig(
        identity=f"github.com/hseshadr/ci@{SHA}",
        path="dagger.json",
        name="ci",
        engine_version="v0.21.8",
        dependencies=dependencies,
    )


def _central_foundation(revision: str = SHA) -> DaggerConfig:
    return DaggerConfig(
        identity=f"github.com/hseshadr/ci/modules/portfolio-foundation@{revision}",
        path="modules/portfolio-foundation/dagger.json",
        name="portfolio-foundation",
        engine_version="v0.21.8",
    )


def _central_provider(source: str = "../portfolio-foundation") -> DaggerConfig:
    return DaggerConfig(
        identity=f"github.com/hseshadr/ci/modules/cloudflare-pages@{SHA}",
        path="modules/cloudflare-pages/dagger.json",
        name="cloudflare-pages",
        engine_version="v0.21.8",
        dependencies=(DaggerDependency(name="foundation", source=source),),
    )


def _central_python_package(source: str = "../portfolio-foundation") -> DaggerConfig:
    return DaggerConfig(
        identity=f"github.com/hseshadr/ci/modules/python-package@{SHA}",
        path="modules/python-package/dagger.json",
        name="python-package",
        engine_version="v0.21.8",
        dependencies=(DaggerDependency(name="foundation", source=source),),
    )


def _shared_codes(snapshot: RepositorySnapshot, expiry: date | None = None) -> tuple[str, ...]:
    expectation = RepositoryExpectation(
        name="example",
        required_contexts=("Dagger",),
        linear_history=True,
        conversation_resolution=True,
        shared_foundation_required=True,
        grandfathered_until=expiry,
    )
    return tuple(finding.code for finding in validate_repository(snapshot, expectation))


def _production_environment(*, branches: tuple[str, ...] = ("main",)) -> DeploymentEnvironment:
    return DeploymentEnvironment(
        name="production",
        protected_branches=False,
        custom_branch_policies=True,
        branch_names=branches,
        secret_names=("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"),
    )


def test_should_accept_pinned_dagger_ingress_and_exact_release_transports() -> None:
    # Given a repository whose only non-Dagger steps are the two reviewed transports
    snapshot = _snapshot(INGRESS, CANDIDATE, PYPI_BRIDGE, NPM_BRIDGE)

    # When the complete repository contract is evaluated
    codes = _codes(snapshot)

    # Then no policy violation is reported
    assert codes == ()


def test_should_reject_shell_setup_and_mutable_actions_in_ordinary_ingress() -> None:
    # Given three independent ways to execute outside the reviewed Dagger boundary
    workflow = INGRESS.replace(
        f"      - uses: dagger/dagger-for-github@{DAGGER}",
        "      - uses: actions/setup-python@v6\n      - run: pytest\n"
        f"      - uses: dagger/dagger-for-github@{DAGGER}",
    )

    # When the ingress is evaluated
    codes = _codes(_snapshot(workflow))

    # Then each executable escape is rejected
    assert {"mutable-action", "shell-step", "non-dagger-ingress"} <= set(codes)


def test_should_reject_candidate_upload_when_identity_or_order_is_not_exact() -> None:
    # Given an upload before Dagger whose artifact name is not bound to the candidate SHA
    upload = f"""      - uses: actions/upload-artifact@{UPLOAD}
        with:
          name: floating
          path: dist/
"""
    workflow = CANDIDATE.replace(upload, "").replace(
        f"      - uses: dagger/dagger-for-github@{DAGGER}",
        upload + f"      - uses: dagger/dagger-for-github@{DAGGER}",
    )

    # When the candidate transport is evaluated
    codes = _codes(_snapshot(workflow))

    # Then it cannot persist unproven bytes
    assert {"candidate-order", "artifact-identity"} <= set(codes)


def test_should_reject_privileged_bridge_with_source_shell_or_weak_attestation() -> None:
    # Given a PyPI bridge that checks out source, runs a verifier, and disables attestations
    bad = PYPI_BRIDGE.replace(
        f"      - uses: actions/download-artifact@{DOWNLOAD}",
        f"      - uses: actions/checkout@{ACTION}\n      - run: python verify.py\n"
        f"      - uses: actions/download-artifact@{DOWNLOAD}",
    ).replace("attestations: true", "attestations: false")

    # When the privileged bridge is evaluated
    codes = _codes(_snapshot(bad))

    # Then source, shell, and provenance weakening all fail closed
    assert {"privileged-source", "shell-step", "pypi-attestation"} <= set(codes)


def test_should_reject_npm_bridge_without_exact_module_or_typed_oidc() -> None:
    # Given a mutable remote module and untyped OIDC arguments
    bridge = NPM_BRIDGE.replace(
        "github.com/hseshadr/example@${{ github.event.workflow_run.head_sha }}",
        "github.com/hseshadr/example@main",
    ).replace("oidc_url: dagger.Secret", "oidc_url: str")

    # When the npm publisher is evaluated
    codes = _codes(
        _snapshot(bridge, module=MODULE.replace("oidc_url: dagger.Secret", "oidc_url: str"))
    )

    # Then both exact source and secret typing are required
    assert {"remote-module-identity", "untyped-secret"} <= set(codes)


def test_should_allow_decrypted_credentials_inside_internal_adapters() -> None:
    # Given an internal HTTP adapter that receives a credential after Dagger decrypts it
    internal = (
        MODULE
        + """
class InternalTransport:
    def __init__(self, token: str) -> None:
        self.token = token
"""
    )

    # When module credential boundaries are evaluated
    codes = _codes(_snapshot(INGRESS, module=internal))

    # Then only Dagger-exposed @function arguments require dagger.Secret
    assert "untyped-secret" not in codes


def test_should_reject_missing_or_wrong_branch_protection_integration() -> None:
    # Given a required Dagger context attached to the wrong app and a stale check run
    original = _snapshot(INGRESS)
    snapshot = replace(
        original,
        protection=replace(
            original.protection,
            checks=(RequiredCheck(context="Dagger", app_id=7),),
        ),
        check_runs=(
            CheckRun(name="Dagger", app_id=15368, head_sha="b" * 40, conclusion="success"),
        ),
    )

    # When authoritative protection and exact-main integration are evaluated
    codes = _codes(snapshot)

    # Then projections and stale checks cannot look healthy
    assert {"required-check-app", "main-integration"} <= set(codes)


def test_should_reject_legacy_central_execution_reference() -> None:
    # Given a current-main file that still executes a retired central reusable workflow
    snapshot = replace(
        _snapshot(INGRESS),
        legacy_references=(".github/workflows/ci.yml:hseshadr/ci",),
    )

    # When the repository contract is evaluated
    codes = _codes(snapshot)

    # Then deletion is blocked until the reference is removed
    assert codes == ("legacy-central-reference",)


def test_should_reject_managed_codeql_and_cloudflare_but_allow_gitguardian() -> None:
    # Given exact-main checks from Dagger, advisory GitGuardian, and Cloudflare Git
    snapshot = replace(
        _snapshot(INGRESS),
        codeql_default_state="configured",
        check_apps=("github-actions", "gitguardian", "cloudflare-pages"),
    )

    # When independent control-plane ownership is evaluated
    codes = _codes(snapshot)

    # Then managed CodeQL and Cloudflare fail while GitGuardian stays advisory
    assert {"managed-codeql", "independent-check-app"} <= set(codes)


def test_should_accept_typescript_workspace_constructor_when_source_is_explicit() -> None:
    # Given a TypeScript module with the same typed Workspace-to-Directory boundary
    module = """
export class Example {
  private readonly source: Directory;
  constructor(workspace: Workspace) {
    this.source = workspace.directory("/", { exclude: [".git", ".env"] });
  }
  publish(token: Secret): string { return "ready"; }
}
"""

    # When its complete repository contract is evaluated
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/main.ts"))

    # Then TypeScript receives the same explicit-source treatment as Python
    assert "explicit-source" not in codes


def test_should_accept_check_or_call_input_when_dagger_action_owns_execution() -> None:
    # Given the action's two supported invocation encodings
    check_workflow = INGRESS.replace(
        "verb: call\n          args: ci", "verb: check\n          args: ci"
    )
    call_workflow = INGRESS.replace(
        "verb: call\n          args: ci --commit-sha=${{ github.sha }}",
        "call: ci --commit-sha=${{ github.sha }}",
    )
    action_check_workflow = INGRESS.replace(
        "verb: call\n          args: ci --commit-sha=${{ github.sha }}",
        'check: "**"',
    )

    # When both thin Dagger jobs are evaluated
    check_codes = _codes(_snapshot(check_workflow))
    call_codes = _codes(_snapshot(call_workflow))
    action_check_codes = _codes(_snapshot(action_check_workflow))

    # Then invocation syntax does not create independent orchestration
    assert "dagger-verb" not in check_codes
    assert "dagger-verb" not in call_codes
    assert "dagger-verb" not in action_check_codes


def test_should_accept_exact_remote_dagger_plan_before_official_pypi() -> None:
    # Given Assay's source-free exact-SHA Dagger decision before official PyPI
    plan = f"""      - uses: dagger/dagger-for-github@{DAGGER}
        with:
          version: "0.21.8"
          verb: call
          module: github.com/hseshadr/example@{HEAD_SHA}
          args: pypi-required --candidate=release --expected-sha="$HEAD_SHA"
"""
    bridge = PYPI_BRIDGE.replace(
        f"      - uses: pypa/gh-action-pypi-publish@{PYPI}",
        plan + f"      - uses: pypa/gh-action-pypi-publish@{PYPI}",
    )

    # When the privileged bridge is evaluated
    codes = _codes(_snapshot(bridge))

    # Then exact remote planning remains source-free and allowed
    assert "pypi-shape" not in codes
    assert "remote-module-identity" not in codes


@pytest.mark.parametrize(
    "source",
    (
        "github.com/hseshadr/ci/modules/portfolio-foundation@main",
        "github.com/hseshadr/ci/modules/portfolio-foundation@v1",
        "github.com/hseshadr/ci/modules/portfolio-foundation@latest",
    ),
)
def test_should_reject_mutable_dagger_dependency(source: str) -> None:
    # Given a consumer dependency selected by a moving Git reference
    snapshot = replace(_snapshot(INGRESS), dagger_configs=_shared_configs(source))

    # When shared-module policy evaluates the generated dependency metadata
    codes = _shared_codes(snapshot)

    # Then only a literal full commit identity can authorize shared execution
    assert "mutable-dagger-dependency" in codes


@pytest.mark.parametrize(
    "source",
    (
        "gitlab.com/acme/module@main",
        "https://gitlab.com/acme/module.git#main",
        "../../../../outside-repository",
    ),
)
def test_should_reject_unsupported_remote_or_escaping_local_dependency(source: str) -> None:
    # Given an otherwise valid root adds an unsupported or repository-escaping dependency
    foundation = f"github.com/hseshadr/ci/modules/portfolio-foundation@{'b' * 40}"
    root, shared = _shared_configs(foundation)
    external = DaggerDependency(name="external", source=source)
    root = replace(root, dependencies=(*root.dependencies, external))
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root, shared))

    # When canonical dependency identity is evaluated
    codes = _shared_codes(snapshot)

    # Then no unsupported remote or out-of-tree local source is silently accepted
    assert "invalid-dagger-dependency" in codes


@pytest.mark.parametrize(
    "source",
    (
        f"github.com//ci/modules/evil@{'b' * 40}",
        f"github.com/hseshadr//modules/evil@{'b' * 40}",
        f"github.com/hseshadr/ci/modules//evil@{'b' * 40}",
        f"github.com/hseshadr/ci/modules/./evil@{'b' * 40}",
        f"github.com/hseshadr/ci/modules/../evil@{'b' * 40}",
        f"github.com/hseshadr/ci/modules/%2e%2e/evil@{'b' * 40}",
        f"github.com/hseshadr/ci/modules%2fevil@{'b' * 40}",
        f"github.com/hseshadr/ci/modules\\evil@{'b' * 40}",
    ),
)
def test_should_reject_noncanonical_github_module_path(source: str) -> None:
    # Given a literal revision is paired with a non-canonical GitHub path spelling
    root = DaggerConfig(
        identity=f"github.com/hseshadr/example@{SHA}",
        path="dagger.json",
        name="example",
        engine_version="v0.21.8",
        dependencies=(DaggerDependency(name="external", source=source, pin="b" * 40),),
    )
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root,))

    # When dependency identity is validated before any location is used
    codes = _codes(snapshot)

    # Then raw aliases and alternate separators fail closed
    assert "invalid-dagger-dependency" in codes


def test_should_accept_canonical_github_module_path_with_matching_pin() -> None:
    # Given every GitHub identity component and subpath segment is canonical
    source = f"github.com/hseshadr/ci/modules/portfolio-foundation@{'b' * 40}"
    root, shared = _shared_configs(source)
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root, shared))

    # When exact source and generated pin identity are validated
    codes = _codes(snapshot)

    # Then the canonical exact remote remains accepted
    assert "invalid-dagger-dependency" not in codes
    assert "invalid-generated-pin" not in codes


def test_should_accept_canonical_repository_root_module_with_matching_pin() -> None:
    # Given an exact GitHub dependency intentionally uses the repository-root module
    source = f"github.com/example-org/example.repo@{'b' * 40}"
    root = DaggerConfig(
        identity=f"github.com/hseshadr/example@{SHA}",
        path="dagger.json",
        name="example",
        engine_version="v0.21.8",
        dependencies=(DaggerDependency(name="external", source=source, pin="b" * 40),),
    )
    dependency = DaggerConfig(
        identity=source,
        path="dagger.json",
        name="external",
        engine_version="v0.21.8",
    )
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root, dependency))

    # When canonical remote identity is validated without a subpath
    codes = _codes(snapshot)

    # Then a repository-root module remains a valid exact dependency
    assert "invalid-dagger-dependency" not in codes
    assert "invalid-generated-pin" not in codes


def test_should_allow_exact_shared_module_sha_independent_of_consumer_sha() -> None:
    # Given the consumer and reviewed central module intentionally use different SHAs
    source = "github.com/hseshadr/ci/modules/portfolio-foundation@" + "b" * 40
    snapshot = replace(_snapshot(INGRESS), dagger_configs=_shared_configs(source))

    # When the dependency graph is validated independently from consumer source identity
    codes = _shared_codes(snapshot)

    # Then the exact central publisher and compatible engine are accepted
    assert codes == ()


def test_should_reject_missing_dependency_config_and_recursive_cycle() -> None:
    # Given one exact dependency is missing and another graph closes a cycle
    foundation = "github.com/hseshadr/ci/modules/portfolio-foundation@" + "b" * 40
    provider = "github.com/hseshadr/ci/modules/cloudflare-pages@" + "c" * 40
    root, shared = _shared_configs(foundation)
    shared = replace(shared, dependencies=(DaggerDependency(name="provider", source=provider),))
    provider_config = DaggerConfig(
        identity=provider,
        path="modules/cloudflare-pages/dagger.json",
        name="cloudflare-pages",
        engine_version="v0.21.8",
        dependencies=(DaggerDependency(name="foundation", source=foundation),),
    )
    cycle = replace(_snapshot(INGRESS), dagger_configs=(root, shared, provider_config))
    missing = replace(
        _snapshot(INGRESS),
        dagger_configs=(root,),
        missing_dagger_configs=(foundation,),
    )

    # When both recursively resolved graphs are evaluated
    cycle_codes = _shared_codes(cycle)
    missing_codes = _shared_codes(missing)

    # Then recursion cannot silently omit a node or loop forever
    assert "dagger-dependency-cycle" in cycle_codes
    assert "missing-dagger-config" in missing_codes


def test_should_accept_absent_language_lock_with_authoritative_dependency_pin() -> None:
    # Given the exact root config has an authoritative generated dependency pin
    foundation = f"github.com/hseshadr/ci/modules/portfolio-foundation@{'b' * 40}"
    root, shared = _shared_configs(foundation)
    root = replace(root, sdk="python", source=".dagger")
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root, shared))

    # When exact dependency metadata is evaluated
    codes = _shared_codes(snapshot)

    # Then a legacy language SDK lock is not invented as authoritative metadata
    assert "missing-generated-lock" not in codes
    assert "invalid-generated-lock" not in codes


def test_should_not_require_sdk_lock_before_shared_dependency_adoption() -> None:
    # Given an Assay-shaped legacy Python module has no shared dependency or SDK lock
    root = DaggerConfig(
        identity=f"github.com/hseshadr/example@{SHA}",
        path="dagger.json",
        name="example",
        engine_version="v0.21.8",
        sdk="python",
        source=".dagger",
    )
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root,))

    # When its explicit missing-module grandfather is active
    codes = _shared_codes(snapshot, date.today() + timedelta(days=1))

    # Then legacy SDK metadata does not invent a language-lock violation
    assert codes == ()


def test_should_reject_missing_generated_dependency_pin() -> None:
    # Given an exact remote shared source omits Dagger's generated dependency pin
    foundation = f"github.com/hseshadr/ci/modules/portfolio-foundation@{'b' * 40}"
    root, shared = _shared_configs(foundation)
    root = replace(root, dependencies=(replace(root.dependencies[0], pin=None),))
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root, shared))

    # When authoritative dependency identity is evaluated
    codes = _shared_codes(snapshot)

    # Then the incomplete generated dependency identity fails closed
    assert "missing-generated-pin" in codes


def test_should_reject_mismatched_generated_dependency_pin() -> None:
    # Given Dagger's generated pin disagrees with the literal source revision
    foundation = f"github.com/hseshadr/ci/modules/portfolio-foundation@{'b' * 40}"
    root, shared = _shared_configs(foundation)
    dependency = replace(root.dependencies[0], pin="c" * 40)
    root = replace(root, dependencies=(dependency,))
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root, shared))

    # When authoritative dependency identity is evaluated
    codes = _shared_codes(snapshot)

    # Then mutable or tampered generated pins cannot validate the exact source
    assert "invalid-generated-pin" in codes


def test_should_reject_tampered_generated_python_lock_metadata() -> None:
    # Given the generated Python lock no longer binds the local typed Dagger SDK
    foundation = f"github.com/hseshadr/ci/modules/portfolio-foundation@{'b' * 40}"
    root, shared = _shared_configs(foundation)
    lock = SourceFile(path=".dagger/uv.lock", text="version = 1\npackage = []\n")
    root = replace(root, sdk="python", source=".dagger", generated_lock=lock)
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root, shared))

    # When generated lock semantics are evaluated
    codes = _shared_codes(snapshot)

    # Then syntactically valid but stale generated metadata is rejected
    assert "invalid-generated-lock" in codes


@pytest.mark.parametrize(
    ("sdk", "source", "path", "text"),
    (
        (
            "python",
            ".dagger",
            ".dagger/uv.lock",
            'version = 1\n[[package]]\nname = "dagger-io"\nsource = { editable = "sdk" }\n',
        ),
        (
            "typescript",
            "dagger",
            "dagger/yarn.lock",
            "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
            "# yarn lockfile v1\n\n"
            "typescript@5.9.3:\n"
            '  version "5.9.3"\n'
            '  resolved "https://registry.yarnpkg.com/typescript/-/typescript-5.9.3.tgz#'
            + "b"
            * 40
            + '"\n'
            "  integrity sha512-YWJjZA==\n",
        ),
    ),
)
def test_should_accept_semantically_pinned_generated_language_lock(
    sdk: str, source: str, path: str, text: str
) -> None:
    # Given a configured SDK has its exact generated lock with immutable package identity
    foundation = f"github.com/hseshadr/ci/modules/portfolio-foundation@{'b' * 40}"
    root, shared = _shared_configs(foundation)
    root = replace(
        root,
        sdk=sdk,
        source=source,
        generated_lock=SourceFile(path=path, text=text),
    )
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root, shared))

    # When generated lock semantics are evaluated
    codes = _shared_codes(snapshot)

    # Then a supported, correctly located, immutable generated lock is accepted
    assert "missing-generated-lock" not in codes
    assert "invalid-generated-lock" not in codes


def test_should_reject_incompatible_engine_and_action_tuple() -> None:
    # Given the config requests an older engine and the action pin is unreviewed
    source = "github.com/hseshadr/ci/modules/portfolio-foundation@" + "b" * 40
    configs = _shared_configs(source, engine="v0.21.7")
    workflow = INGRESS.replace(DAGGER, "f" * 40)
    snapshot = replace(_snapshot(workflow), dagger_configs=configs)

    # When the config, generated graph, action revision, and action version are compared
    codes = _shared_codes(snapshot)

    # Then both incompatible execution boundaries fail closed
    assert {"incompatible-dagger-engine", "incompatible-dagger-action"} <= set(codes)


def test_should_reject_wrong_shared_module_publisher() -> None:
    # Given a lookalike module name is fetched from an unapproved publisher
    source = "github.com/attacker/ci/modules/portfolio-foundation@" + "b" * 40
    snapshot = replace(_snapshot(INGRESS), dagger_configs=_shared_configs(source))

    # When shared dependency identity is evaluated
    codes = _shared_codes(snapshot)

    # Then an exact SHA cannot compensate for the wrong publisher
    assert "shared-module-publisher" in codes


def test_should_bind_literal_publisher_sha_to_approved_central_identity() -> None:
    # Given publisher code is exact but intentionally differs from the consumer SHA
    approved = "github.com/hseshadr/ci/modules/npm-publisher@" + "b" * 40
    hostile = "github.com/attacker/ci/modules/npm-publisher@" + "b" * 40
    approved_bridge = NPM_BRIDGE.replace(f"github.com/hseshadr/example@{HEAD_SHA}", approved)
    hostile_bridge = NPM_BRIDGE.replace(f"github.com/hseshadr/example@{HEAD_SHA}", hostile)

    # When approved and lookalike publisher identities are compared
    approved_codes = _codes(_snapshot(approved_bridge))
    hostile_codes = _codes(_snapshot(hostile_bridge))

    # Then the exact central publisher is accepted independently of consumer identity
    assert "remote-module-identity" not in approved_codes
    assert "publisher-module-identity" in hostile_codes


def test_should_accept_exact_central_foundation_from_same_snapshot() -> None:
    # Given hseshadr/ci root and foundation configs come from one exact commit snapshot
    dependency = DaggerDependency(name="foundation", source="modules/portfolio-foundation")
    snapshot = replace(
        _snapshot(INGRESS),
        name="ci",
        dagger_configs=(_central_root(dependency), _central_foundation()),
    )

    # When the central publisher graph is evaluated
    codes = _codes(snapshot)

    # Then its exact same-tree foundation edge is accepted
    assert "shared-module-publisher" not in codes


def test_should_accept_exact_central_provider_graph_from_same_snapshot() -> None:
    # Given the central root installs both reviewed local modules at one revision
    foundation = DaggerDependency(name="foundation", source="modules/portfolio-foundation")
    provider = DaggerDependency(name="cloudflare-pages", source="modules/cloudflare-pages")
    configs = (_central_root(foundation, provider), _central_foundation(), _central_provider())
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=configs)

    # When all publisher relationships are evaluated
    codes = _codes(snapshot)

    # Then root-to-modules and provider-to-foundation local edges remain valid
    assert "shared-module-publisher" not in codes
    assert "invalid-dagger-dependency" not in codes


def test_should_accept_exact_central_python_package_graph_from_same_snapshot() -> None:
    # Given the central root and package Lego share one snapshot and Foundation edge
    foundation = DaggerDependency(name="foundation", source="modules/portfolio-foundation")
    package = DaggerDependency(name="python-package", source="modules/python-package")
    configs = (_central_root(foundation, package), _central_foundation(), _central_python_package())
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=configs)

    # When the publisher graph is evaluated
    codes = _codes(snapshot)

    # Then both local edges remain exact and approved
    assert "shared-module-publisher" not in codes
    assert "invalid-dagger-dependency" not in codes


def test_should_reject_python_package_with_unreviewed_foundation_edge() -> None:
    # Given the package Lego redirects its Foundation dependency outside the reviewed tree
    foundation = DaggerDependency(name="foundation", source="modules/portfolio-foundation")
    package = DaggerDependency(name="python-package", source="modules/python-package")
    configs = (
        _central_root(foundation, package),
        _central_foundation(),
        _central_python_package("../../lookalike"),
    )
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=configs)

    # When / Then same-repository placement cannot authorize an unreviewed edge
    assert "invalid-dagger-dependency" in _codes(snapshot)


def test_should_reject_central_local_dependency_from_different_snapshot() -> None:
    # Given the root points locally but the loaded foundation identity has another revision
    dependency = DaggerDependency(name="foundation", source="modules/portfolio-foundation")
    configs = (_central_root(dependency), _central_foundation("b" * 40))
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=configs)

    # When same-snapshot identity is evaluated
    codes = _codes(snapshot)

    # Then a cross-revision local edge fails closed
    assert "invalid-dagger-dependency" in codes


def test_should_reject_central_local_dependency_without_loaded_config() -> None:
    # Given exact central root metadata names a local module absent from the graph
    dependency = DaggerDependency(name="foundation", source="modules/portfolio-foundation")
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=(_central_root(dependency),))

    # When local dependency completeness is evaluated
    codes = _codes(snapshot)

    # Then missing same-snapshot config evidence cannot authorize execution
    assert "invalid-dagger-dependency" in codes


def test_should_reject_renamed_central_shared_module_path() -> None:
    # Given a shared dependency name is redirected to an unreviewed local path
    dependency = DaggerDependency(name="foundation", source="modules/foundation-copy")
    snapshot = replace(_snapshot(INGRESS), name="ci", dagger_configs=(_central_root(dependency),))

    # When canonical publisher paths are evaluated
    codes = _codes(snapshot)

    # Then a renamed local module cannot inherit shared-module authority
    assert "invalid-dagger-dependency" in codes


def test_should_reject_unrelated_local_dependency_even_in_central_root() -> None:
    # Given the exact central root declares an unrelated same-tree module
    dependency = DaggerDependency(name="unrelated", source="modules/unrelated")
    unrelated = DaggerConfig(
        identity=f"github.com/hseshadr/ci/modules/unrelated@{SHA}",
        path="modules/unrelated/dagger.json",
        name="unrelated",
        engine_version="v0.21.8",
    )
    snapshot = replace(
        _snapshot(INGRESS), name="ci", dagger_configs=(_central_root(dependency), unrelated)
    )

    # When the local allowlist boundary is evaluated
    codes = _codes(snapshot)

    # Then central ownership alone cannot authorize arbitrary local code
    assert "invalid-dagger-dependency" in codes


def test_should_reject_unreviewed_local_edge_from_central_provider() -> None:
    # Given the reviewed provider redirects its foundation name to another local module
    snapshot = replace(
        _snapshot(INGRESS),
        name="ci",
        dagger_configs=(_central_provider("../foundation-copy"),),
    )

    # When provider-to-foundation identity is evaluated
    codes = _codes(snapshot)

    # Then an approved provider identity cannot broaden the local allowlist
    assert "invalid-dagger-dependency" in codes


def test_should_reject_local_dependency_from_consumer_repository() -> None:
    # Given a consumer tries to install an arbitrary repository-local module
    root = DaggerConfig(
        identity=f"github.com/hseshadr/example@{SHA}",
        path="dagger.json",
        name="example",
        engine_version="v0.21.8",
        dependencies=(DaggerDependency(name="unrelated", source="modules/unrelated"),),
    )
    snapshot = replace(_snapshot(INGRESS), dagger_configs=(root,))

    # When consumer dependency provenance is evaluated
    codes = _codes(snapshot)

    # Then consumers must use immutable remote modules instead of local executable code
    assert "invalid-dagger-dependency" in codes


def test_should_reject_arbitrary_command_dagger_argument() -> None:
    # Given a public Dagger function exposes a caller-controlled command vector
    module = (
        MODULE
        + """
    @function
    def escape(self, command: list[str]) -> str:
        return command[0]
"""
    )

    # When authored module APIs are inspected
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then generic command execution cannot hide behind the typed graph
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    ("name", "arguments"),
    (
        ("execute", "program: str, arguments: list[str]"),
        ("launch", "executable: str, options: list[str]"),
        ("process", "binary: str, parameters: list[str]"),
    ),
)
def test_should_reject_semantic_python_process_capability(name: str, arguments: str) -> None:
    # Given a public Python function exposes an equivalent process execution vocabulary
    module = (
        MODULE
        + f"""
    @function
    def {name}(self, {arguments}) -> str:
        return "not executed"
"""
    )

    # When the exposed capability is inspected semantically
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then argument renaming cannot create an arbitrary-command escape hatch
    assert "arbitrary-command" in codes


def test_should_allow_typed_data_argument_in_fixed_executable_command() -> None:
    # Given a public function passes typed identity data after a fixed executable and subcommand
    module = (
        MODULE
        + """
    @function
    def release_preflight(self, commit_sha: str) -> dagger.Container:
        return dag.container().with_exec(["sh", "release.sh", "preflight", commit_sha])
"""
    )

    # When executable sink use is distinguished from caller-controlled command structure
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then fixed commands remain valid typed capabilities
    assert "arbitrary-command" not in codes


@pytest.mark.parametrize(
    "function",
    (
        "def task(self, payload: list[str]) -> dagger.Container:\n"
        "        return dag.container().with_exec(payload)",
        "def task(self, binary: str, flags: list[str]) -> dagger.Container:\n"
        "        return dag.container().with_exec([binary, *flags])",
    ),
)
def test_should_reject_public_argument_forwarded_as_command_structure(function: str) -> None:
    # Given a neutral method name forwards caller data as a whole command or executable vector
    module = (
        MODULE
        + f"""
    @function
    {function}
"""
    )

    # When execution-sink data flow is inspected
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then semantic command control cannot hide behind neutral names
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    "body",
    (
        "selected = payload\n        return dag.container().with_exec(selected)",
        "selected = payload\n        chosen = selected\n"
        "        return dag.container().with_exec(chosen)",
        'selected = ["sh", *payload]\n        return dag.container().with_exec(selected)',
        "selected = normalize(payload)\n        return dag.container().with_exec(selected)",
        "selected: list[str] = payload\n        return dag.container().with_exec(selected)",
        "binary, *rest = payload\n        return dag.container().with_exec([binary, *rest])",
    ),
)
def test_should_reject_python_argument_aliases_reaching_command_sink(body: str) -> None:
    # Given caller command data reaches an execution sink through bounded local flow
    module = (
        MODULE
        + f"""
    @function
    def task(self, payload: list[str]) -> dagger.Container:
        {body}
"""
    )

    # When Python command authority is inspected
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then aliases, composition, helpers, and destructuring cannot hide caller control
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    "command",
    (
        "self._build(payload)",
        "payload.copy()",
        "self._wrap(self._build(payload))",
        "self._wrap(self._fixed(), payload)",
    ),
)
def test_should_reject_tainted_python_expression_at_command_sink(command: str) -> None:
    # Given caller-controlled data is embedded directly in a non-literal command expression
    module = (
        MODULE
        + f"""
    @function
    def task(self, payload: list[str]) -> dagger.Container:
        return dag.container().with_exec({command})
"""
    )

    # When the whole command expression is inspected
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then helper and member calls cannot hide caller-controlled command structure
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    "command",
    (
        'self._build(["sh", "release.sh"])',
        "self._build(payload_copy)",
        'self._build("payload")',
    ),
)
def test_should_allow_safe_python_expression_at_command_sink(command: str) -> None:
    # Given a non-literal helper expression contains no caller-controlled identifier
    module = (
        MODULE
        + f"""
    @function
    def task(self, payload: list[str]) -> dagger.Container:
        payload_copy = ["sh", "release.sh"]
        return dag.container().with_exec({command})
"""
    )

    # When exact identifier flow is distinguished from literals and prefixes
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then reviewed fixed command expressions remain allowed
    assert "arbitrary-command" not in codes


def test_should_allow_python_literal_alias_at_command_sink() -> None:
    # Given a fixed reviewed command is named locally without caller-controlled structure
    module = (
        MODULE
        + """
    @function
    def task(self) -> dagger.Container:
        selected = ["sh", "release.sh", "preflight"]
        return dag.container().with_exec(selected)
"""
    )

    # When Python command authority is inspected
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then local names alone do not make a fixed literal command arbitrary
    assert "arbitrary-command" not in codes


@pytest.mark.parametrize(
    "body",
    (
        'command = ["npm", "publish", archive, "--provenance"]\n'
        "        return dag.container().with_exec(command)",
        'args = ["/opt/tool", "upload", f"--repository={repository}"]\n'
        '        command = ["sh", "-ceu", "exec $@", "upload", *args]\n'
        "        return dag.container().with_exec(command)",
    ),
)
def test_should_allow_scalar_data_in_aliased_fixed_python_command(body: str) -> None:
    # Given caller data occupies only data positions behind a fixed executable
    module = (
        MODULE
        + f"""
    @function
    def publish(self, archive: str, repository: str) -> dagger.Container:
        {body}
"""
    )

    # When bounded alias flow distinguishes command structure from typed data
    codes = _codes(_snapshot(INGRESS, module=module))

    # Then EdgeReco and privacy-core shaped fixed commands remain valid
    assert "arbitrary-command" not in codes


def test_should_reject_typescript_arbitrary_command_dagger_argument() -> None:
    # Given a TypeScript Dagger function exposes a generic shell argument
    module = """
@object()
class Example {
  source: Directory
  constructor(workspace: Workspace) { this.source = workspace.directory("/") }
  @func()
  async escape(shell: string): Promise<string> { return shell }
}
"""

    # When the authored TypeScript API is inspected
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then the language cannot provide an arbitrary-command escape hatch
    assert "arbitrary-command" in codes


def test_should_reject_semantic_typescript_process_capability() -> None:
    # Given a TypeScript Dagger function renames a generic executable and argument vector
    module = """
@object()
class Example {
  source: Directory
  constructor(workspace: Workspace) { this.source = workspace.directory("/") }
  @func()
  async execute(program: string, arguments: string[]): Promise<string> { return program }
}
"""

    # When the exposed capability is inspected semantically
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then language and spelling changes do not bypass the command boundary
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    "body",
    (
        "const selected = payload; return dag.container().withExec(selected)",
        "const selected = payload; const chosen = selected; "
        "return dag.container().withExec(chosen)",
        'const selected = ["sh", ...payload]; return dag.container().withExec(selected)',
        "const selected = normalize(payload); return dag.container().withExec(selected)",
        "const [binary, ...rest] = payload; return dag.container().withExec([binary, ...rest])",
    ),
)
def test_should_reject_typescript_argument_aliases_reaching_command_sink(body: str) -> None:
    # Given caller command data reaches a TypeScript execution sink through bounded local flow
    module = f"""
@object()
class Example {{
  source: Directory
  constructor(workspace: Workspace) {{ this.source = workspace.directory("/") }}
  @func()
  async task(payload: string[]): Promise<Container> {{ {body} }}
}}
"""

    # When TypeScript command authority is inspected
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then aliases, composition, helpers, and destructuring cannot hide caller control
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    "command",
    (
        "this.build(payload)",
        "payload.map((item) => item)",
        "this.wrap(this.build(payload))",
        "this.wrap(this.fixed(), payload)",
        "this.build(`fixed-${payload}`)",
    ),
)
def test_should_reject_tainted_typescript_expression_at_command_sink(command: str) -> None:
    # Given caller-controlled data is embedded directly in a non-literal command expression
    module = f"""
@object()
class Example {{
  source: Directory
  constructor(workspace: Workspace) {{ this.source = workspace.directory("/") }}
  @func()
  async task(payload: string[]): Promise<Container> {{
    return dag.container().withExec({command})
  }}
}}
"""

    # When the whole TypeScript command expression is inspected
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then helper, member, and bounded nested calls cannot hide caller control
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    "command",
    (
        'this.build(["sh", "release.sh"])',
        "this.build(payloadCopy)",
        'this.build("payload")',
        "this.build(`payload`)",
    ),
)
def test_should_allow_safe_typescript_expression_at_command_sink(command: str) -> None:
    # Given a helper expression contains a fixed literal or a distinct local identifier
    module = f"""
@object()
class Example {{
  source: Directory
  constructor(workspace: Workspace) {{ this.source = workspace.directory("/") }}
  @func()
  async task(payload: string[]): Promise<Container> {{
    const payloadCopy = ["sh", "release.sh"]
    return dag.container().withExec({command})
  }}
}}
"""

    # When tokens are distinguished from strings and similarly named locals
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then safe reviewed expressions are not false positives
    assert "arbitrary-command" not in codes


def test_should_allow_typescript_literal_alias_at_command_sink() -> None:
    # Given a fixed reviewed TypeScript command is named without caller-controlled structure
    module = """
@object()
class Example {
  source: Directory
  constructor(workspace: Workspace) { this.source = workspace.directory("/") }
  @func()
  async task(): Promise<Container> {
    const selected = ["sh", "release.sh", "preflight"]
    return dag.container().withExec(selected)
  }
}
"""

    # When TypeScript command authority is inspected
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then local names alone do not make a fixed literal command arbitrary
    assert "arbitrary-command" not in codes


def test_should_allow_scalar_data_in_aliased_fixed_typescript_command() -> None:
    # Given caller data occupies only a data position behind a fixed executable
    module = """
@object()
class Example {
  source: Directory
  constructor(workspace: Workspace) { this.source = workspace.directory("/") }
  @func()
  async publish(archive: string): Promise<Container> {
    const command = ["npm", "publish", archive, "--provenance"]
    return dag.container().withExec(command)
  }
}
"""

    # When bounded alias flow distinguishes command structure from typed data
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then a fixed TypeScript command remains a typed capability
    assert "arbitrary-command" not in codes


@pytest.mark.parametrize(
    "noise",
    (
        'const note = "withExec(payload)";',
        "const note = `withExec(${payload})`;",
        "// withExec(payload) } )",
        "/* withExec(payload) } ) */",
        r"const note = /withExec\(payload\)[})]?/;",
        r'const note = "escaped \" } ) withExec(payload)";',
    ),
)
def test_should_ignore_non_code_typescript_sink_text(noise: str) -> None:
    # Given sink-shaped text exists only in a literal, comment, template, or regular expression
    module = _typescript_command_module(
        f'{noise}\nreturn dag.container().withExec(["sh", "release.sh", payload])'
    )

    # When the TypeScript command boundary is analyzed lexically
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then fixed command structure with scalar caller data remains allowed
    assert "arbitrary-command" not in codes


@pytest.mark.parametrize(
    "noise",
    (
        'const note = "}";',
        'const note = "(";',
        "/* } ) */",
        "const note = `static } )`;",
        r"const note = /[})]/;",
    ),
)
def test_should_find_real_typescript_sink_after_lexical_noise(noise: str) -> None:
    # Given inert lexical content precedes a real caller-controlled helper expression
    body = f"{noise}\nreturn dag.container().withExec(this.wrap(')', this.build(payload)))"
    module = _typescript_command_module(body)

    # When braces and parentheses are balanced only in executable code
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then lexical noise cannot truncate or hide the real execution sink
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    "statement",
    (
        "const marker = typeof /}/;",
        "const marker = void /}/;",
        "const marker = delete /[})]/u.source;",
        "const marker = !/[})]/u.test(value);",
        "const marker = value ?? /[})]/u;",
        "const marker = value && /[})]/u;",
        "const marker = value instanceof /[})]/u;",
        "const marker = flag ? /[})]/u : /safe/;",
        "const marker = (() => /[})]/u)();",
        "const marker = { pattern: /[})]/u };",
        r"const marker = /\p{L}+\u{1F600}\/[})]/gu;",
        r"const marker = /\/\*[^]*?\*\/[})]/u;",
        "const marker = function* () { yield /[})]/u };",
        "const marker = async () => await /[})]/u;",
        "function marker() { return /[})]/u }",
        "function marker() { throw /[})]/u }",
        "switch (value) { case /[})]/u: break; }",
    ),
)
def test_should_find_tainted_sink_after_regex_in_valid_expression_position(statement: str) -> None:
    # Given a valid JavaScript regular expression contains inert balancing punctuation
    module = _typescript_command_module(
        f"{statement}\nreturn dag.container().withExec(this.build(payload))"
    )
    assert parse_typescript(module).valid

    # When the complete TypeScript lexical grammar selects regex rather than division
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then regex text cannot truncate the later caller-controlled execution sink
    assert "arbitrary-command" in codes


@pytest.mark.parametrize(
    "statement",
    (
        "const ratio = total / divisor;",
        "const ratio = total / divisor / scale;",
        "const ratio = total / /units/.source.length;",
        "counter /= divisor;",
    ),
)
def test_should_preserve_division_before_typescript_command_analysis(statement: str) -> None:
    # Given slash tokens are division operators rather than regular-expression literals
    module = _typescript_command_module(
        f'{statement}\nreturn dag.container().withExec(["sh", "release.sh", payload])'
    )
    assert parse_typescript(module).valid

    # When the parsed command boundary is evaluated
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then scalar caller data in a fixed command remains allowed
    assert "arbitrary-command" not in codes


@pytest.mark.parametrize(
    "statement",
    (
        'const marker = "typeof /}/ withExec(payload)";',
        "// typeof /}/ withExec(payload)",
        "/* void /}/ withExec(payload) */",
        "const marker = `static typeof /}/ withExec(payload)`;",
        "const marker = `outer-${`${typeof /}/}`}`;",
    ),
)
def test_should_distinguish_nested_typescript_literal_contexts(statement: str) -> None:
    # Given comments, strings, templates, and nested interpolation contain lexical lookalikes
    module = _typescript_command_module(
        f"{statement}\nreturn dag.container().withExec(this.build(payload))"
    )
    assert parse_typescript(module).valid

    # When syntax nodes distinguish inert text from executable interpolation
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then the real downstream caller-controlled sink is still rejected
    assert "arbitrary-command" in codes


def test_should_fail_closed_when_typescript_syntax_is_invalid() -> None:
    # Given malformed TypeScript prevents authoritative syntax classification
    module = _typescript_command_module(
        'const marker = (\nreturn dag.container().withExec(["sh", "release.sh", payload])'
    )
    assert not parse_typescript(module).valid

    # When the module command boundary is parsed
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then unparseable source cannot bypass the arbitrary-command guard
    assert "arbitrary-command" in codes


def test_should_analyze_nested_typescript_template_interpolation_as_code() -> None:
    # Given caller control is nested inside an executable template interpolation
    module = _typescript_command_module(
        "return dag.container().withExec(`fixed-${this.wrap('}', this.build(payload))}`)"
    )

    # When template static text and interpolation code are separated
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then the interpolation remains part of command-structure analysis
    assert "arbitrary-command" in codes


def test_should_allow_tainted_scalar_in_fixed_typescript_command_array() -> None:
    # Given helper-derived caller data occupies only a scalar position after a fixed executable
    module = _typescript_command_module(
        'return dag.container().withExec(["sh", "release.sh", this.format(payload)])'
    )

    # When the fixed array command structure is distinguished from scalar data
    codes = _codes(_snapshot(INGRESS, module=module, module_path=".dagger/src/example/index.ts"))

    # Then typed scalar data does not turn the fixed command into a generic process API
    assert "arbitrary-command" not in codes


def _typescript_command_module(body: str) -> str:
    return f"""
@object()
class Example {{
  source: Directory
  constructor(workspace: Workspace) {{ this.source = workspace.directory("/") }}
  @func()
  async task(payload: string[]): Promise<Container> {{
    {body}
  }}
}}
"""


def test_should_require_production_secrets_in_production_environment() -> None:
    # Given a provider consumer retains Cloudflare credentials at repository scope
    snapshot = replace(
        _snapshot(INGRESS),
        dagger_configs=_provider_configs(),
        repository_secret_names=("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"),
    )

    # When secret-name placement is evaluated without requesting values
    codes = _codes(snapshot)

    # Then production authority must be isolated to the environment
    assert "unscoped-production-secret" in codes


@pytest.mark.parametrize(
    "expression",
    (
        "${{ secrets.CLOUDFLARE_API_TOKEN }}",
        "${{ secrets['CLOUDFLARE_API_TOKEN'] }}",
        '${{ secrets["CLOUDFLARE_API_TOKEN"] }}',
        "${{ secrets[matrix.production_secret] }}",
    ),
)
def test_should_scope_all_github_secret_access_forms_to_production(expression: str) -> None:
    # Given a provider consumer references production authority without a job environment
    workflow = INGRESS.replace(
        "      - uses: dagger/dagger-for-github",
        f"      - env:\n          AUTHORITY: {expression}\n        uses: dagger/dagger-for-github",
    )
    snapshot = replace(
        _snapshot(workflow),
        dagger_configs=_provider_configs(),
        environments=(_production_environment(),),
    )

    # When supported and dynamic GitHub expression forms are evaluated
    codes = _codes(snapshot)

    # Then every production-authority job is bound to environment production
    assert "unscoped-production-secret" in codes


def test_should_not_apply_provider_environment_rules_before_provider_install() -> None:
    # Given a legacy consumer has repository secrets but no shared provider dependency
    snapshot = replace(
        _snapshot(INGRESS),
        repository_secret_names=("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"),
    )

    # When its explicit missing-module rollout window remains active
    codes = _shared_codes(snapshot, date.today() + timedelta(days=1))

    # Then future provider scoping is not misapplied to the legacy lifecycle
    assert "missing-shared-module" not in codes
    assert "unscoped-production-secret" not in codes


def test_should_apply_environment_rules_to_exact_direct_provider_ingress() -> None:
    # Given migration starts through an exact direct provider call before config installation
    provider = "github.com/hseshadr/ci/modules/cloudflare-pages@" + "b" * 40
    direct_call = f"          verb: call\n          module: {provider}"
    workflow = INGRESS.replace("          verb: call", direct_call)
    snapshot = replace(
        _snapshot(workflow),
        repository_secret_names=("CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"),
    )

    # When lifecycle applicability is evaluated
    codes = _codes(snapshot)

    # Then direct provider adoption activates environment scoping
    assert {"unscoped-production-secret", "production-environment"} <= set(codes)


def test_should_reject_mutable_direct_dagger_provider_module() -> None:
    # Given an ordinary Dagger ingress imports the provider from mutable main
    provider = "github.com/hseshadr/ci/modules/cloudflare-pages@main"
    direct_call = f"          verb: call\n          module: {provider}"
    workflow = INGRESS.replace("          verb: call", direct_call)

    # When direct Dagger import identity is validated
    codes = _codes(_snapshot(workflow))

    # Then environment applicability cannot substitute for immutable executable identity
    assert "remote-module-identity" in codes


def test_should_ignore_module_input_on_non_dagger_action_for_provider_applicability() -> None:
    # Given an unrelated pinned action happens to use an input named module
    provider = "github.com/hseshadr/ci/modules/cloudflare-pages@" + "b" * 40
    unrelated = f"""      - uses: example/action@{"c" * 40}
        with:
          module: {provider}
"""
    dagger_step = "      - uses: dagger/dagger-for-github"
    workflow = INGRESS.replace(dagger_step, unrelated + dagger_step)
    snapshot = replace(
        _snapshot(workflow),
        repository_secret_names=("CLOUDFLARE_API_TOKEN",),
    )

    # When provider lifecycle applicability is evaluated
    codes = _codes(snapshot)

    # Then only the Dagger action's typed module input can activate provider policy
    assert "production-environment" not in codes
    assert "unscoped-production-secret" not in codes


def test_should_bind_dynamic_publisher_candidate_to_expected_consumer() -> None:
    # Given a publisher bridge points its dynamic candidate expression at an attacker repository
    hostile = "github.com/attacker/evil@${{ github.event.workflow_run.head_sha }}"
    bridge = NPM_BRIDGE.replace(f"github.com/hseshadr/example@{HEAD_SHA}", hostile)

    # When publisher identity is checked in the example repository context
    codes = _codes(_snapshot(bridge))

    # Then a matching SHA expression cannot authorize a different consumer
    assert "publisher-module-identity" in codes


def test_should_reject_remote_module_override_in_candidate_build() -> None:
    # Given the candidate transport checks out source but overrides Dagger with a remote module
    remote = "github.com/attacker/candidate@" + "b" * 40
    call = f"          verb: call\n          module: {remote}"
    workflow = CANDIDATE.replace("          verb: call", call)

    # When the candidate build context is validated
    codes = _codes(_snapshot(workflow))

    # Then only the checked-out consumer source can produce candidate bytes
    assert "candidate-module-identity" in codes


def test_should_reject_unlisted_literal_central_publisher_module() -> None:
    # Given a literal exact central module is not an explicitly reviewed publisher transport
    approved = "github.com/hseshadr/ci/modules/npm-publisher@" + "b" * 40
    unknown = "github.com/hseshadr/ci/modules/arbitrary-publisher@" + "b" * 40
    bridge = NPM_BRIDGE.replace(f"github.com/hseshadr/example@{HEAD_SHA}", approved)
    hostile = bridge.replace(approved, unknown)

    # When the explicit central publisher allowlist is enforced
    approved_codes = _codes(_snapshot(bridge))
    hostile_codes = _codes(_snapshot(hostile))

    # Then only the documented literal publisher identity is authorized
    assert "publisher-module-identity" not in approved_codes
    assert "publisher-module-identity" in hostile_codes


def test_should_accept_provider_secrets_in_main_only_production_environment() -> None:
    # Given provider authority exists only in a main-restricted production environment
    snapshot = replace(
        _snapshot(INGRESS),
        dagger_configs=_provider_configs(),
        environments=(_production_environment(),),
    )

    # When the provider lifecycle boundary is validated
    codes = _shared_codes(snapshot)

    # Then exact provider identity and environment placement are green
    assert codes == ()


def test_should_require_main_only_environment_for_secret_referencing_job() -> None:
    # Given a deployment job references production secrets outside a main-only environment
    workflow = INGRESS.replace(
        "      - uses: dagger/dagger-for-github",
        "      - env:\n          CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}\n"
        "        uses: dagger/dagger-for-github",
    )
    snapshot = replace(
        _snapshot(workflow),
        dagger_configs=_provider_configs(),
        environments=(_production_environment(branches=("*",)),),
    )

    # When workflow and authoritative environment metadata are joined
    codes = _codes(snapshot)

    # Then both job scoping and deployment branch identity fail closed
    assert {"unscoped-production-secret", "production-branch-policy"} <= set(codes)


def test_should_grandfather_only_missing_shared_module_until_expiry() -> None:
    # Given a current consumer has no shared dependency and also uses a mutable action
    workflow = INGRESS.replace(f"dagger/dagger-for-github@{DAGGER}", "dagger/dagger-for-github@v8")
    snapshot = _snapshot(workflow)

    # When its explicit rollout allowance is active, then expired
    active = _shared_codes(snapshot, date.today() + timedelta(days=1))
    expired = _shared_codes(snapshot, date.today() - timedelta(days=1))

    # Then the allowance suppresses only absence and never executable drift
    assert "missing-shared-module" not in active
    assert "mutable-action" in active
    assert "missing-shared-module" in expired


def test_should_report_stale_foundation_pin_through_repository_contract() -> None:
    # Given an otherwise valid consumer whose foundation pin predates the required floor
    source = "github.com/hseshadr/ci/modules/portfolio-foundation@" + "b" * 40
    stale = PinAncestry(
        floor=REQUIRED_MINIMUM["portfolio-foundation"],
        pin="b" * 40,
        floor_status="behind",
        main_status="ahead",
    )
    snapshot = replace(
        _snapshot(INGRESS), dagger_configs=_shared_configs(source), pin_ancestry=(stale,)
    )

    # When the complete repository contract is evaluated
    codes = _shared_codes(snapshot)

    # Then the stale release gate is the only failure
    assert codes == ("pin-below-required-minimum",)
