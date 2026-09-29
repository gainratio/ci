"""Central CI quality, security, and fleet-policy Dagger graph."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final, Self

import dagger
from dagger import check, dag, field, function, object_type

PYTHON_IMAGE: Final = (
    "python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
)
UV_IMAGE: Final = (
    "ghcr.io/astral-sh/uv:0.11.32@sha256:"
    "df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c"
)
# Module gates need git, uvx, and a Dagger CLI that reaches the engine through nesting.
MODULE_IMAGE: Final = (
    "python:3.13.14-bookworm@sha256:"
    "8b9a8b28d9cc221c6ab5d40e9cfcd99429959f6a8f5171612a99147975ab043f"
)
ENGINE_IMAGE: Final = (
    "registry.dagger.io/engine:v0.21.8@sha256:"
    "c9c1a0a6546380983d42e8d75adde070a2a0935c54b498d8bc9045d9cb2ee336"
)
MODULE_GATES: Final = (
    "modules/cloudflare-pages",
    "modules/portfolio-foundation",
    "modules/python-package",
)
# Hosted module gates run inside Dagger. These tests need host Docker (gitleaks via
# `docker run`) or a host Dagger CLI working in a temp directory; a nested CLI resolves
# paths against the container workdir instead. Hosted CI still runs gitleaks through
# `foundation.guard`; run these locally with each module's `poe gate`.
HOSTED_SKIPPED_TESTS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {
        "modules/portfolio-foundation": (
            "tests/test_guard_integration.py",
            "tests/test_artifact.py::test_should_envelope_nested_directory_and_reject_unexpected_input",
            "tests/test_artifact.py::test_should_reject_symlink_and_preserve_control_filename_in_evidence",
            "tests/test_bootstrap.py::test_should_bootstrap_clean_module_before_frozen_sync",
            "tests/test_source_integration.py::test_should_bind_exact_nested_public_tree_and_reject_tampering",
        ),
        "modules/cloudflare-pages": (
            "tests/test_deploy_contract.py::test_should_run_real_dagger_mock_provider_contract",
        ),
    }
)
REPOSITORY_URL: Final = "https://github.com/hseshadr/ci.git"
REPOSITORY: Final = "hseshadr/ci"
SHA_LENGTH: Final = 40
SOURCE_EXCLUDES: Final = [
    ".git",
    ".env",
    "**/.env",
    "**/*.key",
    "**/*.pem",
    "**/.venv",
    "**/.coverage",
    "**/.mypy_cache",
    "**/.pytest_cache",
    "**/.ruff_cache",
    "**/node_modules",
    "**/sdk",
    ".dagger/sdk",
    "**/__pycache__",
]
FIXTURE_MODULES: Final = (
    "tests/dagger/python_consumer",
    "tests/dagger/typescript_consumer",
)
FLEET_COMMAND: Final = ("uv", "run", "--directory", ".dagger", "python", "-m", "ci.fleet_cli")


@object_type
class Ci:
    """Run central policy from one explicit typed workspace snapshot."""

    source: dagger.Directory = field()

    @classmethod
    def create(cls, workspace: dagger.Workspace) -> Self:
        """Construct the graph from caller-selected workspace bytes."""
        instance = cls.__new__(cls)
        instance.source = workspace.directory("/", exclude=SOURCE_EXCLUDES)
        return instance

    @function
    @check
    async def ci(self, github_token: dagger.Secret, commit_sha: str = "") -> str:
        """Run canonical quality, security, and composition gates."""
        await self._quality().sync()
        await self._module_gates()
        await self._security(commit_sha, github_token)
        await self._module_fixtures()
        return "central Dagger gate passed"

    @function
    async def security(self, github_token: dagger.Secret, commit_sha: str = "") -> str:
        """Run the complete scheduled security graph."""
        await self._security(commit_sha, github_token)
        return "central Dagger security gate passed"

    @function
    async def fleet(self, github_token: dagger.Secret, include_central: bool = False) -> str:
        """Fail closed on authoritative exact-main fleet evidence."""
        command = list(FLEET_COMMAND)
        if include_central:
            command.append("--include-central")
        scan = self._repository().with_secret_variable("GITHUB_TOKEN", github_token)
        await scan.with_exec(command).sync()
        return "authoritative Dagger fleet policy passed"

    @function
    async def module_fixtures(self) -> str:
        """Run both generated-client consumer checks from this source snapshot."""
        return await self._module_fixtures()

    async def _module_fixtures(self) -> str:
        for path in FIXTURE_MODULES:
            await self._module_fixture(path)
        return "cross-language Dagger module fixtures passed"

    async def _module_fixture(self, path: str) -> None:
        module = self.source.as_module(source_root_path=path)
        fixture = module.check("contract").run()
        if not await fixture.passed():
            raise RuntimeError(f"Dagger module fixture failed: {path}")

    async def _module_gates(self) -> None:
        gates = (self._module_gate(path).sync() for path in MODULE_GATES)
        results = await asyncio.gather(*gates, return_exceptions=True)
        failed = [
            path
            for path, result in zip(MODULE_GATES, results, strict=True)
            if isinstance(result, BaseException)
        ]
        if failed:
            raise RuntimeError(f"module gates failed: {', '.join(failed)}")

    def _module_gate(self, path: str) -> dagger.Container:
        project = f"{path}/.dagger"
        skipped = " ".join(f"--deselect={test}" for test in HOSTED_SKIPPED_TESTS.get(path, ()))
        generated = self.source.as_module_source(source_root_path=path)
        base = self._module_tools().with_directory("/src", self.source)
        base = base.with_directory("/src", generated.generated_context_directory())
        base = base.with_env_variable("PYTEST_ADDOPTS", skipped)
        # Nested Dagger takes its context from the nearest .git and resolves paths from the
        # workdir, so `dagger -m ..` in a module's gate loads that module and its siblings.
        base = base.with_exec(["git", "init", "--quiet", "/src"]).with_workdir(f"/src/{project}")
        base = base.with_exec(["uv", "sync", "--frozen", "--all-groups"])
        gate = ["uv", "run", "poe", "gate"]
        return base.with_exec(gate, experimental_privileged_nesting=True)

    def _module_tools(self) -> dagger.Container:
        uv = dag.container().from_(UV_IMAGE)
        engine = dag.container().from_(ENGINE_IMAGE)
        base = dag.container(platform=dagger.Platform("linux/amd64")).from_(MODULE_IMAGE)
        base = base.with_file("/usr/local/bin/uv", uv.file("/uv"))
        base = base.with_file("/usr/local/bin/uvx", uv.file("/uvx"))
        base = base.with_file("/usr/local/bin/dagger", engine.file("/usr/local/bin/dagger"))
        base = base.with_mounted_cache("/root/.cache/uv", dag.cache_volume("ci-module-uv"))
        return base.with_workdir("/src")

    async def _security(self, commit_sha: str, github_token: dagger.Secret) -> None:
        await self._dependency_audit().sync()
        await (await self._repository_guard(commit_sha)).sync()
        await self._zizmor(github_token).sync()

    async def _repository_guard(self, commit_sha: str) -> dagger.Container:
        exact_sha = commit_sha or await dag.git(REPOSITORY_URL).branch("main").commit()
        self._require_sha(exact_sha)
        return dag.foundation().guard(
            source=self.source,
            repository=REPOSITORY,
            commit_sha=exact_sha,
        )

    def _quality(self) -> dagger.Container:
        command = [
            "uv",
            "run",
            "--directory",
            ".dagger",
            "poe",
            "gate",
        ]
        return self._repository().with_exec(command)

    def _dependency_audit(self) -> dagger.Container:
        command = ["uv", "run", "--directory", ".dagger", "poe", "audit"]
        return self._repository().with_exec(command)

    def _zizmor(self, github_token: dagger.Secret) -> dagger.Container:
        command = [
            "uv",
            "run",
            "--directory",
            ".dagger",
            "zizmor",
            "--pedantic",
            "--min-severity",
            "medium",
            "../.github/workflows",
            "../.github/dependabot.yml",
        ]
        base = self._repository().with_secret_variable("GH_TOKEN", github_token)
        return base.with_exec(command)

    def _repository(self) -> dagger.Container:
        uv = dag.container().from_(UV_IMAGE).file("/uv")
        sdk = dag.current_module().source().directory("sdk")
        base = dag.container(platform=dagger.Platform("linux/amd64")).from_(PYTHON_IMAGE)
        base = base.with_file("/usr/local/bin/uv", uv).with_directory("/src", self.source)
        base = base.with_directory("/src/.dagger/sdk", sdk)
        base = base.with_workdir("/src")
        base = base.with_mounted_cache("/root/.cache/uv", dag.cache_volume("ci-uv"))
        return base.with_exec(["uv", "sync", "--directory", ".dagger", "--frozen", "--all-groups"])

    @staticmethod
    def _require_sha(commit_sha: str) -> None:
        valid = len(commit_sha) == SHA_LENGTH
        valid = valid and all(character in "0123456789abcdef" for character in commit_sha)
        if not valid:
            raise ValueError("commit_sha must be a lowercase 40-character Git SHA")
