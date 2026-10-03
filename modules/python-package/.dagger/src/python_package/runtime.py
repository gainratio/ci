"""Pinned, secret-free Dagger adapters for package candidate construction."""

from __future__ import annotations

from typing import Final, Literal

import dagger
from dagger import dag
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

from .distributions import DistributionObservation
from .identity import CandidateIdentity, RepositoryCommit

PYTHON_IMAGE: Final = (
    "ghcr.io/hseshadr/mirror/docker.io/library/python:3.13.14-slim@sha256:"
    "9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
)
UV_IMAGE: Final = (
    "ghcr.io/hseshadr/mirror/ghcr.io/astral-sh/uv:0.11.32@sha256:"
    "df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c"
)
PIP_AUDIT_VERSION: Final = "2.10.0"
TWINE_VERSION: Final = "7.0.0"
NONROOT_USER: Final = "65532:65532"
BUILD_PATH: Final = "/work/venv/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"
CLOSED_MODEL: Final = ConfigDict(extra="forbid", frozen=True, strict=True)
EXPORT_COMMAND: Final = (
    "uv",
    "export",
    "--frozen",
    "--all-extras",
    "--all-groups",
    "--no-emit-project",
    "--no-hashes",
    "--output-file",
    "/work/requirements.txt",
)
AUDIT_COMMAND: Final = (
    "uv",
    "tool",
    "run",
    "--from",
    f"pip-audit=={PIP_AUDIT_VERSION}",
    "pip-audit",
    "-r",
    "/work/requirements.txt",
    "--disable-pip",
    "--no-deps",
)
SYNC_COMMAND: Final = (
    "uv",
    "sync",
    "--frozen",
    "--all-extras",
    "--all-groups",
    "--no-install-project",
)
BUILD_COMMAND: Final = (
    "uv",
    "build",
    "--no-sources",
    "--no-build-isolation",
    "--out-dir",
    "/work/dist",
)


class FoundationGreenEvidence(BaseModel):  # type: ignore[explicit-any]  # Pydantic stub
    """Exact serialization currently returned by Foundation green-main."""

    model_config = CLOSED_MODEL
    repository: str
    branch: str
    commit_sha: str
    workflow_name: str
    workflow_path: str
    check_name: str
    check_run_id: str
    check_suite_id: str
    workflow_job_id: str
    run_attempt: int = Field(gt=0)
    check_started_at: str
    check_completed_at: str
    workflow_run_id: str
    workflow_started_at: str
    workflow_created_at: str
    workflow_updated_at: str
    app_id: int = Field(gt=0)


class ProbeObservation(BaseModel):  # type: ignore[explicit-any]  # Pydantic stub
    """Closed JSON boundary from the static archive probe."""

    model_config = CLOSED_MODEL
    filename: str
    sha256: str
    kind: Literal["wheel", "sdist"]
    project: str
    version: str
    member_count: int
    size: int


PROBE_ADAPTER: Final = TypeAdapter(tuple[ProbeObservation, ...])


def parse_observations(value: str) -> tuple[DistributionObservation, ...]:
    """Parse only the probe's closed JSON record schema."""
    try:
        records = PROBE_ADAPTER.validate_json(value, strict=True)
    except ValidationError:
        raise ValueError("distribution probe schema differs") from None
    return tuple(_observation(item) for item in records)


def require_green_binding(evidence: FoundationGreenEvidence, identity: CandidateIdentity) -> None:
    """Bind current exact-green main evidence to source and workflow attempt."""
    actual_source = evidence.repository, evidence.branch, evidence.commit_sha
    expected_source = identity.repository.value, "main", identity.commit.value
    if actual_source != expected_source:
        raise ValueError("Foundation green-main evidence does not bind requested commit")
    actual_attempt = evidence.workflow_run_id, evidence.run_attempt
    expected_attempt = identity.workflow.run_id, identity.workflow.attempt
    if actual_attempt != expected_attempt:
        raise ValueError("Foundation green-main evidence attempt identity differs")


async def green_evidence(
    github_token: dagger.Secret, identity: CandidateIdentity
) -> FoundationGreenEvidence:
    """Resolve and parse live exact-green main evidence through Foundation."""
    raw = (
        await dag.foundation()
        .green_main(github_token=github_token, repository=identity.repository.value)
        .serialization()
    )
    try:
        result = FoundationGreenEvidence.model_validate_json(raw)
    except ValidationError:
        raise ValueError("Foundation green-main evidence schema differs") from None
    require_green_binding(result, identity)
    return result


async def guarded_source(
    source: dagger.Directory,
    identity: RepositoryCommit,
    http_auth_header: dagger.Secret | None = None,
) -> dagger.Directory:
    """Bind and guard source through the exact same-tree Foundation dependency."""
    foundation = dag.foundation()
    repository = identity.repository.value
    commit_sha = identity.commit.value
    bound = foundation.source(source, repository, commit_sha, http_auth_header=http_auth_header)
    guard = foundation.guard(source, repository, commit_sha, http_auth_header=http_auth_header)
    await guard.sync()
    return bound


def dependency_audit_container(source: dagger.Directory) -> dagger.Container:
    """Audit only the frozen exported dependency graph."""
    return _base(source).with_exec(list(EXPORT_COMMAND)).with_exec(list(AUDIT_COMMAND))


def build_container(source: dagger.Directory) -> dagger.Container:
    """Build in a non-root, secret-free, frozen project environment."""
    cleanup = ["rm", "-f", "/work/dist/.gitignore"]
    result = _base(source).with_exec(list(SYNC_COMMAND)).with_exec(list(BUILD_COMMAND))
    return result.with_exec(cleanup)


async def inspect_products(directory: dagger.Directory) -> tuple[DistributionObservation, ...]:
    """Run the bounded stdlib probe in a pinned verifier container."""
    source = dag.current_module().source().directory("src")
    base = dag.container(platform=dagger.Platform("linux/amd64")).from_(PYTHON_IMAGE)
    base = base.with_directory("/tool/src", source).with_directory("/dist", directory)
    base = base.with_env_variable("PYTHONPATH", "/tool/src")
    command = ["python", "-m", "python_package.distribution_probe", "/dist"]
    return parse_observations(await base.with_exec(command).stdout())


async def check_distributions(
    directory: dagger.Directory, observations: tuple[DistributionObservation, ...]
) -> None:
    """Apply Twine's official strict metadata checks to the observed products."""
    uv = dag.container().from_(UV_IMAGE).file("/uv")
    base = dag.container(platform=dagger.Platform("linux/amd64")).from_(PYTHON_IMAGE)
    base = base.with_file("/usr/local/bin/uv", uv).with_directory("/dist", directory)
    await base.with_exec(_twine_command(observations)).sync()


def _twine_command(observations: tuple[DistributionObservation, ...]) -> list[str]:
    command = (
        "uv",
        "tool",
        "run",
        "--from",
        f"twine=={TWINE_VERSION}",
        "twine",
        "check",
        "--strict",
    )
    products = tuple(f"/dist/{item.filename}" for item in observations)
    return [*command, *products]


async def require_tag(identity: CandidateIdentity, tag: str) -> None:
    """Require the metadata-derived immutable tag to resolve to the requested commit."""
    resolved = await dag.git(identity.repository.github_url).tag(tag).commit()
    if resolved != identity.commit.value:
        raise ValueError("metadata-derived release tag does not bind requested commit")


def _base(source: dagger.Directory) -> dagger.Container:
    uv = dag.container().from_(UV_IMAGE).file("/uv")
    base = dag.container(platform=dagger.Platform("linux/amd64")).from_(PYTHON_IMAGE)
    base = base.with_file("/usr/local/bin/uv", uv).with_directory("/src", source)
    base = base.with_workdir("/src").with_exec(_work_directory_command())
    base = base.with_user(NONROOT_USER).with_env_variable("UV_PROJECT_ENVIRONMENT", "/work/venv")
    base = base.with_env_variable("UV_CACHE_DIR", "/work/cache")
    base = base.with_env_variable("UV_TOOL_DIR", "/work/tools")
    base = base.with_env_variable("VIRTUAL_ENV", "/work/venv")
    base = base.with_env_variable("PATH", BUILD_PATH)
    return base.with_env_variable("HOME", "/work")


def _work_directory_command() -> list[str]:
    return [
        "/bin/sh",
        "-euc",
        "mkdir -p /work/cache /work/dist /work/tmp /work/venv && chown -R 65532:65532 /work",
    ]


def _observation(item: ProbeObservation) -> DistributionObservation:
    return DistributionObservation(
        item.filename,
        item.sha256,
        item.kind,
        item.project,
        item.version,
        item.member_count,
        item.size,
    )
