"""Discover every Dagger consumer of the central modules and prove fleet coverage.

The reviewed fleet contract (`repository_expectations`) is a hand-maintained list, so a
new consumer silently escapes every fleet check until someone remembers to add it. This
module closes that gap: it lists the owner's repositories, reads each default-branch
`dagger.json`, and fails the scan for any consumer the contract does not name.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from pydantic.dataclasses import dataclass as validated_dataclass

from ci.fleet_policy import PolicyFinding, finding
from ci.github_fleet import (
    BOUNDARY_CONFIG,
    HTTP_NOT_FOUND,
    GitHubTransport,
    decode_source,
    parse_content_response,
    parse_dagger_config,
    read_model,
)

UNCOVERED_CODE: Final = "uncovered-consumer"
CENTRAL_PREFIXES: Final = ("github.com/hseshadr/ci/", "github.com/hseshadr/ci@")
PAGE_SIZE: Final = 100


@validated_dataclass(config=BOUNDARY_CONFIG)
class OwnedRepositoryPayload:
    """One entry of the owner's public repository listing."""

    name: str
    archived: bool
    default_branch: str


@dataclass(frozen=True)
class UncoveredConsumer:
    """One discovered consumer that the reviewed fleet contract does not name."""

    name: str
    findings: tuple[PolicyFinding, ...]


def discover_consumers(transport: GitHubTransport, owner: str) -> tuple[str, ...]:
    """Return every active repository whose default-branch dagger.json pins hseshadr/ci."""
    return tuple(
        repository.name
        for repository in list_repositories(transport, owner)
        if not repository.archived and consumes_central(transport, owner, repository)
    )


def list_repositories(transport: GitHubTransport, owner: str) -> tuple[OwnedRepositoryPayload, ...]:
    """Read every page of the owner's repository listing, failing closed on any error."""
    collected: list[OwnedRepositoryPayload] = []
    page = 1
    while True:
        path = f"users/{owner}/repos?type=owner&per_page={PAGE_SIZE}&page={page}"
        batch = read_model(transport, path, tuple[OwnedRepositoryPayload, ...])
        collected.extend(batch)
        if len(batch) < PAGE_SIZE:
            return tuple(collected)
        page += 1


def consumes_central(
    transport: GitHubTransport, owner: str, repository: OwnedRepositoryPayload
) -> bool:
    """Return whether one default-branch dagger.json declares a central module."""
    base = f"repos/{owner}/{repository.name}"
    path = f"{base}/contents/dagger.json?ref={repository.default_branch}"
    response = transport.get(path)
    if response.status == HTTP_NOT_FOUND:
        return False
    source = decode_source(parse_content_response(response, path), "dagger.json", base)
    config = parse_dagger_config(source)
    return any(item.source.startswith(CENTRAL_PREFIXES) for item in config.dependencies)


def uncovered_consumers(discovered: tuple[str, ...], reviewed: tuple[str, ...]) -> tuple[str, ...]:
    """Return discovered consumers absent from the reviewed fleet contract."""
    return tuple(name for name in discovered if name not in reviewed)


def coverage_results(
    transport: GitHubTransport, owner: str, reviewed: tuple[str, ...]
) -> tuple[UncoveredConsumer, ...]:
    """Build one failing result per discovered consumer the fleet scan would skip."""
    missing = uncovered_consumers(discover_consumers(transport, owner), reviewed)
    return tuple(UncoveredConsumer(name, (uncovered_finding(name),)) for name in missing)


def uncovered_finding(name: str) -> PolicyFinding:
    """Name the exact fix for one consumer that escapes the fleet scan."""
    message = f"{name} pins hseshadr/ci modules but is missing from repository_expectations"
    return finding(UNCOVERED_CODE, "dagger.json", message)
