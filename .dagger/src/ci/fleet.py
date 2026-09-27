"""Fleet-wide Dagger control-plane evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from ci.fleet_coverage import coverage_results
from ci.fleet_policy import PolicyFinding, RepositoryExpectation, finding, validate_repository
from ci.github_fleet import FleetAccessError, GitHubHttpTransport, GitHubTransport, read_repository

OWNER = "hseshadr"


@dataclass(frozen=True)
class RepositoryResult:
    """Exact-main identity and policy result for one repository."""

    name: str
    sha: str
    findings: tuple[PolicyFinding, ...]


def repository_expectations(include_central: bool) -> tuple[RepositoryExpectation, ...]:
    """Return the reviewed fleet contract for the current rollout phase."""
    consumers = (
        expectation("agentic-context-service"),
        expectation("agentic-saga"),
        expectation("almamesh", grandfathered_until=date(2026, 12, 15)),
        expectation("aml-filter", grandfathered_until=date(2026, 12, 31)),
        expectation("assay", linear_history=True, grandfathered_until=date(2026, 11, 30)),
        expectation("edge-proc", grandfathered_until=date(2026, 10, 15)),
        expectation("edge-reco", grandfathered_until=date(2026, 9, 30)),
        expectation("edgeproc-core", grandfathered_until=date(2026, 10, 31)),
        expectation("privacy-core", grandfathered_until=date(2026, 11, 15)),
    )
    central = expectation("ci", conversation_resolution=False, shared_foundation_required=False)
    return consumers + ((central,) if include_central else ())


def expectation(
    name: str,
    *,
    linear_history: bool = False,
    conversation_resolution: bool = True,
    shared_foundation_required: bool = True,
    grandfathered_until: date | None = None,
) -> RepositoryExpectation:
    """Build one sole-Dagger branch-protection expectation."""
    protection = (name, ("Dagger",), linear_history, conversation_resolution)
    rollout = (shared_foundation_required, grandfathered_until)
    return RepositoryExpectation(*protection, *rollout)


def expectation_for(name: str) -> RepositoryExpectation:
    """Return one explicit rollout contract by repository name."""
    match = next((item for item in repository_expectations(True) if item.name == name), None)
    if match is None:
        raise ValueError(f"unknown fleet repository: {name}")
    return match


def scan_fleet(token: str, include_central: bool) -> tuple[RepositoryResult, ...]:
    """Read and evaluate each repository from authoritative exact-main evidence."""
    return scan_fleet_with(GitHubHttpTransport(token), include_central)


def scan_fleet_with(
    transport: GitHubTransport, include_central: bool
) -> tuple[RepositoryResult, ...]:
    """Prove coverage of every discovered consumer, then evaluate each reviewed one."""
    reviewed = tuple(item.name for item in repository_expectations(True))
    uncovered = coverage_results(transport, OWNER, reviewed)
    coverage = tuple(RepositoryResult(item.name, "", item.findings) for item in uncovered)
    expectations = repository_expectations(include_central)
    return coverage + tuple(scan_repository(transport, item) for item in expectations)


def scan_repository(
    transport: GitHubTransport, expectation_: RepositoryExpectation
) -> RepositoryResult:
    """Evaluate one repository, turning unreadable evidence into a failing finding."""
    try:
        snapshot = read_repository(transport, OWNER, expectation_.name)
    except FleetAccessError as error:
        unreadable = finding("evidence-unreadable", "github", str(error))
        return RepositoryResult(expectation_.name, "", (unreadable,))
    findings = validate_repository(snapshot, expectation_)
    return RepositoryResult(snapshot.name, snapshot.sha, findings)
