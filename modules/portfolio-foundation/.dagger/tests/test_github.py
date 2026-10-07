from __future__ import annotations

import asyncio
import http.client
import json
import os
import shutil
import subprocess
import time
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import dagger
import pytest
from pydantic import ValidationError

from portfolio_foundation import github as github_module
from portfolio_foundation.github import (
    APP_ID,
    CHECK_NAME,
    MAX_RUN_START_SKEW_SECONDS,
    WORKFLOW_NAME,
    WORKFLOW_PATH,
    ApiTarget,
    BranchPayload,
    CheckRunsPayload,
    DuplicateGreenCheckError,
    GitHubApiError,
    GitHubCheckRun,
    GitHubCredentialError,
    GitHubNetworkError,
    GitHubPolicyError,
    GitHubResponseError,
    GreenMainDecision,
    HttpPage,
    RepositoryPayload,
    WorkflowRunPayload,
    decide_green_main,
    decide_green_main_from_api,
    parse_branch_response,
    parse_check_runs_response,
    parse_repository_response,
    parse_workflow_response,
    resolve_green_main,
    resolve_green_main_from_api,
    select_green_dagger,
)
from portfolio_foundation.identity import RepositoryRef

MODULE = Path(__file__).parents[2]
REPOSITORY = RepositoryRef("owner", "repository")
SHA = "a" * 40
RUN_ID = 456
SUITE_ID = 321
CREATED_AT = "2026-08-27T00:00:00Z"
RUN_STARTED_AT = "2026-08-27T00:00:01Z"
CHECK_STARTED_AT = "2026-08-27T00:00:02Z"
CHECK_COMPLETED_AT = "2026-08-27T00:00:03Z"
UPDATED_AT = "2026-08-27T00:00:04Z"
LIVE_REPOSITORY = "hseshadr/ci"


def _app(app_id: int = APP_ID) -> dict[str, object]:
    return {"id": app_id}


def _check_payload(
    *,
    check_id: int = 123,
    status: str = "completed",
    conclusion: str | None = "success",
    started_at: str = CHECK_STARTED_AT,
    completed_at: str = CHECK_COMPLETED_AT,
) -> dict[str, object]:
    completion = completed_at if status == "completed" else None
    return {
        "id": check_id,
        "name": CHECK_NAME,
        "head_sha": SHA,
        "status": status,
        "conclusion": conclusion,
        "details_url": f"https://github.com/owner/repository/actions/runs/{RUN_ID}/job/{check_id}",
        "started_at": started_at,
        "completed_at": completion,
        "app": _app(),
        "check_suite": {"id": SUITE_ID},
    }


def _check(**changes: object) -> GitHubCheckRun:
    payload = _check_payload()
    payload.update(changes)
    if payload["status"] != "completed" and "completed_at" not in changes:
        payload["completed_at"] = None
    return GitHubCheckRun.model_validate(payload)


def _repository_payload(**changes: object) -> str:
    payload: dict[str, object] = {"full_name": "owner/repository", "default_branch": "main"}
    payload.update(changes)
    return json.dumps(payload)


def _branch_payload(**changes: object) -> str:
    payload: dict[str, object] = {"name": "main", "commit": {"sha": SHA}}
    payload.update(changes)
    return json.dumps(payload)


def _checks_payload(*checks: dict[str, object], total_count: int | None = None) -> str:
    count = len(checks) if total_count is None else total_count
    return json.dumps({"total_count": count, "check_runs": checks})


def _workflow_payload(**changes: object) -> str:
    payload: dict[str, object] = {
        "id": RUN_ID,
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "head_branch": "main",
        "head_sha": SHA,
        "status": "completed",
        "conclusion": "success",
        "event": "push",
        "run_attempt": 1,
        "created_at": CREATED_AT,
        "updated_at": UPDATED_AT,
        "run_started_at": RUN_STARTED_AT,
        "repository": {"full_name": "owner/repository"},
    }
    payload.update(changes)
    return json.dumps(payload)


def _job_payload(
    *,
    job_id: int = 123,
    status: str = "completed",
    conclusion: str | None = "success",
    run_attempt: int = 1,
    started_at: str = CHECK_STARTED_AT,
) -> str:
    completion = _one_second_after(started_at) if status == "completed" else None
    payload = {
        "id": job_id,
        "run_id": RUN_ID,
        "run_attempt": run_attempt,
        "workflow_name": WORKFLOW_NAME,
        "head_branch": "main",
        "head_sha": SHA,
        "status": status,
        "conclusion": conclusion,
        "name": CHECK_NAME,
        "check_run_url": f"https://api.github.com/repos/owner/repository/check-runs/{job_id}",
        "started_at": started_at,
        "completed_at": completion,
    }
    return json.dumps(payload)


def _one_second_after(timestamp: str) -> str:
    parsed = datetime.fromisoformat(timestamp.removesuffix("Z") + "+00:00")
    completed = (parsed + timedelta(seconds=1)).astimezone(UTC)
    return completed.isoformat().replace("+00:00", "Z")


def _targets() -> tuple[ApiTarget, ApiTarget, ApiTarget, ApiTarget]:
    base = "/repos/owner/repository"
    return (
        ApiTarget(base),
        ApiTarget(f"{base}/branches/main"),
        ApiTarget(f"{base}/commits/{SHA}/check-runs?filter=all&per_page=100&page=1"),
        ApiTarget(f"{base}/actions/runs/{RUN_ID}/attempts/1"),
    )


def _job_target(job_id: int = 123) -> ApiTarget:
    return ApiTarget(f"/repos/owner/repository/actions/jobs/{job_id}")


def _attempt_target(attempt: int = 1) -> ApiTarget:
    return ApiTarget(f"/repos/owner/repository/actions/runs/{RUN_ID}/attempts/{attempt}")


class FakeApi:
    def __init__(self, pages: Mapping[ApiTarget, HttpPage]) -> None:
        self._pages = pages

    async def get(self, target: ApiTarget) -> HttpPage:
        if target in self._pages:
            return self._pages[target]
        marker = "/actions/jobs/"
        if marker in target.value:
            return HttpPage(_job_payload(job_id=int(target.value.rpartition(marker)[2])))
        raise KeyError(target)


class FakeSecret:
    def __init__(self, plaintext: str) -> None:
        self._plaintext = plaintext

    async def plaintext(self) -> str:
        return self._plaintext


class FakeHttpResponse:
    def __init__(
        self,
        status: int,
        body: str = "{}",
        link: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status = status
        self._body = body
        self._link = link
        self._headers = headers or {}

    def read(self) -> bytes:
        return self._body.encode()

    def getheader(self, name: str) -> str | None:
        return self._link if name == "Link" else self._headers.get(name)


type HttpOutcome = FakeHttpResponse | OSError


class FakeHttpConnection:
    def __init__(self, outcomes: list[HttpOutcome], calls: list[tuple[str, str]]) -> None:
        self._outcomes = outcomes
        self._calls = calls

    def request(self, method: str, target: str, *, headers: dict[str, str]) -> None:
        assert headers["Authorization"].startswith("Bearer ")
        self._calls.append((method, target))

    def getresponse(self) -> FakeHttpResponse:
        outcome = self._outcomes.pop(0)
        if isinstance(outcome, OSError):
            raise outcome
        return outcome

    def close(self) -> None:
        return None


def _install_http(
    monkeypatch: pytest.MonkeyPatch, outcomes: Sequence[HttpOutcome]
) -> list[tuple[str, str]]:
    calls: list[tuple[str, str]] = []
    queue = list(outcomes)

    def factory(_: str, *, timeout: float) -> FakeHttpConnection:
        assert timeout == 10.0
        return FakeHttpConnection(queue, calls)

    monkeypatch.setattr(http.client, "HTTPSConnection", factory)
    monkeypatch.setattr(time, "sleep", lambda _: None)
    return calls


@dataclass(frozen=True)
class ApiOverrides:
    repository: str | None = None
    branch: str | None = None
    checks: str | None = None
    workflow: str | None = None
    job: str | None = None
    link: str | None = None


def _api(overrides: ApiOverrides | None = None) -> FakeApi:
    overrides = overrides or ApiOverrides()
    repo_target, branch_target, checks_target, workflow_target = _targets()
    return FakeApi(
        {
            repo_target: HttpPage(overrides.repository or _repository_payload()),
            branch_target: HttpPage(overrides.branch or _branch_payload()),
            checks_target: HttpPage(
                overrides.checks or _checks_payload(_check_payload()), overrides.link
            ),
            _job_target(): HttpPage(overrides.job or _job_payload()),
            workflow_target: HttpPage(overrides.workflow or _workflow_payload()),
        }
    )


@pytest.mark.parametrize("conclusion", [None, "", "failure", "cancelled", "skipped"])
def test_should_not_accept_non_green_check(conclusion: str | None) -> None:
    # Given
    evidence = _check(status="in_progress", conclusion=conclusion)

    # When / Then
    assert select_green_dagger((evidence,), SHA) is None


def test_should_parse_nullable_conclusion_without_boundary_failure() -> None:
    # Given / When
    payload = CheckRunsPayload.model_validate(
        {"total_count": 1, "check_runs": (_check(conclusion=None).model_dump(),)}
    )

    # Then
    assert payload.check_runs[0].conclusion is None


def test_should_reject_green_check_from_wrong_app() -> None:
    # Given / When / Then
    assert select_green_dagger((_check(app={"id": 85455}),), SHA) is None


def test_should_reject_stale_or_wrong_named_green_check() -> None:
    # Given
    checks = (_check(head_sha="b" * 40), _check(name="Dagger fleet policy"))

    # When / Then
    assert select_green_dagger(checks, SHA) is None


@pytest.mark.parametrize("status", ("in_progress", "completed"))
def test_should_reject_old_success_when_newer_required_check_is_not_green(status: str) -> None:
    # Given
    conclusion = None if status == "in_progress" else "failure"
    old = _check(id=122, started_at="2026-08-27T00:00:01Z")
    newer = _check(id=123, status=status, conclusion=conclusion)
    checks = (old, newer)

    # When / Then
    assert select_green_dagger(checks, SHA) is None


def test_should_reject_duplicate_green_checks() -> None:
    # Given / When / Then
    with pytest.raises(DuplicateGreenCheckError, match="ambiguous"):
        select_green_dagger((_check(), _check(id=124)), SHA)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (RepositoryPayload, {"full_name": "owner/repository", "default_branch": "main"}),
        (BranchPayload, {"name": "main", "commit": {"sha": SHA}}),
        (CheckRunsPayload, {"total_count": 0, "check_runs": []}),
        (WorkflowRunPayload, json.loads(_workflow_payload())),
    ],
)
def test_should_reject_unknown_external_response_fields(
    model: type[RepositoryPayload | BranchPayload | CheckRunsPayload | WorkflowRunPayload],
    payload: dict[str, object],
) -> None:
    # Given
    payload["unexpected"] = "value"

    # When / Then
    with pytest.raises(ValidationError, match="extra_forbidden"):
        model.model_validate(payload)


def test_should_keep_external_models_frozen() -> None:
    # Given
    payload = RepositoryPayload.model_validate(
        {"full_name": "owner/repository", "default_branch": "main"}
    )

    # When / Then
    with pytest.raises(ValidationError, match="frozen_instance"):
        payload.default_branch = "develop"


def test_should_project_documented_fields_from_realistic_provider_payloads() -> None:
    # Given
    repository = _repository_payload(id=1, url="https://api.github.com/repos/owner/repository")
    checks = json.loads(_checks_payload(_check_payload()))
    checks["check_runs"][0]["node_id"] = "node"

    # When / Then
    assert parse_repository_response(repository).full_name == "owner/repository"
    assert parse_branch_response(_branch_payload(protected=True)).commit.sha == SHA
    assert parse_check_runs_response(json.dumps(checks)).check_runs[0].app.id == APP_ID
    workflow = parse_workflow_response(_workflow_payload(created_at="2026-08-27T00:00:00Z"))
    assert workflow.id == RUN_ID


@pytest.mark.parametrize(
    "raw",
    ("not-json", "[]", "{}", '{"full_name": 3, "default_branch": "main"}'),
)
def test_should_sanitize_malformed_repository_responses(raw: str) -> None:
    # Given / When / Then
    with pytest.raises(GitHubResponseError, match="required schema"):
        parse_repository_response(raw)


@pytest.mark.parametrize("raw", ('{"check_runs": {}}', '{"check_runs": []}'))
def test_should_sanitize_malformed_check_pages(raw: str) -> None:
    # Given / When / Then
    with pytest.raises(GitHubResponseError, match="required schema"):
        parse_check_runs_response(raw)


def test_should_reject_nonpositive_authoritative_provider_identity() -> None:
    # Given
    check = _check_payload()
    check["check_suite"] = {"id": 0}

    # When / Then
    with pytest.raises(GitHubResponseError, match="required schema"):
        parse_check_runs_response(_checks_payload(check))


def test_should_reject_api_target_outside_fixed_read_only_queries() -> None:
    # Given / When / Then
    with pytest.raises(GitHubPolicyError, match="read-only contract"):
        ApiTarget("/user/repos")


def test_should_use_get_and_return_only_response_body_and_link(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    link = '<https://api.github.com/repos/owner/repository?page=2>; rel="next"'
    calls = _install_http(monkeypatch, [FakeHttpResponse(http.client.OK, "{}", link)])
    api = github_module._GitHubRestApi("private-value")

    # When
    page = asyncio.run(api.get(ApiTarget("/repos/owner/repository")))

    # Then
    assert page == HttpPage("{}", link)
    assert calls == [("GET", "/repos/owner/repository")]
    assert "private-value" not in page.body + (page.link or "")


@pytest.mark.parametrize("status", (http.client.UNAUTHORIZED, http.client.FORBIDDEN))
def test_should_classify_rejected_credentials_without_response_leak(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    # Given
    _install_http(monkeypatch, [FakeHttpResponse(status, "provider-secret-body")])
    api = github_module._GitHubRestApi("private-value")

    # When / Then
    with pytest.raises(GitHubCredentialError, match="credential was rejected"):
        asyncio.run(api.get(ApiTarget("/repos/owner/repository")))


def test_should_retry_transient_status_then_return_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    outcomes = [FakeHttpResponse(http.client.INTERNAL_SERVER_ERROR), FakeHttpResponse(200)]
    calls = _install_http(monkeypatch, outcomes)

    # When
    page = asyncio.run(
        github_module._GitHubRestApi("private-value").get(ApiTarget("/repos/owner/repository"))
    )

    # Then
    assert page.body == "{}"
    assert len(calls) == 2


def test_should_retry_primary_rate_limit_403(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    limited = FakeHttpResponse(
        http.client.FORBIDDEN,
        headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"},
    )
    calls = _install_http(monkeypatch, [limited, FakeHttpResponse(http.client.OK)])

    # When
    page = asyncio.run(
        github_module._GitHubRestApi("private-value").get(ApiTarget("/repos/owner/repository"))
    )

    # Then
    assert page.body == "{}"
    assert len(calls) == 2


@pytest.mark.parametrize(
    "headers",
    (
        {"Retry-After": "0"},
        {"Retry-After": "malformed"},
        {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "malformed"},
    ),
)
def test_should_retry_secondary_or_malformed_rate_limit_hints(
    monkeypatch: pytest.MonkeyPatch, headers: dict[str, str]
) -> None:
    # Given
    limited = FakeHttpResponse(http.client.FORBIDDEN, headers=headers)
    calls = _install_http(monkeypatch, [limited, FakeHttpResponse(http.client.OK)])

    # When
    page = asyncio.run(
        github_module._GitHubRestApi("private-value").get(ApiTarget("/repos/owner/repository"))
    )

    # Then
    assert page.body == "{}"
    assert len(calls) == 2


@pytest.mark.parametrize(
    ("status", "headers"),
    (
        (http.client.TOO_MANY_REQUESTS, {"Retry-After": "9999"}),
        (
            http.client.FORBIDDEN,
            {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "99999999999"},
        ),
    ),
)
def test_should_cap_oversized_rate_limit_hint(
    monkeypatch: pytest.MonkeyPatch, status: int, headers: dict[str, str]
) -> None:
    # Given
    sleeps: list[float] = []
    limited = FakeHttpResponse(status, headers=headers)
    _install_http(monkeypatch, [limited, FakeHttpResponse(http.client.OK)])
    monkeypatch.setattr(time, "sleep", sleeps.append)

    # When
    page = asyncio.run(
        github_module._GitHubRestApi("private-value").get(ApiTarget("/repos/owner/repository"))
    )

    # Then
    assert page.body == "{}"
    assert sleeps == [1.0]


def test_should_bound_total_rate_limit_wait_and_sanitize_exhaustion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    sleeps: list[float] = []
    limited = [
        FakeHttpResponse(http.client.FORBIDDEN, headers={"Retry-After": "1"}) for _ in range(3)
    ]
    _install_http(monkeypatch, limited)
    monkeypatch.setattr(time, "sleep", sleeps.append)

    # When / Then
    with pytest.raises(GitHubApiError, match="API request failed") as error:
        asyncio.run(
            github_module._GitHubRestApi("private-value").get(ApiTarget("/repos/owner/repository"))
        )
    assert sleeps == [1.0, 1.0]
    assert "private-value" not in str(error.value)


@pytest.mark.parametrize(
    ("outcomes", "error"),
    [
        ([FakeHttpResponse(429) for _ in range(3)], GitHubApiError),
        ([OSError("private provider detail") for _ in range(3)], GitHubNetworkError),
    ],
)
def test_should_stop_after_bounded_provider_retries(
    monkeypatch: pytest.MonkeyPatch,
    outcomes: list[HttpOutcome],
    error: type[GitHubApiError | GitHubNetworkError],
) -> None:
    # Given
    _install_http(monkeypatch, outcomes)
    api = github_module._GitHubRestApi("private-value")

    # When / Then
    with pytest.raises(error):
        asyncio.run(api.get(ApiTarget("/repos/owner/repository")))


def test_should_reject_non_retryable_provider_status_without_body_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    _install_http(monkeypatch, [FakeHttpResponse(http.client.NOT_FOUND, "private detail")])

    # When / Then
    with pytest.raises(GitHubApiError, match="API request failed"):
        asyncio.run(
            github_module._GitHubRestApi("private-value").get(ApiTarget("/repos/owner/repository"))
        )


def test_should_reject_empty_typed_secret_before_provider_request() -> None:
    # Given
    secret = cast(dagger.Secret, FakeSecret(""))

    # When / Then
    with pytest.raises(GitHubCredentialError, match="credential was rejected"):
        asyncio.run(resolve_green_main(secret, REPOSITORY))


def test_should_keep_typed_secret_out_of_returned_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.setattr(github_module, "_GitHubRestApi", lambda _: _api())
    secret = cast(dagger.Secret, FakeSecret("private-value"))

    # When
    evidence = asyncio.run(resolve_green_main(secret, REPOSITORY))

    # Then
    assert "private-value" not in repr(evidence)


def test_should_resolve_exact_main_and_app_bound_workflow_evidence() -> None:
    # Given / When
    evidence = asyncio.run(resolve_green_main_from_api(_api(), REPOSITORY))

    # Then
    assert evidence.repository == "owner/repository"
    assert evidence.branch == "main"
    assert evidence.commit_sha == SHA
    assert evidence.workflow_name == WORKFLOW_NAME
    assert evidence.workflow_path == WORKFLOW_PATH
    assert evidence.check_name == CHECK_NAME
    assert evidence.check_run_id == "123"
    assert evidence.workflow_run_id == str(RUN_ID)
    assert evidence.app_id == APP_ID
    assert evidence.check_suite_id == str(SUITE_ID)
    assert evidence.workflow_job_id == "123"
    assert evidence.run_attempt == 1
    serialized = json.loads(evidence.serialization())
    assert serialized["check_run_id"] == "123"
    assert serialized["workflow_run_id"] == str(RUN_ID)
    assert serialized["run_attempt"] == 1


def test_should_reject_evidence_when_main_moves_during_resolution() -> None:
    # Given
    branch_target = _targets()[1]
    api = _api()
    original_get = api.get
    samples = iter(
        (HttpPage(_branch_payload()), HttpPage(_branch_payload(commit={"sha": "b" * 40})))
    )

    async def moving_get(target: ApiTarget) -> HttpPage:
        return next(samples) if target == branch_target else await original_get(target)

    api.get = moving_get  # type: ignore[method-assign]

    # When / Then
    with pytest.raises(GitHubPolicyError, match="main moved"):
        asyncio.run(resolve_green_main_from_api(api, REPOSITORY))


def test_should_reject_completed_attempt_with_reversed_timestamps() -> None:
    # Given
    completed_before_start = "2026-08-27T00:00:01Z"
    job = json.loads(_job_payload())
    job["completed_at"] = completed_before_start
    checks = _checks_payload(_check_payload(completed_at=completed_before_start))
    api = _api(ApiOverrides(checks=checks, job=json.dumps(job)))

    # When / Then
    with pytest.raises(GitHubPolicyError, match="timestamps"):
        asyncio.run(resolve_green_main_from_api(api, REPOSITORY))


# Real payload: GET repos/hseshadr/aml-filter/actions/runs/36033566429/attempts/2.
# GitHub stamps a rerun attempt's created_at one second after its run_started_at.
RERUN_CREATED_AT = "2026-09-24T17:22:33Z"
RERUN_STARTED_AT = "2026-09-24T17:22:32Z"
RERUN_UPDATED_AT = "2026-09-24T17:43:06Z"
RERUN_CHECK_STARTED_AT = "2026-09-24T17:22:40Z"


def _rerun_timestamp_api(created_at: str, started_at: str, updated_at: str) -> FakeApi:
    workflow = _workflow_payload(
        created_at=created_at, run_started_at=started_at, updated_at=updated_at
    )
    check = _check_payload(
        started_at=RERUN_CHECK_STARTED_AT,
        completed_at=_one_second_after(RERUN_CHECK_STARTED_AT),
    )
    job = _job_payload(started_at=RERUN_CHECK_STARTED_AT)
    return _api(ApiOverrides(checks=_checks_payload(check), job=job, workflow=workflow))


def test_should_pin_run_start_skew_bound_to_five_seconds() -> None:
    # Given / When / Then
    assert MAX_RUN_START_SKEW_SECONDS == 5


def test_should_accept_rerun_attempt_created_one_second_after_it_started() -> None:
    # Given
    api = _rerun_timestamp_api(RERUN_CREATED_AT, RERUN_STARTED_AT, RERUN_UPDATED_AT)

    # When
    evidence = asyncio.run(resolve_green_main_from_api(api, REPOSITORY))

    # Then
    assert evidence.commit_sha == SHA


def test_should_reject_run_created_beyond_skew_bound_after_start() -> None:
    # Given
    created_six_seconds_after_start = "2026-09-24T17:22:38Z"
    api = _rerun_timestamp_api(created_six_seconds_after_start, RERUN_STARTED_AT, RERUN_UPDATED_AT)

    # When / Then
    with pytest.raises(GitHubPolicyError, match="workflow timestamps are inconsistent"):
        asyncio.run(resolve_green_main_from_api(api, REPOSITORY))


def test_should_reject_run_started_after_it_was_updated() -> None:
    # Given
    updated_before_start = "2026-09-24T17:22:31Z"
    api = _rerun_timestamp_api(RERUN_CREATED_AT, RERUN_STARTED_AT, updated_before_start)

    # When / Then
    with pytest.raises(GitHubPolicyError, match="workflow timestamps are inconsistent"):
        asyncio.run(resolve_green_main_from_api(api, REPOSITORY))


@pytest.mark.parametrize(
    ("status", "conclusion"),
    [
        ("in_progress", None),
        ("completed", "failure"),
        ("completed", "cancelled"),
        ("completed", "skipped"),
    ],
)
def test_should_reject_old_success_when_newer_rerun_is_not_green(
    status: str, conclusion: str | None
) -> None:
    # Given
    api = _rerun_api(status, conclusion)

    # When / Then
    with pytest.raises(GitHubPolicyError, match=r"latest.*not successful"):
        asyncio.run(resolve_green_main_from_api(api, REPOSITORY))


def _rerun_api(status: str, conclusion: str | None) -> FakeApi:
    repo, branch, checks, first_attempt = _targets()
    second_page = ApiTarget(
        f"/repos/owner/repository/commits/{SHA}/check-runs?filter=all&per_page=100&page=2"
    )
    link = f'<https://api.github.com{second_page.value}>; rel="next"'
    old = _check_payload(check_id=122, started_at="2026-08-27T00:00:02Z")
    new = _check_payload(
        status=status,
        conclusion=conclusion,
        started_at="2026-08-27T00:01:02Z",
        completed_at="2026-08-27T00:01:03Z",
    )
    return FakeApi(
        {
            repo: HttpPage(_repository_payload()),
            branch: HttpPage(_branch_payload()),
            checks: HttpPage(_checks_payload(old, total_count=2), link),
            second_page: HttpPage(_checks_payload(new, total_count=2)),
            _job_target(122): HttpPage(_job_payload(job_id=122)),
            _job_target(): HttpPage(
                _job_payload(
                    status=status,
                    conclusion=conclusion,
                    run_attempt=2,
                    started_at="2026-08-27T00:01:02Z",
                )
            ),
            first_attempt: HttpPage(_workflow_payload()),
            _attempt_target(2): HttpPage(
                _workflow_payload(
                    status=status,
                    conclusion=conclusion,
                    run_attempt=2,
                    run_started_at="2026-08-27T00:01:01Z",
                    updated_at="2026-08-27T00:01:04Z",
                )
            ),
        }
    )


@pytest.mark.parametrize(
    ("api", "message"),
    [
        (
            _api(ApiOverrides(repository=_repository_payload(full_name="foreign/repository"))),
            "repository",
        ),
        (
            _api(ApiOverrides(repository=_repository_payload(default_branch="develop"))),
            "default branch",
        ),
        (_api(ApiOverrides(branch=_branch_payload(name="develop"))), "branch"),
        (_api(ApiOverrides(branch=_branch_payload(commit={"sha": "short"}))), "full SHA"),
        (
            _api(ApiOverrides(checks=_checks_payload(_check_payload() | {"head_sha": "b" * 40}))),
            "count",
        ),
        (
            _api(ApiOverrides(checks=_checks_payload(_check_payload() | {"app": _app(85455)}))),
            "count",
        ),
        (_api(ApiOverrides(job=_job_payload(job_id=124))), "job identity"),
        (
            _api(ApiOverrides(job=_job_payload(started_at="2026-08-27T00:00:03Z"))),
            "job identity",
        ),
        (_api(ApiOverrides(workflow=_workflow_payload(head_branch="feature"))), "workflow"),
        (_api(ApiOverrides(workflow=_workflow_payload(head_sha="b" * 40))), "workflow"),
        (
            _api(ApiOverrides(workflow=_workflow_payload(path=".github/workflows/other.yml"))),
            "workflow",
        ),
        (_api(ApiOverrides(workflow=_workflow_payload(run_attempt=2))), "workflow"),
        (_api(ApiOverrides(workflow=_workflow_payload(event="pull_request"))), "workflow"),
        (
            _api(ApiOverrides(workflow=_workflow_payload(status="in_progress", conclusion=None))),
            "workflow",
        ),
        (
            _api(ApiOverrides(workflow=_workflow_payload(updated_at="2026-08-26T23:59:59Z"))),
            "timestamps",
        ),
        (
            _api(
                ApiOverrides(
                    workflow=_workflow_payload(repository={"full_name": "foreign/repository"})
                )
            ),
            "workflow",
        ),
    ],
)
def test_should_fail_closed_when_exact_policy_binding_differs(api: FakeApi, message: str) -> None:
    # Given / When / Then
    with pytest.raises(GitHubPolicyError, match=message):
        asyncio.run(resolve_green_main_from_api(api, REPOSITORY))


def test_should_follow_official_link_pagination_to_green_check() -> None:
    # Given
    repo, branch, checks, workflow = _targets()
    second = ApiTarget(
        f"/repos/owner/repository/commits/{SHA}/check-runs?filter=all&per_page=100&page=2"
    )
    link = f'<https://api.github.com{second.value}>; rel="next"'
    api = FakeApi(
        {
            repo: HttpPage(_repository_payload()),
            branch: HttpPage(_branch_payload()),
            checks: HttpPage(
                _checks_payload(
                    _check_payload(check_id=122, status="in_progress", conclusion=None),
                    total_count=2,
                ),
                link,
            ),
            second: HttpPage(
                _checks_payload(
                    _check_payload(
                        started_at="2026-08-27T00:01:02Z",
                        completed_at="2026-08-27T00:01:03Z",
                    ),
                    total_count=2,
                )
            ),
            _job_target(122): HttpPage(
                _job_payload(job_id=122, status="in_progress", conclusion=None)
            ),
            _job_target(): HttpPage(
                _job_payload(
                    run_attempt=2,
                    started_at="2026-08-27T00:01:02Z",
                )
            ),
            workflow: HttpPage(_workflow_payload()),
            _attempt_target(2): HttpPage(
                _workflow_payload(
                    run_attempt=2,
                    run_started_at="2026-08-27T00:01:01Z",
                    updated_at="2026-08-27T00:01:04Z",
                )
            ),
        }
    )

    # When
    evidence = asyncio.run(resolve_green_main_from_api(api, REPOSITORY))

    # Then
    assert evidence.commit_sha == SHA


@pytest.mark.parametrize("second_total", (3, 2))
def test_should_reject_inconsistent_or_duplicate_check_pages(second_total: int) -> None:
    # Given
    repo, branch, checks, workflow = _targets()
    second = ApiTarget(
        f"/repos/owner/repository/commits/{SHA}/check-runs?filter=all&per_page=100&page=2"
    )
    link = f'<https://api.github.com{second.value}>; rel="next"'
    first_check = _check_payload(status="in_progress")
    second_check = _check_payload(check_id=124 if second_total == 3 else 123)
    api = FakeApi(
        {
            repo: HttpPage(_repository_payload()),
            branch: HttpPage(_branch_payload()),
            checks: HttpPage(_checks_payload(first_check, total_count=2), link),
            second: HttpPage(_checks_payload(second_check, total_count=second_total)),
            workflow: HttpPage(_workflow_payload()),
        }
    )

    # When / Then
    with pytest.raises(GitHubPolicyError, match=r"count|duplicate"):
        asyncio.run(resolve_green_main_from_api(api, REPOSITORY))


def test_should_reject_foreign_pagination_origin() -> None:
    # Given
    target = f"/repos/owner/repository/commits/{SHA}/check-runs"
    link = f'<https://attacker.invalid{target}?filter=all&per_page=100&page=2>; rel="next"'

    # When / Then
    with pytest.raises(GitHubPolicyError, match="pagination"):
        asyncio.run(resolve_green_main_from_api(_api(ApiOverrides(link=link)), REPOSITORY))


def test_should_reject_nonsequential_pagination() -> None:
    # Given
    target = f"/repos/owner/repository/commits/{SHA}/check-runs"
    link = f'<https://api.github.com{target}?filter=all&per_page=100&page=3>; rel="next"'

    # When / Then
    with pytest.raises(GitHubPolicyError, match="sequence"):
        asyncio.run(resolve_green_main_from_api(_api(ApiOverrides(link=link)), REPOSITORY))


def test_should_reject_truncated_check_pagination() -> None:
    # Given
    checks = _checks_payload(_check_payload(), total_count=2)

    # When / Then
    with pytest.raises(GitHubPolicyError, match="count"):
        asyncio.run(resolve_green_main_from_api(_api(ApiOverrides(checks=checks)), REPOSITORY))


def test_should_reject_check_details_outside_exact_repository_workflow() -> None:
    # Given
    checks = _checks_payload(
        _check_payload()
        | {"details_url": f"https://github.com/foreign/repository/actions/runs/{RUN_ID}/job/789"}
    )

    # When / Then
    with pytest.raises(GitHubPolicyError, match="details URL"):
        asyncio.run(resolve_green_main_from_api(_api(ApiOverrides(checks=checks)), REPOSITORY))


def test_should_reject_duplicate_green_across_pages() -> None:
    # Given
    repo, branch, checks, workflow = _targets()
    second = ApiTarget(
        f"/repos/owner/repository/commits/{SHA}/check-runs?filter=all&per_page=100&page=2"
    )
    link = f'<https://api.github.com{second.value}>; rel="next"'
    api = FakeApi(
        {
            repo: HttpPage(_repository_payload()),
            branch: HttpPage(_branch_payload()),
            checks: HttpPage(_checks_payload(_check_payload(), total_count=2), link),
            second: HttpPage(_checks_payload(_check_payload(check_id=124), total_count=2)),
            workflow: HttpPage(_workflow_payload()),
        }
    )

    # When / Then
    with pytest.raises(DuplicateGreenCheckError):
        asyncio.run(resolve_green_main_from_api(api, REPOSITORY))


def test_should_distinguish_sanitized_transport_and_credential_errors() -> None:
    # Given / When / Then
    assert str(GitHubNetworkError()) == "GitHub network request failed"
    assert str(GitHubCredentialError()) == "GitHub credential was rejected"
    assert "token" not in str(GitHubApiError()).lower()


def test_should_declare_supported_pydantic_v2_dependency() -> None:
    # Given
    config = tomllib.loads((MODULE / ".dagger/pyproject.toml").read_text())

    # When
    dependencies = config["project"]["dependencies"]

    # Then
    assert "pydantic>=2.11,<3" in dependencies


class RecordingApi:
    """Wrap a fake API and record every target the policy reads."""

    def __init__(self, inner: FakeApi) -> None:
        self._inner = inner
        self.targets: list[ApiTarget] = []

    async def get(self, target: ApiTarget) -> HttpPage:
        self.targets.append(target)
        return await self._inner.get(target)


NEWER = "b" * 40
OLDER = "c" * 40


def _decide(api: FakeApi | RecordingApi, requested: str = SHA) -> GreenMainDecision:
    return asyncio.run(decide_green_main_from_api(api, REPOSITORY, requested))


def _moving_main_api(after: str) -> FakeApi:
    branch_target = _targets()[1]
    api = _api()
    original_get = api.get
    samples = iter((HttpPage(_branch_payload()), HttpPage(_branch_payload(commit={"sha": after}))))

    async def moving_get(target: ApiTarget) -> HttpPage:
        return next(samples) if target == branch_target else await original_get(target)

    api.get = moving_get  # type: ignore[method-assign]
    return api


def test_should_deploy_requested_commit_when_it_is_green_main_head() -> None:
    # Given / When
    decision = _decide(_api())

    # Then
    assert decision.action == "deploy"
    assert decision.commit_sha == decision.main_sha == SHA
    assert decision.evidence is not None
    assert decision.evidence.commit_sha == SHA
    serialized = json.loads(decision.serialization())
    assert serialized["action"] == "deploy"
    assert serialized["evidence"]["commit_sha"] == SHA
    assert serialized["evidence"]["workflow_run_id"] == str(RUN_ID)


@pytest.mark.parametrize("conclusion", ("failure", "cancelled", None))
def test_should_fail_when_main_head_dagger_attempt_is_not_green(conclusion: str | None) -> None:
    # Given
    status = "in_progress" if conclusion is None else "completed"
    checks = _checks_payload(_check_payload(status=status, conclusion=conclusion))

    # When / Then
    with pytest.raises(GitHubPolicyError):
        _decide(_api(ApiOverrides(checks=checks)))


def test_should_fail_when_main_head_has_no_dagger_check() -> None:
    # Given
    api = _api(ApiOverrides(checks=_checks_payload()))

    # When / Then
    with pytest.raises(GitHubPolicyError, match="outside bounds"):
        _decide(api)


def test_should_skip_without_reading_checks_when_requested_commit_is_superseded() -> None:
    # Given: main HEAD is NEWER, the deploy asks for the older SHA.
    api = RecordingApi(_api(ApiOverrides(branch=_branch_payload(commit={"sha": NEWER}))))

    # When
    decision = _decide(api, SHA)

    # Then
    assert decision.action == "skip"
    assert decision.commit_sha == SHA
    assert decision.main_sha == NEWER
    assert decision.evidence is None
    assert f"superseded by {NEWER}" in decision.message
    assert "newer commit's deploy will ship it" in decision.message
    assert not any("/check-runs" in target.value for target in api.targets)
    serialized = json.loads(decision.serialization())
    assert serialized == {
        "action": "skip",
        "commit_sha": SHA,
        "evidence": None,
        "main_sha": NEWER,
        "message": decision.message,
    }


def test_should_skip_when_main_moves_off_requested_commit_during_resolution() -> None:
    # Given / When
    decision = _decide(_moving_main_api(NEWER))

    # Then
    assert decision.action == "skip"
    assert decision.main_sha == NEWER
    assert decision.evidence is None


def test_should_reject_malformed_requested_commit_before_provider_reads() -> None:
    # Given
    api = RecordingApi(_api())

    # When / Then
    with pytest.raises(GitHubPolicyError, match="requested commit"):
        _decide(api, "abc")
    assert api.targets == []


@pytest.mark.parametrize("main_head", (NEWER, OLDER))
@pytest.mark.parametrize("head_green", (True, False))
def test_should_never_authorize_a_commit_other_than_main_head(
    main_head: str, head_green: bool
) -> None:
    # Given: whatever main's HEAD and its Dagger state, the deploy asks for SHA.
    checks = None if head_green else _checks_payload(_check_payload(conclusion="failure"))
    branch = _branch_payload(commit={"sha": main_head})
    api = _api(ApiOverrides(branch=branch, checks=checks))

    # When
    decision = _decide(api, SHA)

    # Then: no deployable evidence can exist for a non-HEAD commit.
    assert decision.action == "skip"
    assert decision.evidence is None
    assert json.loads(decision.serialization())["evidence"] is None


def test_should_bind_deploy_evidence_to_the_requested_head_commit_only() -> None:
    # Given / When
    decision = _decide(_api())

    # Then: the only deployable decision names the requested SHA everywhere.
    assert decision.evidence is not None
    identities = {decision.commit_sha, decision.main_sha, decision.evidence.commit_sha}
    assert identities == {SHA}


def test_should_decide_through_typed_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given
    monkeypatch.setattr(github_module, "_GitHubRestApi", lambda _: _api())
    secret = cast(dagger.Secret, FakeSecret("private-value"))

    # When
    decision = asyncio.run(decide_green_main(secret, REPOSITORY, SHA))

    # Then
    assert decision.action == "deploy"
    assert "private-value" not in str(decision.serialization())


@pytest.mark.skipif(os.environ.get("RUN_LIVE_GITHUB") != "1", reason="explicit live test")
def test_should_resolve_one_stable_live_evidence_object_through_typed_secret() -> None:
    # Given
    gh, git, dagger_cli = _executable("gh"), _executable("git"), _executable("dagger")
    token = subprocess.run(  # noqa: S603 - fixed read-only credential lookup
        [gh, "auth", "token"], check=True, capture_output=True, text=True
    ).stdout.strip()
    environment = os.environ | {"GITHUB_TOKEN": token}

    # When
    before = _remote_main(git)
    result = _call_green_serialization(dagger_cli, environment)
    after = _remote_main(git)

    # Then
    assert result.returncode == 0, _classified_live_error(result.stderr, token)
    evidence = json.loads(result.stdout)
    assert before == after == evidence["commit_sha"]
    assert evidence["repository"] == LIVE_REPOSITORY
    assert evidence["branch"] == "main"
    assert evidence["check_name"] == CHECK_NAME
    assert evidence["workflow_name"] == WORKFLOW_NAME
    assert evidence["app_id"] == APP_ID
    assert evidence["run_attempt"] >= 1
    assert evidence["check_run_id"] == evidence["workflow_job_id"]
    assert token not in result.stdout + result.stderr
    assert "greenMain CACHED" not in result.stderr
    assert result.stderr.count("PortfolioFoundation.greenMain(") == 1


def _call_green_serialization(
    dagger_cli: str, environment: dict[str, str]
) -> subprocess.CompletedProcess[str]:
    command = [
        dagger_cli,
        "-m",
        str(MODULE),
        "call",
        "green-main",
        "--github-token=env:GITHUB_TOKEN",
        f"--repository={LIVE_REPOSITORY}",
        "serialization",
    ]
    return subprocess.run(  # noqa: S603 - fixed read-only integration command
        command, cwd=MODULE, env=environment, capture_output=True, text=True, check=False
    )


def _remote_main(git: str) -> str:
    result = subprocess.run(  # noqa: S603 - fixed read-only Git query
        [git, "ls-remote", "origin", "refs/heads/main"],
        cwd=MODULE,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.split()[0]


def _classified_live_error(stderr: str, token: str) -> str:
    sanitized = stderr.replace(token, "[REDACTED]")
    if "credential was rejected" in sanitized:
        category = "credential"
    elif "network request failed" in sanitized:
        category = "network"
    else:
        category = "policy/provider"
    return f"live GitHub {category} failure: {sanitized}"


def _executable(name: str) -> str:
    executable = shutil.which(name)
    if executable is None:
        pytest.fail(f"required integration executable is unavailable: {name}")
    return executable
