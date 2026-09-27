"""Production rollback policy: explicit targets, refusals, and verified convergence."""

from __future__ import annotations

import ast
import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, cast

import dagger
import pytest

import cloudflare_pages.main as main_module
from cloudflare_pages.api import (
    CloudflareApiError,
    CloudflarePolicyError,
    live_production_deployment,
    rollback_production,
)
from cloudflare_pages.main import CurlRollbackOperations
from cloudflare_pages.models import RollbackEvidence

PROJECT: Final = "edge-reco"
PROJECT_ID: Final = "7b162ea7-7367-4d4a-a28a-cb84f88f6"
LIVE: Final = "11111111"
PREVIOUS: Final = "22222222"
FAILED: Final = "33333333"
OLDER: Final = "44444444"
SECRET_TYPE: Final = "dagger." + "Secret"
BOUNDED_DELAYS: Final = ["sleep:1", "sleep:2", "sleep:4", "sleep:8"]
FINAL_DELAY_SECONDS: Final = 8
ESCAPE_HATCHES: Final = frozenset({"url", "origin", "command", "cmd", "script"})
ROLLBACK_FUNCTIONS: Final = frozenset({"rollback", "previous_production_deployment"})

type CloudflareError = CloudflareApiError | CloudflarePolicyError


def _id(short_id: str) -> str:
    return f"{short_id}-0000-4000-8000-000000000000"


def _url(short_id: str) -> str:
    return f"https://{short_id}.{PROJECT}.pages.dev"


def _secret() -> dagger.Secret:
    return cast(dagger.Secret, object())


@dataclass(frozen=True)
class Row:
    """One provider deployment-list row, serialized only at the JSON boundary."""

    short_id: str
    status: str = "success"
    environment: str = "production"
    stage: str = "deploy"
    project_id: str = PROJECT_ID

    def payload(self) -> dict[str, object]:
        metadata = {"branch": "main", "commit_hash": "", "commit_dirty": False}
        return {
            "id": _id(self.short_id),
            "short_id": self.short_id,
            "url": _url(self.short_id),
            "project_id": self.project_id,
            "project_name": PROJECT,
            "environment": self.environment,
            "latest_stage": {"name": self.stage, "status": self.status},
            "deployment_trigger": {"type": "ad_hoc", "metadata": metadata},
        }


def _envelope(result: object) -> dict[str, object]:
    return {"errors": [], "messages": [], "success": True, "result": result}


def _project(canonical: str | None, name: str = PROJECT) -> str:
    live = None if canonical is None else {"id": _id(canonical)}
    result = {
        "id": PROJECT_ID,
        "name": name,
        "production_branch": "main",
        "domains": [f"{PROJECT}.pages.dev"],
        "source": None,
        "canonical_deployment": live,
    }
    return json.dumps(_envelope(result))


def _deployments(rows: tuple[Row, ...]) -> str:
    info = {"count": len(rows), "page": 1, "per_page": 10, "total_count": 30, "total_pages": 3}
    payload = _envelope([row.payload() for row in rows])
    return json.dumps(payload | {"result_info": info})


def _rollback_response(short_id: str) -> str:
    return json.dumps(_envelope(Row(short_id).payload()))


def _history() -> tuple[Row, ...]:
    return (Row(LIVE), Row(FAILED, status="failure"), Row(PREVIOUS), Row(OLDER))


@dataclass
class FakeRollbackOperations:
    """Stubbed Pages API that switches production only when told to converge."""

    rows: tuple[Row, ...] = field(default_factory=_history)
    live: str | None = LIVE
    converge: bool = True
    project_name: str = PROJECT
    rollback_error: CloudflareError | None = None
    response_id: str | None = None
    events: list[str] = field(default_factory=list)

    async def get_project(self) -> str:
        self.events.append("get-project")
        return _project(self.live, self.project_name)

    async def get_deployments(self) -> str:
        self.events.append("get-deployments")
        return _deployments(self.rows)

    async def rollback(self, deployment_id: str) -> str:
        self.events.append(f"rollback:{deployment_id}")
        if self.rollback_error is not None:
            raise self.rollback_error
        short_id = deployment_id.split("-", maxsplit=1)[0]
        if self.converge:
            self.live = short_id
        return _rollback_response(self.response_id or short_id)

    async def sleep(self, seconds: int) -> None:
        self.events.append(f"sleep:{seconds}")


@dataclass
class DelayedOperations(FakeRollbackOperations):
    """Production switches only after the first verification read."""

    pending: str | None = None

    async def rollback(self, deployment_id: str) -> str:
        self.events.append(f"rollback:{deployment_id}")
        self.pending = deployment_id.split("-", maxsplit=1)[0]
        return _rollback_response(self.pending)

    async def sleep(self, seconds: int) -> None:
        self.events.append(f"sleep:{seconds}")
        self.live = self.pending


@dataclass
class LateOperations(DelayedOperations):
    """Production switches only during the final bounded delay."""

    async def sleep(self, seconds: int) -> None:
        self.events.append(f"sleep:{seconds}")
        if seconds == FINAL_DELAY_SECONDS:
            self.live = self.pending


@dataclass
class UnsuccessfulRollbackOperations(FakeRollbackOperations):
    """The rollback POST returns 2xx with an unsuccessful Cloudflare envelope."""

    async def rollback(self, deployment_id: str) -> str:
        self.events.append(f"rollback:{deployment_id}")
        return json.dumps(_envelope(None) | {"success": False})


@dataclass
class MalformedLiveOperations(FakeRollbackOperations):
    """The project names its live deployment with a non-string id."""

    async def get_project(self) -> str:
        payload = json.loads(_project(LIVE))
        payload["result"]["canonical_deployment"] = {"id": 7}
        return json.dumps(payload)


class ImmediateTimeout:
    """Async deadline that expires before the first verification read."""

    async def __aenter__(self) -> None:
        raise TimeoutError

    async def __aexit__(self, error_type: object, error: object, traceback: object) -> None:
        return None


@dataclass(frozen=True)
class RecordingRollbackTransport(CurlRollbackOperations):
    """Curl adapter double that records the exact method, suffix, and body."""

    requests: list[tuple[str, str, str]] = field(default_factory=list)

    async def _request(self, method: str, suffix: str, body: str = "") -> str:
        self.requests.append((method, suffix, body))
        return "response"


@dataclass
class FailingContainer:
    """Transport container whose curl run reports one HTTP status."""

    output: str

    async def stdout(self) -> str:
        return self.output


def _rollbacks(operations: FakeRollbackOperations) -> list[str]:
    return [event for event in operations.events if event.startswith("rollback:")]


def _sleeps(operations: FakeRollbackOperations) -> list[str]:
    return [event for event in operations.events if event.startswith("sleep:")]


def _transport() -> RecordingRollbackTransport:
    return RecordingRollbackTransport(_secret(), _secret(), PROJECT)


def _patched_pages(
    monkeypatch: pytest.MonkeyPatch, operations: FakeRollbackOperations
) -> main_module.CloudflarePages:
    monkeypatch.setattr(main_module, "CurlRollbackOperations", lambda *_: operations)
    return main_module.CloudflarePages()


def _public_methods() -> list[ast.AsyncFunctionDef]:
    tree = ast.parse(Path(main_module.__file__).read_text())
    classes = (node for node in tree.body if isinstance(node, ast.ClassDef))
    public = next(node for node in classes if node.name == "CloudflarePages")
    return [
        node
        for node in public.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name in ROLLBACK_FUNCTIONS
    ]


def _cache_value(method: ast.AsyncFunctionDef) -> object:
    decorator = next(item for item in method.decorator_list if isinstance(item, ast.Call))
    cache = next(item.value for item in decorator.keywords if item.arg == "cache")
    return cache.value if isinstance(cache, ast.Constant) else None


def _annotations(method: ast.AsyncFunctionDef) -> dict[str, str]:
    return {
        argument.arg: ast.unparse(argument.annotation or ast.Constant(None))
        for argument in method.args.args
    }


@pytest.mark.asyncio
async def test_should_serve_explicit_target_when_rollback_converges() -> None:
    # Given
    operations = FakeRollbackOperations()

    # When
    evidence = await rollback_production(operations, PROJECT, _id(PREVIOUS))

    # Then
    expected = RollbackEvidence(PROJECT, _id(LIVE), _id(PREVIOUS), _id(PREVIOUS), _url(PREVIOUS))
    assert evidence == expected
    assert operations.events == [
        "get-project",
        "get-deployments",
        f"rollback:{_id(PREVIOUS)}",
        "get-project",
    ]


@pytest.mark.asyncio
async def test_should_pick_previous_successful_deployment_when_no_target_is_given() -> None:
    # Given
    operations = FakeRollbackOperations()

    # When
    evidence = await rollback_production(operations, PROJECT, None)

    # Then
    assert evidence.to_deployment_id == _id(PREVIOUS)
    assert _rollbacks(operations) == [f"rollback:{_id(PREVIOUS)}"]


@pytest.mark.asyncio
async def test_should_refuse_when_no_previous_successful_deployment_exists() -> None:
    # Given
    operations = FakeRollbackOperations(rows=(Row(LIVE), Row(FAILED, status="failure")))

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="no previous successful production"):
        await rollback_production(operations, PROJECT, None)
    assert _rollbacks(operations) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("row", "reason"),
    (
        (Row(PREVIOUS, environment="preview"), "not a production deployment"),
        (Row(PREVIOUS, status="failure"), "not a successful deployment"),
        (Row(PREVIOUS, status="active"), "not a successful deployment"),
        (Row(PREVIOUS, stage="build"), "not a successful deployment"),
    ),
)
async def test_should_refuse_when_target_is_preview_or_unsuccessful(row: Row, reason: str) -> None:
    # Given
    operations = FakeRollbackOperations(rows=(Row(LIVE), row))

    # When / Then
    with pytest.raises(CloudflarePolicyError, match=reason):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))
    assert _rollbacks(operations) == []


@pytest.mark.asyncio
async def test_should_refuse_when_target_is_absent_from_recent_history() -> None:
    # Given
    operations = FakeRollbackOperations(rows=(Row(LIVE),))

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="not in recent production history"):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))
    assert _rollbacks(operations) == []


@pytest.mark.asyncio
async def test_should_refuse_when_target_belongs_to_another_project() -> None:
    # Given
    foreign = Row(PREVIOUS, project_id="other-project")
    operations = FakeRollbackOperations(rows=(Row(LIVE), foreign))

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="identity differs"):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))
    assert _rollbacks(operations) == []


@pytest.mark.asyncio
async def test_should_refuse_explicit_noop_when_target_is_already_live() -> None:
    # Given
    operations = FakeRollbackOperations()

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="already live"):
        await rollback_production(operations, PROJECT, _id(LIVE))
    assert _rollbacks(operations) == []


@pytest.mark.asyncio
async def test_should_refuse_rollback_when_project_has_no_live_deployment() -> None:
    # Given
    operations = FakeRollbackOperations(live=None)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="no live production deployment"):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))
    assert _rollbacks(operations) == []


@pytest.mark.asyncio
async def test_should_refuse_rollback_when_project_name_differs() -> None:
    # Given
    operations = FakeRollbackOperations(project_name="other")

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="project binding differs"):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))
    assert _rollbacks(operations) == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error",
    (
        CloudflareApiError("Cloudflare 8000009: rollback rejected"),
        CloudflareApiError("Cloudflare API request failed"),
    ),
)
async def test_should_fail_closed_when_rollback_api_rejects(error: CloudflareApiError) -> None:
    # Given
    operations = FakeRollbackOperations(rollback_error=error)

    # When / Then
    with pytest.raises(CloudflareApiError):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))
    assert operations.events[-1] == f"rollback:{_id(PREVIOUS)}"


@pytest.mark.asyncio
async def test_should_raise_api_error_when_rollback_body_is_unsuccessful() -> None:
    # Given
    operations = UnsuccessfulRollbackOperations()

    # When / Then
    with pytest.raises(CloudflareApiError, match="API request failed"):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))


@pytest.mark.asyncio
async def test_should_refuse_when_rollback_response_names_another_deployment() -> None:
    # Given
    operations = FakeRollbackOperations(response_id=OLDER)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="rollback response identity differs"):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))


@pytest.mark.asyncio
async def test_should_fail_closed_when_production_never_serves_rollback_target() -> None:
    # Given
    operations = FakeRollbackOperations(converge=False)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="does not serve the rollback target"):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))
    assert _sleeps(operations) == BOUNDED_DELAYS


@pytest.mark.asyncio
async def test_should_accept_rollback_when_production_converges_after_first_delay() -> None:
    # Given
    operations = DelayedOperations()

    # When
    evidence = await rollback_production(operations, PROJECT, _id(PREVIOUS))

    # Then
    assert evidence.live_deployment_id == _id(PREVIOUS)
    assert _sleeps(operations) == ["sleep:1"]


@pytest.mark.asyncio
async def test_should_accept_rollback_when_production_converges_after_final_delay() -> None:
    # Given
    operations = LateOperations()

    # When
    evidence = await rollback_production(operations, PROJECT, _id(PREVIOUS))

    # Then
    assert evidence.live_deployment_id == _id(PREVIOUS)
    assert _sleeps(operations) == BOUNDED_DELAYS


@pytest.mark.asyncio
async def test_should_fail_closed_when_verification_deadline_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.setattr(asyncio, "timeout", lambda _: ImmediateTimeout())
    operations = FakeRollbackOperations()

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="does not serve the rollback target"):
        await rollback_production(operations, PROJECT, _id(PREVIOUS))


@pytest.mark.asyncio
async def test_should_record_live_deployment_when_reading_rollback_target() -> None:
    # Given
    operations = FakeRollbackOperations()

    # When
    deployment = await live_production_deployment(operations, PROJECT)

    # Then
    assert (deployment.id, deployment.url) == (_id(LIVE), _url(LIVE))
    assert operations.events == ["get-project", "get-deployments"]


@pytest.mark.asyncio
async def test_should_refuse_to_record_target_when_nothing_is_live() -> None:
    # Given
    operations = FakeRollbackOperations(live=None)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="no live production deployment"):
        await live_production_deployment(operations, PROJECT)


@pytest.mark.asyncio
async def test_should_refuse_to_record_target_when_live_is_missing_from_history() -> None:
    # Given
    operations = FakeRollbackOperations(rows=(Row(PREVIOUS),))

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="not in recent production history"):
        await live_production_deployment(operations, PROJECT)


@pytest.mark.asyncio
async def test_should_refuse_to_record_target_when_live_reference_is_malformed() -> None:
    # Given
    operations = MalformedLiveOperations()

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="schema mismatch"):
        await live_production_deployment(operations, PROJECT)


@pytest.mark.asyncio
async def test_should_send_only_documented_requests_when_rolling_back() -> None:
    # Given
    transport = _transport()

    # When
    await transport.get_project()
    await transport.get_deployments()
    await transport.rollback(_id(PREVIOUS))

    # Then
    assert transport.requests == [
        ("GET", "/pages/projects/edge-reco", ""),
        ("GET", "/pages/projects/edge-reco/deployments?env=production&per_page=10", ""),
        ("POST", f"/pages/projects/edge-reco/deployments/{_id(PREVIOUS)}/rollback", ""),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ("", "../../projects/x", "ABC", "a" * 65, "a/b"))
async def test_should_refuse_before_transport_when_rollback_id_is_malformed(value: str) -> None:
    # Given
    transport = _transport()

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="deployment id is malformed"):
        await transport.rollback(value)
    assert transport.requests == []


def test_should_refuse_before_transport_when_project_name_is_malformed() -> None:
    # Given
    project = "../edge"

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="project name is malformed"):
        CurlRollbackOperations(_secret(), _secret(), project)


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ("400", "403", "409", "500", "503"))
async def test_should_raise_api_error_when_rollback_returns_http_failure(
    monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    # Given
    container = FailingContainer(f'{status}\n{{"errors":[],"messages":[],"success":false}}')
    monkeypatch.setattr(main_module, "_curl_request_container", lambda *_: container)
    operations = CurlRollbackOperations(_secret(), _secret(), PROJECT)

    # When / Then
    with pytest.raises(CloudflareApiError, match="API request failed"):
        await operations.rollback(_id(PREVIOUS))


def test_should_send_post_with_body_and_without_retry_when_method_writes() -> None:
    # Given / When
    script = main_module._curl_script()

    # Then
    assert 'if [ "$method" = PATCH ] || [ "$method" = POST ]; then' in script
    assert "retry = 0" in script


def test_should_expose_rollback_functions_as_uncached_when_published() -> None:
    # Given
    methods = _public_methods()

    # When
    cache_values = {method.name: _cache_value(method) for method in methods}

    # Then
    assert cache_values == dict.fromkeys(ROLLBACK_FUNCTIONS, "never")


def test_should_take_typed_secrets_without_escape_hatches_when_published() -> None:
    # Given
    methods = _public_methods()

    # When
    signatures = [_annotations(method) for method in methods]

    # Then
    assert len(signatures) == len(ROLLBACK_FUNCTIONS)
    for arguments in signatures:
        credentials = (arguments["cloudflare_api_token"], arguments["cloudflare_account_id"])
        assert credentials == (SECRET_TYPE, SECRET_TYPE)
        assert ESCAPE_HATCHES.isdisjoint(arguments)


@pytest.mark.asyncio
async def test_should_return_public_evidence_when_rollback_function_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    pages = _patched_pages(monkeypatch, FakeRollbackOperations())

    # When
    evidence = await pages.rollback(_secret(), _secret(), PROJECT)

    # Then
    moved = (evidence.project, evidence.from_deployment_id, evidence.to_deployment_id)
    assert moved == (PROJECT, _id(LIVE), _id(PREVIOUS))
    live = (evidence.live_deployment_id, evidence.live_deployment_url)
    assert live == (_id(PREVIOUS), _url(PREVIOUS))


@pytest.mark.asyncio
async def test_should_return_recorded_target_without_writing_when_helper_is_called(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    operations = FakeRollbackOperations()
    pages = _patched_pages(monkeypatch, operations)

    # When
    recorded = await pages.previous_production_deployment(_secret(), _secret(), PROJECT)

    # Then
    assert (recorded.project, recorded.deployment_id) == (PROJECT, _id(LIVE))
    assert recorded.deployment_url == _url(LIVE)
    assert _rollbacks(operations) == []


@pytest.mark.asyncio
async def test_should_use_async_sleep_when_waiting_between_verification_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    delays: list[float] = []

    async def record(seconds: float) -> None:
        delays.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", record)

    # When
    await CurlRollbackOperations(_secret(), _secret(), PROJECT).sleep(2)

    # Then
    assert delays == [2]
