from __future__ import annotations

import base64
import json
import textwrap
from dataclasses import dataclass
from types import TracebackType
from urllib.request import Request

import pytest

from ci.fleet_policy import CheckApp, PendingCheck
from ci.github_fleet import (
    FleetAccessError,
    GitHubHttpTransport,
    HttpResponse,
    OpenedResponse,
    read_repository,
)

SHA = "a" * 40
PYTHON_LOCK = """
version = 1

[[package]]
name = "dagger-io"
version = "0.0.0"
source = { editable = "sdk" }
"""


@dataclass(frozen=True)
class FakeTransport:
    """Return exact fixture responses for one authoritative read."""

    responses: dict[str, HttpResponse]

    def get(self, path: str) -> HttpResponse:
        return self.responses.get(path, HttpResponse(status=404, body="{}"))


@dataclass
class MovingMainTransport:
    """Move main only when the authoritative reader performs its final reread."""

    responses: dict[str, HttpResponse]
    main_reads: int = 0

    def get(self, path: str) -> HttpResponse:
        if path != "repos/gainratio/example/commits/main":
            return self.responses.get(path, HttpResponse(status=404, body="{}"))
        self.main_reads += 1
        return _json({"sha": SHA if self.main_reads == 1 else "f" * 40})


def _json(value: object, status: int = 200) -> HttpResponse:
    return HttpResponse(status=status, body=json.dumps(value))


def _content(path: str, text: str) -> HttpResponse:
    encoded = base64.b64encode(text.encode()).decode()
    wrapped = textwrap.fill(encoded, width=12)
    return _json({"type": "file", "path": path, "encoding": "base64", "content": wrapped})


def _responses() -> dict[str, HttpResponse]:
    base = "repos/gainratio/example"
    workflow = ".github/workflows/dagger.yml"
    module = "dagger/src/index.ts"
    config = "dagger.json"
    foundation_sha = "b" * 40
    foundation = "modules/portfolio-foundation/dagger.json"
    dependency = f"github.com/hseshadr/ci/modules/portfolio-foundation@{foundation_sha}"
    return {
        f"{base}/commits/main": _json({"sha": SHA}),
        f"{base}/git/trees/{SHA}?recursive=1": _json(
            {
                "sha": SHA,
                "truncated": False,
                "tree": [
                    {"path": workflow, "type": "blob"},
                    {"path": module, "type": "blob"},
                    {"path": config, "type": "blob"},
                    {"path": ".dagger/uv.lock", "type": "blob"},
                ],
            }
        ),
        f"{base}/contents/{workflow}?ref={SHA}": _content(workflow, "name: Dagger"),
        f"{base}/contents/{module}?ref={SHA}": _content(module, "source: dagger.Directory"),
        f"{base}/contents/{config}?ref={SHA}": _content(
            config,
            json.dumps(
                {
                    "name": "example",
                    "engineVersion": "v0.21.8",
                    "sdk": {"source": "python"},
                    "dependencies": [
                        {"name": "foundation", "source": dependency, "pin": foundation_sha}
                    ],
                    "source": ".dagger",
                }
            ),
        ),
        f"repos/hseshadr/ci/contents/{foundation}?ref={foundation_sha}": _content(
            foundation,
            json.dumps(
                {
                    "name": "portfolio-foundation",
                    "engineVersion": "v0.21.8",
                    "sdk": {"source": "python"},
                    "source": ".dagger",
                }
            ),
        ),
        f"{base}/contents/.dagger/uv.lock?ref={SHA}": _content(".dagger/uv.lock", PYTHON_LOCK),
        (
            f"repos/hseshadr/ci/contents/modules/portfolio-foundation/"
            f".dagger/uv.lock?ref={foundation_sha}"
        ): _content("modules/portfolio-foundation/.dagger/uv.lock", PYTHON_LOCK),
        f"{base}/branches/main/protection": _json(
            {
                "required_status_checks": {
                    "strict": True,
                    "checks": [{"context": "Dagger", "app_id": 15368}],
                },
                "enforce_admins": {"enabled": True},
                "required_pull_request_reviews": {"required_approving_review_count": 0},
                "required_conversation_resolution": {"enabled": True},
                "required_linear_history": {"enabled": True},
                "allow_force_pushes": {"enabled": False},
                "allow_deletions": {"enabled": False},
            }
        ),
        f"{base}/commits/{SHA}/check-runs?per_page=100": _json(
            {
                "total_count": 2,
                "check_runs": [
                    {
                        "name": "Dagger",
                        "head_sha": SHA,
                        "status": "completed",
                        "conclusion": "success",
                        "app": {"id": 15368, "slug": "github-actions"},
                    },
                    {
                        "name": "GitGuardian Security Checks",
                        "head_sha": SHA,
                        "status": "completed",
                        "conclusion": "success",
                        "app": {"id": 123, "slug": "gitguardian"},
                    },
                ],
            }
        ),
        f"{base}/code-scanning/default-setup": _json({"state": "not-configured"}),
        f"{base}/environments?per_page=100": _json(
            {
                "total_count": 1,
                "environments": [
                    {
                        "name": "production",
                        "deployment_branch_policy": {
                            "protected_branches": False,
                            "custom_branch_policies": True,
                        },
                    }
                ],
            }
        ),
        f"{base}/environments/production/deployment-branch-policies?per_page=100": _json(
            {"total_count": 1, "branch_policies": [{"name": "main", "type": "branch"}]}
        ),
        f"{base}/actions/secrets?per_page=100": _json(
            {"total_count": 1, "secrets": [{"name": "PORTFOLIO_PAT"}]}
        ),
        f"{base}/environments/production/secrets?per_page=100": _json(
            {
                "total_count": 2,
                "secrets": [
                    {"name": "CLOUDFLARE_ACCOUNT_ID"},
                    {"name": "CLOUDFLARE_API_TOKEN"},
                ],
            }
        ),
    }


@dataclass(frozen=True)
class FakeOpenedResponse:
    """Behave like one successful urllib response."""

    status: int
    body: bytes

    def read(self) -> bytes:
        return self.body

    def __enter__(self) -> FakeOpenedResponse:
        return self

    def __exit__(
        self,
        error_type: type[BaseException] | None,
        error: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None


@dataclass
class RecordingOpener:
    """Capture one request while returning deterministic bytes."""

    response: FakeOpenedResponse
    authorization: str = ""
    url: str = ""

    def open(self, request: Request) -> OpenedResponse:
        self.authorization = request.get_header("Authorization") or ""
        self.url = request.full_url
        return self.response


def test_should_build_exact_snapshot_when_authoritative_endpoints_are_complete() -> None:
    # Given complete exact-main source, protection, checks, and CodeQL responses
    transport = FakeTransport(_responses())

    # When the repository is read through the typed boundary
    snapshot = read_repository(transport, "gainratio", "example")

    # Then identity and app-bound evidence remain exact
    assert snapshot.sha == SHA
    assert snapshot.protection.checks[0].app_id == 15368
    assert snapshot.check_runs[0].head_sha == SHA
    assert snapshot.codeql_default_state == "not-configured"
    assert snapshot.modules[0].path == "dagger/src/index.ts"


def test_should_read_exact_recursive_module_and_environment_metadata() -> None:
    # Given exact-main config plus one immutable shared dependency and name-only secrets
    transport = FakeTransport(_responses())

    # When the authoritative repository boundary is read
    snapshot = read_repository(transport, "gainratio", "example")

    # Then the graph, main-only production boundary, and secret names remain typed
    assert tuple(config.name for config in snapshot.dagger_configs) == (
        "example",
        "portfolio-foundation",
    )
    assert snapshot.dagger_configs[1].identity.endswith("@" + "b" * 40)
    assert snapshot.repository_secret_names == ("PORTFOLIO_PAT",)
    assert snapshot.environments[0].branch_names == ("main",)
    assert snapshot.environments[0].secret_names == (
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_API_TOKEN",
    )
    assert snapshot.dagger_configs[0].generated_lock is not None
    assert snapshot.dagger_configs[0].generated_lock.path == ".dagger/uv.lock"
    assert snapshot.dagger_configs[0].dependencies[0].pin == "b" * 40


def test_should_preserve_unsupported_sdk_without_inventing_lock_metadata() -> None:
    # Given exact dagger.json selects an SDK whose generated lock contract is not reviewed
    responses = _responses()
    path = f"repos/gainratio/example/contents/dagger.json?ref={SHA}"
    payload = json.loads(responses[path].body)
    config = json.loads(base64.b64decode("".join(payload["content"].splitlines())).decode())
    config["sdk"] = {"source": "go"}
    responses[path] = _content("dagger.json", json.dumps(config))

    # When the typed reader assembles exact SDK evidence
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then policy receives the unsupported SDK without fabricated generated metadata
    assert snapshot.dagger_configs[0].sdk == "go"
    assert snapshot.dagger_configs[0].generated_lock is None


def test_should_parse_in_progress_checks_without_treating_them_as_green() -> None:
    # Given GitHub reports an in-progress exact-main check with no conclusion yet
    responses = _responses()
    path = f"repos/gainratio/example/commits/{SHA}/check-runs?per_page=100"
    payload = json.loads(responses[path].body)
    payload["total_count"] = 3
    payload["check_runs"].append(
        {
            "name": "Dagger fleet policy",
            "head_sha": SHA,
            "status": "in_progress",
            "conclusion": None,
            "app": {"id": 999, "slug": "untrusted-app"},
        }
    )
    responses[path] = _json(payload)
    responses.update(_previous_main(conclusion="success"))

    # When the authoritative boundary parses the live check page
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then unfinished work cannot satisfy a green check, but its app remains observable
    assert all(run.name != "Dagger fleet policy" for run in snapshot.check_runs)
    assert CheckApp(slug="untrusted-app", app_id=999) in snapshot.check_apps
    assert (
        PendingCheck(name="Dagger fleet policy", app_id=999, head_sha=SHA)
        in snapshot.pending_check_runs
    )


def test_should_name_minimal_scope_when_protection_read_is_forbidden() -> None:
    # Given a token that can read source but not effective protection
    responses = _responses()
    responses["repos/gainratio/example/branches/main/protection"] = _json(
        {"message": "forbidden detail must stay private"}, status=403
    )

    # When the authoritative reader reaches the protected endpoint
    with pytest.raises(FleetAccessError) as caught:
        read_repository(FakeTransport(responses), "gainratio", "example")

    # Then it retains permission guidance without reflecting arbitrary provider text
    assert str(caught.value) == (
        "GitHub 403 for repos/gainratio/example/branches/main/protection; "
        "token requires Administration:read"
    )


def test_should_fail_closed_when_tree_or_check_page_is_incomplete() -> None:
    # Given GitHub signals that source or check evidence was truncated
    responses = _responses()
    responses[f"repos/gainratio/example/git/trees/{SHA}?recursive=1"] = _json(
        {"sha": SHA, "truncated": True, "tree": []}
    )

    # When the repository read cannot prove completeness
    with pytest.raises(FleetAccessError, match="incomplete"):
        read_repository(FakeTransport(responses), "gainratio", "example")


def test_should_fail_closed_when_exact_check_page_omits_runs() -> None:
    # Given GitHub's exact-main check count exceeds the returned bounded page
    responses = _responses()
    path = f"repos/gainratio/example/commits/{SHA}/check-runs?per_page=100"
    payload = json.loads(responses[path].body)
    payload["total_count"] += 1
    responses[path] = _json(payload)

    # When the repository reader cannot prove the complete check set
    with pytest.raises(FleetAccessError, match="incomplete authoritative check runs"):
        read_repository(FakeTransport(responses), "gainratio", "example")


def test_should_authenticate_exact_api_path_when_transport_reads_github() -> None:
    # Given an injected HTTP opener and a credential held only by the transport
    opener = RecordingOpener(FakeOpenedResponse(status=200, body=b'{"sha":"abc"}'))
    transport = GitHubHttpTransport("secret-token", opener)

    # When one repository-relative path is read
    response = transport.get("repos/gainratio/example/commits/main")

    # Then the request uses GitHub's versioned bearer boundary and exact URL
    assert response == HttpResponse(status=200, body='{"sha":"abc"}')
    assert opener.authorization == "Bearer secret-token"
    assert opener.url == "https://api.github.com/repos/gainratio/example/commits/main"


def test_should_accept_additive_provider_fields_when_required_evidence_is_typed() -> None:
    # Given GitHub adds an unrelated response field while required evidence remains exact
    responses = _responses()
    responses["repos/gainratio/example/commits/main"] = _json(
        {"sha": SHA, "provider-added-field": "ignored"}
    )

    # When the typed evidence reader selects its reviewed contract
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then provider evolution does not weaken or break the required identity
    assert snapshot.sha == SHA


def test_should_fail_closed_when_main_moves_during_authoritative_scan() -> None:
    # Given main advances only after every exact-SHA and repository metadata read
    transport = MovingMainTransport(_responses())

    # When the authoritative snapshot is assembled across that movement
    with pytest.raises(FleetAccessError, match="main moved during authoritative scan"):
        read_repository(transport, "gainratio", "example")

    # Then the scanner proved movement with an explicit final reread
    assert transport.main_reads == 2


@pytest.mark.parametrize(
    ("path", "field", "value"),
    [
        (f"repos/gainratio/example/git/trees/{SHA}?recursive=1", "truncated", "false"),
        ("repos/gainratio/example/environments?per_page=100", "total_count", "1"),
    ],
)
def test_should_reject_coerced_types_at_github_boundary(path: str, field: str, value: str) -> None:
    # Given GitHub returns a schema field with the wrong JSON type
    responses = _responses()
    payload = json.loads(responses[path].body)
    payload[field] = value
    responses[path] = _json(payload)

    # When the strict authoritative reader validates the response
    with pytest.raises(FleetAccessError, match="invalid authoritative response"):
        read_repository(FakeTransport(responses), "gainratio", "example")


def test_should_reject_wrong_typed_commit_identity_at_github_boundary() -> None:
    # Given authoritative string identity arrives as a JSON integer
    responses = _responses()
    responses["repos/gainratio/example/commits/main"] = _json({"sha": 123})

    # When the exact commit identity is validated
    with pytest.raises(FleetAccessError, match="invalid authoritative response"):
        read_repository(FakeTransport(responses), "gainratio", "example")


def test_should_reject_wrong_typed_app_id_at_github_boundary() -> None:
    # Given the app-bound protection ID is a string rather than an integer
    responses = _responses()
    path = "repos/gainratio/example/branches/main/protection"
    payload = json.loads(responses[path].body)
    payload["required_status_checks"]["checks"][0]["app_id"] = "15368"
    responses[path] = _json(payload)

    # Then strict protection evidence rejects the coerced app identity
    with pytest.raises(FleetAccessError, match="invalid authoritative response"):
        read_repository(FakeTransport(responses), "gainratio", "example")


def test_should_record_missing_exact_dependency_config_without_guessing() -> None:
    # Given an immutable dependency whose exact config no longer exists
    responses = _responses()
    path = f"repos/hseshadr/ci/contents/modules/portfolio-foundation/dagger.json?ref={'b' * 40}"
    responses[path] = _json({}, status=404)

    # When the recursive graph is read
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then the exact unresolved identity remains policy evidence
    assert snapshot.missing_dagger_configs == (
        f"github.com/hseshadr/ci/modules/portfolio-foundation@{'b' * 40}",
    )


def test_should_terminate_recursive_cycle_while_preserving_graph_edges() -> None:
    # Given the exact foundation config points back to the exact consumer root
    responses = _responses()
    path = f"repos/hseshadr/ci/contents/modules/portfolio-foundation/dagger.json?ref={'b' * 40}"
    responses[path] = _content(
        "modules/portfolio-foundation/dagger.json",
        json.dumps(
            {
                "name": "portfolio-foundation",
                "engineVersion": "v0.21.8",
                "sdk": {"source": "python"},
                "dependencies": [
                    {"name": "consumer", "source": f"github.com/gainratio/example@{SHA}"}
                ],
                "source": ".dagger",
            }
        ),
    )

    # When the graph walker encounters the ancestor again
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then it terminates without dropping either loaded config
    assert tuple(config.name for config in snapshot.dagger_configs) == (
        "example",
        "portfolio-foundation",
    )


def test_should_model_absent_root_config_as_missing_exact_metadata() -> None:
    # Given the exact source tree has no root dagger.json
    responses = _responses()
    tree_path = f"repos/gainratio/example/git/trees/{SHA}?recursive=1"
    tree = json.loads(responses[tree_path].body)
    tree["tree"] = [item for item in tree["tree"] if item["path"] != "dagger.json"]
    responses[tree_path] = _json(tree)

    # When the repository is read
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then absence is explicit rather than replaced with a default config
    assert snapshot.dagger_configs == ()
    assert snapshot.missing_dagger_configs == (f"github.com/gainratio/example@{SHA}",)


def test_should_resolve_local_dependency_and_not_fetch_mutable_remote() -> None:
    # Given the root has one local config and one policy-invalid mutable remote
    responses = _responses()
    root_path = f"repos/gainratio/example/contents/dagger.json?ref={SHA}"
    responses[root_path] = _content(
        "dagger.json",
        json.dumps(
            {
                "name": "example",
                "engineVersion": "v0.21.8",
                "sdk": {"source": "python"},
                "dependencies": [
                    {"name": "local", "source": "./modules/local"},
                    {"name": "mutable", "source": "github.com/hseshadr/ci@main"},
                ],
                "source": ".dagger",
            }
        ),
    )
    local_path = "modules/local/dagger.json"
    responses[f"repos/gainratio/example/contents/{local_path}?ref={SHA}"] = _content(
        local_path,
        json.dumps(
            {
                "name": "local",
                "engineVersion": "v0.21.8",
                "sdk": {"source": "python"},
                "source": ".dagger",
            }
        ),
    )
    lock_path = "modules/local/.dagger/uv.lock"
    responses[f"repos/gainratio/example/contents/{lock_path}?ref={SHA}"] = _content(
        lock_path, PYTHON_LOCK
    )

    # When fetchable dependency locations are resolved
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then local exact metadata is loaded and mutable remote source remains policy-only evidence
    assert tuple(config.name for config in snapshot.dagger_configs) == ("example", "local")


def test_should_preserve_unsupported_remote_as_policy_evidence_without_fetching() -> None:
    # Given dagger.json declares a non-supported remote URL form
    responses = _responses()
    root_path = f"repos/gainratio/example/contents/dagger.json?ref={SHA}"
    payload = json.loads(responses[root_path].body)
    decoded = json.loads(base64.b64decode("".join(payload["content"].splitlines())).decode())
    decoded["dependencies"].append(
        {"name": "external", "source": "https://gitlab.com/acme/module.git#main"}
    )
    responses[root_path] = _content("dagger.json", json.dumps(decoded))

    # When the graph reader resolves only canonical fetchable variants
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then the invalid declaration remains typed policy evidence without a fake missing config
    assert snapshot.dagger_configs[0].dependencies[-1].source.startswith("https://gitlab.com")
    assert snapshot.missing_dagger_configs == ()


def test_should_not_fetch_noncanonical_remote_module_path() -> None:
    # Given a literal revision contains traversal and an API response exists at that raw alias
    responses = _responses()
    root_path = f"repos/gainratio/example/contents/dagger.json?ref={SHA}"
    payload = json.loads(responses[root_path].body)
    decoded = json.loads(base64.b64decode("".join(payload["content"].splitlines())).decode())
    revision = "b" * 40
    source = f"github.com/hseshadr/ci/modules/ok/../../evil@{revision}"
    decoded["dependencies"] = [{"name": "external", "source": source, "pin": revision}]
    responses[root_path] = _content("dagger.json", json.dumps(decoded))
    raw_path = "repos/hseshadr/ci/contents/modules/ok/../../evil/dagger.json?ref=" + revision
    responses[raw_path] = _content(
        "modules/ok/../../evil/dagger.json",
        json.dumps(
            {
                "name": "evil",
                "engineVersion": "v0.21.8",
                "sdk": {"source": "python"},
            }
        ),
    )

    # When recursive locations are resolved before GitHub contents access
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then raw traversal is preserved only as policy evidence and never fetched
    assert tuple(config.name for config in snapshot.dagger_configs) == ("example",)
    assert snapshot.missing_dagger_configs == ()


def test_should_skip_branch_page_when_environment_has_no_custom_policy() -> None:
    # Given an environment without any deployment branch policy
    responses = _responses()
    path = "repos/gainratio/example/environments?per_page=100"
    responses[path] = _json(
        {
            "total_count": 1,
            "environments": [{"name": "preview", "deployment_branch_policy": None}],
        }
    )
    responses["repos/gainratio/example/environments/preview/secrets?per_page=100"] = _json(
        {"total_count": 0, "secrets": []}
    )

    # When environment evidence is read
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then no unconfigured branch endpoint is invented
    assert snapshot.environments[0].branch_names == ()


def test_should_fail_closed_when_a_bounded_metadata_page_is_incomplete() -> None:
    # Given GitHub reports more secret names than the bounded page contains
    responses = _responses()
    path = "repos/gainratio/example/actions/secrets?per_page=100"
    responses[path] = _json({"total_count": 2, "secrets": [{"name": "PORTFOLIO_PAT"}]})

    # When the authoritative reader cannot prove the whole name inventory
    with pytest.raises(FleetAccessError, match="incomplete authoritative page"):
        read_repository(FakeTransport(responses), "gainratio", "example")


def test_should_name_environment_scope_without_reading_secret_values() -> None:
    # Given name-only environment secret metadata is forbidden
    responses = _responses()
    path = "repos/gainratio/example/environments/production/secrets?per_page=100"
    responses[path] = _json({}, status=403)

    # When the typed reader reaches that endpoint
    with pytest.raises(FleetAccessError, match="Environments:read"):
        read_repository(FakeTransport(responses), "gainratio", "example")


@pytest.mark.parametrize(
    ("response", "message"),
    [
        (_content("wrong.json", "{}"), "invalid exact source identity"),
        (
            _json(
                {
                    "type": "symlink",
                    "path": "dagger.json",
                    "encoding": "base64",
                    "content": "e30=",
                }
            ),
            "invalid exact source identity",
        ),
        (_content("dagger.json", "{}"), "invalid Dagger config"),
    ],
)
def test_should_fail_closed_on_invalid_exact_dagger_metadata(
    response: HttpResponse, message: str
) -> None:
    # Given exact dagger.json metadata has the wrong identity or schema
    responses = _responses()
    responses[f"repos/gainratio/example/contents/dagger.json?ref={SHA}"] = response

    # When the boundary validates that config
    with pytest.raises(FleetAccessError, match=message):
        read_repository(FakeTransport(responses), "gainratio", "example")


FLOOR = "dd19871486588b1582e432b7bc1f2cfffb296340"
COMPARE_FLOOR = f"repos/gainratio/ci/compare/{FLOOR}...{'b' * 40}?per_page=1"
COMPARE_MAIN = f"repos/gainratio/ci/compare/{'b' * 40}...main?per_page=1"


def test_should_read_floor_and_main_ancestry_for_floored_central_pin() -> None:
    # Given GitHub compare evidence for the consumer's central foundation pin
    responses = _responses()
    responses[COMPARE_FLOOR] = _json({"status": "behind", "ahead_by": 0})
    responses[COMPARE_MAIN] = _json({"status": "ahead"})

    # When the repository is read
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then both comparisons are typed ancestry evidence for policy
    evidence = snapshot.pin_ancestry
    assert [(item.floor, item.pin) for item in evidence] == [(FLOOR, "b" * 40)]
    assert (evidence[0].floor_status, evidence[0].main_status) == ("behind", "ahead")


def test_should_record_unrelated_history_when_compare_has_no_common_ancestor() -> None:
    # Given GitHub cannot compare the pin because it shares no history with the floor
    responses = _responses()

    # When the repository is read (both compares answer 404)
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then the pin is recorded as unrelated rather than silently accepted
    assert snapshot.pin_ancestry[0].floor_status == "unrelated"
    assert snapshot.pin_ancestry[0].main_status == "unrelated"


def test_should_fail_closed_when_compare_endpoint_errors() -> None:
    # Given the compare endpoint is unavailable
    responses = _responses()
    responses[COMPARE_FLOOR] = _json({}, status=500)

    # When the repository is read
    # Then the scan fails instead of guessing ancestry
    with pytest.raises(FleetAccessError, match="compare"):
        read_repository(FakeTransport(responses), "gainratio", "example")


PARENT = "c" * 40
CHECKS_PATH = f"repos/gainratio/example/commits/{SHA}/check-runs?per_page=100"
PARENT_CHECKS_PATH = f"repos/gainratio/example/commits/{PARENT}/check-runs?per_page=100"


def _previous_main(conclusion: str) -> dict[str, HttpResponse]:
    run = {
        "name": "Dagger",
        "head_sha": PARENT,
        "status": "completed",
        "conclusion": conclusion,
        "app": {"id": 15368, "slug": "github-actions"},
    }
    return {
        f"repos/gainratio/example/commits/{SHA}": _json({"sha": SHA, "parents": [{"sha": PARENT}]}),
        PARENT_CHECKS_PATH: _json({"total_count": 1, "check_runs": [run]}),
    }


def _with_dagger_run(**fields: object) -> dict[str, HttpResponse]:
    responses = _responses()
    payload = json.loads(responses[CHECKS_PATH].body)
    dagger = payload["check_runs"][0]
    dagger.update(fields)
    for key in [key for key, value in fields.items() if value is MISSING]:
        del dagger[key]
    responses[CHECKS_PATH] = _json(payload)
    responses.update(_previous_main(conclusion="success"))
    return responses


MISSING = object()


@pytest.mark.parametrize(
    "fields",
    [
        {"status": "mystery"},
        {"status": "mystery", "conclusion": None},
        {"status": "COMPLETED"},
        {"status": "COMPLETED", "conclusion": None},
        {"status": None, "conclusion": None},
        {"status": MISSING},
        {"conclusion": MISSING},
        {"status": "completed", "conclusion": None},
        {"status": "in_progress", "conclusion": "success"},
        {"status": "queued", "conclusion": "failure"},
    ],
)
def test_should_fail_closed_when_check_status_is_unknown_missing_or_contradictory(
    fields: dict[str, object],
) -> None:
    # Given a check run whose status cannot be trusted
    responses = _with_dagger_run(**fields)

    # When / Then the reader refuses the page instead of guessing pending or green
    with pytest.raises(FleetAccessError, match="invalid authoritative response"):
        read_repository(FakeTransport(responses), "gainratio", "example")


def test_should_read_previous_main_checks_when_exact_main_is_running() -> None:
    # Given exact main's Dagger check is still running
    responses = _with_dagger_run(status="in_progress", conclusion=None)

    # When the reader assembles evidence
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then the most recent completed main (the first parent) is the fallback evidence
    assert snapshot.previous_main_sha == PARENT
    assert [run.conclusion for run in snapshot.previous_check_runs] == ["success"]


def test_should_skip_previous_main_read_when_exact_main_is_complete() -> None:
    # Given every exact-main check has completed (no parent fixtures exist)
    # When the reader assembles evidence
    snapshot = read_repository(FakeTransport(_responses()), "gainratio", "example")

    # Then no fallback evidence is read or invented
    assert snapshot.previous_main_sha is None
    assert snapshot.previous_check_runs == ()


def test_should_record_no_previous_main_for_a_root_commit() -> None:
    # Given a running check on a commit with no parent
    responses = _with_dagger_run(status="queued", conclusion=None)
    responses[f"repos/gainratio/example/commits/{SHA}"] = _json({"sha": SHA, "parents": []})

    # When the reader assembles evidence
    snapshot = read_repository(FakeTransport(responses), "gainratio", "example")

    # Then there is no completed fallback to lean on
    assert snapshot.previous_main_sha is None
    assert snapshot.previous_check_runs == ()


@pytest.mark.parametrize(
    ("path", "response"),
    [
        (PARENT_CHECKS_PATH, HttpResponse(status=500, body="{}")),
        (PARENT_CHECKS_PATH, HttpResponse(status=200, body="not json")),
        (f"repos/gainratio/example/commits/{SHA}", HttpResponse(status=502, body="{}")),
        (f"repos/gainratio/example/commits/{SHA}", _json({"sha": SHA})),
    ],
)
def test_should_fail_closed_when_previous_main_cannot_be_read(
    path: str, response: HttpResponse
) -> None:
    # Given exact main is running and the fallback evidence errors or will not parse
    responses = _with_dagger_run(status="in_progress", conclusion=None)
    responses[path] = response

    # When / Then the scan stops instead of skipping the check
    with pytest.raises(FleetAccessError):
        read_repository(FakeTransport(responses), "gainratio", "example")
