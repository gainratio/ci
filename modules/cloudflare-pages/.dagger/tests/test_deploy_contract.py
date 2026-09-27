"""Provider ordering, attempt binding, and bounded convergence contracts."""

from __future__ import annotations

import ast
import asyncio
import hashlib
import json
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Self, cast

import dagger
import pytest

import cloudflare_pages.api as api_module
import cloudflare_pages.main as main_module
from cloudflare_pages.api import (
    CloudflarePolicyError,
    deploy_verified_artifact,
    preflight_provider,
    require_evidence_binding,
    verify_current_deployment,
)
from cloudflare_pages.main import (
    CurlPagesOperations,
    wrangler_deploy_args,
)
from cloudflare_pages.models import (
    AttemptIdentity,
    CreatedDeployment,
    GitHubEvidence,
    PagesTarget,
    ProviderDeploymentEvidence,
)

FULL_SHA = "a" * 40
MAIN = Path(__file__).parents[1] / "src/cloudflare_pages/main.py"
MODULE = Path(__file__).parents[2]
FOUNDATION = MODULE.parent / "portfolio-foundation"
PROVIDER_SOURCE = MAIN.parent

MOCK_SERVER = r"""from __future__ import annotations
import json
import ssl
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

ACCOUNT = "0123456789abcdef0123456789abcdef"
PROJECT = "/client/v4/accounts/" + ACCOUNT + "/pages/projects/edge-reco"
EVENTS: list[str] = []
DEPLOYMENT_READS = 0
GIT_DISABLED = False
SHA = "a" * 40

def project(enabled: bool = True, preview: str = "all") -> dict[str, object]:
    return {"errors": [], "messages": [], "success": True, "result": {
        "id": "7b162ea7-7367-4d4a-a28a-cb84f88f6", "name": "edge-reco",
        "production_branch": "main", "domains": ["edge-reco.pages.dev", "edge-reco.com"],
        "source": {"type": "github", "config": {"owner": "hseshadr",
        "repo_name": "edge-reco", "production_branch": "main",
        "production_deployments_enabled": enabled, "preview_deployment_setting": preview}}}}

def deployment() -> dict[str, object]:
    return {"id": "f64788e9-fccd-4d4a-a28a-cb84f88f6",
        "short_id": "f64788e9",
        "url": "https://f64788e9.edge-reco.pages.dev",
        "project_id": "7b162ea7-7367-4d4a-a28a-cb84f88f6", "project_name": "edge-reco",
        "environment": "production", "latest_stage": {"name": "deploy", "status": "success"},
        "deployment_trigger": {"type": "ad_hoc", "metadata": {"branch": "main",
        "commit_hash": SHA, "commit_dirty": False}}}

def deployments() -> dict[str, object]:
    global DEPLOYMENT_READS
    DEPLOYMENT_READS += 1
    result = [] if DEPLOYMENT_READS == 1 else [deployment()]
    return {"errors": [], "messages": [], "success": True, "result": result,
        "result_info": {"count": len(result), "page": 1, "per_page": 10,
        "total_count": len(result), "total_pages": int(bool(result))}}

ROLL = "/client/v4/accounts/" + ACCOUNT + "/pages/projects/edge-roll"
ROLL_LIVE = "11111111"

def rid(short: str) -> str:
    return short + "-0000-4000-8000-000000000000"

def roll_row(short: str, status: str = "success") -> dict[str, object]:
    return {"id": rid(short), "short_id": short, "url": "https://" + short + ".edge-roll.pages.dev",
        "project_id": "roll-project-id", "project_name": "edge-roll", "environment": "production",
        "latest_stage": {"name": "deploy", "status": status, "ended_on": None},
        "deployment_trigger": {"type": "ad_hoc", "metadata": {"branch": "main",
        "commit_hash": "", "commit_dirty": False, "commit_message": "ignored"}}, "aliases": None}

def roll_project() -> dict[str, object]:
    return {"errors": [], "messages": [], "success": True, "result": {"id": "roll-project-id",
        "name": "edge-roll", "production_branch": "main", "domains": ["edge-roll.pages.dev"],
        "source": None, "canonical_deployment": roll_row(ROLL_LIVE),
        "latest_deployment": roll_row("11111111")}}

def roll_history() -> dict[str, object]:
    result = [roll_row("11111111"), roll_row("33333333", "failure"), roll_row("22222222")]
    return {"errors": [], "messages": [], "success": True, "result": result,
        "result_info": {"count": 3, "page": 1, "per_page": 10, "total_count": 3, "total_pages": 1}}

class Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None: return
    def send(self, value: object) -> None:
        body = json.dumps(value).encode(); self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self) -> None:
        if self.path == "/": self.send({}); return
        if self.path == PROJECT:
            EVENTS.append("get-project"); self.send(project(not GIT_DISABLED, "none" if GIT_DISABLED else "all")); return
        if self.path == PROJECT + "/deployments?env=production&per_page=10":
            EVENTS.append("get-deployments"); self.send(deployments()); return
        if self.path == ROLL:
            EVENTS.append("get-roll-project"); self.send(roll_project()); return
        if self.path == ROLL + "/deployments?env=production&per_page=10":
            EVENTS.append("get-roll-deployments"); self.send(roll_history()); return
        if self.path.endswith("/__mock/events"):
            payload = project(False, "none"); payload["result"]["domains"] = EVENTS
            self.send(payload); return
        if self.path.endswith("/__mock/preflight"):
            EVENTS.append("wrangler-preflight"); self.send(project()); return
        if self.path.endswith("/__mock/upload"):
            EVENTS.append("upload"); self.send(project(False, "none")); return
        self.send_error(404)
    def do_PATCH(self) -> None:
        global GIT_DISABLED
        size = int(self.headers.get("Content-Length", "0")); body = self.rfile.read(size)
        if self.path == PROJECT:
            payload = json.loads(body); config = payload["source"]["config"]
            assert config == {"preview_deployment_setting": "none", "production_deployments_enabled": False}
            GIT_DISABLED = True; EVENTS.append("disable-git"); self.send(project(False, "none")); return
        self.send_error(404)

    def do_POST(self) -> None:
        global ROLL_LIVE
        assert self.headers.get("Content-Length") == "0"
        if self.path == ROLL + "/deployments/" + rid("22222222") + "/rollback":
            ROLL_LIVE = "22222222"; EVENTS.append("rollback")
            self.send({"errors": [], "messages": [], "success": True, "result": roll_row("22222222")}); return
        self.send_error(404)

health = HTTPServer(("0.0.0.0", 8080), Handler)
threading.Thread(target=health.serve_forever, daemon=True).start()
server = HTTPServer(("0.0.0.0", 443), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.load_cert_chain("/cert.pem", "/key.pem")
server.socket = context.wrap_socket(server.socket, server_side=True); server.serve_forever()
"""

FIXTURE_MAIN = r"""from __future__ import annotations
import json
import dagger
from dagger import dag, function, object_type
from cloudflare_pages.api import (CloudflarePolicyError, deploy_verified_artifact,
  live_production_deployment, rollback_production)
from cloudflare_pages.main import (CurlPagesOperations, CurlRollbackOperations, NODE_IMAGE, WRANGLER_OUTPUT_PATH, _jq_binary,
  _prepare_deploy_artifact, _uncached, _verify_envelope, _wrangler_script,
  wrangler_deploy_args)
from cloudflare_pages.models import AttemptIdentity, CreatedDeployment, GitHubEvidence, PagesTarget

PYTHON_IMAGE = "python:3.13.14-slim@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6"
SHA = "a" * 40
MOCK_SERVER = __MOCK_SERVER__
CA_CERT = __CA_CERT__
PRIVATE_KEY = __PRIVATE_KEY__
FAKE_WRANGLER = r'''#!/bin/sh
set -eu
[ "$1 $2 $3" = "pages deploy /artifact" ]
entries=$(find /artifact -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)
if [ -e /artifact/_worker.js ]; then
  [ -d /artifact/_worker.js ]
  [ "$entries" = "_routes.json
_worker.js
index.html" ]
  [ "$(find /artifact/_worker.js -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = "index.js" ]
  ! grep -q '^------formdata-' /artifact/_worker.js/index.js
  ! grep -q 'Content-Disposition: form-data' /artifact/_worker.js/index.js
  grep -q hello-from-functions /artifact/_worker.js/index.js
  node --input-type=module --check < /artifact/_worker.js/index.js
  node --input-type=module -e '
    const fs = await import("node:fs");
    const source = fs.readFileSync("/artifact/_worker.js/index.js").toString("base64");
    const worker = (await import(`data:text/javascript;base64,${source}`)).default;
    const response = await worker.fetch(new Request("https://example.com/api/hello"),
      {ASSETS: {fetch: () => new Response("asset")}}, {waitUntil: () => undefined});
    if (await response.text() !== "hello-from-functions") process.exit(1);
  '
else
  [ "$entries" = "index.html" ]
  [ "$(cat /artifact/index.html)" = "verified artifact" ]
fi
cat > "$WRANGLER_OUTPUT_FILE_PATH" <<'EOF'
{"type":"pages-deploy","version":1,"pages_project":"edge-reco","deployment_id":"f64788e9-fccd-4d4a-a28a-cb84f88f6","url":"https://f64788e9.edge-reco.pages.dev","timestamp":"2026-08-27T20:00:00Z"}
{"type":"pages-deploy-detailed","version":1,"pages_project":"edge-reco","deployment_id":"f64788e9-fccd-4d4a-a28a-cb84f88f6","url":"https://f64788e9.edge-reco.pages.dev","timestamp":"2026-08-27T20:00:00Z"}
EOF
'''

class MockOperations(CurlPagesOperations):
    async def wrangler_preflight(self) -> None:
        await super().wrangler_preflight(); await self._request("GET", "/__mock/preflight")
    async def upload(self, artifact: dagger.Directory, source_sha: str) -> CreatedDeployment:
        created = await super().upload(artifact, source_sha)
        await self._request("GET", "/__mock/upload")
        return created
    def _upload_container(self, artifact: dagger.Directory, source_sha: str) -> dagger.Container:
        base = dag.container(platform=dagger.Platform("linux/amd64")).from_(NODE_IMAGE)
        base = base.with_new_file("/usr/local/bin/wrangler", FAKE_WRANGLER, permissions=0o755)
        base = base.with_mounted_directory("/artifact", artifact, read_only=True)
        base = base.with_mounted_temp("/run/provider-output")
        base = base.with_mounted_temp("/run/provider-cache").with_mounted_temp("/run/provider-config")
        base = base.with_env_variable("WRANGLER_OUTPUT_FILE_PATH", WRANGLER_OUTPUT_PATH)
        base = base.with_mounted_file("/run/jq", _jq_binary())
        command = ["/bin/sh", "-euc", _wrangler_script(), "--"]
        return _uncached(base).with_exec([*command, *wrangler_deploy_args(self.target, source_sha)])

def evidence() -> GitHubEvidence:
    return GitHubEvidence.model_validate({"app_id":15368,"branch":"main",
      "check_completed_at":"2026-08-27T20:00:01Z","check_name":"Dagger","check_run_id":"41",
      "check_started_at":"2026-08-27T20:00:00Z","check_suite_id":"42","commit_sha":SHA,
      "repository":"hseshadr/edge-reco","run_attempt":2,"workflow_created_at":"2026-08-27T19:59:58Z",
      "workflow_job_id":"43","workflow_name":"Dagger","workflow_path":".github/workflows/dagger.yml",
      "workflow_run_id":"44","workflow_started_at":"2026-08-27T19:59:59Z",
      "workflow_updated_at":"2026-08-27T20:00:02Z"})

def service() -> dagger.Service:
    server = dag.container(platform=dagger.Platform("linux/amd64")).from_(PYTHON_IMAGE)
    server = server.with_new_file("/mock_server.py", MOCK_SERVER)
    server = server.with_new_file("/cert.pem", CA_CERT).with_new_file("/key.pem", PRIVATE_KEY)
    server = server.with_exposed_port(8080)
    server = server.with_exposed_port(443, experimental_skip_healthcheck=True)
    return server.as_service(args=["python", "/mock_server.py"])

def fixture_files() -> dagger.Directory:
    source = dag.directory().with_new_file("mock_server.py", MOCK_SERVER)
    source = source.with_new_file("ca.pem", CA_CERT)
    return source.with_new_file("key.pem", PRIVATE_KEY)

async def functions_transaction(envelope: dagger.Directory, operations: MockOperations,
    target: PagesTarget) -> CreatedDeployment:
    verified = await _verify_envelope(envelope, "hseshadr/edge-reco@" + SHA,
      "b" * 40 + ":44", ["dist", "functions"])
    prepared = await _prepare_deploy_artifact(verified, target)
    return await deploy_verified_artifact(operations, prepared, target, evidence(), AttemptIdentity("44", 2))

async def reject_functions_escape(source: dagger.Directory, target: PagesTarget,
    specifier: str) -> None:
    code = f'import pkg from "{specifier}"; export const onRequest=()=>new Response(pkg.name)'
    escaped = source.with_new_file("functions/api/hello.js", code)
    try: await _prepare_deploy_artifact(escaped, target)
    except CloudflarePolicyError: return
    raise ValueError("outside import reached provider transport")

async def reject_external_wasm(source: dagger.Directory, target: PagesTarget) -> None:
    specifier = "../../../usr/local/lib/node_modules/wrangler/node_modules/blake3-wasm/dist/wasm/nodejs/blake3_js_bg.wasm"
    await reject_functions_escape(source, target, specifier)

async def accept_executable_auxiliary(source: dagger.Directory, target: PagesTarget) -> None:
    code = 'import value from "../data.txt"; export const onRequest=()=>new Response(value)'
    value = source.with_new_file("functions/data.txt", "authenticated auxiliary", permissions=0o755)
    value = value.with_new_file("functions/api/hello.js", code)
    prepared = await _prepare_deploy_artifact(value, target)
    worker = prepared.directory("_worker.js")
    paths = await worker.glob("*.txt")
    if len(paths) != 1: raise ValueError("authenticated auxiliary module was not staged")
    emitted = worker.file(paths[0]); original = value.file("functions/data.txt")
    if await emitted.digest() == await original.digest(): raise ValueError("mode fixture did not differ")
    if await emitted.digest(exclude_metadata=True) != await original.digest(exclude_metadata=True):
        raise ValueError("authenticated auxiliary content differed")

async def functions_contract(token: dagger.Secret, account: dagger.Secret,
    mock: dagger.Service, cert: dagger.File) -> None:
    target = PagesTarget("hseshadr/edge-reco", "edge-reco", "main", "edge-reco.com", "dist", pages_functions=True)
    source = dag.directory().with_new_file("dist/index.html", "verified artifact")
    source = source.with_new_file("functions/api/hello.js", 'export const onRequest=()=>new Response("hello-from-functions")')
    missing = source.with_new_file("functions/api/hello.js", 'import value from "not-present"; export const onRequest=()=>new Response(value)')
    try: await _prepare_deploy_artifact(missing, target)
    except CloudflarePolicyError: pass
    else: raise ValueError("missing bare import reached provider transport")
    await reject_functions_escape(source, target, "/usr/local/lib/node_modules/wrangler/package.json")
    await reject_functions_escape(source, target, "../../../usr/local/lib/node_modules/wrangler/package.json")
    await accept_executable_auxiliary(source, target)
    await reject_external_wasm(source, target)
    operations = MockOperations(token, account, target, mock, cert)
    envelope = dag.foundation().envelope(source, "hseshadr/edge-reco@" + SHA,
      "b" * 40 + ":44", ["dist", "functions"])
    for path in ("artifact/dist/index.html", "artifact/functions/api/hello.js"):
        tampered = envelope.with_new_file(path, "tampered")
        try: await functions_transaction(tampered, operations, target)
        except dagger.QueryError: pass
        else: raise ValueError("tampered Functions envelope reached provider transport")
    result = await functions_transaction(envelope, operations, target)
    assert result.source_sha == SHA
    events = json.loads(await operations._request("GET", "/__mock/events"))["result"]["domains"]
    assert events.count("upload") == 2

async def rollback_contract(token: dagger.Secret, account: dagger.Secret,
    mock: dagger.Service, cert: dagger.File) -> None:
    roll = CurlRollbackOperations(token, account, "edge-roll", mock, cert)
    recorded = await live_production_deployment(roll, "edge-roll")
    assert recorded.id == "11111111-0000-4000-8000-000000000000"
    rolled = await rollback_production(roll, "edge-roll", None)
    assert rolled.from_deployment_id == recorded.id
    assert rolled.to_deployment_id == rolled.live_deployment_id == "22222222-0000-4000-8000-000000000000"
    assert rolled.live_deployment_url == "https://22222222.edge-roll.pages.dev"
    try: await rollback_production(roll, "edge-roll", rolled.live_deployment_id)
    except CloudflarePolicyError: pass
    else: raise ValueError("no-op rollback reached provider transport")
    events = json.loads(await roll._request("GET", "/__mock/events"))["result"]["domains"]
    assert events.count("rollback") == 1

@object_type
class ProviderContract:
    @function
    async def contract(self) -> str:
        artifact = dag.directory().with_new_file("dist/index.html", "verified artifact")
        envelope = dag.foundation().envelope(artifact, "hseshadr/edge-reco@" + SHA, "b" * 40 + ":44", ["dist"])
        verified = await _verify_envelope(envelope, "hseshadr/edge-reco@" + SHA, "b" * 40 + ":44", ["dist"])
        token = dag.set_secret("token", "t" * 32); account = dag.set_secret("account", "0123456789abcdef0123456789abcdef")
        mock = service(); await mock.start()
        operations = MockOperations(token, account, PagesTarget("hseshadr/edge-reco", "edge-reco", "main", "edge-reco.com", "dist"), mock, fixture_files().file("ca.pem"))
        result = await deploy_verified_artifact(operations, verified.directory("dist"), operations.target, evidence(), AttemptIdentity("44", 2))
        events = json.loads(await operations._request("GET", "/__mock/events"))["result"]["domains"]
        assert events == ["wrangler-preflight", "get-project", "get-deployments", "disable-git", "get-project", "upload", "get-deployments"]
        assert result.source_sha == SHA
        await functions_contract(token, account, mock, fixture_files().file("ca.pem"))
        await rollback_contract(token, account, mock, fixture_files().file("ca.pem"))
        tampered = envelope.with_new_file("artifact/dist/index.html", "tampered")
        try: await _verify_envelope(tampered, "hseshadr/edge-reco@" + SHA, "b" * 40 + ":44", ["dist"])
        except dagger.QueryError: return "provider order, runnable module tree, multipart, escape, conflict, and tamper rejection passed"
        raise ValueError("tampered envelope was accepted")
"""


def _target(*, pages_functions: bool = False) -> PagesTarget:
    return PagesTarget(
        "hseshadr/edge-reco",
        "edge-reco",
        "main",
        "edge-reco.com",
        "dist",
        pages_functions=pages_functions,
    )


def _github_evidence() -> GitHubEvidence:
    return GitHubEvidence.model_validate(
        {
            "app_id": 15368,
            "branch": "main",
            "check_completed_at": "2026-08-27T20:00:01Z",
            "check_name": "Dagger",
            "check_run_id": "41",
            "check_started_at": "2026-08-27T20:00:00Z",
            "check_suite_id": "42",
            "commit_sha": FULL_SHA,
            "repository": "hseshadr/edge-reco",
            "run_attempt": 2,
            "workflow_created_at": "2026-08-27T19:59:58Z",
            "workflow_job_id": "43",
            "workflow_name": "Dagger",
            "workflow_path": ".github/workflows/dagger.yml",
            "workflow_run_id": "44",
            "workflow_started_at": "2026-08-27T19:59:59Z",
            "workflow_updated_at": "2026-08-27T20:00:02Z",
        }
    )


def _project_payload(project: str = "edge-reco") -> str:
    return json.dumps(
        {
            "errors": [],
            "messages": [],
            "result": {
                "id": "7b162ea7-7367-4d4a-a28a-cb84f88f6",
                "name": project,
                "production_branch": "main",
                "domains": ["edge-reco.pages.dev", "edge-reco.com"],
                "source": {
                    "type": "github",
                    "config": {
                        "owner": "hseshadr",
                        "repo_name": "edge-reco",
                        "production_branch": "main",
                        "production_deployments_enabled": True,
                        "preview_deployment_setting": "all",
                    },
                },
            },
            "success": True,
        }
    )


def _direct_upload_project_payload() -> str:
    payload = json.loads(_project_payload())
    payload["result"]["source"] = None
    return json.dumps(payload)


def _project_payload_with_foreign_domain() -> str:
    payload = json.loads(_direct_upload_project_payload())
    payload["result"]["domains"] = ["edge-reco.pages.dev"]
    return json.dumps(payload)


def _direct_upload_project_payload_with_domain_drift() -> str:
    payload = json.loads(_direct_upload_project_payload())
    payload["result"]["domains"] = ["edge-reco.com", "attacker.example"]
    return json.dumps(payload)


def _git_project_payload_with_domain_drift() -> str:
    payload = json.loads(_project_payload())
    payload["result"]["domains"] = ["edge-reco.com", "attacker.example"]
    config = payload["result"]["source"]["config"]
    config["production_deployments_enabled"] = False
    config["preview_deployment_setting"] = "none"
    return json.dumps(payload)


def _deployment_payload(status: str = "success") -> str:
    result = [] if status == "absent" else [_deployment(status)]
    return json.dumps(
        {
            "errors": [],
            "messages": [],
            "result": result,
            "success": True,
            "result_info": {
                "count": len(result),
                "page": 1,
                "per_page": 10,
                "total_count": len(result),
                "total_pages": int(bool(result)),
            },
        }
    )


def _deployments_payload(*results: dict[str, object]) -> str:
    payload = json.loads(_deployment_payload("absent"))
    payload["result"] = list(results)
    payload["result_info"]["count"] = len(results)
    payload["result_info"]["total_count"] = len(results)
    payload["result_info"]["total_pages"] = int(bool(results))
    return json.dumps(payload)


def _deployment(
    status: str, deployment_id: str = "f64788e9-fccd-4d4a-a28a-cb84f88f6"
) -> dict[str, object]:
    short_id = deployment_id[:8]
    return {
        "id": deployment_id,
        "short_id": short_id,
        "url": f"https://{short_id}.edge-reco.pages.dev",
        "project_id": "7b162ea7-7367-4d4a-a28a-cb84f88f6",
        "project_name": "edge-reco",
        "environment": "production",
        "latest_stage": {"name": "deploy", "status": status},
        "deployment_trigger": {
            "type": "ad_hoc",
            "metadata": {
                "branch": "main",
                "commit_hash": FULL_SHA,
                "commit_dirty": False,
            },
        },
    }


def _with_commit_sha(deployment: dict[str, object], sha: str) -> dict[str, object]:
    trigger = cast(dict[str, object], deployment["deployment_trigger"])
    metadata = cast(dict[str, object], trigger["metadata"])
    metadata["commit_hash"] = sha
    return deployment


def _with_stage(deployment: dict[str, object], name: str, status: str) -> dict[str, object]:
    deployment["latest_stage"] = {"name": name, "status": status}
    return deployment


def _provider_evidence() -> ProviderDeploymentEvidence:
    return ProviderDeploymentEvidence(
        "f64788e9-fccd-4d4a-a28a-cb84f88f6",
        "https://f64788e9.edge-reco.pages.dev",
        "7b162ea7-7367-4d4a-a28a-cb84f88f6",
        "edge-reco",
        "hseshadr/edge-reco",
        "main",
        FULL_SHA,
        AttemptIdentity("44", 2),
    )


@dataclass
class FakeOperations:
    """Deterministic provider double that retains real policy and parsing."""

    deployments: list[str]
    project: str = field(default_factory=_project_payload)
    patched_project: str | None = None
    revalidated_project: str | None = None
    disable_production: bool = True
    disable_preview: bool = True
    events: list[str] = field(default_factory=list)
    sleeps: list[int] = field(default_factory=list)
    uploaded_artifact: object | None = None
    project_reads: int = 0

    async def get_project(self) -> str:
        self.events.append("get-project")
        self.project_reads += 1
        if self.project_reads > 1 and self.revalidated_project is not None:
            return self.revalidated_project
        return self.project

    async def get_deployments(self) -> str:
        self.events.append("get-deployments")
        return self.deployments.pop(0)

    async def disable_git(self) -> str:
        self.events.append("disable-git")
        payload = json.loads(self.patched_project or self.project)
        source = payload["result"]["source"]
        if source is None:
            self.project = json.dumps(payload)
            return self.project
        config = source["config"]
        if self.disable_production:
            config["production_deployments_enabled"] = False
        if self.disable_preview:
            config["preview_deployment_setting"] = "none"
        self.project = json.dumps(payload)
        return self.project

    async def wrangler_preflight(self) -> None:
        self.events.append("wrangler-preflight")

    async def upload(self, artifact: object, source_sha: str) -> CreatedDeployment:
        self.events.append(f"upload:{source_sha}")
        self.uploaded_artifact = artifact
        return CreatedDeployment(
            "f64788e9-fccd-4d4a-a28a-cb84f88f6",
            "https://f64788e9.edge-reco.pages.dev",
        )

    async def sleep(self, seconds: int) -> None:
        self.events.append(f"sleep:{seconds}")
        self.sleeps.append(seconds)


class ImmediateTimeout:
    """Async deadline that expires before the first provider read."""

    async def __aenter__(self) -> None:
        raise TimeoutError

    async def __aexit__(self, error_type: object, error: object, traceback: object) -> None:
        return None


@dataclass
class FakeFile:
    contents_value: str

    async def contents(self) -> str:
        return self.contents_value

    async def size(self) -> int:
        return len(self.contents_value.encode())

    async def digest(self, *, exclude_metadata: bool | None = False) -> str:
        assert exclude_metadata is True
        value = hashlib.sha256(self.contents_value.encode()).hexdigest()
        return f"sha256:{value}"


@dataclass
class DigestConcurrency:
    active: int = 0
    maximum: int = 0


@dataclass(frozen=True)
class ConcurrentDigestFile:
    state: DigestConcurrency

    async def digest(self, *, exclude_metadata: bool | None = False) -> str:
        assert exclude_metadata is True
        self.state.active += 1
        self.state.maximum = max(self.state.maximum, self.state.active)
        await asyncio.sleep(0)
        self.state.active -= 1
        return "sha256:fixture"


@dataclass(frozen=True)
class ConcurrentDigestDirectory:
    state: DigestConcurrency

    def file(self, path: str) -> ConcurrentDigestFile:
        assert path
        return ConcurrentDigestFile(self.state)


@dataclass
class OversizedMetadataFile:
    contents_read: bool = False

    async def size(self) -> int:
        return main_module.FUNCTIONS_METADATA_BYTES + 1

    async def contents(self) -> str:
        self.contents_read = True
        raise AssertionError("CONTENTS_READ_BEFORE_LIMIT")


@dataclass(frozen=True)
class OversizedMetadataDirectory:
    metadata: OversizedMetadataFile

    def file(self, path: str) -> OversizedMetadataFile:
        assert path == main_module.FUNCTIONS_METADATA_NAME
        return self.metadata


@dataclass
class FakeDirectory:
    selected: str = ""
    entries_by_path: dict[str, tuple[str, ...]] = field(default_factory=dict)
    contents_by_path: dict[str, str] = field(default_factory=dict)
    digested: bool = False
    added_files: list[tuple[str, object]] = field(default_factory=list)
    added_directory_values: list[tuple[str, object]] = field(default_factory=list)
    filters: list[tuple[str, ...]] = field(default_factory=list)
    added_directories: list[str] = field(default_factory=list)
    glob_by_path: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def directory(self, path: str) -> FakeDirectory:
        selected = f"{self.selected}/{path}".strip("/")
        return FakeDirectory(
            selected=selected,
            entries_by_path=self.entries_by_path,
            contents_by_path=self.contents_by_path,
            added_files=self.added_files,
            added_directory_values=self.added_directory_values,
            glob_by_path=self.glob_by_path,
        )

    def file(self, path: str) -> object:
        selected = f"{self.selected}/{path}".strip("/")
        if selected in self.contents_by_path:
            return FakeFile(self.contents_by_path[selected])
        return (self.selected, path)

    def with_file(self, path: str, value: object) -> FakeDirectory:
        self.added_files.append((path, value))
        return self

    def with_directory(self, path: str, value: object) -> FakeDirectory:
        self.added_directory_values.append((path, value))
        return self

    def filter(self, *, exclude: list[str]) -> FakeDirectory:
        self.filters.append(tuple(exclude))
        return self

    def with_new_directory(self, path: str) -> FakeDirectory:
        self.added_directories.append(path)
        return self

    async def entries(self) -> list[str]:
        return list(self.entries_by_path.get(self.selected, ()))

    async def glob(self, pattern: str) -> list[str]:
        key = self.selected if self.selected else pattern
        return list(self.glob_by_path.get(key, ()))

    async def digest(self) -> str:
        self.digested = True
        return "sha256:fixture"


@dataclass
class FakeFunctionsContainer:
    """Record the closed Pages Functions compiler boundary."""

    events: list[tuple[str, object]] = field(default_factory=list)
    derived: FakeDirectory = field(
        default_factory=lambda: FakeDirectory(entries_by_path={"": ("_routes.json", "_worker.js/")})
    )

    def with_mounted_directory(self, path: str, value: object, *, read_only: bool = False) -> Self:
        self.events.append(("mount", (path, value, read_only)))
        return self

    def with_mounted_temp(self, path: str) -> Self:
        self.events.append(("temp", path))
        return self

    def with_directory(self, path: str, value: object) -> Self:
        self.events.append(("seed-directory", (path, value)))
        return self

    def with_workdir(self, path: str) -> Self:
        self.events.append(("workdir", path))
        return self

    def with_env_variable(self, name: str, value: str) -> Self:
        self.events.append(("env", (name, value)))
        return self

    def with_exec(self, command: list[str]) -> Self:
        self.events.append(("exec", command))
        return self

    def directory(self, path: str) -> FakeDirectory:
        self.events.append(("directory", path))
        return self.derived


class FailingFunctionsDirectory(FakeDirectory):
    async def entries(self) -> list[str]:
        raise TimeoutError("consumer source detail must stay private")


def _derived_with_metadata(*inputs: str) -> FakeDirectory:
    metadata = json.dumps({"inputs": {path: {"bytes": 1} for path in inputs}, "outputs": {}})
    return FakeDirectory(
        entries_by_path={
            "": ("_build-metadata.json", "_routes.json", "_worker.js/"),
            "_worker.js": ("index.js",),
        },
        contents_by_path={
            "_build-metadata.json": metadata,
            "_worker.js/index.js": "export default {fetch() { return new Response('ok') }};",
        },
        glob_by_path={"_worker.js": ("index.js",)},
    )


def _source_with_auxiliary(value: str) -> FakeDirectory:
    return FakeDirectory(
        contents_by_path={"functions/api/module.wasm": value},
        glob_by_path={"functions/**": ("functions/api/module.wasm",)},
    )


def _derived_with_auxiliary(value: str) -> FakeDirectory:
    derived = _derived_with_metadata("api/hello.js")
    derived.entries_by_path["_worker.js"] = ("index.js", "module.wasm")
    derived.glob_by_path["_worker.js"] = ("index.js", "module.wasm")
    derived.contents_by_path["_worker.js/module.wasm"] = value
    return derived


@dataclass(frozen=True)
class RecordingCurlOperations(CurlPagesOperations):
    """Curl adapter double that records the exact method, suffix, and body."""

    requests: list[tuple[str, str, str]] = field(default_factory=list)

    async def _request(self, method: str, suffix: str, body: str = "") -> str:
        self.requests.append((method, suffix, body))
        return "response"


@dataclass
class FakeContainer:
    """Minimal async Dagger container result used at the transport boundary."""

    output: str = ""
    response: str = ""
    commands: list[list[str]] = field(default_factory=list)
    synced: bool = False

    def with_exec(self, command: list[str]) -> FakeContainer:
        self.commands.append(command)
        return self

    async def stdout(self) -> str:
        return self.output

    def file(self, path: str) -> FakeContainer:
        assert path in {"/work/cloudflare-response.json", main_module.WRANGLER_OUTPUT_PATH}
        return self

    async def contents(self) -> str:
        return self.response

    async def size(self) -> int:
        return len(self.response.encode())

    async def sync(self) -> None:
        self.synced = True


@dataclass
class FakeRequestContainer:
    """Fluent request-container recorder for service injection branches."""

    events: list[str] = field(default_factory=list)

    def _record(self, name: str) -> Self:
        self.events.append(name)
        return self

    def from_(self, *_: object, **__: object) -> Self:
        return self._record("from")

    def with_entrypoint(self, *_: object, **__: object) -> Self:
        return self._record("entrypoint")

    def with_user(self, *_: object, **__: object) -> Self:
        return self._record("user")

    def with_workdir(self, *_: object, **__: object) -> Self:
        return self._record("workdir")

    def with_mounted_temp(self, *_: object, **__: object) -> Self:
        return self._record("temp")

    def with_mounted_secret(self, *_: object, **__: object) -> Self:
        return self._record("secret")

    def with_service_binding(self, *_: object, **__: object) -> Self:
        return self._record("service")

    def with_mounted_file(self, path: object, *_: object, **__: object) -> Self:
        return self._record("ca" if path == "/run/mock-ca.pem" else "jq")

    def with_env_variable(self, *_: object, **__: object) -> Self:
        return self._record("nonce")

    def with_exec(self, *_: object, **__: object) -> Self:
        return self._record("exec")

    def file(self, *_: object, **__: object) -> Self:
        return self._record("file")


@dataclass(frozen=True)
class FakeDag:
    container_value: FakeRequestContainer

    def container(self, *_: object, **__: object) -> FakeRequestContainer:
        return self.container_value


@dataclass
class FakeGreenEvidence:
    value: str

    async def serialization(self) -> str:
        return self.value


@dataclass
class FakeFoundation:
    value: str
    calls: list[tuple[object, str]] = field(default_factory=list)

    def green_main(self, github_token: object, repository: str) -> FakeGreenEvidence:
        self.calls.append((github_token, repository))
        return FakeGreenEvidence(self.value)


@dataclass(frozen=True)
class FakeEvidenceDag:
    foundation_value: FakeFoundation

    def foundation(self) -> FakeFoundation:
        return self.foundation_value


def test_should_bind_foundation_evidence_to_explicit_attempt() -> None:
    # Given
    attempt = AttemptIdentity("44", 2)

    # When / Then
    require_evidence_binding(_target(), _github_evidence(), attempt)


@pytest.mark.asyncio
async def test_should_obtain_exact_green_from_local_foundation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    foundation = FakeFoundation(_github_evidence().model_dump_json())
    monkeypatch.setattr(main_module, "dag", FakeEvidenceDag(foundation))
    token = cast(dagger.Secret, object())
    inputs = main_module.TargetInputs(
        "hseshadr/edge-reco", "edge-reco", "main", "edge-reco.com", "dist", ()
    )
    context = await main_module._provider_context(token, "44", 2, inputs)
    assert foundation.calls == [(token, "hseshadr/edge-reco")]
    assert context.github.commit_sha == FULL_SHA


def test_should_reject_wrong_explicit_attempt() -> None:
    # Given
    attempt = AttemptIdentity("44", 3)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="attempt identity"):
        require_evidence_binding(_target(), _github_evidence(), attempt)


def test_should_reject_foreign_foundation_source() -> None:
    # Given
    evidence = _github_evidence().model_copy(update={"repository": "hseshadr/almamesh"})

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="source identity"):
        require_evidence_binding(_target(), evidence, AttemptIdentity("44", 2))


@pytest.mark.asyncio
async def test_should_deploy_one_verified_artifact_in_required_order() -> None:
    # Given
    artifact = object()
    operations = FakeOperations([_deployment_payload("absent"), _deployment_payload()])

    # When
    evidence = await deploy_verified_artifact(
        operations, artifact, _target(), _github_evidence(), AttemptIdentity("44", 2)
    )

    # Then
    assert operations.events == [
        "wrangler-preflight",
        "get-project",
        "get-deployments",
        "disable-git",
        "get-project",
        f"upload:{FULL_SHA}",
        "get-deployments",
    ]
    assert operations.uploaded_artifact is artifact
    assert evidence.source_sha == FULL_SHA
    assert evidence.attempt_identity == AttemptIdentity("44", 2)


@pytest.mark.asyncio
async def test_should_deploy_existing_direct_upload_without_git_patch() -> None:
    # Given
    project = _direct_upload_project_payload()
    operations = FakeOperations(
        [_deployment_payload("absent"), _deployment_payload()], project=project
    )

    # When
    await deploy_verified_artifact(
        operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
    )

    # Then
    assert operations.events == [
        "wrangler-preflight",
        "get-project",
        "get-deployments",
        "get-project",
        f"upload:{FULL_SHA}",
        "get-deployments",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("project", "expected"),
    (
        (
            _project_payload(),
            [
                "compile-functions",
                "wrangler-preflight",
                "get-project",
                "get-deployments",
                "disable-git",
                "get-project",
                f"upload:{FULL_SHA}",
                "get-deployments",
            ],
        ),
        (
            _direct_upload_project_payload(),
            [
                "compile-functions",
                "wrangler-preflight",
                "get-project",
                "get-deployments",
                "get-project",
                f"upload:{FULL_SHA}",
                "get-deployments",
            ],
        ),
    ),
)
async def test_should_compile_functions_before_git_or_direct_provider_transport(
    monkeypatch: pytest.MonkeyPatch, project: str, expected: list[str]
) -> None:
    artifact = cast(dagger.Directory, object())
    target = _target(pages_functions=True)
    context = main_module.ProviderContext(target, _github_evidence(), AttemptIdentity("44", 2))
    operations = FakeOperations(
        [_deployment_payload("absent"), _deployment_payload()], project=project
    )

    async def verified(*_: object) -> tuple[dagger.Directory, main_module.ProviderContext]:
        return artifact, context

    async def prepare(source: dagger.Directory, _: PagesTarget) -> dagger.Directory:
        operations.events.append("compile-functions")
        return source

    monkeypatch.setattr(main_module, "_verified_context", verified)
    monkeypatch.setattr(main_module, "_prepare_deploy_artifact", prepare)
    monkeypatch.setattr(main_module, "CurlPagesOperations", lambda *_: operations)
    pages = main_module.CloudflarePages.__new__(main_module.CloudflarePages)

    await pages.deploy(
        artifact,
        cast(dagger.Secret, object()),
        cast(dagger.Secret, object()),
        cast(dagger.Secret, object()),
        "44",
        2,
        "hseshadr/edge-reco",
        "edge-reco",
        "main",
        "edge-reco.com",
        "dist",
        [],
        f"hseshadr/edge-reco@{FULL_SHA}",
        "b" * 40 + ":44",
        ["dist", "functions"],
        True,
    )

    assert operations.events == expected


@pytest.mark.asyncio
async def test_should_keep_static_artifact_preparation_as_exact_identity() -> None:
    artifact = cast(dagger.Directory, object())

    assert await main_module._prepare_deploy_artifact(artifact, _target()) is artifact


@pytest.mark.asyncio
async def test_should_reject_direct_upload_identity_drift_before_upload() -> None:
    # Given
    operations = FakeOperations(
        [_deployment_payload("absent")],
        project=_direct_upload_project_payload(),
        revalidated_project=_project_payload_with_foreign_domain(),
    )

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="target binding"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert operations.events == [
        "wrangler-preflight",
        "get-project",
        "get-deployments",
        "get-project",
    ]


@pytest.mark.asyncio
async def test_should_reject_direct_upload_domain_set_drift_before_upload() -> None:
    # Given
    operations = FakeOperations(
        [_deployment_payload("absent")],
        project=_direct_upload_project_payload(),
        revalidated_project=_direct_upload_project_payload_with_domain_drift(),
    )

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="domains changed"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert not any(event.startswith("upload:") for event in operations.events)


@pytest.mark.asyncio
async def test_should_reject_direct_upload_source_added_before_upload() -> None:
    # Given
    operations = FakeOperations(
        [_deployment_payload("absent")],
        project=_direct_upload_project_payload(),
        revalidated_project=_project_payload(),
    )

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="delivery mode changed"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert not any(event.startswith("upload:") for event in operations.events)


@pytest.mark.asyncio
async def test_should_reject_git_source_removed_by_patch() -> None:
    # Given
    operations = FakeOperations(
        [_deployment_payload("absent")], patched_project=_direct_upload_project_payload()
    )

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="delivery mode changed"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert operations.events == [
        "wrangler-preflight",
        "get-project",
        "get-deployments",
        "disable-git",
    ]


@pytest.mark.asyncio
async def test_should_reject_git_source_removed_before_upload() -> None:
    # Given
    operations = FakeOperations(
        [_deployment_payload("absent")],
        revalidated_project=_direct_upload_project_payload(),
    )

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="delivery mode changed"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert operations.events == [
        "wrangler-preflight",
        "get-project",
        "get-deployments",
        "disable-git",
        "get-project",
    ]


@pytest.mark.asyncio
async def test_should_reject_git_domain_set_drift_before_upload() -> None:
    # Given
    operations = FakeOperations(
        [_deployment_payload("absent")],
        revalidated_project=_git_project_payload_with_domain_drift(),
    )

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="domains changed"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert not any(event.startswith("upload:") for event in operations.events)


@pytest.mark.asyncio
async def test_should_ignore_old_same_sha_and_wait_for_created_id() -> None:
    old = _deployment("success", "11111111-fccd-4d4a-a28a-cb84f88f6")
    pending = _deployment("active")
    current = _deployment("success")
    operations = FakeOperations(
        [
            _deployments_payload(old),
            _deployments_payload(old, pending),
            _deployments_payload(old, current),
        ]
    )
    evidence = await deploy_verified_artifact(
        operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
    )
    assert evidence.deployment_id == "f64788e9-fccd-4d4a-a28a-cb84f88f6"
    assert operations.sleeps == [1]


@pytest.mark.asyncio
async def test_should_upload_when_historical_rows_have_empty_commit_sha() -> None:
    # Given
    legacy = _with_commit_sha(_deployment("success", "11111111-fccd-4d4a-a28a-cb84f88f6"), "")
    current = _deployment("success")
    operations = FakeOperations(
        [_deployments_payload(legacy), _deployments_payload(legacy, current)]
    )

    # When
    evidence = await deploy_verified_artifact(
        operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
    )

    # Then
    assert evidence.deployment_id == "f64788e9-fccd-4d4a-a28a-cb84f88f6"
    assert f"upload:{FULL_SHA}" in operations.events


@pytest.mark.asyncio
async def test_should_timeout_when_created_deployment_has_empty_commit_sha() -> None:
    # Given
    empty_created = _with_commit_sha(_deployment("success"), "")
    responses = [_deployments_payload()] + [_deployments_payload(empty_created)] * 5
    operations = FakeOperations(responses)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="did not converge"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert operations.sleeps == [1, 2, 4, 8]


@pytest.mark.asyncio
async def test_should_report_created_failure_despite_old_same_sha_success() -> None:
    old = _deployment("success", "11111111-fccd-4d4a-a28a-cb84f88f6")
    failed = _deployment("failure")
    operations = FakeOperations([_deployments_payload(old), _deployments_payload(old, failed)])
    with pytest.raises(CloudflarePolicyError, match="deployment failed"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert operations.events.count("disable-git") == 1


@pytest.mark.asyncio
async def test_should_converge_with_bounded_exponential_delays() -> None:
    # Given
    operations = FakeOperations(
        [
            _deployment_payload("absent"),
            _deployment_payload("active"),
            _deployment_payload("active"),
            _deployment_payload(),
        ]
    )

    # When
    await deploy_verified_artifact(
        operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
    )

    # Then
    assert operations.sleeps == [1, 2]


@pytest.mark.asyncio
async def test_should_poll_through_documented_predeploy_stages() -> None:
    # Given
    operations = FakeOperations(
        [
            _deployment_payload("absent"),
            _deployments_payload(_with_stage(_deployment("active"), "queued", "idle")),
            _deployments_payload(_with_stage(_deployment("active"), "build", "active")),
            _deployment_payload(),
        ]
    )

    # When
    await deploy_verified_artifact(
        operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
    )

    # Then
    assert operations.sleeps == [1, 2]


@pytest.mark.asyncio
async def test_should_accept_success_after_final_bounded_delay() -> None:
    # Given
    responses = [_deployment_payload("absent")] * 5 + [_deployment_payload()]
    operations = FakeOperations(responses)

    # When
    await deploy_verified_artifact(
        operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
    )

    # Then
    assert operations.sleeps == [1, 2, 4, 8]


@pytest.mark.asyncio
async def test_should_timeout_without_unbounded_polling() -> None:
    # Given
    responses = [_deployment_payload("absent")] * 6
    operations = FakeOperations(responses)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="did not converge"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert operations.sleeps == [1, 2, 4, 8]


@pytest.mark.asyncio
async def test_should_enforce_hard_convergence_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    operations = FakeOperations([_deployment_payload("absent")])
    monkeypatch.setattr(asyncio, "timeout", lambda _: ImmediateTimeout())

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="within 60 seconds"):
        await verify_current_deployment(
            operations, _target(), _github_evidence(), AttemptIdentity("44", 2)
        )


@pytest.mark.asyncio
async def test_should_not_mutate_foreign_project() -> None:
    # Given
    operations = FakeOperations([_deployment_payload()], _project_payload("almamesh"))

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="target binding"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert operations.events == ["wrangler-preflight", "get-project"]


@pytest.mark.asyncio
async def test_should_reject_project_change_after_single_patch() -> None:
    # Given
    patched = json.loads(_project_payload())
    patched["result"]["id"] = "foreign-project-id"
    operations = FakeOperations(
        [_deployment_payload("absent")],
        patched_project=json.dumps(patched),
    )

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="identity changed"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert operations.events == [
        "wrangler-preflight",
        "get-project",
        "get-deployments",
        "disable-git",
    ]


@pytest.mark.asyncio
async def test_should_reject_git_production_mode_left_enabled() -> None:
    # Given
    operations = FakeOperations([_deployment_payload("absent")], disable_production=False)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="production deployment remains"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )


@pytest.mark.asyncio
async def test_should_reject_git_preview_mode_left_enabled() -> None:
    # Given
    operations = FakeOperations([_deployment_payload("absent")], disable_preview=False)

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="preview deployment remains"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )


@pytest.mark.asyncio
async def test_should_revalidate_disabled_project_immediately_before_upload() -> None:
    operations = FakeOperations(
        [_deployment_payload("absent")], revalidated_project=_project_payload()
    )
    with pytest.raises(CloudflarePolicyError, match="production deployment remains"):
        await deploy_verified_artifact(
            operations, object(), _target(), _github_evidence(), AttemptIdentity("44", 2)
        )
    assert not any(event.startswith("upload:") for event in operations.events)


@pytest.mark.asyncio
async def test_should_run_read_only_public_preflight() -> None:
    # Given
    operations = FakeOperations([_deployment_payload("absent")])

    # When
    await preflight_provider(operations, _target())

    # Then
    assert operations.events == ["get-project", "get-deployments", "wrangler-preflight"]


@pytest.mark.asyncio
async def test_should_verify_current_deployment_without_mutation() -> None:
    # Given
    operations = FakeOperations([_deployment_payload()])

    # When
    evidence = await verify_current_deployment(
        operations, _target(), _github_evidence(), AttemptIdentity("44", 2)
    )

    # Then
    assert operations.events == ["get-project", "get-deployments"]
    assert evidence.deployment_id == "f64788e9-fccd-4d4a-a28a-cb84f88f6"


def test_should_upload_without_build_or_secret_arguments() -> None:
    # Given / When
    command = wrangler_deploy_args(_target(), FULL_SHA)

    # Then
    assert command == [
        "wrangler",
        "pages",
        "deploy",
        "/artifact",
        "--project-name=edge-reco",
        "--branch=main",
        f"--commit-hash={FULL_SHA}",
        "--commit-dirty=false",
        "--no-bundle",
        "--skip-caching",
    ]


@pytest.mark.asyncio
async def test_should_build_only_documented_api_requests() -> None:
    # Given
    operations = RecordingCurlOperations(
        cast(dagger.Secret, object()), cast(dagger.Secret, object()), _target()
    )

    # When
    await operations.get_project()
    await operations.get_deployments()
    await operations.disable_git()

    # Then
    assert operations.requests[0] == ("GET", "/pages/projects/edge-reco", "")
    assert operations.requests[1] == (
        "GET",
        "/pages/projects/edge-reco/deployments?env=production&per_page=10",
        "",
    )
    patch = json.loads(operations.requests[2][2])
    assert patch == api_module.disable_git_payload(_target())


def test_should_inject_only_internal_tls_mock_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    container = FakeRequestContainer()
    monkeypatch.setattr(main_module, "dag", FakeDag(container))
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()),
        cast(dagger.Secret, object()),
        _target(),
        cast(dagger.Service, object()),
        cast(dagger.File, object()),
    )

    # When
    operations._request_container("GET", "/pages/projects/edge-reco", "")

    # Then
    assert "service" in container.events
    assert "ca" in container.events


def test_should_omit_mock_dependencies_in_production(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    container = FakeRequestContainer()
    monkeypatch.setattr(main_module, "dag", FakeDag(container))
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()), cast(dagger.Secret, object()), _target()
    )

    # When
    operations._request_container("GET", "/pages/projects/edge-reco", "")

    # Then
    assert "service" not in container.events
    assert "ca" not in container.events


@pytest.mark.asyncio
async def test_should_validate_pinned_wrangler_help(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    container = FakeContainer(" ".join(main_module.WRANGLER_REQUIRED_FLAGS))
    monkeypatch.setattr(main_module, "_wrangler_base", lambda: container)
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()), cast(dagger.Secret, object()), _target()
    )

    # When
    await operations.wrangler_preflight()

    # Then
    assert container.commands == [["wrangler", "pages", "deploy", "--help"]]


@pytest.mark.asyncio
async def test_should_validate_pinned_functions_build_help(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = " ".join(
        (*main_module.WRANGLER_REQUIRED_FLAGS, *main_module.WRANGLER_FUNCTIONS_REQUIRED_FLAGS)
    )
    container = FakeContainer(output)
    monkeypatch.setattr(main_module, "_wrangler_base", lambda: container)
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()),
        cast(dagger.Secret, object()),
        _target(pages_functions=True),
    )

    await operations.wrangler_preflight()

    assert container.commands == [
        ["wrangler", "pages", "deploy", "--help"],
        ["wrangler", "pages", "functions", "build", "--help"],
    ]


@pytest.mark.asyncio
async def test_should_reject_changed_wrangler_help(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    monkeypatch.setattr(main_module, "_wrangler_base", lambda: FakeContainer("usage"))
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()), cast(dagger.Secret, object()), _target()
    )

    # When / Then
    with pytest.raises(CloudflarePolicyError, match="flags differ"):
        await operations.wrangler_preflight()


@pytest.mark.asyncio
async def test_should_sanitize_transport_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    container = FakeContainer('500\n{"errors":[]}', "")
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()), cast(dagger.Secret, object()), _target()
    )
    monkeypatch.setattr(
        CurlPagesOperations,
        "_request_container",
        lambda *_: cast(dagger.Container, container),
    )

    # When / Then
    with pytest.raises(api_module.CloudflareApiError, match="API request failed"):
        await operations._request("GET", "/pages/projects/edge-reco")


@pytest.mark.asyncio
async def test_should_read_successful_transport_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    container = FakeContainer("200\nprovider-body", "")
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()), cast(dagger.Secret, object()), _target()
    )
    monkeypatch.setattr(
        CurlPagesOperations,
        "_request_container",
        lambda *_: cast(dagger.Container, container),
    )

    # When / Then
    assert await operations._request("GET", "/pages/projects/edge-reco") == "provider-body"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "limit"),
    (("200", main_module.API_RESPONSE_BYTES), ("500", main_module.API_ERROR_BYTES)),
)
async def test_should_reject_oversized_provider_response(status: str, limit: int) -> None:
    container = FakeContainer(status + "\n" + "x" * (limit + 1), "")
    with pytest.raises(api_module.CloudflareApiError, match="byte limit"):
        await main_module._request_result(cast(dagger.Container, container))


@pytest.mark.asyncio
async def test_should_reject_unframed_provider_response() -> None:
    with pytest.raises(api_module.CloudflareApiError, match="framing"):
        await main_module._request_result(cast(dagger.Container, FakeContainer("200")))


def test_should_keep_static_envelope_root_contract_unchanged() -> None:
    main_module._require_deploy_root(_target(), ["dist"])
    with pytest.raises(CloudflarePolicyError, match="only envelope root"):
        main_module._require_deploy_root(_target(), ["dist", "reports"])


@pytest.mark.parametrize(
    "roots",
    (
        ["dist"],
        ["functions", "dist"],
        ["dist", "functions", "reports"],
        ["dist", "Functions"],
    ),
)
def test_should_require_exact_pages_functions_root_matrix(roots: list[str]) -> None:
    target = _target(pages_functions=True)
    with pytest.raises(CloudflarePolicyError, match=r"dist.*functions"):
        main_module._require_deploy_root(target, roots)


def test_should_accept_only_ordered_pages_functions_roots() -> None:
    main_module._require_deploy_root(_target(pages_functions=True), ["dist", "functions"])


def test_should_build_pages_functions_from_one_read_only_project_mount(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = FakeFunctionsContainer()
    artifact = FakeDirectory()
    empty_directory = object()
    monkeypatch.setattr(main_module, "_wrangler_base", lambda: container)
    monkeypatch.setattr(main_module, "_empty_directory", lambda: empty_directory)

    result = cast(
        FakeFunctionsContainer,
        main_module._functions_build_container(cast(dagger.Directory, artifact)),
    )

    assert result is container
    assert container.events == [
        ("mount", ("/project", artifact, True)),
        ("temp", "/project/.wrangler/tmp"),
        ("seed-directory", ("/derived", empty_directory)),
        ("temp", "/run/functions-cache"),
        ("temp", "/run/functions-config"),
        ("env", ("WRANGLER_CACHE_DIR", "/run/functions-cache")),
        ("env", ("XDG_CONFIG_HOME", "/run/functions-config")),
        ("workdir", "/project"),
        ("exec", main_module.functions_build_args()),
    ]


def test_should_remove_consumer_packages_and_configs_from_compiler_input() -> None:
    source = FakeDirectory()

    result = cast(FakeDirectory, main_module._functions_source(cast(dagger.Directory, source)))

    assert result is source
    assert source.filters == [
        (
            "**/node_modules",
            "**/package.json",
            "**/package-lock.json",
            "**/pnpm-lock.yaml",
            "**/yarn.lock",
            "**/wrangler.toml",
            "**/wrangler.json",
            "**/wrangler.jsonc",
        )
    ]
    assert source.added_directories == [".wrangler/tmp"]


def test_should_request_module_directory_output_from_pinned_functions_compiler() -> None:
    assert main_module.functions_build_args() == [
        "wrangler",
        "pages",
        "functions",
        "build",
        "functions",
        "--outdir=/derived/_worker.js",
        "--output-routes-path=/derived/_routes.json",
        "--project-directory=/project",
        "--build-output-directory=/project/dist",
        "--metafile=/derived/_build-metadata.json",
    ]


@pytest.mark.asyncio
async def test_should_stage_only_compiled_worker_and_routes() -> None:
    source = FakeDirectory(entries_by_path={"dist": ("index.html",)})
    derived = _derived_with_metadata(
        "api/hello.js",
        "../.wrangler/tmp/functionsRoutes-fixed.mjs",
        "../../usr/local/lib/node_modules/wrangler/node_modules/path-to-regexp/dist.es2015/index.js",
        "../../usr/local/lib/node_modules/wrangler/templates/pages-template-worker.ts",
    )
    container = FakeFunctionsContainer(derived=derived)

    staged = await main_module._compiled_pages_artifact(
        cast(dagger.Directory, source), cast(dagger.Container, container), "dist"
    )

    assert cast(FakeDirectory, staged).selected == "dist"
    assert cast(FakeDirectory, staged).added_directory_values == [
        ("_worker.js", derived.directory("_worker.js"))
    ]
    assert cast(FakeDirectory, staged).added_files == [("_routes.json", ("", "_routes.json"))]


@pytest.mark.asyncio
async def test_should_reject_serialized_multipart_worker_before_staging() -> None:
    derived = _derived_with_metadata("api/hello.js")
    derived.contents_by_path["_worker.js/index.js"] = (
        "------formdata-undici-fixed\r\nContent-Disposition: form-data; name=metadata"
    )
    container = FakeFunctionsContainer(derived=derived)

    with pytest.raises(CloudflarePolicyError, match="module output differs"):
        await main_module._compiled_pages_artifact(
            cast(dagger.Directory, FakeDirectory()), cast(dagger.Container, container), "dist"
        )


@pytest.mark.asyncio
async def test_should_reject_worker_module_path_escape_before_staging() -> None:
    derived = _derived_with_metadata("api/hello.js")
    derived.glob_by_path["_worker.js"] = ("index.js", "../outside.js")
    container = FakeFunctionsContainer(derived=derived)

    with pytest.raises(CloudflarePolicyError, match="module output differs"):
        await main_module._compiled_pages_artifact(
            cast(dagger.Directory, FakeDirectory()), cast(dagger.Container, container), "dist"
        )


@pytest.mark.asyncio
async def test_should_reject_missing_worker_entrypoint_before_staging() -> None:
    derived = _derived_with_metadata("api/hello.js")
    derived.entries_by_path["_worker.js"] = ("foreign.js",)
    derived.glob_by_path["_worker.js"] = ("foreign.js",)
    container = FakeFunctionsContainer(derived=derived)

    with pytest.raises(CloudflarePolicyError, match="module output differs"):
        await main_module._compiled_pages_artifact(
            cast(dagger.Directory, FakeDirectory()), cast(dagger.Container, container), "dist"
        )


@pytest.mark.asyncio
async def test_should_reject_changed_functions_build_outputs() -> None:
    source = FakeDirectory(entries_by_path={"dist": ("index.html",)})
    derived = FakeDirectory(entries_by_path={"": ("_worker.js", "foreign.txt")})
    container = FakeFunctionsContainer(derived=derived)

    with pytest.raises(CloudflarePolicyError, match="derived outputs differ"):
        await main_module._compiled_pages_artifact(
            cast(dagger.Directory, source), cast(dagger.Container, container), "dist"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("outside", ("/outside.mjs", "../outside.mjs"))
async def test_should_reject_resolved_inputs_outside_authenticated_roots(outside: str) -> None:
    derived = _derived_with_metadata("api/hello.js", outside)

    with pytest.raises(CloudflarePolicyError, match="escaped authenticated roots"):
        await main_module._require_closed_functions_build(
            cast(dagger.Directory, FakeDirectory()), cast(dagger.Directory, derived)
        )


@pytest.mark.asyncio
async def test_should_accept_only_authenticated_and_fixed_compiler_inputs() -> None:
    derived = _derived_with_metadata(
        "api/hello.js",
        "../dist/shared.js",
        "../.wrangler/tmp/functionsRoutes-fixed.mjs",
        "../../usr/local/lib/node_modules/wrangler/node_modules/path-to-regexp/dist.es2015/index.js",
        "../../usr/local/lib/node_modules/wrangler/templates/pages-template-worker.ts",
    )

    await main_module._require_closed_functions_build(
        cast(dagger.Directory, FakeDirectory()), cast(dagger.Directory, derived)
    )


@pytest.mark.asyncio
async def test_should_accept_auxiliary_worker_with_authenticated_content() -> None:
    source = _source_with_auxiliary("authenticated wasm")
    derived = _derived_with_auxiliary("authenticated wasm")

    await main_module._require_closed_functions_build(
        cast(dagger.Directory, source), cast(dagger.Directory, derived)
    )


@pytest.mark.asyncio
async def test_should_reject_auxiliary_worker_without_authenticated_content() -> None:
    source = _source_with_auxiliary("authenticated wasm")
    derived = _derived_with_auxiliary("toolchain wasm")

    with pytest.raises(CloudflarePolicyError, match="module provenance differs"):
        await main_module._require_closed_functions_build(
            cast(dagger.Directory, source), cast(dagger.Directory, derived)
        )


@pytest.mark.asyncio
async def test_should_bound_terminal_content_digest_queries() -> None:
    state = DigestConcurrency()
    directory = ConcurrentDigestDirectory(state)
    paths = tuple(f"asset-{index}.wasm" for index in range(65))

    await main_module._file_digests(cast(dagger.Directory, directory), paths)

    assert 1 < state.maximum <= 32


@pytest.mark.asyncio
async def test_should_reject_unlisted_pinned_image_input() -> None:
    derived = _derived_with_metadata(
        "api/hello.js",
        "../../usr/local/lib/node_modules/wrangler/package.json",
    )

    with pytest.raises(CloudflarePolicyError, match="escaped authenticated roots"):
        await main_module._require_closed_functions_build(
            cast(dagger.Directory, FakeDirectory()), cast(dagger.Directory, derived)
        )


@pytest.mark.asyncio
async def test_should_reject_oversized_build_metadata_before_reading_contents() -> None:
    metadata = OversizedMetadataFile()
    derived = OversizedMetadataDirectory(metadata)

    with pytest.raises(CloudflarePolicyError, match="build metadata differs"):
        await main_module._functions_build_metadata(cast(dagger.Directory, derived))
    assert metadata.contents_read is False


def test_should_resolve_metadata_from_fixed_functions_working_directory() -> None:
    assert main_module._resolved_functions_input("api/hello.js").as_posix() == (
        "/project/functions/api/hello.js"
    )


@pytest.mark.asyncio
async def test_should_sanitize_functions_build_failure_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container = FakeFunctionsContainer(derived=FailingFunctionsDirectory())
    monkeypatch.setattr(
        main_module,
        "_functions_build_container",
        lambda _: cast(dagger.Container, container),
    )

    with pytest.raises(CloudflarePolicyError, match="Pages Functions build failed") as error:
        await main_module._prepare_deploy_artifact(
            cast(dagger.Directory, FakeDirectory()), _target(pages_functions=True)
        )
    assert "consumer source detail" not in str(error.value)


@pytest.mark.asyncio
async def test_should_upload_with_bounded_adapter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    output = json.dumps(
        {
            "type": "pages-deploy",
            "version": 1,
            "pages_project": "edge-reco",
            "deployment_id": "f64788e9-fccd-4d4a-a28a-cb84f88f6",
            "url": "https://f64788e9.edge-reco.pages.dev",
            "timestamp": "2026-08-27T20:00:00Z",
        }
    )
    container = FakeContainer(output=output)
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()), cast(dagger.Secret, object()), _target()
    )
    monkeypatch.setattr(
        CurlPagesOperations,
        "_upload_container",
        lambda *_: cast(dagger.Container, container),
    )

    # When
    created = await operations.upload(cast(dagger.Directory, object()), FULL_SHA)

    # Then
    assert created.deployment_id == "f64788e9-fccd-4d4a-a28a-cb84f88f6"


@pytest.mark.asyncio
async def test_should_sleep_only_requested_backoff() -> None:
    # Given
    operations = CurlPagesOperations(
        cast(dagger.Secret, object()), cast(dagger.Secret, object()), _target()
    )

    # When / Then
    await operations.sleep(0)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("consumer_matches", "pages_functions"),
    ((True, False), (False, False), (True, True)),
)
async def test_should_bind_verified_envelope_to_internal_green_evidence(
    monkeypatch: pytest.MonkeyPatch, consumer_matches: bool, pages_functions: bool
) -> None:
    verified = FakeDirectory(entries_by_path={"dist": ("index.html",), "functions": ("api",)})
    target = _target(pages_functions=pages_functions)
    context = main_module.ProviderContext(target, _github_evidence(), AttemptIdentity("44", 2))

    async def verify(*_: object) -> FakeDirectory:
        return verified

    async def provider(*_: object) -> main_module.ProviderContext:
        return context

    monkeypatch.setattr(main_module, "_verify_envelope", verify)
    monkeypatch.setattr(main_module, "_provider_context", provider)
    consumer = f"hseshadr/edge-reco@{FULL_SHA}" if consumer_matches else "foreign"
    inputs = main_module.TargetInputs(
        "hseshadr/edge-reco",
        "edge-reco",
        "main",
        "edge-reco.com",
        "dist",
        (),
        pages_functions,
    )
    allowed_roots = ["dist", "functions"] if pages_functions else ["dist"]
    arguments = (
        cast(dagger.Directory, object()),
        cast(dagger.Secret, object()),
        "44",
        2,
        inputs,
        consumer,
        "b" * 40 + ":44",
        allowed_roots,
    )
    if not consumer_matches:
        with pytest.raises(CloudflarePolicyError, match="Envelope source identity"):
            await main_module._verified_context(*arguments)
        return
    artifact, result = await main_module._verified_context(*arguments)
    expected = "" if pages_functions else "dist"
    assert cast(FakeDirectory, artifact).selected == expected
    assert result == context


@pytest.mark.asyncio
@pytest.mark.parametrize("conflict", ("_worker.js", "_worker.js/", "_routes.json", "_routes.json/"))
async def test_should_reject_derived_conflict_before_green_main(
    monkeypatch: pytest.MonkeyPatch,
    conflict: str,
) -> None:
    verified = FakeDirectory(
        entries_by_path={"dist": (conflict, "index.html"), "functions": ("api",)}
    )
    green_called = False

    async def verify(*_: object) -> FakeDirectory:
        return verified

    async def provider(*_: object) -> main_module.ProviderContext:
        nonlocal green_called
        green_called = True
        raise AssertionError("green-main must not run for a conflicting envelope")

    monkeypatch.setattr(main_module, "_verify_envelope", verify)
    monkeypatch.setattr(main_module, "_provider_context", provider)
    inputs = main_module.TargetInputs(
        "hseshadr/edge-reco",
        "edge-reco",
        "main",
        "edge-reco.com",
        "dist",
        (),
        True,
    )

    with pytest.raises(CloudflarePolicyError, match=rf"{conflict}.*functions"):
        await main_module._verified_context(
            cast(dagger.Directory, object()),
            cast(dagger.Secret, object()),
            "44",
            2,
            inputs,
            f"hseshadr/edge-reco@{FULL_SHA}",
            "b" * 40 + ":44",
            ["dist", "functions"],
        )
    assert green_called is False


@pytest.mark.asyncio
async def test_should_reject_empty_functions_root_before_provider_transport() -> None:
    verified = FakeDirectory(entries_by_path={"dist": ("index.html",), "functions": ()})

    with pytest.raises(CloudflarePolicyError, match="functions root must not be empty"):
        await main_module._require_pages_functions_source(
            cast(dagger.Directory, verified), _target(pages_functions=True)
        )


def test_should_reject_malformed_wrangler_output() -> None:
    with pytest.raises(CloudflarePolicyError, match="output schema"):
        main_module._parse_wrangler_output("{}", _target())


def test_should_reject_multiple_matching_wrangler_records() -> None:
    record = main_module._wrangler_records(
        json.dumps(
            {
                "type": "pages-deploy",
                "version": 1,
                "pages_project": "edge-reco",
                "deployment_id": "f64788e9-fccd-4d4a-a28a-cb84f88f6",
                "url": "https://f64788e9.edge-reco.pages.dev",
                "timestamp": "2026-08-27T20:00:00Z",
            }
        )
    )[0]
    with pytest.raises(CloudflarePolicyError, match="created deployment identity"):
        main_module._one_wrangler_record((record, record))


def test_should_materialize_complete_public_evidence() -> None:
    # Given / When
    evidence = main_module._public_evidence(_provider_evidence())

    # Then
    assert evidence.provider == "cloudflare-pages"
    assert evidence.deployment_id == "f64788e9-fccd-4d4a-a28a-cb84f88f6"
    assert evidence.source_sha == FULL_SHA
    assert evidence.workflow_run_id == "44"
    assert evidence.run_attempt == 2


def test_should_keep_api_origin_and_credentials_out_of_curl_argv() -> None:
    # Given / When
    script = main_module._curl_script()

    # Then
    assert "https://api.cloudflare.com/client/v4/accounts/%s%s" in script
    assert "/run/secrets/token" in script
    assert "--config /work/cloudflare-curl.cfg" in script


def test_should_expose_only_uncached_provider_functions() -> None:
    # Given
    tree = ast.parse(MAIN.read_text())
    methods = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name in {"preflight", "deploy", "verify"}
    ]

    # When
    cache_values = [_cache_value(method) for method in methods]

    # Then
    assert {method.name for method in methods} == {"preflight", "deploy", "verify"}
    assert cache_values == ["never", "never", "never"]


def test_should_not_accept_forgeable_public_github_json() -> None:
    tree = ast.parse(MAIN.read_text())
    methods = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name in {"preflight", "deploy", "verify"}
    ]
    arguments = {argument.arg for method in methods for argument in method.args.args}
    assert "github_evidence" not in arguments
    assert "github_token" in arguments
    assert all(
        {
            "envelope",
            "consumer_identity",
            "producing_identity",
            "allowed_roots",
            "deploy_root",
        }.issubset({arg.arg for arg in method.args.args})
        for method in methods
    )


def test_should_expose_pages_functions_as_one_default_false_option() -> None:
    tree = ast.parse(MAIN.read_text())
    methods = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name in {"preflight", "deploy", "verify"}
    ]

    for method in methods:
        names = [argument.arg for argument in method.args.args]
        assert names[-1] == "pages_functions"
        default = method.args.defaults[-1]
        assert isinstance(default, ast.Constant)
        assert default.value is False


def test_should_verify_envelope_before_internal_green_main() -> None:
    tree = ast.parse(MAIN.read_text())
    helper = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_verified_context"
    )
    calls = [
        node.func.id
        for node in ast.walk(helper)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    ]
    assert calls.index("_verify_envelope") < calls.index("_provider_context")


def test_should_use_temporary_mounts_and_method_specific_retries() -> None:
    source = MAIN.read_text()
    assert source.count("with_mounted_temp") >= 3
    script = main_module._curl_script()
    assert 'if [ "$method" = GET ]' in script
    assert "retry = 0" in script
    assert "WRANGLER_OUTPUT_FILE_PATH" in source


def test_should_reject_public_url_or_command_escape_hatches() -> None:
    # Given
    tree = ast.parse(MAIN.read_text())
    methods = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name in {"preflight", "deploy", "verify"}
    ]

    # When
    arguments = {argument.arg for method in methods for argument in method.args.args}

    # Then
    assert not arguments.intersection({"url", "origin", "command", "cmd", "script"})


def test_real_fixture_should_cover_closed_two_root_functions_transaction() -> None:
    required = (
        '["dist", "functions"]',
        "artifact/dist/index.html",
        "artifact/functions/api/hello.js",
        "/usr/local/lib/node_modules/wrangler/package.json",
        "[ -d /artifact/_worker.js ]",
        "Content-Disposition: form-data",
        "node --input-type=module --check",
        "deploy_verified_artifact(",
        'events.count("upload") == 2',
    )

    assert all(value in FIXTURE_MAIN for value in required)


def _cache_value(method: ast.AsyncFunctionDef) -> str | None:
    decorator = next(item for item in method.decorator_list if isinstance(item, ast.Call))
    cache = next(item.value for item in decorator.keywords if item.arg == "cache")
    return cache.value if isinstance(cache, ast.Constant) and isinstance(cache.value, str) else None


def _run(command: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)


def _require_success(result: subprocess.CompletedProcess[str]) -> None:
    assert result.returncode == 0, f"{result.stdout}\n{result.stderr}"


def _initialize_fixture(fixture: Path) -> None:
    command = ["dagger", "init", "--name", "provider-contract", "--sdk", "python"]
    _require_success(_run([*command, "--source", ".dagger"], fixture))
    shutil.copytree(FOUNDATION, fixture / "foundation", ignore=_fixture_ignore())
    _require_success(_run(["dagger", "install", "foundation", "--name", "foundation"], fixture))


def _fixture_ignore() -> Callable[[str, list[str]], set[str]]:
    return shutil.ignore_patterns(".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache")


def _copy_fixture_sources(fixture: Path) -> None:
    source = fixture / ".dagger"
    shutil.copytree(PROVIDER_SOURCE, source / "src/cloudflare_pages")
    (source / "src/provider_contract/main.py").write_text(_fixture_main(fixture))


def _fixture_main(fixture: Path) -> str:
    value = FIXTURE_MAIN.replace("__MOCK_SERVER__", repr(MOCK_SERVER))
    value = value.replace("__CA_CERT__", repr((fixture / "ca.pem").read_text()))
    return value.replace("__PRIVATE_KEY__", repr((fixture / "key.pem").read_text()))


def _add_fixture_dependency(fixture: Path) -> None:
    project = fixture / ".dagger/pyproject.toml"
    value = project.read_text().replace(
        'dependencies = ["dagger-io"]',
        'dependencies = ["dagger-io", "pydantic>=2.11,<3"]',
    )
    project.write_text(value)


def _create_fixture_certificate(fixture: Path) -> None:
    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=api.cloudflare.com",
        "-addext",
        "subjectAltName=DNS:api.cloudflare.com",
        "-keyout",
        "key.pem",
        "-out",
        "ca.pem",
        "-days",
        "1",
    ]
    _require_success(_run(command, fixture))


def _prepare_fixture(fixture: Path) -> None:
    fixture.mkdir()
    _initialize_fixture(fixture)
    _create_fixture_certificate(fixture)
    _copy_fixture_sources(fixture)
    _add_fixture_dependency(fixture)
    _require_success(_run(["uv", "lock", "--directory", ".dagger"], fixture))
    _require_success(_run(["dagger", "develop"], fixture))


def test_should_run_real_dagger_mock_provider_contract(tmp_path: Path) -> None:
    # Given
    fixture = tmp_path / "provider-contract"
    _prepare_fixture(fixture)

    # When
    result = _run(["dagger", "call", "contract"], fixture)

    # Then
    _require_success(result)
    assert (
        "provider order, runnable module tree, multipart, escape, conflict, and tamper rejection passed"
        in result.stdout
    )
