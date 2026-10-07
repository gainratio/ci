from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import cast

from ci.fleet_policy import SHARED_MODULES, SourceFile, validate_workflow

ROOT = Path(__file__).parents[2]
MODULE = ROOT / "modules" / "python-package"
MAIN = MODULE / ".dagger" / "src" / "python_package" / "main.py"


def test_should_ship_exact_local_python_package_module() -> None:
    # Given the central reusable-module inventory
    config = _json(MODULE / "dagger.json")

    # When the package Lego identity and dependency are inspected
    dependencies = cast(list[object], config["dependencies"])

    # Then it is a same-tree module composed from the exact Foundation Lego
    assert config["name"] == "python-package"
    assert config["engineVersion"] == "v0.21.8"
    assert dependencies == [{"name": "foundation", "source": "../portfolio-foundation"}]


def test_should_register_python_package_in_central_same_tree_fleet() -> None:
    # Given the central root dependency graph and recursive fleet policy
    root = _json(ROOT / "dagger.json")
    fleet = (ROOT / ".dagger/src/ci/fleet_policy.py").read_text()

    # When Python package module identities are inventoried
    dependencies = cast(list[object], root["dependencies"])

    # Then both same-tree edges and the exact remote publisher are closed contracts
    assert {"name": "python-package", "source": "modules/python-package"} in dependencies
    assert SHARED_MODULES["python-package"] == (
        "github.com/hseshadr/ci/modules/python-package@",
        "github.com/gainratio/ci/modules/python-package@",
    )
    assert '"modules/python-package/dagger.json"' in fleet
    assert '"../portfolio-foundation"' in fleet


def test_should_prove_python_package_generated_clients_in_both_languages() -> None:
    # Given the committed Python and TypeScript consumer fixtures
    fixtures = ROOT / "tests/dagger"
    configs = tuple(
        _json(fixtures / name / "dagger.json")
        for name in ("python_consumer", "typescript_consumer")
    )

    # When their local dependencies and generated-client calls are inspected
    dependencies = tuple(cast(list[object], item["dependencies"]) for item in configs)
    python = (fixtures / "python_consumer/.dagger/src/python_consumer/main.py").read_text()
    typescript = (fixtures / "typescript_consumer/src/index.ts").read_text()

    # Then both languages compile and execute the same local package Lego
    expected = {"name": "python-package", "source": "../../../modules/python-package"}
    assert all(expected in items for items in dependencies)
    assert "dag.python_package().build(" in python
    assert "dag.pythonPackage().build(" in typescript


def test_should_document_source_free_official_pypa_boundary() -> None:
    # Given the central quickstart and repository landing page
    readme = (ROOT / "README.md").read_text()
    guide = (ROOT / "docs/dagger-modules.md").read_text()

    # When package candidate installation and publication ownership are explained
    required = (
        "modules/python-package",
        "source-free",
        "pypa/gh-action-pypi-publish",
        "id-token: write",
        "github.event.workflow_run.head_sha",
        "github-token: ${{ github.token }}",
        "run-id: ${{ github.event.workflow_run.id }}",
    )

    # Then a consumer can install the Lego without granting Dagger publication authority
    assert "python-package" in readme
    assert all(fragment in guide for fragment in required)
    assert "dagger call candidate" in guide
    assert "needs: candidate" not in guide
    source = SourceFile(path="docs/python-publisher.yml", text=_publisher_example(guide))
    assert validate_workflow(source, repository="python-project") == ()


def test_should_expose_only_closed_release_candidate_functions() -> None:
    # Given the public Python package Dagger object
    module = ast.parse(MAIN.read_text())

    # When decorated functions are projected to their public schema
    signatures = _public_signatures(module)

    # Then callers receive only closed build, audit, and candidate operations
    assert signatures == {
        "build": ("source", "repository", "commit_sha", "project_name"),
        "candidate": (
            "source",
            "github_token",
            "repository",
            "commit_sha",
            "project_name",
            "central_module_sha",
            "workflow_run_id",
            "run_attempt",
        ),
        "dependency_audit": ("source", "repository", "commit_sha", "http_auth_header"),
        "verify_candidate": (
            "envelope",
            "repository",
            "commit_sha",
            "project_name",
            "central_module_sha",
            "workflow_run_id",
            "run_attempt",
        ),
    }
    package = next(
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == "PythonPackage"
    )
    dependency_audit = next(
        node
        for node in package.body
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "dependency_audit"
    )
    auth_header = dependency_audit.args.args[-1]
    assert auth_header.annotation is not None
    assert ast.unparse(auth_header.annotation) == "dagger.Secret | None"
    assert tuple(map(ast.unparse, dependency_audit.args.defaults)) == ("None",)


def test_should_reject_public_execution_and_publication_escape_hatches() -> None:
    # Given every public input in the package release-candidate schema
    module = ast.parse(MAIN.read_text())
    inputs = {name for values in _public_signatures(module).values() for name in values}

    # When generic execution, image, path, tag, and publication controls are checked
    forbidden = {
        "command",
        "script",
        "shell",
        "image",
        "path",
        "tag",
        "registry",
        "publisher",
        "oidc_token",
    }

    # Then no caller can turn the Lego into a generic command runner or publisher
    assert inputs.isdisjoint(forbidden)
    assert '@function(cache="never")' in MAIN.read_text()


def _json(path: Path) -> dict[str, object]:
    value: object = json.loads(path.read_text())
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _publisher_example(guide: str) -> str:
    marker = "```yaml\nname: Publish Python candidate\n"
    body = guide.split(marker, maxsplit=1)[1].split("\n```", maxsplit=1)[0]
    return f"name: Publish Python candidate\n{body}"


def _public_signatures(module: ast.Module) -> dict[str, tuple[str, ...]]:
    package = next(
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == "PythonPackage"
    )
    return {
        node.name: tuple(argument.arg for argument in node.args.args[1:])
        for node in package.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        if any(_decorator_name(item) == "function" for item in node.decorator_list)
    }


def _decorator_name(value: ast.expr) -> str:
    target = value.func if isinstance(value, ast.Call) else value
    return target.id if isinstance(target, ast.Name) else ""
