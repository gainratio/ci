import ast
from pathlib import Path
from typing import cast

import dagger
import pytest

MODULE = Path(__file__).parents[2]
type Parameter = tuple[str, str]
type PublicSignature = tuple[str, tuple[Parameter, ...], str]
type PublicFunction = ast.FunctionDef | ast.AsyncFunctionDef
EXPECTED_PUBLIC_SCHEMA: tuple[PublicSignature, ...] = (
    (
        "source",
        (
            ("source", "dagger.Directory"),
            ("repository", "str"),
            ("commit_sha", "str"),
            ("http_auth_header", "dagger.Secret | None"),
        ),
        "dagger.Directory",
    ),
    (
        "guard",
        (
            ("source", "dagger.Directory"),
            ("repository", "str"),
            ("commit_sha", "str"),
            ("http_auth_header", "dagger.Secret | None"),
        ),
        "dagger.Container",
    ),
    (
        "envelope",
        (
            ("artifact", "dagger.Directory"),
            ("consumer_identity", "str"),
            ("producing_identity", "str"),
            ("allowed_roots", "list[str]"),
        ),
        "dagger.Directory",
    ),
    (
        "verify_envelope",
        (
            ("envelope", "dagger.Directory"),
            ("consumer_identity", "str"),
            ("producing_identity", "str"),
            ("allowed_roots", "list[str]"),
        ),
        "dagger.Directory",
    ),
    (
        "green_main",
        (("github_token", "dagger.Secret"), ("repository", "str")),
        "CheckEvidence",
    ),
    (
        "release_lineage",
        (
            ("github_token", "dagger.Secret"),
            ("repository", "str"),
            ("run_id", "int"),
            ("head_sha", "str"),
            ("publish_run_id", "int"),
        ),
        "str",
    ),
    (
        "release_provenance",
        (
            ("github_token", "dagger.Secret"),
            ("repository", "str"),
            ("run_id", "int"),
            ("head_sha", "str"),
            ("publish_run_id", "int"),
        ),
        "dagger.File",
    ),
)


def _directory() -> dagger.Directory:
    return cast(dagger.Directory, None)


def _main_tree(source: str | None = None) -> ast.Module:
    text = source or (MODULE / ".dagger/src/portfolio_foundation/main.py").read_text()
    return ast.parse(text)


def _public_methods(tree: ast.Module) -> tuple[PublicFunction, ...]:
    foundation = next(node for node in tree.body if isinstance(node, ast.ClassDef))
    return tuple(
        node
        for node in foundation.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and _is_function(node)
    )


def _is_function(node: PublicFunction) -> bool:
    decorators = (_decorator_name(decorator) for decorator in node.decorator_list)
    return any(name in {"function", "dagger.function"} for name in decorators)


def _decorator_name(decorator: ast.expr) -> str:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    return ast.unparse(target)


def _annotation(node: ast.expr | None) -> str:
    assert node is not None
    return ast.unparse(node)


def _signature(node: PublicFunction) -> PublicSignature:
    parameters = tuple(
        (argument.arg, _annotation(argument.annotation)) for argument in node.args.args[1:]
    )
    return node.name, parameters, _annotation(node.returns)


def test_should_expose_stable_public_functions() -> None:
    schema = (MODULE / "dagger.json").read_text()
    for name in ("portfolio-foundation", "v0.21.8"):
        assert name in schema


def test_should_keep_exact_typed_dagger_public_schema() -> None:
    actual = tuple(_signature(node) for node in _public_methods(_main_tree()))
    assert actual == EXPECTED_PUBLIC_SCHEMA


@pytest.mark.parametrize("name", ("source", "guard"))
def test_should_expose_optional_typed_history_header_without_plaintext_input(name: str) -> None:
    # Given
    method = next(node for node in _public_methods(_main_tree()) if node.name == name)
    header = method.args.args[-1]

    # When
    default = method.args.defaults[-1]

    # Then
    assert header.arg == "http_auth_header"
    assert _annotation(header.annotation) == "dagger.Secret | None"
    assert isinstance(default, ast.Constant) and default.value is None


@pytest.mark.parametrize("escape_hatch", ("command", "script", "cmd", "shell"))
def test_should_reject_public_arbitrary_command_escape_hatch(escape_hatch: str) -> None:
    source = (MODULE / ".dagger/src/portfolio_foundation/main.py").read_text()
    altered = source.replace("repository", escape_hatch, 1)
    schema = tuple(_signature(node) for node in _public_methods(_main_tree(altered)))
    assert schema != EXPECTED_PUBLIC_SCHEMA


def test_should_expose_source_as_async_runtime_adapter() -> None:
    source = next(node for node in _public_methods(_main_tree()) if node.name == "source")
    assert isinstance(source, ast.AsyncFunctionDef)


def test_should_expose_guard_as_async_runtime_adapter() -> None:
    guard = next(node for node in _public_methods(_main_tree()) if node.name == "guard")
    assert isinstance(guard, ast.AsyncFunctionDef)


def test_should_expose_envelope_as_async_runtime_adapter() -> None:
    envelope = next(node for node in _public_methods(_main_tree()) if node.name == "envelope")
    assert isinstance(envelope, ast.AsyncFunctionDef)


def test_should_expose_envelope_verifier_as_async_runtime_adapter() -> None:
    verifier = next(
        node for node in _public_methods(_main_tree()) if node.name == "verify_envelope"
    )
    assert isinstance(verifier, ast.AsyncFunctionDef)


def test_should_expose_green_main_as_async_runtime_adapter() -> None:
    green_main = next(node for node in _public_methods(_main_tree()) if node.name == "green_main")
    assert isinstance(green_main, ast.AsyncFunctionDef)


def test_should_disable_cache_for_current_github_evidence() -> None:
    green_main = next(node for node in _public_methods(_main_tree()) if node.name == "green_main")
    decorator = next(node for node in green_main.decorator_list if isinstance(node, ast.Call))
    cache = next(keyword.value for keyword in decorator.keywords if keyword.arg == "cache")
    assert isinstance(cache, ast.Constant)
    assert cache.value == "never"
