from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Protocol, cast

import dagger
import pytest

from ci.main import SOURCE_EXCLUDES, Ci

ROOT = Path(__file__).parents[2]
FIXTURES = ROOT / "tests" / "dagger"
NAMES = ("python_consumer", "typescript_consumer")
GENERATED = ("sdk", ".venv", "node_modules", "__pycache__")


class FakeCheck:
    def __init__(self, path: str, events: list[str], *, success: bool = True) -> None:
        self.path = path
        self.events = events
        self.success = success

    def run(self) -> FakeCheck:
        self.events.append(f"run:{self.path}")
        return self

    async def passed(self) -> bool:
        return self.success


class Digest(Protocol):
    def update(self, value: bytes) -> object: ...


class FakeModule:
    def __init__(self, path: str, events: list[str], *, success: bool = True) -> None:
        self.path = path
        self.events = events
        self.success = success

    def check(self, name: str) -> FakeCheck:
        self.events.append(f"check:{self.path}:{name}")
        return FakeCheck(self.path, self.events, success=self.success)


class FakeSource:
    def __init__(self, events: list[str], *, success: bool = True) -> None:
        self.events = events
        self.success = success

    def as_module(self, *, source_root_path: str) -> FakeModule:
        self.events.append(f"load:{source_root_path}")
        return FakeModule(source_root_path, self.events, success=self.success)


def test_should_ship_both_supported_language_consumers() -> None:
    # Given the supported generated-client languages
    expected = ("python_consumer", "typescript_consumer")

    # When their committed fixture roots are resolved
    fixtures = tuple(FIXTURES / name for name in expected)

    # Then both real consumer modules exist
    assert all(path.is_dir() for path in fixtures)


def test_should_pin_fixture_engine_and_exact_local_dependencies() -> None:
    # Given both committed consumer module configurations
    configs = tuple(_config(name) for name in NAMES)

    # When the engine and dependency declarations are inspected
    engines = tuple(config["engineVersion"] for config in configs)
    dependencies = tuple(_dependencies(config) for config in configs)

    # Then both consumers use the current engine and exact local modules
    assert engines == ("v0.21.8", "v0.21.8")
    assert all(items == _expected_dependencies() for items in dependencies)


def test_should_keep_generated_clients_ignored_and_language_locks_committed() -> None:
    # Given deterministic language-owned metadata
    python = FIXTURES / "python_consumer" / ".dagger"
    typescript = FIXTURES / "typescript_consumer"

    # When clean-checkout prerequisites are inventoried
    required = (
        python / "uv.lock",
        python / ".gitignore",
        typescript / "yarn.lock",
        typescript / "tsconfig.json",
        typescript / ".gitignore",
    )

    # Then locks/config exist and generated SDKs remain absent from Git
    assert all(path.is_file() for path in required)
    assert _ignores_sdk(python) and _ignores_sdk(typescript)


def test_should_exclude_generated_tooling_from_root_source() -> None:
    # Given the root source is the shared input for policy and dynamic modules
    required = {"**/.venv", "**/node_modules", "**/sdk"}

    # When its stable exclusion contract is inspected
    excluded = set(SOURCE_EXCLUDES)

    # Then no host-generated language tooling enters either graph
    assert required <= excluded


def test_should_use_disjoint_cache_namespaces_without_cache_writes() -> None:
    # Given the two consumer implementations
    python, typescript = _python_source(), _typescript_source()

    # When their explicit cache boundaries are inspected
    names = ("fixture-python-v1", "fixture-typescript-v1")

    # Then namespaces differ and neither adapter writes fixture bytes to cache
    assert names[0] in python and names[1] in typescript
    assert names[1] not in python and names[0] not in typescript
    assert "withMountedCache" not in typescript
    assert "with_mounted_cache" not in python


def test_should_use_disjoint_consumer_identities_and_artifact_canaries() -> None:
    # Given independently generated consumer adapters
    python, typescript = _python_source(), _typescript_source()

    # When their immutable identities and artifact canaries are compared
    identities = (_commit_sha(python), _commit_sha(typescript))

    # Then neither consumer can accidentally assert the other's boundary
    assert identities[0] != identities[1]
    assert "typescript-artifact.txt" not in python
    assert "python-artifact.txt" not in typescript


def test_should_contract_tamper_failure_before_provider_transport() -> None:
    # Given both adapters deliberately submit a tampered envelope
    sources = (_python_source(), _typescript_source())

    # When their fail-before-transport contracts are inspected
    markers = ("api.cloudflare.com", "api.github.com", "wrangler")

    # Then each adapter rejects any marker from provider transport
    assert all(all(marker in source for marker in markers) for source in sources)


def test_should_run_exact_alma_detector_adversary_in_python_fixture() -> None:
    # Given the hosted generated-client fixture and its production guard
    python = _python_source()
    guard = _foundation_guard_source()

    # When / Then the hosted contract runs every exact pinned Alma proof
    assert "await _alma_gitleaks_contract()" in python
    assert "76cfea53cb96d215278048a326bd4aab91af9949" in python
    assert _gitleaks_image(python) == _gitleaks_image(guard)
    assert all(marker in python for marker in ("fresh-copy", "snapshot-copy"))


def test_should_run_both_fixture_checks_from_the_explicit_root_source() -> None:
    # Given an explicit root source and observable dynamic module checks
    events: list[str] = []
    central = Ci.__new__(Ci)
    central.source = cast(dagger.Directory, FakeSource(events))

    # When the root fixture function runs
    result: str = asyncio.run(central.module_fixtures())

    # Then both real module roots are loaded and their contract checks pass
    assert result == "cross-language Dagger module fixtures passed"
    assert events == _expected_events()


def test_should_fail_root_canary_when_a_consumer_check_fails() -> None:
    # Given a dynamically loaded consumer whose real check result is false
    central = Ci.__new__(Ci)
    central.source = cast(dagger.Directory, FakeSource([], success=False))

    # When / Then the root graph cannot report a false green
    with pytest.raises(RuntimeError, match="tests/dagger/python_consumer"):
        asyncio.run(central._module_fixture("tests/dagger/python_consumer"))


def test_should_regenerate_clean_clients_without_tracked_drift(tmp_path: Path) -> None:
    # Given a clean copy with every ignored generated client absent
    if not _has_generation_tools():
        pytest.skip("clean regeneration requires host Git and Dagger CLIs")
    copied = _copy_clean_repository(tmp_path)
    before = _fixture_digest(copied)

    # When both current-engine clients are regenerated and loaded
    for name in NAMES:
        _run_dagger(("develop",), copied / "tests" / "dagger" / name)

    # Then generated SDKs exist while committed config and locks are unchanged
    assert _generated_clients(copied)
    assert _fixture_digest(copied) == before


def _config(name: str) -> dict[str, object]:
    value: object = json.loads((FIXTURES / name / "dagger.json").read_text())
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _dependencies(config: dict[str, object]) -> tuple[tuple[str, str], ...]:
    raw = config.get("dependencies")
    assert isinstance(raw, list)
    items = cast(list[object], raw)
    return tuple(_dependency(item) for item in items)


def _dependency(value: object) -> tuple[str, str]:
    assert isinstance(value, dict)
    item = cast(dict[str, object], value)
    return (str(item["name"]), str(item["source"]))


def _expected_dependencies() -> tuple[tuple[str, str], ...]:
    return (
        ("foundation", "../../../modules/portfolio-foundation"),
        ("cloudflare-pages", "../../../modules/cloudflare-pages"),
        ("python-package", "../../../modules/python-package"),
    )


def _ignores_sdk(path: Path) -> bool:
    rules = tuple(line.strip() for line in (path / ".gitignore").read_text().splitlines())
    return "/sdk" in rules or "/sdk/" in rules


def _python_source() -> str:
    return (FIXTURES / "python_consumer/.dagger/src/python_consumer/main.py").read_text()


def _foundation_guard_source() -> str:
    path = ROOT / "modules/portfolio-foundation/.dagger/src/portfolio_foundation/guard.py"
    return path.read_text()


def _gitleaks_image(source: str) -> str:
    pattern = r"ghcr\.io/hseshadr/mirror/ghcr\.io/gitleaks/gitleaks:v8\.30\.1@sha256:[0-9a-f]+"
    match = re.search(pattern, source.replace('"\n    "', ""))
    assert match is not None
    return match.group()


def _typescript_source() -> str:
    return (FIXTURES / "typescript_consumer/src/index.ts").read_text()


def _commit_sha(source: str) -> str:
    match = re.search(r'COMMIT_SHA\s*(?::\s*\w+)?\s*=\s*["\']([0-9a-f]{40})', source)
    assert match is not None
    return match.group(1)


def _expected_events() -> list[str]:
    events: list[str] = []
    for name in NAMES:
        path = f"tests/dagger/{name}"
        events.extend((f"load:{path}", f"check:{path}:contract", f"run:{path}"))
    return events


def _copy_clean_repository(tmp_path: Path) -> Path:
    target = tmp_path / "repository"
    ignored = shutil.ignore_patterns(".git", *GENERATED, ".pytest_cache", ".ruff_cache")
    copied = Path(shutil.copytree(ROOT, target, ignore=ignored))
    _initialize_checkout(copied)
    return copied


def _has_generation_tools() -> bool:
    return all(shutil.which(name) is not None for name in ("git", "dagger"))


def _initialize_checkout(root: Path) -> None:
    binary = shutil.which("git")
    assert binary is not None
    subprocess.run(  # noqa: S603 - fixed trusted binary and literal arguments
        (binary, "init", "-q"), cwd=root, text=True, capture_output=True, check=True
    )


def _fixture_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for name in NAMES:
        _hash_tree(digest, root / "tests" / "dagger" / name)
    return digest.hexdigest()


def _hash_tree(digest: Digest, root: Path) -> None:
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if not any(part in GENERATED for part in path.parts):
            digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes())


def _run_dagger(arguments: tuple[str, ...], directory: Path) -> None:
    binary = shutil.which("dagger")
    if binary is None:
        raise AssertionError("Dagger CLI is required for clean-generation proof")
    result = subprocess.run(  # noqa: S603 - fixed trusted binary and literal test arguments
        (binary, *arguments), cwd=directory, text=True, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stderr


def _generated_clients(root: Path) -> bool:
    python = root / "tests/dagger/python_consumer/.dagger/sdk"
    typescript = root / "tests/dagger/typescript_consumer/sdk"
    return python.is_dir() and typescript.is_dir()
