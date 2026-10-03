"""Dagger owns the mirror job: pinned crane, upstream bootstrap, login, then proof."""

from __future__ import annotations

import asyncio
import inspect
from typing import cast

import dagger
import pytest

from ci import main as main_module
from ci.main import CRANE_SHA256, CRANE_URL, MIRROR_BOOTSTRAP_IMAGE, Ci

Operation = tuple[object, ...]


class FakeSource:
    def file(self, path: str) -> dagger.File:
        return cast(dagger.File, f"source:{path}")


class FakeContainer:
    def __init__(self, operations: list[Operation]) -> None:
        self.operations = operations

    def from_(self, image: str) -> FakeContainer:
        self.operations.append(("from", image))
        return self

    def with_file(self, path: str, file: dagger.File) -> FakeContainer:
        self.operations.append(("file", path, file))
        return self

    def with_secret_variable(self, name: str, secret: dagger.Secret) -> FakeContainer:
        self.operations.append(("secret", name, secret))
        return self

    def with_exec(self, command: list[str]) -> FakeContainer:
        self.operations.append(("exec", tuple(command)))
        return self

    async def stdout(self) -> str:
        return "12/12 images proven"


class FakeDag:
    def __init__(self, operations: list[Operation]) -> None:
        self.operations = operations

    def container(self, platform: dagger.Platform | None = None) -> FakeContainer:
        self.operations.append(("platform", platform))
        return FakeContainer(self.operations)

    def http(self, url: str) -> dagger.File:
        return cast(dagger.File, f"http:{url}")


def _run(monkeypatch: pytest.MonkeyPatch, verb: str) -> tuple[str, list[Operation]]:
    operations: list[Operation] = []
    central = Ci.__new__(Ci)
    central.source = cast(dagger.Directory, FakeSource())
    monkeypatch.setattr(main_module, "dag", FakeDag(operations))
    token = cast(dagger.Secret, "token")
    call = central.image_mirror(token) if verb == "sync" else central.image_mirror_verify()
    return asyncio.run(call), operations


def _execs(operations: list[Operation]) -> list[tuple[str, ...]]:
    return [cast(tuple[str, ...], item[1]) for item in operations if item[0] == "exec"]


def test_should_bootstrap_from_upstream_with_a_checksum_pinned_crane(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given the read-only verification lane
    result, operations = _run(monkeypatch, "verify")

    # Then the job never depends on the mirror it repairs, and crane is checksum-verified
    assert result == "12/12 images proven"
    assert ("from", MIRROR_BOOTSTRAP_IMAGE) in operations
    assert MIRROR_BOOTSTRAP_IMAGE.startswith("docker.io/library/python:3.13.14-slim@sha256:")
    assert ("file", "/opt/crane.tar.gz", f"http:{CRANE_URL}") in operations
    assert "v0.22.1/go-containerregistry_Linux_x86_64.tar.gz" in CRANE_URL
    assert CRANE_SHA256 == "0ab7a1d6932a213aed964ce97666c3077fe691c8606413674a8b3e0b9ec4cda0"
    install = " ".join(_execs(operations)[0])
    assert f"{CRANE_SHA256}  /opt/crane.tar.gz" in install and "sha256sum -c" in install


def test_should_verify_upstream_without_credentials(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given the PR lane
    _, operations = _run(monkeypatch, "verify")

    # Then no secret is mounted and only the verify command runs after install
    assert not any(item[0] == "secret" for item in operations)
    assert _execs(operations)[-1] == (
        "python3",
        "/mirror/image_mirror.py",
        "verify",
        "/mirror/images.json",
    )
    assert ("file", "/mirror/images.json", "source:mirror/images.json") in operations
    assert (
        "file",
        "/mirror/image_mirror.py",
        "source:.dagger/src/ci/image_mirror.py",
    ) in operations


def test_should_log_in_with_the_typed_token_before_sync(monkeypatch: pytest.MonkeyPatch) -> None:
    # Given the main-branch write lane
    _, operations = _run(monkeypatch, "sync")

    # Then the token enters as a secret, login reads it from stdin, and sync runs last
    execs = _execs(operations)
    assert ("secret", "GITHUB_TOKEN", "token") in operations
    assert "--password-stdin" in execs[1][-1] and '"$GITHUB_TOKEN"' in execs[1][-1]
    assert execs[-1] == ("python3", "/mirror/image_mirror.py", "sync", "/mirror/images.json")


def test_should_type_the_mirror_credential_as_a_secret() -> None:
    # Given the public mirror function
    signature = inspect.signature(Ci.image_mirror)

    # Then its only credential is a typed Dagger secret
    assert "Secret" in str(signature.parameters["github_token"].annotation)
