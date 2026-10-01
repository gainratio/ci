"""Typed Python consumer for the reusable portfolio modules."""

from __future__ import annotations

import asyncio
import re
from typing import Final

import dagger
from dagger import check, dag, function, object_type

REPOSITORY: Final = "hseshadr/ci"
REPOSITORY_URL: Final = "https://github.com/hseshadr/ci.git"
COMMIT_SHA: Final = "1b2b18a38fc52801bdd2f3eb89d6616d847ef1fe"
CONSUMER: Final = f"{REPOSITORY}@{COMMIT_SHA}"
PRODUCER: Final = "b" * 40 + ":7"
ALLOWED_ROOTS: Final = ["dist"]
CACHE_NAMESPACE: Final = "fixture-python-v1"
SECRET_CANARY: Final = "-".join(("python", "private", "canary"))
ARTIFACT_NAME: Final = "python-artifact.txt"
TRANSPORT_MARKERS: Final = ("api.cloudflare.com", "api.github.com", "wrangler")
ALMA_REPOSITORY: Final = "hseshadr/almamesh"
ALMA_REPOSITORY_URL: Final = "https://github.com/hseshadr/almamesh.git"
ALMA_COMMIT_SHA: Final = "76cfea53cb96d215278048a326bd4aab91af9949"
GITLEAKS_IMAGE: Final = (
    "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:"
    "c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)
FIXTURE_PATHS: Final = (
    "backend/tests/test_predictive_golden.py",
    "frontend/packages/browser/integration/parity.mjs",
)
PAYLOAD_PARTS: Final = (
    "616c6d616d6573682d7061726974792d",
    "666978747572652d7369676e65723030",
)
EXPECTED_FINDINGS: Final = 2
PACKAGE_REPOSITORY: Final = "hseshadr/edgeproc-core"
PACKAGE_URL: Final = "https://github.com/hseshadr/edgeproc-core.git"
PACKAGE_SHA: Final = "0bf2a8394b205f099b14b71303627ef871715622"
PACKAGE_PROJECT: Final = "edgeproc-core"
PACKAGE_VERSION: Final = "0.4.3"
PACKAGE_PRODUCT_COUNT: Final = 2


@object_type
class PythonConsumer:
    """Prove Python generated clients compose the exact local modules."""

    @function
    @check
    async def contract(self) -> str:
        """Run the positive foundation chain and provider tamper boundary."""
        await _source_guard()
        await _alma_gitleaks_contract()
        envelope = await _verified_envelope()
        secret = dag.set_secret("python-fixture-secret", SECRET_CANARY)
        _typed_evidence(secret)
        await _provider_rejects_tamper(envelope, secret)
        await _package_build()
        await dag.cache_volume(CACHE_NAMESPACE).id()
        return "python fixture passed"


async def _source_guard() -> None:
    history = dag.git(REPOSITORY_URL).commit(COMMIT_SHA).tree(depth=0, include_tags=True)
    source = dag.foundation().source(history, REPOSITORY, COMMIT_SHA)
    await source.digest()
    await dag.foundation().guard(source, REPOSITORY, COMMIT_SHA).sync()


async def _alma_gitleaks_contract() -> None:
    history = _alma_history()
    await dag.foundation().guard(history, ALMA_REPOSITORY, ALMA_COMMIT_SHA).sync()
    fresh = _fresh_copy(history)
    snapshot = await _snapshot_copy(history)
    await asyncio.gather(
        _require_detector_rejection(fresh, history=True, marker="fresh-copy"),
        _require_detector_rejection(snapshot, history=False, marker="snapshot-copy"),
    )


def _alma_history() -> dagger.Directory:
    repository = dag.git(ALMA_REPOSITORY_URL).commit(ALMA_COMMIT_SHA)
    return repository.tree(depth=0, include_tags=True)


def _fixture_files() -> tuple[tuple[str, str], ...]:
    seed = "".join(PAYLOAD_PARTS)
    return (
        (FIXTURE_PATHS[0], f'FIXTURE_KEY_SEED_HEX = "{seed}"\n'),
        (FIXTURE_PATHS[1], f'const PREDICTIVE_FIXTURE_KEY_SEED_HEX = "{seed}";\n'),
    )


def _with_fixture_files(source: dagger.Directory) -> dagger.Directory:
    result = source
    for path, contents in _fixture_files():
        result = result.with_new_file(path, contents)
    return result


def _fresh_copy(history: dagger.Directory) -> dagger.Directory:
    source = _with_fixture_files(history)
    container = _git_container(source)
    container = container.with_exec(["git", "add", "--", *FIXTURE_PATHS])
    container = container.with_exec(["git", "commit", "-qm", "fresh-copy"])
    return container.directory("/repo")


def _git_container(source: dagger.Directory) -> dagger.Container:
    base = dag.container().from_(GITLEAKS_IMAGE).with_entrypoint([])
    base = base.with_directory("/repo", source).with_workdir("/repo")
    base = base.with_exec(["git", "config", "user.email", "fixture@example.invalid"])
    return base.with_exec(["git", "config", "user.name", "Fixture"])


async def _snapshot_copy(history: dagger.Directory) -> dagger.Directory:
    policy = await history.file(".gitleaks.toml").contents()
    return _with_fixture_files(dag.directory().with_new_file(".gitleaks.toml", policy))


def _detector_arguments(history: bool) -> list[str]:
    mode = ["--log-opts=--all"] if history else ["--no-git"]
    return [
        "gitleaks",
        "detect",
        "--source",
        "/repo",
        *mode,
        "--config",
        "/repo/.gitleaks.toml",
        "--redact",
        "--no-banner",
        "--verbose",
    ]


def _detector(source: dagger.Directory, *, history: bool) -> dagger.Container:
    base = dag.container().from_(GITLEAKS_IMAGE).with_entrypoint([])
    base = base.with_mounted_directory("/repo", source, read_only=True)
    return base.with_exec(_detector_arguments(history), expect=dagger.ReturnType.FAILURE)


async def _require_detector_rejection(
    source: dagger.Directory, *, history: bool, marker: str
) -> None:
    scan = _detector(source, history=history)
    code, stdout, stderr = await asyncio.gather(scan.exit_code(), scan.stdout(), scan.stderr())
    output = stdout + stderr
    findings = len(re.findall(r"RuleID:\s+generic-api-key", output))
    if code != 1 or "leaks found: 2" not in output or findings != EXPECTED_FINDINGS:
        raise ValueError(f"{marker} detector evidence differed: exit={code}, findings={findings}")


async def _verified_envelope() -> dagger.Directory:
    artifact = dag.directory().with_new_file(f"dist/{ARTIFACT_NAME}", "python artifact")
    envelope = dag.foundation().envelope(artifact, CONSUMER, PRODUCER, ALLOWED_ROOTS)
    verified = dag.foundation().verify_envelope(envelope, CONSUMER, PRODUCER, ALLOWED_ROOTS)
    entries = await verified.directory("dist").entries()
    if entries != [ARTIFACT_NAME]:
        raise ValueError("verified Python artifact boundary differs")
    return envelope


def _typed_evidence(secret: dagger.Secret) -> None:
    evidence: dagger.FoundationCheckEvidence = dag.foundation().green_main(secret, REPOSITORY)
    if evidence is None:
        raise ValueError("generated evidence type was unavailable")


async def _package_build() -> None:
    history = dag.git(PACKAGE_URL).commit(PACKAGE_SHA).tree(depth=0, include_tags=True)
    package = dag.python_package().build(history, PACKAGE_REPOSITORY, PACKAGE_SHA, PACKAGE_PROJECT)
    version = await package.version()
    entries = await package.directory().entries()
    if version != PACKAGE_VERSION or len(entries) != PACKAGE_PRODUCT_COUNT:
        raise ValueError("Python package build evidence differs")


async def _provider_rejects_tamper(envelope: dagger.Directory, secret: dagger.Secret) -> None:
    tampered = envelope.with_new_file(f"artifact/dist/{ARTIFACT_NAME}", "tampered")
    try:
        await _preflight(tampered, secret)
    except dagger.QueryError as error:
        _require_safe_tamper_error(str(error))
        return
    raise ValueError("provider accepted a tampered envelope")


# fmt: off
async def _preflight(envelope: dagger.Directory, secret: dagger.Secret) -> str:
    # The generated SDK boundary has fifteen typed positional inputs.
    return await dag.cloudflare_pages().preflight(
        envelope, secret, secret, secret, "7", 1, REPOSITORY,
        "ci", "main", "example.invalid", "dist", [], CONSUMER,
        PRODUCER, ALLOWED_ROOTS,
    )
# fmt: on


def _require_safe_tamper_error(message: str) -> None:
    if "artifact bytes or modes differ from manifest" not in message.lower():
        raise ValueError("provider reached transport before envelope rejection")
    if any(marker in message for marker in TRANSPORT_MARKERS):
        raise ValueError("provider emitted a transport marker for a rejected envelope")
    if SECRET_CANARY in message:
        raise ValueError("provider error disclosed the typed secret")
