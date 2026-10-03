from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
from collections.abc import Awaitable, Callable
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import cast

import dagger
import pytest

from portfolio_foundation import artifact as artifact_module
from portfolio_foundation import source as source_module
from portfolio_foundation.artifact import (
    ENGINE_VERSION,
    TOOLCHAIN,
    ArtifactContext,
    ArtifactFile,
    ArtifactManifest,
    ArtifactNode,
    ChecksumMismatch,
    EmptyArtifact,
    ManifestParseError,
    ToolchainMismatch,
    UnexpectedArtifactPath,
    UnsupportedArtifactNode,
    artifact_files,
    build_manifest,
    canonical_roots,
    parse_consumer_identity,
    parse_manifest,
    parse_producing_identity,
    require_compatible_toolchain,
    sha256_sums,
    validate_evidence,
    validate_paths,
    verify_envelope_directory,
)
from portfolio_foundation.identity import CommitIdentity, FullSha, RepositoryRef
from portfolio_foundation.source import EntryType, InventoryEntry

MODULE = Path(__file__).parents[2]
IDENTITY = CommitIdentity(RepositoryRef("owner", "consumer"), FullSha("a" * 40))
MODULE_SHA = "b" * 40
RUN_ID = "12345"
ROOTS = ("dist",)
CONTEXT = ArtifactContext(IDENTITY, MODULE_SHA, ROOTS, RUN_ID)
UINT64_MAX = 18_446_744_073_709_551_615
OVERSIZED_ROOT_SETS = (
    tuple(f"root-{index:02}" for index in range(33)),
    ("a" * 256,),
    tuple(f"{index:02}-{'a' * 128}" for index in range(32)),
)


def _file(path: str, contents: bytes) -> ArtifactFile:
    return ArtifactFile(path, hashlib.sha256(contents).hexdigest())


def _manifest(files: tuple[ArtifactFile, ...]) -> ArtifactManifest:
    return build_manifest(files, CONTEXT)


def _manifest_payload() -> dict[str, object]:
    manifest = _manifest((_file("dist/index.html", b"index"),))
    return cast(dict[str, object], json.loads(manifest.to_json()))


def _file_payload(path: str, contents: bytes) -> dict[str, object]:
    return {"mode": 0o644, "path": path, "sha256": hashlib.sha256(contents).hexdigest()}


class FakeArtifactFile:
    def __init__(self, contents: str) -> None:
        self._contents = contents

    async def contents(self) -> str:
        return self._contents


class FakeInventoryContainer:
    async def stdout(self) -> str:
        return "regular\t644\t" + ("0" * 64) + "\tZGlzdC9pbmRleC5odG1s\n"


class FakeArtifactDirectory:
    def __init__(self, nodes: tuple[ArtifactNode, ...], files: dict[str, str]) -> None:
        self._nodes = nodes
        self._files = files

    async def entries(self, *, path: str | None = None) -> list[str]:
        return _entry_names_at(self._nodes, path or "")

    def file(self, path: str) -> FakeArtifactFile:
        return FakeArtifactFile(self._files[path])

    def directory(self, path: str) -> dagger.Directory:
        assert path == "artifact"
        return cast(dagger.Directory, self)


class FakeEnvelopeDirectory(FakeArtifactDirectory):
    def __init__(self, artifact: FakeArtifactDirectory, files: dict[str, str]) -> None:
        super().__init__((), files)
        self._artifact = artifact

    async def entries(self, *, path: str | None = None) -> list[str]:
        if path == "evidence":
            return ["SHA256SUMS", "artifact-manifest.json"]
        return ["artifact/", "evidence/"]

    def directory(self, path: str) -> dagger.Directory:
        assert path == "artifact"
        return cast(dagger.Directory, self._artifact)


class FakeOutputDirectory:
    pass


type Tamperer = Callable[[FakeArtifactDirectory, FakeEnvelopeDirectory, pytest.MonkeyPatch], None]


def _entry_names_at(nodes: tuple[ArtifactNode, ...], parent: str) -> list[str]:
    prefix = f"{parent}/" if parent else ""
    children = tuple(node for node in nodes if _is_direct_child(node.path, prefix))
    return [node.path.removeprefix(prefix).removesuffix("/") + _suffix(node) for node in children]


def _is_direct_child(path: str, prefix: str) -> bool:
    return path.startswith(prefix) and "/" not in path.removeprefix(prefix)


def _suffix(node: ArtifactNode) -> str:
    return "/" if node.entry_type is EntryType.DIRECTORY else ""


def _artifact_nodes() -> tuple[ArtifactNode, ...]:
    digest = hashlib.sha256(b"index").hexdigest()
    return (
        ArtifactNode("dist", EntryType.DIRECTORY, "0" * 64, 0o755),
        ArtifactNode("dist/index.html", EntryType.REGULAR, digest, 0o644),
    )


def _artifact_directory() -> FakeArtifactDirectory:
    return FakeArtifactDirectory(_artifact_nodes(), {"dist/index.html": "index"})


def _envelope(artifact: FakeArtifactDirectory | None = None) -> FakeEnvelopeDirectory:
    manifest = _manifest((_file("dist/index.html", b"index"),))
    files = {
        "evidence/artifact-manifest.json": manifest.to_json(),
        "evidence/SHA256SUMS": sha256_sums(manifest),
    }
    return FakeEnvelopeDirectory(artifact or _artifact_directory(), files)


def test_should_create_stable_immutable_manifest_when_input_order_differs() -> None:
    # Given
    first, second = _file("dist/index.html", b"index"), _file("dist/app.js", b"app")

    # When
    manifest = _manifest((second, first))

    # Then
    assert manifest.to_json() == _manifest((first, second)).to_json()
    assert manifest.files == (second, first)
    with pytest.raises(FrozenInstanceError):
        manifest.producing_run_id = "changed"  # type: ignore[misc]


def test_should_bind_full_identity_module_and_toolchain_when_manifest_is_built() -> None:
    # Given / When
    manifest = _manifest((_file("dist/index.html", b"index"),))

    # Then
    payload = json.loads(manifest.to_json())
    assert payload["repository"] == "owner/consumer"
    assert payload["consumer_sha"] == "a" * 40
    assert payload["module_sha"] == MODULE_SHA
    assert payload["engine_version"] == ENGINE_VERSION
    assert payload["toolchain"] == list(manifest.toolchain)


def test_should_record_digest_pinned_hasher_when_manifest_is_built() -> None:
    # Given / When / Then
    assert TOOLCHAIN[0] == f"dagger-engine:{ENGINE_VERSION}"
    assert "@sha256:" in TOOLCHAIN[1]


def test_should_keep_toolchain_identity_when_the_hasher_is_pulled_from_a_mirror() -> None:
    # Given evidence manifests already published with the upstream hasher identity
    digest = "sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
    upstream = "alpine@" + digest

    # Then the pull location may move to the GHCR mirror (same digest, same bytes) but the
    # recorded toolchain, which verification compares exactly, does not change
    assert ("dagger-engine:v0.21.8", f"artifact-hasher:{upstream}") == TOOLCHAIN
    assert source_module.HASH_IMAGE.endswith(f"@{digest}")
    assert source_module.HASH_IMAGE.startswith("ghcr.io/hseshadr/mirror/docker.io/library/alpine:")


def test_should_parse_exact_consumer_and_producing_identities_when_enveloping() -> None:
    # Given / When
    consumer = parse_consumer_identity(f"owner/consumer@{'a' * 40}")
    module_sha, run_id = parse_producing_identity(f"{'b' * 40}:12345")

    # Then
    assert consumer == IDENTITY
    assert (module_sha, run_id) == (MODULE_SHA, RUN_ID)


@pytest.mark.parametrize("consumer", ("owner/consumer", f"owner/consumer@{'A' * 40}"))
def test_should_reject_malformed_consumer_identity_when_enveloping(consumer: str) -> None:
    # Given / When / Then
    with pytest.raises(ValueError):
        parse_consumer_identity(consumer)


@pytest.mark.parametrize("producer", ("short:12345", f"{'b' * 40}/12345", f"{'b' * 40}:"))
def test_should_reject_malformed_producing_identity_when_enveloping(producer: str) -> None:
    # Given / When / Then
    with pytest.raises(ValueError):
        parse_producing_identity(producer)


def test_should_accept_largest_unsigned_64_bit_producing_run_identity() -> None:
    # Given / When
    module_sha, run_id = parse_producing_identity(f"{'b' * 40}:{UINT64_MAX}")

    # Then
    assert (module_sha, run_id) == (MODULE_SHA, str(UINT64_MAX))


@pytest.mark.parametrize("run_id", ("9" * 21, str(UINT64_MAX + 1)))
def test_should_reject_producing_run_identity_outside_unsigned_64_bit(run_id: str) -> None:
    # Given / When / Then
    with pytest.raises(ManifestParseError, match="run ID"):
        parse_producing_identity(f"{'b' * 40}:{run_id}")


@pytest.mark.parametrize("roots", OVERSIZED_ROOT_SETS)
def test_should_reject_allowed_roots_that_exceed_scalar_bounds(
    roots: tuple[str, ...],
) -> None:
    # Given / When / Then
    with pytest.raises(UnexpectedArtifactPath, match="roots"):
        canonical_roots(roots)


def test_should_accept_allowed_root_at_per_root_byte_boundary() -> None:
    # Given
    roots = ("a" * 255,)

    # When / Then
    assert canonical_roots(roots) == roots


@pytest.mark.parametrize("paths", (("dist/index.html", "debug.log"), ("debug.log",)))
def test_should_reject_unexpected_path_when_not_under_an_allowed_root(
    paths: tuple[str, ...],
) -> None:
    # Given / When / Then
    with pytest.raises(UnexpectedArtifactPath, match=r"debug\.log"):
        validate_paths(paths, ROOTS)


@pytest.mark.parametrize(
    "paths", ((), ("dist/../debug.log",), ("dist/index.html", "dist/index.html"))
)
def test_should_reject_ambiguous_or_empty_artifact_inventory(paths: tuple[str, ...]) -> None:
    # Given / When / Then
    with pytest.raises((EmptyArtifact, UnexpectedArtifactPath), match="artifact"):
        validate_paths(paths, ROOTS)


def test_should_reject_symlink_when_collecting_artifact_files() -> None:
    # Given
    entry = InventoryEntry("dist/link", "0" * 64, EntryType.SYMLINK)

    # When / Then
    with pytest.raises(UnsupportedArtifactNode, match="dist/link"):
        artifact_files((entry,))


def test_should_checksum_structured_evidence_when_filename_has_legal_separators() -> None:
    # Given
    manifest = _manifest((_file("dist/line\nbreak: space.js", b"content"),))

    # When
    checksums = sha256_sums(manifest)

    # Then
    assert "\\n" in checksums
    validate_evidence(manifest, checksums)
    with pytest.raises(ChecksumMismatch):
        validate_evidence(manifest, checksums.replace("a", "b", 1))


def test_should_reject_incompatible_or_tampered_manifest_toolchain() -> None:
    # Given
    manifest = _manifest((_file("dist/index.html", b"index"),))

    # When / Then
    require_compatible_toolchain(manifest)
    with pytest.raises(ToolchainMismatch):
        ArtifactManifest(
            manifest.identity,
            manifest.module_sha,
            "v0.0.0",
            manifest.toolchain,
            manifest.producing_run_id,
            manifest.allowed_roots,
            manifest.files,
        )


@pytest.mark.parametrize(
    ("run_id", "roots", "files"),
    (
        ("bad", ROOTS, (_file("dist/index.html", b"index"),)),
        (RUN_ID, ("../escape",), (_file("dist/index.html", b"index"),)),
        (RUN_ID, ROOTS, (_file("dist/z", b"z"), _file("dist/a", b"a"))),
        (RUN_ID, ROOTS, (_file("dist/a", b"a"), _file("dist/a", b"a"))),
    ),
)
def test_should_reject_invalid_direct_manifest_construction(
    run_id: str, roots: tuple[str, ...], files: tuple[ArtifactFile, ...]
) -> None:
    # Given / When / Then
    with pytest.raises((ManifestParseError, UnexpectedArtifactPath)):
        ArtifactManifest(
            IDENTITY, FullSha(MODULE_SHA), ENGINE_VERSION, TOOLCHAIN, run_id, roots, files
        )


class DuckIdentity:
    repository = RepositoryRef("owner", "consumer")
    commit = FullSha("a" * 40)


@pytest.mark.parametrize(
    "identity",
    (
        "owner/consumer@sha",
        DuckIdentity(),
        CommitIdentity(cast(RepositoryRef, "owner/consumer"), FullSha("a" * 40)),
        CommitIdentity(RepositoryRef("owner", "consumer"), cast(FullSha, "a" * 40)),
    ),
)
def test_should_reject_noncanonical_runtime_identity_when_constructing_manifest(
    identity: object,
) -> None:
    # Given / When / Then
    with pytest.raises(ManifestParseError, match="identity"):
        _direct_manifest(identity, 1)


@pytest.mark.parametrize("schema_version", (True, 1.0, "1", None, 2))
def test_should_reject_nonexact_schema_version_when_constructing_manifest(
    schema_version: object,
) -> None:
    # Given / When / Then
    with pytest.raises(ManifestParseError, match="schema"):
        _direct_manifest(IDENTITY, schema_version)


def _direct_manifest(identity: object, schema_version: object) -> ArtifactManifest:
    return ArtifactManifest(
        cast(CommitIdentity, identity),
        FullSha(MODULE_SHA),
        ENGINE_VERSION,
        TOOLCHAIN,
        RUN_ID,
        ROOTS,
        (_file("dist/index.html", b"index"),),
        cast(int, schema_version),
    )


def test_should_reject_unknown_or_missing_manifest_fields_when_parsing() -> None:
    # Given
    payload = _manifest_payload()
    unknown = {**payload, "untrusted": "value"}
    missing = {key: value for key, value in payload.items() if key != "module_sha"}

    # When / Then
    with pytest.raises(ManifestParseError, match="unknown or missing"):
        parse_manifest(json.dumps(unknown))
    with pytest.raises(ManifestParseError, match="unknown or missing"):
        parse_manifest(json.dumps(missing))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("schema_version", True),
        ("toolchain", "not-an-array"),
        ("files", {}),
        ("repository", 7),
        ("producing_run_id", None),
    ),
)
def test_should_reject_wrong_manifest_field_types_when_parsing(field: str, value: object) -> None:
    # Given
    payload = _manifest_payload()
    payload[field] = value

    # When / Then
    with pytest.raises((ManifestParseError, ValueError)):
        parse_manifest(json.dumps(payload))


@pytest.mark.parametrize(
    "mutator",
    (
        lambda payload: payload.__setitem__("schema_version", 2),
        lambda payload: payload.__setitem__("producing_run_id", "not-a-run"),
        lambda payload: payload.__setitem__("allowed_roots", ["../escape"]),
        lambda payload: payload.__setitem__("allowed_roots", ["z", "dist"]),
        lambda payload: payload.__setitem__("toolchain", ["untrusted"]),
    ),
)
def test_should_reject_invalid_manifest_invariants_when_parsing(
    mutator: object,
) -> None:
    # Given
    payload = _manifest_payload()
    assert callable(mutator)
    mutator(payload)

    # When / Then
    with pytest.raises((ManifestParseError, ToolchainMismatch, UnexpectedArtifactPath)):
        parse_manifest(json.dumps(payload))


@pytest.mark.parametrize(
    "files",
    (
        [
            _file_payload("dist/z", b"z"),
            _file_payload("dist/a", b"a"),
        ],
        [
            _file_payload("dist/a", b"a"),
            _file_payload("dist/a", b"a"),
        ],
        [_file_payload("dist/../escape", b"a")],
        [{"path": "dist/a", "sha256": "not-a-digest", "mode": 420}],
        [{"path": "dist/a", "sha256": "a" * 64, "mode": 0o600}],
    ),
)
def test_should_reject_noncanonical_file_records_when_parsing(files: list[object]) -> None:
    # Given
    payload = _manifest_payload()
    payload["files"] = files

    # When / Then
    with pytest.raises((ManifestParseError, UnexpectedArtifactPath)):
        parse_manifest(json.dumps(payload))


def test_should_expose_actual_directory_verifier_before_privileged_consumption() -> None:
    # Given / When / Then
    assert callable(verify_envelope_directory)


@pytest.mark.parametrize(
    "nodes",
    (
        (ArtifactNode("dist/link", EntryType.SYMLINK, "0" * 64, 0o777),),
        (ArtifactNode("debug-empty", EntryType.DIRECTORY, "0" * 64, 0o755),),
        (ArtifactNode("dist/empty", EntryType.DIRECTORY, "0" * 64, 0o755),),
    ),
)
def test_should_reject_unmanifested_artifact_nodes_when_inventorying(
    nodes: tuple[ArtifactNode, ...],
) -> None:
    # Given / When / Then
    with pytest.raises((UnsupportedArtifactNode, UnexpectedArtifactPath, EmptyArtifact)):
        artifact_module._validate_nodes(nodes, ROOTS)


def test_should_reject_artifact_inventory_without_complete_stream_trailer() -> None:
    # Given
    container = cast(dagger.Container, FakeInventoryContainer())

    # When / Then
    with pytest.raises(artifact_module.ArtifactEnvelopeError, match="malformed"):
        asyncio.run(artifact_module._artifact_inventory_entries(container))


def test_should_keep_only_regular_nodes_and_normalize_executable_behavior() -> None:
    # Given
    nodes = (
        ArtifactNode("dist", EntryType.DIRECTORY, "0" * 64, 0o755),
        ArtifactNode("dist/run", EntryType.REGULAR, "a" * 64, 0o711),
        ArtifactNode("dist/plain", EntryType.REGULAR, "b" * 64, 0o640),
    )

    # When
    files = artifact_module._normalized_files(nodes)

    # Then
    assert files == (
        ArtifactFile("dist/plain", "b" * 64, 0o644),
        ArtifactFile("dist/run", "a" * 64, 0o755),
    )


def test_should_reject_noncanonical_permissions_when_verifying_artifact_records() -> None:
    # Given
    nodes = (ArtifactNode("dist/index.html", EntryType.REGULAR, "a" * 64, 0o600),)

    # When / Then
    with pytest.raises(ChecksumMismatch, match="mode"):
        artifact_module._verified_files(nodes)


@pytest.mark.parametrize(
    "text",
    (
        "",
        f"{'a' * 64}  not-json\n",
        f"{'a' * 64}  9\n",
        'not-a-digest  "artifact/dist/index.html"\n',
        f'{"a" * 64}  "artifact/dist/index.html"\n{"b" * 64}  "artifact/dist/index.html"\n',
    ),
)
def test_should_reject_ambiguous_or_malformed_checksum_records_when_parsing(text: str) -> None:
    # Given / When / Then
    with pytest.raises(ChecksumMismatch):
        artifact_module._parse_sums(text)


def test_should_collect_normalized_evidence_from_complete_typed_inventory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    directory = _artifact_directory()
    output = FakeOutputDirectory()

    async def inventory(_: dagger.Directory) -> artifact_module._ArtifactInventory:
        return artifact_module._ArtifactInventory(_artifact_nodes(), cast(dagger.Directory, output))

    monkeypatch.setattr(artifact_module, "_artifact_inventory", inventory)

    # When
    evidence = asyncio.run(
        artifact_module.collect_artifact_evidence(
            cast(dagger.Directory, directory), IDENTITY, MODULE_SHA, ROOTS, RUN_ID
        )
    )

    # Then
    assert evidence.directory is cast(dagger.Directory, output)
    assert evidence.manifest.files == (_file("dist/index.html", b"index"),)


def test_should_return_only_verified_artifact_when_envelope_matches_every_invariant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given
    directory = _artifact_directory()
    envelope = _envelope(directory)

    monkeypatch.setattr(artifact_module, "_artifact_nodes", _fake_live_nodes(directory))

    # When
    verified = asyncio.run(
        verify_envelope_directory(
            cast(dagger.Directory, envelope), IDENTITY, MODULE_SHA, ROOTS, RUN_ID
        )
    )

    # Then
    assert verified is cast(dagger.Directory, directory)


@pytest.mark.parametrize(
    "kind",
    ("identity", "manifest", "sums", "layout", "bytes", "mode"),
)
def test_should_fail_before_returning_artifact_when_live_envelope_is_tampered(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Given
    directory = _artifact_directory()
    envelope = _envelope(directory)
    _tamper_fake_envelope(kind, directory, envelope, monkeypatch)

    # When / Then
    with pytest.raises((ChecksumMismatch, ManifestParseError)):
        asyncio.run(
            verify_envelope_directory(
                cast(dagger.Directory, envelope), IDENTITY, MODULE_SHA, ROOTS, RUN_ID
            )
        )


def _tamper_fake_envelope(
    kind: str,
    directory: FakeArtifactDirectory,
    envelope: FakeEnvelopeDirectory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _tamperer(kind)(directory, envelope, monkeypatch)
    monkeypatch.setattr(artifact_module, "_artifact_nodes", _fake_live_nodes(directory))


def _tamperer(kind: str) -> Tamperer:
    return {
        "identity": _tamper_identity,
        "manifest": _tamper_manifest_text,
        "sums": _tamper_sums,
        "layout": _tamper_layout,
        "bytes": _tamper_bytes,
        "mode": _tamper_mode,
    }[kind]


def _tamper_identity(
    _: FakeArtifactDirectory, envelope: FakeEnvelopeDirectory, __: pytest.MonkeyPatch
) -> None:
    payload = json.loads(envelope._files["evidence/artifact-manifest.json"])
    payload["producing_run_id"] = "999"
    envelope._files["evidence/artifact-manifest.json"] = json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )


def _tamper_manifest_text(
    _: FakeArtifactDirectory, envelope: FakeEnvelopeDirectory, __: pytest.MonkeyPatch
) -> None:
    envelope._files["evidence/artifact-manifest.json"] = " { } "


def _tamper_sums(
    _: FakeArtifactDirectory, envelope: FakeEnvelopeDirectory, __: pytest.MonkeyPatch
) -> None:
    envelope._files["evidence/SHA256SUMS"] = "tampered"


def _tamper_layout(
    _: FakeArtifactDirectory, envelope: FakeEnvelopeDirectory, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def entries(*, path: str | None = None) -> list[str]:
        return ["artifact/", "evidence/", "surprise"] if path is None else ["SHA256SUMS"]

    monkeypatch.setattr(envelope, "entries", entries)


def _tamper_bytes(
    directory: FakeArtifactDirectory, _: FakeEnvelopeDirectory, __: pytest.MonkeyPatch
) -> None:
    directory._files["dist/index.html"] = "changed"


def _tamper_mode(
    directory: FakeArtifactDirectory, _: FakeEnvelopeDirectory, __: pytest.MonkeyPatch
) -> None:
    digest = hashlib.sha256(b"index").hexdigest()
    directory._nodes = (
        directory._nodes[0],
        ArtifactNode("dist/index.html", EntryType.REGULAR, digest, 0o600),
    )


def _fake_live_nodes(
    directory: FakeArtifactDirectory,
) -> Callable[[dagger.Directory], Awaitable[tuple[ArtifactNode, ...]]]:
    async def nodes(_: dagger.Directory) -> tuple[ArtifactNode, ...]:
        return tuple(_live_node(node, directory) for node in directory._nodes)

    return nodes


def _live_node(node: ArtifactNode, directory: FakeArtifactDirectory) -> ArtifactNode:
    if node.entry_type is not EntryType.REGULAR:
        return node
    digest = hashlib.sha256(directory._files[node.path].encode()).hexdigest()
    return ArtifactNode(node.path, node.entry_type, digest, node.permissions)


def _run_envelope(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    dagger = shutil.which("dagger")
    assert dagger is not None
    return subprocess.run(  # noqa: S603
        (
            dagger,
            "-m",
            ".",
            "call",
            "envelope",
            f"--artifact={source}",
            f"--consumer-identity=owner/consumer@{'a' * 40}",
            f"--producing-identity={'b' * 40}:12345",
            "--allowed-roots=dist",
            "export",
            f"--path={output}",
        ),
        cwd=MODULE,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )


def _run_verifier(source: Path, output: Path) -> subprocess.CompletedProcess[str]:
    dagger = shutil.which("dagger")
    assert dagger is not None
    return subprocess.run(  # noqa: S603
        (
            dagger,
            "-m",
            ".",
            "call",
            "verify-envelope",
            f"--envelope={source}",
            f"--consumer-identity=owner/consumer@{'a' * 40}",
            f"--producing-identity={'b' * 40}:12345",
            "--allowed-roots=dist",
            "export",
            f"--path={output}",
        ),
        cwd=MODULE,
        capture_output=True,
        check=False,
        text=True,
        timeout=60,
    )


def _assert_exported_envelope(output: Path) -> None:
    expected = {"artifact/dist/index.html", "artifact/dist/nested/app.js"}
    paths = {path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()}
    assert paths == expected | {"evidence/artifact-manifest.json", "evidence/SHA256SUMS"}
    manifest = json.loads((output / "evidence/artifact-manifest.json").read_text())
    sums = (output / "evidence/SHA256SUMS").read_text().splitlines()
    records = {
        json.loads(line.split("  ", maxsplit=1)[1]): line.split("  ", maxsplit=1)[0]
        for line in sums
    }
    for record in manifest["files"]:
        content = (output / "artifact" / record["path"]).read_bytes()
        assert record["sha256"] == hashlib.sha256(content).hexdigest()
        assert records[f"artifact/{record['path']}"] == record["sha256"]
    manifest_bytes = (output / "evidence/artifact-manifest.json").read_bytes()
    manifest_digest = hashlib.sha256(manifest_bytes).hexdigest()
    assert records["evidence/artifact-manifest.json"] == manifest_digest


def test_should_envelope_nested_directory_and_reject_unexpected_input(tmp_path: Path) -> None:
    # Given
    source, output = tmp_path / "artifact", tmp_path / "envelope"
    (source / "dist/nested").mkdir(parents=True)
    (source / "dist/index.html").write_text("index")
    (source / "dist/nested/app.js").write_text("app")

    # When
    result = _run_envelope(source, output)
    (source / "debug.log").write_text("debug")
    rejected = _run_envelope(source, tmp_path / "rejected")

    # Then
    assert result.returncode == 0, result.stderr
    _assert_exported_envelope(output)
    assert rejected.returncode != 0
    assert "debug.log" in rejected.stderr


def test_should_order_manifest_paths_by_canonical_posix_string(tmp_path: Path) -> None:
    # Given
    source, envelope = tmp_path / "artifact", tmp_path / "envelope"
    (source / "dist/a").mkdir(parents=True)
    (source / "dist/a-z").write_text("flat")
    (source / "dist/a/b").write_text("nested")

    # When
    created = _run_envelope(source, envelope)

    # Then
    assert created.returncode == 0, created.stderr
    manifest = json.loads((envelope / "evidence/artifact-manifest.json").read_text())
    assert [record["path"] for record in manifest["files"]] == ["dist/a-z", "dist/a/b"]
    assert _run_verifier(envelope, tmp_path / "verified").returncode == 0


def test_should_verify_actual_envelope_and_reject_each_mutated_member(tmp_path: Path) -> None:
    # Given
    source, envelope = tmp_path / "artifact", tmp_path / "envelope"
    (source / "dist").mkdir(parents=True)
    (source / "dist/index.html").write_text("index")
    created = _run_envelope(source, envelope)
    assert created.returncode == 0, created.stderr

    # When / Then
    assert _run_verifier(envelope, tmp_path / "verified").returncode == 0
    for path in _tampered_members(envelope):
        rejected = _run_verifier(path, tmp_path / path.name)
        assert rejected.returncode != 0, path


def _tampered_members(envelope: Path) -> tuple[Path, ...]:
    changed = _copy_envelope(envelope, envelope.parent / "changed")
    (changed / "artifact/dist/index.html").write_text("changed")
    extra = _copy_envelope(envelope, envelope.parent / "extra")
    (extra / "artifact/dist/extra.js").write_text("extra")
    deleted = _copy_envelope(envelope, envelope.parent / "deleted")
    (deleted / "artifact/dist/index.html").unlink()
    sums = _copy_envelope(envelope, envelope.parent / "sums")
    (sums / "evidence/SHA256SUMS").write_text("tampered\n")
    manifest = _copy_envelope(envelope, envelope.parent / "manifest")
    _tamper_toolchain_manifest(manifest)
    missing_manifest = _copy_envelope(envelope, envelope.parent / "missing-manifest")
    (missing_manifest / "evidence/artifact-manifest.json").unlink()
    missing_sums = _copy_envelope(envelope, envelope.parent / "missing-sums")
    (missing_sums / "evidence/SHA256SUMS").unlink()
    extra_evidence = _copy_envelope(envelope, envelope.parent / "extra-evidence")
    (extra_evidence / "evidence/untrusted.json").write_text("untrusted")
    mode = _copy_envelope(envelope, envelope.parent / "mode")
    os.chmod(mode / "artifact/dist/index.html", 0o600)
    return (
        changed,
        extra,
        deleted,
        sums,
        manifest,
        missing_manifest,
        missing_sums,
        extra_evidence,
        mode,
    )


def _tamper_toolchain_manifest(envelope: Path) -> None:
    manifest_path = envelope / "evidence/artifact-manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["toolchain"] = ["untrusted"]
    manifest_path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")))


def _copy_envelope(source: Path, destination: Path) -> Path:
    shutil.copytree(source, destination)
    return destination


def test_should_reject_empty_directories_and_normalize_executable_metadata(tmp_path: Path) -> None:
    # Given
    empty, unexpected = tmp_path / "empty", tmp_path / "unexpected"
    executable, plain = tmp_path / "executable", tmp_path / "plain"
    (empty / "dist/nested").mkdir(parents=True)
    (unexpected / "dist").mkdir(parents=True)
    (unexpected / "dist/index.html").write_text("index")
    (unexpected / "debug-empty").mkdir()
    for root in (executable, plain):
        (root / "dist").mkdir(parents=True)
        (root / "dist/run").write_text("")
    os.chmod(executable / "dist/run", 0o755)  # noqa: S103
    os.chmod(plain / "dist/run", 0o644)

    # When
    rejected = _run_envelope(empty, tmp_path / "empty-envelope")
    unexpected_rejected = _run_envelope(unexpected, tmp_path / "unexpected-envelope")
    first = _run_envelope(executable, tmp_path / "exec-envelope")
    second = _run_envelope(plain, tmp_path / "plain-envelope")

    # Then
    assert rejected.returncode != 0
    assert unexpected_rejected.returncode != 0
    assert first.returncode == second.returncode == 0
    exec_manifest = (tmp_path / "exec-envelope/evidence/artifact-manifest.json").read_bytes()
    plain_manifest = (tmp_path / "plain-envelope/evidence/artifact-manifest.json").read_bytes()
    assert exec_manifest != plain_manifest


def test_should_export_stable_metadata_for_repeated_envelopes(tmp_path: Path) -> None:
    # Given
    source = tmp_path / "artifact"
    (source / "dist").mkdir(parents=True)
    run = source / "dist/run"
    run.write_text("run")
    os.chmod(run, 0o755)  # noqa: S103

    # When
    first = _run_envelope(source, tmp_path / "first")
    second = _run_envelope(source, tmp_path / "second")

    # Then
    assert first.returncode == second.returncode == 0
    for relative in ("artifact/dist/run", "evidence/artifact-manifest.json", "evidence/SHA256SUMS"):
        initial, repeated = tmp_path / "first" / relative, tmp_path / "second" / relative
        assert initial.read_bytes() == repeated.read_bytes()
        assert initial.stat().st_mtime == repeated.stat().st_mtime == 0
    assert (tmp_path / "first/artifact/dist/run").stat().st_mode & 0o777 == 0o755


def test_should_reject_symlink_and_preserve_control_filename_in_evidence(
    tmp_path: Path,
) -> None:
    # Given
    source, output = tmp_path / "artifact", tmp_path / "envelope"
    (source / "dist").mkdir(parents=True)
    control = 'line\nbreak\t"name.js'
    (source / "dist" / control).write_text("content")

    # When
    exported = _run_envelope(source, output)
    (source / "dist/link").symlink_to(control)
    rejected = _run_envelope(source, tmp_path / "rejected")

    # Then
    assert exported.returncode == 0, exported.stderr
    manifest = json.loads((output / "evidence/artifact-manifest.json").read_text())
    assert manifest["files"][0]["path"] == f"dist/{control}"
    assert _run_verifier(output, tmp_path / "verified").returncode == 0
    assert rejected.returncode != 0
    assert "unsupported node" in rejected.stderr
