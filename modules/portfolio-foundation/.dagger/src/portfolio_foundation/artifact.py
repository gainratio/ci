"""Deterministic artifact envelopes and strict pre-mutation verification."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from dataclasses import dataclass
from functools import reduce
from typing import Final, TypeGuard

import dagger
from dagger import dag

from .identity import CommitIdentity, FullSha, RepositoryRef
from .source import (
    HASH_IMAGE,
    HASH_IMAGE_IDENTITY,
    INVENTORY_TRAILER,
    EntryType,
    InventoryEntry,
    SourceMismatch,
    _parse_inventory,
    _require_unique_entry_paths,
)

ENGINE_VERSION: Final = "v0.21.8"
EPOCH: Final = 0
EVIDENCE_IMAGE: Final = (
    "ghcr.io/gainratio/mirror/docker.io/library/python:3.13.15-alpine3.24"
    "@sha256:540c7d91f98ff6880174c40e99067bf5941eb54d818a7a5e094d188b196a934d"
)
IDENTITY_SEPARATOR_INDEX: Final = 40
MANIFEST_PATH: Final = "evidence/artifact-manifest.json"
MAX_ALLOWED_ROOT_BYTES: Final = 255
MAX_ALLOWED_ROOT_COUNT: Final = 32
MAX_ALLOWED_ROOTS_JSON_BYTES: Final = 4_096
MAX_RUN_ID_DIGITS: Final = 20
MAX_RUN_ID_VALUE: Final = (2**64) - 1
MIN_PRODUCING_IDENTITY_LENGTH: Final = 42
SCHEMA_VERSION: Final = 1
SUMS_PATH: Final = "evidence/SHA256SUMS"
TOOLCHAIN: Final = ("dagger-engine:v0.21.8", f"artifact-hasher:{HASH_IMAGE_IDENTITY}")
RUN_ID_PATTERN: Final = re.compile(r"[1-9][0-9]*")
SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
NORMAL_MODES: Final = frozenset((0o644, 0o755))
ARTIFACT_INVENTORY_SCRIPT: Final = r"""set -eu
zero=$(printf '%064d' 0)
records=/tmp/portfolio-foundation-inventory
output=/normalized
: > "$records"
mkdir -p "$output"
find /source -mindepth 1 -exec sh -c '
records=$1
zero=$2
output=$3
shift 3
for full_path do
  path=${full_path#/source/}
  if [ -L "$full_path" ]; then
    kind=symlink
    digest=$zero
    permissions=0
  elif [ -f "$full_path" ]; then
    kind=regular
    digest=$(sha256sum "$full_path")
    digest=${digest%% *}
    permissions=$(stat -c "%a" "$full_path")
    target=$output/$path
    mkdir -p "$(dirname "$target")"
    cp "$full_path" "$target"
    mode=644
    if [ $((0$permissions & 0111)) -ne 0 ]; then mode=755; fi
    chmod "$mode" "$target"
  elif [ -d "$full_path" ]; then
    kind=directory
    digest=$zero
    permissions=0
  else
    kind=unknown
    digest=$zero
    permissions=0
  fi
  encoded=$(printf "%s" "$path" | base64 | tr -d "\n")
  printf "%s\t%s\t%s\t%s\n" "$kind" "$permissions" "$digest" "$encoded" >> "$records"
done
' sh "$records" "$zero" "$output" {} +
count=$(wc -l < "$records" | tr -d "[:space:]")
digest=$(sha256sum "$records")
digest=${digest%% *}
cat "$records"
printf "%s\t%s\t%s\n" "$INVENTORY_TRAILER" "$count" "$digest"
"""
ARTIFACT_EVIDENCE_SCRIPT: Final = r"""import hashlib
import json
import os
import shutil
import stat
from pathlib import Path

SOURCE = Path("/input")
ENVELOPE = Path("/envelope")
ARTIFACT = ENVELOPE / "artifact"
EVIDENCE = ENVELOPE / "evidence"


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative_path(path):
    return path.relative_to(ARTIFACT).as_posix()


def artifact_files():
    files = []
    for path in sorted(ARTIFACT.rglob("*"), key=relative_path):
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            files.append({
                "mode": stat.S_IMODE(metadata.st_mode),
                "path": relative_path(path),
                "sha256": file_digest(path),
            })
    return files


def manifest(files):
    return {
        "allowed_roots": json.loads(os.environ["ALLOWED_ROOTS"]),
        "consumer_sha": os.environ["CONSUMER_SHA"],
        "engine_version": os.environ["ENGINE_VERSION"],
        "files": files,
        "module_sha": os.environ["MODULE_SHA"],
        "producing_run_id": os.environ["PRODUCING_RUN_ID"],
        "repository": os.environ["REPOSITORY"],
        "schema_version": int(os.environ["SCHEMA_VERSION"]),
        "toolchain": json.loads(os.environ["TOOLCHAIN"]),
    }


def canonical_json(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def checksum_record(path, digest):
    return f"{digest}  {canonical_json(path)}\n"


def write_evidence(files):
    text = canonical_json(manifest(files))
    records = [(f"artifact/{item['path']}", item["sha256"]) for item in files]
    records.append(("evidence/artifact-manifest.json", hashlib.sha256(text.encode()).hexdigest()))
    (EVIDENCE / "artifact-manifest.json").write_text(text, encoding="utf-8")
    sums = "".join(checksum_record(path, digest) for path, digest in records)
    (EVIDENCE / "SHA256SUMS").write_text(sums, encoding="utf-8")


def normalize_evidence():
    for name in ("artifact-manifest.json", "SHA256SUMS"):
        os.chmod(EVIDENCE / name, 0o644)


def set_epoch():
    for path in sorted(ENVELOPE.rglob("*"), reverse=True):
        os.utime(path, (0, 0), follow_symlinks=False)
    os.utime(ENVELOPE, (0, 0), follow_symlinks=False)


shutil.copytree(SOURCE, ARTIFACT)
EVIDENCE.mkdir()
write_evidence(artifact_files())
normalize_evidence()
set_epoch()
"""


class ArtifactEnvelopeError(ValueError):
    """Base error for invalid product artifacts and immutable evidence."""


class UnexpectedArtifactPathError(ArtifactEnvelopeError):
    """Raised for paths outside the declared product artifact contract."""


class EmptyArtifactError(ArtifactEnvelopeError):
    """Raised when a product artifact has no files or contains empty directories."""


class UnsupportedArtifactNodeError(ArtifactEnvelopeError):
    """Raised for symlinks and every non-regular, non-directory node."""


class ChecksumMismatchError(ArtifactEnvelopeError):
    """Raised when current envelope contents differ from checksum evidence."""


class ToolchainMismatchError(ArtifactEnvelopeError):
    """Raised for evidence made by an incompatible immutable toolchain."""


class ManifestParseError(ArtifactEnvelopeError):
    """Raised when a manifest is not a closed canonical JSON schema instance."""


@dataclass(frozen=True)
class ArtifactFile:
    """A regular artifact file's normalized behavioral metadata and digest."""

    path: str
    sha256: str
    mode: int = 0o644

    def __post_init__(self) -> None:
        """Reject unsafe paths, malformed digests, and unnormalized modes."""
        if not _safe_path(self.path) or SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise UnexpectedArtifactPathError("artifact file requires a safe path and SHA-256")
        if self.mode not in NORMAL_MODES:
            raise UnexpectedArtifactPathError("artifact file mode must be canonical 0644 or 0755")


@dataclass(frozen=True)
class ArtifactManifest:
    """Closed durable identity for a product artifact and producing toolchain."""

    identity: CommitIdentity
    module_sha: FullSha
    engine_version: str
    toolchain: tuple[str, ...]
    producing_run_id: str
    allowed_roots: tuple[str, ...]
    files: tuple[ArtifactFile, ...]
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        """Enforce every immutable manifest invariant on direct construction."""
        _validate_manifest(self)

    def to_json(self) -> str:
        """Serialize this closed schema with deterministic key and record ordering."""
        return json.dumps(
            _manifest_payload(self), ensure_ascii=True, separators=(",", ":"), sort_keys=True
        )


@dataclass(frozen=True)
class ArtifactContext:
    """Exact producer identity expected by construction and public verification."""

    identity: CommitIdentity
    module_sha: str
    allowed_roots: tuple[str, ...]
    producing_run_id: str


@dataclass(frozen=True)
class ArtifactNode:
    """A fully observed Dagger node before it becomes product evidence."""

    path: str
    entry_type: EntryType
    sha256: str
    permissions: int


@dataclass(frozen=True)
class ArtifactEvidence:
    """Normalized product bytes paired with their transportable manifest."""

    directory: dagger.Directory
    manifest: ArtifactManifest


@dataclass(frozen=True)
class _ArtifactInventory:
    """Authenticated nodes and normalized bytes from one utility step."""

    nodes: tuple[ArtifactNode, ...]
    directory: dagger.Directory


def build_manifest(files: tuple[ArtifactFile, ...], context: ArtifactContext) -> ArtifactManifest:
    """Build validated canonical evidence from normalized regular artifact records."""
    roots = canonical_roots(context.allowed_roots)
    return ArtifactManifest(
        context.identity,
        FullSha(context.module_sha),
        ENGINE_VERSION,
        TOOLCHAIN,
        context.producing_run_id,
        roots,
        tuple(sorted(files, key=lambda item: item.path)),
    )


def parse_consumer_identity(value: str) -> CommitIdentity:
    """Parse the public repository-at-full-SHA argument without a mutable ref."""
    repository, marker, commit_sha = value.rpartition("@")
    if not marker:
        raise ValueError("consumer identity must be owner/repository@full-sha")
    return CommitIdentity(RepositoryRef.parse(repository), FullSha(commit_sha))


def parse_producing_identity(value: str) -> tuple[str, str]:
    """Parse an exact module SHA and a numeric producing GitHub run identity."""
    if len(value) < MIN_PRODUCING_IDENTITY_LENGTH or value[IDENTITY_SEPARATOR_INDEX] != ":":
        raise ValueError("producing identity must be full-module-sha:run-id")
    module_sha = FullSha(value[:IDENTITY_SEPARATOR_INDEX]).value
    run_id = value[MIN_PRODUCING_IDENTITY_LENGTH - 1 :]
    _require_run_id(run_id)
    return module_sha, run_id


def canonical_roots(roots: tuple[str, ...]) -> tuple[str, ...]:
    """Return canonical ordering for a nonempty safe allowed-root set."""
    ordered = tuple(sorted(roots))
    _require_canonical_roots(roots, ordered)
    _require_safe_roots(ordered)
    _require_bounded_roots(ordered)
    return ordered


def validate_paths(paths: tuple[str, ...], allowed_roots: tuple[str, ...]) -> None:
    """Require unique, safe regular-file inventory under explicit allowed roots."""
    roots = canonical_roots(allowed_roots)
    _require_artifact_paths(paths)
    _require_unique_paths(paths)
    _require_allowed_paths(paths, roots)


def _require_canonical_roots(actual: tuple[str, ...], ordered: tuple[str, ...]) -> None:
    """Reject empty, unsorted, and duplicate root declarations."""
    if not actual or actual != ordered or len(actual) != len(frozenset(actual)):
        raise UnexpectedArtifactPathError("artifact roots must be sorted and unique")


def _require_safe_roots(roots: tuple[str, ...]) -> None:
    """Reject a root that cannot safely participate in a slash-separated path contract."""
    if any(not _safe_path(root) for root in roots):
        raise UnexpectedArtifactPathError("artifact roots must be safe relative paths")


def _require_bounded_roots(roots: tuple[str, ...]) -> None:
    """Keep caller-controlled root policy below every GraphQL scalar boundary."""
    if len(roots) > MAX_ALLOWED_ROOT_COUNT:
        raise UnexpectedArtifactPathError("artifact roots exceed count limit")
    if any(len(root.encode()) > MAX_ALLOWED_ROOT_BYTES for root in roots):
        raise UnexpectedArtifactPathError("artifact roots exceed per-root byte limit")
    if len(_roots_json(roots).encode()) > MAX_ALLOWED_ROOTS_JSON_BYTES:
        raise UnexpectedArtifactPathError("artifact roots exceed serialized byte limit")


def _roots_json(roots: tuple[str, ...]) -> str:
    """Serialize the exact bounded root policy passed to the evidence container."""
    return json.dumps(roots, ensure_ascii=True, separators=(",", ":"))


def _require_artifact_paths(paths: tuple[str, ...]) -> None:
    """Reject an empty regular-file inventory before it can form evidence."""
    if not paths:
        raise EmptyArtifactError("artifact inventory is empty")


def _require_unique_paths(paths: tuple[str, ...]) -> None:
    """Reject duplicate records that could conceal a substituted digest."""
    if len(paths) != len(frozenset(paths)):
        raise UnexpectedArtifactPathError("artifact inventory contains duplicate path")


def _require_allowed_paths(paths: tuple[str, ...], roots: tuple[str, ...]) -> None:
    """Reject a regular file outside the explicitly declared artifact roots."""
    invalid = next((path for path in paths if not _allowed_path(path, roots)), None)
    if invalid is not None:
        raise UnexpectedArtifactPathError(f"artifact path is not allowed: {invalid}")


def artifact_files(entries: tuple[InventoryEntry, ...]) -> tuple[ArtifactFile, ...]:
    """Adapt legacy typed inventory tests while rejecting every non-regular file node."""
    invalid = next(
        (entry.path for entry in entries if entry.entry_type is not EntryType.REGULAR), None
    )
    if invalid is not None:
        raise UnsupportedArtifactNodeError(f"artifact contains unsupported node at {invalid}")
    return tuple(ArtifactFile(entry.path, entry.sha256) for entry in entries)


async def envelope_directory(
    artifact: dagger.Directory,
    identity: CommitIdentity,
    module_sha: str,
    allowed_roots: tuple[str, ...],
    producing_run_id: str,
) -> dagger.Directory:
    """Normalize an artifact and wrap it in the closed evidence transport directory."""
    evidence = await collect_artifact_evidence(
        artifact, identity, module_sha, allowed_roots, producing_run_id
    )
    return _envelope_directory(evidence)


async def verify_envelope_directory(
    envelope: dagger.Directory,
    identity: CommitIdentity,
    module_sha: str,
    allowed_roots: tuple[str, ...],
    producing_run_id: str,
) -> dagger.Directory:
    """Revalidate current envelope bytes before returning only the artifact subtree."""
    _require_context(identity, module_sha, allowed_roots, producing_run_id)
    await _require_closed_layout(envelope)
    manifest, raw = await _read_manifest(envelope)
    expected = ArtifactContext(identity, module_sha, allowed_roots, producing_run_id)
    await _verify_manifest_and_artifact(envelope, manifest, raw, expected)
    return envelope.directory("artifact")


async def _verify_manifest_and_artifact(
    envelope: dagger.Directory, manifest: ArtifactManifest, raw: str, expected: ArtifactContext
) -> None:
    """Validate identity, canonical serialization, current artifact, and actual checksums."""
    _require_expected_manifest(manifest, expected)
    if raw != manifest.to_json():
        raise ManifestParseError("artifact manifest JSON is not canonical")
    await _require_current_artifact(envelope.directory("artifact"), manifest)
    await _require_sums(envelope, manifest)


async def collect_artifact_evidence(
    artifact: dagger.Directory,
    identity: CommitIdentity,
    module_sha: str,
    allowed_roots: tuple[str, ...],
    producing_run_id: str,
) -> ArtifactEvidence:
    """Observe all nodes, reject gaps, and normalize accepted artifact output."""
    _require_context(identity, module_sha, allowed_roots, producing_run_id)
    inventory = await _artifact_inventory(artifact)
    _validate_nodes(inventory.nodes, allowed_roots)
    files = _normalized_files(inventory.nodes)
    context = ArtifactContext(identity, module_sha, allowed_roots, producing_run_id)
    return ArtifactEvidence(inventory.directory, build_manifest(files, context))


async def _artifact_nodes(directory: dagger.Directory) -> tuple[ArtifactNode, ...]:
    """Return every Dagger node including directories, links, modes, and file digests."""
    return (await _artifact_inventory(directory)).nodes


async def _artifact_inventory(directory: dagger.Directory) -> _ArtifactInventory:
    """Inventory and bulk-normalize one tree through a shared pinned step."""
    container = _artifact_inventory_container(directory)
    entries = await _artifact_inventory_entries(container)
    nodes = tuple(sorted((_artifact_node(entry) for entry in entries), key=lambda node: node.path))
    return _ArtifactInventory(nodes, _normalized_directory(container))


async def _artifact_inventory_entries(
    container: dagger.Container,
) -> tuple[InventoryEntry, ...]:
    """Parse and authenticate every raw artifact inventory record."""
    try:
        entries = _parse_inventory(await container.stdout())
        _require_unique_entry_paths(entries)
    except SourceMismatch as error:
        raise ArtifactEnvelopeError("artifact inventory output is malformed") from error
    return entries


def _artifact_node(entry: InventoryEntry) -> ArtifactNode:
    """Adapt one authenticated raw inventory record to artifact policy."""
    return ArtifactNode(entry.path, entry.entry_type, entry.sha256, entry.permissions)


def _artifact_inventory_container(directory: dagger.Directory) -> dagger.Container:
    """Inventory and normalize one read-only tree in one pinned execution."""
    return (
        dag.container()
        .from_(HASH_IMAGE)
        .with_env_variable("INVENTORY_TRAILER", INVENTORY_TRAILER)
        .with_mounted_directory("/source", directory, read_only=True)
        .with_exec(["sh", "-ec", ARTIFACT_INVENTORY_SCRIPT])
    )


def _validate_nodes(nodes: tuple[ArtifactNode, ...], roots: tuple[str, ...]) -> None:
    """Reject unmanifestable nodes, empty directories, and out-of-contract paths."""
    _require_supported_nodes(nodes)
    _require_allowed_nodes(nodes, canonical_roots(roots))
    _require_no_empty_directories(nodes)
    paths = tuple(node.path for node in nodes if node.entry_type is EntryType.REGULAR)
    validate_paths(paths, roots)


def _require_supported_nodes(nodes: tuple[ArtifactNode, ...]) -> None:
    """Reject links and unknown node kinds rather than following or omitting them."""
    invalid = next(
        (
            node.path
            for node in nodes
            if node.entry_type not in {EntryType.DIRECTORY, EntryType.REGULAR}
        ),
        None,
    )
    if invalid is not None:
        raise UnsupportedArtifactNodeError(f"artifact contains unsupported node at {invalid}")


def _require_allowed_nodes(nodes: tuple[ArtifactNode, ...], roots: tuple[str, ...]) -> None:
    """Ensure files and directories both live below one explicit allowed root."""
    invalid = next((node.path for node in nodes if not _allowed_path(node.path, roots)), None)
    if invalid is not None:
        raise UnexpectedArtifactPathError(f"artifact path is not allowed: {invalid}")


def _require_no_empty_directories(nodes: tuple[ArtifactNode, ...]) -> None:
    """Reject every empty directory so no invisible node can cross the boundary."""
    empty = next((node.path for node in nodes if _empty_directory(node, nodes)), None)
    if empty is not None:
        raise EmptyArtifactError(f"artifact contains empty directory at {empty}")


def _empty_directory(node: ArtifactNode, nodes: tuple[ArtifactNode, ...]) -> bool:
    """Return whether an observed directory has no observed descendant node."""
    return node.entry_type is EntryType.DIRECTORY and not any(
        other.path.startswith(f"{node.path}/") for other in nodes
    )


def _normalized_files(nodes: tuple[ArtifactNode, ...]) -> tuple[ArtifactFile, ...]:
    """Create sorted durable records retaining only execute-bit behavior metadata."""
    files = tuple(_normalized_file(node) for node in nodes if node.entry_type is EntryType.REGULAR)
    return tuple(sorted(files, key=lambda item: item.path))


def _normalized_file(node: ArtifactNode) -> ArtifactFile:
    """Normalize arbitrary source permissions to portable nonexec or exec modes."""
    return ArtifactFile(node.path, node.sha256, 0o755 if node.permissions & 0o111 else 0o644)


def _normalized_directory(container: dagger.Container) -> dagger.Directory:
    """Return the bulk-normalized output from the authenticated inventory step."""
    return container.directory("/normalized").with_timestamps(EPOCH)


def sha256_sums(manifest: ArtifactManifest) -> str:
    """Render exact checksums for normalized files and canonical manifest evidence."""
    records = tuple((f"artifact/{file.path}", file.sha256) for file in manifest.files)
    digest = hashlib.sha256(manifest.to_json().encode()).hexdigest()
    all_records = (*records, (MANIFEST_PATH, digest))
    return "".join(_checksum_record(path, value) for path, value in all_records)


def validate_evidence(manifest: ArtifactManifest, checksums: str) -> None:
    """Validate pure manifest/checksum correspondence; use verifier for live bytes."""
    _require_compatible_toolchain(manifest)
    if checksums != sha256_sums(manifest):
        raise ChecksumMismatchError("artifact evidence checksum does not match its manifest")


def require_compatible_toolchain(manifest: ArtifactManifest) -> None:
    """Public pure check retained for callers that hold a validated manifest value object."""
    _require_compatible_toolchain(manifest)


def parse_manifest(text: str) -> ArtifactManifest:
    """Parse a closed canonical JSON manifest and reject unknown or malformed fields."""
    try:
        value = json.loads(text)
    except json.JSONDecodeError as error:
        raise ManifestParseError("artifact manifest is not JSON") from error
    return _manifest_from_value(value)


async def _require_closed_layout(envelope: dagger.Directory) -> None:
    """Require exactly artifact/evidence roots and exactly two evidence files."""
    roots, evidence = await asyncio.gather(envelope.entries(), envelope.entries(path="evidence"))
    if not _closed_entries(roots, evidence):
        raise ManifestParseError("envelope layout is not closed")


async def _read_manifest(envelope: dagger.Directory) -> tuple[ArtifactManifest, str]:
    """Read and parse the manifest from actual caller-supplied envelope bytes."""
    text = await envelope.file(MANIFEST_PATH).contents()
    return parse_manifest(text), text


async def _require_current_artifact(
    directory: dagger.Directory, manifest: ArtifactManifest
) -> None:
    """Hash caller bytes and require their exact path, digest, and mode set."""
    nodes = await _artifact_nodes(directory)
    _validate_nodes(nodes, manifest.allowed_roots)
    actual = _verified_files(nodes)
    if actual != manifest.files:
        raise ChecksumMismatchError("artifact bytes or modes differ from manifest")


def _verified_files(nodes: tuple[ArtifactNode, ...]) -> tuple[ArtifactFile, ...]:
    """Require envelope files already have canonical modes rather than normalizing tamper."""
    regular = _regular_nodes(nodes)
    _require_canonical_modes(regular)
    return tuple(ArtifactFile(node.path, node.sha256, node.permissions) for node in regular)


def _regular_nodes(nodes: tuple[ArtifactNode, ...]) -> tuple[ArtifactNode, ...]:
    """Keep regular nodes after the complete inventory rejects every other type."""
    return tuple(node for node in nodes if node.entry_type is EntryType.REGULAR)


def _require_canonical_modes(nodes: tuple[ArtifactNode, ...]) -> None:
    """Reject a changed output permission rather than normalizing a tampered artifact."""
    invalid = next((node.path for node in nodes if node.permissions not in NORMAL_MODES), None)
    if invalid is not None:
        raise ChecksumMismatchError(f"artifact mode is not canonical at {invalid}")


async def _require_sums(envelope: dagger.Directory, manifest: ArtifactManifest) -> None:
    """Read and compare actual checksums, including manifest digest record and set."""
    actual = await envelope.file(SUMS_PATH).contents()
    if _parse_sums(actual) != _parse_sums(sha256_sums(manifest)):
        raise ChecksumMismatchError("artifact checksum records differ from manifest")


def _manifest_from_value(value: object) -> ArtifactManifest:
    """Convert only the exact JSON object schema into a validating manifest record."""
    data = _object(value)
    if frozenset(data) != _manifest_keys():
        raise ManifestParseError("artifact manifest has unknown or missing fields")
    return ArtifactManifest(
        _identity(data),
        FullSha(_text(data, "module_sha")),
        _text(data, "engine_version"),
        _strings(data, "toolchain"),
        _text(data, "producing_run_id"),
        _strings(data, "allowed_roots"),
        _files(data),
        _integer(data, "schema_version"),
    )


def _object(value: object) -> dict[str, object]:
    """Require a JSON object with string keys before closed-schema parsing."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ManifestParseError("artifact manifest must be an object")
    return value


def _identity(data: dict[str, object]) -> CommitIdentity:
    """Build full consumer identity from the two closed manifest fields."""
    repository = RepositoryRef.parse(_text(data, "repository"))
    return CommitIdentity(repository, FullSha(_text(data, "consumer_sha")))


def _text(data: dict[str, object], key: str) -> str:
    """Require one named JSON string field without coercion."""
    value = data.get(key)
    if not isinstance(value, str):
        raise ManifestParseError(f"artifact manifest field {key} must be text")
    return value


def _integer(data: dict[str, object], key: str) -> int:
    """Require one named JSON integer field without accepting booleans."""
    value = data.get(key)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ManifestParseError(f"artifact manifest field {key} must be an integer")
    return value


def _strings(data: dict[str, object], key: str) -> tuple[str, ...]:
    """Require one named JSON string array and preserve supplied ordering."""
    value = data.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ManifestParseError(f"artifact manifest field {key} must be text array")
    return tuple(value)


def _files(data: dict[str, object]) -> tuple[ArtifactFile, ...]:
    """Require every closed file record to contain exactly path, digest, and mode."""
    value = data.get("files")
    if not isinstance(value, list):
        raise ManifestParseError("artifact manifest files must be an array")
    return tuple(_file_record(item) for item in value)


def _file_record(value: object) -> ArtifactFile:
    """Parse one closed JSON file record without ignoring unknown properties."""
    data = _object(value)
    if frozenset(data) != frozenset(("path", "sha256", "mode")):
        raise ManifestParseError("artifact manifest file record has unknown or missing fields")
    return ArtifactFile(_text(data, "path"), _text(data, "sha256"), _integer(data, "mode"))


def _parse_sums(text: str) -> tuple[tuple[str, str], ...]:
    """Parse JSON-escaped checksum records so duplicate paths cannot be hidden."""
    records = tuple(_sum_record(line) for line in text.splitlines())
    if not records or len(records) != len(frozenset(path for path, _ in records)):
        raise ChecksumMismatchError("artifact checksum records are empty or duplicate")
    return records


def _sum_record(line: str) -> tuple[str, str]:
    """Require one SHA-256 plus JSON path checksum record without permissive splitting."""
    digest, separator, encoded = line.partition("  ")
    if separator != "  " or SHA256_PATTERN.fullmatch(digest) is None:
        raise ChecksumMismatchError("artifact checksum record is malformed")
    try:
        path = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise ChecksumMismatchError("artifact checksum path is malformed") from error
    if not isinstance(path, str):
        raise ChecksumMismatchError("artifact checksum path is not text")
    return path, digest


def _validate_manifest(manifest: ArtifactManifest) -> None:
    """Validate schema, identities, roots, run ID, records, and toolchain exactly."""
    _require_manifest_schema(manifest.schema_version)
    _require_manifest_identity(manifest.identity)
    if not isinstance(manifest.module_sha, FullSha):
        raise ManifestParseError("artifact manifest module identity is invalid")
    _require_run_id(manifest.producing_run_id)
    canonical_roots(manifest.allowed_roots)
    validate_paths(tuple(file.path for file in manifest.files), manifest.allowed_roots)
    if manifest.files != tuple(sorted(manifest.files, key=lambda item: item.path)):
        raise ManifestParseError("artifact manifest files must be sorted")
    _require_compatible_toolchain(manifest)


def _require_manifest_schema(value: object) -> None:
    """Require the one supported schema as an exact non-boolean integer."""
    if type(value) is not int or value != SCHEMA_VERSION:
        raise ManifestParseError("artifact manifest schema version is invalid")


def _require_manifest_identity(value: object) -> None:
    """Require a complete identity graph before immutable evidence can exist."""
    if not _is_exact_identity(value):
        raise ManifestParseError("artifact manifest identity is invalid")
    _validate_identity_values(value)


def _is_exact_identity(value: object) -> TypeGuard[CommitIdentity]:
    """Recognize only canonical identity value types, never structural lookalikes."""
    if not isinstance(value, CommitIdentity) or type(value) is not CommitIdentity:
        return False
    return type(value.repository) is RepositoryRef and type(value.commit) is FullSha


def _validate_identity_values(identity: CommitIdentity) -> None:
    """Reconstruct nested value objects to reject forged instances with invalid fields."""
    try:
        RepositoryRef(identity.repository.owner, identity.repository.name)
        FullSha(identity.commit.value)
    except (TypeError, ValueError) as error:
        raise ManifestParseError("artifact manifest identity is invalid") from error


def _require_compatible_toolchain(manifest: ArtifactManifest) -> None:
    """Require fixed engine and digest-pinned hashing tuple exactly."""
    if manifest.engine_version != ENGINE_VERSION or manifest.toolchain != TOOLCHAIN:
        raise ToolchainMismatchError("artifact manifest toolchain is incompatible")


def _require_context(
    identity: CommitIdentity, module_sha: str, roots: tuple[str, ...], run_id: str
) -> None:
    """Validate public verifier expectations before caller-controlled bytes are inspected."""
    FullSha(module_sha)
    canonical_roots(roots)
    _require_run_id(run_id)


def _require_expected_manifest(manifest: ArtifactManifest, expected: ArtifactContext) -> None:
    """Bind received envelope to every exact caller-supplied production identity."""
    actual = ArtifactContext(
        manifest.identity,
        manifest.module_sha.value,
        manifest.allowed_roots,
        manifest.producing_run_id,
    )
    if actual != expected:
        raise ManifestParseError("artifact manifest does not match expected identities")


def _entry_names(entries: list[str]) -> tuple[str, ...]:
    """Normalize Dagger slash suffixes for exact closed-layout comparison."""
    return tuple(sorted(entry.removesuffix("/") for entry in entries))


def _evidence_names() -> tuple[str, str]:
    """Return the only two evidence basenames allowed in a transport envelope."""
    return "SHA256SUMS", "artifact-manifest.json"


def _closed_entries(roots: list[str], evidence: list[str]) -> bool:
    """Check both directory levels use exactly the closed envelope layout."""
    return (
        _entry_names(roots) == ("artifact", "evidence")
        and _entry_names(evidence) == _evidence_names()
    )


def _manifest_keys() -> frozenset[str]:
    """Return every and only permitted manifest key for closed-schema parsing."""
    return frozenset(
        (
            "allowed_roots",
            "consumer_sha",
            "engine_version",
            "files",
            "module_sha",
            "producing_run_id",
            "repository",
            "schema_version",
            "toolchain",
        )
    )


def _manifest_payload(manifest: ArtifactManifest) -> object:
    """Render serializable manifest body without exposing mutable record maps."""
    return {
        "allowed_roots": manifest.allowed_roots,
        "consumer_sha": manifest.identity.commit.value,
        "engine_version": manifest.engine_version,
        "files": [_file_payload(file) for file in manifest.files],
        "module_sha": manifest.module_sha.value,
        "producing_run_id": manifest.producing_run_id,
        "repository": f"{manifest.identity.repository.owner}/{manifest.identity.repository.name}",
        "schema_version": manifest.schema_version,
        "toolchain": manifest.toolchain,
    }


def _file_payload(file: ArtifactFile) -> object:
    """Render one immutable file record for the canonical JSON manifest schema."""
    return {"mode": file.mode, "path": file.path, "sha256": file.sha256}


def _safe_path(path: str) -> bool:
    """Accept legal non-NUL Git names while excluding absolute and traversal components."""
    parts = tuple(path.split("/"))
    return (
        bool(path)
        and "\x00" not in path
        and not path.startswith("/")
        and all(part not in {"", ".", ".."} for part in parts)
    )


def _allowed_path(path: str, roots: tuple[str, ...]) -> bool:
    """Check whether a safe node path is recursively under an allowed root."""
    return _safe_path(path) and any(path == root or path.startswith(f"{root}/") for root in roots)


def _require_run_id(run_id: str) -> None:
    """Require nonempty numeric producing-run identity with no free-text serialization."""
    matches = RUN_ID_PATTERN.fullmatch(run_id) is not None
    if not matches or len(run_id) > MAX_RUN_ID_DIGITS or int(run_id) > MAX_RUN_ID_VALUE:
        raise ManifestParseError("producing run ID must be a nonempty positive decimal value")


def _checksum_record(path: str, digest: str) -> str:
    """Encode checksum paths as JSON so every legal filename remains unambiguous."""
    return f"{digest}  {json.dumps(path, ensure_ascii=True, separators=(',', ':'))}\n"


def _envelope_directory(evidence: ArtifactEvidence) -> dagger.Directory:
    """Create the complete envelope in one pinned, fixed-size execution graph."""
    container = _evidence_container(evidence.directory, evidence.manifest)
    return container.directory("/envelope").with_timestamps(EPOCH)


def _evidence_container(artifact: dagger.Directory, manifest: ArtifactManifest) -> dagger.Container:
    """Generate scale-independent evidence without inline manifest graph arguments."""
    container = dag.container().from_(EVIDENCE_IMAGE)
    container = container.with_mounted_directory("/input", artifact, read_only=True)
    container = reduce(_with_evidence_variable, _evidence_environment(manifest), container)
    return container.with_exec(["python", "-c", ARTIFACT_EVIDENCE_SCRIPT])


def _with_evidence_variable(
    container: dagger.Container, variable: tuple[str, str]
) -> dagger.Container:
    """Add one non-secret, cacheable evidence input to the pinned builder."""
    return container.with_env_variable(*variable)


def _evidence_environment(manifest: ArtifactManifest) -> tuple[tuple[str, str], ...]:
    """Return only fixed identity and policy inputs for in-container serialization."""
    repository = manifest.identity.repository
    return (
        ("ALLOWED_ROOTS", _roots_json(manifest.allowed_roots)),
        ("CONSUMER_SHA", manifest.identity.commit.value),
        ("ENGINE_VERSION", manifest.engine_version),
        ("MODULE_SHA", manifest.module_sha.value),
        ("PRODUCING_RUN_ID", manifest.producing_run_id),
        ("REPOSITORY", f"{repository.owner}/{repository.name}"),
        ("SCHEMA_VERSION", str(manifest.schema_version)),
        ("TOOLCHAIN", json.dumps(manifest.toolchain, separators=(",", ":"))),
    )


UnexpectedArtifactPath = UnexpectedArtifactPathError
EmptyArtifact = EmptyArtifactError
UnsupportedArtifactNode = UnsupportedArtifactNodeError
ChecksumMismatch = ChecksumMismatchError
ToolchainMismatch = ToolchainMismatchError
