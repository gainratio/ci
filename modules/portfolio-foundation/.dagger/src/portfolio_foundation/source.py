"""Fail-closed source inventories and Dagger workspace binding."""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import re
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

import dagger
from dagger import dag

from .identity import CommitIdentity

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
MAX_PERMISSIONS = 0o7777
# Evidence records the upstream identity; pulls use the GHCR mirror copy of the same digest.
HASH_IMAGE_IDENTITY = (
    "alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
)
HASH_IMAGE = (
    "ghcr.io/hseshadr/mirror/docker.io/library/alpine:3.22.1"
    "@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"
)
INVENTORY_TRAILER = "portfolio-foundation-inventory-v1"
INVENTORY_SCRIPT = r"""set -eu
zero=$(printf '%064d' 0)
records=/tmp/portfolio-foundation-inventory
: > "$records"
find /source -mindepth 1 -exec sh -c '
records=$1
zero=$2
shift 2
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
' sh "$records" "$zero" {} +
count=$(wc -l < "$records" | tr -d "[:space:]")
digest=$(sha256sum "$records")
digest=${digest%% *}
cat "$records"
printf "portfolio-foundation-inventory-v1\t%s\t%s\n" "$count" "$digest"
"""


class SourceMismatchError(ValueError):
    """Raised when supplied workspace bytes differ from the claimed commit."""


SourceMismatch = SourceMismatchError


class EntryType(Enum):
    """The only node kinds accepted into a source inventory."""

    DIRECTORY = "directory"
    REGULAR = "regular"
    SYMLINK = "symlink"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class InventoryEntry:
    """A content-addressed relative workspace file."""

    path: str
    sha256: str
    entry_type: EntryType
    permissions: int = 0o644

    def __post_init__(self) -> None:
        """Reject paths and hashes that cannot safely form a manifest."""
        if not _is_safe_path(self.path) or SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ValueError("inventory entries require a relative path and SHA-256 hash")
        if not 0 <= self.permissions <= MAX_PERMISSIONS:
            raise ValueError("inventory entry permissions are invalid")


@runtime_checkable
class SourceInventory(Protocol):
    """A typed adapter that exposes all nodes in a source tree."""

    async def entries(self) -> tuple[InventoryEntry, ...]:
        """Return every source node with its type and regular-file hash."""


@dataclass(frozen=True)
class SourceBinding[SourceT, HistoryT]:
    """A verified workspace plus separate exact Git history input."""

    source: SourceT
    history: HistoryT
    identity: CommitIdentity
    manifest_sha256: str


def dagger_history(
    identity: CommitIdentity, http_auth_header: dagger.Secret | None
) -> dagger.Directory:
    """Load the exact Git tree, forwarding an optional typed header only to Git."""
    repository = _history_repository(identity, http_auth_header)
    return repository.commit(identity.commit.value).tree(depth=0, include_tags=True)


def _history_repository(
    identity: CommitIdentity, http_auth_header: dagger.Secret | None
) -> dagger.GitRepository:
    if http_auth_header is None:
        return dag.git(identity.repository.github_url)
    return dag.git(identity.repository.github_url, http_auth_header=http_auth_header)


@dataclass(frozen=True)
class DaggerSourceInventory:
    """Inventory adapter that hashes Dagger regular files without host access."""

    directory: dagger.Directory

    async def entries(self) -> tuple[InventoryEntry, ...]:
        """Return a complete typed inventory for this Dagger directory."""
        output = await _inventory_container(self.directory).stdout()
        entries = _parse_inventory(output)
        _require_unique_entry_paths(entries)
        return _file_entries(list(entries))


def _inventory_container(directory: dagger.Directory) -> dagger.Container:
    """Inventory one mounted tree in one pinned read-only execution."""
    return (
        dag.container()
        .from_(HASH_IMAGE)
        .with_mounted_directory("/source", directory, read_only=True)
        .with_exec(["sh", "-ec", INVENTORY_SCRIPT])
    )


def _parse_inventory(output: str) -> tuple[InventoryEntry, ...]:
    """Parse the binary-safe fixed-field inventory emitted by the utility container."""
    records = _inventory_records(output)
    return tuple(_inventory_entry(record.removesuffix("\n")) for record in records)


def _inventory_records(output: str) -> tuple[str, ...]:
    """Require the versioned terminal marker before exposing inventory records."""
    lines = _inventory_lines(output)
    records = tuple(lines[:-1])
    _require_single_trailer(records)
    _require_trailer_digest(records, lines[-1].removesuffix("\n"))
    return records


def _inventory_lines(output: str) -> tuple[str, ...]:
    """Split only output with a complete terminal version marker."""
    if not output.endswith("\n"):
        raise SourceMismatch("source inventory complete-stream trailer is truncated")
    lines = tuple(output.splitlines(keepends=True))
    if not lines or not lines[-1].startswith(f"{INVENTORY_TRAILER}\t"):
        raise SourceMismatch("source inventory complete-stream trailer is missing")
    return lines


def _require_single_trailer(records: tuple[str, ...]) -> None:
    """Reject a second version marker anywhere in the record sequence."""
    if any(record.startswith(f"{INVENTORY_TRAILER}\t") for record in records):
        raise SourceMismatch("source inventory has a duplicate complete-stream trailer")


def _require_trailer_digest(records: tuple[str, ...], trailer: str) -> None:
    """Reject a terminal marker unless it authenticates the exact record bytes."""
    try:
        version, count, digest = trailer.split("\t")
    except ValueError as error:
        raise SourceMismatch("source inventory complete-stream trailer is malformed") from error
    actual = hashlib.sha256("".join(records).encode()).hexdigest()
    if version != INVENTORY_TRAILER or count != str(len(records)) or digest != actual:
        raise SourceMismatch("source inventory complete-stream trailer differs")


def _inventory_entry(record: str) -> InventoryEntry:
    """Build one fail-closed typed entry from an encoded inventory record."""
    try:
        entry_type, permissions, digest, path = record.split("\t")
        return InventoryEntry(
            _decoded_path(path), digest, EntryType(entry_type), _decoded_permissions(permissions)
        )
    except ValueError as error:
        raise SourceMismatch("source inventory output is malformed") from error


def _decoded_path(value: str) -> str:
    """Decode one canonical base64 UTF-8 relative path without replacement."""
    try:
        raw = base64.b64decode(value, validate=True)
        path = raw.decode()
    except (binascii.Error, UnicodeDecodeError) as error:
        raise ValueError("inventory path encoding is invalid") from error
    if base64.b64encode(raw).decode() != value:
        raise ValueError("inventory path encoding is not canonical")
    return path


def _decoded_permissions(value: str) -> int:
    """Decode canonical octal permissions without accepting signed or padded forms."""
    if not value or any(digit not in "01234567" for digit in value):
        raise ValueError("inventory permissions are invalid")
    permissions = int(value, 8)
    if f"{permissions:o}" != value:
        raise ValueError("inventory permissions are not canonical")
    return permissions


def bind_source[SourceT, HistoryT](
    source: SourceT, history: HistoryT, identity: CommitIdentity, manifest: tuple[str, ...]
) -> SourceBinding[SourceT, HistoryT]:
    """Bind distinct source and history values to a canonical manifest."""
    return SourceBinding(source, history, identity, manifest_sha256(manifest))


async def bind_dagger_source(
    source: dagger.Directory, history: dagger.Directory, identity: CommitIdentity
) -> SourceBinding[dagger.Directory, dagger.Directory]:
    """Reject a workspace unless every hosted byte matches the exact commit."""
    expected, actual = await asyncio.gather(
        canonical_inventory(DaggerSourceInventory(history.without_directory(".git"))),
        canonical_inventory(DaggerSourceInventory(source.without_directory(".git"))),
    )
    require_same_inventory(expected, actual)
    return bind_source(source, history, identity, expected)


async def canonical_inventory(inventory: SourceInventory) -> tuple[str, ...]:
    """Create a sorted path-and-SHA-256 inventory from regular files only."""
    entries = await inventory.entries()
    _require_regular_entries(entries)
    lines = tuple(_manifest_line(entry) for entry in entries)
    _require_unique_paths(lines)
    return tuple(sorted(lines))


def manifest_sha256(manifest: tuple[str, ...]) -> str:
    """Hash a canonical text representation of a source inventory."""
    content = _encoded_manifest(sorted(manifest))
    return hashlib.sha256(content).hexdigest()


def _encoded_manifest(lines: list[str]) -> bytes:
    records = tuple(line.encode() for line in lines)
    return len(records).to_bytes(8) + b"".join(_encoded_record(record) for record in records)


def _encoded_record(record: bytes) -> bytes:
    return len(record).to_bytes(8) + record


def require_same_inventory(expected: tuple[str, ...], actual: tuple[str, ...]) -> None:
    """Fail closed with the first missing, unexpected, or changed path."""
    mismatch = _first_mismatch(expected, actual)
    if mismatch is not None:
        raise SourceMismatch(f"workspace does not match exact commit at {mismatch}")


async def _dagger_paths(directory: dagger.Directory, parent: str) -> tuple[str, ...]:
    """Recursively list every path, retaining nodes until their type is checked."""
    names = await directory.entries(path=parent or None)
    return await _paths_with_descendants(directory, parent, names)


async def _paths_with_descendants(
    directory: dagger.Directory, parent: str, names: list[str]
) -> tuple[str, ...]:
    """Join direct child names and append their recursively discovered paths."""
    paths = _child_paths(parent, names)
    nested = await asyncio.gather(*(_nested_paths(directory, path) for path in paths))
    return paths + _flatten_paths(nested)


async def _nested_paths(directory: dagger.Directory, path: str) -> tuple[str, ...]:
    """Return descendants only when a Dagger node is a directory."""
    entry_type = await _dagger_entry_type(directory, path)
    return await _dagger_paths(directory, path) if entry_type is EntryType.DIRECTORY else ()


async def _dagger_entry_type(directory: dagger.Directory, path: str) -> EntryType:
    """Translate Dagger file metadata to the closed source-node vocabulary."""
    file_type = await directory.stat(path, do_not_follow_symlinks=True).file_type()
    return _entry_type(file_type)


async def _dagger_sha256(directory: dagger.Directory, path: str) -> str:
    """Hash mounted bytes with a pinned utility image rather than text decoding."""
    output = await _sha256_container(directory, path).stdout()
    return output.split(maxsplit=1)[0]


def _sha256_container(directory: dagger.Directory, path: str) -> dagger.Container:
    """Create the fixed, read-only hashing step for one relative workspace file."""
    return (
        dag.container()
        .from_(HASH_IMAGE)
        .with_mounted_directory("/source", directory, read_only=True)
        .with_exec(["sha256sum", f"/source/{path}"])
    )


def _entry_type(file_type: dagger.FileType | None) -> EntryType:
    """Map all Dagger metadata values to an explicitly handled local value."""
    if file_type is dagger.FileType.DIRECTORY:
        return EntryType.DIRECTORY
    if file_type is dagger.FileType.REGULAR:
        return EntryType.REGULAR
    if file_type is dagger.FileType.SYMLINK:
        return EntryType.SYMLINK
    return EntryType.UNKNOWN


def _first_mismatch(expected: tuple[str, ...], actual: tuple[str, ...]) -> str | None:
    """Return the first path whose full manifest line is absent or different."""
    expected_by_path = _lines_by_path(expected)
    actual_by_path = _lines_by_path(actual)
    return _first_changed_path(expected_by_path, actual_by_path)


def _lines_by_path(lines: tuple[str, ...]) -> tuple[tuple[str, str], ...]:
    """Keep manifest records ordered without introducing mutable record maps."""
    return tuple(sorted(_split_manifest_line(line) for line in lines))


def _first_changed_path(
    expected: tuple[tuple[str, str], ...], actual: tuple[tuple[str, str], ...]
) -> str | None:
    """Find the first path that is missing, unexpected, or has a new hash."""
    paths = tuple(sorted({path for path, _ in expected} | {path for path, _ in actual}))
    return next(
        (path for path in paths if _hash_at(expected, path) != _hash_at(actual, path)), None
    )


def _hash_at(lines: tuple[tuple[str, str], ...], path: str) -> str | None:
    """Read a manifest hash by path from its small sorted immutable sequence."""
    return next((digest for candidate, digest in lines if candidate == path), None)


def _is_safe_path(path: str) -> bool:
    """Allow only non-empty relative paths that cannot traverse their parent."""
    parts = tuple(path.split("/"))
    return (
        bool(path)
        and not path.startswith("/")
        and all(part not in {"", ".", ".."} for part in parts)
    )


def _join_path(parent: str, name: str) -> str:
    """Create a slash-separated relative child path."""
    logical_name = name.removesuffix("/")
    return f"{parent}/{logical_name}" if parent else logical_name


def _child_paths(parent: str, names: list[str]) -> tuple[str, ...]:
    """Join a Dagger directory's direct child names to their parent path."""
    return tuple(_join_path(parent, name) for name in names)


def _flatten_paths(groups: list[tuple[str, ...]]) -> tuple[str, ...]:
    """Flatten immutable groups of descendants without changing their order."""
    return tuple(path for group in groups for path in group)


def _manifest_line(entry: InventoryEntry) -> str:
    """Render one regular-file inventory entry in its canonical form."""
    return f"{entry.path}:{entry.permissions:o}:{entry.sha256}"


def _file_entries(entries: list[InventoryEntry]) -> tuple[InventoryEntry, ...]:
    """Omit traversed directories while retaining links for fail-closed rejection."""
    return tuple(entry for entry in entries if entry.entry_type is not EntryType.DIRECTORY)


def _require_regular_entries(entries: tuple[InventoryEntry, ...]) -> None:
    """Reject all directories, symlinks, and unknown nodes before comparison."""
    invalid = next(
        (entry.path for entry in entries if entry.entry_type is not EntryType.REGULAR), None
    )
    if invalid is not None:
        raise SourceMismatch(f"source inventory contains unsupported node at {invalid}")


def _require_unique_entry_paths(entries: tuple[InventoryEntry, ...]) -> None:
    """Reject duplicate raw nodes before directories can be filtered out."""
    paths = tuple(entry.path for entry in entries)
    if len(paths) != len(frozenset(paths)):
        raise SourceMismatch("source inventory contains duplicate raw paths")


def _require_unique_paths(lines: tuple[str, ...]) -> None:
    """Reject duplicated paths so no hash can be hidden by a repeated record."""
    paths = tuple(_split_manifest_line(line)[0] for line in lines)
    if len(paths) != len(frozenset(paths)):
        raise SourceMismatch("hosted source contains duplicate file paths")


def _split_manifest_line(line: str) -> tuple[str, str]:
    """Split the canonical path-and-mode-and-digest representation."""
    path, permissions, digest = line.rsplit(":", maxsplit=2)
    return path, f"{permissions}:{digest}"
