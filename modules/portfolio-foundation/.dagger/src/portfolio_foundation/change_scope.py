"""Conservative docs-only change classification for pull-request fast paths.

The answer is advisory in one direction only: `True` lets a consumer skip its
heavy gate, so every doubt (no base, git failure, odd output, odd path, odd
mode, empty diff) answers `False` and the full gate runs.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Final

import dagger
from dagger import dag

from .guard import GITLEAKS_IMAGE
from .identity import CommitIdentity, FullSha, RepositoryRef
from .source import dagger_history

# The guard already pulls this pinned image, and it ships git.
GIT_IMAGE: Final = GITLEAKS_IMAGE
# Only plain files may change; symlinks (120000), gitlinks (160000), and
# executables (100755) always take the full gate.
PLAIN_MODES: Final = frozenset({"000000", "100644"})
DOCS_ROOT: Final = "docs"
DOCS_SUFFIX: Final = ".md"
RAW_FIELDS: Final = 5
# Added, modified, deleted. Type changes, copies, and renames take the full gate.
PLAIN_STATUSES: Final = frozenset({"A", "M", "D"})


@dataclass(frozen=True)
class ChangedPath:
    """One side-independent path record from `git diff --raw`."""

    path: str
    old_mode: str
    new_mode: str


def diff_command(base_sha: str, head_sha: str) -> list[str]:
    """Return the merge-base diff that lists every touched path, renames unfolded."""
    raw = ["diff", "--raw", "-z", "--no-renames", "--no-ext-diff"]
    return ["git", "-C", "/repo", *raw, f"{base_sha}...{head_sha}"]


def parse_raw_diff(output: str) -> tuple[ChangedPath, ...]:
    """Parse NUL-separated `--raw` records; anything unexpected is an error."""
    fields = output.split("\0")
    if fields[-1] != "" or len(fields) % 2 == 0:
        raise ValueError("malformed git diff output")
    pairs = zip(fields[0:-1:2], fields[1:-1:2], strict=True)
    return tuple(_changed_path(header, path) for header, path in pairs)


def is_docs_only(changes: tuple[ChangedPath, ...]) -> bool:
    """Return whether a non-empty change set touches only plain Markdown docs."""
    return bool(changes) and all(map(_is_doc_change, changes))


async def classify_docs_only(repository: str, head_sha: str, base_sha: str) -> bool:
    """Diff the exact merge base against head; any doubt means the full gate."""
    head = FullSha(head_sha)
    if not base_sha:
        return False
    base = FullSha(base_sha)
    identity = CommitIdentity(RepositoryRef.parse(repository), head)
    try:
        output = await _diff_container(identity, base).stdout()
        return is_docs_only(parse_raw_diff(output))
    except (dagger.QueryError, ValueError):
        return False


def _diff_container(identity: CommitIdentity, base: FullSha) -> dagger.Container:
    history = dagger_history(identity, None)
    container = dag.container().from_(GIT_IMAGE).with_entrypoint([])
    container = container.with_mounted_directory("/repo", history, read_only=True)
    return container.with_exec(diff_command(base.value, identity.commit.value))


def _changed_path(header: str, path: str) -> ChangedPath:
    parts = header.split(" ")
    if len(parts) != RAW_FIELDS or not parts[0].startswith(":") or parts[4] not in PLAIN_STATUSES:
        raise ValueError(f"unexpected git diff record: {header!r}")
    return ChangedPath(path, parts[0].removeprefix(":"), parts[1])


def _is_doc_change(change: ChangedPath) -> bool:
    modes_are_plain = {change.old_mode, change.new_mode} <= PLAIN_MODES
    return modes_are_plain and _is_doc_path(change.path)


def _is_doc_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if not path.endswith(DOCS_SUFFIX) or ".." in parts or "." in parts:
        return False
    return len(parts) == 1 or parts[0] == DOCS_ROOT
