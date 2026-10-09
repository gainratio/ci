"""Copy pinned upstream images into the GHCR mirror by digest, then prove the copy.

Stdlib only: the mirror job runs this file with plain ``python3`` next to a pinned
``crane`` binary, so it must not depend on the module's virtual environment.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import quote

MIRROR_OWNER: Final = "gainratio"
MIRROR_ROOT: Final = f"ghcr.io/{MIRROR_OWNER}/mirror"
PACKAGE_URL: Final = f"https://github.com/orgs/{MIRROR_OWNER}/packages/container/package/"
DIGEST: Final = re.compile(r"sha256:[0-9a-f]{64}")
SOURCE: Final = re.compile(r"(?P<repository>[a-z0-9.-]+\.[a-z]+/[a-z0-9._/-]+):(?P<tag>[\w.-]+)")
FIELDS: Final = frozenset(("source", "digest", "mirror"))
CRANE: Final = "/usr/local/bin/crane"
USAGE: Final = "usage: image_mirror.py {sync|verify} MANIFEST"


@dataclass(frozen=True)
class CraneResult:
    """One crane invocation outcome."""

    returncode: int
    stdout: str
    stderr: str


Crane = Callable[[Sequence[str], bool], CraneResult]


@dataclass(frozen=True)
class MirrorImage:
    """One upstream image, pinned by digest, and where its mirror copy lives."""

    source: str
    digest: str
    mirror: str

    @property
    def repository(self) -> str:
        """Upstream repository without tag."""
        return self.source.rsplit(":", 1)[0]

    @property
    def tag(self) -> str:
        """Upstream tag recorded when the digest was pinned."""
        return self.source.rsplit(":", 1)[1]

    @property
    def source_ref(self) -> str:
        """Digest-only upstream ref; tags are never re-resolved."""
        return f"{self.repository}@{self.digest}"

    @property
    def mirror_tag_ref(self) -> str:
        """Human-readable mirror tag the copy is published under."""
        return f"{self.mirror}:{self.tag}"

    @property
    def pin(self) -> str:
        """The exact ref module code uses: mirror, tag, and digest."""
        return f"{self.mirror_tag_ref}@{self.digest}"

    @property
    def package_url(self) -> str:
        """GitHub package page that holds the visibility setting."""
        name = self.mirror.removeprefix(f"ghcr.io/{MIRROR_OWNER}/")
        return PACKAGE_URL + quote(name, safe="")


def load_manifest(text: str) -> tuple[MirrorImage, ...]:
    """Parse and validate the mirror manifest."""
    entries = json.loads(text).get("images")
    if not isinstance(entries, list):
        raise ValueError("manifest images must be a list")
    images = tuple(_image(entry) for entry in entries)
    pins = [image.mirror_tag_ref for image in images]
    if len(set(pins)) != len(pins):
        raise ValueError("duplicate mirror tag in manifest")
    return images


def _image(entry: object) -> MirrorImage:
    if not isinstance(entry, dict) or set(entry) != FIELDS:
        raise ValueError(f"entry fields must be exactly {sorted(FIELDS)}")
    image = MirrorImage(str(entry["source"]), str(entry["digest"]), str(entry["mirror"]))
    _validate(image)
    return image


def _validate(image: MirrorImage) -> None:
    if not DIGEST.fullmatch(image.digest):
        raise ValueError(f"{image.source}: digest must be sha256:<64 hex>")
    match = SOURCE.fullmatch(image.source)
    if match is None:
        raise ValueError(f"{image.source}: source needs a registry host and a tag")
    if image.mirror != f"{MIRROR_ROOT}/{match['repository']}":
        raise ValueError(f"{image.source}: mirror path must be {MIRROR_ROOT}/<upstream>")


def sync(images: Sequence[MirrorImage], crane: Crane) -> tuple[str, ...]:
    """Copy each image by digest and return every failed proof."""
    return tuple(failure for image in images for failure in _sync_one(image, crane))


def _sync_one(image: MirrorImage, crane: Crane) -> tuple[str, ...]:
    copied = crane(("copy", image.source_ref, image.mirror_tag_ref), False)
    if copied.returncode:
        return (f"{image.mirror_tag_ref}: copy failed: {copied.stderr}",)
    mismatch = _digest_mismatch(image.mirror_tag_ref, image.digest, crane, "digest lookup")
    if mismatch:
        return (mismatch,)
    public = crane(("manifest", f"{image.mirror}@{image.digest}"), True)
    if public.returncode:
        detail = f"not anonymously pullable; make public at {image.package_url}"
        return (f"{image.mirror_tag_ref}: {detail}",)
    return ()


def verify_upstream(images: Sequence[MirrorImage], crane: Crane) -> tuple[str, ...]:
    """Read-only check that every pinned upstream digest still resolves."""
    results = (
        _digest_mismatch(image.source_ref, image.digest, crane, "upstream digest lookup")
        for image in images
    )
    return tuple(result for result in results if result)


def _digest_mismatch(ref: str, expected: str, crane: Crane, label: str) -> str:
    resolved = crane(("digest", ref), False)
    if resolved.returncode:
        return f"{ref}: {label} failed: {resolved.stderr}"
    if resolved.stdout != expected:
        return f"{ref}: digest {resolved.stdout} != {expected}"
    return ""


def run_crane(args: Sequence[str], anonymous: bool) -> CraneResult:
    """Run crane; anonymous calls get an empty Docker config so no credential is sent."""
    with tempfile.TemporaryDirectory() as empty:
        env = dict(os.environ)
        if anonymous:
            env["DOCKER_CONFIG"] = empty
        done = subprocess.run(  # noqa: S603 - fixed binary, argv from the reviewed manifest
            [CRANE, *args], env=env, capture_output=True, text=True, check=False
        )
    return CraneResult(done.returncode, done.stdout.strip(), done.stderr.strip())


def main(argv: Sequence[str]) -> int:
    """Run ``sync`` (copy and prove) or ``verify`` (read-only upstream check)."""
    actions = {"sync": sync, "verify": verify_upstream}
    if len(argv) != 2 or argv[0] not in actions:  # noqa: PLR2004 - command plus manifest
        print(USAGE)
        return 2
    images = load_manifest(Path(argv[1]).read_text())
    failures = actions[argv[0]](images, run_crane)
    for failure in failures:
        print(f"FAIL {failure}")
    print(f"{len(images) - len(failures)}/{len(images)} images proven")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
