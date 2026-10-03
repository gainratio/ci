"""The GHCR mirror copies every pinned upstream image by digest and proves it."""

from __future__ import annotations

import ast
import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from ci import image_mirror
from ci.image_mirror import CraneResult, MirrorImage, load_manifest, main, sync, verify_upstream

ROOT = Path(__file__).parents[2]
MANIFEST = ROOT / "mirror" / "images.json"
DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64
IMAGE_REF = re.compile(r"(?:[a-z0-9.-]+/)*[a-z0-9._-]+(?::[\w.-]+)?@sha256:[0-9a-f]{64}")
SCANNED = (".dagger/src", "modules/*/.dagger/src", "tests/dagger/python_consumer/.dagger/src")


class FakeCrane:
    def __init__(self, digests: Mapping[str, str] | None = None, failing: str = "") -> None:
        self.calls: list[tuple[tuple[str, ...], bool]] = []
        self.digests = dict(digests or {})
        self.failing = failing

    def __call__(self, args: Sequence[str], anonymous: bool) -> CraneResult:
        self.calls.append((tuple(args), anonymous))
        if self.failing and self.failing in args:
            return CraneResult(returncode=1, stdout="", stderr="denied")
        return CraneResult(returncode=0, stdout=self.digests.get(args[-1], DIGEST), stderr="")


def _entry(**overrides: str) -> dict[str, str]:
    entry = {
        "source": "docker.io/library/python:3.13.14-slim",
        "digest": DIGEST,
        "mirror": "ghcr.io/hseshadr/mirror/docker.io/library/python",
    }
    return {**entry, **overrides}


def _manifest(*entries: dict[str, str]) -> str:
    return json.dumps({"images": list(entries)})


def _image() -> MirrorImage:
    return load_manifest(_manifest(_entry()))[0]


def test_should_derive_source_mirror_and_package_refs_from_one_entry() -> None:
    # Given one manifest entry
    image = _image()

    # Then the copy source is digest-only and the pin keeps the upstream tag for humans
    assert image.source_ref == f"docker.io/library/python@{DIGEST}"
    assert image.mirror_tag_ref == "ghcr.io/hseshadr/mirror/docker.io/library/python:3.13.14-slim"
    assert image.pin == f"{image.mirror_tag_ref}@{DIGEST}"
    assert image.package_url == (
        "https://github.com/users/hseshadr/packages/container/package/"
        "mirror%2Fdocker.io%2Flibrary%2Fpython"
    )


@pytest.mark.parametrize(
    ("override", "reason"),
    [
        ({"digest": "sha256:abc"}, "digest"),
        ({"digest": "sha512:" + "a" * 64}, "digest"),
        ({"source": "python:3.13.14-slim"}, "registry host"),
        ({"source": "docker.io/library/python"}, "tag"),
        ({"source": f"docker.io/library/python@{DIGEST}"}, "tag"),
        ({"mirror": "ghcr.io/hseshadr/mirror/python"}, "mirror path"),
        ({"mirror": "ghcr.io/someone/mirror/docker.io/library/python"}, "mirror path"),
    ],
)
def test_should_refuse_entries_that_break_the_digest_and_path_rules(
    override: dict[str, str], reason: str
) -> None:
    # Given an entry that would make the mirror ambiguous or mutable
    text = _manifest(_entry(**override))

    # Then loading fails and names the broken rule
    with pytest.raises(ValueError, match=reason):
        load_manifest(text)


def test_should_refuse_duplicate_mirror_tags_and_unknown_fields() -> None:
    # Given two entries that would publish the same mirror tag
    duplicate = _manifest(_entry(), _entry(digest=OTHER_DIGEST))
    extra = _manifest({**_entry(), "tag": "latest"})

    # Then neither manifest loads
    with pytest.raises(ValueError, match="duplicate"):
        load_manifest(duplicate)
    with pytest.raises(ValueError, match="fields"):
        load_manifest(extra)
    with pytest.raises(ValueError, match="images"):
        load_manifest(json.dumps({"images": "nope"}))


def test_should_copy_by_digest_then_verify_tag_and_anonymous_pull() -> None:
    # Given a mirror that serves the copied digest
    crane = FakeCrane()

    # When the mirror is synchronized
    failures = sync((_image(),), crane)

    # Then copy, digest check, and anonymous manifest fetch run in that order
    image = _image()
    assert failures == ()
    assert crane.calls == [
        (("copy", image.source_ref, image.mirror_tag_ref), False),
        (("digest", image.mirror_tag_ref), False),
        (("manifest", f"{image.mirror}@{DIGEST}"), True),
    ]


def test_should_report_digest_mismatch_without_checking_publicness() -> None:
    # Given a mirror tag that resolves to different bytes
    image = _image()
    crane = FakeCrane(digests={image.mirror_tag_ref: OTHER_DIGEST})

    # When the mirror is synchronized
    failures = sync((image,), crane)

    # Then the mismatch is named and the run fails
    assert failures == (f"{image.mirror_tag_ref}: digest {OTHER_DIGEST} != {DIGEST}",)
    assert len(crane.calls) == 2


def test_should_report_copy_failure_and_private_package_with_its_settings_url() -> None:
    # Given a failed copy, and separately a package that refuses anonymous pulls
    image = _image()
    copy_failed = sync((image,), FakeCrane(failing="copy"))
    private = sync((image,), FakeCrane(failing="manifest"))

    # Then each failure is reported, and the private one points at the visibility setting
    assert copy_failed == (f"{image.mirror_tag_ref}: copy failed: denied",)
    assert private == (
        f"{image.mirror_tag_ref}: not anonymously pullable; make public at {image.package_url}",
    )


def test_should_verify_every_upstream_digest_without_writing() -> None:
    # Given one upstream digest that exists and one that does not
    good = _image()
    bad = load_manifest(_manifest(_entry(digest=OTHER_DIGEST)))[0]
    crane = FakeCrane(failing=bad.source_ref)

    # When upstream pins are verified
    failures = verify_upstream((good, bad), crane)

    # Then only read-only digest lookups ran, and the missing digest is named
    assert failures == (f"{bad.source_ref}: upstream digest lookup failed: denied",)
    assert crane.calls == [
        (("digest", good.source_ref), False),
        (("digest", bad.source_ref), False),
    ]


def test_should_report_upstream_digest_that_resolves_elsewhere() -> None:
    # Given an upstream that answers with other bytes
    image = _image()
    crane = FakeCrane(digests={image.source_ref: OTHER_DIGEST})

    # Then the mismatch is a failure
    assert verify_upstream((image,), crane) == (
        f"{image.source_ref}: digest {OTHER_DIGEST} != {DIGEST}",
    )


def test_should_exit_by_failures_and_reject_unknown_commands(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # Given a manifest on disk and a crane that refuses everything
    manifest = tmp_path / "images.json"
    manifest.write_text(_manifest(_entry()))
    monkeypatch.setattr(image_mirror, "run_crane", FakeCrane(failing="digest"))

    # Then failing verification exits 1, a good sync exits 0, and bad usage exits 2
    assert main(["verify", str(manifest)]) == 1
    assert "upstream digest lookup failed" in capsys.readouterr().out
    monkeypatch.setattr(image_mirror, "run_crane", FakeCrane())
    assert main(["sync", str(manifest)]) == 0
    assert main(["publish", str(manifest)]) == 2
    assert main([]) == 2


def test_should_run_crane_anonymously_with_an_empty_docker_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Given a recorder in place of the subprocess boundary
    seen: list[tuple[list[str], str | None, bool]] = []

    def fake_run(command: list[str], **kwargs: object) -> object:
        env = kwargs["env"]
        assert isinstance(env, dict)
        config = env.get("DOCKER_CONFIG")
        empty = config is not None and not any(Path(config).iterdir())
        seen.append((command, config, empty))
        return subprocess.CompletedProcess(command, 0, "sha256:x\n", "")

    monkeypatch.setattr(subprocess, "run", fake_run)

    # When crane runs authenticated and anonymously
    authed = image_mirror.run_crane(("digest", "ref"), False)
    anonymous = image_mirror.run_crane(("manifest", "ref"), True)

    # Then output is trimmed and only the anonymous call swaps in an empty config dir
    assert authed == CraneResult(0, "sha256:x", "")
    assert anonymous.returncode == 0
    assert seen[0][0] == ["/usr/local/bin/crane", "digest", "ref"]
    assert seen[0][1] != seen[1][1]
    assert seen[1][2] is True


def test_should_load_the_committed_manifest_with_unique_digest_pins() -> None:
    # Given the committed manifest
    images = load_manifest(MANIFEST.read_text())

    # Then it covers the Dagger engine and the Python SDK base image
    sources = {image.source for image in images}
    assert "registry.dagger.io/engine:v0.21.8" in sources
    assert "docker.io/library/python:3.13.14-slim" in sources
    assert len({image.pin for image in images}) == len(images)


def test_should_mirror_every_image_pinned_by_central_and_shared_module_code() -> None:
    # Given every digest-pinned image ref in central, shared-module, and fixture source
    pinned = _pinned_refs()

    # When each ref is matched to a manifest entry by repository and digest
    images = load_manifest(MANIFEST.read_text())
    known = {_identity(image.source_ref) for image in images}
    known |= {_identity(image.pin) for image in images}
    missing = sorted(ref for ref in pinned if _identity(ref) not in known)

    # Then nothing pinned in code is absent from the mirror
    assert len(pinned) >= 10
    assert missing == []


def _pinned_refs() -> set[str]:
    refs: set[str] = set()
    for pattern in SCANNED:
        for path in ROOT.glob(f"{pattern}/**/*.py"):
            constants = ast.walk(ast.parse(path.read_text()))
            refs.update(
                node.value
                for node in constants
                if isinstance(node, ast.Constant)
                and isinstance(node.value, str)
                and IMAGE_REF.fullmatch(node.value)
            )
    return refs


def _identity(ref: str) -> tuple[str, str]:
    name, _, digest = ref.partition("@")
    repository = name.rsplit(":", 1)[0] if ":" in name.rsplit("/", 1)[-1] else name
    first = repository.split("/", 1)[0]
    if "." not in first:
        repository = f"docker.io/{repository}"
    if repository.count("/") == 1 and repository.startswith("docker.io/"):
        repository = repository.replace("docker.io/", "docker.io/library/", 1)
    return repository, digest
