"""Shared modules pull only from the GHCR mirror, by digest, including the SDK base image."""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

import yaml

from ci.image_mirror import load_manifest
from ci.main import MIRROR_BOOTSTRAP_IMAGE

ROOT = Path(__file__).parents[2]
IMAGES = load_manifest((ROOT / "mirror" / "images.json").read_text())
PINS = frozenset(image.pin for image in IMAGES)
IMAGE_REF = re.compile(r"(?:[a-z0-9.-]+/)*[a-z0-9._-]+(?::[\w.-]+)?@sha256:[0-9a-f]{64}")
SOURCES = (
    ".dagger/src",
    "modules/*/.dagger/src",
    "modules/*/.dagger/tests",
    "tests/dagger/python_consumer/.dagger/src",
)
PYTHON_MODULES = (
    ".dagger",
    "modules/cloudflare-pages/.dagger",
    "modules/portfolio-foundation/.dagger",
    "modules/python-package/.dagger",
    "tests/dagger/python_consumer/.dagger",
)
RUNNER_HOST = "_EXPERIMENTAL_DAGGER_RUNNER_HOST"
HASH_IDENTITY = "alpine@sha256:4bcff63911fcb4448bd4fdacec207030997caf25e9bea4045fa6c8c44de311d1"


def _pin(source: str) -> str:
    return next(image.pin for image in IMAGES if image.source == source)


def _image_constants() -> dict[str, str]:
    found: dict[str, str] = {}
    for pattern in SOURCES:
        for path in sorted(ROOT.glob(f"{pattern}/**/*.py")):
            for node in ast.walk(ast.parse(path.read_text())):
                value = node.value if isinstance(node, ast.Constant) else None
                if isinstance(value, str) and IMAGE_REF.fullmatch(value):
                    found[value] = str(path.relative_to(ROOT))
    return found


def test_should_pull_every_pinned_image_from_the_mirror_by_digest() -> None:
    # Given every digest-pinned image string in central, module, and fixture code
    constants = _image_constants()

    # When the refs are compared with the manifest's mirror pins
    outside = {ref: path for ref, path in constants.items() if ref not in PINS}

    # Then only two upstream refs remain: the mirror job's bootstrap image, which must not
    # depend on the mirror it repairs, and the hasher identity that evidence manifests record
    # (never pulled; the pull uses the mirror copy of the same digest)
    assert outside == {
        MIRROR_BOOTSTRAP_IMAGE: ".dagger/src/ci/main.py",
        HASH_IDENTITY: "modules/portfolio-foundation/.dagger/src/portfolio_foundation/source.py",
    }
    assert len(constants) >= 12


def test_should_pin_every_python_sdk_base_image_to_the_mirror() -> None:
    # Given every Python Dagger module in this repository
    expected = _pin("docker.io/library/python:3.13.14-slim")

    # When each module's [tool.dagger] table is read
    found = {
        path: tomllib.loads((ROOT / path / "pyproject.toml").read_text())
        .get("tool", {})
        .get("dagger", {})
        .get("base-image")
        for path in PYTHON_MODULES
    }

    # Then the SDK runtime never resolves an unpinned python:<ver>-slim from Docker Hub
    assert found == dict.fromkeys(PYTHON_MODULES, expected)


def test_should_start_central_dagger_engines_from_the_mirror() -> None:
    # Given every central workflow except the mirror job, which must not need the mirror
    expected = "image://" + _pin("registry.dagger.io/engine:v0.21.8")
    workflows = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
    steps = [
        step
        for path in workflows
        if path.name != "image-mirror.yml"
        for job in yaml.safe_load(path.read_text())["jobs"].values()
        for step in job["steps"]
        if str(step.get("uses", "")).startswith("dagger/dagger-for-github@")
    ]

    # Then every Dagger step provisions its engine from the digest-pinned mirror copy
    assert len(steps) >= 5
    assert {step.get("env", {}).get(RUNNER_HOST) for step in steps} == {expected}
