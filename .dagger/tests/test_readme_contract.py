from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).parents[2]
README = ROOT / "README.md"

SECTIONS = (
    "## How a repo uses it",
    "## Try it",
    "## How it works",
    "## What it does not do",
    "## Develop",
    "## More detail",
    "## License",
)
MODULES = ("portfolio-foundation", "cloudflare-pages", "python-package")
BANNED = (
    "northstar",
    "seam",
    "lego",
    "trust envelope",
    "fail-closed",
    "fail closed",
    "fleet",
    "gate",
    "portfolio",
    "production-ready",
    "robust",
    "blazing",
    "enterprise-grade",
    "seamless",
    "tl;dr",
)


def _prose(text: str) -> str:
    without_blocks = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
    without_code = re.sub(r"`[^`]*`", "", without_blocks)
    return re.sub(r"\]\([^)]*\)", "]", without_code).lower()


def test_should_open_with_name_and_plain_audience_sentence() -> None:
    # Given the repository landing page
    lines = README.read_text().splitlines()

    # When a reader sees only the first three lines
    title, blank, sentence = lines[0], lines[1], lines[2]

    # Then it names the repo and says plainly who it is for and what it holds
    assert title == "# hseshadr/ci"
    assert blank == ""
    assert "Harish Seshadri's own repositories" in sentence
    assert "Dagger modules" in sentence


def test_should_keep_sections_in_the_agreed_order() -> None:
    # Given the landing page headings
    text = README.read_text()

    # When the required sections are located
    positions = [text.find(heading + "\n") for heading in SECTIONS]

    # Then every section exists, in order, with technical links above the first one
    assert all(position >= 0 for position in positions)
    assert positions == sorted(positions)
    assert 0 <= text.find("**Technical docs:**") < positions[0]


def test_should_state_true_facts_about_modules_and_checks() -> None:
    # Given the landing page
    text = README.read_text()

    # When the reader looks for what the repo ships and how to run it
    required = (*MODULES, "dagger call ci", "Dagger 0.21.8", "dagger.json", '"pin"')

    # Then every shared module and the real local command are named
    assert all(fragment in text for fragment in required)


def test_should_link_every_technical_document() -> None:
    # Given every document under docs/ plus the changelog
    text = README.read_text()
    documents = sorted(path.relative_to(ROOT).as_posix() for path in ROOT.glob("docs/**/*.md"))

    # When the README link targets are collected
    targets = set(re.findall(r"\]\(([^)#]+)", text))

    # Then nothing technical is orphaned
    expected = {*documents, "docs/architecture/index.html", "CHANGELOG.md", "LICENSE"}
    assert "docs/ARCHITECTURE.md" in documents
    assert "docs/GETTING_STARTED.md" in documents
    assert expected <= targets


def test_should_avoid_internal_jargon_and_hype_in_prose() -> None:
    # Given the README with code and link targets removed
    prose = _prose(README.read_text())

    # When banned vocabulary is searched as whole words
    found = [word for word in BANNED if re.search(rf"\b{re.escape(word)}s?\b", prose)]

    # Then the prose reads as plain English
    assert found == []
