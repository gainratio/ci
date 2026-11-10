# CLAUDE.md — Central Dagger CI & Fleet Policy (`gainratio/ci`)

- **Status**: Production control plane for `gainratio` repositories (10 consumer repos + `gainratio/ci`).
- **Stack**: Python `>=3.13`, Dagger `v0.21.8`, Pydantic `2.13.4` (`mypy` plugin, strict), `ruff`, `xenon`, `pytest` (`>=90%` branch coverage), `pip-audit`, `zizmor`, `actionlint`, `gitleaks`.
- **Consumers (`10`)**: `agentic-context-service`, `agentic-saga`, `agentic-tab-context`, `almamesh`, `aml-filter`, `assay`, `edge-proc`, `edge-reco`, `edgeproc-core`, `privacy-core`.

## Repository Layout

- `.dagger/src/ci/` — Central `ci` and `fleet` Dagger functions, GitHub API snapshot transport (`github_fleet.py`), policy engine (`fleet_policy.py`), uncovered-consumer discovery (`fleet_coverage.py`), and image-mirror verification.
- `modules/portfolio-foundation/` — Exact source binding (`source`), full-history `gitleaks`/`zizmor`/`actionlint` (`guard`), deterministic artifact envelopes (`envelope`, `verify-envelope`), `docs-only`, `green-main` / `green-main-decision`, and publisher lineage (`release-lineage`, `release-provenance`).
- `modules/cloudflare-pages/` — Fail-closed Cloudflare Pages deployment, preflight, and live alias verification.
- `modules/python-package/` — Frozen wheel/sdist candidate builder, tag/version identity verification, and locked dependency audit (no registry publishing credentials).
- `mirror/images.json` — Digest-pinned upstream-to-`ghcr.io/gainratio/mirror/...` container manifest.
- `tests/dagger/` — Isolated Python and TypeScript consumer composition fixtures.

## Core Invariants

1. **Immutable 40-hex SHA pins only**: Consumers install modules at exact 40-character lowercase commit SHAs (`source` suffix == `pin`), at or above `REQUIRED_MINIMUM` on `gainratio/ci` `main`.
2. **Thin GitHub Actions ingress**: Workflows only check out exact source and invoke Dagger (plus the narrow artifact-transport and source-free OIDC publisher exceptions enforced by `fleet_policy.py`).
3. **Fail-closed GitHub evidence**: Missing or unreadable source, branch protection, exact-SHA check runs, or owner repo listings produce failing findings (`evidence-unreadable`, `uncovered-consumer`), never silent skips.
4. **Zero publication authority in shared builders**: `python-package` never receives PyPI tokens or OIDC permissions; consumers publish in a separate source-free job gated by `release-lineage` / `release-provenance`.
5. **Mirrored digests everywhere**: Every container image pinned in workflows, modules, fixtures, or `[tool.dagger]` must resolve from `ghcr.io/gainratio/mirror/...` and match `mirror/images.json`.

## Scarred Quality Gates

- `.dagger/tests/test_readme_contract.py` & `test_python_package_contract.py` — Enforce cold-reader opening, section order, zero banned internal jargon in prose, link completeness across `docs/**/*.md`, and source-free PyPA publisher boundary docs.
- `.dagger/tests/test_mirror_contract.py` & `test_image_mirror.py` — Reject any unmirrored or non-`gainratio` container image reference.
- `.dagger/tests/test_fleet_*.py` — Pin branch protection, `dagger-for-github` expression injection bans (`dagger-args-expression`), publisher lineage ordering, minimum module SHA floors, and uncovered-consumer detection.
- Read-only `poe lint` (`ruff check` + `ruff format --check`), `mypy --strict` (`disallow_any_explicit = true`), `xenon A/A/A`, and `>= 90%` line + branch coverage across `.dagger` and all three `modules/*/.dagger` packages.

## Commands

```bash
# Central Dagger module gate
UV_PYTHON=3.13 uv run --directory .dagger poe gate

# Reusable module gates
UV_PYTHON=3.13 uv run --directory modules/portfolio-foundation/.dagger poe gate
UV_PYTHON=3.13 uv run --directory modules/cloudflare-pages/.dagger poe gate
UV_PYTHON=3.13 uv run --directory modules/python-package/.dagger poe gate

# Full containerized gate (matches CI)
export GITHUB_TOKEN="$(gh auth token)"
dagger call ci --github-token=env:GITHUB_TOKEN --repository=gainratio/ci
```

## Engineering Standard Applicability

- **Configuration**: Dagger functions accept explicit typed parameters and `dagger.Secret` handles (`GITHUB_TOKEN`, `CLOUDFLARE_API_TOKEN`); no implicit `.env` loading inside module code.
- **UI / Accessibility**: Not a user-facing web app; interactive architecture map lives in `docs/architecture/index.html`.
