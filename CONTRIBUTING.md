# Contributing to `gainratio/ci`

This repository maintains the shared Dagger modules (`portfolio-foundation`, `cloudflare-pages`, `python-package`) and the daily `fleet` policy verifier for `gainratio` repositories. Read [docs/GETTING_STARTED.md](docs/GETTING_STARTED.md) and [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) before making changes.

## Prerequisites

- **Python**: `3.13` and [`uv`](https://docs.astral.sh/uv/)
- **Docker** and **[Dagger `0.21.8`](https://docs.dagger.io/install)**

## Local Quality Gates

`poe lint` is strictly read-only (`ruff check` and `ruff format --check`) so formatting drift fails fast instead of mutating the checkout silently. Run the central gate and every affected module's gate:

```bash
dagger develop
UV_PYTHON=3.13 uv run --directory .dagger poe gate
UV_PYTHON=3.13 uv run --directory modules/portfolio-foundation/.dagger poe gate
UV_PYTHON=3.13 uv run --directory modules/cloudflare-pages/.dagger poe gate
UV_PYTHON=3.13 uv run --directory modules/python-package/.dagger poe gate
```

To run the full containerized gate identical to GitHub Actions:

```bash
export GITHUB_TOKEN="$(gh auth token)"
dagger call ci --github-token=env:GITHUB_TOKEN --repository=gainratio/ci --commit-sha="$(git rev-parse HEAD)"
```

## Key Rules

1. **Pin images via `mirror/images.json`**: Never reference unmirrored upstream tags; every container image must use its `ghcr.io/gainratio/mirror/...` digest and appear in `mirror/images.json`.
2. **Preserve closed module schemas**: Public `@function` signatures on `portfolio-foundation`, `cloudflare-pages`, and `python-package` are guarded by AST schema tests (`test_public_schema.py`, `test_python_package_contract.py`) — never add generic shell/image/tag escape hatches.
3. **Raise `REQUIRED_MINIMUM` when shipping mandatory security fixes**: Update `.dagger/src/ci/fleet_policy.py`, `.dagger/tests/test_fleet_minimum_pin.py`, and `docs/dagger-modules.md` together, then bump consumers via PR.
4. **Security issues**: Report vulnerabilities privately per [SECURITY.md](SECURITY.md).
