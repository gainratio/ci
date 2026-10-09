"""Fail-closed workflow and secret scanning."""

from __future__ import annotations

from typing import Final

import dagger
from dagger import dag

from .source import SourceBinding

ACTIONLINT_IMAGE: Final = (
    "ghcr.io/gainratio/mirror/docker.io/rhysd/actionlint:1.7.10@sha256:"
    "ef8299f97635c4c30e2298f48f30763ab782a4ad2c95b744649439a039421e36"
)
GITLEAKS_IMAGE: Final = (
    "ghcr.io/gainratio/mirror/ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:"
    "c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
)
ACTIONLINT_PATH: Final = "/usr/local/bin/actionlint"
CANARY_EXIT_CODE: Final = 86


SNAPSHOT_ROOT: Final = "/snapshot"


def actionlint_command(root: str = SNAPSHOT_ROOT) -> str:
    """Return the closed workflow-file validation program."""
    patterns = r"\( -name '*.yml' -o -name '*.yaml' \)"
    workflow_root = f"{root}/.github/workflows"
    return "\n".join(
        (
            f"test -d {workflow_root}",
            f'test -n "$(find {workflow_root} -type f {patterns} -print -quit)"',
            *_actionlint_config_commands(root),
            f'find {workflow_root} -type f {patterns} -exec actionlint "$@" {{}} +',
        )
    )


def _actionlint_config_commands(root: str) -> tuple[str, ...]:
    """Pass the consumer's actionlint config explicitly: the snapshot has no .git to find it."""
    yaml, yml = (f"{root}/.github/actionlint.{extension}" for extension in ("yaml", "yml"))
    return (
        "set --",
        f"if test -f {yaml}; then set -- -config-file {yaml};",
        f"elif test -f {yml}; then set -- -config-file {yml}; fi",
    )


def secret_scan_command(commit_sha: str) -> str:
    """Return the canary, explicit snapshot, and canonical-history scan."""
    return "\n".join(_canary_commands() + _snapshot_commands() + _history_commands(commit_sha))


def build_guard(
    binding: SourceBinding[dagger.Directory, dagger.Directory],
) -> dagger.Container:
    """Build the fixed guard from a verified full source binding."""
    snapshot = binding.source.without_directory(".git")
    base = _guard_container(snapshot, binding.history)
    checked = base.with_exec(["sh", "-ceu", actionlint_command()])
    return checked.with_exec(["sh", "-ceu", secret_scan_command(binding.identity.commit.value)])


def _guard_container(snapshot: dagger.Directory, history: dagger.Directory) -> dagger.Container:
    actionlint = dag.container().from_(ACTIONLINT_IMAGE).file(ACTIONLINT_PATH)
    base = dag.container().from_(GITLEAKS_IMAGE).with_entrypoint([])
    base = base.with_file(ACTIONLINT_PATH, actionlint)
    base = base.with_mounted_directory("/snapshot", snapshot, read_only=True)
    return base.with_mounted_directory("/repo", history, read_only=True)


def _canary_commands() -> tuple[str, ...]:
    return (
        'canary_dir="/tmp/canary"',
        'mkdir -p "$canary_dir"',
        'git init -q "$canary_dir"',
        "printf 'ghp_%s%s\\n' '0123456789abcdefAB' 'CDEFGHIJKLMNOPQRST' > \"$canary_dir/canary\"",
        "set +e",
        _gitleaks("$canary_dir", no_git=True, exit_code=CANARY_EXIT_CODE),
        'canary_status="$?"',
        "set -e",
        f'test "$canary_status" -eq {CANARY_EXIT_CODE}',
        "echo guard-canary-detected >&2",
    )


def _snapshot_commands() -> tuple[str, ...]:
    return (
        'test -n "$(find /snapshot -type f -print -quit)"',
        "echo guard-snapshot-nonempty >&2",
        *_configured_gitleaks("/snapshot", no_git=True),
    )


def _history_commands(commit_sha: str) -> tuple[str, ...]:
    return (
        "test -d /repo/.git",
        'test "$(git -C /repo rev-parse --is-shallow-repository)" = false',
        f'test "$(git -C /repo rev-parse HEAD)" = {commit_sha}',
        'test -n "$(git -C /repo rev-list --all)"',
        "git -C /repo fsck --full --no-dangling",
        "echo guard-history-verified >&2",
        *_configured_gitleaks("/repo", log_options="--all"),
    )


def _configured_gitleaks(
    source: str, *, no_git: bool = False, log_options: str | None = None
) -> tuple[str, ...]:
    config = f"{source}/.gitleaks.toml"
    configured = _gitleaks(source, no_git=no_git, log_options=log_options, config=config)
    default = _gitleaks(source, no_git=no_git, log_options=log_options)
    return (f"if test -f {config}; then", f"  {configured}", "else", f"  {default}", "fi")


def _gitleaks(
    source: str,
    *,
    no_git: bool = False,
    exit_code: int | None = None,
    log_options: str | None = None,
    config: str | None = None,
) -> str:
    options: tuple[str, ...] = ("gitleaks", "detect", "--source", source)
    options += _no_git_flag(no_git)
    options += _log_options_flag(log_options)
    options += _config_flag(config)
    options += ("--redact", "--no-banner")
    options += _exit_code_flag(exit_code)
    return " ".join(options)


def _no_git_flag(enabled: bool) -> tuple[str, ...]:
    if enabled:
        return ("--no-git",)
    return ()


def _log_options_flag(options: str | None) -> tuple[str, ...]:
    if options is not None:
        return (f"--log-opts={options}",)
    return ()


def _config_flag(path: str | None) -> tuple[str, ...]:
    if path is not None:
        return ("--config", path)
    return ()


def _exit_code_flag(exit_code: int | None) -> tuple[str, ...]:
    if exit_code is not None:
        return ("--exit-code", str(exit_code))
    return ()
