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
CANARY_ROOT: Final = "/tmp/canary"  # noqa: S108 - scratch dir inside the throwaway guard container
SNAPSHOT_ROOT: Final = "/snapshot"
HISTORY_ROOT: Final = "/repo"
FOUNDATION_CONFIG_PATH: Final = "/etc/portfolio-foundation/gitleaks.toml"
STATELESS_GITHUB_RULE_ID: Final = "github-app-token-stateless"
# Used when a consumer ships no .gitleaks.toml: every upstream rule plus the GitHub token
# format gitleaks 8.30.1 cannot see yet (https://github.com/gitleaks/gitleaks/issues/2192).
FOUNDATION_GITLEAKS_CONFIG: Final = f"""title = "portfolio-foundation secret scan"

[extend]
useDefault = true

# GitHub App installation tokens and Actions GITHUB_TOKEN use a stateless
# ghs_<APPID>_<JWT> format (~520 chars, charset [A-Za-z0-9._-]) since 2026-10-02.
# The built-in github-app-token rule only matches the classic 36-char form, so this
# rule uses GitHub's documented pattern. Drop it once upstream covers the format.
[[rules]]
id = "{STATELESS_GITHUB_RULE_ID}"
description = "GitHub App installation or Actions token (stateless ghs_<APPID>_<JWT> format)"
regex = '''ghs_[A-Za-z0-9._-]{{36,}}'''
keywords = ["ghs_"]
"""
# Canary values are drawn from /dev/urandom at runtime: no detector-shaped literal is committed,
# and a rule narrowed to one fixed APPID or JWT cannot pass. The stateless one must not match
# the classic rule, so it proves the stateless rule loaded. Its shape follows GitHub's format:
# ghs_<APPID>_<header>.<claims>.<signature>, base64url JWT segments, about 520 chars in all.
CANARY_RANDOM: Final = (
    'canary_random() { LC_ALL=C tr -dc "$1" < /dev/urandom | head -c "$2"; }',
    "canary_byte() { od -An -N1 -tu1 /dev/urandom | tr -d ' '; }",
)
BASE64URL: Final = "A-Za-z0-9_-"
CANARY_PROBES: Final = (
    ("classic", ('canary_token="ghp_$(canary_random A-Za-z0-9 36)"',)),
    (
        "stateless",
        (
            'appid_digits="$(( $(canary_byte) % 6 + 3 ))"',
            'claims_length="$(( $(canary_byte) % 32 + 128 ))"',
            'canary_token="ghs_$(canary_random 1-9 1)$(canary_random 0-9 "$appid_digits")"',
            f'canary_token="${{canary_token}}_eyJ$(canary_random {BASE64URL} 33)"',
            f'canary_token="${{canary_token}}.eyJ$(canary_random {BASE64URL} "$claims_length")"',
            f'canary_token="${{canary_token}}.$(canary_random {BASE64URL} 342)"',
        ),
    ),
)
# A path allowlist by extension would hide real secrets while an extensionless canary passed,
# so every probe is written under each of these names and each one must be detected.
CANARY_FILE_NAMES: Final = ("canary.py", "canary.ts", "canary.txt", "canary.env", "canary")


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
    """Return the canaries, explicit snapshot scan, and canonical-history scan."""
    canaries = (canary_command(root) for root in (SNAPSHOT_ROOT, HISTORY_ROOT))
    scans = _snapshot_commands() + _history_commands(commit_sha)
    return "\n".join((*canaries, *scans))


def canary_command(root: str = SNAPSHOT_ROOT, canary_root: str = CANARY_ROOT) -> str:
    """Prove the exact config the real scan of ``root`` uses detects GitHub tokens.

    The selected path is kept in a per-root shell variable that the real scan then reads,
    so the canaried config and the scanned config cannot drift apart.
    """
    variable = scan_config_variable(root)
    probe_root = f"{canary_root}/{variable}"
    probes = (
        line for probe in CANARY_PROBES for line in _canary_probe(probe_root, variable, *probe)
    )
    select = _select_scan_config(root, variable)
    return "\n".join((*select, *CANARY_RANDOM, *probes, "echo guard-canary-detected >&2"))


def _select_scan_config(root: str, variable: str) -> tuple[str, ...]:
    config = f"{root}/.gitleaks.toml"
    return (
        f'{variable}="{FOUNDATION_CONFIG_PATH}"',
        f'if test -f {config}; then {variable}="{config}"; fi',
    )


def scan_config_variable(root: str) -> str:
    """Return the shell variable holding the gitleaks config selected for ``root``."""
    name = "".join(character if character.isalnum() else "_" for character in root.strip("/"))
    return f"scan_config_{name}"


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
    base = base.with_new_file(FOUNDATION_CONFIG_PATH, FOUNDATION_GITLEAKS_CONFIG)
    base = base.with_mounted_directory(SNAPSHOT_ROOT, snapshot, read_only=True)
    return base.with_mounted_directory(HISTORY_ROOT, history, read_only=True)


def _canary_probe(
    canary_root: str, variable: str, name: str, generate: tuple[str, ...]
) -> tuple[str, ...]:
    files = (
        line
        for file in CANARY_FILE_NAMES
        for line in _canary_file(canary_root, variable, name, file)
    )
    return (*generate, *files)


def _canary_file(canary_root: str, variable: str, name: str, file: str) -> tuple[str, ...]:
    probe = f"{canary_root}/{name}/{file.replace('.', '-')}"
    missed = f"guard-canary-missed: {name} GitHub token in {file} not detected by ${variable}"
    return (
        f'mkdir -p "{probe}"',
        f'git init -q "{probe}"',
        f'printf \'%s\\n\' "$canary_token" > "{probe}/{file}"',
        "set +e",
        _gitleaks(probe, no_git=True, exit_code=CANARY_EXIT_CODE, config=f'"${variable}"'),
        'canary_status="$?"',
        "set -e",
        f'test "$canary_status" -eq {CANARY_EXIT_CODE} || {{ echo "{missed}" >&2; exit 1; }}',
    )


def _snapshot_commands() -> tuple[str, ...]:
    return (
        'test -n "$(find /snapshot -type f -print -quit)"',
        "echo guard-snapshot-nonempty >&2",
        _gitleaks(SNAPSHOT_ROOT, no_git=True, config=_scan_config(SNAPSHOT_ROOT)),
    )


def _history_commands(commit_sha: str) -> tuple[str, ...]:
    return (
        "test -d /repo/.git",
        'test "$(git -C /repo rev-parse --is-shallow-repository)" = false',
        f'test "$(git -C /repo rev-parse HEAD)" = {commit_sha}',
        'test -n "$(git -C /repo rev-list --all)"',
        "git -C /repo fsck --full --no-dangling",
        "echo guard-history-verified >&2",
        _gitleaks(HISTORY_ROOT, log_options="--all", config=_scan_config(HISTORY_ROOT)),
    )


def _scan_config(root: str) -> str:
    return f'"${scan_config_variable(root)}"'


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
