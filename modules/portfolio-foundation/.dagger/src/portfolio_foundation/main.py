"""Public Dagger API for reusable portfolio foundations."""

from __future__ import annotations

import dagger
from dagger import dag, function, object_type

from .artifact import (
    envelope_directory,
    parse_consumer_identity,
    parse_producing_identity,
    verify_envelope_directory,
)
from .github import CheckEvidence, resolve_green_main
from .guard import build_guard
from .identity import CommitIdentity, FullSha, RepositoryRef
from .lineage import LineageRequest, release_lineage, release_provenance
from .source import SourceBinding, bind_dagger_source, dagger_history

PROVENANCE_FILE = "github-context.json"


@object_type
class PortfolioFoundation:
    """Expose typed foundations for unprivileged portfolio operations."""

    @function
    async def source(
        self,
        source: dagger.Directory,
        repository: str,
        commit_sha: str,
        http_auth_header: dagger.Secret | None = None,
    ) -> dagger.Directory:
        """Bind a supplied workspace to a repository identity."""
        binding = await _source_binding(source, repository, commit_sha, http_auth_header)
        return binding.source

    @function
    async def guard(
        self,
        source: dagger.Directory,
        repository: str,
        commit_sha: str,
        http_auth_header: dagger.Secret | None = None,
    ) -> dagger.Container:
        """Apply repository security checks to a bound source."""
        binding = await _source_binding(source, repository, commit_sha, http_auth_header)
        return build_guard(binding)

    @function
    async def envelope(
        self,
        artifact: dagger.Directory,
        consumer_identity: str,
        producing_identity: str,
        allowed_roots: list[str],
    ) -> dagger.Directory:
        """Wrap a typed artifact with deterministic evidence."""
        identity = parse_consumer_identity(consumer_identity)
        module_sha, run_id = parse_producing_identity(producing_identity)
        return await envelope_directory(
            artifact, identity, module_sha, tuple(allowed_roots), run_id
        )

    @function
    async def verify_envelope(
        self,
        envelope: dagger.Directory,
        consumer_identity: str,
        producing_identity: str,
        allowed_roots: list[str],
    ) -> dagger.Directory:
        """Revalidate and return only a closed envelope's artifact subtree."""
        identity = parse_consumer_identity(consumer_identity)
        module_sha, run_id = parse_producing_identity(producing_identity)
        return await verify_envelope_directory(
            envelope, identity, module_sha, tuple(allowed_roots), run_id
        )

    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]  # SDK stub gap
    async def green_main(self, github_token: dagger.Secret, repository: str) -> CheckEvidence:
        """Resolve exact-green main evidence using a typed secret."""
        return await resolve_green_main(github_token, RepositoryRef.parse(repository))

    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]  # SDK stub gap
    async def release_lineage(
        self,
        github_token: dagger.Secret,
        repository: str,
        run_id: int,
        head_sha: str,
        publish_run_id: int,
    ) -> str:
        """Prove a release candidate run was built from main before anything publishes it."""
        request = LineageRequest.parse(repository, run_id, head_sha, publish_run_id)
        return await release_lineage(github_token, request)

    @function(cache="never")  # type: ignore[call-overload,untyped-decorator]  # SDK stub gap
    async def release_provenance(
        self,
        github_token: dagger.Secret,
        repository: str,
        run_id: int,
        head_sha: str,
        publish_run_id: int,
    ) -> dagger.File:
        """Prove lineage, then return npm's provenance context for the publish run."""
        request = LineageRequest.parse(repository, run_id, head_sha, publish_run_id)
        context = await release_provenance(github_token, request)
        return dag.directory().with_new_file(PROVENANCE_FILE, context).file(PROVENANCE_FILE)


async def _source_binding(
    source: dagger.Directory,
    repository: str,
    commit_sha: str,
    http_auth_header: dagger.Secret | None,
) -> SourceBinding[dagger.Directory, dagger.Directory]:
    identity = CommitIdentity(RepositoryRef.parse(repository), FullSha(commit_sha))
    history = dagger_history(identity, http_auth_header)
    return await bind_dagger_source(source, history, identity)
