# Security Policy

`gainratio/ci` is the shared CI control plane for the public `gainratio` repositories. It
holds no application data, but it does read repository state with a GitHub token, builds
artifacts, and pushes OCI images to GHCR. A bypass of its source guard, secret scan, or
release-lineage checks affects every consumer.

## Reporting a vulnerability

Please do not open a public issue, pull request, or discussion for a security
vulnerability. Report it privately to:

> **harish.seshadri@gmail.com**

Include the affected workflow or module, the commit, the impact on a consumer repository,
and a minimal reproduction if you have one. You can expect an acknowledgement within a few
days.

## Scope

In scope:

- A way to make `guard` accept a workspace that is not the claimed commit, or to make the
  generated envelope describe different bytes than the artifact.
- A way to make the full-history secret scan miss a credential, or to make a canary pass
  without being detected.
- A way to make `fleet` report green for a repository that is not green, or to skip a
  repository that pins a module from here.
- A workflow injection, expression injection, or permission escalation in
  `.github/workflows/`.

Out of scope: findings in a consumer repository's own code (report those to that
repository), and the design choice that consumers pin this repository at a commit SHA.

## Supported versions

Consumers pin an exact commit; fixes land on `main` and consumers upgrade by changing the
pin. There is no supported-version table because there are no floating releases.
