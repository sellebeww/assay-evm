# ADR 0021: Preparing the sandbox image in the GitHub Action

- Status: Accepted
- Date: 2026-10-12

## Context

The Action (`action.yml`) has to run `assay ci verify` on a hosted runner, and every oracle runs
inside the runner image `assay-runner:dev`. A hosted runner has Docker and no such image. The image
is not published: its parts carry licenses that are not reviewed for redistribution, and
`docs/roadmap.md` keeps a built image out of the release. The Action therefore has to build it from
`docker/runner/Dockerfile` and `docker/runner/versions.lock`, and the build downloads about a
hundred megabytes of pinned archives, so doing it from scratch on every pull request is slow.

Options considered:

1. Pull a published image. Rejected: there is none, and an image pulled by tag would take its
   contents from outside the repository's pins.
2. `make image` on the runner. It works, but it caches nothing between runs and needs `make` and a
   checkout of the Action's source with its Makefile, which a user of the Action does not have as
   the working directory.
3. Docker Buildx with the GitHub Actions cache (`docker/setup-buildx-action` and
   `docker/build-push-action` with `cache-from` and `cache-to` of type `gha`), building from the
   Action's own directory.

## Decision

Option 3.

- The Dockerfile and `versions.lock` are taken from `github.action_path`, never from the project
  of the pull request. Every `KEY=VALUE` line of `versions.lock` is passed as a build argument, as
  the Makefile does, so the file remains the single source of truth for the image.
- The image is tagged `assay-runner:dev`, the name the sandbox runner uses by default, and loaded
  into the local Docker daemon (`load: true`, `push: false`). Nothing is pushed anywhere.
- The layer cache is the GitHub Actions cache, in a scope per image (`assay-runner`,
  `assay-runner-symbolic`). The cache only speeds up the build: the Dockerfile verifies the sha256
  of every download, so a poisoned or stale cache entry cannot change what is installed without
  the checksum failing. A cache that is missing or cannot be written (for example for some pull
  requests from forks) makes the build slower, not different.
- The symbolic image (`runner-symbolic`, linux/amd64 only, ADR 0018) is built only when the input
  `symbolic` is `true`.
- Third-party Actions used for this (Buildx setup and the build step) are pinned to full commit
  SHAs with a version comment, like every other Action of the repository.

## Consequences

- The first run on a repository builds the whole image (several minutes); later runs reuse the
  cache. The GitHub Actions cache is limited in size and evicts old entries, so a repository with
  little activity may rebuild now and then.
- The image is built on every run from pinned inputs, so two runs of the same Action version run
  the same tools. `assay replay` records the image id in the bundle (ADR 0013); ids differ between
  builds, as in ADR 0020, so a replay elsewhere compares the pinned tool versions.
- Hosted runners with Docker are required. Windows and macOS runners are not supported.
- Docker is the only privilege the Action needs beyond reading the repository. The sandbox
  policy of `docs/sandbox.md` applies unchanged inside the runner's Docker daemon.
