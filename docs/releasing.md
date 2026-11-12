# Releasing

This page is the checklist for the first release and for every later one. Nothing in the
repository publishes by itself: the release workflow (`.github/workflows/release.yml`) runs only
for a tag, and it can publish only after the steps in "One-time setup" were done by the owner.

## One-time setup

1. On PyPI, create the project `assay-evm` or reserve the name with a *pending publisher*:
   Account settings, Publishing, add a GitHub publisher with owner `sellebeww`, repository
   `assay-evm`, workflow `release.yml` and environment `pypi`.
2. In the GitHub repository, Settings, Environments, create the environment `pypi`. Require a
   reviewer for it, so that a tag alone cannot publish.
3. Optionally do the same on TestPyPI with the environment `testpypi` (not wired in the workflow).

Trusted publishing uses a short-lived OpenID Connect token. There is no API token and no secret to
store, and the workflow must keep using none.

## Before a tag

1. Move the entries of `## [Unreleased]` in `CHANGELOG.md` under a new heading `## [X.Y.Z] - date`.
2. Set `__version__` in `src/assay/__init__.py` to `X.Y.Z` (the only place; hatch reads it).
3. Run `make check`, `make lint-actions`, and, with Docker and the image, `make test-integration`.
4. Build and look at the result: `uv build`, then `uvx twine check dist/*`. Install the wheel in
   a clean virtual environment and run `assay --version` and `assay image build --dry-run`.
5. Pin the Action in the examples (`docs/github-action.md`) to the new tag.

## Tagging

```sh
git tag -s vX.Y.Z -m "assay-evm X.Y.Z"
git push origin vX.Y.Z
```

The workflow checks that the tag equals `__version__`, runs `make check`, builds the sdist and
the wheel, checks their contents, installs the wheel in a clean environment and then publishes
with `uv publish --trusted-publishing always`. `workflow_dispatch` with `dry-run` true builds and
checks without publishing.

## GitHub Marketplace

`action.yml` carries the name, description and branding that the listing needs. Publishing it is a
manual step: after the tag exists, create a GitHub release from it and tick "Publish this Action to
the GitHub Marketplace". The listing requires a unique Action name and two-factor authentication
on the owner account.

## What a release does not change

A release does not change the verdict rules or the measured results. Regenerate the result pages
(`make bench-report` and the other `make` targets of the `docs/` pages) only when the oracles or
`versions.lock` changed, and say so in the changelog.
