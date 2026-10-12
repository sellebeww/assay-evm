# Contributing

Assay is in early development; the plan is in [docs/roadmap.md](docs/roadmap.md). For anything
larger than a small fix, open an issue first so that the approach can be agreed on.

## Setup

Requirements: [uv](https://docs.astral.sh/uv/), GNU Make, and Docker for the runner image.

```sh
make install      # create the environment and install dependencies
make check        # lint, type check, unit tests and docs-check; needs no Docker
make image        # build the runner image (Docker)
make image-check  # build and test the smoke project inside the image, offline
make test-integration  # tests that need Docker and the runner image (about half an hour)
make test-security     # sandbox security claims (docs/sandbox.md), needs the runner image
make fixtures-check    # fixture ground truth (docs/fixture-spec.md), needs the runner image
make demo              # offline demo of the whole flow (docs/demo.md); also make demo-overfit
make schemas           # rewrite docs/schemas/ after a change to a --json document
uv build               # sdist and wheel into dist/ (ignored by Git)
```

`make check` runs `make docs-check`, which fails on a broken relative link or heading anchor in
`README.md` and `docs/`, and on the words the project never uses for a result. Pages that a tool
writes (the classification matrix, variant search power, static coverage, symbolic checks) are
rebuilt by running their `make` target, never edited by hand. Golden files of the unit tests
(`tests/unit/golden/`, `tests/unit/snapshots/`) are rewritten with `ASSAY_UPDATE_GOLDEN=1` when a
change to them is intended; review the diff.

## Rules

- Every behavior change comes with tests. Tests, lint rules and type-checker settings are never
  weakened to make a build pass.
- `make check` must pass before a change is submitted.
- Decisions that deviate from an accepted ADR need a new ADR in [docs/adr/](docs/adr/).
- Pinned tool versions in `docker/runner/versions.lock` change only through an ADR.
- No secrets in the repository, test data or logs.
- A change to a prompt, to the scan output or to the oracle feedback can make the demo cassettes
  stale; `make demo-cassettes` records them again and the diff shows what changed.
- Fixtures follow [docs/fixture-spec.md](docs/fixture-spec.md). Their labels change only through
  human review.
- Output and documentation use the verdict vocabulary of the project (`VERIFIED_WITHIN_BOUNDS`,
  `REJECTED`, `INCONCLUSIVE`) and never describe code as secure or safe.

## Reporting security issues

Do not open public issues for vulnerabilities; follow [SECURITY.md](SECURITY.md).

## Code of conduct

Participation is governed by the [Code of Conduct](CODE_OF_CONDUCT.md).
