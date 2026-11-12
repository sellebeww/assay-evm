# Quickstart

You need Python 3.12 or newer and Docker. The first step downloads the pinned tools into a local
image, once; everything after that runs without network access.

## Install

From a clone (there is no PyPI release yet):

```sh
git clone https://github.com/sellebeww/assay-evm.git assay && cd assay
make install      # uv sync
make image        # builds the runner images from docker/runner/versions.lock
uv run assay doctor
```

After a release, `pipx install assay-evm` followed by `assay image build` does the same without a
clone (see [releasing](releasing.md)). `assay doctor` checks Docker, the image, the tool versions,
the platform and the disk, and prints a one-line fix for every problem.

## Verify a patch

```sh
uv run assay verify --base fixtures/reentrancy/single_function \
  --patch fixtures/reentrancy/single_function/patches/overfit.diff \
  --poc fixtures/reentrancy/single_function/poc --profile quick --bundle-out out/overfit
```

The command prints one verdict per oracle and the final verdict. For the `overfit` patch of this
fixture the expected result is `REJECTED` with the reason `variant_found`; for `good.diff` it is
`VERIFIED_WITHIN_BOUNDS` (the expectations are recorded in the fixture's `expected.json` and
checked in [the classification matrix](classification-matrix.md)). The exit code says the same:
0 verified, 1 rejected, 3 inconclusive (see [exit codes](cli.md#exit-codes)).

## Keep and share the evidence

```sh
uv run assay replay out/overfit                    # re-check the bundle offline
uv run assay report out/overfit --out report.html  # one HTML file, no JavaScript
uv run assay verify ... --json > report.json       # then open it in the report viewer
uv run assay verify ... --sarif verify.sarif       # for GitHub Code Scanning
```

## Use it in a pull request

```yaml
- uses: sellebeww/assay-evm@main
  with:
    poc-dir: poc
```

See [the GitHub Action](github-action.md). Never run it from `pull_request_target`.
