# Third-party notices

Assay's own code is under the [MIT license](LICENSE). Assay does not vendor third-party code: its
only runtime dependencies are Python packages, and the external tools it drives live in the runner
image, which is built from `docker/runner/` on the user's machine and is never distributed as a
built artifact (only the Dockerfile and the pinned inputs in `docker/runner/versions.lock` are
distributed).

This file records the licenses of those third-party components. Each license was read from the
component's own license file or packaging metadata at the pinned version, not from memory. The
sources are the release the version pins (for the tools) and the `dist-info` metadata inside the
built image (for the Python packages). To reproduce the Python list:

```sh
make image
make third-party-notices   # writes build/audit/python-licenses.json
```

## Copyleft summary (read this first)

Several tools in the runner image are under copyleft licenses. **This matters only if you
redistribute a built image or offer Assay to others as a network service; it does not affect
running Assay locally or using or modifying Assay's own MIT-licensed code.**

| Component | Version | License | Kind |
|---|---|---|---|
| Slither (`slither-analyzer`) | 0.11.6 | AGPL-3.0-only | strong + network copyleft |
| crytic-compile (Slither dependency) | 0.4.2 | AGPL-3.0-only | strong + network copyleft |
| Halmos | 0.3.3 | AGPL-3.0-only | strong + network copyleft |
| solc (Solidity compiler) | 0.8.36 | GPL-3.0-only | strong copyleft |
| Aderyn | 0.6.8 | GPL-3.0 | strong copyleft |
| certifi (transitive) | 2026.7.22 | MPL-2.0 | weak, file-level copyleft |

What this means in practice:

- **Running Assay locally does not trigger any copyleft obligation.** The GPL and AGPL tools are
  separate programs that Assay starts in a container; they are not linked into Assay and not
  modified. Assay runs them offline for the operator, not as a service offered to third parties
  over a network, so AGPL section 13 (offering the program to users of a network service) is not
  triggered by ordinary local use.
- **Assay does not distribute these tools.** The project distributes the Dockerfile and the pins;
  the user's `make image` downloads each tool from its own release. Distributing Assay's source
  therefore conveys no GPL or AGPL binary.
- **If you redistribute a built runner image**, you are conveying GPL-3.0 and AGPL-3.0 programs and
  must meet their terms, including offering their corresponding source. The project does not do
  this, and neither should a fork without reading those licenses.
- **If you offer Assay as a hosted or network service** that lets remote users interact with
  Slither, crytic-compile or Halmos, AGPL-3.0 section 13 requires you to offer those users the
  corresponding source of those tools. Assay ships no server and no network API; this applies only
  to a service someone else builds around it.
- **Assay's own license is unaffected.** Calling a separate GPL/AGPL program through a process
  boundary does not place Assay's code under those licenses. Assay stays MIT.
- The `license = "MIT"` field in Aderyn's `Cargo.toml` at this tag contradicts its own `LICENSE`
  file and README, which state GPL-3.0; the authoritative `LICENSE` file governs, so Aderyn is
  recorded here as GPL-3.0.

## Tools in the runner image

| Component | Version | License | Where read |
|---|---|---|---|
| Foundry (`forge`) | v1.8.4 | Apache-2.0 OR MIT | `LICENSE-APACHE`, `LICENSE-MIT` of the `v1.8.4` release |
| solc | 0.8.36 | GPL-3.0-only | `LICENSE.txt` of the `v0.8.36` tag |
| forge-std | v1.17.0 | Apache-2.0 OR MIT | `LICENSE-APACHE`, `LICENSE-MIT` copied into the image |
| Slither | 0.11.6 | AGPL-3.0-only | `slither_analyzer` wheel metadata |
| Aderyn | 0.6.8 | GPL-3.0 | `LICENSE` of the `aderyn-v0.6.8` tag |
| Halmos | 0.3.3 | AGPL-3.0-only | `halmos` wheel metadata |
| z3 (`z3-solver`) | 4.12.6.0 | MIT | `z3_solver` wheel metadata |
| CPython | 3.12.15 | PSF-2.0 | `LICENSE.txt` in the python-build-standalone build |
| Debian runtime libraries (glibc, libcap, libcrypt, libgcc, libstdc++, libudev) | trixie (13) | mixed: LGPL-2.1+, GPL-2+ with runtime exceptions, BSD, PSF | Debian `trixie-slim` base, pinned by digest |

The base image is pinned by index digest in `versions.lock`. Only the shared libraries that the
pinned tools link against are copied into the runtime image (the C runtime and a handful of
`lib*.so` files); no shell, package manager or other Debian program is included.

## Python runtime dependencies of Assay

Assay's own runtime dependencies (installed with `make install`, not part of the image) are:

| Package | License |
|---|---|
| typer | MIT |
| pydantic | MIT |
| rich | MIT |
| httpx | BSD-3-Clause |

All four are permissive. The development dependencies (ruff, mypy, pytest and others) are not
distributed and are all permissive.

## Python packages inside the runner images

The runner image (for Slither) and the symbolic runner image (for Halmos) bundle 58 Python
packages in total, pinned by sha256 in `docker/runner/slither-requirements.txt` and
`docker/runner/halmos-requirements.txt`. Their licenses, by family:

| License family | Count | Notes |
|---|---|---|
| MIT | many | permissive |
| BSD (2- and 3-clause) | several | permissive |
| Apache-2.0 | several | permissive |
| PSF-2.0 | typing-extensions, CPython | permissive |
| Public Domain / CC0 | safe-pysha3 (Keccak part) | permissive |
| MPL-2.0 | certifi | weak, file-level copyleft |
| AGPL-3.0-only | slither-analyzer, crytic-compile, halmos | the tools themselves (above) |

The full machine-readable list, with each package's version and license, is written to
`build/audit/python-licenses.json` by `make third-party-notices`.

## No vulnerabilities at the pinned versions

At the time of the audit, `pip-audit` reported no known vulnerabilities in Assay's dependencies or
in the Python packages pinned for the images, and an image scan found no vulnerabilities in the
Python or Node layers. The Debian base carries unpatched advisories in its libraries; these and
the scanner used are recorded in [the audit](docs/audit.md).
