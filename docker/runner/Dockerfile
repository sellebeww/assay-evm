# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
# check=skip=InvalidDefaultArgInFrom

# Runner image for Assay: forge, solc, forge-std and the static analyzers Slither
# and Aderyn, pinned for offline and deterministic runs. All values come from
# docker/runner/versions.lock through build arguments. None has a default, so a
# build without them fails; this is why the InvalidDefaultArgInFrom check is
# skipped above. Build with `make image`.
#
# Two targets: `runner` (the image of every oracle and analyzer, for the native
# platform) and `runner-symbolic` (the same image plus Halmos and its solver,
# for linux/amd64 only; ADR 0018).

ARG BASE_IMAGE
ARG TARGETARCH

# ---------------------------------------------------------------------------
# Downloads. ADD --checksum verifies every file before it is used; a mismatch
# aborts the build. Only the stage for the target architecture is built.
# ---------------------------------------------------------------------------

FROM scratch AS downloads-amd64
ARG FOUNDRY_VERSION
ARG FOUNDRY_SHA256_LINUX_AMD64
ARG SOLC_BUILD
ARG SOLC_SHA256_LINUX_AMD64
ARG PYTHON_VERSION
ARG PYTHON_BUILD_RELEASE
ARG PYTHON_SHA256_LINUX_AMD64
ARG ADERYN_VERSION
ARG ADERYN_SHA256_LINUX_AMD64
ADD --checksum=sha256:${FOUNDRY_SHA256_LINUX_AMD64} \
    https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_linux_amd64.tar.gz \
    /foundry.tar.gz
ADD --checksum=sha256:${SOLC_SHA256_LINUX_AMD64} \
    https://binaries.soliditylang.org/linux-amd64/solc-linux-amd64-${SOLC_BUILD} \
    /solc
ADD --checksum=sha256:${PYTHON_SHA256_LINUX_AMD64} \
    https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_BUILD_RELEASE}/cpython-${PYTHON_VERSION}%2B${PYTHON_BUILD_RELEASE}-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz \
    /python.tar.gz
ADD --checksum=sha256:${ADERYN_SHA256_LINUX_AMD64} \
    https://github.com/Cyfrin/aderyn/releases/download/aderyn-${ADERYN_VERSION}/aderyn-x86_64-unknown-linux-gnu.tar.xz \
    /aderyn.tar.xz

FROM scratch AS downloads-arm64
ARG FOUNDRY_VERSION
ARG FOUNDRY_SHA256_LINUX_ARM64
ARG SOLC_BUILD
ARG SOLC_SHA256_LINUX_ARM64
ARG PYTHON_VERSION
ARG PYTHON_BUILD_RELEASE
ARG PYTHON_SHA256_LINUX_ARM64
ARG ADERYN_VERSION
ARG ADERYN_SHA256_LINUX_ARM64
ADD --checksum=sha256:${FOUNDRY_SHA256_LINUX_ARM64} \
    https://github.com/foundry-rs/foundry/releases/download/${FOUNDRY_VERSION}/foundry_${FOUNDRY_VERSION}_linux_arm64.tar.gz \
    /foundry.tar.gz
ADD --checksum=sha256:${SOLC_SHA256_LINUX_ARM64} \
    https://binaries.soliditylang.org/linux-arm64/solc-linux-arm64-${SOLC_BUILD} \
    /solc
ADD --checksum=sha256:${PYTHON_SHA256_LINUX_ARM64} \
    https://github.com/astral-sh/python-build-standalone/releases/download/${PYTHON_BUILD_RELEASE}/cpython-${PYTHON_VERSION}%2B${PYTHON_BUILD_RELEASE}-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz \
    /python.tar.gz
ADD --checksum=sha256:${ADERYN_SHA256_LINUX_ARM64} \
    https://github.com/Cyfrin/aderyn/releases/download/aderyn-${ADERYN_VERSION}/aderyn-aarch64-unknown-linux-gnu.tar.xz \
    /aderyn.tar.xz

FROM downloads-${TARGETARCH} AS downloads

FROM scratch AS forge-std-download
ARG FORGE_STD_COMMIT
ARG FORGE_STD_SHA256
ADD --checksum=sha256:${FORGE_STD_SHA256} \
    https://codeload.github.com/foundry-rs/forge-std/tar.gz/${FORGE_STD_COMMIT} \
    /forge-std.tar.gz

# ---------------------------------------------------------------------------
# Python and Slither, built in /opt/assay with the pinned Python. pip runs only
# here, at build time: it installs the wheels listed in slither-requirements.txt,
# each verified by sha256, without resolving dependencies and without building
# anything from source. A long timeout and retries keep a slow connection (for
# example in an emulated build) from failing the build; a truncated download fails
# its sha256. pip itself does not reach the runtime image. The Aderyn archive is
# unpacked here too, because the base image has no xz program.
# ---------------------------------------------------------------------------

FROM ${BASE_IMAGE} AS analyzers
ARG SLITHER_REQUIREMENTS_SHA256
COPY --from=downloads /python.tar.gz /aderyn.tar.xz /in/
COPY slither-requirements.txt /in/
COPY solc_select/ /in/solc_select/
RUN set -eu; \
    echo "${SLITHER_REQUIREMENTS_SHA256}  /in/slither-requirements.txt" | sha256sum -c -; \
    mkdir -p /opt/assay /in/aderyn; \
    tar -xzf /in/python.tar.gz -C /opt/assay; \
    python=/opt/assay/python/bin/python3; \
    "$python" -c 'import sys, tarfile; tarfile.open(sys.argv[1]).extractall(sys.argv[2], filter="data")' \
        /in/aderyn.tar.xz /in/aderyn; \
    install -m 0755 /in/aderyn/aderyn-*/aderyn /opt/assay/aderyn; \
    "$python" -m venv /opt/assay/slither; \
    /opt/assay/slither/bin/python -m pip install --no-cache-dir --disable-pip-version-check \
        --timeout 120 --retries 10 \
        --require-hashes --no-deps --only-binary :all: -r /in/slither-requirements.txt; \
    /opt/assay/slither/bin/python -m pip uninstall --yes --disable-pip-version-check pip; \
    site="$(/opt/assay/slither/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; \
    stdlib="$("$python" -c 'import sysconfig; print(sysconfig.get_paths()["stdlib"])')"; \
    cp -R /in/solc_select "$site/solc_select"; \
    # No package manager, GUI toolkit or bundled test suite in the runtime image.
    rm -rf /opt/assay/python/bin/pip* /opt/assay/python/bin/idle* /opt/assay/python/bin/pydoc* \
        /opt/assay/python/bin/2to3* "$stdlib/ensurepip" "$stdlib/idlelib" "$stdlib/tkinter" \
        "$stdlib/turtledemo" "$stdlib/test" "$stdlib"/lib-dynload/_tkinter* \
        "$stdlib"/site-packages/*; \
    # Byte code compiled now, since the runtime filesystem is read-only.
    "$python" -m compileall -q -j 0 --invalidation-mode unchecked-hash "$stdlib" "$site"; \
    /opt/assay/slither/bin/slither --version; \
    /opt/assay/aderyn --version

# ---------------------------------------------------------------------------
# Assemble the runtime filesystem in /rootfs, using only the tools of the
# pinned base image (no package installation).
# ---------------------------------------------------------------------------

FROM ${BASE_IMAGE} AS rootfs
ARG FORGE_STD_COMMIT
ARG SOLC_VERSION
COPY --from=downloads /foundry.tar.gz /solc /in/
COPY --from=forge-std-download /forge-std.tar.gz /in/
COPY --from=analyzers /opt/assay/python /rootfs/opt/assay/python
COPY --from=analyzers /opt/assay/slither /rootfs/opt/assay/slither
COPY --from=analyzers /opt/assay/aderyn /rootfs/usr/local/bin/aderyn
RUN set -eu; \
    mkdir -p /in/foundry /rootfs/usr/local/bin /rootfs/opt/assay/bin \
        /rootfs/opt/assay/lib/forge-std /rootfs/etc /rootfs/tmp /rootfs/work; \
    chmod 1777 /rootfs/tmp; \
    chmod 0755 /rootfs/work; \
    tar -xzf /in/foundry.tar.gz -C /in/foundry; \
    install -m 0755 /in/foundry/forge /rootfs/usr/local/bin/forge; \
    install -m 0755 /in/solc /rootfs/opt/assay/bin/solc; \
    # Aderyn looks up compilers in the data directory of svm-rs and downloads a
    # missing one. The pinned solc is registered there as the one installed
    # version, read-only, so the lookup succeeds offline (ADR 0015).
    mkdir -p "/rootfs/opt/assay/share/svm/${SOLC_VERSION}"; \
    ln -s /opt/assay/bin/solc "/rootfs/opt/assay/share/svm/${SOLC_VERSION}/solc-${SOLC_VERSION}"; \
    ln -s /opt/assay/slither/bin/slither /rootfs/usr/local/bin/slither; \
    tar -xzf /in/forge-std.tar.gz -C /rootfs/opt/assay/lib/forge-std --strip-components=1 \
        "forge-std-${FORGE_STD_COMMIT}/src" \
        "forge-std-${FORGE_STD_COMMIT}/LICENSE-APACHE" \
        "forge-std-${FORGE_STD_COMMIT}/LICENSE-MIT" \
        "forge-std-${FORGE_STD_COMMIT}/package.json"; \
    chmod -R a+rX,go-w /rootfs/opt/assay/lib/forge-std; \
    # Shared libraries and dynamic loader of forge, Aderyn, Python and every
    # extension module, copied from the base image with their paths (solc is a
    # static binary). Libraries that a wheel bundles under /rootfs stay where they
    # are. The loader cache resolves the multiarch paths.
    find /rootfs/usr/local/bin /rootfs/opt/assay/python /rootfs/opt/assay/slither \
            -type f \( -perm -u+x -o -name '*.so' -o -name '*.so.*' \) \
        | while read -r file; do ldd "$file" 2>/dev/null || true; done \
        | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }' \
        | sort -u \
        | while read -r lib; do \
            case "$lib" in /rootfs/*) ;; *) cp -L --parents "$lib" /rootfs ;; esac; \
        done; \
    cp /etc/ld.so.cache /rootfs/etc/ld.so.cache; \
    # Users written directly; useradd would record the build date in /etc/shadow.
    printf 'root:x:0:0:root:/nonexistent:/nonexistent\nassay:x:10001:10001::/nonexistent:/nonexistent\n' \
        > /rootfs/etc/passwd; \
    printf 'root:x:0:\nassay:x:10001:\n' > /rootfs/etc/group; \
    # The runtime filesystem must contain no set-uid or set-gid file.
    test -z "$(find /rootfs -perm /6000)"

# ---------------------------------------------------------------------------
# Runtime image: no shell and no package manager. Its one interpreter is the
# Python that runs Slither (ADR 0015).
# ---------------------------------------------------------------------------

FROM scratch AS runner
ARG FOUNDRY_VERSION
ARG SOLC_VERSION
ARG FORGE_STD_VERSION
ARG PYTHON_VERSION
ARG SLITHER_VERSION
ARG ADERYN_VERSION

COPY --from=rootfs /rootfs/ /

# Foundry settings that hold for every run in this image. These environment
# values take precedence over a project's foundry.toml. Foundry ignores the
# environment for `ffi` and `fs_permissions`; those are enforced by rewriting
# foundry.toml before a run (see docs/sandbox.md).
ENV FOUNDRY_OFFLINE=true \
    FOUNDRY_SOLC=/opt/assay/bin/solc \
    HOME=/tmp \
    NO_COLOR=1
# Python settings for Slither: no byte code written at run time, no user site
# directory, neither the working directory nor the script directory on the
# module path (a project cannot shadow a module), and a fixed hash seed so that
# the order of Slither's results repeats.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONNOUSERSITE=1 \
    PYTHONSAFEPATH=1 \
    PYTHONHASHSEED=0
# Aderyn's compiler lookup (svm-rs) reads its installed versions from
# $XDG_DATA_HOME/svm when $HOME/.svm does not exist (HOME is the empty /tmp);
# there it finds only the pinned solc (ADR 0015).
ENV XDG_DATA_HOME=/opt/assay/share

LABEL org.opencontainers.image.title="assay-runner" \
      org.opencontainers.image.description="Offline Foundry and static-analysis runner for Assay" \
      assay.foundry.version="${FOUNDRY_VERSION}" \
      assay.solc.version="${SOLC_VERSION}" \
      assay.forge-std.version="${FORGE_STD_VERSION}" \
      assay.python.version="${PYTHON_VERSION}" \
      assay.slither.version="${SLITHER_VERSION}" \
      assay.aderyn.version="${ADERYN_VERSION}"

USER 10001:10001
WORKDIR /work
CMD ["forge", "--version"]

# ---------------------------------------------------------------------------
# Halmos and its solver, in /opt/assay/halmos, a virtual environment of the
# pinned Python. The pinned z3-solver wheel (the Python binding Halmos builds its
# queries with, and the `z3` binary that answers them) exists for linux/amd64
# only, so this stage refuses any other platform (ADR 0018). pip runs only here,
# as for Slither: wheels listed in halmos-requirements.txt, each verified by
# sha256, no dependency resolution, no source builds.
# ---------------------------------------------------------------------------

FROM ${BASE_IMAGE} AS halmos
ARG TARGETARCH
ARG HALMOS_REQUIREMENTS_SHA256
COPY --from=downloads /python.tar.gz /in/
COPY halmos-requirements.txt /in/
RUN set -eu; \
    if [ "${TARGETARCH}" != "amd64" ]; then \
        echo "error: Halmos is built for linux/amd64 only (ADR 0018)" >&2; exit 1; \
    fi; \
    echo "${HALMOS_REQUIREMENTS_SHA256}  /in/halmos-requirements.txt" | sha256sum -c -; \
    mkdir -p /opt/assay /rootfs/opt/assay /rootfs/usr/local/bin; \
    tar -xzf /in/python.tar.gz -C /opt/assay; \
    /opt/assay/python/bin/python3 -m venv /opt/assay/halmos; \
    /opt/assay/halmos/bin/python -m pip install --no-cache-dir --disable-pip-version-check \
        --timeout 120 --retries 10 \
        --require-hashes --no-deps --only-binary :all: -r /in/halmos-requirements.txt; \
    /opt/assay/halmos/bin/python -m pip uninstall --yes --disable-pip-version-check pip; \
    site="$(/opt/assay/halmos/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"; \
    "/opt/assay/halmos/bin/python" -m compileall -q -j 0 --invalidation-mode unchecked-hash "$site"; \
    /opt/assay/halmos/bin/halmos --version; \
    /opt/assay/halmos/bin/z3 --version; \
    cp -a /opt/assay/halmos /rootfs/opt/assay/halmos; \
    ln -s /opt/assay/halmos/bin/halmos /rootfs/usr/local/bin/halmos; \
    # Shared libraries of the solver and extension modules, copied from the base image as for
    # the runner; the runner image already holds most of them.
    find /rootfs/opt/assay/halmos -type f \( -perm -u+x -o -name '*.so' -o -name '*.so.*' \) \
        | while read -r file; do ldd "$file" 2>/dev/null || true; done \
        | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }' \
        | sort -u \
        | while read -r lib; do \
            case "$lib" in /rootfs/*|/opt/assay/*) ;; *) cp -L --parents "$lib" /rootfs ;; esac; \
        done; \
    test -z "$(find /rootfs -perm /6000)"

# ---------------------------------------------------------------------------
# Symbolic runner image: the runner plus Halmos. linux/amd64 only; on an arm64
# host it runs under emulation (ADR 0018).
# ---------------------------------------------------------------------------

FROM runner AS runner-symbolic
ARG HALMOS_VERSION
ARG Z3_SOLVER_VERSION

COPY --from=halmos /rootfs/ /

LABEL org.opencontainers.image.title="assay-runner-symbolic" \
      org.opencontainers.image.description="Offline Foundry, static-analysis and Halmos runner for Assay" \
      assay.halmos.version="${HALMOS_VERSION}" \
      assay.z3.version="${Z3_SOLVER_VERSION}"
