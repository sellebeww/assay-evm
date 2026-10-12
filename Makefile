.DEFAULT_GOAL := help

RUNNER_IMAGE ?= assay-runner:dev
# Optional, for example linux/amd64. Empty means the native platform.
RUNNER_PLATFORM ?=
# The runner plus Halmos, always linux/amd64: the pinned solvers have no linux/arm64 builds, so on
# an arm64 host this image runs under emulation (ADR 0018).
SYMBOLIC_IMAGE ?= assay-runner-symbolic:dev
SYMBOLIC_PLATFORM := linux/amd64

# uv and docker are taken from PATH, or else from their default install locations
# (shells on macOS often lack these directories). Both can be overridden, for
# example `make UV=/path/to/uv install`.
UV_FALLBACK := $(HOME)/.local/bin/uv
DOCKER_DESKTOP_BIN := /Applications/Docker.app/Contents/Resources/bin
ifeq ($(origin UV),undefined)
UV := $(or $(shell command -v uv 2>/dev/null),$(wildcard $(UV_FALLBACK)),uv)
endif
ifeq ($(origin DOCKER),undefined)
DOCKER := $(or $(shell command -v docker 2>/dev/null),$(wildcard $(DOCKER_DESKTOP_BIN)/docker),docker)
endif
# The docker CLI finds its credential helper and plugins through PATH.
ifneq ($(wildcard $(DOCKER_DESKTOP_BIN)),)
export PATH := $(PATH):$(DOCKER_DESKTOP_BIN)
endif

DEMO_PROJECT := fixtures/reentrancy/single_function
DEMO_CASSETTES := demo/cassettes
DEMO_OUT := demo-out

VERSIONS_LOCK := docker/runner/versions.lock
RUNNER_DOCKERFILE := docker/runner/Dockerfile
SMOKE_DIR := tests/data/smoke
SYMBOLIC_SMOKE_DIR := tests/data/symbolic_smoke
SYMBOLIC_RESULTS := build/symbolic/results.json
SYMBOLIC_PAGE := docs/symbolic.md
MATRIX_RESULTS := build/matrix/results.json
MATRIX_PAGE := docs/classification-matrix.md
# Campaign profile of the variant search in `make matrix` (quick, standard or thorough).
PROFILE ?= standard
# Profiles that `make variant-power` runs, in order.
PROFILES ?= quick standard thorough
VARIANT_POWER_RESULTS := build/variant-power/results.json
VARIANT_POWER_PAGE := docs/variant-power.md
COVERAGE_RESULTS := build/static-coverage/results.json
COVERAGE_PAGE := docs/static-coverage.md

# Every KEY=VALUE line of versions.lock becomes a docker build argument.
RUNNER_BUILD_ARGS := $(shell sed -n 's/^\([A-Z0-9_]*\)=\(.*\)$$/--build-arg \1=\2/p' $(VERSIONS_LOCK))
DOCKERFILE_FRONTEND := $(shell sed -n 's/^DOCKERFILE_FRONTEND=//p' $(VERSIONS_LOCK))
SLITHER_VERSION := $(shell sed -n 's/^SLITHER_VERSION=//p' $(VERSIONS_LOCK))
ADERYN_VERSION := $(shell sed -n 's/^ADERYN_VERSION=//p' $(VERSIONS_LOCK))
HALMOS_VERSION := $(shell sed -n 's/^HALMOS_VERSION=//p' $(VERSIONS_LOCK))
Z3_SOLVER_VERSION := $(shell sed -n 's/^Z3_SOLVER_VERSION=//p' $(VERSIONS_LOCK))

# Container policy for image-check; it mirrors the sandbox policy in docs/sandbox.md.
RUNNER_RUN_FLAGS := --rm --pull never --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --pids-limit 256 --memory 2g --memory-swap 2g --cpus 2 \
	--user 10001:10001 --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
	--log-driver none --label assay.role=image-check

# $(call smoke_run,<name>) expands to a docker run prefix for the smoke project:
# project mounted read-only, one scratch directory writable for out/ and cache/.
smoke_run = $(DOCKER) run $(RUNNER_RUN_FLAGS) --name assay-image-check-$(1)-$$$$ \
	$(if $(RUNNER_PLATFORM),--platform $(RUNNER_PLATFORM)) \
	--volume "$(CURDIR)/$(SMOKE_DIR):/work/project:ro" \
	--volume "$$scratch:/work/scratch" \
	--workdir /work/project $(RUNNER_IMAGE)
SMOKE_FORGE_FLAGS := --out /work/scratch/out --cache-path /work/scratch/cache
# $(call symbolic_run,<name>,<dir>) is the same for the symbolic image and a project <dir>; the
# tmpfs is larger because Halmos writes its solver queries to /tmp.
symbolic_run = $(DOCKER) run $(subst size=64m,size=256m,$(RUNNER_RUN_FLAGS)) \
	--name assay-image-check-$(1)-$$$$ --platform $(SYMBOLIC_PLATFORM) \
	--volume "$(CURDIR)/$(2):/work/project:ro" \
	--volume "$$scratch:/work/scratch" \
	--workdir /work/project $(SYMBOLIC_IMAGE)

.PHONY: help install lint typecheck test test-integration test-security check fmt clean image \
	image-check fixtures-check bench-oracles bench-freeze bench-report matrix static-coverage variant-power symbolic-report schemas \
	demo demo-overfit demo-cassettes docs-check lint-actions claims-check third-party-notices

help:
	@echo "Targets:"
	@echo "  install      install the project and dev dependencies (uv sync)"
	@echo "  lint         ruff check and ruff format --check"
	@echo "  typecheck    mypy --strict on src"
	@echo "  test         unit tests"
	@echo "  test-integration  integration tests against Docker and $(RUNNER_IMAGE)"
	@echo "  test-security     sandbox security claims against Docker and $(RUNNER_IMAGE)"
	@echo "  check        lint, typecheck and test; fails if any of them fails (no Docker)"
	@echo "  fmt          format and auto-fix with ruff"
	@echo "  clean        remove caches and build output"
	@echo "  image        build the runner image $(RUNNER_IMAGE) and the symbolic image"
	@echo "               $(SYMBOLIC_IMAGE) ($(SYMBOLIC_PLATFORM)) from $(VERSIONS_LOCK)"
	@echo "  image-check  tool versions, then build and test $(SMOKE_DIR) in the image and run"
	@echo "               Halmos on $(SYMBOLIC_SMOKE_DIR) in the symbolic image, offline"
	@echo "  fixtures-check  establish the fixture labels with plain Foundry in $(RUNNER_IMAGE)"
	@echo "  bench-oracles  assay bench run on SPLIT=dev|heldout (long); PROFILE, SYMBOLIC=1 optional"
	@echo "  bench-freeze   record the oracle hash in bench/FROZEN_HASH (see bench/PROTOCOL.md)"
	@echo "  bench-report   docs/results.md and docs/results.json from RESULTS=\"<dir> <dir>\""
	@echo "  matrix       classification matrix: assay verify on every fixture patch (long);"
	@echo "               PROFILE=quick|standard|thorough (default standard)"
	@echo "  variant-power  variant search on every overfit and good patch per profile (long);"
	@echo "               PROFILES=\"quick standard thorough\" (default), renders $(VARIANT_POWER_PAGE)"
	@echo "  static-coverage  assay scan on every fixture; renders $(COVERAGE_PAGE)"
	@echo "  symbolic-report  symbolic oracle on every fixture patch; renders $(SYMBOLIC_PAGE)"
	@echo "  schemas      export the JSON Schemas of --json to docs/schemas/"
	@echo "  docs-check   relative links and vocabulary of README.md and docs/ (part of check)"
	@echo "  lint-actions  pinned actionlint over the workflows and action.yml (downloads it once)"
	@echo "  demo         offline demo: assay run on a fixture from cassettes, to $(DEMO_OUT)/run/"
	@echo "  demo-overfit assay verify on the overfit patch: REJECTED variant_found, to $(DEMO_OUT)/overfit/"
	@echo "  demo-cassettes  re-record $(DEMO_CASSETTES)/ (needs Docker; see docs/demo.md)"

install:
	$(UV) sync

lint:
	$(UV) run ruff check .
	$(UV) run ruff format --check .

typecheck:
	$(UV) run mypy --strict src tools

test:
	$(UV) run pytest tests/unit -q

# Needs Docker and the runner image (`make image`); not part of `check`.
test-integration:
	$(UV) run pytest tests/integration -m integration -q

# Security claims of docs/sandbox.md; needs Docker and the runner image, not part of `check`.
test-security:
	$(UV) run pytest tests/security -m integration -q

# Ground truth of the fixtures (docs/fixture-spec.md, section 8): every variant runs with plain
# Foundry in the sandbox and is compared with expected.json. Needs Docker and the runner image.
fixtures-check:
	$(UV) run python tools/fixture_check.py --image $(RUNNER_IMAGE)

# Benchmark (bench/PROTOCOL.md). `bench-oracles` runs `assay verify` on every patch of a split and
# stores the per-oracle results in bench/results/<run-id>/ (ten minutes to about two hours; needs
# Docker and the runner image). `bench-freeze` records the hash of the oracle tree; after it,
# src/assay/oracles, solidity/ and versions.lock must not change until the benchmark is finished.
# `bench-report` renders docs/results.md and docs/results.json from the result folders in RESULTS.
SPLIT ?= dev
bench-oracles:
	$(UV) run assay bench run --split $(SPLIT) --profile $(PROFILE) $(if $(SYMBOLIC),--symbolic)

bench-freeze:
	$(UV) run assay bench freeze

bench-report:
	@test -n "$(RESULTS)" || { echo 'error: set RESULTS="bench/results/<dev-run> bench/results/<heldout-run>"' >&2; exit 2; }
	$(UV) run assay bench report $(RESULTS)

# Classification matrix (docs/fixture-spec.md, section 4): `assay verify` on every patch of every
# fixture, compared with expected.json; between half an hour and two hours. Needs Docker and the
# runner image. The results are rendered into $(MATRIX_PAGE) even when a patch does not match,
# and the output ends with the line `MATRIX RESULT: <matching>/<total> match`. An infrastructure
# problem (exit code 4, for example Docker out of memory) stops the run without a page. PROFILE
# selects the campaign profile of the variant search; the page records it.
matrix:
	@rm -f $(MATRIX_RESULTS); \
	status=0; \
	ASSAY_MATRIX_PROFILE=$(PROFILE) $(UV) run pytest tests/integration/test_matrix.py -m matrix -q -s \
		|| status=$$?; \
	if [ -f $(MATRIX_RESULTS) ]; then \
		$(UV) run python tools/matrix_report.py --results $(MATRIX_RESULTS) --out $(MATRIX_PAGE) \
			|| status=$$?; \
	fi; \
	exit $$status

# Static analysis coverage: `assay scan` on the vulnerable revision of every fixture, rendered into
# $(COVERAGE_PAGE) with the number of findings per analyzer and the classes no analyzer detected.
# Needs Docker and the runner image. Exit status 1 means that an analyzer gave no usable result
# on some fixture (the page is still written); a class that is not detected is not a failure.
static-coverage:
	$(UV) run python tools/static_coverage.py --image $(RUNNER_IMAGE) \
		--results $(COVERAGE_RESULTS) --out $(COVERAGE_PAGE)

# Variant search power: the VariantOracle on the overfit and good patch of every fixture, once per
# profile in PROFILES, rendered into $(VARIANT_POWER_PAGE) with whether a variant was found, with
# which seed and how long it took. Needs Docker and the runner image; one to several hours. Exit
# status 1 means that a good patch got a variant, a finding to investigate.
variant-power:
	$(UV) run python tools/variant_power.py --image $(RUNNER_IMAGE) --profiles "$(PROFILES)" \
		--results $(VARIANT_POWER_RESULTS) --out $(VARIANT_POWER_PAGE)

# Symbolic oracle (Halmos) on the patches of every fixture that has symbolic properties, and the
# list of fixtures without them, rendered into $(SYMBOLIC_PAGE). Needs Docker, the runner image
# and the symbolic image. Exit status 1 means that a result differs from what the patch's label
# leads one to expect (for example a counterexample on a good patch); the page is still written.
symbolic-report:
	$(UV) run python tools/symbolic_report.py --image $(RUNNER_IMAGE) \
		--symbolic-image $(SYMBOLIC_IMAGE) --results $(SYMBOLIC_RESULTS) --out $(SYMBOLIC_PAGE)

# JSON Schemas of the `--json` output, exported from the Pydantic models (docs/cli.md). The unit
# tests fail when docs/schemas/ is out of date; this target rewrites it.
schemas:
	$(UV) run python tools/export_schemas.py

# Relative links in README.md and docs/, and the words the project never uses for a result.
docs-check:
	$(UV) run python tools/docs_check.py

# The workflows and action.yml, with an actionlint that is pinned by version and sha256
# (tools/lint_actions.py). The first run downloads the binary into build/actionlint/.
lint-actions:
	$(UV) run python tools/lint_actions.py

# Every claim in README.md and docs/ has an evidence row in docs/claims.md, and every evidence
# path of that table exists (tools/claims_check.py). Part of `check`; needs no Docker.
claims-check:
	$(UV) run python tools/claims_check.py

# The licenses of every Python package in the runner images, written to
# build/audit/python-licenses.json (keeps THIRD_PARTY_NOTICES.md honest). Needs Docker and the
# images (`make image`); exports each image's filesystem and reads the dist-info metadata.
third-party-notices:
	@mkdir -p build/audit
	@cid="$$($(DOCKER) create $(RUNNER_IMAGE) forge)"; \
		$(DOCKER) export "$$cid" > build/audit/runner-fs.tar; $(DOCKER) rm "$$cid" >/dev/null
	@cid="$$($(DOCKER) create $(SYMBOLIC_IMAGE) forge)"; \
		$(DOCKER) export "$$cid" > build/audit/symbolic-fs.tar; $(DOCKER) rm "$$cid" >/dev/null
	$(UV) run python tools/third_party_notices.py \
		--runner-fs build/audit/runner-fs.tar --symbolic-fs build/audit/symbolic-fs.tar

check: lint typecheck test docs-check claims-check

# Offline demo (docs/demo.md): `assay run` on the reentrancy fixture, answering from the shipped
# synthetic cassettes instead of a model. Needs Docker and the runner image (`make image`), and
# no network and no API key. The output goes to $(DEMO_OUT)/, which is not tracked by Git.
demo:
	@rm -rf $(DEMO_OUT)/run
	@mkdir -p $(DEMO_OUT)/run
	$(UV) run assay run $(DEMO_PROJECT) --class reentrancy --mode replay \
		--cassette-dir $(DEMO_CASSETTES) --profile quick \
		--ledger $(DEMO_OUT)/run/ledger.db --poc-dir $(DEMO_OUT)/run/poc \
		--bundle-out $(DEMO_OUT)/run/bundle
	$(UV) run assay report $(DEMO_OUT)/run/bundle --out $(DEMO_OUT)/run/report.html
	@echo
	@echo "Open the report:      open $(DEMO_OUT)/run/report.html   (xdg-open on Linux)"
	@echo "Re-check the bundle:  $(UV) run assay replay $(DEMO_OUT)/run/bundle"

# The overfit patch passes the tests that existed and blocks the original PoC, but the variant
# search finds a close variant: REJECTED with variant_found. `assay verify` exits with 1 then,
# which is the expected result of this demo.
demo-overfit:
	@rm -rf $(DEMO_OUT)/overfit
	@mkdir -p $(DEMO_OUT)/overfit
	@$(UV) run assay verify --base $(DEMO_PROJECT) \
		--patch $(DEMO_PROJECT)/patches/overfit.diff --poc $(DEMO_PROJECT)/poc \
		--profile quick --ledger $(DEMO_OUT)/overfit/ledger.db \
		--bundle-out $(DEMO_OUT)/overfit/bundle; \
	status=$$?; \
	if [ $$status -ne 1 ]; then \
		echo "error: expected exit code 1 (REJECTED), got $$status" >&2; exit 1; \
	fi; \
	$(UV) run assay report $(DEMO_OUT)/overfit/bundle --out $(DEMO_OUT)/overfit/report.html || exit 1; \
	echo; \
	echo "The patch passes the benign tests (behavior PASS) and blocks the original PoC (exploit PASS),"; \
	echo "but the variant search found a variant (variant FAIL, variant_found). The test it wrote:"; \
	echo "  $(DEMO_OUT)/overfit/bundle/evidence/variant/variant_poc.t.sol"; \
	echo "Open the report:      open $(DEMO_OUT)/overfit/report.html   (xdg-open on Linux)"

# Re-record the cassettes of the demo (needs Docker); rarely needed.
demo-cassettes:
	$(UV) run python tools/demo_cassettes.py

fmt:
	$(UV) run ruff format .
	$(UV) run ruff check --fix .

clean:
	rm -rf .mypy_cache .ruff_cache .pytest_cache .coverage coverage.xml htmlcov build dist
	find src tests tools -type d -name __pycache__ -prune -exec rm -rf {} +

image:
	@grep -qxF "# syntax=$(DOCKERFILE_FRONTEND)" $(RUNNER_DOCKERFILE) || \
		{ echo "error: syntax line of $(RUNNER_DOCKERFILE) does not match DOCKERFILE_FRONTEND in $(VERSIONS_LOCK)" >&2; exit 1; }
	$(DOCKER) build $(if $(RUNNER_PLATFORM),--platform $(RUNNER_PLATFORM)) --target runner \
		$(RUNNER_BUILD_ARGS) --tag $(RUNNER_IMAGE) --file $(RUNNER_DOCKERFILE) docker/runner
	$(DOCKER) build --platform $(SYMBOLIC_PLATFORM) --target runner-symbolic \
		$(RUNNER_BUILD_ARGS) --tag $(SYMBOLIC_IMAGE) --file $(RUNNER_DOCKERFILE) docker/runner

image-check:
	@set -eu; \
	scratch="$$(mktemp -d)"; \
	trap 'rm -rf "$$scratch"' EXIT; \
	echo "== forge --version"; \
	$(call smoke_run,version) forge --version; \
	echo "== slither --version (versions.lock: $(SLITHER_VERSION))"; \
	found="$$($(call smoke_run,slither) slither --version)"; \
	echo "$$found"; \
	test "$$found" = "$(SLITHER_VERSION)" || \
		{ echo "error: slither reports $$found, versions.lock pins $(SLITHER_VERSION)" >&2; exit 1; }; \
	echo "== aderyn --version (versions.lock: $(ADERYN_VERSION))"; \
	found="$$($(call smoke_run,aderyn) aderyn --version)"; \
	echo "$$found"; \
	test "$$found" = "aderyn $(ADERYN_VERSION:v%=%)" || \
		{ echo "error: aderyn reports $$found, versions.lock pins $(ADERYN_VERSION)" >&2; exit 1; }; \
	echo "== forge build ($(SMOKE_DIR))"; \
	$(call smoke_run,build) forge build $(SMOKE_FORGE_FLAGS); \
	echo "== forge test ($(SMOKE_DIR))"; \
	$(call smoke_run,test) forge test $(SMOKE_FORGE_FLAGS); \
	echo "== halmos --version in $(SYMBOLIC_IMAGE) (versions.lock: $(HALMOS_VERSION))"; \
	found="$$($(call symbolic_run,halmos,$(SMOKE_DIR)) halmos --version)"; \
	echo "$$found"; \
	test "$$found" = "halmos $(HALMOS_VERSION)" || \
		{ echo "error: halmos reports $$found, versions.lock pins $(HALMOS_VERSION)" >&2; exit 1; }; \
	echo "== z3 --version in $(SYMBOLIC_IMAGE) (versions.lock: $(Z3_SOLVER_VERSION))"; \
	found="$$($(call symbolic_run,z3,$(SMOKE_DIR)) /opt/assay/halmos/bin/z3 --version)"; \
	echo "$$found"; \
	test "$$found" = "Z3 version $(basename $(Z3_SOLVER_VERSION)) - 64 bit" || \
		{ echo "error: z3 reports $$found, versions.lock pins $(Z3_SOLVER_VERSION)" >&2; exit 1; }; \
	echo "== halmos ($(SYMBOLIC_SMOKE_DIR))"; \
	scratch="$$scratch/symbolic"; mkdir -m 777 "$$scratch"; \
	$(call symbolic_run,halmos-run,$(SYMBOLIC_SMOKE_DIR)) halmos --root /work/project \
		--forge-build-out /work/scratch/out --loop 2 --solver z3 --solver-threads 1 --no-status \
		--json-output /work/scratch/halmos.json; \
	test -s "$$scratch/halmos.json" || { echo "error: halmos wrote no JSON report" >&2; exit 1; }; \
	echo "image-check: OK"
